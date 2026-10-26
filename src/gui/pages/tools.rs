//! Tools page: state and update logic.
mod view;

use super::personal;

use crate::app::maintenance::{
    self as logic, Found, InstallEvent, InstallResult, InstallStage, RepairEvent, RepairKind,
    RepairProgress, RepairResult, TipProfile, TipsReport,
};
use crate::app::settings::ToolsTab;
use crate::broker;
use crate::gui::widgets::anim::{self, Clock};
use crate::gui::{blocking, blocking_stream, Ctx, Message, Tone};
use iced::{Subscription, Task};
use secblitz::actions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

pub use view::{modal, view};
#[cfg(test)]
pub use view::{tab_label, tab_name, BUSY_MARK};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sheet {
    Scan,
    RemoveThreats,
    Renewal { bitlocker: bool },
    DefenderUpdate,
    Repair(RepairKind),
    InstallUpdates,
    Bitwarden,
    Restart,
}

impl Sheet {
    /// What each confirmation sheet must tell the person before they agree.
    pub fn notices(self) -> secblitz::hardening::Notices {
        let (restart, undoable) = match self {
            Sheet::RemoveThreats | Sheet::Repair(RepairKind::Repair) | Sheet::InstallUpdates => {
                (false, false)
            }
            Sheet::Restart => (true, true),
            Sheet::Renewal { .. } => (true, false),
            Sheet::Scan
            | Sheet::DefenderUpdate
            | Sheet::Repair(RepairKind::Check)
            | Sheet::Bitwarden => (false, true),
        };
        secblitz::hardening::Notices {
            managed: false,
            restart,
            undoable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shortcut {
    WindowsUpdate,
    WindowsSecurity,
    Encryption,
    SignIn,
}

impl Shortcut {
    fn page(self) -> crate::guide::Page {
        use crate::guide::Page;
        match self {
            Self::WindowsUpdate => Page::WindowsUpdate,
            Self::WindowsSecurity => Page::WindowsSecurity,
            Self::Encryption => Page::Encryption,
            Self::SignIn => Page::SignIn,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detail {
    TipsList,
    TipsGood,
}

#[derive(Debug, Clone)]
pub enum Msg {
    Ask(Sheet),
    CloseSheet,
    Point(String),
    Confirm,
    ScanDone(Result<(), String>),
    ThreatsDone(Result<actions::ThreatRemoval, String>),
    ClearThreats,
    RenewalDone(Result<actions::RenewalOutcome, String>),
    OpenRecoveryKey,
    RecoveryKeyOpened(bool),
    DefenderDone(Result<(), String>),
    ClearScan,
    ClearDefender,
    Repair(RepairEvent),
    StopRepair,
    ClearRepair,
    LookForUpdates,
    Found(Result<Found, (String, &'static str)>),
    Install(InstallEvent),
    StopInstall,
    ClearUpdates,
    PickTips(TipProfile),
    Tips(Box<TipsReport>),
    TipsRefreshed(Box<TipsReport>),
    TipChoice(TipProfile),
    Frame(Instant),
    BitwardenDone(Result<broker::Reply, String>),
    BitwardenKnown(Result<broker::Reply, String>),
    ClearBitwarden,
    Open(Shortcut),
    OpenAction(actions::Action),
    OpenSecurity,
    RestartDone(Result<(), String>),
    ToggleDetail(Detail),
    SetTab(ToolsTab),
    PrefsSaved,
    Personal(personal::Msg),
    AccountKnown(Option<&'static str>),
    CheckAccount,
    Ready(Sheet, Option<&'static str>, bool),
}

#[derive(Debug)]
pub enum Run<T> {
    Idle,
    Working,
    Done(T),
}

// Not derived: a derive would demand `T: Default`.
#[allow(clippy::derivable_impls)]
impl<T> Default for Run<T> {
    fn default() -> Self {
        Self::Idle
    }
}

#[derive(Debug, Default)]
pub enum Repair {
    #[default]
    Idle,
    Working {
        kind: RepairKind,
        cancel: Arc<AtomicBool>,
        progress: Option<RepairProgress>,
    },
    Done {
        kind: RepairKind,
        result: RepairResult,
        note: Option<&'static str>,
        #[allow(dead_code)] // raw evidence, never shown on screen
        technical: String,
    },
}

#[derive(Debug, Default)]
pub enum Updates {
    #[default]
    Idle,
    Looking,
    UpToDate,
    Found(Found),
    Failed {
        #[allow(dead_code)] // raw evidence, never shown on screen
        technical: String,
        note: &'static str,
    },
    Installing {
        cancel: Arc<AtomicBool>,
        stage: InstallStage,
        elapsed: u64,
        count: usize,
    },
    Done {
        result: InstallResult,
        note: Option<&'static str>,
        #[allow(dead_code)] // raw evidence, never shown on screen
        technical: String,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Account {
    #[default]
    Checking,
    Fine,
    Blocked(&'static str),
}

#[derive(Debug, Default)]
pub enum Tips {
    #[default]
    Pick,
    Running(TipProfile),
    Done(Box<TipsReport>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Scan,
    Threats,
    Defender,
    Repair,
    Updates,
    Bitwarden,
}

pub struct State {
    sheet: Option<Sheet>,
    sheet_block: Option<&'static str>,
    points: crate::gui::widgets::point::Opened,
    sheet_checking: bool,
    account: Account,
    scan: Run<Result<(), String>>,
    threats: Run<Result<actions::ThreatRemoval, String>>,
    renewing: bool,
    renewal_unconfirmed: bool,
    defender: Run<Result<(), String>>,
    repair: Repair,
    updates: Updates,
    tips: Tips,
    tip_choice: TipProfile,
    bitwarden: Run<Result<(), String>>,
    bitwarden_why: Option<broker::Reply>,
    pub bitwarden_present: bool,
    bitwarden_not_here: bool,
    open_details: Vec<Detail>,
    personal: personal::State,
    now: Instant,
    spin: Instant,
    shots: Vec<(Slot, Clock)>,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("tools::State").finish_non_exhaustive()
    }
}

impl State {
    fn bitwarden_known(&mut self, reply: &Result<broker::Reply, String>) {
        self.bitwarden_present = matches!(reply, Ok(broker::Reply::Done));
        self.bitwarden_not_here = matches!(reply, Ok(broker::Reply::Unavailable));
    }
}

impl Default for State {
    fn default() -> Self {
        Self {
            sheet: None,
            sheet_block: None,
            points: crate::gui::widgets::point::Opened::default(),
            sheet_checking: false,
            account: Account::Checking,
            scan: Run::Idle,
            threats: Run::Idle,
            renewing: false,
            renewal_unconfirmed: false,
            defender: Run::Idle,
            repair: Repair::Idle,
            updates: Updates::Idle,
            tips: Tips::Pick,
            tip_choice: TipProfile::Everyday,
            bitwarden: Run::Idle,
            bitwarden_why: None,
            bitwarden_present: false,
            bitwarden_not_here: false,
            open_details: Vec::new(),
            personal: Default::default(),
            now: Instant::now(),
            spin: Instant::now(),
            shots: Vec::new(),
        }
    }
}

fn tools(msg: Msg) -> Message {
    Message::Tools(msg)
}

fn plain(e: anyhow::Error) -> String {
    format!("{e:#}")
}

pub fn escape(state: &mut State) {
    if state.sheet.is_some() {
        state.sheet = None;
        state.points.clear();
        state.sheet_block = None;
        state.sheet_checking = false;
    }
}

pub fn subscription(state: &State, _ctx: &Ctx) -> Subscription<Message> {
    if state.needs_frames() && anim::animating() {
        iced::window::frames().map(|at| Message::Tools(Msg::Frame(at)))
    } else {
        Subscription::none()
    }
}

pub fn on_enter(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    let settings = personal::on_enter(&mut state.personal, ctx);
    let account = check_account(state);
    if ctx.broker.is_none() || state.bitwarden_present || !matches!(state.bitwarden, Run::Idle) {
        return Task::batch([settings, account]);
    }
    Task::batch([
        settings,
        account,
        ctx.broker_task(broker::Request::BitwardenStatus, |r| {
            tools(Msg::BitwardenKnown(r))
        }),
    ])
}

fn check_account(state: &mut State) -> Task<Message> {
    if state.account == Account::Fine {
        return Task::none();
    }
    Task::perform(
        blocking(|| logic::updates_account_note(secblitz::patching::account_supported())),
        |note| tools(Msg::AccountKnown(note)),
    )
}

fn needs_ready_check(sheet: Sheet) -> bool {
    matches!(sheet, Sheet::Repair(_) | Sheet::InstallUpdates)
}

fn check_ready(sheet: Sheet, start: bool) -> Task<Message> {
    Task::perform(blocking(logic::check_start_blocker), move |note| {
        tools(Msg::Ready(sheet, note, start))
    })
}

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    match msg {
        Msg::Ask(sheet) => {
            // A restart would cut a running fix, repair or update short, and
            // a threat removal must not run alongside a fix or undo.
            let changes_pc = matches!(
                sheet,
                Sheet::Repair(_)
                    | Sheet::InstallUpdates
                    | Sheet::Restart
                    | Sheet::RemoveThreats
                    | Sheet::Renewal { .. }
            );
            let blocked = changes_pc && (ctx.busy || !state.can_start_change());
            if blocked {
                return Task::none();
            }
            state.sheet = Some(sheet);
            state.points.clear();
            state.sheet_block = None;
            state.sheet_checking = false;
            if needs_ready_check(sheet) {
                return check_ready(sheet, false);
            }
            Task::none()
        }
        Msg::Point(key) => {
            if state.sheet.is_some() {
                state.points.toggle(&key);
            }
            Task::none()
        }
        Msg::CloseSheet => {
            state.sheet = None;
            state.points.clear();
            state.sheet_block = None;
            state.sheet_checking = false;
            Task::none()
        }
        Msg::Confirm => {
            let Some(sheet) = state.sheet else {
                return Task::none();
            };
            if needs_ready_check(sheet) {
                if state.sheet_checking {
                    return Task::none();
                }
                state.sheet_checking = true;
                return check_ready(sheet, true);
            }
            state.sheet = None;
            confirm(state, sheet, ctx)
        }
        Msg::Ready(sheet, note, start) => {
            if state.sheet != Some(sheet) {
                return Task::none();
            }
            if start {
                state.sheet_checking = false;
            }
            state.sheet_block = note;
            if start && note.is_none() {
                state.sheet = None;
                return confirm(state, sheet, ctx);
            }
            Task::none()
        }
        Msg::AccountKnown(note) => {
            state.account = note.map_or(Account::Fine, Account::Blocked);
            Task::none()
        }
        Msg::CheckAccount => {
            state.account = Account::Checking;
            check_account(state)
        }
        Msg::ScanDone(r) => {
            state.scan = Run::Done(r);
            state.finish(Slot::Scan);
            Task::none()
        }
        Msg::ThreatsDone(r) => {
            ctx.busy = false;
            let changed = r.as_ref().is_ok_and(|t| {
                crate::app::maintenance::threats_result(t)
                    != crate::app::maintenance::ThreatsResult::Stuck
            });
            state.threats = Run::Done(r);
            state.finish(Slot::Threats);
            match (&state.tips, changed) {
                (Tips::Done(shown), true) => {
                    let profile = shown.profile;
                    Task::perform(blocking(move || logic::run_tips(profile)), |r| {
                        tools(Msg::TipsRefreshed(Box::new(r)))
                    })
                }
                _ => Task::none(),
            }
        }
        Msg::RenewalDone(r) => {
            ctx.busy = false;
            state.renewing = false;
            if matches!(r, Ok(actions::RenewalOutcome::Started { .. })) {
                record_renewal(ctx);
            }
            state.renewal_unconfirmed = r.is_err();
            let (words, tone) = match &r {
                Ok(outcome) => (
                    crate::app::maintenance::renewal_result_text(*outcome),
                    match outcome {
                        actions::RenewalOutcome::Started { .. } => Tone::Good,
                        actions::RenewalOutcome::Refused(_) => Tone::Warn,
                    },
                ),
                Err(_) => (
                    "The renewal may have started, but we couldn't confirm it. Check the tip again in a few minutes.",
                    Tone::Warn,
                ),
            };
            let toast = Task::done(Message::Toast(ctx.t(words), tone));
            match &state.tips {
                Tips::Done(shown) => {
                    let profile = shown.profile;
                    Task::batch([
                        toast,
                        Task::perform(blocking(move || logic::run_tips(profile)), |r| {
                            tools(Msg::TipsRefreshed(Box::new(r)))
                        }),
                    ])
                }
                _ => toast,
            }
        }
        Msg::OpenRecoveryKey => ctx.broker_task(crate::broker::Request::OpenRecoveryKey, |reply| {
            tools(Msg::RecoveryKeyOpened(matches!(
                reply,
                Ok(crate::broker::Reply::Done)
            )))
        }),
        Msg::RecoveryKeyOpened(true) => Task::none(),
        Msg::RecoveryKeyOpened(false) => Task::done(Message::Toast(
            ctx.t("We couldn't open your web browser. Visit aka.ms/myrecoverykey to find your recovery key."),
            Tone::Warn,
        )),
        Msg::TipsRefreshed(report) => {
            if std::mem::take(&mut state.renewal_unconfirmed)
                && report
                    .tips
                    .iter()
                    .any(|t| t.renewal == Some(secblitz::diagnostics::Renewal::Started))
            {
                record_renewal(ctx);
            }
            if matches!(state.tips, Tips::Done(_)) {
                state.tips = Tips::Done(report);
            }
            Task::none()
        }
        Msg::ClearThreats => {
            state.threats = Run::Idle;
            Task::none()
        }
        Msg::DefenderDone(r) => {
            state.defender = Run::Done(r);
            state.finish(Slot::Defender);
            Task::none()
        }
        Msg::ClearScan => {
            state.scan = Run::Idle;
            Task::none()
        }
        Msg::ClearDefender => {
            state.defender = Run::Idle;
            Task::none()
        }
        Msg::Repair(event) => {
            let Repair::Working { kind, progress, .. } = &mut state.repair else {
                return Task::none();
            };
            match event {
                RepairEvent::Preparing => {}
                RepairEvent::Progress(p) => {
                    *progress = Some(p);
                }
                RepairEvent::Done {
                    result,
                    note,
                    technical,
                } => {
                    let kind = *kind;
                    state.repair = Repair::Done {
                        kind,
                        result,
                        note,
                        technical,
                    };
                    state.finish(Slot::Repair);
                    ctx.busy = false;
                }
            }
            Task::none()
        }
        Msg::StopRepair => {
            if let Repair::Working { cancel, .. } = &state.repair {
                cancel.store(true, Ordering::SeqCst);
            }
            Task::none()
        }
        Msg::ClearRepair => {
            if matches!(state.repair, Repair::Done { .. }) {
                state.repair = Repair::Idle;
            }
            Task::none()
        }
        Msg::LookForUpdates => {
            if !matches!(
                state.updates,
                Updates::Idle
                    | Updates::UpToDate
                    | Updates::Found(_)
                    | Updates::Failed { .. }
                    | Updates::Done { .. }
            ) {
                return Task::none();
            }
            state.updates = Updates::Looking;
            Task::perform(blocking(logic::discover_updates), |r| tools(Msg::Found(r)))
        }
        Msg::Found(result) => {
            if matches!(state.updates, Updates::Looking) {
                state.updates = match result {
                    Ok(found) if found.updates.is_empty() => Updates::UpToDate,
                    Ok(found) => Updates::Found(found),
                    Err((technical, note)) => Updates::Failed { technical, note },
                };
                if !matches!(state.updates, Updates::Found(_)) {
                    state.finish(Slot::Updates);
                }
            }
            Task::none()
        }
        Msg::Install(event) => {
            let Updates::Installing { stage, elapsed, .. } = &mut state.updates else {
                return Task::none();
            };
            match event {
                InstallEvent::Stage {
                    stage: s,
                    elapsed: e,
                } => {
                    *stage = s;
                    *elapsed = e;
                }
                InstallEvent::Done {
                    result,
                    note,
                    technical,
                } => {
                    state.updates = Updates::Done {
                        result,
                        note,
                        technical,
                    };
                    state.finish(Slot::Updates);
                    ctx.busy = false;
                }
            }
            Task::none()
        }
        Msg::StopInstall => {
            if let Updates::Installing { cancel, .. } = &state.updates {
                cancel.store(true, Ordering::SeqCst);
            }
            Task::none()
        }
        Msg::ClearUpdates => {
            if matches!(
                state.updates,
                Updates::Done { .. } | Updates::Failed { .. } | Updates::UpToDate
            ) {
                state.updates = Updates::Idle;
            }
            Task::none()
        }
        Msg::PickTips(profile) => {
            if matches!(state.tips, Tips::Running(_)) {
                return Task::none();
            }
            state.tips = Tips::Running(profile);
            state.close_detail(Detail::TipsList);
            state.tip_choice = profile;
            Task::perform(blocking(move || logic::run_tips(profile)), |r| {
                tools(Msg::Tips(Box::new(r)))
            })
        }
        Msg::Tips(report) => {
            if matches!(state.tips, Tips::Running(_)) {
                state.tips = Tips::Done(report);
                if !state.detail_open(Detail::TipsList) {
                    state.open_details.push(Detail::TipsList);
                }
            }
            Task::none()
        }
        Msg::TipChoice(profile) => {
            state.tip_choice = profile;
            Task::none()
        }
        Msg::Frame(now) => {
            state.now = now;
            state
                .shots
                .retain(|(_, clock)| !clock.done(anim::SLOW, now));
            Task::none()
        }
        Msg::BitwardenDone(reply) => {
            state.bitwarden_why = match reply {
                Ok(r @ (broker::Reply::Offline | broker::Reply::Unavailable)) => Some(r),
                _ => None,
            };
            state.bitwarden_present |= matches!(reply, Ok(broker::Reply::Done));
            state.bitwarden = Run::Done(match reply {
                Ok(broker::Reply::Done) => Ok(()),
                Ok(other) => Err(format!("{other:?}")),
                Err(e) => Err(e),
            });
            state.finish(Slot::Bitwarden);
            Task::none()
        }
        Msg::BitwardenKnown(reply) => {
            state.bitwarden_known(&reply);
            Task::none()
        }
        Msg::ClearBitwarden => {
            state.bitwarden = Run::Idle;
            Task::none()
        }
        Msg::Open(shortcut) => super::fixes::open_page(ctx, shortcut.page()),
        Msg::OpenAction(action) => match crate::guide::Page::from_action(action) {
            Some(page) => super::fixes::open_page(ctx, page),
            None => Task::none(),
        },
        Msg::OpenSecurity => super::fixes::open_page(ctx, crate::guide::Page::WindowsSecurity),
        Msg::RestartDone(result) => match result {
            Ok(()) => Task::done(Message::Toast(
                ctx.t("Restarting now. Programs with unsaved work will ask you first."),
                Tone::Good,
            )),
            Err(_) => Task::done(Message::Toast(
                ctx.t("We couldn't restart your computer. Restart it from the Start menu instead."),
                Tone::Warn,
            )),
        },
        Msg::SetTab(tab) => {
            if ctx.prefs.tools_tab == tab {
                return Task::none();
            }
            ctx.prefs.tools_tab = tab;
            Task::perform(crate::gui::save_prefs(ctx.prefs.clone()), |_| {
                tools(Msg::PrefsSaved)
            })
        }
        Msg::PrefsSaved => Task::none(),
        Msg::Personal(msg) => personal::update(&mut state.personal, msg, ctx),
        Msg::ToggleDetail(detail) => {
            if state.open_details.contains(&detail) {
                state.close_detail(detail);
            } else {
                state.open_details.push(detail);
            }
            Task::none()
        }
    }
}

fn repair_ratio(p: &RepairProgress) -> f32 {
    const PACE: f32 = 180.0;
    let creep = 1.0 - (-(p.step_elapsed as f32) / PACE).exp();
    (p.step.saturating_sub(1) as f32 + 0.9 * creep) / p.total.max(1) as f32
}

fn stage_ratio(stage: InstallStage) -> f32 {
    match stage {
        InstallStage::Preparing => 0.12,
        InstallStage::Installing => 0.55,
        InstallStage::Checking => 0.9,
    }
}

impl State {
    fn finish(&mut self, slot: Slot) {
        self.shots.retain(|(s, _)| *s != slot);
        self.shots.push((slot, Clock::new()));
    }
    fn shot(&self, slot: Slot) -> f32 {
        self.shots
            .iter()
            .find(|(s, _)| *s == slot)
            .map_or(1.0, |(_, clock)| clock.progress_at(anim::SLOW, self.now))
    }
    fn needs_frames(&self) -> bool {
        !self.shots.is_empty() || self.spinning()
    }

    fn spinning(&self) -> bool {
        matches!(self.scan, Run::Working)
            || matches!(self.threats, Run::Working)
            || matches!(self.defender, Run::Working)
            || matches!(self.bitwarden, Run::Working)
            || matches!(self.updates, Updates::Looking)
    }

    pub fn tab_busy(&self, tab: ToolsTab) -> bool {
        match tab {
            ToolsTab::Tips => matches!(self.tips, Tips::Running(_)) || self.renewing,
            ToolsTab::Viruses => {
                matches!(self.scan, Run::Working)
                    || matches!(self.threats, Run::Working)
                    || matches!(self.defender, Run::Working)
            }
            ToolsTab::Updates => {
                matches!(self.repair, Repair::Working { .. })
                    || matches!(self.updates, Updates::Looking | Updates::Installing { .. })
            }
            ToolsTab::Account => {
                matches!(self.bitwarden, Run::Working) || personal::account_busy(&self.personal)
            }
        }
    }

    pub(super) fn spin_elapsed(&self) -> std::time::Duration {
        self.now.saturating_duration_since(self.spin)
    }

    fn close_detail(&mut self, detail: Detail) {
        self.open_details.retain(|d| *d != detail);
    }
    fn detail_open(&self, detail: Detail) -> bool {
        self.open_details.contains(&detail)
    }
    fn can_start_change(&self) -> bool {
        !matches!(self.repair, Repair::Working { .. })
            && !matches!(self.updates, Updates::Installing { .. } | Updates::Looking)
    }
}

fn record_renewal(ctx: &Ctx) {
    if let Some(dir) = &ctx.state_dir {
        let score = ctx.score().unwrap_or_default();
        let _ = crate::app::history::record(
            dir,
            &crate::app::history::Entry {
                t: crate::app::history::now(),
                kind: crate::app::history::Kind::SecureBootRenewal,
                protected: score.protected,
                total: score.total,
                n: 0,
            },
        );
    }
}

fn confirm(state: &mut State, sheet: Sheet, ctx: &mut Ctx) -> Task<Message> {
    ctx.forget_check();
    match sheet {
        Sheet::Restart => Task::perform(
            blocking(|| actions::restart_for_updates().map_err(plain)),
            |r| tools(Msg::RestartDone(r)),
        ),
        Sheet::Scan => {
            state.scan = Run::Working;
            Task::perform(
                blocking(|| {
                    actions::run(actions::Action::QuickScan)
                        .map(|_| ())
                        .map_err(plain)
                }),
                |r| tools(Msg::ScanDone(r)),
            )
        }
        Sheet::RemoveThreats => {
            if ctx.busy || !state.can_start_change() {
                return Task::none();
            }
            ctx.busy = true;
            state.threats = Run::Working;
            Task::perform(blocking(|| actions::remove_threats().map_err(plain)), |r| {
                tools(Msg::ThreatsDone(r))
            })
        }
        Sheet::Renewal { .. } => {
            if ctx.busy || !state.can_start_change() {
                return Task::none();
            }
            ctx.busy = true;
            state.renewing = true;
            Task::perform(
                blocking(|| actions::start_secure_boot_renewal().map_err(plain)),
                |r| tools(Msg::RenewalDone(r)),
            )
        }
        Sheet::DefenderUpdate => {
            state.defender = Run::Working;
            Task::perform(
                blocking(|| {
                    actions::run(actions::Action::UpdateDefender)
                        .map(|_| ())
                        .map_err(plain)
                }),
                |r| tools(Msg::DefenderDone(r)),
            )
        }
        Sheet::Repair(kind) => {
            if ctx.busy || !state.can_start_change() {
                return Task::none();
            }
            ctx.busy = true;
            let cancel = Arc::new(AtomicBool::new(false));
            state.repair = Repair::Working {
                kind,
                cancel: cancel.clone(),
                progress: None,
            };
            Task::run(
                blocking_stream(move |emit| logic::run_repair(kind, cancel, emit)),
                |event| tools(Msg::Repair(event)),
            )
        }
        Sheet::InstallUpdates => {
            let Updates::Found(found) = &state.updates else {
                return Task::none();
            };
            if ctx.busy || !state.can_start_change() {
                return Task::none();
            }
            let reviewed = found.identities();
            let count = reviewed.len();
            ctx.busy = true;
            let cancel = Arc::new(AtomicBool::new(false));
            state.updates = Updates::Installing {
                cancel: cancel.clone(),
                stage: InstallStage::Preparing,
                elapsed: 0,
                count,
            };
            Task::run(
                blocking_stream(move |emit| logic::run_install(reviewed, cancel, emit)),
                |event| tools(Msg::Install(event)),
            )
        }
        Sheet::Bitwarden => {
            state.bitwarden = Run::Working;
            ctx.broker_task(broker::Request::InstallBitwarden, |r| {
                tools(Msg::BitwardenDone(r))
            })
        }
    }
}

#[cfg(test)]
mod followup_tests {
    use super::*;

    #[test]
    fn every_sheet_says_what_its_notices_promise() {
        let sheets = [
            Sheet::Scan,
            Sheet::RemoveThreats,
            Sheet::DefenderUpdate,
            Sheet::Repair(RepairKind::Check),
            Sheet::Repair(RepairKind::Repair),
            Sheet::InstallUpdates,
            Sheet::Bitwarden,
            Sheet::Restart,
            Sheet::Renewal { bitlocker: false },
            Sheet::Renewal { bitlocker: true },
        ];
        for sheet in sheets {
            let (_, _, lines, _) = view::sheet_copy(sheet);
            let text = lines.join(" ").to_lowercase();
            let n = sheet.notices();
            assert_eq!(text.contains("can't be undone"), !n.undoable, "{sheet:?}");
            assert_eq!(
                text.contains("restart"),
                n.restart || sheet == Sheet::InstallUpdates,
                "{sheet:?}"
            );
        }
    }

    #[test]
    fn what_a_sheet_promises_is_never_in_the_hidden_part() {
        let sheets = [
            Sheet::Scan,
            Sheet::RemoveThreats,
            Sheet::DefenderUpdate,
            Sheet::Repair(RepairKind::Check),
            Sheet::Repair(RepairKind::Repair),
            Sheet::InstallUpdates,
            Sheet::Bitwarden,
            Sheet::Restart,
            Sheet::Renewal { bitlocker: false },
            Sheet::Renewal { bitlocker: true },
        ];
        for sheet in sheets {
            let (_, _, lines, _) = view::sheet_copy(sheet);
            let whole = view::whole_lines(sheet);
            let shown = lines
                .iter()
                .enumerate()
                .map(|(i, l)| {
                    if whole.contains(&i) {
                        (*l).to_owned()
                    } else {
                        crate::gui::widgets::point::first_sentence(l).0.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase();
            let all = lines.join(" ").to_lowercase();
            let n = sheet.notices();
            assert_eq!(
                shown.contains("can't be undone"),
                all.contains("can't be undone"),
                "{sheet:?}"
            );
            if n.restart || sheet == Sheet::InstallUpdates {
                assert!(shown.contains("restart"), "{sheet:?}");
            }
            if sheet == (Sheet::Renewal { bitlocker: true }) {
                assert!(shown.contains("bitlocker recovery key"), "{sheet:?}");
            }
        }
    }

    #[test]
    fn repair_bar_creeps_inside_its_step_and_never_goes_back() {
        let at = |step, secs| {
            repair_ratio(&RepairProgress {
                label: "",
                step,
                total: 2,
                elapsed: secs,
                step_elapsed: secs,
            })
        };
        assert_eq!(at(1, 0), 0.0);
        assert!(at(2, 30) > at(2, 0) && at(2, 600) > at(2, 30));
        assert!(at(1, 100_000) < at(2, 0), "the next step starts ahead");
        assert!(at(2, 100_000) < 1.0, "only Done fills the bar");
    }

    #[test]
    fn bitwarden_known_sets_not_here_and_present_correctly() {
        let fresh = State::default();
        assert!(!fresh.bitwarden_not_here, "default: not_here is false");
        assert!(!fresh.bitwarden_present, "default: present is false");

        let mut state = State::default();
        state.bitwarden_known(&Ok(broker::Reply::Unavailable));
        assert!(!state.bitwarden_present, "Unavailable: not present");
        assert!(state.bitwarden_not_here, "Unavailable: not_here is set");

        let mut state = State::default();
        state.bitwarden_known(&Ok(broker::Reply::Done));
        assert!(state.bitwarden_present, "Done: present");
        assert!(!state.bitwarden_not_here, "Done: not_here stays false");

        let mut state = State::default();
        state.bitwarden_known(&Ok(broker::Reply::NotApplicable));
        assert!(!state.bitwarden_present, "NotApplicable: not present");
        assert!(
            !state.bitwarden_not_here,
            "NotApplicable: not_here is false"
        );

        let mut state = State::default();
        state.bitwarden_known(&Ok(broker::Reply::Unavailable));
        assert!(state.bitwarden_not_here);
        state.bitwarden_known(&Ok(broker::Reply::Done));
        assert!(state.bitwarden_present, "second call Done: present");
        assert!(
            !state.bitwarden_not_here,
            "second call Done: not_here cleared"
        );
    }
}
