//! Drawing code for the Tools page.
use super::{
    repair_ratio, stage_ratio, tools, Account, Detail, Msg, Repair, Run, Sheet, Shortcut, Slot,
    State, Tips, Updates,
};
use crate::app::maintenance::{
    self as logic, InstallResult, RepairKind, RepairResult, TipProfile, TipState,
};
use crate::app::settings::ToolsTab;
use crate::broker;
use crate::gui::icons::Icon;
use crate::gui::pages::personal;
use crate::gui::theme::{self, Palette, Tone};
use crate::gui::widgets::info::InfoSheet;
use crate::gui::widgets::point::{self, Words};
use crate::gui::widgets::{self, anim, progress, ButtonKind};
use crate::gui::{Ctx, Helper, Message, Page};
use iced::widget::{column, container, row, space, text};
use iced::{Alignment, Element, Length};

type El<'a> = Element<'a, Message>;
type MenuEntry = (Icon, String, Message, bool);

const MARK: f32 = 20.0;

pub fn view<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    page(state, ctx)
}

pub fn modal<'a>(state: &'a State, ctx: &'a Ctx) -> Option<El<'a>> {
    state.sheet.map(|sheet| sheet_panel(state, ctx, sheet))
}

fn page<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    let tab = ctx.prefs.tools_tab;
    let tabs = widgets::segmented(
        p,
        &ToolsTab::ALL.map(|t| (t, tab_label(state, ctx, t))),
        tab,
        |t| tools(Msg::SetTab(t)),
    );
    let body = match tab {
        ToolsTab::Tips => tips_tab(state, ctx),
        ToolsTab::Viruses => viruses_tab(state, ctx),
        ToolsTab::Updates => updates_tab(state, ctx),
        ToolsTab::Account => account_tab(state, ctx),
    };
    column![
        widgets::page_header(
            p,
            ctx.t("Tools"),
            Some(ctx.t("Handy ways to keep your computer safe and healthy.")),
        ),
        column![tabs, body].spacing(theme::S4).width(Length::Fill),
    ]
    .spacing(theme::S6)
    .width(Length::Fill)
    .into()
}

pub fn tab_label(state: &State, ctx: &Ctx, tab: ToolsTab) -> String {
    let name = tab_name(ctx, tab);
    if state.tab_busy(tab) {
        format!("{name}{BUSY_MARK}")
    } else {
        name
    }
}

pub const BUSY_MARK: &str = " \u{2022}";

/// Kept to one short word or two so the four tabs fit the narrowest window in every language.
pub fn tab_name(ctx: &Ctx, tab: ToolsTab) -> String {
    ctx.t(match tab {
        ToolsTab::Tips => "Tips",
        ToolsTab::Viruses => "Viruses",
        ToolsTab::Updates => "Updates",
        ToolsTab::Account => "Account",
    })
}

fn tips_tab<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    widgets::group(
        ctx.palette,
        ctx.t("Computer health tips"),
        None,
        None,
        tips_block(state, ctx),
    )
}

fn viruses_tab<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let mut rows = virus_rows(state, ctx);
    rows.extend(shortcut_rows(ctx, &[Shortcut::WindowsSecurity]));
    widgets::group(ctx.palette, ctx.t("Virus protection"), None, None, rows)
}

fn updates_tab<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    let mut windows = vec![repair_row(state, ctx), updates_row(state, ctx)];
    windows.extend(shortcut_rows(ctx, &[Shortcut::WindowsUpdate]));
    column![widgets::group(
        p,
        ctx.t("Repair & updates"),
        None,
        None,
        windows
    )]
    .spacing(theme::S8)
    .width(Length::Fill)
    .into()
}

fn account_tab<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    let account = personal::account(&state.personal, ctx);
    let mut rows = account.rows;
    rows.extend(shortcut_rows(
        ctx,
        &[Shortcut::Encryption, Shortcut::SignIn],
    ));
    column![
        widgets::group(p, ctx.t("Your account"), Some(account.subtitle), None, rows),
        widgets::group(
            p,
            ctx.t("Passwords"),
            None,
            None,
            vec![manager_row(state, ctx)]
        ),
    ]
    .spacing(theme::S8)
    .width(Length::Fill)
    .into()
}

fn secondary<'a>(p: Palette, label: String, msg: Option<Msg>) -> El<'a> {
    widgets::action(p, ButtonKind::Secondary, label, None, msg.map(tools))
}

fn entry(icon: Icon, label: String, msg: Msg) -> MenuEntry {
    (icon, label, tools(msg), false)
}

fn more<'a>(p: Palette, items: Vec<MenuEntry>) -> El<'a> {
    if items.is_empty() {
        space::horizontal().width(0).into()
    } else {
        widgets::overflow_menu(p, items)
    }
}

fn trailing<'a>(items: Vec<El<'a>>) -> El<'a> {
    row(items)
        .spacing(theme::S2)
        .align_y(Alignment::Center)
        .into()
}

struct Running<'a> {
    icon: Icon,
    title: String,
    sub: String,
    menu: Vec<MenuEntry>,
    bar: El<'a>,
    notes: Vec<El<'a>>,
}

fn running<'a>(p: Palette, r: Running<'a>) -> El<'a> {
    let mut below = vec![r.bar];
    below.extend(r.notes);
    widgets::row_item_below(
        p,
        Some(r.icon),
        r.title,
        Some(r.sub),
        trailing(vec![more(p, r.menu)]),
        below,
        None,
    )
}

fn busy_row<'a>(state: &State, p: Palette, icon: Icon, title: String, sub: String) -> El<'a> {
    widgets::row_item(
        p,
        Some(icon),
        title,
        Some(sub),
        anim::spinner(MARK, p.text_muted, state.spin_elapsed()),
        None,
    )
}

struct Outcome {
    slot: Slot,
    icon: Icon,
    tone: Tone,
    title: String,
    sub: Option<String>,
    menu: Vec<MenuEntry>,
    raw: Option<String>,
}

fn finished<'a>(state: &State, ctx: &Ctx, o: Outcome) -> El<'a> {
    finished_with(state, ctx, o, None)
}

fn finished_with<'a>(
    state: &State,
    ctx: &Ctx,
    o: Outcome,
    button: Option<(String, Icon, Msg)>,
) -> El<'a> {
    let p = ctx.palette;
    let t = state.shot(o.slot);
    let color = p.tone(o.tone);
    let mark: El<'a> = match o.tone {
        Tone::Good => anim::check_draw(MARK, color, t),
        Tone::Bad => anim::cross_draw(MARK, color, t),
        _ => anim::warn_draw(MARK, color, t),
    };
    let mut menu = o.menu;
    let below = Vec::new();
    if let Some(raw) = o.raw {
        menu.push(more_details(ctx, &o.title, &raw));
    }
    widgets::row_item_below(
        p,
        Some(o.icon),
        o.title,
        o.sub,
        {
            let mut items = Vec::new();
            if let Some((label, icon, msg)) = button {
                items.push(widgets::action(
                    p,
                    ButtonKind::Secondary,
                    label,
                    Some(icon),
                    Some(tools(msg)),
                ));
            }
            items.push(mark);
            items.push(more(p, menu));
            trailing(items)
        },
        below,
        None,
    )
}

fn raw_text(ctx: &Ctx, plain: &str) -> String {
    if plain.trim().is_empty() {
        ctx.t("No extra details.")
    } else {
        ctx.t(plain.trim())
    }
}

fn more_details(ctx: &Ctx, title: &str, raw: &str) -> MenuEntry {
    let sheet = InfoSheet::new(title).text(ctx.t("More details"), raw_text(ctx, raw));
    (
        Icon::Info,
        ctx.t("More details"),
        Message::Info(Some(Box::new(sheet))),
        false,
    )
}

fn elapsed_phrase(ctx: &Ctx, secs: u64) -> String {
    if secs < 60 {
        ctx.t("{n} sec").replace("{n}", &secs.to_string())
    } else {
        ctx.t("{n} min").replace("{n}", &(secs / 60).to_string())
    }
}

fn running_for(ctx: &Ctx, secs: u64) -> String {
    ctx.t("Running for {time}")
        .replace("{time}", &elapsed_phrase(ctx, secs))
}

fn details<'a>(ctx: &Ctx, title: &str, raw: &str) -> El<'a> {
    let sheet = InfoSheet::new(title).text(ctx.t("More details"), raw_text(ctx, raw));
    widgets::info::link(ctx, ctx.t("More details"), Some(sheet))
        .unwrap_or_else(|| space::horizontal().width(0).into())
}

fn open_security_entry(ctx: &Ctx) -> Option<MenuEntry> {
    ctx.can_open_pages().then(|| {
        entry(
            Icon::ExternalLink,
            ctx.t("Open Windows Security"),
            Msg::OpenSecurity,
        )
    })
}

fn helper_hint(ctx: &Ctx) -> String {
    ctx.t(ctx
        .helper
        .blocker()
        .unwrap_or(crate::gui::REOPEN_TO_DO_THIS))
}

fn busy_hint(ctx: &Ctx) -> String {
    ctx.t("Another task is running. Please wait for it to finish.")
}

fn virus_rows<'a>(state: &'a State, ctx: &'a Ctx) -> Vec<El<'a>> {
    let mut rows = vec![scan_row(state, ctx), defender_row(state, ctx)];
    if !matches!(state.threats, Run::Idle) {
        rows.insert(0, threats_row(state, ctx));
    }
    rows
}

fn threats_row<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    let title = ctx.t("Remove found threats");
    let again = |label: String| entry(Icon::Refresh, label, Msg::ClearThreats);
    match &state.threats {
        Run::Idle => space::horizontal().width(0).into(),
        Run::Working => busy_row(
            state,
            p,
            Icon::Bug,
            title,
            ctx.t("Removing what Windows Security found…"),
        ),
        Run::Done(Ok(result)) => {
            let (tone, headline, sub) = match logic::threats_result(result) {
                logic::ThreatsResult::Nothing => (
                    Tone::Good,
                    ctx.t("Nothing to remove"),
                    ctx.t("Windows Security reports no active threats right now."),
                ),
                logic::ThreatsResult::Removed => (
                    Tone::Good,
                    ctx.t("Harmful files removed"),
                    ctx.t("{n} removed. Windows Security usually keeps them in quarantine, where you can restore one if you need to.")
                        .replace("{n}", &result.removed.to_string()),
                ),
                logic::ThreatsResult::Partly => (
                    Tone::Warn,
                    ctx.t("Some are still there"),
                    ctx.t("{removed} removed, {left} still need you. Open Windows Security to finish.")
                        .replace("{removed}", &result.removed.to_string())
                        .replace("{left}", &result.left.to_string()),
                ),
                logic::ThreatsResult::Stuck => (
                    Tone::Warn,
                    ctx.t("We couldn't remove them"),
                    ctx.t("Open Windows Security and follow the steps there."),
                ),
            };
            finished(
                state,
                ctx,
                Outcome {
                    slot: Slot::Threats,
                    icon: Icon::Bug,
                    tone,
                    title: headline,
                    sub: Some(sub),
                    menu: open_security_entry(ctx)
                        .into_iter()
                        .chain([entry(Icon::Check, ctx.t("Done"), Msg::ClearThreats)])
                        .collect(),
                    raw: None,
                },
            )
        }
        Run::Done(Err(raw)) => finished(
            state,
            ctx,
            Outcome {
                slot: Slot::Threats,
                icon: Icon::Bug,
                tone: Tone::Warn,
                title: ctx.t("We couldn't remove them"),
                sub: Some(ctx.t("Open Windows Security and follow the steps there.")),
                menu: open_security_entry(ctx)
                    .into_iter()
                    .chain([again(ctx.t("Done"))])
                    .collect(),
                raw: Some(logic::friendly_why(raw).to_owned()),
            },
        ),
    }
}

fn scan_row<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    match &state.scan {
        Run::Idle => widgets::row_item(
            p,
            Some(Icon::Bug),
            ctx.t("Scan for viruses"),
            Some(ctx.t("Look for harmful software on your computer.")),
            secondary(p, ctx.t("Scan"), Some(Msg::Ask(Sheet::Scan))),
            None,
        ),
        Run::Working => busy_row(
            state,
            p,
            Icon::Bug,
            ctx.t("Scan for viruses"),
            ctx.t("Scanning your computer. This can take a few minutes."),
        ),
        Run::Done(Ok(())) => finished(
            state,
            ctx,
            Outcome {
                slot: Slot::Scan,
                icon: Icon::Bug,
                tone: Tone::Good,
                title: ctx.t("Scan finished"),
                sub: Some(ctx.t("Windows Security tells you if it found anything.")),
                menu: open_security_entry(ctx)
                    .into_iter()
                    .chain([entry(Icon::Check, ctx.t("Done"), Msg::ClearScan)])
                    .collect(),
                raw: None,
            },
        ),
        Run::Done(Err(raw)) => finished(
            state,
            ctx,
            Outcome {
                slot: Slot::Scan,
                icon: Icon::Bug,
                tone: Tone::Warn,
                title: ctx.t("We couldn't start the scan"),
                sub: Some(ctx.t("Open Windows Security and start a scan there.")),
                menu: open_security_entry(ctx)
                    .into_iter()
                    .chain([entry(Icon::Refresh, ctx.t("Try again"), Msg::ClearScan)])
                    .collect(),
                raw: Some(logic::friendly_why(raw).to_owned()),
            },
        ),
    }
}

fn defender_row<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    match &state.defender {
        Run::Idle => widgets::row_item(
            p,
            Some(Icon::Download),
            ctx.t("Update virus protection"),
            Some(ctx.t("Get the newest virus information.")),
            secondary(p, ctx.t("Update"), Some(Msg::Ask(Sheet::DefenderUpdate))),
            None,
        ),
        Run::Working => busy_row(
            state,
            p,
            Icon::Download,
            ctx.t("Update virus protection"),
            ctx.t("Updating…"),
        ),
        Run::Done(Ok(())) => finished(
            state,
            ctx,
            Outcome {
                slot: Slot::Defender,
                icon: Icon::Download,
                tone: Tone::Good,
                title: ctx.t("Virus protection updated"),
                sub: Some(ctx.t("Windows asked Microsoft for the newest virus information.")),
                menu: vec![entry(Icon::Check, ctx.t("Done"), Msg::ClearDefender)],
                raw: None,
            },
        ),
        Run::Done(Err(raw)) => {
            let note = logic::friendly_error(raw);
            let sub = match note {
                logic::ERR_NETWORK => ctx.t("Check your internet connection and try again."),
                logic::ERR_GENERAL => ctx.t("Try again in a few minutes. If it keeps happening, update in Windows Security instead."),
                other => ctx.t(other),
            };
            let menu = if logic::is_retryable(note) {
                vec![entry(Icon::Refresh, ctx.t("Try again"), Msg::ClearDefender)]
            } else {
                open_security_entry(ctx)
                    .into_iter()
                    .chain([entry(Icon::Check, ctx.t("Done"), Msg::ClearDefender)])
                    .collect()
            };
            finished(
                state,
                ctx,
                Outcome {
                    slot: Slot::Defender,
                    icon: Icon::Download,
                    tone: Tone::Warn,
                    title: ctx.t("We couldn't update right now"),
                    sub: Some(sub),
                    menu,
                    raw: Some(logic::friendly_why(raw).to_owned()),
                },
            )
        }
    }
}

fn keep_using<'a>(p: Palette, ctx: &Ctx) -> El<'a> {
    widgets::small(
        p,
        ctx.t("You can keep using your computer. Please don't turn it off."),
    )
}

fn stop_menu(ctx: &Ctx, stopping: bool, stop: Msg) -> Vec<MenuEntry> {
    if stopping {
        vec![]
    } else {
        vec![entry(Icon::X, ctx.t("Stop after this step"), stop)]
    }
}

fn stop_note<'a>(p: Palette, ctx: &Ctx, stopping: bool) -> El<'a> {
    if stopping {
        widgets::small(p, ctx.t("Stopping after this step…"))
    } else {
        keep_using(p, ctx)
    }
}

fn repair_row<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    match &state.repair {
        Repair::Idle => repair_idle(ctx),
        Repair::Working {
            kind,
            cancel,
            progress: pr,
        } => repair_working(ctx, *kind, cancel, pr.as_ref()),
        Repair::Done {
            kind, result, note, ..
        } => repair_done(state, ctx, *kind, *result, *note),
    }
}

fn repair_idle<'a>(ctx: &Ctx) -> El<'a> {
    let p = ctx.palette;
    let free = !ctx.busy;
    let menu = if free {
        vec![entry(
            Icon::Wrench,
            ctx.t("Repair system files"),
            Msg::Ask(Sheet::Repair(RepairKind::Repair)),
        )]
    } else {
        vec![]
    };
    widgets::row_item(
        p,
        Some(Icon::Wrench),
        ctx.t("Repair Windows"),
        Some(if free {
            ctx.t("Find and fix problems with Windows itself.")
        } else {
            busy_hint(ctx)
        }),
        trailing(vec![
            secondary(
                p,
                ctx.t("Check"),
                free.then_some(Msg::Ask(Sheet::Repair(RepairKind::Check))),
            ),
            more(p, menu),
        ]),
        None,
    )
}

fn repair_working<'a>(
    ctx: &Ctx,
    kind: RepairKind,
    cancel: &std::sync::atomic::AtomicBool,
    pr: Option<&logic::RepairProgress>,
) -> El<'a> {
    let p = ctx.palette;
    let title = match kind {
        RepairKind::Check => ctx.t("Checking for problems"),
        RepairKind::Repair => ctx.t("Repairing Windows"),
    };
    let stopping = cancel.load(std::sync::atomic::Ordering::SeqCst);
    let (ratio, label) = match pr {
        Some(pr) => (repair_ratio(pr), ctx.t(pr.label)),
        None => (0.03, ctx.t("Getting ready…")),
    };
    let mut notes = Vec::new();
    if let Some(pr) = pr {
        notes.push(widgets::small(
            p,
            format!(
                "{}  ·  {}",
                ctx.t("Step {a} of {b}")
                    .replace("{a}", &pr.step.to_string())
                    .replace("{b}", &pr.total.to_string()),
                running_for(ctx, pr.elapsed)
            ),
        ));
    }
    notes.push(stop_note(p, ctx, stopping));
    running(
        p,
        Running {
            icon: Icon::Wrench,
            title,
            sub: label,
            menu: stop_menu(ctx, stopping, Msg::StopRepair),
            bar: progress::bar_eased(p, ratio, Tone::Brand),
            notes,
        },
    )
}

fn repair_done<'a>(
    state: &'a State,
    ctx: &'a Ctx,
    kind: RepairKind,
    result: RepairResult,
    note: Option<&'static str>,
) -> El<'a> {
    let tone = match result {
        RepairResult::NoProblems | RepairResult::Repaired => Tone::Good,
        RepairResult::CouldNotFinish => Tone::Bad,
        RepairResult::ProblemsFound | RepairResult::NeedsRestart | RepairResult::Stopped => {
            Tone::Warn
        }
    };
    let detail = match (result, note) {
        (RepairResult::CouldNotFinish, Some(n)) => ctx.t(n),
        _ => ctx.t(result.detail()),
    };
    let mut menu = Vec::new();
    if result == RepairResult::ProblemsFound && kind == RepairKind::Check && !ctx.busy {
        menu.push(entry(
            Icon::Wrench,
            ctx.t("Repair system files"),
            Msg::Ask(Sheet::Repair(RepairKind::Repair)),
        ));
    }
    menu.push(entry(Icon::Check, ctx.t("Done"), Msg::ClearRepair));
    finished(
        state,
        ctx,
        Outcome {
            slot: Slot::Repair,
            icon: Icon::Wrench,
            tone,
            title: ctx.t(result.title()),
            sub: Some(detail),
            menu,
            raw: Some(logic::repair_why(result, note).to_owned()),
        },
    )
}

fn check_again(label: String) -> MenuEntry {
    entry(Icon::Refresh, label, Msg::LookForUpdates)
}

fn updates_row<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    match &state.updates {
        Updates::Idle => updates_idle(state, ctx),
        Updates::Looking => busy_row(
            state,
            ctx.palette,
            Icon::Download,
            ctx.t("Windows updates"),
            ctx.t("Looking for updates…"),
        ),
        Updates::UpToDate => finished(
            state,
            ctx,
            Outcome {
                slot: Slot::Updates,
                icon: Icon::Download,
                tone: Tone::Good,
                title: ctx.t("Your computer is up to date"),
                sub: Some(ctx.t("There are no important updates waiting.")),
                menu: vec![check_again(ctx.t("Check again"))],
                raw: None,
            },
        ),
        Updates::Found(found) => updates_found(ctx, found),
        Updates::Failed { note, .. } => updates_failed(state, ctx, note),
        Updates::Installing {
            cancel,
            stage,
            elapsed,
            count,
        } => updates_installing(ctx, cancel, *stage, *elapsed, *count),
        Updates::Done { result, note, .. } => updates_done(state, ctx, *result, *note),
    }
}

fn updates_idle<'a>(state: &State, ctx: &Ctx) -> El<'a> {
    let p = ctx.palette;
    if let Account::Blocked(note) = state.account {
        let retry = entry(Icon::Refresh, ctx.t("Try again"), Msg::CheckAccount);
        let (menu, button) = failure_steps(ctx, note, retry);
        let mut items = Vec::new();
        if let Some((label, icon, msg)) = button {
            items.push(widgets::action(
                p,
                ButtonKind::Secondary,
                label,
                Some(icon),
                Some(tools(msg)),
            ));
        }
        if !menu.is_empty() {
            items.push(more(p, menu));
        }
        return widgets::row_item_tinted(
            p,
            Some(Icon::Download),
            Some(Tone::Warn),
            ctx.t("Windows updates"),
            Some(ctx.t(note)),
            trailing(items),
            None,
        );
    }
    let free = !ctx.busy && state.account == Account::Fine;
    widgets::row_item(
        p,
        Some(Icon::Download),
        ctx.t("Windows updates"),
        Some(if free {
            ctx.t("Install important security updates.")
        } else {
            busy_hint(ctx)
        }),
        secondary(
            p,
            ctx.t("Look for updates"),
            free.then_some(Msg::LookForUpdates),
        ),
        None,
    )
}

fn updates_found<'a>(ctx: &Ctx, found: &logic::Found) -> El<'a> {
    let p = ctx.palette;
    let size = logic::size_phrase(found.total_bytes());
    let restart = ctx.t("Windows may need to restart afterwards.");
    let tail = if size.is_empty() {
        restart
    } else {
        format!(
            "{} {restart}",
            ctx.t("The download is about {size}.")
                .replace("{size}", &size)
        )
    };
    widgets::row_item_tinted(
        p,
        Some(Icon::Download),
        Some(Tone::Warn),
        count_line(ctx, found.updates.len()),
        Some(tail),
        trailing(vec![
            widgets::action(
                p,
                ButtonKind::Primary,
                ctx.t("Install updates"),
                None,
                (!ctx.busy).then(|| tools(Msg::Ask(Sheet::InstallUpdates))),
            ),
            more(p, vec![check_again(ctx.t("Check again"))]),
        ]),
        None,
    )
}

fn updates_failed<'a>(state: &'a State, ctx: &'a Ctx, note: &'static str) -> El<'a> {
    let (menu, button) = failure_steps(ctx, note, check_again(ctx.t("Try again")));
    finished_with(
        state,
        ctx,
        Outcome {
            slot: Slot::Updates,
            icon: Icon::Download,
            tone: Tone::Warn,
            title: ctx.t("We couldn't check for updates"),
            sub: Some(ctx.t(note)),
            menu,
            raw: Some(logic::why_for_note(note).to_owned()),
        },
        button,
    )
}

fn updates_installing<'a>(
    ctx: &Ctx,
    cancel: &std::sync::atomic::AtomicBool,
    stage: logic::InstallStage,
    elapsed: u64,
    count: usize,
) -> El<'a> {
    let p = ctx.palette;
    let stopping = cancel.load(std::sync::atomic::Ordering::SeqCst);
    let notes = vec![
        widgets::small(p, running_for(ctx, elapsed)),
        stop_note(p, ctx, stopping),
    ];
    running(
        p,
        Running {
            icon: Icon::Download,
            title: count_installing(ctx, count),
            sub: ctx.t(stage.label()),
            menu: stop_menu(ctx, stopping, Msg::StopInstall),
            bar: progress::bar_eased(p, stage_ratio(stage), Tone::Brand),
            notes,
        },
    )
}

fn updates_done<'a>(
    state: &'a State,
    ctx: &'a Ctx,
    result: InstallResult,
    note: Option<&'static str>,
) -> El<'a> {
    let tone = match result {
        InstallResult::Installed => Tone::Good,
        InstallResult::CouldNotFinish => Tone::Bad,
        _ => Tone::Warn,
    };
    let detail = match (result, note) {
        (InstallResult::CouldNotFinish, Some(n)) => ctx.t(n),
        _ => ctx.t(result.detail()),
    };
    let mut menu = Vec::new();
    let mut button = None;
    if let (InstallResult::CouldNotFinish, Some(n)) = (result, note) {
        if logic::suggests_windows_update(n) && ctx.can_open_pages() {
            button = Some(open_update_button(ctx));
        }
    }
    if result == InstallResult::NotConfirmed && ctx.can_open_pages() {
        menu.push(entry(
            Icon::ExternalLink,
            ctx.t("Open Windows Update"),
            Msg::Open(Shortcut::WindowsUpdate),
        ));
    }
    menu.push(entry(Icon::Check, ctx.t("Done"), Msg::ClearUpdates));
    finished_with(
        state,
        ctx,
        Outcome {
            slot: Slot::Updates,
            icon: Icon::Download,
            tone,
            title: ctx.t(result.title()),
            sub: Some(detail),
            menu,
            raw: Some(logic::install_why(result, note).to_owned()),
        },
        button,
    )
}

fn tips_summary(ctx: &Ctx, report: &logic::TipsReport) -> String {
    ctx.t("{good} checks look fine, {look} need a look and {unknown} could not be checked.")
        .replace("{good}", &report.count(logic::TipState::Good).to_string())
        .replace("{look}", &report.count(logic::TipState::Look).to_string())
        .replace(
            "{unknown}",
            &report.count(logic::TipState::Unknown).to_string(),
        )
}

fn open_update_button(ctx: &Ctx) -> (String, Icon, Msg) {
    (
        ctx.t("Open Windows Update"),
        Icon::ExternalLink,
        Msg::Open(Shortcut::WindowsUpdate),
    )
}

fn failure_steps(
    ctx: &Ctx,
    note: &str,
    retry: MenuEntry,
) -> (Vec<MenuEntry>, Option<(String, Icon, Msg)>) {
    if logic::suggests_windows_update(note) {
        let button = ctx.can_open_pages().then(|| open_update_button(ctx));
        (Vec::new(), button)
    } else if logic::is_retryable(note) {
        (vec![retry], None)
    } else {
        (Vec::new(), None)
    }
}

fn count_line(ctx: &Ctx, n: usize) -> String {
    if n == 1 {
        ctx.t("1 important update is ready to install.")
    } else {
        ctx.t("{n} important updates are ready to install.")
            .replace("{n}", &n.to_string())
    }
}

fn count_installing(ctx: &Ctx, n: usize) -> String {
    if n == 1 {
        ctx.t("Installing 1 update")
    } else {
        ctx.t("Installing {n} updates")
            .replace("{n}", &n.to_string())
    }
}

fn tips_block<'a>(state: &'a State, ctx: &'a Ctx) -> Vec<El<'a>> {
    if let Tips::Running(profile) = &state.tips {
        return vec![tips_running(ctx, *profile)];
    }
    let mut out = vec![tips_picker(state, ctx)];
    if let Tips::Done(report) = &state.tips {
        out.extend(tips_lists(state, ctx, report));
    }
    out
}

fn tips_running<'a>(ctx: &Ctx, profile: TipProfile) -> El<'a> {
    let p = ctx.palette;
    widgets::row_item_below(
        p,
        Some(Icon::ShieldCheck),
        ctx.t("Looking at your computer…"),
        Some(format!(
            "{}  ·  {}",
            ctx.t(profile.title()),
            ctx.t("This can take about a minute.")
        )),
        iced::widget::space::horizontal().width(0),
        vec![progress::indeterminate(p, Tone::Brand)],
        None,
    )
}

fn tips_picker<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    let profiles: Vec<(TipProfile, String)> = TipProfile::ALL
        .iter()
        .map(|t| (*t, ctx.t(t.title())))
        .collect();
    let picker: El<'a> = container(widgets::segmented(p, &profiles, state.tip_choice, |t| {
        tools(Msg::TipChoice(t))
    }))
    .max_width(theme::CONTENT_MAX)
    .into();
    let done = matches!(state.tips, Tips::Done(_));
    let mut items = vec![secondary(
        p,
        if done {
            ctx.t("Check again")
        } else {
            ctx.t("Check")
        },
        Some(Msg::PickTips(state.tip_choice)),
    )];
    if let Tips::Done(report) = &state.tips {
        items.push(more(
            p,
            vec![more_details(
                ctx,
                &ctx.t("What do you use this computer for?"),
                &tips_summary(ctx, report),
            )],
        ));
    }
    let blurb = widgets::small(p, ctx.t(state.tip_choice.blurb()));
    let below = vec![picker, blurb];
    widgets::row_item_below(
        p,
        Some(Icon::ShieldCheck),
        ctx.t("What do you use this computer for?"),
        Some(ctx.t("This only looks at your computer. Nothing is changed.")),
        trailing(items),
        below,
        None,
    )
}

fn tips_lists<'a>(state: &'a State, ctx: &'a Ctx, report: &logic::TipsReport) -> Vec<El<'a>> {
    let p = ctx.palette;
    let scanning = matches!(state.scan, Run::Working);
    let threats_busy = matches!(state.threats, Run::Working);
    let (needs, fine): (Vec<&logic::Tip>, Vec<&logic::Tip>) = report
        .tips
        .iter()
        .partition(|tip| tip.state != TipState::Good);
    let rows = |tips: &[&logic::Tip]| -> El<'a> {
        column(
            tips.iter()
                .map(|tip| tip_row(ctx, tip, scanning, threats_busy)),
        )
        .spacing(theme::S1)
        .width(Length::Fill)
        .into()
    };
    let mut out = Vec::new();
    if !needs.is_empty() {
        out.push(widgets::collapsible(
            p,
            ctx.t("Needs a look"),
            Some(count_text(ctx, needs.len())),
            !state.detail_open(Detail::TipsList),
            tools(Msg::ToggleDetail(Detail::TipsList)),
            rows(&needs),
        ));
    }
    if !fine.is_empty() {
        out.push(widgets::collapsible(
            p,
            ctx.t("All good"),
            Some(count_text(ctx, fine.len())),
            state.detail_open(Detail::TipsGood),
            tools(Msg::ToggleDetail(Detail::TipsGood)),
            rows(&fine),
        ));
    }
    out
}

fn count_text(ctx: &Ctx, n: usize) -> String {
    if n == 1 {
        ctx.t("1 item")
    } else {
        ctx.t("{n} items").replace("{n}", &n.to_string())
    }
}

fn tip_row<'a>(ctx: &Ctx, tip: &logic::Tip, scanning: bool, threats_busy: bool) -> El<'a> {
    let p = ctx.palette;
    let fix = logic::tip_fix(tip, ctx.report.as_deref(), &ctx.catalog.available);
    let (advice, guide) = logic::tip_words(tip, fix);
    let (tone, icon, words) = match tip.state {
        TipState::Good => (Tone::Good, Icon::CheckCircle, ctx.t("Looks good")),
        TipState::Look => (Tone::Warn, Icon::AlertTriangle, ctx.t(advice)),
        TipState::Unknown => (Tone::Neutral, Icon::Info, ctx.t("We couldn't check this")),
    };
    let action: El<'a> = match logic::tip_action(tip, fix, ctx.can_open_pages()) {
        logic::TipAction::ReviewFix(id) => widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("Review fix"),
            Some(Icon::ShieldCheck),
            (!ctx.busy && ctx.checking.is_none() && ctx.check_error.is_none())
                .then_some(Message::ReviewFixes(vec![id.to_owned()])),
        ),
        logic::TipAction::SeeWhy => widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("See why"),
            None,
            Some(Message::Navigate(Page::Fixes)),
        ),
        logic::TipAction::CheckNow => widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("Check my computer"),
            Some(Icon::Refresh),
            (!ctx.busy && ctx.checking.is_none()).then_some(Message::CheckNow),
        ),
        logic::TipAction::RestartNow => {
            secondary(p, ctx.t("Restart now"), Some(Msg::Ask(Sheet::Restart)))
        }
        logic::TipAction::RemoveThreats => secondary(
            p,
            ctx.t("Remove"),
            (!threats_busy && !ctx.busy).then_some(Msg::Ask(Sheet::RemoveThreats)),
        ),
        logic::TipAction::StartRenewal { bitlocker } => secondary(
            p,
            ctx.t("Renew now"),
            (!ctx.busy).then_some(Msg::Ask(Sheet::Renewal { bitlocker })),
        ),
        logic::TipAction::Scan => secondary(
            p,
            if scanning {
                ctx.t("Scanning…")
            } else {
                ctx.t("Scan now")
            },
            (!scanning).then_some(Msg::Ask(Sheet::Scan)),
        ),
        logic::TipAction::Open(open) => {
            let label =
                crate::guide::Page::from_action(open).map_or("Open", crate::guide::Page::button);
            widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t(label),
                Some(Icon::ExternalLink),
                Some(tools(Msg::OpenAction(open))),
            )
        }
        logic::TipAction::Steps | logic::TipAction::None => space::horizontal().width(0).into(),
    };
    let head = widgets::row_item_tinted(
        p,
        Some(icon),
        Some(tone),
        ctx.t(tip.title),
        (tip.state != TipState::Good).then(|| words.clone()),
        action,
        None,
    );
    let head = match (guide, tip.state) {
        (Some(g), TipState::Look) => column![
            head,
            crate::gui::pages::fixes::guide_block(ctx, g, widgets::INDENT, ctx.can_open_pages())
        ]
        .spacing(theme::S1)
        .into(),
        _ => head,
    };
    let sheet = tip
        .explain
        .as_deref()
        .and_then(|id| widgets::info::for_check(ctx, ctx.t(tip.title), id, true))
        .map(|s| s.without(&[words.as_str()]));
    match widgets::info::button(ctx, sheet) {
        Some(info) => row![head, info]
            .spacing(theme::S1)
            .align_y(Alignment::Center)
            .into(),
        None => head,
    }
}

fn bitwarden_offer_row<'a>(ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    let has_broker = ctx.broker.is_some();
    let not_here = ctx.helper == Helper::NotOnThisAccount;
    widgets::row_item(
        p,
        Some(Icon::Lock),
        ctx.t("Password manager"),
        Some(if has_broker {
            ctx.t("Makes strong passwords and keeps them all safe in one place.")
        } else if not_here {
            format!(
                "{} {}",
                helper_hint(ctx),
                ctx.t("You can get it from bitwarden.com instead.")
            )
        } else {
            helper_hint(ctx)
        }),
        secondary(
            p,
            ctx.t("Install"),
            has_broker.then_some(Msg::Ask(Sheet::Bitwarden)),
        ),
        None,
    )
}

fn manager_row<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    match &state.bitwarden {
        Run::Idle if state.bitwarden_present => widgets::row_item(
            p,
            Some(Icon::Lock),
            ctx.t("Bitwarden is installed"),
            Some(ctx.t("Find it in your Start menu.")),
            anim::check_draw(MARK, p.tone(Tone::Good), 1.0),
            None,
        ),
        Run::Idle if state.bitwarden_not_here => widgets::row_item(
            p,
            Some(Icon::Lock),
            ctx.t("Bitwarden can't be installed from this account"),
            Some(ctx.t("You can get it from bitwarden.com instead.")),
            anim::warn_draw(MARK, p.tone(Tone::Warn), 1.0),
            None,
        ),
        Run::Idle => bitwarden_offer_row(ctx),
        Run::Working => busy_row(
            state,
            p,
            Icon::Lock,
            ctx.t("Password manager"),
            ctx.t("Installing Bitwarden. This can take a few minutes."),
        ),
        Run::Done(Ok(())) => finished(
            state,
            ctx,
            Outcome {
                slot: Slot::Bitwarden,
                icon: Icon::Lock,
                tone: Tone::Good,
                title: ctx.t("Bitwarden is installed"),
                sub: Some(ctx.t("Find it in your Start menu.")),
                menu: vec![entry(Icon::Check, ctx.t("Done"), Msg::ClearBitwarden)],
                raw: None,
            },
        ),
        Run::Done(Err(_)) if state.bitwarden_why == Some(broker::Reply::Unavailable) => finished(
            state,
            ctx,
            Outcome {
                slot: Slot::Bitwarden,
                icon: Icon::Lock,
                tone: Tone::Warn,
                title: ctx.t("Bitwarden can't be installed from this account"),
                sub: Some(ctx.t("You can get it from bitwarden.com instead.")),
                menu: vec![entry(Icon::Check, ctx.t("Done"), Msg::ClearBitwarden)],
                raw: Some(logic::WHY_BITWARDEN_UNAVAILABLE.to_owned()),
            },
        ),
        Run::Done(Err(_)) if state.bitwarden_why == Some(broker::Reply::Offline) => finished_with(
            state,
            ctx,
            Outcome {
                slot: Slot::Bitwarden,
                icon: Icon::Lock,
                tone: Tone::Warn,
                title: ctx.t("We couldn't install Bitwarden"),
                sub: Some(ctx.t("You're offline. Connect to the internet and try again.")),
                menu: vec![entry(Icon::X, ctx.t("Done"), Msg::ClearBitwarden)],
                raw: Some(logic::WHY_BITWARDEN_OFFLINE.to_owned()),
            },
            Some((ctx.t("Retry"), Icon::Refresh, Msg::Ask(Sheet::Bitwarden))),
        ),
        Run::Done(Err(raw)) => finished(
            state,
            ctx,
            Outcome {
                slot: Slot::Bitwarden,
                icon: Icon::Lock,
                tone: Tone::Bad,
                title: ctx.t("We couldn't install Bitwarden"),
                sub: Some(ctx.t("Check your internet connection and try again. You can also get it from bitwarden.com.")),
                menu: vec![entry(
                    Icon::Refresh,
                    ctx.t("Try again"),
                    Msg::ClearBitwarden,
                )],
                raw: Some(logic::bitwarden_why(raw).to_owned()),
            },
        ),
    }
}

fn shortcut_rows<'a>(ctx: &'a Ctx, which: &[Shortcut]) -> Vec<El<'a>> {
    let p = ctx.palette;
    let available = ctx.can_open_pages();
    let mut rows: Vec<El<'a>> = which
        .iter()
        .map(|&shortcut| {
            let (icon, title, desc) = match shortcut {
                Shortcut::WindowsUpdate => (
                    Icon::Download,
                    "Windows Update",
                    "See and install Windows updates",
                ),
                Shortcut::WindowsSecurity => (
                    Icon::Shield,
                    "Windows Security",
                    "Virus protection and firewall",
                ),
                Shortcut::Encryption => (
                    Icon::Lock,
                    "Device encryption",
                    "Keep your files private if your computer is lost",
                ),
                Shortcut::SignIn => (
                    Icon::Key,
                    "Sign-in options",
                    "PIN, fingerprint and password",
                ),
            };
            widgets::row_item(
                p,
                Some(icon),
                ctx.t(title),
                Some(ctx.t(desc)),
                widgets::icon(Icon::ExternalLink, 16.0, p.text_muted),
                available.then_some(tools(Msg::Open(shortcut))),
            )
        })
        .collect();
    if !available {
        rows.push(
            container(widgets::small(p, helper_hint(ctx)))
                .padding([0.0, theme::S4])
                .into(),
        );
    }
    rows
}

type SheetText = (Icon, String, Vec<String>, String);

fn sheet_text(state: &State, ctx: &Ctx, sheet: Sheet) -> SheetText {
    let (icon, title, lines, confirm) = sheet_copy(sheet);
    let title = match sheet {
        Sheet::InstallUpdates => {
            let n = match &state.updates {
                Updates::Found(f) => f.updates.len(),
                _ => 0,
            };
            if n == 1 {
                ctx.t("Install 1 update?")
            } else {
                ctx.t("Install {n} updates?").replace("{n}", &n.to_string())
            }
        }
        _ => ctx.t(title),
    };
    (
        icon,
        title,
        lines.iter().map(|l| ctx.t(l)).collect(),
        ctx.t(confirm),
    )
}

pub(super) type SheetCopy = (Icon, &'static str, &'static [&'static str], &'static str);

/// English source of each confirmation sheet. The install sheet's title is built from the update count.
pub(super) fn sheet_copy(sheet: Sheet) -> SheetCopy {
    match sheet {
        Sheet::Scan => (
            Icon::Bug,
            "Scan for viruses?",
            &[
                "Windows Security will check your computer for harmful software.",
                "If it finds something, it removes it or puts it somewhere safe.",
                "You can keep using your computer.",
            ],
            "Start scan",
        ),
        Sheet::RemoveThreats => (
            Icon::Bug,
            "Remove the harmful files?",
            &[
                "Windows Security will remove the harmful files it has found on this computer.",
                "This can't be undone from Secblitz. Windows Security usually keeps what it removes in quarantine. If it was a mistake, you can restore an item there.",
                "You can keep using your computer while it works.",
            ],
            "Remove them",
        ),
        Sheet::Renewal { bitlocker } => (
            Icon::ShieldCheck,
            "Renew your computer's startup security?",
            if bitlocker {
                &[
                    "This can't be undone.",
                    "It finishes the next time you restart your computer. Secblitz never restarts your computer for you.",
                    "Your computer may ask for your BitLocker recovery key once after the restart. Make sure you can find it before you continue.",
                ]
            } else {
                &[
                    "This can't be undone.",
                    "It finishes the next time you restart your computer. Secblitz never restarts your computer for you.",
                ]
            },
            "Renew now",
        ),
        Sheet::DefenderUpdate => (
            Icon::Download,
            "Update virus protection?",
            &["Windows will download the newest virus information from Microsoft."],
            "Update now",
        ),
        Sheet::Repair(RepairKind::Check) => (
            Icon::Wrench,
            "Check for problems?",
            &[
                "Secblitz will look at Windows for damage. Nothing is changed.",
                "This can take a few minutes. You can keep using your computer.",
            ],
            "Start check",
        ),
        Sheet::Repair(RepairKind::Repair) => (
            Icon::Wrench,
            "Repair system files?",
            &[
                "Secblitz will look for damaged Windows files and replace them with good copies.",
                "This can take 15–45 minutes. You can keep using your computer.",
                "Your own files and apps are not touched. This can't be undone automatically, but it only fixes files that belong to Windows.",
            ],
            "Repair now",
        ),
        Sheet::InstallUpdates => (
            Icon::Download,
            "Install updates?",
            &[
                "These updates come from Microsoft and protect your computer.",
                "This can take a while. You can keep using your computer, but save your work first because Windows may need to restart.",
                "Updates can't be undone automatically. By continuing you accept Microsoft's license terms for them.",
            ],
            "Install now",
        ),
        Sheet::Restart => (
            Icon::Restart,
            "Restart your computer now?",
            &[
                "Your computer restarts to finish installing updates.",
                "Save your work first. Programs with unsaved work will ask you before they close.",
            ],
            "Restart now",
        ),
        Sheet::Bitwarden => (
            Icon::Lock,
            "Install Bitwarden?",
            &[
                "Bitwarden is a free password manager.",
                "Secblitz will download it from its official source and install it for you.",
                "You can remove it later in Windows Settings.",
            ],
            "Install",
        ),
    }
}

/// Lines of a confirmation sheet that are read in full: they tell what the person must know before they agree.
pub(super) fn whole_lines(sheet: Sheet) -> &'static [usize] {
    match sheet {
        Sheet::Renewal { .. } => &[0, 1, 2],
        Sheet::Repair(RepairKind::Repair) => &[2],
        Sheet::InstallUpdates => &[1, 2],
        _ => &[],
    }
}

fn install_updates_extra<'a>(ctx: &'a Ctx, found: &logic::Found) -> Vec<El<'a>> {
    let p = ctx.palette;
    let mut list = column![].spacing(theme::S2);
    for u in found.updates.iter().take(5) {
        list = list.push(
            row![
                widgets::icon(Icon::Check, 14.0, p.good),
                text(u.title.clone())
                    .size(theme::SMALL)
                    .color(p.text)
                    .width(Length::Fill)
            ]
            .spacing(theme::S2)
            .align_y(Alignment::Center),
        );
    }
    if found.updates.len() > 5 {
        list = list.push(widgets::small(
            p,
            ctx.t("and {n} more")
                .replace("{n}", &(found.updates.len() - 5).to_string()),
        ));
    }
    let mut raw = ctx.t("These updates come from Microsoft through Windows Update.");
    let mut seen: Vec<&str> = Vec::new();
    for u in &found.updates {
        if !u.license.is_empty() && !seen.contains(&u.license.as_str()) {
            seen.push(&u.license);
            raw.push('\n');
            raw.push_str(&u.license);
        }
    }
    if raw.len() > 4000 {
        raw.truncate(raw.floor_char_boundary(4000));
    }
    vec![list.into(), details(ctx, &ctx.t("Install updates"), &raw)]
}

fn sheet_panel<'a>(state: &'a State, ctx: &'a Ctx, sheet: Sheet) -> El<'a> {
    let p = ctx.palette;
    let (icon, title, lines, confirm_label) = sheet_text(state, ctx, sheet);
    let mut content = column![row![
        widgets::icon(icon, theme::ICON_ROW, p.text_muted),
        widgets::h2(p, title)
    ]
    .spacing(theme::S3)
    .align_y(Alignment::Center)]
    .spacing(theme::S3)
    .width(Length::Fill);
    let whole = whole_lines(sheet);
    for (i, line) in lines.into_iter().enumerate() {
        content = content.push(if whole.contains(&i) {
            widgets::body(p, line)
        } else {
            let key = format!("line:{i}");
            point::text_point(
                p,
                &line,
                Words::Body,
                state.points.has(&key),
                tools(Msg::Point(key)),
            )
        });
    }
    if !sheet.notices().undoable {
        content = content.push(
            row![
                widgets::icon(Icon::AlertTriangle, 16.0, p.tone(Tone::Warn)),
                widgets::body(p, ctx.t("Can't be undone"))
            ]
            .spacing(theme::S2)
            .align_y(Alignment::Center),
        );
    }
    if let Some(note) = state.sheet_block {
        content = content.push(
            row![
                widgets::icon(Icon::AlertTriangle, 16.0, p.tone(Tone::Warn)),
                widgets::body(p, ctx.t(note))
            ]
            .spacing(theme::S2)
            .align_y(Alignment::Center),
        );
    }
    if sheet == (Sheet::Renewal { bitlocker: true }) {
        content = content.push(widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("Find my recovery key"),
            Some(Icon::ExternalLink),
            Some(tools(Msg::OpenRecoveryKey)),
        ));
    }
    if sheet == Sheet::InstallUpdates {
        if let Updates::Found(found) = &state.updates {
            for item in install_updates_extra(ctx, found) {
                content = content.push(item);
            }
        }
    }
    let footer = row![
        space::horizontal(),
        widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("Cancel"),
            None,
            Some(tools(Msg::CloseSheet)),
        ),
        widgets::action(
            p,
            ButtonKind::Primary,
            confirm_label,
            None,
            (!state.sheet_checking).then(|| tools(Msg::Confirm)),
        ),
    ]
    .spacing(theme::S2);
    column![content, footer]
        .spacing(theme::S6)
        .width(Length::Fill)
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    fn renewal_sheet(lang: Lang, bitlocker: bool) -> (String, Vec<String>, String) {
        let (app, _) = crate::gui::App::new(crate::gui::Options {
            lang,
            broker: None,
            start: None,
        });
        let (_, title, lines, confirm) =
            sheet_text(&app.tools, &app.ctx, Sheet::Renewal { bitlocker });
        (title, lines, confirm)
    }

    #[test]
    fn the_renewal_sheet_says_it_cannot_be_undone_and_needs_a_restart_before_the_yes() {
        let (_, lines, confirm) = renewal_sheet(Lang::En, false);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("can't be undone"));
        assert!(lines[1].contains("restart") && lines[1].contains("never restarts"));
        assert_eq!(confirm, "Renew now");
        assert!(lines.iter().all(|l| !l.contains('\u{2014}')));
    }

    #[test]
    fn the_recovery_key_line_shows_only_when_bitlocker_is_on() {
        let (_, plain, _) = renewal_sheet(Lang::En, false);
        let (_, locked, _) = renewal_sheet(Lang::En, true);
        assert_eq!(locked.len(), plain.len() + 1);
        assert!(locked[2].contains("BitLocker recovery key"));
    }

    #[test]
    fn every_language_has_the_three_lines() {
        for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            let (en_title, en, _) = renewal_sheet(Lang::En, true);
            let (title, lines, _) = renewal_sheet(lang, true);
            assert_ne!(title, en_title, "{lang:?}");
            assert_eq!(lines.len(), 3);
            for (line, english) in lines.iter().zip(&en) {
                assert_ne!(line, english, "{lang:?}");
            }
        }
    }
}
