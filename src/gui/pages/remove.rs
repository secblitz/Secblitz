//! Removing Secblitz itself, never any other app: one sheet that asks what should happen to
//! the changes Secblitz made, optionally puts everything back (with progress), and then
//! starts the uninstaller. Opened from the last group on the Settings page.
use crate::broker::{Reply, Request};
use crate::gui::pages::settings;
use crate::gui::theme::Tone;
use crate::gui::widgets::anim;
use crate::gui::widgets::point::Opened;
use crate::gui::{blocking, blocking_stream, Ctx, Helper, Message};
use crate::i18n::Lang;
use crate::uninstall::{Left, Plan};
use iced::{Element, Subscription, Task};
use secblitz::user_settings::{Op, Setting};
use std::path::PathBuf;
use std::time::Instant;

type El<'a> = Element<'a, Message>;

pub const SECTION_TITLE: &str = "Remove Secblitz";
pub const SECTION_ROW: &str = "Remove Secblitz from this computer";
pub const SECTION_HELP: &str = "You choose whether your settings stay as they are or go back.";
const QUESTION: &str = "What should happen to the changes Secblitz made?";
const NOTHING_TO_PUT_BACK: &str = "Nothing Secblitz changed needs to be put back.";
const KEEP_TITLE: &str = "Keep my computer as it is now";
const KEEP_HELP: &str = "Your protection stays on, and apps you removed stay removed.";
const PUT_BACK_TITLE: &str = "Put everything back the way it was";
const STAY_NOTE: &str = "Windows updates, virus scans and apps you installed with Secblitz stay.";
const WEB_STOPS: &str = "Web protection stops too, because it is part of Secblitz.";
const KEEP_DELETES_COPIES: &str = "The saved copies of removed apps are deleted to free space, so those apps can then only come back from the Microsoft Store.";
const OWN_ACCOUNT_ONLY: &str =
    "Personal settings are put back for your account only. Other accounts on this computer keep theirs.";
const STORE_NEEDS_INTERNET: &str = "Apps without a saved copy download again from the Microsoft Store, which needs an internet connection. They can take a few minutes to show up in Start.";
const CANCEL: &str = "Cancel";
const LOADING: &str = "Looking at what Secblitz changed…";
const WORKING_TITLE: &str = "Putting everything back…";
const WORKING_HELP: &str = "Please keep this window open. This can take a few minutes.";
const STEP_WAITING: &str = "Waiting";
const STEP_RUNNING: &str = "Putting back…";
const STEP_DONE: &str = "Put back";
const STEP_PARTLY: &str = "Some were left as they are";
const ITEM_PERSONAL: &str = "Your personal settings";
const ITEM_SETTINGS: &str = "Windows settings";
const ITEM_APPS: &str = "Removed apps";
const ITEM_SUGGESTED: &str = "Suggested apps";
const ITEM_WEB: &str = "Web protection";
#[cfg_attr(not(windows), allow(dead_code))]
const WEB_LEFT: &str = "Web protection could not be turned off. Close Secblitz, open it again and try once more. If it still does not work, check for a Secblitz update.";
const RESULT_LEFT_TITLE: &str = "Some things could not be put back";
const RESULT_LEFT_HELP: &str =
    "These are left as they are. You can remove Secblitz anyway, or keep it and try again later.";
const RESULT_DONE_TITLE: &str = "Everything is back the way it was";
const DELETE_EXE: &str = "You can now delete secblitz.exe.";
const REMOVE_ANYWAY: &str = "Remove Secblitz anyway";
const KEEP_SECBLITZ: &str = "Keep Secblitz";
const CLOSE: &str = "Close";
const LEAVING_TITLE: &str = "Removing Secblitz…";
const LEAVING_HELP: &str = "This window closes by itself.";
const CANNOT_START: &str = "We couldn't start the removal. Secblitz was not removed. Close Secblitz, open it again and try once more. If that does not work, restart your computer.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Keep,
    PutBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item {
    Personal,
    Settings,
    Apps,
    Suggested,
    Web,
}

impl Item {
    pub const ALL: [Item; 5] = [
        Item::Personal,
        Item::Settings,
        Item::Apps,
        Item::Suggested,
        Item::Web,
    ];

    fn index(self) -> usize {
        Self::ALL.iter().position(|i| *i == self).unwrap_or(0)
    }

    fn label(self) -> &'static str {
        match self {
            Item::Personal => ITEM_PERSONAL,
            Item::Settings => ITEM_SETTINGS,
            Item::Apps => ITEM_APPS,
            Item::Suggested => ITEM_SUGGESTED,
            Item::Web => ITEM_WEB,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Waiting,
    Working,
    Done(bool, Instant),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub changes: usize,
    pub apps: usize,
}

pub fn counts(plan: Option<&Plan>, safe: &[Setting]) -> Option<Counts> {
    let plan = plan?;
    Some(Counts {
        changes: plan.settings
            + safe.len()
            + usize::from(plan.suggested && !safe.contains(&Setting::SuggestedApps)),
        apps: plan.apps_with_copy + plan.apps_store_only,
    })
}

pub fn keep_note(plan: Option<&Plan>) -> Option<(Tone, &'static str)> {
    let plan = plan?;
    match plan.apps_copy_only {
        0 if plan.apps_with_copy > 0 => Some((Tone::Neutral, KEEP_DELETES_COPIES)),
        0 => None,
        1 => Some((Tone::Warn, "The saved copies of removed apps are deleted to free space. {n} of these apps is not in the Microsoft Store, so it can't come back after this. To keep it, bring it back first in Clean up apps.")),
        _ => Some((Tone::Warn, "The saved copies of removed apps are deleted to free space. {n} of these apps are not in the Microsoft Store, so they can't come back after this. To keep them, bring them back first in Clean up apps.")),
    }
}

pub fn web_note(plan: Option<&Plan>) -> Option<&'static str> {
    plan.is_some_and(|p| p.web_on).then_some(WEB_STOPS)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Personal,
    StoreApps(usize),
}

pub fn limits(helper: Helper, plan: Option<&Plan>) -> Vec<Limit> {
    if helper == Helper::Ready {
        return Vec::new();
    }
    let mut out = vec![Limit::Personal];
    if let Some(n) = plan.map(|p| p.apps_store_only).filter(|n| *n > 0) {
        out.push(Limit::StoreApps(n));
    }
    out
}

pub fn limit_key(helper: Helper, limit: Limit) -> &'static str {
    match (helper, limit) {
        (Helper::Reopen, Limit::Personal) => "Settings Secblitz changed for your own account can't be put back right now. Close Secblitz and open it again from its Start menu shortcut to include them.",
        (Helper::Reopen, Limit::StoreApps(1)) => "{n} removed app has no saved copy, so it can't be brought back right now. Close Secblitz and open it again from its Start menu shortcut to include it.",
        (Helper::Reopen, Limit::StoreApps(_)) => "{n} removed apps have no saved copy, so they can't be brought back right now. Close Secblitz and open it again from its Start menu shortcut to include them.",
        (_, Limit::Personal) => "Windows doesn't let Secblitz put back settings for your own account from the built-in Administrator account or when account protection (UAC) is off. They stay as they are.",
        (_, Limit::StoreApps(1)) => "{n} removed app has no saved copy, and Windows doesn't let Secblitz get it from the Microsoft Store from this account. You can install it from the Microsoft Store yourself.",
        (_, Limit::StoreApps(_)) => "{n} removed apps have no saved copy, and Windows doesn't let Secblitz get them from the Microsoft Store from this account. You can install them from the Microsoft Store yourself.",
    }
}

pub fn can_put_back(counts: Option<Counts>) -> bool {
    counts.is_none_or(|c| c.changes > 0 || c.apps > 0)
}

pub fn choices(can_put_back: bool, installed: bool) -> Vec<Choice> {
    match (installed, can_put_back) {
        (true, true) => vec![Choice::Keep, Choice::PutBack],
        (true, false) => vec![Choice::Keep],
        (false, true) => vec![Choice::PutBack],
        (false, false) => Vec::new(),
    }
}

pub fn put_back_key(counts: Option<Counts>) -> &'static str {
    let Some(Counts { changes, apps }) = counts else {
        return "Secblitz undoes the changes it made and brings back the apps you removed first. This can take a few minutes.";
    };
    match (changes, apps) {
        (0, 0) => "",
        (0, 1) => "Secblitz brings back {apps} removed app first. This can take a few minutes.",
        (0, _) => "Secblitz brings back {apps} removed apps first. This can take a few minutes.",
        (1, 0) => "Secblitz undoes its {n} change first. This can take a few minutes.",
        (_, 0) => "Secblitz undoes its {n} changes first. This can take a few minutes.",
        (1, 1) => "Secblitz undoes its {n} change and brings back {apps} removed app first. This can take a few minutes.",
        (1, _) => "Secblitz undoes its {n} change and brings back {apps} removed apps first. This can take a few minutes.",
        (_, 1) => "Secblitz undoes its {n} changes and brings back {apps} removed app first. This can take a few minutes.",
        (_, _) => "Secblitz undoes its {n} changes and brings back {apps} removed apps first. This can take a few minutes.",
    }
}

fn put_back_text(lang: Lang, counts: Option<Counts>) -> String {
    let c = counts.unwrap_or(Counts {
        changes: 0,
        apps: 0,
    });
    lang.t(put_back_key(counts))
        .replace("{n}", &c.changes.to_string())
        .replace("{apps}", &c.apps.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    PutBack,
    Remove,
    Nothing,
}

pub fn start(choice: Choice, installed: bool) -> Start {
    match (choice, installed) {
        (Choice::PutBack, _) => Start::PutBack,
        (Choice::Keep, true) => Start::Remove,
        (Choice::Keep, false) => Start::Nothing,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    Remove,
    ShowResult,
}

pub fn finish(lines: &[String], installed: bool) -> Finish {
    if lines.is_empty() && installed {
        Finish::Remove
    } else {
        Finish::ShowResult
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultAction {
    RemoveAnyway,
    Keep,
    Close,
}

pub fn result_actions(installed: bool) -> Vec<ResultAction> {
    if installed {
        vec![ResultAction::Keep, ResultAction::RemoveAnyway]
    } else {
        vec![ResultAction::Close]
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn prune_apps(left: Vec<Left>, still_removed: &[String]) -> Vec<Left> {
    left.into_iter()
        .filter(|l| match l {
            Left::App { name } | Left::AppNeedsStore { name } => still_removed.contains(name),
            _ => true,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
enum Sheet {
    Closed,
    Loading {
        plan: Option<Option<Plan>>,
        waiting: usize,
        safe: Vec<Setting>,
    },
    Choose {
        plan: Option<Plan>,
        safe: Vec<Setting>,
        choice: Option<Choice>,
    },
    Working {
        steps: [StepState; 5],
    },
    Result {
        lines: Vec<String>,
        at: Instant,
    },
    Leaving,
}

#[derive(Debug)]
pub struct State {
    sheet: Sheet,
    installed: bool,
    generation: u32,
    spin: anim::Clock,
    now: Instant,
    since: Instant,
    points: Opened,
}

impl Default for State {
    fn default() -> Self {
        State {
            sheet: Sheet::Closed,
            installed: false,
            generation: 0,
            spin: anim::Clock::new(),
            now: Instant::now(),
            since: Instant::now(),
            points: Opened::default(),
        }
    }
}

impl State {
    fn settle(&mut self) {
        if let Sheet::Loading {
            plan: Some(plan),
            waiting: 0,
            safe,
        } = &mut self.sheet
        {
            let choices = choices(can_put_back(counts(plan.as_ref(), safe)), self.installed);
            self.sheet = Sheet::Choose {
                plan: plan.take(),
                safe: std::mem::take(safe),
                choice: (choices.len() == 1).then(|| choices[0]),
            };
        }
    }

    fn on_planned(&mut self, generation: u32, plan: Result<Plan, String>) {
        if generation != self.generation {
            return;
        }
        if let Sheet::Loading { plan: slot, .. } = &mut self.sheet {
            *slot = Some(plan.ok());
        }
        self.settle();
    }

    fn on_queried(&mut self, generation: u32, setting: Setting, reply: Result<Reply, String>) {
        if generation != self.generation {
            return;
        }
        if let Sheet::Loading { waiting, safe, .. } = &mut self.sheet {
            *waiting = waiting.saturating_sub(1);
            if matches!(reply, Ok(Reply::SafeByUs)) {
                safe.push(setting);
            }
        }
        self.settle();
    }

    fn pick(&mut self, picked: Choice) {
        if let Sheet::Choose { plan, safe, choice } = &mut self.sheet {
            if choices(can_put_back(counts(plan.as_ref(), safe)), self.installed).contains(&picked)
            {
                *choice = Some(picked);
            }
        }
    }

    fn on_event(&mut self, event: Event, now: Instant) {
        self.now = now;
        match event {
            Event::Started(item) => {
                if let Sheet::Working { steps } = &mut self.sheet {
                    steps[item.index()] = StepState::Working;
                }
            }
            Event::Finished(item, ok) => {
                if let Sheet::Working { steps } = &mut self.sheet {
                    steps[item.index()] = StepState::Done(ok, now);
                }
            }
            Event::Done(_) => {}
        }
    }

    fn finished_steps(&self) -> usize {
        match &self.sheet {
            Sheet::Working { steps } => steps
                .iter()
                .filter(|s| matches!(s, StepState::Done(..)))
                .count(),
            _ => 0,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Started(Item),
    Finished(Item, bool),
    Done(Vec<String>),
}

#[derive(Debug, Clone)]
pub enum Msg {
    Open,
    Cancel,
    Planned(u32, Result<Plan, String>),
    Queried(u32, Setting, Result<Reply, String>),
    Pick(Choice),
    Confirm,
    Event(Event),
    RemoveAnyway,
    Spawned(bool),
    Frame(Instant),
    Point(String),
}

fn wrap(msg: Msg) -> Message {
    Message::Settings(settings::Msg::Remove(msg))
}

mod system;
#[cfg(test)]
use system::put_back_left;
pub use system::uninstaller;
use system::{launch_uninstaller, load_plan, run_put_back};

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    let task = apply(state, msg, ctx);
    if matches!(state.sheet, Sheet::Closed) {
        state.points.clear();
    }
    task
}

fn apply(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    match msg {
        Msg::Point(key) => {
            if !matches!(state.sheet, Sheet::Closed) {
                state.points.toggle(&key);
            }
            Task::none()
        }
        Msg::Open => {
            if ctx.busy || !matches!(state.sheet, Sheet::Closed) {
                return Task::none();
            }
            state.installed = uninstaller().is_some();
            state.generation = state.generation.wrapping_add(1);
            state.now = Instant::now();
            state.spin = anim::Clock::at(state.now);
            let generation = state.generation;
            let ask = if ctx.broker.is_some() {
                Setting::ALL.to_vec()
            } else {
                Vec::new()
            };
            state.sheet = Sheet::Loading {
                plan: None,
                waiting: ask.len(),
                safe: Vec::new(),
            };
            let mut tasks = vec![Task::perform(blocking(load_plan), move |r| {
                wrap(Msg::Planned(generation, r))
            })];
            for setting in ask {
                tasks.push(
                    ctx.broker_task(Request::UserSetting(setting, Op::Query), move |r| {
                        wrap(Msg::Queried(generation, setting, r))
                    }),
                );
            }
            Task::batch(tasks)
        }
        Msg::Cancel => {
            close(state);
            Task::none()
        }
        Msg::Planned(generation, plan) => {
            state.on_planned(generation, plan);
            Task::none()
        }
        Msg::Queried(generation, setting, reply) => {
            state.on_queried(generation, setting, reply);
            Task::none()
        }
        Msg::Pick(choice) => {
            state.pick(choice);
            Task::none()
        }
        Msg::Confirm => confirm(state, ctx),
        Msg::Event(Event::Done(lines)) => {
            ctx.busy = false;
            state.now = Instant::now();
            match finish(&lines, state.installed) {
                Finish::Remove => remove(state),
                Finish::ShowResult => {
                    state.sheet = Sheet::Result {
                        lines,
                        at: state.now,
                    };
                    Task::done(Message::CheckIfAgreed)
                }
            }
        }
        Msg::Event(event) => {
            state.on_event(event, Instant::now());
            Task::none()
        }
        Msg::RemoveAnyway => {
            if matches!(state.sheet, Sheet::Result { .. }) && state.installed {
                remove(state)
            } else {
                Task::none()
            }
        }
        Msg::Spawned(true) => iced::exit(),
        Msg::Spawned(false) => {
            state.sheet = Sheet::Closed;
            Task::done(Message::Toast(ctx.t(CANNOT_START), Tone::Warn))
        }
        Msg::Frame(now) => {
            state.now = now;
            Task::none()
        }
    }
}

fn close(state: &mut State) {
    if matches!(
        state.sheet,
        Sheet::Loading { .. } | Sheet::Choose { .. } | Sheet::Result { .. }
    ) {
        state.generation = state.generation.wrapping_add(1);
        state.sheet = Sheet::Closed;
    }
}

pub fn escape(state: &mut State) -> bool {
    let open = !matches!(state.sheet, Sheet::Closed);
    close(state);
    open
}

fn confirm(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    let Sheet::Choose {
        safe,
        choice: Some(choice),
        ..
    } = &state.sheet
    else {
        return Task::none();
    };
    match start(*choice, state.installed) {
        Start::Nothing => {
            state.sheet = Sheet::Closed;
            Task::none()
        }
        Start::Remove => remove(state),
        Start::PutBack => {
            if ctx.busy {
                return Task::none();
            }
            let safe = safe.clone();
            let client = ctx.broker.clone();
            let lang = ctx.lang;
            ctx.busy = true;
            state.now = Instant::now();
            state.spin = anim::Clock::at(state.now);
            state.since = state.now;
            state.sheet = Sheet::Working {
                steps: [StepState::Waiting; 5],
            };
            let stream = blocking_stream(move |emit: &dyn Fn(Event)| {
                run_put_back(client, safe, lang, emit);
            });
            Task::run(stream, |e| wrap(Msg::Event(e)))
        }
    }
}

fn remove(state: &mut State) -> Task<Message> {
    state.now = Instant::now();
    state.spin = anim::Clock::at(state.now);
    state.sheet = Sheet::Leaving;
    Task::perform(blocking(launch_uninstaller), |ok| wrap(Msg::Spawned(ok)))
}

pub fn subscription(state: &State) -> Subscription<Message> {
    let moving = match &state.sheet {
        Sheet::Loading { .. } | Sheet::Working { .. } | Sheet::Leaving => true,
        // The result's drawing asks for its own frames.
        _ => false,
    };
    if moving && anim::animating() {
        iced::window::frames().map(|t| wrap(Msg::Frame(t)))
    } else {
        Subscription::none()
    }
}

mod view;
pub use view::modal;

#[cfg(test)]
mod tests {
    use super::view::result_run;
    use super::*;
    use crate::gui::widgets::hairline::Run;

    const LANGS: [Lang; 6] = [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It];

    fn plan(settings: usize, copy: usize, store: usize, suggested: bool) -> Plan {
        Plan {
            settings,
            apps_with_copy: copy,
            apps_store_only: store,
            apps_copy_only: 0,
            suggested,
            web_on: false,
            history_damaged: false,
        }
    }

    #[test]
    fn web_note_only_while_web_protection_is_on() {
        assert_eq!(web_note(None), None);
        assert_eq!(web_note(Some(&plan(3, 0, 0, false))), None);
        let on = Plan {
            web_on: true,
            ..plan(0, 0, 0, false)
        };
        assert_eq!(web_note(Some(&on)), Some(WEB_STOPS));
    }

    fn loading(installed: bool) -> State {
        State {
            installed,
            sheet: Sheet::Loading {
                plan: None,
                waiting: 0,
                safe: Vec::new(),
            },
            ..State::default()
        }
    }

    #[test]
    fn sheet_hides_put_back_when_nothing_to_undo() {
        let none = counts(Some(&plan(0, 0, 0, false)), &[]);
        assert!(!can_put_back(none));
        assert_eq!(choices(can_put_back(none), true), vec![Choice::Keep]);
        let some = counts(Some(&plan(2, 0, 0, false)), &[]);
        assert_eq!(
            choices(can_put_back(some), true),
            vec![Choice::Keep, Choice::PutBack]
        );
        let personal = counts(Some(&plan(0, 0, 0, false)), &[Setting::OfficeMacros]);
        assert!(can_put_back(personal));
        assert!(can_put_back(None));
        let mut state = loading(true);
        state.on_planned(0, Ok(plan(0, 0, 0, false)));
        assert!(matches!(
            state.sheet,
            Sheet::Choose {
                choice: Some(Choice::Keep),
                ..
            }
        ));
    }

    #[test]
    fn put_back_text_counts() {
        let c = counts(Some(&plan(7, 2, 1, false)), &[Setting::ShowExtensions; 5]);
        assert_eq!(
            c,
            Some(Counts {
                changes: 12,
                apps: 3
            })
        );
        assert_eq!(
            put_back_text(Lang::En, c),
            "Secblitz undoes its 12 changes and brings back 3 removed apps first. This can take a few minutes."
        );
        assert_eq!(
            put_back_text(
                Lang::En,
                Some(Counts {
                    changes: 1,
                    apps: 0
                })
            ),
            "Secblitz undoes its 1 change first. This can take a few minutes."
        );
        assert_eq!(
            put_back_text(
                Lang::En,
                Some(Counts {
                    changes: 0,
                    apps: 1
                })
            ),
            "Secblitz brings back 1 removed app first. This can take a few minutes."
        );
        let both = counts(
            Some(&plan(0, 0, 0, true)),
            &[Setting::SuggestedApps, Setting::OfficeMacros],
        );
        assert_eq!(both.map(|c| c.changes), Some(2));
        let machine_only = counts(Some(&plan(1, 0, 0, true)), &[]);
        assert_eq!(machine_only.map(|c| c.changes), Some(2));
        for (changes, apps) in [
            (0, 1),
            (0, 4),
            (1, 0),
            (4, 0),
            (1, 1),
            (1, 4),
            (4, 1),
            (4, 4),
        ] {
            for lang in LANGS {
                let text = put_back_text(lang, Some(Counts { changes, apps }));
                assert!(!text.contains('{') && !text.contains('}'), "{text}");
            }
        }
        assert!(!put_back_text(Lang::En, None).contains('{'));
    }

    #[test]
    fn portable_sheet_offers_put_back_only() {
        assert_eq!(choices(true, false), vec![Choice::PutBack]);
        assert!(choices(false, false).is_empty());
        let mut state = loading(false);
        state.on_planned(0, Ok(plan(3, 0, 0, false)));
        assert!(matches!(
            state.sheet,
            Sheet::Choose {
                choice: Some(Choice::PutBack),
                ..
            }
        ));
        assert_eq!(start(Choice::PutBack, false), Start::PutBack);
        assert_eq!(start(Choice::Keep, false), Start::Nothing);
        assert_eq!(finish(&[], false), Finish::ShowResult);
        assert_eq!(result_actions(false), vec![ResultAction::Close]);
        state.pick(Choice::Keep);
        assert!(matches!(
            state.sheet,
            Sheet::Choose {
                choice: Some(Choice::PutBack),
                ..
            }
        ));
    }

    #[test]
    fn missing_helper_is_explained_before_putting_back() {
        assert!(limits(Helper::Ready, Some(&plan(1, 0, 2, false))).is_empty());
        assert_eq!(
            limits(Helper::Reopen, Some(&plan(1, 0, 2, false))),
            vec![Limit::Personal, Limit::StoreApps(2)]
        );
        assert_eq!(
            limits(Helper::NotOnThisAccount, Some(&plan(1, 3, 0, false))),
            vec![Limit::Personal]
        );
        assert!(limit_key(Helper::Reopen, Limit::StoreApps(1)).contains("Start menu"));
        assert!(limit_key(Helper::NotOnThisAccount, Limit::Personal).contains("UAC"));
    }

    #[test]
    fn failure_lists_left_lines_and_two_buttons() {
        let left = [
            Left::Setting {
                title: "Firewall at home".into(),
                reason: crate::uninstall::LeftReason::ChangedSince,
            },
            Left::Personal {
                id: "net.nearby_sharing",
            },
        ];
        let lines: Vec<String> = left
            .iter()
            .map(|l| crate::uninstall::left_line(l, Lang::En))
            .collect();
        assert_eq!(
            lines[0],
            "Firewall at home: it has changed since Secblitz set it, so it was left as it is. No action is needed."
        );
        assert_eq!(finish(&lines, true), Finish::ShowResult);
        assert_eq!(
            result_actions(true),
            vec![ResultAction::Keep, ResultAction::RemoveAnyway]
        );
        assert_eq!(finish(&[], true), Finish::Remove);
    }

    #[test]
    fn keep_skips_put_back() {
        assert_eq!(start(Choice::Keep, true), Start::Remove);
        assert_eq!(start(Choice::PutBack, true), Start::PutBack);
    }

    #[test]
    fn keeping_warns_before_an_app_is_lost_for_good() {
        assert_eq!(keep_note(None), None);
        assert_eq!(keep_note(Some(&plan(3, 0, 2, false))), None);
        let in_store = plan(0, 2, 0, false);
        assert_eq!(
            keep_note(Some(&in_store)),
            Some((Tone::Neutral, KEEP_DELETES_COPIES))
        );
        let one = Plan {
            apps_copy_only: 1,
            ..in_store.clone()
        };
        let two = Plan {
            apps_copy_only: 2,
            ..in_store
        };
        for (plan, word) in [(one, "is not"), (two, "are not")] {
            let (tone, key) = keep_note(Some(&plan)).unwrap();
            assert_eq!(tone, Tone::Warn);
            assert!(key.contains(word) && key.contains("{n}"), "{key}");
        }
    }

    #[test]
    fn a_name_that_is_back_is_not_listed() {
        let left = vec![
            Left::AppNeedsStore { name: "A".into() },
            Left::App { name: "B".into() },
            Left::SuggestedOlderVersion,
        ];
        let kept = prune_apps(left, &["B".to_owned()]);
        assert_eq!(
            kept,
            vec![Left::App { name: "B".into() }, Left::SuggestedOlderVersion]
        );
    }

    #[test]
    fn put_back_reports_each_personal_reply_plainly() {
        let s = Setting::OfficeMacros;
        assert_eq!(put_back_left(s, true, Some(Some(&Reply::Done))), None);
        assert!(matches!(
            put_back_left(s, false, Some(Some(&Reply::ChangedSince))),
            Some(Left::Setting {
                reason: crate::uninstall::LeftReason::ChangedSince,
                ..
            })
        ));
        assert_eq!(
            put_back_left(s, false, Some(Some(&Reply::Unavailable))),
            None
        );
        assert_eq!(put_back_left(s, false, None), None);
        assert!(matches!(
            put_back_left(s, true, None),
            Some(Left::Personal { .. })
        ));
        assert!(matches!(
            put_back_left(s, false, Some(Some(&Reply::Failed))),
            Some(Left::Personal { .. })
        ));
    }

    #[test]
    fn loading_waits_for_the_plan_and_every_answer() {
        let mut state = State {
            installed: true,
            generation: 4,
            sheet: Sheet::Loading {
                plan: None,
                waiting: 2,
                safe: Vec::new(),
            },
            ..State::default()
        };
        state.on_planned(4, Ok(plan(1, 0, 0, false)));
        assert!(matches!(state.sheet, Sheet::Loading { .. }));
        state.on_queried(3, Setting::OfficeMacros, Ok(Reply::SafeByUs));
        assert!(matches!(state.sheet, Sheet::Loading { waiting: 2, .. }));
        state.on_queried(4, Setting::OfficeMacros, Ok(Reply::SafeByUs));
        state.on_queried(4, Setting::ShowExtensions, Ok(Reply::Safe));
        match &state.sheet {
            Sheet::Choose { safe, choice, .. } => {
                assert_eq!(safe, &vec![Setting::OfficeMacros]);
                assert_eq!(*choice, None);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn unreadable_counts_still_offer_both_choices() {
        let mut state = loading(true);
        state.on_planned(0, Err("x".into()));
        match &state.sheet {
            Sheet::Choose { plan, .. } => assert!(plan.is_none()),
            other => panic!("{other:?}"),
        }
        state.pick(Choice::PutBack);
        assert!(matches!(
            state.sheet,
            Sheet::Choose {
                choice: Some(Choice::PutBack),
                ..
            }
        ));
    }

    #[test]
    fn progress_ticks_each_line_in_order() {
        let mut state = State {
            sheet: Sheet::Working {
                steps: [StepState::Waiting; 5],
            },
            ..State::default()
        };
        let now = Instant::now();
        state.on_event(Event::Started(Item::Personal), now);
        state.on_event(Event::Finished(Item::Personal, true), now);
        state.on_event(Event::Started(Item::Settings), now);
        state.on_event(Event::Finished(Item::Settings, false), now);
        assert_eq!(state.finished_steps(), 2);
        match &state.sheet {
            Sheet::Working { steps } => {
                assert_eq!(steps[0], StepState::Done(true, now));
                assert_eq!(steps[1], StepState::Done(false, now));
                assert_eq!(steps[2], StepState::Waiting);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn rewind_ends_done_or_partly_done() {
        assert_eq!(result_run(&[]), Run::Done);
        assert_eq!(result_run(&["Web protection".into()]), Run::Partial);
    }

    #[test]
    fn escape_closes_only_when_no_work_runs() {
        let mut state = loading(true);
        assert!(escape(&mut state));
        assert!(matches!(state.sheet, Sheet::Closed));
        state.sheet = Sheet::Working {
            steps: [StepState::Waiting; 5],
        };
        escape(&mut state);
        assert!(matches!(state.sheet, Sheet::Working { .. }));
        state.sheet = Sheet::Leaving;
        escape(&mut state);
        assert!(matches!(state.sheet, Sheet::Leaving));
    }

    #[test]
    fn uninstaller_is_none_for_a_copy_that_is_not_installed() {
        assert!(uninstaller().is_none());
    }

    #[test]
    fn every_text_is_plain_and_translated() {
        let sources = [
            SECTION_TITLE,
            SECTION_ROW,
            SECTION_HELP,
            QUESTION,
            NOTHING_TO_PUT_BACK,
            KEEP_TITLE,
            KEEP_HELP,
            PUT_BACK_TITLE,
            STAY_NOTE,
            WEB_STOPS,
            KEEP_DELETES_COPIES,
            OWN_ACCOUNT_ONLY,
            STORE_NEEDS_INTERNET,
            LOADING,
            WORKING_TITLE,
            WORKING_HELP,
            STEP_RUNNING,
            STEP_DONE,
            STEP_PARTLY,
            ITEM_PERSONAL,
            ITEM_SUGGESTED,
            ITEM_WEB,
            WEB_LEFT,
            RESULT_LEFT_TITLE,
            RESULT_LEFT_HELP,
            RESULT_DONE_TITLE,
            DELETE_EXE,
            REMOVE_ANYWAY,
            KEEP_SECBLITZ,
            CLOSE,
            LEAVING_TITLE,
            LEAVING_HELP,
            CANNOT_START,
            "Secblitz undoes the changes it made and brings back the apps you removed first. This can take a few minutes.",
            "Secblitz brings back {apps} removed app first. This can take a few minutes.",
            "Secblitz brings back {apps} removed apps first. This can take a few minutes.",
            "Secblitz undoes its {n} change first. This can take a few minutes.",
            "Secblitz undoes its {n} changes first. This can take a few minutes.",
            "Secblitz undoes its {n} change and brings back {apps} removed app first. This can take a few minutes.",
            "Secblitz undoes its {n} change and brings back {apps} removed apps first. This can take a few minutes.",
            "Secblitz undoes its {n} changes and brings back {apps} removed app first. This can take a few minutes.",
            "Secblitz undoes its {n} changes and brings back {apps} removed apps first. This can take a few minutes.",
            "The saved copies of removed apps are deleted to free space. {n} of these apps is not in the Microsoft Store, so it can't come back after this. To keep it, bring it back first in Clean up apps.",
            "The saved copies of removed apps are deleted to free space. {n} of these apps are not in the Microsoft Store, so they can't come back after this. To keep them, bring them back first in Clean up apps.",
        ];
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/i18n-pending/a6.tsv");
        let pending = std::fs::read_to_string(path).ok();
        for source in sources {
            assert!(!source.contains('\u{2014}'), "{source}");
            for jargon in ["DNS", "NRPT", "registry", "service"] {
                assert!(!source.contains(jargon), "{source}");
            }
            let row = pending.as_deref().and_then(|t| {
                t.lines()
                    .map(|l| l.split('\t').collect::<Vec<_>>())
                    .find(|c| c[0] == source)
            });
            if let Some(cols) = row {
                assert_eq!(cols.len(), 6, "{source}");
                assert!(cols
                    .iter()
                    .all(|c| !c.trim().is_empty() && !c.contains('\u{2014}')));
                for placeholder in ["{n}", "{apps}"] {
                    for c in &cols {
                        assert_eq!(
                            source.contains(placeholder),
                            c.contains(placeholder),
                            "{source}"
                        );
                    }
                }
            } else {
                for lang in &LANGS[1..] {
                    assert_ne!(lang.t(source), source, "{source}");
                }
            }
        }
    }
}
