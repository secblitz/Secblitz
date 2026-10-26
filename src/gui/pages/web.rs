//! Web protection: overview, switches and allowed sites.
use crate::app::{history, settings as app_settings};
use crate::gui::icons::Icon;
use crate::gui::pages::home;
use crate::gui::theme::{self, Palette, Tone};
use crate::gui::widgets::hairline::{web_globe, Plate};
use crate::gui::widgets::{self, progress, ButtonKind};
use crate::gui::{blocking, Ctx, Message, Page};
use crate::i18n::Lang;
use iced::widget::canvas::Cache;
use iced::widget::{column, container, row, text_input};
use iced::{
    Alignment, Background, Border, Color, Element, Length, Padding, Pixels, Subscription, Task,
};
use secblitz::filter::config::{
    self, BlockHistory, Config, ErrorCode, Lookups, RecentItem, State as ListState, Status,
    MAX_ALLOWED, STATS_DAYS,
};
use secblitz::filter::control::{self, ServiceState};
use secblitz::filter::gaps::Gap;
use secblitz::filter::matcher::{Kind, KINDS};
use std::time::{Duration, Instant};

type El<'a> = Element<'a, Message>;

const SECONDS_PER_DAY: u64 = 86_400;
const CHART_HEIGHT: f32 = 150.0;
const TOP_SHOWN: usize = 5;
const RECENT_SHOWN: usize = 6;
const MAX_TYPED: usize = 300;
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Switch {
    Ads,
    Tracking,
    Dangerous,
    Scam,
    Popups,
    Adult,
    Gambling,
    SafeSearch,
    PrivateLookups,
}

impl Switch {
    const PROTECTION: [Switch; 5] = [
        Switch::Ads,
        Switch::Tracking,
        Switch::Dangerous,
        Switch::Scam,
        Switch::Popups,
    ];
    const FAMILY: [Switch; 3] = [Switch::Adult, Switch::Gambling, Switch::SafeSearch];
    const PRIVACY: [Switch; 1] = [Switch::PrivateLookups];
    #[cfg(test)]
    const ALL: [Switch; 9] = [
        Switch::Ads,
        Switch::Tracking,
        Switch::Dangerous,
        Switch::Scam,
        Switch::Popups,
        Switch::Adult,
        Switch::Gambling,
        Switch::SafeSearch,
        Switch::PrivateLookups,
    ];

    fn id(self) -> &'static str {
        match self {
            Switch::Ads => "web.ads",
            Switch::Tracking => "web.tracking",
            Switch::Dangerous => "web.dangerous",
            Switch::Scam => "web.scam",
            Switch::Popups => "web.popups",
            Switch::Adult => "web.adult",
            Switch::Gambling => "web.gambling",
            Switch::SafeSearch => "web.safe_search",
            Switch::PrivateLookups => "web.private_lookups",
        }
    }

    fn get(self, c: &Config) -> bool {
        match self {
            Switch::Ads => c.ads,
            Switch::Tracking => c.tracking,
            Switch::Dangerous => c.dangerous,
            Switch::Scam => c.scam,
            Switch::Popups => c.popups,
            Switch::Adult => c.adult,
            Switch::Gambling => c.gambling,
            Switch::SafeSearch => c.safe_search,
            Switch::PrivateLookups => c.private_lookups,
        }
    }

    fn set(self, c: &mut Config, on: bool) {
        match self {
            Switch::Ads => c.ads = on,
            Switch::Tracking => c.tracking = on,
            Switch::Dangerous => c.dangerous = on,
            Switch::Scam => c.scam = on,
            Switch::Popups => c.popups = on,
            Switch::Adult => c.adult = on,
            Switch::Gambling => c.gambling = on,
            Switch::SafeSearch => c.safe_search = on,
            Switch::PrivateLookups => c.private_lookups = on,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Overview,
    Block,
    Sites,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseFor {
    Quarter,
    Hour,
    UntilRestart,
}

impl PauseFor {
    const ALL: [PauseFor; 3] = [PauseFor::Quarter, PauseFor::Hour, PauseFor::UntilRestart];

    fn label(self) -> &'static str {
        match self {
            PauseFor::Quarter => "15 minutes",
            PauseFor::Hour => "1 hour",
            PauseFor::UntilRestart => "Until restart",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub config: Config,
    pub status: Option<Status>,
    pub service: ServiceState,
    pub installed: bool,
    pub now: u64,
    pub recent: Vec<RecentItem>,
    pub stats: Option<BlockHistory>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Busy {
    Switch(Switch),
    Pause,
    Resume,
    Retry,
    Allow,
    AllowOnce,
    Remove,
    Add,
}

#[derive(Debug, Default)]
pub struct State {
    snapshot: Option<Snapshot>,
    busy: Option<Busy>,
    polling: bool,
    generation: u32,
    look: Option<(web_globe::Guard, Instant)>,
    tab: Tab,
    pause_choices: bool,
    confirm: Option<String>,
    confirm_once: Option<String>,
    site: String,
    site_problem: Option<SiteProblem>,
    all_recent: bool,
    days: Vec<(u64, u64)>,
    chart: Cache,
}

#[derive(Debug, Clone)]
pub enum Msg {
    Seen(Box<Snapshot>),
    Polled(u32, Box<Snapshot>),
    Toggle(Switch, bool),
    Pause(PauseFor),
    PauseChoices,
    Resume,
    Retry,
    Done(u32, Result<(), String>),
    SetTab(Tab),
    FocusPrivacy,
    AskAllow(String),
    CancelAllow,
    Allow(String),
    AskOnce(String),
    CancelOnce,
    AllowOnce(String),
    Unallow(String),
    SiteInput(String),
    AddSite,
    MoreRecent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Line {
    Off,
    PrivateOnly,
    On,
    Paused(u64),
    PausedUntilRestart,
    GettingReady,
    NotWorking,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Coverage {
    Everything,
    Gaps(Vec<Gap>),
}

/// `None` unless protection is on and the service could check the PC, so
/// neither claim is made on a guess.
fn coverage(snapshot: &Snapshot, line: Line) -> Option<Coverage> {
    if line != Line::On {
        return None;
    }
    let gaps = snapshot.status.as_ref()?.gaps.as_ref()?;
    Some(if gaps.is_empty() {
        Coverage::Everything
    } else {
        Coverage::Gaps(gaps.clone())
    })
}

pub fn status_line(
    config: &Config,
    status: Option<&Status>,
    service: ServiceState,
    now: u64,
) -> Line {
    if !config.needs_service() {
        return Line::Off;
    }
    if !config.any_on() {
        let working = service == ServiceState::Running
            && status.is_some_and(|s| {
                config::fresh(s, now) && s.last_error != Some(ErrorCode::PortInUse)
            });
        return if working {
            Line::PrivateOnly
        } else {
            Line::NotWorking
        };
    }
    if let Some(until) = config.paused_until.filter(|t| *t > now) {
        return Line::Paused(until);
    }
    if config.paused(now) {
        return Line::PausedUntilRestart;
    }
    if service != ServiceState::Running {
        return Line::NotWorking;
    }
    let Some(status) = status.filter(|s| config::fresh(s, now)) else {
        return Line::NotWorking;
    };
    if status.last_error == Some(ErrorCode::PortInUse) {
        return Line::NotWorking;
    }
    if !status.listening {
        return Line::GettingReady;
    }
    match status.state {
        ListState::Ready => Line::On,
        ListState::Starting | ListState::NoLists => Line::GettingReady,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusAction {
    Choose,
    Pause,
    Resume,
    Retry,
}

pub fn status_action(line: Line) -> Option<StatusAction> {
    match line {
        Line::Off | Line::PrivateOnly => Some(StatusAction::Choose),
        Line::Paused(_) | Line::PausedUntilRestart => Some(StatusAction::Resume),
        Line::NotWorking => Some(StatusAction::Retry),
        Line::On | Line::GettingReady => Some(StatusAction::Pause),
    }
}

fn current_line(snapshot: &Snapshot) -> Line {
    status_line(
        &snapshot.config,
        snapshot.status.as_ref(),
        snapshot.service,
        snapshot.now,
    )
}

pub fn guard_of(line: Line) -> web_globe::Guard {
    use web_globe::Guard;
    match line {
        Line::On => Guard::On,
        Line::GettingReady => Guard::Starting,
        Line::Paused(_) | Line::PausedUntilRestart => Guard::Paused,
        Line::Off | Line::PrivateOnly => Guard::Off,
        Line::NotWorking => Guard::Broken,
    }
}

fn note_look(state: &mut State, snapshot: &Snapshot, now: Instant) {
    let guard = guard_of(current_line(snapshot));
    if state.look.map(|(g, _)| g) != Some(guard) {
        state.look = Some((guard, now));
    }
}

pub fn controls_enabled(snapshot: Option<&Snapshot>, busy: bool) -> bool {
    snapshot.is_some_and(|s| s.installed) && !busy
}

pub fn suggests(snapshot: &Snapshot) -> bool {
    snapshot.installed && !snapshot.config.any_on()
}

fn blocked_today(snapshot: &Snapshot) -> Option<[u64; KINDS]> {
    let status = snapshot.status.as_ref()?;
    if !snapshot.config.any_on() || !config::fresh(status, snapshot.now) {
        return None;
    }
    Some(if status.day == history::local_day(snapshot.now) {
        status.blocked
    } else {
        [0; KINDS]
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupState {
    Off,
    Private,
    Paused,
    PausedWithBlocking,
    GettingReady,
    NotRunning,
}

pub fn private_state(config: &Config, status: Option<&Status>, now: u64) -> LookupState {
    if !config.private_lookups {
        return LookupState::Off;
    }
    if config.paused(now) {
        return LookupState::PausedWithBlocking;
    }
    match status.filter(|s| config::fresh(s, now)).map(|s| s.lookups) {
        None => LookupState::NotRunning,
        Some(Lookups::Private) => LookupState::Private,
        Some(Lookups::PrivateFallback) => LookupState::Paused,
        Some(Lookups::Plain) => LookupState::GettingReady,
    }
}

fn dangerous_today(snapshot: &Snapshot) -> Option<u64> {
    let status = snapshot
        .status
        .as_ref()
        .filter(|s| config::fresh(s, snapshot.now))?;
    let at = status.dangerous_at.filter(|t| *t <= snapshot.now)?;
    (history::local_day(at) == history::local_day(snapshot.now)).then_some(at)
}

/// `live` is today's count from the status file, which can be newer than the saved statistics.
pub fn daily_totals(
    stats: Option<&BlockHistory>,
    today: u64,
    live: Option<u64>,
) -> Vec<(u64, u64)> {
    (0..STATS_DAYS)
        .rev()
        .map(|back| {
            let day = today.saturating_sub(back);
            let saved = stats
                .and_then(|s| s.days.iter().find(|d| d.day == day))
                .map_or(0, |d| d.blocked.iter().sum::<u64>());
            let count = if back == 0 {
                saved.max(live.unwrap_or(0))
            } else {
                saved
            };
            (day, count)
        })
        .collect()
}

pub fn top_companies(stats: Option<&BlockHistory>, limit: usize) -> Vec<(String, u64)> {
    stats.map_or_else(Vec::new, |s| {
        s.top_companies
            .iter()
            .take(limit)
            .map(|c| (c.site.clone(), c.count))
            .collect()
    })
}

pub fn is_allowed(name: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| {
        name == a
            || name
                .strip_suffix(a.as_str())
                .is_some_and(|p| p.ends_with('.'))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteProblem {
    Empty,
    NotAName,
    Already,
    Full,
}

/// Reduces pasted text such as `https://example.com/page?x=1` to a bare name.
pub fn site_from_input(raw: &str) -> String {
    let typed = raw.trim();
    let lower = typed.to_ascii_lowercase();
    let rest = ["https://", "http://"]
        .iter()
        .find(|scheme| lower.starts_with(**scheme))
        .map_or(typed, |scheme| &typed[scheme.len()..]);
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    host.to_string()
}

pub fn check_new_site(raw: &str, allowed: &[String]) -> Result<String, SiteProblem> {
    if raw.trim().is_empty() {
        return Err(SiteProblem::Empty);
    }
    let name = config::normalized_site(&site_from_input(raw)).ok_or(SiteProblem::NotAName)?;
    if allowed.contains(&name) {
        return Err(SiteProblem::Already);
    }
    if allowed.len() >= MAX_ALLOWED {
        return Err(SiteProblem::Full);
    }
    Ok(name)
}

fn site_problem_text(problem: SiteProblem) -> &'static str {
    match problem {
        SiteProblem::Empty => "Type the website you want to allow, for example example.com.",
        SiteProblem::NotAName => NOT_A_NAME,
        SiteProblem::Already => "That site is already allowed.",
        SiteProblem::Full => LIST_FULL,
    }
}

const NOT_A_NAME: &str = "That is not a website name. Type it the way it appears in the address bar, for example example.com.";
const LIST_FULL: &str =
    "The list of allowed sites is full. Remove a site you no longer need and try again.";
const LIST_TOO_LONG: &str =
    "The list of allowed sites is too long. Remove a site you no longer need and try again.";

pub fn minutes_ago(now: u64, at: u64) -> u64 {
    now.saturating_sub(at) / 60
}

pub fn visible_recent(snapshot: &Snapshot) -> Vec<&RecentItem> {
    snapshot
        .recent
        .iter()
        .filter(|i| !is_allowed(&i.name, &snapshot.config.allow))
        .filter(|i| !snapshot.config.allowed_once(&i.name, snapshot.now))
        .collect()
}

/// The kinds a person may want to open for a moment. Ads and trackers are blocked all the time and are not worth a prompt.
fn lets_through_once(kind: Kind) -> bool {
    matches!(kind, Kind::Dangerous | Kind::Scam | Kind::Popups)
}

pub fn recent_blocks(snapshot: &Snapshot) -> Vec<&RecentItem> {
    visible_recent(snapshot)
        .into_iter()
        .filter(|i| lets_through_once(i.kind))
        .collect()
}

fn service_state() -> ServiceState {
    #[cfg(windows)]
    {
        secblitz::filter::scm::state().unwrap_or(ServiceState::Other)
    }
    #[cfg(not(windows))]
    {
        ServiceState::NotInstalled
    }
}

fn read_snapshot() -> Snapshot {
    let config = config::config_path()
        .map(|p| config::load_config(&p))
        .unwrap_or_default();
    let status = config::status_path()
        .ok()
        .and_then(|p| config::load_status(&p));
    let now = history::now();
    let recent = config::recent_path()
        .ok()
        .and_then(|p| config::load_recent(&p))
        .map(|r| r.within_window(now).items)
        .unwrap_or_default();
    let stats = config::stats_path()
        .ok()
        .and_then(|p| config::load_stats(&p));
    Snapshot {
        config,
        status,
        service: service_state(),
        installed: app_settings::installed_exe().is_some(),
        now,
        recent,
        stats,
    }
}

fn apply(config: Config) -> Result<(), String> {
    #[cfg(windows)]
    {
        secblitz::filter::control::apply_switches(config).map_err(|e| format!("{e:#}"))
    }
    #[cfg(not(windows))]
    {
        let _ = config;
        Err("unavailable".into())
    }
}

fn pause(length: PauseFor) -> Result<(), String> {
    #[cfg(windows)]
    {
        match length {
            PauseFor::Quarter => secblitz::filter::control::pause_for(Duration::from_secs(15 * 60)),
            PauseFor::Hour => secblitz::filter::control::pause_for(Duration::from_secs(3600)),
            PauseFor::UntilRestart => secblitz::filter::control::pause_until_restart(),
        }
        .map_err(|e| format!("{e:#}"))
    }
    #[cfg(not(windows))]
    {
        let _ = length;
        Err("unavailable".into())
    }
}

fn resume() -> Result<(), String> {
    #[cfg(windows)]
    {
        secblitz::filter::control::resume().map_err(|e| format!("{e:#}"))
    }
    #[cfg(not(windows))]
    {
        Err("unavailable".into())
    }
}

fn allow_site(name: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        secblitz::filter::control::allow_site(&name).map_err(|e| format!("{e:#}"))
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err("unavailable".into())
    }
}

fn allow_once(name: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        secblitz::filter::control::allow_site_once(&name).map_err(|e| format!("{e:#}"))
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err("unavailable".into())
    }
}

fn remove_allowed(name: String) -> Result<(), String> {
    #[cfg(windows)]
    {
        secblitz::filter::control::remove_allowed(&name).map_err(|e| format!("{e:#}"))
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err("unavailable".into())
    }
}

fn read_task(generation: u32) -> Task<Message> {
    Task::perform(blocking(read_snapshot), move |snapshot| {
        Message::Web(Msg::Polled(generation, Box::new(snapshot)))
    })
}

fn poll(state: &mut State) -> Task<Message> {
    if state.polling || state.busy.is_some() {
        return Task::none();
    }
    state.polling = true;
    read_task(state.generation)
}

fn start(
    state: &mut State,
    busy: Busy,
    work: impl FnOnce() -> Result<(), String> + Send + 'static,
) -> Task<Message> {
    state.busy = Some(busy);
    state.generation = state.generation.wrapping_add(1);
    let generation = state.generation;
    Task::perform(blocking(work), move |result| {
        Message::Web(Msg::Done(generation, result))
    })
}

pub fn on_enter(state: &mut State, _ctx: &mut Ctx) -> Task<Message> {
    escape(state);
    poll(state)
}

pub fn escape(state: &mut State) {
    state.confirm = None;
    state.confirm_once = None;
    state.pause_choices = false;
}

/// Whether two readings would draw the same page, whatever the clock says.
fn same_look(a: &Snapshot, b: &Snapshot) -> bool {
    let fresh = |s: &Snapshot| s.status.as_ref().is_some_and(|st| config::fresh(st, s.now));
    a.config == b.config
        && a.status == b.status
        && a.service == b.service
        && a.installed == b.installed
        && current_line(a) == current_line(b)
        && blocked_today(a) == blocked_today(b)
        && fresh(a) == fresh(b)
        && a.recent == b.recent
        && a.stats == b.stats
        && dangerous_today(a) == dangerous_today(b)
        && history::local_day(a.now) == history::local_day(b.now)
        && a.recent
            .iter()
            .map(|i| minutes_ago(a.now, i.at))
            .eq(b.recent.iter().map(|i| minutes_ago(b.now, i.at)))
}

/// Rereads every two seconds on its own thread and speaks up only when the
/// page would look different, so an unchanged page never redraws.
pub fn subscription() -> Subscription<Message> {
    Subscription::run(|| {
        let (tx, rx) = iced::futures::channel::mpsc::unbounded();
        std::thread::spawn(move || {
            let mut last: Option<Snapshot> = None;
            loop {
                std::thread::sleep(Duration::from_secs(2));
                if tx.is_closed() {
                    break;
                }
                let now = read_snapshot();
                if last.as_ref().is_some_and(|l| same_look(l, &now)) {
                    continue;
                }
                last = Some(now.clone());
                if tx.unbounded_send(now).is_err() {
                    break;
                }
            }
        });
        rx
    })
    .map(|snapshot| Message::Web(Msg::Seen(Box::new(snapshot))))
}

fn take_snapshot(state: &mut State, snapshot: Snapshot) -> Task<Message> {
    let suggest = suggests(&snapshot);
    note_look(state, &snapshot, Instant::now());
    state.days = daily_totals(
        snapshot.stats.as_ref(),
        history::local_day(snapshot.now),
        blocked_today(&snapshot).map(|c| c.iter().sum::<u64>()),
    );
    state.snapshot = Some(snapshot);
    Task::done(Message::Home(home::Msg::WebSuggest(suggest)))
}

fn ready(state: &State) -> bool {
    controls_enabled(state.snapshot.as_ref(), state.busy.is_some())
}

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    match msg {
        Msg::Seen(snapshot) => {
            if state.busy.is_some() {
                return Task::none();
            }
            take_snapshot(state, *snapshot)
        }
        Msg::Polled(generation, snapshot) => {
            state.polling = false;
            if generation != state.generation {
                return Task::none();
            }
            take_snapshot(state, *snapshot)
        }
        Msg::Toggle(switch, on) => {
            let Some(snapshot) = state.snapshot.as_ref() else {
                return Task::none();
            };
            if !controls_enabled(Some(snapshot), state.busy.is_some()) {
                return Task::none();
            }
            let mut config = snapshot.config.clone();
            switch.set(&mut config, on);
            config = control::resumed_config(config);
            start(state, Busy::Switch(switch), move || apply(config))
        }
        Msg::PauseChoices => {
            state.pause_choices = !state.pause_choices;
            Task::none()
        }
        Msg::Pause(length) => {
            if !ready(state) {
                return Task::none();
            }
            state.pause_choices = false;
            start(state, Busy::Pause, move || pause(length))
        }
        Msg::Resume => {
            if !ready(state) {
                return Task::none();
            }
            start(state, Busy::Resume, resume)
        }
        Msg::Retry => {
            let Some(snapshot) = state.snapshot.as_ref() else {
                return Task::none();
            };
            if !controls_enabled(Some(snapshot), state.busy.is_some()) {
                return Task::none();
            }
            let config = snapshot.config.clone();
            start(state, Busy::Retry, move || apply(config))
        }
        Msg::Done(generation, result) => {
            if generation != state.generation {
                return Task::none();
            }
            let finished = state.busy.take();
            state.generation = state.generation.wrapping_add(1);
            state.polling = false;
            if result.is_ok() && finished == Some(Busy::Add) {
                state.site.clear();
                state.site_problem = None;
            }
            let reread = poll(state);
            match result {
                Ok(()) => reread,
                Err(raw) => Task::batch([
                    Task::done(Message::Toast(ctx.t(failure_text(&raw)), Tone::Warn)),
                    reread,
                ]),
            }
        }
        Msg::SetTab(tab) => {
            state.tab = tab;
            state.confirm = None;
            state.confirm_once = None;
            Task::none()
        }
        Msg::FocusPrivacy => update(state, Msg::SetTab(Tab::Block), ctx),
        Msg::AskAllow(name) => {
            state.confirm = Some(name);
            Task::none()
        }
        Msg::CancelAllow => {
            state.confirm = None;
            Task::none()
        }
        Msg::Allow(name) => {
            if !ready(state) {
                return Task::none();
            }
            state.confirm = None;
            start(state, Busy::Allow, move || allow_site(name))
        }
        Msg::AskOnce(name) => {
            state.confirm_once = Some(name);
            Task::none()
        }
        Msg::CancelOnce => {
            state.confirm_once = None;
            Task::none()
        }
        Msg::AllowOnce(name) => {
            if !ready(state) {
                return Task::none();
            }
            state.confirm_once = None;
            start(state, Busy::AllowOnce, move || allow_once(name))
        }
        Msg::Unallow(name) => {
            if !ready(state) {
                return Task::none();
            }
            start(state, Busy::Remove, move || remove_allowed(name))
        }
        Msg::SiteInput(typed) => {
            state.site = typed.chars().take(MAX_TYPED).collect();
            state.site_problem = None;
            Task::none()
        }
        Msg::AddSite => {
            if !ready(state) {
                return Task::none();
            }
            let allowed = state
                .snapshot
                .as_ref()
                .map(|s| s.config.allow.clone())
                .unwrap_or_default();
            match check_new_site(&state.site, &allowed) {
                Ok(name) => {
                    state.site_problem = None;
                    start(state, Busy::Add, move || allow_site(name))
                }
                Err(problem) => {
                    state.site_problem = Some(problem);
                    Task::none()
                }
            }
        }
        Msg::MoreRecent => {
            state.all_recent = true;
            Task::none()
        }
    }
}

fn failure_text(raw: &str) -> &'static str {
    let r = raw.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| r.contains(n));
    if has(&["administrator", "access is denied", "os error 5", "elevat"]) {
        "Windows wouldn't let Secblitz change web protection. Sign in with an account that can make changes to this computer, then open Secblitz again."
    } else if has(&["not a website name"]) {
        NOT_A_NAME
    } else if has(&["allowed sites is full"]) {
        LIST_FULL
    } else if has(&["allowed sites is too long"]) {
        LIST_TOO_LONG
    } else if has(&[
        "unavailable",
        "only supported on windows",
        "requires windows",
    ]) {
        "Web protection isn't available on this computer."
    } else if has(&["marked for deletion", "already exists", "1072", "1073"]) {
        "Windows is still tidying up the old web protection. Restart your computer, then try again."
    } else if has(&["untrusted", "unexpected", "writable", "owner"]) {
        "Secblitz couldn't safely set up web protection on this computer. Install the latest Secblitz and try again."
    } else {
        "We couldn't change web protection. Please try again. If it keeps happening, restart your computer."
    }
}

fn problem_hint(snapshot: &Snapshot, line: Line) -> Option<&'static str> {
    if !matches!(line, Line::NotWorking | Line::GettingReady | Line::On) {
        return None;
    }
    let status = snapshot
        .status
        .as_ref()
        .filter(|s| config::fresh(s, snapshot.now));
    match status.and_then(|s| s.last_error) {
        Some(ErrorCode::PortInUse) => Some(
            "Another program on your computer is using what web protection needs. Close other ad blockers or VPN apps.",
        ),
        Some(ErrorCode::NoUpstream) => Some(
            "Web protection can't find your internet connection. Connect to the internet.",
        ),
        Some(ErrorCode::DownloadFailed) => Some(
            "The block lists couldn't be downloaded. Connect to the internet. Secblitz will try again by itself.",
        ),
        Some(ErrorCode::ListInvalid) => Some(
            "The block lists couldn't be used. Secblitz will try to download them again. If this stays, check for a Secblitz update.",
        ),
        None if line == Line::NotWorking => Some(
            "Press Try again. If that doesn't help, restart your computer.",
        ),
        None => None,
    }
}

fn format_clock(lang: Lang, secs: u64) -> String {
    let hour = (secs % SECONDS_PER_DAY) / 3600;
    let minute = (secs % 3600) / 60;
    if lang == Lang::En {
        let suffix = if hour < 12 { "AM" } else { "PM" };
        let h12 = match hour % 12 {
            0 => 12,
            h => h,
        };
        format!("{h12}:{minute:02} {suffix}")
    } else {
        format!("{hour}:{minute:02}")
    }
}

fn group_digits(lang: Lang, n: u64) -> String {
    let sep = match lang {
        Lang::En => ",",
        Lang::Fr => "\u{202f}",
        Lang::Es | Lang::De | Lang::Pt | Lang::It => ".",
    };
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push_str(sep);
        }
        out.push(c);
    }
    out
}

/// `day` is days since 1970.
fn short_day(lang: Lang, day: u64) -> String {
    let (_, month, date) = history::civil(day);
    format!("{} {}", date, lang.t(MONTHS[(month as usize - 1) % 12]))
}

fn day_fn(lang: Lang) -> &'static dyn Fn(u64) -> String {
    match lang {
        Lang::En => &|d| short_day(Lang::En, d),
        Lang::Es => &|d| short_day(Lang::Es, d),
        Lang::Fr => &|d| short_day(Lang::Fr, d),
        Lang::De => &|d| short_day(Lang::De, d),
        Lang::Pt => &|d| short_day(Lang::Pt, d),
        Lang::It => &|d| short_day(Lang::It, d),
    }
}

fn count_fn(lang: Lang) -> &'static dyn Fn(u64) -> String {
    match lang {
        Lang::En => &|n| group_digits(Lang::En, n),
        Lang::Es => &|n| group_digits(Lang::Es, n),
        Lang::Fr => &|n| group_digits(Lang::Fr, n),
        Lang::De => &|n| group_digits(Lang::De, n),
        Lang::Pt => &|n| group_digits(Lang::Pt, n),
        Lang::It => &|n| group_digits(Lang::It, n),
    }
}

fn line_text(ctx: &Ctx, line: Line) -> String {
    match line {
        Line::Off => ctx.t("Off"),
        Line::PrivateOnly => ctx.t("Only private lookups are on"),
        Line::On => ctx.t("On"),
        Line::Paused(until) => ctx.t("Paused until {time}").replace(
            "{time}",
            &format_clock(ctx.lang, history::local_seconds(until)),
        ),
        Line::PausedUntilRestart => ctx.t("Paused until restart"),
        Line::GettingReady => ctx.t("Getting block lists ready"),
        Line::NotWorking => {
            ctx.t("Not working right now. Your internet still works, but nothing is being blocked.")
        }
    }
}

fn on_title(coverage: Option<&Coverage>) -> &'static str {
    match coverage {
        Some(Coverage::Everything) => "Web protection covers everything",
        Some(Coverage::Gaps(_)) => "Web protection is on, but some sites can get around it",
        None => "Web protection is on",
    }
}

fn hero_text(ctx: &Ctx, line: Line, coverage: Option<&Coverage>) -> (String, Option<String>) {
    match line {
        Line::On => (ctx.t(on_title(coverage)), None),
        Line::GettingReady => (
            ctx.t("Getting block lists ready"),
            Some(ctx.t("Blocking starts as soon as the lists are ready.")),
        ),
        Line::Paused(_) | Line::PausedUntilRestart => (
            line_text(ctx, line),
            Some(ctx.t("Nothing is being blocked for now.")),
        ),
        Line::Off => (
            ctx.t("Web protection is off"),
            Some(ctx.t("Ads, trackers and dangerous websites can load.")),
        ),
        Line::PrivateOnly => (
            ctx.t("Only private lookups are on"),
            Some(ctx.t("Blocking is not turned on.")),
        ),
        Line::NotWorking => (ctx.t("Not working right now"), None),
    }
}

fn private_text(ctx: &Ctx, state: LookupState) -> String {
    match state {
        LookupState::Off => ctx.t("Your internet lookups are not private."),
        LookupState::Private => ctx.t("Your internet lookups are private."),
        LookupState::Paused => ctx.t("Private lookups are paused: this network blocks them"),
        LookupState::PausedWithBlocking => ctx.t("Private lookups are paused too"),
        LookupState::GettingReady => ctx.t("Private lookups are getting ready"),
        LookupState::NotRunning => ctx.t("Private lookups aren't running right now"),
    }
}

fn wrap(msg: Msg) -> Message {
    Message::Web(msg)
}

fn tab_label(ctx: &Ctx, tab: Tab) -> String {
    ctx.t(match tab {
        Tab::Overview => "Overview",
        Tab::Block => "What to block",
        Tab::Sites => "Sites",
    })
}

fn kind_icon(kind: Kind) -> Icon {
    match kind {
        Kind::Ads => Icon::Apps,
        Kind::Tracking => Icon::Eye,
        Kind::Dangerous => Icon::ShieldAlert,
        Kind::Adult => Icon::EyeOff,
        Kind::Gambling => Icon::Gamepad,
        Kind::Scam => Icon::AlertTriangle,
        Kind::Popups => Icon::Bell,
    }
}

fn kind_label(ctx: &Ctx, kind: Kind) -> String {
    ctx.t(match kind {
        Kind::Ads => "Ads",
        Kind::Tracking => "Tracking",
        Kind::Dangerous => "Dangerous websites",
        Kind::Adult => "Adult websites",
        Kind::Gambling => "Gambling",
        Kind::Scam => "Scam sites",
        Kind::Popups => "Pop-up spam",
    })
}

fn kind_short(ctx: &Ctx, kind: Kind) -> String {
    ctx.t(match kind {
        Kind::Ads => "Ads",
        Kind::Tracking => "Tracking",
        Kind::Dangerous => "Dangerous",
        Kind::Adult => "Adult",
        Kind::Gambling => "Gambling",
        Kind::Scam => "Scam",
        Kind::Popups => "Pop-ups",
    })
}

fn ago_text(ctx: &Ctx, minutes: u64) -> String {
    match minutes {
        0 => ctx.t("Just now"),
        1 => ctx.t("1 minute ago"),
        n => ctx
            .t("{n} minutes ago")
            .replace("{n}", &group_digits(ctx.lang, n)),
    }
}

fn switch_text(ctx: &Ctx, switch: Switch) -> (Icon, String, String) {
    match switch {
        Switch::Ads => (
            Icon::Apps,
            ctx.t("Block ads"),
            ctx.t("Stops ads from loading in your browser and in apps."),
        ),
        Switch::Tracking => (
            Icon::Eye,
            ctx.t("Block tracking and telemetry"),
            ctx.t("Stops websites, apps and Windows from sending data about what you do."),
        ),
        Switch::Dangerous => (
            Icon::ShieldAlert,
            ctx.t("Block dangerous websites"),
            ctx.t("Stops your computer from opening known scam and virus websites."),
        ),
        Switch::Scam => (
            Icon::AlertTriangle,
            ctx.t("Scam and fake shop sites"),
            ctx.t("Blocks fake online shops, fake streaming sites and subscription traps."),
        ),
        Switch::Popups => (
            Icon::Bell,
            ctx.t("Pop-up and notification spam"),
            ctx.t(
                "Blocks pop-up floods and fake 'your computer is infected' warnings.",
            ),
        ),
        Switch::Adult => (
            Icon::EyeOff,
            ctx.t("Block adult websites"),
            ctx.t("Stops your computer from opening websites meant for adults."),
        ),
        Switch::Gambling => (
            Icon::Gamepad,
            ctx.t("Block gambling websites"),
            ctx.t("Stops your computer from opening online betting and casino websites."),
        ),
        Switch::SafeSearch => (
            Icon::Search,
            ctx.t("Safe search"),
            ctx.t("Google, Bing, YouTube and DuckDuckGo show only family-friendly results."),
        ),
        Switch::PrivateLookups => (
            Icon::Lock,
            ctx.t("Private lookups through Secblitz"),
            ctx.t(
                "Keeps the websites you visit private from your internet provider and public Wi-Fi.",
            ),
        ),
    }
}

fn switch_row<'a>(state: &'a State, ctx: &'a Ctx, switch: Switch, snapshot: &Snapshot) -> El<'a> {
    let p = ctx.palette;
    let (icon, title, sentence) = switch_text(ctx, switch);
    let sheet = widgets::info::for_check(ctx, title.clone(), switch.id(), false)
        .map(|s| s.without(&[sentence.as_str()]));
    let enabled = controls_enabled(Some(snapshot), state.busy.is_some());
    let working = state.busy == Some(Busy::Switch(switch));
    let on = switch.get(&snapshot.config);
    let control = widgets::switch(
        p,
        on,
        enabled.then_some(move |now_on: bool| wrap(Msg::Toggle(switch, now_on))),
    );
    let sub = if working {
        ctx.t("Changing…")
    } else {
        sentence
    };
    let control = match widgets::info::button(ctx, sheet) {
        Some(info) => row![info, control]
            .spacing(theme::S1)
            .align_y(Alignment::Center)
            .into(),
        None => control,
    };
    let head = widgets::row_item(p, Some(icon), title, Some(sub), control, None);
    let mut rows = vec![head];
    if working {
        rows.push(widgets::under_row(vec![progress::indeterminate(
            p,
            Tone::Brand,
        )]));
    }
    column(rows).width(Length::Fill).into()
}

fn status_controls<'a>(
    state: &'a State,
    ctx: &'a Ctx,
    snapshot: &Snapshot,
    line: Line,
) -> Option<El<'a>> {
    let p = ctx.palette;
    let enabled = controls_enabled(Some(snapshot), state.busy.is_some());
    let (label, kind, msg) = match status_action(line)? {
        StatusAction::Choose => (
            "Choose what to block",
            ButtonKind::Primary,
            Msg::SetTab(Tab::Block),
        ),
        StatusAction::Resume => ("Resume now", ButtonKind::Primary, Msg::Resume),
        StatusAction::Retry => ("Try again", ButtonKind::Secondary, Msg::Retry),
        StatusAction::Pause => (
            "Pause web protection",
            ButtonKind::Secondary,
            Msg::PauseChoices,
        ),
    };
    let button = widgets::action(p, kind, ctx.t(label), None, enabled.then_some(wrap(msg)));
    let working = matches!(state.busy, Some(Busy::Pause | Busy::Resume | Busy::Retry));
    let mut col = column![button].spacing(theme::S2);
    if state.pause_choices && status_action(line) == Some(StatusAction::Pause) && !working {
        let choices = PauseFor::ALL.iter().fold(row![], |r, length| {
            r.push(widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t(length.label()),
                None,
                enabled.then_some(wrap(Msg::Pause(*length))),
            ))
        });
        col = col.push(widgets::small(p, ctx.t("Pause for"))).push(
            choices
                .spacing(theme::S2)
                .wrap()
                .vertical_spacing(theme::S2),
        );
    }
    if working {
        col = col.push(progress::indeterminate(p, Tone::Brand));
    }
    Some(
        container(col)
            .padding(Padding::default().top(theme::S2))
            .into(),
    )
}

fn hero<'a>(state: &'a State, ctx: &'a Ctx, snapshot: &Snapshot) -> El<'a> {
    let p = ctx.palette;
    let line = current_line(snapshot);
    let (guard, since) = state
        .look
        .unwrap_or_else(|| (guard_of(line), Instant::now()));
    let counts = blocked_today(snapshot);
    let picture = web_globe::WebGlobe {
        p,
        plate: Plate::Surface,
        guard,
        changed: since,
        now: since,
        blocked: counts.map(|[ads, trackers, dangerous, ..]| [ads, trackers, dangerous]),
        labels: web_globe::Labels::new(|k| ctx.t(k)),
    }
    .view();
    let (title, sub) = hero_text(ctx, line, coverage(snapshot, line).as_ref());
    let mut words = column![widgets::h2(p, title)].spacing(theme::S1);
    if let Some(sub) = sub {
        words = words.push(widgets::muted(p, sub));
    }
    if snapshot.installed {
        if let Some(hint) = problem_hint(snapshot, line) {
            words = words.push(widgets::muted(p, ctx.t(hint)));
        }
    }
    if snapshot.installed {
        if let Some(controls) = status_controls(state, ctx, snapshot, line) {
            words = words.push(controls);
        }
    }
    widgets::region(
        p,
        row![picture, words.width(Length::Fill)]
            .spacing(theme::S6)
            .align_y(Alignment::Center),
    )
    .into()
}

fn stat<'a>(p: Palette, number: String, label: String) -> El<'a> {
    column![widgets::h2(p, number), widgets::small(p, label)]
        .spacing(2)
        .width(Length::Fill)
        .into()
}

fn blocked_today_group<'a>(ctx: &'a Ctx, snapshot: &Snapshot) -> Option<El<'a>> {
    let p = ctx.palette;
    let counts = blocked_today(snapshot)?;
    let count = count_fn(ctx.lang);
    let stats = Kind::ALL
        .iter()
        .filter(|k| {
            matches!(k, Kind::Ads | Kind::Tracking | Kind::Dangerous)
                || counts[k.index()] > 0
                || match k {
                    Kind::Adult => snapshot.config.adult,
                    Kind::Gambling => snapshot.config.gambling,
                    Kind::Scam => snapshot.config.scam,
                    Kind::Popups => snapshot.config.popups,
                    _ => false,
                }
        })
        .fold(row![].spacing(theme::S4), |r, k| {
            r.push(stat(p, count(counts[k.index()]), kind_label(ctx, *k)))
        });
    Some(widgets::group(
        p,
        ctx.t("Blocked today"),
        None,
        None,
        vec![widgets::region(p, stats).into()],
    ))
}

fn last_days_group<'a>(state: &'a State, ctx: &'a Ctx, days: &'a [(u64, u64)]) -> El<'a> {
    let p = ctx.palette;
    let total: u64 = days.iter().map(|(_, n)| n).sum();
    let subtitle = (total > 0).then(|| {
        ctx.t("{n} blocked in the last 30 days")
            .replace("{n}", &group_digits(ctx.lang, total))
    });
    let body: El<'a> = if total == 0 {
        widgets::muted(p, ctx.t("Nothing has been blocked yet."))
    } else {
        widgets::bars::daily(
            Palette::of(p.mode),
            Tone::Brand,
            days,
            &state.chart,
            day_fn(ctx.lang),
            count_fn(ctx.lang),
            CHART_HEIGHT,
        )
    };
    widgets::group(
        p,
        ctx.t("Last 30 days"),
        subtitle,
        None,
        vec![widgets::region(p, body).into()],
    )
}

fn most_blocked_group<'a>(ctx: &'a Ctx, top: Vec<(String, u64)>) -> Option<El<'a>> {
    if top.is_empty() {
        return None;
    }
    let p = ctx.palette;
    let rows = top
        .into_iter()
        .map(|(name, n)| {
            widgets::row_item(
                p,
                None,
                name,
                None,
                widgets::body(
                    p,
                    ctx.t("{n} blocked")
                        .replace("{n}", &group_digits(ctx.lang, n)),
                ),
                None,
            )
        })
        .collect();
    Some(widgets::group(
        p,
        ctx.t("Most blocked"),
        Some(ctx.t("Over the last 30 days, kept only on this computer.")),
        None,
        rows,
    ))
}

fn private_row<'a>(ctx: &'a Ctx, snapshot: &Snapshot) -> El<'a> {
    let p = ctx.palette;
    let state = private_state(&snapshot.config, snapshot.status.as_ref(), snapshot.now);
    let change = widgets::link(
        p,
        ctx.t(if state == LookupState::Off {
            "Turn on"
        } else {
            "Change"
        }),
        wrap(Msg::FocusPrivacy),
    );
    widgets::row_item(
        p,
        Some(Icon::Lock),
        private_text(ctx, state),
        None,
        change,
        None,
    )
}

fn gap_text(gap: Gap) -> (Icon, &'static str, &'static str) {
    match gap {
        Gap::BrowserSecureDns => (
            Icon::Globe,
            "A browser uses its own private lookups",
            "Sites it opens this way skip Web protection.",
        ),
        Gap::OtherDnsRule => (
            Icon::AlertTriangle,
            "Another program redirects your lookups",
            "A VPN, security tool or work setting on this computer sends all lookups somewhere else, so Web protection may not see them.",
        ),
        Gap::Vpn => (
            Icon::Lock,
            "Your VPN app uses its own lookups",
            "Web protection can't see those sites. Turn on your VPN's own blocking, or switch off the VPN when you don't need it.",
        ),
    }
}

fn gaps_group<'a>(ctx: &'a Ctx, gaps: &[Gap]) -> El<'a> {
    let p = ctx.palette;
    let rows = gaps
        .iter()
        .map(|gap| {
            let (glyph, title, detail) = gap_text(*gap);
            let trailing: El<'a> = if *gap == Gap::BrowserSecureDns {
                widgets::link(p, ctx.t("Open Protection"), Message::Navigate(Page::Fixes))
            } else {
                column![].into()
            };
            widgets::row_item_tinted(
                p,
                Some(glyph),
                Some(Tone::Warn),
                ctx.t(title),
                Some(ctx.t(detail)),
                trailing,
                None,
            )
        })
        .collect();
    widgets::group(p, ctx.t("What can get around it"), None, None, rows)
}

fn overview<'a>(state: &'a State, ctx: &'a Ctx, snapshot: &Snapshot) -> El<'a> {
    let p = ctx.palette;
    let mut page = column![hero(state, ctx, snapshot)].spacing(theme::S8);
    if let Some(at) = dangerous_today(snapshot) {
        page = page.push(widgets::inline_notice(
            p,
            Tone::Neutral,
            ctx.t("A dangerous website was blocked today at {time}.")
                .replace(
                    "{time}",
                    &format_clock(ctx.lang, history::local_seconds(at)),
                ),
        ));
    }
    if let Some(Coverage::Gaps(gaps)) = coverage(snapshot, current_line(snapshot)) {
        page = page.push(gaps_group(ctx, &gaps));
    }
    if snapshot.installed {
        page = page.push(private_row(ctx, snapshot));
    }
    if state.busy == Some(Busy::AllowOnce) {
        page = page.push(progress::indeterminate(p, Tone::Brand));
    }
    if let Some(group) = recent_blocks_group(state, ctx, snapshot) {
        page = page.push(group);
    }
    if let Some(group) = blocked_today_group(ctx, snapshot) {
        page = page.push(group);
    }
    if snapshot.installed {
        page = page.push(last_days_group(state, ctx, &state.days));
    }
    if let Some(group) = most_blocked_group(ctx, top_companies(snapshot.stats.as_ref(), TOP_SHOWN))
    {
        page = page.push(group);
    }
    page.into()
}

fn block_tab<'a>(state: &'a State, ctx: &'a Ctx, snapshot: &Snapshot) -> El<'a> {
    let p = ctx.palette;
    let rows = |switches: &[Switch]| -> Vec<El<'a>> {
        switches
            .iter()
            .map(|s| switch_row(state, ctx, *s, snapshot))
            .collect()
    };
    column![
        widgets::group(
            p,
            ctx.t("Protection"),
            None,
            None,
            rows(&Switch::PROTECTION)
        ),
        widgets::group(p, ctx.t("Family safety"), None, None, rows(&Switch::FAMILY)),
        widgets::group(p, ctx.t("Privacy"), None, None, rows(&Switch::PRIVACY)),
        column![
            widgets::small(
                p,
                ctx.t(
                    "Some ads, like the ones inside YouTube videos, come from the same place as the video and can't be blocked this way.",
                ),
            ),
            widgets::small(p, ctx.t("Block lists by AdGuard, EasyList, HaGeZi, malware-filter and Echap.")),
        ]
        .spacing(theme::S2),
    ]
    .spacing(theme::S8)
    .into()
}

fn site_field<'a>(
    p: Palette,
    placeholder: String,
    value: &str,
    enabled: bool,
) -> text_input::TextInput<'a, Message> {
    let pad = (theme::CONTROL - theme::LINE_BODY) / 2.0;
    let mut input = text_input(&placeholder, value)
        .size(theme::BODY)
        .font(theme::REGULAR)
        .line_height(iced::widget::text::LineHeight::Absolute(Pixels(
            theme::LINE_BODY,
        )))
        .padding(Padding {
            top: pad,
            bottom: pad,
            left: theme::S3,
            right: theme::S3,
        })
        .width(Length::Fill)
        .style(move |_, status| {
            let background = match status {
                text_input::Status::Active => p.surface_alt,
                text_input::Status::Hovered => p.hover_strong,
                text_input::Status::Focused { .. } => p.surface,
                text_input::Status::Disabled => p.disabled_bg,
            };
            text_input::Style {
                background: Background::Color(background),
                border: Border {
                    radius: theme::R.into(),
                    ..Border::default()
                },
                icon: p.text_muted,
                placeholder: p.text_muted,
                value: p.text,
                selection: Color { a: 0.3, ..p.accent },
            }
        });
    if enabled {
        input = input
            .on_input(|s| wrap(Msg::SiteInput(s)))
            .on_submit(wrap(Msg::AddSite));
    }
    input
}

fn recent_rows<'a>(state: &'a State, ctx: &'a Ctx, snapshot: &Snapshot) -> Vec<El<'a>> {
    let p = ctx.palette;
    let enabled = controls_enabled(Some(snapshot), state.busy.is_some());
    let items = visible_recent(snapshot);
    if items.is_empty() {
        let line = current_line(snapshot);
        let note = match line {
            Line::Off | Line::PrivateOnly => "Web protection is off, so nothing is being blocked.",
            Line::Paused(_) | Line::PausedUntilRestart => {
                "Web protection is paused, so nothing is being blocked."
            }
            _ => "Nothing was blocked in the last 15 minutes.",
        };
        return vec![container(widgets::muted(p, ctx.t(note)))
            .padding([0.0, theme::S4])
            .into()];
    }
    let shown = widgets::limited(&items, RECENT_SHOWN, state.all_recent);
    let mut rows: Vec<El<'a>> = shown
        .iter()
        .map(|item| {
            let dangerous = item.kind == Kind::Dangerous;
            let name = item.name.clone();
            let msg = if dangerous {
                Msg::AskAllow(name.clone())
            } else {
                Msg::Allow(name.clone())
            };
            let head = widgets::row_item(
                p,
                Some(kind_icon(item.kind)),
                name.clone(),
                Some(format!(
                    "{} · {}",
                    kind_short(ctx, item.kind),
                    ago_text(ctx, minutes_ago(snapshot.now, item.at))
                )),
                widgets::action(
                    p,
                    ButtonKind::Secondary,
                    ctx.t("Allow"),
                    None,
                    enabled.then_some(wrap(msg)),
                ),
                None,
            );
            if dangerous && state.confirm.as_deref() == Some(name.as_str()) {
                column![
                    head,
                    widgets::under_row(vec![
                        widgets::inline_notice(
                            p,
                            Tone::Warn,
                            ctx.t(
                                "This site was blocked because it may be dangerous. Only allow it if you are sure it is safe.",
                            ),
                        ),
                        row![
                            widgets::action(
                                p,
                                ButtonKind::Danger,
                                ctx.t("Allow anyway"),
                                None,
                                enabled.then_some(wrap(Msg::Allow(name))),
                            ),
                            widgets::action(
                                p,
                                ButtonKind::Ghost,
                                ctx.t("Cancel"),
                                None,
                                Some(wrap(Msg::CancelAllow)),
                            ),
                        ]
                        .spacing(theme::S2)
                        .into(),
                    ])
                ]
                .width(Length::Fill)
                .into()
            } else {
                head
            }
        })
        .collect();
    if items.len() > shown.len() {
        rows.push(widgets::show_more_button(
            p,
            ctx.t("Show more"),
            wrap(Msg::MoreRecent),
        ));
    }
    rows
}

fn recent_blocks_group<'a>(state: &'a State, ctx: &'a Ctx, snapshot: &Snapshot) -> Option<El<'a>> {
    let p = ctx.palette;
    let items = recent_blocks(snapshot);
    if items.is_empty() {
        return None;
    }
    let enabled = controls_enabled(Some(snapshot), state.busy.is_some());
    let shown = widgets::limited(&items, RECENT_SHOWN, state.all_recent);
    let mut rows: Vec<El<'a>> = shown
        .iter()
        .map(|item| {
            let name = item.name.clone();
            let dangerous = item.kind == Kind::Dangerous;
            let ask = if dangerous {
                Msg::AskOnce(name.clone())
            } else {
                Msg::AllowOnce(name.clone())
            };
            let head = widgets::row_item(
                p,
                Some(kind_icon(item.kind)),
                name.clone(),
                Some(format!(
                    "{} · {}",
                    kind_short(ctx, item.kind),
                    ago_text(ctx, minutes_ago(snapshot.now, item.at))
                )),
                widgets::action(
                    p,
                    ButtonKind::Secondary,
                    ctx.t("Let me through once"),
                    None,
                    enabled.then_some(wrap(ask)),
                ),
                None,
            );
            if dangerous && state.confirm_once.as_deref() == Some(name.as_str()) {
                column![
                    head,
                    widgets::under_row(vec![
                        widgets::inline_notice(
                            p,
                            Tone::Warn,
                            ctx.t(
                                "This site was blocked because it may be dangerous. Only open it if you are sure it is safe. It stays open for 10 minutes.",
                            ),
                        ),
                        row![
                            widgets::action(
                                p,
                                ButtonKind::Danger,
                                ctx.t("Let me through anyway"),
                                None,
                                enabled.then_some(wrap(Msg::AllowOnce(name))),
                            ),
                            widgets::action(
                                p,
                                ButtonKind::Ghost,
                                ctx.t("Cancel"),
                                None,
                                Some(wrap(Msg::CancelOnce)),
                            ),
                        ]
                        .spacing(theme::S2)
                        .into(),
                    ])
                ]
                .width(Length::Fill)
                .into()
            } else {
                head
            }
        })
        .collect();
    if items.len() > shown.len() {
        rows.push(widgets::show_more_button(
            p,
            ctx.t("Show more"),
            wrap(Msg::MoreRecent),
        ));
    }
    Some(widgets::group(
        p,
        ctx.t("Recent blocks"),
        Some(ctx.t("Blocked in the last 15 minutes. You can open one you trust for 10 minutes.")),
        None,
        rows,
    ))
}

fn allowed_rows<'a>(state: &'a State, ctx: &'a Ctx, snapshot: &Snapshot) -> Vec<El<'a>> {
    let p = ctx.palette;
    let enabled = controls_enabled(Some(snapshot), state.busy.is_some());
    if snapshot.config.allow.is_empty() {
        return vec![
            container(widgets::muted(p, ctx.t("You haven't allowed any sites.")))
                .padding([0.0, theme::S4])
                .into(),
        ];
    }
    snapshot
        .config
        .allow
        .iter()
        .map(|name| {
            widgets::row_item(
                p,
                Some(Icon::CheckCircle),
                name.clone(),
                None,
                widgets::action(
                    p,
                    ButtonKind::Ghost,
                    ctx.t("Remove"),
                    None,
                    enabled.then_some(wrap(Msg::Unallow(name.clone()))),
                ),
                None,
            )
        })
        .collect()
}

fn add_site_group<'a>(state: &'a State, ctx: &'a Ctx, snapshot: &Snapshot) -> El<'a> {
    let p = ctx.palette;
    let enabled = controls_enabled(Some(snapshot), state.busy.is_some());
    let field = site_field(p, ctx.t("example.com"), &state.site, enabled);
    let add = widgets::action(
        p,
        ButtonKind::Primary,
        ctx.t("Allow site"),
        None,
        (enabled && !state.site.trim().is_empty()).then_some(wrap(Msg::AddSite)),
    );
    let mut rows: Vec<El<'a>> = vec![container(
        row![field, add]
            .spacing(theme::S2)
            .align_y(Alignment::Center),
    )
    .padding([0.0, theme::S4])
    .into()];
    if let Some(problem) = state.site_problem {
        rows.push(
            container(
                iced::widget::text(ctx.t(site_problem_text(problem)))
                    .size(theme::SMALL)
                    .font(theme::REGULAR)
                    .color(p.bad_text),
            )
            .padding([0.0, theme::S4])
            .into(),
        );
    }
    widgets::group(
        p,
        ctx.t("Add a site"),
        Some(
            ctx.t(
                "Allow a website that web protection blocks by mistake. Only add sites you trust.",
            ),
        ),
        None,
        rows,
    )
}

fn sites_tab<'a>(state: &'a State, ctx: &'a Ctx, snapshot: &Snapshot) -> El<'a> {
    let p = ctx.palette;
    let mut page = column![].spacing(theme::S8);
    if matches!(state.busy, Some(Busy::Allow | Busy::Remove | Busy::Add)) {
        page = page.push(progress::indeterminate(p, Tone::Brand));
    }
    page = page.push(widgets::group(
        p,
        ctx.t("Something not working?"),
        Some(ctx.t("If a page you trust didn't open, allow it here.")),
        None,
        recent_rows(state, ctx, snapshot),
    ));
    page = page.push(widgets::group(
        p,
        ctx.t("Allowed sites"),
        None,
        None,
        allowed_rows(state, ctx, snapshot),
    ));
    page.push(add_site_group(state, ctx, snapshot)).into()
}

pub fn view<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    let header = widgets::page_header(
        p,
        ctx.t("Web protection"),
        Some(ctx.t("Stops ads, trackers and dangerous websites before they load.")),
    );
    let Some(snapshot) = state.snapshot.as_ref() else {
        return column![header, widgets::muted(p, ctx.t("Checking…"))]
            .spacing(theme::S8)
            .into();
    };
    let tabs = widgets::segmented(
        p,
        &[Tab::Overview, Tab::Block, Tab::Sites].map(|t| (t, tab_label(ctx, t))),
        state.tab,
        |t| wrap(Msg::SetTab(t)),
    );
    let body = match state.tab {
        Tab::Overview => overview(state, ctx, snapshot),
        Tab::Block => block_tab(state, ctx, snapshot),
        Tab::Sites => sites_tab(state, ctx, snapshot),
    };
    let mut page = column![header].spacing(theme::S6);
    let mut content = column![tabs].spacing(theme::S6);
    if !snapshot.installed {
        content = content.push(widgets::inline_notice(
            p,
            Tone::Neutral,
            ctx.t("Web protection needs Secblitz to be installed."),
        ));
    }
    content = content.push(body);
    page = page.push(content);
    page.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gui::Page;
    use secblitz::filter::config::{BlockHistory, DayCount, TopSite};

    const NOW: u64 = 1_000_000;

    fn config(ads: bool) -> Config {
        Config {
            ads,
            ..Config::default()
        }
    }

    fn healthy() -> Status {
        Status {
            listening: true,
            state: ListState::Ready,
            written_at: NOW - 5,
            day: NOW / SECONDS_PER_DAY,
            blocked: [1204, 388, 0, 0, 0, 0, 0],
            ..Status::default()
        }
    }

    fn snapshot(config: Config, status: Option<Status>, installed: bool) -> Snapshot {
        Snapshot {
            config,
            status,
            service: ServiceState::Running,
            installed,
            now: NOW,
            recent: Vec::new(),
            stats: None,
        }
    }

    #[test]
    fn coverage_is_claimed_only_when_the_pc_was_checked() {
        let with = |gaps: Option<Vec<Gap>>| {
            snapshot(config(true), Some(Status { gaps, ..healthy() }), true)
        };
        let line = |s: &Snapshot| current_line(s);
        let clear = with(Some(Vec::new()));
        assert_eq!(coverage(&clear, line(&clear)), Some(Coverage::Everything));
        let some = with(Some(vec![Gap::Vpn]));
        assert_eq!(
            coverage(&some, line(&some)),
            Some(Coverage::Gaps(vec![Gap::Vpn]))
        );
        let unknown = with(None);
        assert_eq!(coverage(&unknown, line(&unknown)), None);
        assert_eq!(coverage(&clear, Line::NotWorking), None);
        assert_eq!(coverage(&clear, Line::GettingReady), None);
        assert_eq!(coverage(&clear, Line::Paused(NOW)), None);
    }

    #[test]
    fn the_headline_follows_the_coverage() {
        let title = |c: Option<Coverage>| on_title(c.as_ref());
        assert_eq!(title(None), "Web protection is on");
        assert_eq!(
            title(Some(Coverage::Everything)),
            "Web protection covers everything"
        );
        assert_eq!(
            title(Some(Coverage::Gaps(vec![Gap::OtherDnsRule]))),
            "Web protection is on, but some sites can get around it"
        );
    }

    #[test]
    fn every_gap_has_words_and_a_changed_gap_redraws_the_page() {
        for gap in [Gap::BrowserSecureDns, Gap::OtherDnsRule, Gap::Vpn] {
            let (_, title, detail) = gap_text(gap);
            assert!(!title.is_empty() && !detail.is_empty() && !detail.contains('\u{2014}'));
        }
        let a = snapshot(config(true), Some(healthy()), true);
        let b = snapshot(
            config(true),
            Some(Status {
                gaps: Some(vec![Gap::Vpn]),
                ..healthy()
            }),
            true,
        );
        assert!(!same_look(&a, &b));
    }

    #[test]
    fn a_reading_that_only_moved_the_clock_looks_the_same() {
        let a = snapshot(config(true), Some(healthy()), true);
        let later = Snapshot {
            now: NOW + 2,
            ..a.clone()
        };
        assert!(same_look(&a, &later));
        let stale = Snapshot {
            now: NOW + 3600,
            ..a.clone()
        };
        assert!(!same_look(&a, &stale));
        let mut more = healthy();
        more.blocked[0] += 1;
        assert!(!same_look(&a, &snapshot(config(true), Some(more), true)));
    }

    #[test]
    fn page_order_has_web_after_debloat() {
        let at = |page| Page::ALL.iter().position(|p| *p == page).unwrap();
        assert_eq!(at(Page::Web), at(Page::Debloat) + 1);
        assert_eq!(Page::parse("web"), Some(Page::Web));
        assert_eq!(Page::Web.label(), "Web protection");
    }

    #[test]
    fn status_button_fits_each_state() {
        assert_eq!(status_action(Line::Off), Some(StatusAction::Choose));
        assert_eq!(status_action(Line::On), Some(StatusAction::Pause));
        assert_eq!(status_action(Line::GettingReady), Some(StatusAction::Pause));
        assert_eq!(status_action(Line::Paused(NOW)), Some(StatusAction::Resume));
        assert_eq!(status_action(Line::NotWorking), Some(StatusAction::Retry));
    }

    #[test]
    fn status_line_for_each_state() {
        let on = config(true);
        let ok = healthy();
        let running = ServiceState::Running;
        assert_eq!(status_line(&config(false), None, running, NOW), Line::Off);
        assert_eq!(status_line(&on, Some(&ok), running, NOW), Line::On);
        let waiting = Status {
            state: ListState::NoLists,
            ..healthy()
        };
        assert_eq!(
            status_line(&on, Some(&waiting), running, NOW),
            Line::GettingReady
        );
        let starting = Status {
            listening: false,
            state: ListState::Starting,
            ..healthy()
        };
        assert_eq!(
            status_line(&on, Some(&starting), running, NOW),
            Line::GettingReady
        );
        for service in [
            ServiceState::Stopped,
            ServiceState::NotInstalled,
            ServiceState::Other,
        ] {
            assert_eq!(status_line(&on, Some(&ok), service, NOW), Line::NotWorking);
        }
        let port = Status {
            listening: false,
            last_error: Some(ErrorCode::PortInUse),
            ..healthy()
        };
        assert_eq!(
            status_line(&on, Some(&port), running, NOW),
            Line::NotWorking
        );
        let late = Status {
            last_error: Some(ErrorCode::DownloadFailed),
            ..healthy()
        };
        assert_eq!(status_line(&on, Some(&late), running, NOW), Line::On);
    }

    #[test]
    fn only_private_lookups_is_its_own_state() {
        let only = Config {
            private_lookups: true,
            ..config(false)
        };
        let running = ServiceState::Running;
        assert_eq!(
            status_line(&only, Some(&healthy()), running, NOW),
            Line::PrivateOnly
        );
        assert_eq!(status_action(Line::PrivateOnly), Some(StatusAction::Choose));
        assert_eq!(guard_of(Line::PrivateOnly), web_globe::Guard::Off);
        for service in [
            ServiceState::Stopped,
            ServiceState::NotInstalled,
            ServiceState::Other,
        ] {
            assert_eq!(
                status_line(&only, Some(&healthy()), service, NOW),
                Line::NotWorking
            );
        }
        assert_eq!(status_line(&only, None, running, NOW), Line::NotWorking);
        let port = Status {
            listening: false,
            last_error: Some(ErrorCode::PortInUse),
            ..healthy()
        };
        assert_eq!(
            status_line(&only, Some(&port), running, NOW),
            Line::NotWorking
        );
        assert_eq!(status_action(Line::NotWorking), Some(StatusAction::Retry));
    }

    #[test]
    fn paused_until_restart_shows_as_paused() {
        let until_restart = Config {
            paused_boot: Some(config::boot_time(NOW)),
            ..config(true)
        };
        assert_eq!(
            status_line(&until_restart, Some(&healthy()), ServiceState::Running, NOW),
            Line::PausedUntilRestart
        );
        assert_eq!(
            status_action(Line::PausedUntilRestart),
            Some(StatusAction::Resume)
        );
        assert_eq!(guard_of(Line::PausedUntilRestart), web_globe::Guard::Paused);
    }

    #[test]
    fn paused_shows_until_time() {
        let paused = Config {
            paused_until: Some(NOW + 600),
            ..config(true)
        };
        assert_eq!(
            status_line(&paused, Some(&healthy()), ServiceState::Running, NOW),
            Line::Paused(NOW + 600)
        );
        let over = Config {
            paused_until: Some(NOW - 1),
            ..config(true)
        };
        assert_eq!(
            status_line(&over, Some(&healthy()), ServiceState::Running, NOW),
            Line::On
        );
        let idle = Config {
            paused_until: Some(NOW + 600),
            ..config(false)
        };
        assert_eq!(
            status_line(&idle, None, ServiceState::Running, NOW),
            Line::Off
        );
        assert_eq!(format_clock(Lang::En, 15 * 3600 + 15 * 60), "3:15 PM");
        assert_eq!(format_clock(Lang::En, 5), "12:00 AM");
        assert_eq!(format_clock(Lang::En, 12 * 3600 + 5 * 60), "12:05 PM");
        assert_eq!(format_clock(Lang::De, 9 * 3600 + 7 * 60), "9:07");
    }

    #[test]
    fn stale_status_shows_not_working() {
        let old = Status {
            written_at: NOW - 121,
            ..healthy()
        };
        assert_eq!(
            status_line(&config(true), Some(&old), ServiceState::Running, NOW),
            Line::NotWorking
        );
        assert_eq!(
            status_line(&config(true), None, ServiceState::Running, NOW),
            Line::NotWorking
        );
        assert!(blocked_today(&snapshot(config(true), Some(old), true)).is_none());
    }

    #[test]
    fn portable_disables_switches() {
        let portable = snapshot(config(false), Some(healthy()), false);
        assert!(!controls_enabled(Some(&portable), false));
        let installed = snapshot(config(false), None, true);
        assert!(controls_enabled(Some(&installed), false));
        assert!(!controls_enabled(Some(&installed), true));
        assert!(!controls_enabled(None, false));
        assert!(!suggests(&portable));
        assert!(suggests(&installed));
        assert!(!suggests(&snapshot(config(true), None, true)));
    }

    #[test]
    fn counts_come_from_today_only() {
        let s = snapshot(config(true), Some(healthy()), true);
        assert_eq!(blocked_today(&s), Some([1204, 388, 0, 0, 0, 0, 0]));
        let yesterday = Status {
            day: NOW / SECONDS_PER_DAY - 1,
            ..healthy()
        };
        assert_eq!(
            blocked_today(&snapshot(config(true), Some(yesterday), true)),
            Some([0; KINDS])
        );
        assert!(blocked_today(&snapshot(config(false), Some(healthy()), true)).is_none());
    }

    #[test]
    fn numbers_are_grouped() {
        assert_eq!(group_digits(Lang::En, 0), "0");
        assert_eq!(group_digits(Lang::En, 999), "999");
        assert_eq!(group_digits(Lang::En, 1204), "1,204");
        assert_eq!(group_digits(Lang::De, 1_234_567), "1.234.567");
    }

    #[test]
    fn changing_a_switch_keeps_the_others() {
        let mut c = Config {
            tracking: true,
            paused_until: Some(5),
            ..config(false)
        };
        Switch::Ads.set(&mut c, true);
        assert!(Switch::Ads.get(&c) && Switch::Tracking.get(&c) && !Switch::Dangerous.get(&c));
        Switch::Adult.set(&mut c, true);
        Switch::PrivateLookups.set(&mut c, true);
        assert!(c.adult && c.private_lookups && c.ads && c.tracking && !c.gambling);
        assert_eq!(c.paused_until, Some(5));
    }

    #[test]
    fn picture_follows_the_status_and_keeps_its_clock() {
        use web_globe::Guard;
        assert_eq!(guard_of(Line::On), Guard::On);
        assert_eq!(guard_of(Line::Off), Guard::Off);
        assert_eq!(guard_of(Line::Paused(NOW)), Guard::Paused);
        assert_eq!(guard_of(Line::GettingReady), Guard::Starting);
        assert_eq!(guard_of(Line::NotWorking), Guard::Broken);
        assert!(Guard::On.blocks() && !Guard::Starting.blocks());

        let mut state = State::default();
        let t0 = Instant::now();
        let on = snapshot(config(true), Some(healthy()), true);
        note_look(&mut state, &on, t0);
        assert_eq!(state.look, Some((Guard::On, t0)));
        note_look(&mut state, &on, t0 + Duration::from_secs(2));
        assert_eq!(state.look, Some((Guard::On, t0)));
        let t1 = t0 + Duration::from_secs(4);
        note_look(&mut state, &snapshot(config(false), None, true), t1);
        assert_eq!(state.look, Some((Guard::Off, t1)));
    }

    #[test]
    fn every_switch_has_an_explainer() {
        for s in Switch::ALL {
            assert!(secblitz::explain::for_check(s.id()).is_some());
        }
    }

    #[test]
    fn known_failures_get_a_fix_and_unknown_ones_never_echo_raw_text() {
        let admin = failure_text("Changing web protection needs administrator rights");
        assert!(admin.contains("Sign in with an account"));
        assert!(failure_text("The service is marked for deletion (1072)")
            .contains("Restart your computer"));
        let raw = "os error 87: weird HRESULT 0x80070057 in scm.rs";
        let general = failure_text(raw);
        assert!(general.starts_with("We couldn't change web protection."));
        assert!(!general.contains("0x8") && !general.contains("scm"));
        for text in [admin, general] {
            assert!(!text.contains('\u{2014}'));
        }
    }

    #[test]
    fn problems_explain_themselves_with_a_next_step() {
        let on = config(true);
        let port = Status {
            listening: false,
            last_error: Some(ErrorCode::PortInUse),
            ..healthy()
        };
        let s = snapshot(on.clone(), Some(port), true);
        let line = status_line(&s.config, s.status.as_ref(), s.service, s.now);
        assert!(!problem_hint(&s, line).unwrap().contains("Try again"));
        let down = Snapshot {
            service: ServiceState::Stopped,
            ..snapshot(on.clone(), None, true)
        };
        assert!(problem_hint(&down, Line::NotWorking)
            .unwrap()
            .contains("restart your computer"));
        let ok = snapshot(on, Some(healthy()), true);
        assert!(problem_hint(&ok, Line::On).is_none());
    }

    fn item(name: &str, kind: Kind, at: u64) -> RecentItem {
        RecentItem {
            name: name.to_string(),
            kind,
            at,
        }
    }

    fn history_of(days: &[(u64, [u64; KINDS])], top: &[(&str, u64)]) -> BlockHistory {
        BlockHistory {
            days: days
                .iter()
                .map(|(day, blocked)| DayCount {
                    day: *day,
                    blocked: *blocked,
                })
                .collect(),
            top: top
                .iter()
                .map(|(site, count)| TopSite {
                    site: site.to_string(),
                    count: *count,
                })
                .collect(),
            top_companies: Vec::new(),
        }
    }

    #[test]
    fn the_chart_covers_thirty_days_ending_today_with_zeros_for_quiet_days() {
        let today = 20_000;
        let stats = history_of(
            &[
                (today - 29, [1, 2, 3, 0, 0, 0, 0]),
                (today - 3, [10, 0, 0, 4, 1, 0, 0]),
            ],
            &[],
        );
        let days = daily_totals(Some(&stats), today, None);
        assert_eq!(days.len(), 30);
        assert_eq!(days[0], (today - 29, 6));
        assert_eq!(days[29], (today, 0));
        assert_eq!(days[26], (today - 3, 15));
        assert!(days.windows(2).all(|w| w[1].0 == w[0].0 + 1));
        let none = daily_totals(None, today, None);
        assert_eq!(none.len(), 30);
        assert!(none.iter().all(|(_, n)| *n == 0));
    }

    #[test]
    fn today_uses_the_newer_of_the_saved_and_the_live_count() {
        let today = 20_000;
        let stats = history_of(&[(today, [5, 0, 0, 0, 0, 0, 0])], &[]);
        assert_eq!(daily_totals(Some(&stats), today, Some(9))[29].1, 9);
        assert_eq!(daily_totals(Some(&stats), today, Some(2))[29].1, 5);
        assert_eq!(daily_totals(Some(&stats), today, None)[29].1, 5);
        let next = daily_totals(Some(&stats), today + 1, Some(1));
        assert_eq!(next[28].1, 5);
        assert_eq!(next[29].1, 1);
        assert_eq!(daily_totals(None, 3, None).len(), 30);
    }

    #[test]
    fn most_blocked_lists_companies_in_the_saved_order_up_to_the_limit() {
        let mut stats = history_of(&[], &[]);
        stats.top_companies = [
            ("Google", 200),
            ("example.org", 150),
            ("Meta", 60),
            ("a.example", 1),
            ("b.example", 1),
            ("c.example", 1),
        ]
        .iter()
        .map(|(site, count)| TopSite {
            site: site.to_string(),
            count: *count,
        })
        .collect();
        let top = top_companies(Some(&stats), 5);
        assert_eq!(
            top,
            vec![
                ("Google".to_string(), 200),
                ("example.org".to_string(), 150),
                ("Meta".to_string(), 60),
                ("a.example".to_string(), 1),
                ("b.example".to_string(), 1),
            ]
        );
        assert!(top_companies(None, 5).is_empty());
        assert!(top_companies(Some(&stats), 0).is_empty());
    }

    #[test]
    fn typed_addresses_become_bare_site_names() {
        assert_eq!(site_from_input("example.com"), "example.com");
        assert_eq!(site_from_input("  Example.COM  "), "Example.COM");
        assert_eq!(
            site_from_input("https://www.example.com/path?q=1#top"),
            "www.example.com"
        );
        assert_eq!(site_from_input("HTTP://example.com:8080/x"), "example.com");
        assert_eq!(site_from_input("example.com/"), "example.com");
        assert_eq!(site_from_input("example.com?x=1"), "example.com");
    }

    #[test]
    fn adding_a_site_checks_the_name_the_list_and_its_size() {
        let allowed = vec!["example.com".to_string()];
        assert_eq!(
            check_new_site("https://Shop.Example.org/", &allowed),
            Ok("shop.example.org".to_string())
        );
        assert_eq!(check_new_site("   ", &allowed), Err(SiteProblem::Empty));
        assert_eq!(check_new_site("", &allowed), Err(SiteProblem::Empty));
        assert_eq!(
            check_new_site("hello", &allowed),
            Err(SiteProblem::NotAName)
        );
        assert_eq!(
            check_new_site("not a site.com", &allowed),
            Err(SiteProblem::NotAName)
        );
        assert_eq!(
            check_new_site("-bad-.com", &allowed),
            Err(SiteProblem::NotAName)
        );
        assert_eq!(
            check_new_site("EXAMPLE.com.", &allowed),
            Err(SiteProblem::Already)
        );
        let full: Vec<String> = (0..MAX_ALLOWED)
            .map(|i| format!("site{i}.example"))
            .collect();
        assert_eq!(check_new_site("new.example", &full), Err(SiteProblem::Full));
        for problem in [
            SiteProblem::Empty,
            SiteProblem::NotAName,
            SiteProblem::Already,
            SiteProblem::Full,
        ] {
            let text = site_problem_text(problem);
            assert!(!text.contains('\u{2014}') && text.ends_with('.'));
        }
    }

    #[test]
    fn an_allowed_site_also_covers_the_names_under_it() {
        let allowed = vec!["example.com".to_string()];
        assert!(is_allowed("example.com", &allowed));
        assert!(is_allowed("ads.example.com", &allowed));
        assert!(!is_allowed("badexample.com", &allowed));
        assert!(!is_allowed("example.com.evil.net", &allowed));
        assert!(!is_allowed("example.com", &[]));
    }

    #[test]
    fn allowed_sites_leave_the_something_not_working_list() {
        let mut s = snapshot(
            Config {
                allow: vec!["ok.example".to_string()],
                ..config(true)
            },
            Some(healthy()),
            true,
        );
        s.recent = vec![
            item("ads.ok.example", Kind::Ads, NOW - 10),
            item("tracker.other.example", Kind::Tracking, NOW - 20),
        ];
        let shown = visible_recent(&s);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0].name, "tracker.other.example");
    }

    #[test]
    fn recent_blocks_list_only_scam_dangerous_and_popup_sites() {
        let mut s = snapshot(config(true), Some(healthy()), true);
        s.recent = vec![
            item("ads.example", Kind::Ads, NOW - 5),
            item("shop.example", Kind::Scam, NOW - 10),
            item("evil.example", Kind::Dangerous, NOW - 20),
            item("pop.example", Kind::Popups, NOW - 30),
            item("tracker.example", Kind::Tracking, NOW - 40),
            item("adult.example", Kind::Adult, NOW - 50),
            item("bet.example", Kind::Gambling, NOW - 60),
        ];
        let names: Vec<_> = recent_blocks(&s).iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["shop.example", "evil.example", "pop.example"]);
    }

    #[test]
    fn a_site_let_through_once_leaves_the_lists_until_it_runs_out() {
        use secblitz::filter::config::AllowOnce;
        let mut s = snapshot(
            Config {
                allow_once: vec![AllowOnce {
                    site: "shop.example".into(),
                    until: NOW + 300,
                }],
                ..config(true)
            },
            Some(healthy()),
            true,
        );
        s.recent = vec![
            item("www.shop.example", Kind::Scam, NOW - 10),
            item("evil.example", Kind::Dangerous, NOW - 20),
        ];
        assert_eq!(recent_blocks(&s).len(), 1);
        assert_eq!(visible_recent(&s).len(), 1);
        s.now = NOW + 300;
        assert_eq!(recent_blocks(&s).len(), 2);
    }

    #[test]
    fn scam_and_popup_switches_start_off_and_sit_under_protection() {
        let c = Config::default();
        assert!(!Switch::Scam.get(&c) && !Switch::Popups.get(&c));
        let mut c = Config::default();
        Switch::Scam.set(&mut c, true);
        assert!(c.scam && !c.popups);
        Switch::Popups.set(&mut c, true);
        assert!(c.scam && c.popups);
        let protection = Switch::PROTECTION;
        let at = |s: Switch| protection.iter().position(|p| *p == s).unwrap();
        assert!(at(Switch::Dangerous) < at(Switch::Scam));
        assert!(at(Switch::Scam) < at(Switch::Popups));
        assert!(!Switch::FAMILY.contains(&Switch::Scam));
    }

    #[test]
    fn blocks_are_told_in_whole_minutes() {
        assert_eq!(minutes_ago(NOW, NOW), 0);
        assert_eq!(minutes_ago(NOW, NOW - 59), 0);
        assert_eq!(minutes_ago(NOW, NOW - 60), 1);
        assert_eq!(minutes_ago(NOW, NOW - 14 * 60 - 30), 14);
        assert_eq!(minutes_ago(NOW, NOW + 30), 0);
    }

    #[test]
    fn day_labels_and_counts_read_properly_in_every_language() {
        assert_eq!(short_day(Lang::En, 0), "1 Jan");
        assert_eq!(short_day(Lang::En, 20_368), "7 Oct");
        assert_eq!(count_fn(Lang::En)(1_204), "1,204");
        assert_eq!(count_fn(Lang::De)(1_204), "1.204");
        assert_eq!(count_fn(Lang::Fr)(0), "0");
        assert_eq!(day_fn(Lang::En)(20_368), "7 Oct");
    }

    #[test]
    fn the_private_lookups_line_follows_the_switch_and_the_service() {
        let on = Config {
            private_lookups: true,
            ..config(false)
        };
        let status = |lookups| Status {
            lookups,
            ..healthy()
        };
        assert_eq!(
            private_state(&config(true), Some(&healthy()), NOW),
            LookupState::Off
        );
        assert_eq!(
            private_state(&on, Some(&status(Lookups::Private)), NOW),
            LookupState::Private
        );
        assert_eq!(
            private_state(&on, Some(&status(Lookups::PrivateFallback)), NOW),
            LookupState::Paused
        );
        assert_eq!(
            private_state(&on, Some(&status(Lookups::Plain)), NOW),
            LookupState::GettingReady
        );
        assert_eq!(private_state(&on, None, NOW), LookupState::NotRunning);
        let paused = Config {
            paused_until: Some(NOW + 60),
            ..on.clone()
        };
        assert_eq!(
            private_state(&paused, Some(&status(Lookups::Plain)), NOW),
            LookupState::PausedWithBlocking
        );
        let stale = Status {
            written_at: NOW - 500,
            ..status(Lookups::Private)
        };
        assert_eq!(
            private_state(&on, Some(&stale), NOW),
            LookupState::NotRunning
        );
    }

    #[test]
    fn a_dangerous_block_shows_only_on_the_day_it_happened() {
        let mut s = snapshot(config(true), Some(healthy()), true);
        assert_eq!(dangerous_today(&s), None);
        s.status = Some(Status {
            dangerous_at: Some(NOW - 60),
            ..healthy()
        });
        assert_eq!(dangerous_today(&s), Some(NOW - 60));
        s.status = Some(Status {
            dangerous_at: Some(NOW - 3 * SECONDS_PER_DAY),
            ..healthy()
        });
        assert_eq!(dangerous_today(&s), None);
        s.status = Some(Status {
            dangerous_at: Some(NOW + 600),
            ..healthy()
        });
        assert_eq!(dangerous_today(&s), None);
    }

    #[test]
    fn new_blocks_and_new_statistics_redraw_the_page() {
        let a = snapshot(config(true), Some(healthy()), true);
        let mut with_recent = a.clone();
        with_recent.recent = vec![item("ads.example.com", Kind::Ads, NOW - 5)];
        assert!(!same_look(&a, &with_recent));
        let mut later = with_recent.clone();
        later.now = NOW + 2;
        assert!(same_look(&with_recent, &later));
        later.now = NOW + 61;
        assert!(!same_look(&with_recent, &later));
        let mut with_stats = a.clone();
        with_stats.stats = Some(history_of(&[(1, [1, 0, 0, 0, 0, 0, 0])], &[]));
        assert!(!same_look(&a, &with_stats));
    }

    #[test]
    fn site_errors_from_the_backend_become_plain_sentences() {
        assert_eq!(failure_text(NOT_A_NAME), NOT_A_NAME);
        assert_eq!(failure_text(LIST_FULL), LIST_FULL);
        assert_eq!(failure_text(LIST_TOO_LONG), LIST_TOO_LONG);
    }

    #[test]
    fn every_pause_choice_and_tab_has_words_without_dashes() {
        for length in PauseFor::ALL {
            let label = length.label();
            assert!(!label.is_empty() && !label.contains('\u{2014}'));
        }
        assert_eq!(PauseFor::ALL.len(), 3);
        assert_eq!(Tab::default(), Tab::Overview);
    }

    #[test]
    fn the_switches_are_grouped_once_each() {
        let mut grouped: Vec<Switch> = Vec::new();
        grouped.extend(Switch::PROTECTION);
        grouped.extend(Switch::FAMILY);
        grouped.extend(Switch::PRIVACY);
        assert_eq!(grouped.len(), Switch::ALL.len());
        for s in Switch::ALL {
            assert_eq!(grouped.iter().filter(|g| **g == s).count(), 1);
        }
        let mut ids: Vec<&str> = Switch::ALL.iter().map(|s| s.id()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), Switch::ALL.len());
    }

    fn busy_day() -> Snapshot {
        let today = NOW / SECONDS_PER_DAY;
        let mut s = snapshot(
            Config {
                tracking: true,
                dangerous: true,
                adult: true,
                private_lookups: true,
                allow: vec!["example.com".into(), "shop.example.org".into()],
                ..config(true)
            },
            Some(Status {
                lookups: Lookups::PrivateFallback,
                dangerous_at: Some(NOW - 600),
                blocked: [1204, 388, 7, 2, 0, 0, 0],
                ..healthy()
            }),
            true,
        );
        s.recent = vec![
            item("ads.tracker-network.example", Kind::Ads, NOW - 30),
            item("login.scam.example", Kind::Dangerous, NOW - 130),
        ];
        s.stats = Some(history_of(
            &(0..30)
                .map(|i| {
                    (
                        today.saturating_sub(29) + i,
                        [i * 7 % 90, i % 11, i % 3, 0, 0, 0, 0],
                    )
                })
                .collect::<Vec<_>>(),
            &[("doubleclick.net", 520), ("example-ads.org", 90)],
        ));
        s
    }

    #[test]
    fn every_tab_lays_out_in_every_language_and_state() {
        use crate::gui::{App, Options, Page};
        use iced::advanced::layout::Limits;
        use iced::advanced::renderer::Headless;
        use iced::advanced::widget::Tree;

        let renderer = iced::futures::executor::block_on(<iced::Renderer as Headless>::new(
            theme::REGULAR,
            14.0.into(),
            Some("tiny-skia"),
        ))
        .expect("tiny-skia renderer");
        let size = iced::Size::new(1100.0, 720.0);
        let stopped = Snapshot {
            service: ServiceState::Stopped,
            ..busy_day()
        };
        let paused = Snapshot {
            config: Config {
                paused_until: Some(NOW + 600),
                ..busy_day().config
            },
            ..busy_day()
        };
        let states = [
            busy_day(),
            stopped,
            paused,
            snapshot(config(false), None, false),
            snapshot(config(true), Some(healthy()), true),
        ];
        for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            for snap in &states {
                for tab in [Tab::Overview, Tab::Block, Tab::Sites] {
                    let (mut app, _) = App::new(Options {
                        lang,
                        broker: None,
                        start: None,
                    });
                    app.page = Page::Web;
                    app.enter_t = 1.0;
                    app.web.days = daily_totals(
                        snap.stats.as_ref(),
                        snap.now / SECONDS_PER_DAY,
                        blocked_today(snap).map(|c| c.iter().sum::<u64>()),
                    );
                    app.web.snapshot = Some(snap.clone());
                    app.web.tab = tab;
                    app.web.pause_choices = true;
                    app.web.confirm = Some("login.scam.example".into());
                    app.web.site = "https://shop.example.org/".into();
                    app.web.site_problem = Some(SiteProblem::NotAName);
                    let mut element = app.view();
                    let mut tree = Tree::new(&element);
                    let node = element.as_widget_mut().layout(
                        &mut tree,
                        &renderer,
                        &Limits::new(iced::Size::ZERO, size),
                    );
                    assert!(node.size().width > 0.0 && node.size().height > 0.0);
                }
            }
        }
    }
}
