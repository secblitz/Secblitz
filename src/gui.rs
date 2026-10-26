//! The Secblitz window (iced, CPU renderer).
#[cfg(test)]
mod bench;
pub mod icons;
pub mod pages;
mod persist;
pub mod render;
mod tasks;
pub mod theme;
pub mod warn;
pub mod widgets;
mod window;

use crate::app::{self, score::Score, worker};
use crate::i18n::Lang;
use iced::widget::{button, column, container, row, scrollable, stack, text};
use iced::{keyboard, Alignment, Background, Border, Element, Length, Subscription, Task};
use icons::Icon;
use pages::{
    app_access, debloat, fixes, fixflow, history, home, recovery, settings, tools, web, welcome,
};
use secblitz::engine::Report;
use secblitz::model::CheckStatus;
use std::path::PathBuf;
use std::sync::Arc;
use theme::{Palette, Tone};

use persist::{forget_check, persist, Cache};
pub use persist::{save_prefs, wait_persisted};
pub use tasks::{blocking, blocking_stream};
use window::{match_title_bar, window_icon};

#[derive(Debug, Clone)]
pub struct Options {
    pub lang: Lang,
    pub broker: Option<String>,
    pub start: Option<Page>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Page {
    #[default]
    Home,
    Fixes,
    Debloat,
    Web,
    Tools,
    History,
    Settings,
}

impl Page {
    pub const ALL: [Page; 7] = [
        Page::Home,
        Page::Fixes,
        Page::Debloat,
        Page::Web,
        Page::Tools,
        Page::History,
        Page::Settings,
    ];
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "home" => Page::Home,
            "fixes" => Page::Fixes,
            "debloat" => Page::Debloat,
            "web" => Page::Web,
            "tools" => Page::Tools,
            "history" => Page::History,
            "settings" => Page::Settings,
            _ => return None,
        })
    }
    pub fn open_target(s: &str) -> Page {
        match s.to_ascii_lowercase().as_str() {
            "protection" => Page::Fixes,
            "web" => Page::Web,
            "tools" => Page::Tools,
            "history" => Page::History,
            _ => Page::Home,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Page::Home => "Home",
            Page::Fixes => "Protection",
            Page::Debloat => "Clean up apps",
            Page::Web => "Web protection",
            Page::Tools => "Tools",
            Page::History => "History",
            Page::Settings => "Settings",
        }
    }
    pub fn icon(self) -> Icon {
        match self {
            Page::Home => Icon::Home,
            Page::Fixes => Icon::Shield,
            Page::Debloat => Icon::Sparkles,
            Page::Web => Icon::Globe,
            Page::Tools => Icon::Toolbox,
            Page::History => Icon::History,
            Page::Settings => Icon::Settings,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CheckProgress {
    pub phase: Option<worker::Phase>,
    pub items: Vec<(String, String)>,
}

/// Whether the helper that acts with the person's normal rights is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Helper {
    Ready,
    /// Started in an unusual way; opening Secblitz from its shortcut fixes it.
    Reopen,
    /// Built-in Administrator or UAC turned off: there are no normal rights to
    /// act with, so per-account work is not possible. Pages still open.
    NotOnThisAccount,
}

pub const REOPEN_TO_DO_THIS: &str =
    "Close Secblitz and open it again from its Start menu shortcut to do this.";
pub const NOT_ON_THIS_ACCOUNT: &str = "Windows doesn't let Secblitz do this from the built-in Administrator account or when account protection (UAC) is off.";

impl Helper {
    /// Why per-account work can't run on this start, or nothing when it can.
    pub fn blocker(self) -> Option<&'static str> {
        match self {
            Helper::Ready => None,
            Helper::Reopen => Some(REOPEN_TO_DO_THIS),
            Helper::NotOnThisAccount => Some(NOT_ON_THIS_ACCOUNT),
        }
    }
}

pub struct Ctx {
    pub lang: Lang,
    pub palette: Palette,
    pub worker: worker::Worker,
    pub catalog: worker::Catalog,
    pub engine_error: Option<String>,
    pub damage: Option<recovery::DamageInfo>,
    pub report: Option<Arc<Report>>,
    pub check_error: Option<String>,
    pub checked_at: Option<u64>,
    pub checking: Option<CheckProgress>,
    /// A check has ended and its screen is settling before the result shows.
    pub finishing: bool,
    pub busy: bool,
    pub broker: Option<Arc<crate::broker::Client>>,
    pub helper: Helper,
    pub state_dir: Option<PathBuf>,
    pub prefs: app::settings::Prefs,
    /// This x64 build runs through emulation on an ARM PC.
    pub x64_on_arm: bool,
    pub toast: Option<(String, Tone)>,
    pub info: Option<Box<widgets::info::InfoSheet>>,
    pub copilot_installed: bool,
}

impl Ctx {
    pub fn t(&self, key: &str) -> String {
        self.lang.t(key)
    }

    /// Something is about to change the PC: the next opening must check again
    /// instead of showing the saved check.
    pub fn forget_check(&self) {
        forget_check(self.state_dir.clone());
    }
    /// A check the person started, not the one that ends a fix or undo.
    /// Home and Protection give it the whole page.
    pub fn full_check(&self) -> Option<&CheckProgress> {
        self.checking
            .as_ref()
            .filter(|c| c.phase != Some(worker::Phase::Verifying))
    }
    pub fn score(&self) -> Option<Score> {
        self.report.as_deref().map(Score::of)
    }
    /// Settings pages and web links can open: through the helper, or directly
    /// when this account has no normal rights to open them with.
    pub fn can_open_pages(&self) -> bool {
        self.helper != Helper::Reopen
    }

    pub fn broker_task(
        &self,
        request: crate::broker::Request,
        map: impl Fn(Result<crate::broker::Reply, String>) -> Message + Send + 'static,
    ) -> Task<Message> {
        let Some(client) = self.broker.clone() else {
            return match request.page() {
                Some(action) if self.helper == Helper::NotOnThisAccount => Task::perform(
                    blocking(move || {
                        secblitz::actions::run(action)
                            .map(|_| crate::broker::Reply::Done)
                            .map_err(|e| format!("{e:#}"))
                    }),
                    map,
                ),
                _ => Task::done(map(Err("unavailable".into()))),
            };
        };
        if !request.is_read_only() {
            self.forget_check();
        }
        // The page is opened by the launcher, which is not the foreground
        // process, so Windows would put it behind this window. This window
        // has the focus (the person just clicked), so it may hand that on.
        #[cfg(windows)]
        if request.opens_window() {
            use windows_sys::Win32::UI::WindowsAndMessaging::{AllowSetForegroundWindow, ASFW_ANY};
            // SAFETY: plain Win32 call with no pointers.
            unsafe { AllowSetForegroundWindow(ASFW_ANY) };
        }
        Task::perform(
            blocking(move || client.send(request).map_err(|e| format!("{e:#}"))),
            map,
        )
    }

    /// Measures or clears one of the signed-in person's own leftover folders through the helper.
    pub fn space_task(
        &self,
        area: secblitz::space::UserArea,
        op: crate::broker::SpaceOp,
        map: impl Fn(Result<(crate::broker::Reply, secblitz::space::Tally), String>) -> Message
            + Send
            + 'static,
    ) -> Task<Message> {
        let Some(client) = self.broker.clone() else {
            return Task::done(map(Err("unavailable".into())));
        };
        Task::perform(
            blocking(move || client.space(area, op).map_err(|e| format!("{e:#}"))),
            map,
        )
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    Navigate(Page),
    /// Opens Clean up apps already narrowed to the app with this package name.
    OpenCleanUp(&'static str),
    CheckNow,
    /// A check after a change the person made, only once they have agreed to checks.
    CheckIfAgreed,
    Worker(worker::Event),
    ReviewFixes(Vec<String>),
    ReviewUndo,
    ReviewUndoSome(Vec<String>),
    /// Opens the Protection page on the settings Secblitz changed.
    PutBackChosen,
    Escape,
    SearchEscape,
    Find,
    Noop,
    CloseWhatsNew,
    CloseRequested(iced::window::Id),
    Toast(String, Tone),
    Info(Option<Box<widgets::info::InfoSheet>>),
    InfoPoint(String),
    DismissToast,
    ToastExpire(u32),
    ToastGone,
    PageFrame(std::time::Instant),
    HandoffLeave(std::time::Instant),
    Tab(bool),
    Home(home::Msg),
    Fixes(fixes::Msg),
    Fix(fixflow::Msg),
    Debloat(debloat::Msg),
    Web(web::Msg),
    Tools(tools::Msg),
    History(history::Msg),
    Settings(settings::Msg),
    Recovery(recovery::Msg),
    AppAccess(app_access::Msg),
    PageOpened(crate::guide::Page, bool),
    WindowFocus(bool),
    OpenRequested(String),
    Welcome(welcome::Msg),
}

const RECHECK_WINDOW: std::time::Duration = std::time::Duration::from_secs(30 * 60);

#[derive(Debug, Default)]
struct Recheck {
    opened: Option<std::time::Instant>,
    left: bool,
}

impl Recheck {
    fn arm(&mut self, now: std::time::Instant, focused: bool) {
        self.opened = Some(now);
        self.left = !focused;
    }

    fn focus(&mut self, focused: bool, now: std::time::Instant, idle: bool) -> bool {
        let Some(at) = self.opened else {
            return false;
        };
        if now.saturating_duration_since(at) > RECHECK_WINDOW {
            *self = Self::default();
            return false;
        }
        if !focused {
            self.left = true;
            return false;
        }
        if !self.left || !idle {
            return false;
        }
        *self = Self::default();
        true
    }
}

/// A finished check whose result waits for the checking screen to settle.
struct Handoff {
    start: std::time::Instant,
    leaving: Option<std::time::Instant>,
    event: worker::Event,
}

pub struct App {
    pub page: Page,
    pub ctx: Ctx,
    pub home: home::State,
    pub fixes: fixes::State,
    pub fix: fixflow::State,
    pub debloat: debloat::State,
    pub web: web::State,
    pub tools: tools::State,
    pub history: history::State,
    pub settings: settings::State,
    pub app_access: app_access::State,
    privacy_shown: bool,
    whats_new: bool,
    toast_gen: u32,
    toast_leaving: bool,
    entered: Option<std::time::Instant>,
    enter_t: f32,
    handoff: Option<Handoff>,
    leave_t: f32,
    warmed: [bool; 3],
    flight: [bool; 3],
    warm_at: [Option<std::time::Instant>; 3],
    recheck: Recheck,
    switch_backs_seen: std::collections::HashSet<String>,
    focused: bool,
    page_first_tab: bool,
    user: Option<String>,
    welcome: Option<welcome::State>,
    /// The person has agreed to a check, now or in an earlier run.
    may_check: bool,
}

impl App {
    /// A setting the monitor saw switched back after the result on screen was made.
    fn switched_back_unseen(&mut self) -> bool {
        let (Some(report), Some(status)) = (&self.ctx.report, secblitz::status::read()) else {
            return false;
        };
        let missed = app::last_check::missed_switch_backs(report, &status.reverted);
        let unseen = missed
            .iter()
            .any(|id| !self.switch_backs_seen.contains(*id));
        self.switch_backs_seen.extend(missed.into_iter().cloned());
        unseen
    }

    fn new(options: Options) -> (Self, Task<Message>) {
        let used_before =
            secblitz::platform::app_dir().is_ok_and(|dir| app::whats_new::used_before(&dir));
        let mut prefs = app::settings::load();
        let whats_new = app::whats_new::due(prefs.whats_new_seen.as_deref(), used_before);
        // Tests stand for a PC that has checked before; its own files must not decide the screen.
        let has_history = cfg!(test)
            || secblitz::platform::app_dir().is_ok_and(|dir| app::welcome::has_history(&dir));
        let news_unrecorded = prefs.whats_new_seen.as_deref() != Some(app::whats_new::VERSION);
        if news_unrecorded {
            prefs.whats_new_seen = Some(app::whats_new::VERSION.to_owned());
        }
        persist::sync_notify(&prefs);
        let lang = prefs
            .lang
            .as_deref()
            .and_then(Lang::parse)
            .unwrap_or(options.lang);
        let mode = match prefs.theme {
            app::settings::ThemeChoice::Dark => theme::Mode::Dark,
            app::settings::ThemeChoice::Light => theme::Mode::Light,
        };
        let worker = worker::Worker::spawn(
            || {
                #[cfg(windows)]
                {
                    let engine = secblitz::engine::Engine::open(
                        secblitz::platform::state_dir()?,
                        secblitz::permissions::with_permissions(secblitz::platform::backend()?),
                    )?;
                    Ok(Box::new(engine) as Box<dyn worker::Session>)
                }
                #[cfg(target_os = "linux")]
                {
                    Ok(Box::new(app::composite::Composite {
                        system: Box::new(crate::linux_bus::client::session()?),
                        person: Box::new(secblitz::linux::person::open_engine()?),
                    }) as Box<dyn worker::Session>)
                }
                #[cfg(not(any(windows, target_os = "linux")))]
                {
                    anyhow::bail!(crate::launcher::NOT_INSTALLED)
                }
            },
            || {
                #[cfg(target_os = "linux")]
                {
                    start_fresh_on_linux()
                }
                #[cfg(not(target_os = "linux"))]
                secblitz::engine::recover::start_fresh(
                    &secblitz::platform::state_dir()?,
                    secblitz::permissions::with_permissions(secblitz::platform::backend()?),
                )
                .map(drop)
            },
        );
        let broker = options
            .broker
            .as_deref()
            .and_then(|id| crate::broker::Client::connect(id).ok())
            .map(Arc::new);
        let helper = if broker.is_some() {
            Helper::Ready
        } else if crate::launcher::has_split_token() {
            Helper::Reopen
        } else {
            Helper::NotOnThisAccount
        };
        let state_dir = secblitz::platform::app_dir().ok();
        let user = crate::launcher::user_sid();
        let now = app::history::now();
        let cached = match (&state_dir, &user, app::last_check::boot_time(now)) {
            (Some(dir), Some(user), Some(boot)) => app::last_check::load(dir, user, now, boot),
            _ => None,
        };
        let reverted = secblitz::status::read()
            .map(|s| s.reverted)
            .unwrap_or_default();
        let cached =
            cached.filter(|(r, _)| app::last_check::missed_switch_backs(r, &reverted).is_empty());
        let checked_at = cached.as_ref().map(|(_, at)| *at);
        let report = cached.map(|(report, _)| Arc::new(report));
        let launch = app::welcome::launch(
            cfg!(test) || used_before,
            prefs.welcome_seen,
            has_history,
            report.is_some(),
        );
        let ctx = Ctx {
            lang,
            palette: Palette::of(mode),
            worker: worker.clone(),
            catalog: worker::Catalog::default(),
            engine_error: None,
            damage: None,
            check_error: None,
            checked_at,
            checking: launch.check.then(CheckProgress::default),
            finishing: false,
            report,
            busy: false,
            broker,
            helper,
            state_dir,
            prefs,
            x64_on_arm: secblitz::platform::x64_on_arm(),
            toast: None,
            info: None,
            copilot_installed: false,
        };
        let mut app = App {
            page: options.start.unwrap_or_default(),
            ctx,
            home: Default::default(),
            fixes: Default::default(),
            fix: Default::default(),
            debloat: Default::default(),
            web: Default::default(),
            tools: Default::default(),
            history: Default::default(),
            settings: Default::default(),
            app_access: Default::default(),
            privacy_shown: false,
            whats_new,
            toast_gen: 0,
            toast_leaving: false,
            entered: None,
            enter_t: 1.0,
            handoff: None,
            leave_t: 0.0,
            warmed: [false; 3],
            flight: [false; 3],
            warm_at: [None; 3],
            recheck: Recheck::default(),
            switch_backs_seen: reverted.into_iter().collect(),
            focused: true,
            page_first_tab: false,
            user,
            welcome: launch.welcome.then(welcome::State::default),
            may_check: has_history,
        };
        let opened = Task::run(worker.opened(), Message::Worker);
        let first_check = if app.ctx.checking.is_some() {
            Task::run(worker.run(worker::Job::Check), Message::Worker)
        } else {
            Task::none()
        };
        // Opening straight on a page (hidden `--self-test`) must load it too.
        let enter = app.enter_page(app.page);
        let web_state = web::on_enter(&mut app.web, &mut app.ctx);
        let pending =
            Task::perform(blocking(secblitz::debloat::offline::finish_pending), |_| ()).discard();
        // A first start that is closed during the welcome must show it again next time.
        let news = if news_unrecorded && !launch.welcome {
            Task::perform(persist::save_prefs(app.ctx.prefs.clone()), |_| {
                Message::Noop
            })
        } else {
            Task::none()
        };
        let title_bar = match_title_bar(app.ctx.palette).map(|()| Message::Noop);
        (
            app,
            Task::batch([
                opened,
                first_check,
                enter,
                web_state,
                pending,
                news,
                title_bar,
            ]),
        )
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        let was_busy = self.ctx.busy;
        let mode = self.ctx.palette.mode;
        let mut task = self.handle(message);
        if self.ctx.palette.mode != mode {
            task = Task::batch([
                task,
                match_title_bar(self.ctx.palette).map(|()| Message::Noop),
            ]);
        }
        let privacy = self.page == Page::Fixes
            && fixes::topic_on_show(&self.fixes) == Some(crate::app::topics::Topic::Privacy);
        if privacy && !self.privacy_shown {
            task = Task::batch([
                task,
                app_access::on_enter(&mut self.app_access, &mut self.ctx),
            ]);
        }
        self.privacy_shown = privacy;
        // A fix, undo, removal or repair may change what a check finds: the
        // next opening must check again (a fix or undo saves its own re-check).
        if self.ctx.busy && !was_busy {
            self.ctx.forget_check();
        }
        task
    }

    fn handle(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Navigate(page) => {
                if page == self.page {
                    return Task::none();
                }
                let finished = self.finish_handoff();
                self.page = page;
                self.ctx.info = None;
                self.page_first_tab = true;
                self.begin_entrance();
                Task::batch([
                    finished,
                    iced::advanced::widget::operate(widgets::focus::clear()),
                    self.enter_page(page),
                    iced::widget::operation::snap_to(
                        PAGE_SCROLL,
                        iced::widget::operation::RelativeOffset::START,
                    ),
                ])
            }
            Message::OpenCleanUp(family) => {
                let shown =
                    debloat::update(&mut self.debloat, debloat::Msg::Show(family), &mut self.ctx);
                Task::batch([shown, self.update(Message::Navigate(Page::Debloat))])
            }
            Message::PageFrame(now) => self.step_frame(now),
            Message::HandoffLeave(start) => {
                if let Some(h) = self.handoff.as_mut().filter(|h| h.start == start) {
                    h.leaving = Some(std::time::Instant::now());
                }
                Task::none()
            }
            Message::Tab(back) => {
                let step = match (back, std::mem::take(&mut self.page_first_tab)) {
                    (true, _) => widgets::focus::Move::Previous,
                    (false, true) => widgets::focus::Move::PageStart,
                    (false, false) => widgets::focus::Move::Next,
                };
                iced::advanced::widget::operate(widgets::focus::step(step))
            }
            Message::CheckNow => {
                if self.ctx.checking.is_some() || self.ctx.busy {
                    return Task::none();
                }
                self.may_check = true;
                self.ctx.info = None;
                self.ctx.checking = Some(CheckProgress::default());
                Task::run(self.ctx.worker.run(worker::Job::Check), Message::Worker)
            }
            Message::CheckIfAgreed if self.may_check => self.update(Message::CheckNow),
            Message::CheckIfAgreed => Task::none(),
            Message::Worker(event) => self.on_worker(event),
            Message::ReviewFixes(ids) => fixflow::open_fixes(&mut self.fix, ids, &mut self.ctx),
            Message::ReviewUndo => fixflow::open_undo(&mut self.fix, &mut self.ctx),
            Message::ReviewUndoSome(ids) => {
                fixflow::open_undo_some(&mut self.fix, ids, &mut self.ctx)
            }
            Message::PutBackChosen => Task::batch([
                self.update(Message::Navigate(Page::Fixes)),
                self.update(Message::Fixes(fixes::Msg::FocusUndo)),
            ]),
            Message::CloseRequested(id) => {
                // A fix, undo, removal or repair must not be cut off halfway.
                if self.ctx.busy {
                    Task::none()
                } else {
                    iced::window::close(id)
                }
            }
            Message::Info(mut sheet) => {
                if let Some(sheet) = sheet.as_mut() {
                    sheet.open_first();
                }
                self.ctx.info = sheet;
                Task::none()
            }
            Message::InfoPoint(key) => {
                if let Some(sheet) = self.ctx.info.as_mut() {
                    sheet.open.toggle(&key);
                }
                Task::none()
            }
            Message::Escape => {
                if self.welcome.is_some() {
                    return self.leave_welcome(false);
                }
                if self.ctx.info.take().is_some() {
                    return Task::none();
                }
                if std::mem::take(&mut self.whats_new) {
                    return Task::none();
                }
                if self.fix.is_open() {
                    return fixflow::escape(&mut self.fix, &mut self.ctx);
                }
                match self.page {
                    Page::Fixes => fixes::escape(&mut self.fixes),
                    Page::Web => web::escape(&mut self.web),
                    Page::Debloat => debloat::escape(&mut self.debloat),
                    Page::Tools => tools::escape(&mut self.tools),
                    Page::Settings => settings::escape(&mut self.settings),
                    _ => {}
                }
                Task::none()
            }
            Message::SearchEscape => {
                match self.page {
                    Page::Fixes if !self.fix.is_open() => fixes::escape(&mut self.fixes),
                    Page::Debloat => debloat::clear_search(&mut self.debloat),
                    _ => {}
                }
                Task::none()
            }
            Message::Find => {
                let id = match self.page {
                    Page::Fixes if fixes::shows_search(&self.ctx) => fixes::SEARCH_ID,
                    Page::Debloat if debloat::shows_search(&self.debloat) => debloat::SEARCH_ID,
                    _ => return Task::none(),
                };
                if self.fix.is_open() {
                    return Task::none();
                }
                iced::widget::operation::focus(id)
            }
            Message::Toast(text, tone) => {
                self.ctx.toast = Some((text, tone));
                self.toast_leaving = false;
                self.toast_gen = self.toast_gen.wrapping_add(1);
                let generation = self.toast_gen;
                Task::perform(
                    blocking(|| std::thread::sleep(std::time::Duration::from_secs(TOAST_SECONDS))),
                    move |_| Message::ToastExpire(generation),
                )
            }
            Message::Noop => Task::none(),
            Message::Welcome(m) => {
                let Some(state) = self.welcome.as_mut() else {
                    return Task::none();
                };
                match welcome::update(state, m) {
                    welcome::Outcome::Stay => Task::none(),
                    welcome::Outcome::Leave { check } => self.leave_welcome(check),
                }
            }
            Message::CloseWhatsNew => {
                self.whats_new = false;
                Task::none()
            }
            Message::PageOpened(page, ok) => {
                let text = if ok {
                    self.recheck.arm(std::time::Instant::now(), self.focused);
                    self.ctx.t("Opened in a new window.")
                } else {
                    crate::guide::failure_text(self.ctx.lang, page)
                };
                self.update(Message::Toast(
                    text,
                    if ok { Tone::Good } else { Tone::Warn },
                ))
            }
            Message::WindowFocus(focused) => {
                self.focused = focused;
                let idle = self.ctx.checking.is_none() && !self.ctx.busy && self.may_check;
                let recheck = self.recheck.focus(focused, std::time::Instant::now(), idle);
                if recheck || (focused && idle && self.switched_back_unseen()) {
                    self.update(Message::CheckNow)
                } else {
                    Task::none()
                }
            }
            Message::OpenRequested(page) => {
                let show = iced::window::latest().and_then(|id| {
                    Task::batch([
                        iced::window::minimize(id, false),
                        iced::window::gain_focus(id),
                    ])
                });
                if page.is_empty() {
                    show
                } else {
                    Task::batch([
                        show,
                        self.update(Message::Navigate(Page::open_target(&page))),
                    ])
                }
            }
            Message::DismissToast => self.begin_toast_exit(),
            Message::ToastGone => {
                if self.toast_leaving {
                    self.ctx.toast = None;
                    self.toast_leaving = false;
                }
                Task::none()
            }
            Message::ToastExpire(generation) => {
                if generation == self.toast_gen {
                    self.begin_toast_exit()
                } else {
                    Task::none()
                }
            }
            Message::Home(m) => home::update(&mut self.home, m, &mut self.ctx),
            Message::Fixes(m) => {
                let focus = matches!(m, fixes::Msg::FocusUndo);
                let task = fixes::update(&mut self.fixes, m, &mut self.ctx);
                if focus {
                    // The group is the last one on the page.
                    Task::batch([
                        task,
                        iced::widget::operation::snap_to(
                            PAGE_SCROLL,
                            iced::widget::operation::RelativeOffset::END,
                        ),
                    ])
                } else {
                    task
                }
            }
            Message::Fix(m) => fixflow::update(&mut self.fix, m, &mut self.ctx),
            Message::Debloat(m) => {
                if let debloat::Msg::Scanned(g, _) = &m {
                    if debloat::is_current_scan(&self.debloat, *g) {
                        self.flight[WARM_DEBLOAT] = false;
                    }
                }
                let task = debloat::update(&mut self.debloat, m, &mut self.ctx);
                self.ctx.copilot_installed =
                    debloat::is_installed(&self.debloat, debloat::COPILOT_APP);
                task
            }
            Message::Web(m) => {
                let focus = matches!(m, web::Msg::FocusPrivacy);
                let task = web::update(&mut self.web, m, &mut self.ctx);
                if focus {
                    // Privacy is the last group on the What to block tab.
                    Task::batch([
                        task,
                        iced::widget::operation::snap_to(
                            PAGE_SCROLL,
                            iced::widget::operation::RelativeOffset::END,
                        ),
                    ])
                } else {
                    task
                }
            }
            Message::Tools(m) => tools::update(&mut self.tools, m, &mut self.ctx),
            Message::History(m) => {
                if matches!(m, history::Msg::Loaded(..)) {
                    self.flight[WARM_HISTORY] = false;
                }
                history::update(&mut self.history, m, &mut self.ctx)
            }
            Message::Settings(m) => {
                if matches!(m, settings::Msg::Loaded { .. }) {
                    self.flight[WARM_SETTINGS] = false;
                }
                settings::update(&mut self.settings, m, &mut self.ctx)
            }
            Message::Recovery(m) => recovery::update(m, &mut self.ctx),
            Message::AppAccess(m) => app_access::update(&mut self.app_access, m, &mut self.ctx),
        }
    }

    fn on_worker(&mut self, event: worker::Event) -> Task<Message> {
        let hand_off = matches!(&event, worker::Event::Checked(Ok(_)))
            && self.ctx.full_check().is_some()
            && self.handoff.is_none()
            && matches!(self.page, Page::Home | Page::Fixes)
            && !widgets::anim::reduced();
        if hand_off {
            let start = std::time::Instant::now();
            self.ctx.finishing = true;
            self.handoff = Some(Handoff {
                start,
                leaving: None,
                event,
            });
            let wait = widgets::handoff::leave_at();
            return Task::perform(blocking(move || std::thread::sleep(wait)), move |_| {
                Message::HandoffLeave(start)
            });
        }
        self.process_worker(event)
    }

    /// Shows the held result now. Called when the hand-off has run its course
    /// or the person has moved on.
    fn finish_handoff(&mut self) -> Task<Message> {
        let Some(h) = self.handoff.take() else {
            return Task::none();
        };
        self.ctx.finishing = false;
        self.leave_t = 0.0;
        self.process_worker(h.event)
    }

    fn process_worker(&mut self, event: worker::Event) -> Task<Message> {
        use worker::Event as E;
        let mut extra = Task::none();
        match &event {
            E::Opened(Ok(catalog)) => self.ctx.catalog = catalog.clone(),
            E::Opened(Err(e)) => {
                self.ctx.engine_error = Some(self.ctx.t(crate::launcher::friendly_problem(e)));
            }
            E::Damaged(damage) => self.ctx.damage = Some(recovery::DamageInfo::new(*damage)),
            E::Recovered(Ok(catalog)) => {
                self.ctx.catalog = catalog.clone();
                self.ctx.damage = None;
                self.ctx.engine_error = None;
                self.ctx.busy = false;
                self.ctx.report = None;
                self.ctx.checked_at = None;
                self.ctx.check_error = None;
                self.ctx.checking = None;
                self.record_recovery();
                let done = self.ctx.t(recovery::DONE);
                extra = Task::batch([
                    self.update(Message::Toast(done, Tone::Good)),
                    self.preload_all(),
                    if self.may_check {
                        self.update(Message::CheckNow)
                    } else {
                        Task::none()
                    },
                ]);
            }
            E::Recovered(Err(_)) => {
                recovery::failed(&mut self.ctx);
                let text = self.ctx.t(recovery::FAILED);
                extra = self.update(Message::Toast(text, Tone::Warn));
            }
            E::Progress { phase, id, status } => {
                if matches!(phase, worker::Phase::Checking | worker::Phase::Verifying) {
                    let p = self.ctx.checking.get_or_insert_with(Default::default);
                    p.phase = Some(*phase);
                    p.items.push((id.clone(), status.clone()));
                }
            }
            E::Checked(outcome) => {
                self.ctx.checking = None;
                self.assessed(outcome, app::history::Kind::Check, 0);
            }
            E::Applied {
                attempted,
                result,
                verify,
            } => {
                self.ctx.checking = None;
                let n = match result {
                    Ok(r) => attempted
                        .iter()
                        .filter(|id| {
                            r.results.iter().any(|o| {
                                o.id == **id
                                    && (o.status == CheckStatus::Applied
                                        || o.status == CheckStatus::Unchanged)
                            })
                        })
                        .count(),
                    Err(_) => 0,
                };
                self.assessed(verify, app::history::Kind::Fix, n);
            }
            E::Undone {
                chosen,
                result,
                verify,
            } => {
                self.ctx.checking = None;
                let back = |o: &&secblitz::engine::Outcome| {
                    o.status == CheckStatus::Restored
                        || (!chosen.is_empty() && o.status == CheckStatus::Unchanged)
                };
                let n = match result {
                    Ok(r) => r.results.iter().filter(back).count(),
                    Err(_) => 0,
                };
                let kind = if chosen.is_empty() {
                    app::history::Kind::Undo
                } else {
                    app::history::Kind::UndoSome
                };
                self.assessed(verify, kind, n);
            }
            E::History(_) | E::Preflight { .. } => {}
        }
        let warm = if matches!(&event, E::Opened(Ok(_))) {
            self.preload_all()
        } else {
            Task::none()
        };
        Task::batch([
            fixflow::on_worker(&mut self.fix, &event, &mut self.ctx),
            history::on_worker(&mut self.history, &event, &mut self.ctx),
            warm,
            extra,
        ])
    }

    fn record_recovery(&mut self) {
        let Some(dir) = self.ctx.state_dir.clone() else {
            return;
        };
        let entry = self.entry(
            app::history::now(),
            app::history::Kind::Recovery,
            &Score::default(),
            0,
        );
        let _ = app::history::record(&dir, &entry);
        forget_check(Some(dir));
    }

    fn assessed(&mut self, outcome: &worker::Outcome, kind: app::history::Kind, n: usize) {
        let operation = kind != app::history::Kind::Check;
        let now = app::history::now();
        match outcome {
            Ok(report) => {
                self.ctx.report = Some(report.clone());
                self.ctx.check_error = None;
                self.ctx.checked_at = Some(now);
                let score = Score::of(report);
                let entry = (!operation || n > 0).then(|| self.entry(now, kind, &score, n));
                let cache = match &self.user {
                    Some(user) => Cache::Save(user.clone(), now, report.clone()),
                    None => Cache::Keep,
                };
                persist(
                    self.ctx.state_dir.clone(),
                    entry,
                    status_of(report, &score, now),
                    Some(persist::Changed {
                        changed: app::score::changed_ids(report),
                        armed: app::score::armed_ids(report),
                    }),
                    cache,
                );
            }
            Err(e) => {
                self.ctx.check_error = Some(self.ctx.t(crate::launcher::friendly_check_problem(e)));
                let entry = if operation && n > 0 {
                    self.ctx
                        .report
                        .as_deref()
                        .map(|report| self.entry(now, kind, &Score::of(report), n))
                } else {
                    None
                };
                // A failed check must not leave the tray showing "protected".
                persist(
                    self.ctx.state_dir.clone(),
                    entry,
                    secblitz::status::summarize(&[], false, now),
                    None,
                    Cache::Forget,
                );
            }
        }
    }

    fn entry(
        &self,
        t: u64,
        kind: app::history::Kind,
        score: &Score,
        n: usize,
    ) -> app::history::Entry {
        app::history::Entry {
            t,
            kind,
            protected: score.protected,
            total: score.total,
            n,
        }
    }

    fn on_page(&self, page: Page, sub: Subscription<Message>) -> Subscription<Message> {
        if self.page == page {
            sub
        } else {
            Subscription::none()
        }
    }

    fn enter_page(&mut self, page: Page) -> Task<Message> {
        match page {
            Page::History => self.revisit(WARM_HISTORY),
            Page::Debloat => self.revisit(WARM_DEBLOAT),
            Page::Settings => self.revisit(WARM_SETTINGS),
            Page::Web => web::on_enter(&mut self.web, &mut self.ctx),
            Page::Tools => tools::on_enter(&mut self.tools, &mut self.ctx),
            _ => Task::none(),
        }
    }

    /// Entering a page again: reload only when the last load is stale.
    fn revisit(&mut self, which: usize) -> Task<Message> {
        let fresh = self.warm_at[which].is_some_and(|t| t.elapsed() < WARM_TTL);
        if fresh {
            Task::none()
        } else {
            self.warm(which)
        }
    }

    fn warm(&mut self, which: usize) -> Task<Message> {
        if self.flight[which] {
            return Task::none();
        }
        self.flight[which] = true;
        self.warm_at[which] = Some(std::time::Instant::now());
        let first = !std::mem::replace(&mut self.warmed[which], true);
        let task = match (which, first) {
            (WARM_HISTORY, true) => history::on_enter(&mut self.history, &mut self.ctx),
            (WARM_HISTORY, false) => history::preload(&mut self.history, &mut self.ctx),
            (WARM_DEBLOAT, true) => debloat::on_enter(&mut self.debloat, &mut self.ctx),
            (WARM_DEBLOAT, false) => debloat::preload(&mut self.debloat, &mut self.ctx),
            (_, true) => settings::on_enter(&mut self.settings, &mut self.ctx),
            (_, false) => settings::preload(&mut self.settings, &mut self.ctx),
        };
        // A page that declined to load (sheet open) must not stay "in flight".
        if self.page_declined(which) {
            self.flight[which] = false;
        }
        task
    }

    fn page_declined(&self, which: usize) -> bool {
        which == WARM_DEBLOAT && self.debloat_busy()
    }

    fn debloat_busy(&self) -> bool {
        debloat::is_busy(&self.debloat)
    }

    fn preload_all(&mut self) -> Task<Message> {
        Task::batch([
            self.warm(WARM_HISTORY),
            self.warm(WARM_DEBLOAT),
            self.warm(WARM_SETTINGS),
        ])
    }

    fn begin_entrance(&mut self) {
        if widgets::anim::reduced() {
            self.finish_entrance();
            return;
        }
        self.entered = Some(std::time::Instant::now());
        self.enter_t = 0.0;
    }

    fn step_entrance(&mut self, now: std::time::Instant) {
        let Some(start) = self.entered else {
            return;
        };
        let t = widgets::appear::enter_progress(start, now);
        if t >= 1.0 {
            self.finish_entrance();
        } else {
            self.enter_t = t;
        }
    }

    fn finish_entrance(&mut self) {
        self.entered = None;
        self.enter_t = 1.0;
    }

    fn step_frame(&mut self, now: std::time::Instant) -> Task<Message> {
        let Some(at) = self.handoff.as_ref().and_then(|h| h.leaving) else {
            self.step_entrance(now);
            return Task::none();
        };
        let since = widgets::handoff::leave_at() + now.saturating_duration_since(at);
        if let widgets::handoff::Stage::Leaving(t) = widgets::handoff::stage(since) {
            self.leave_t = t;
            return Task::none();
        }
        let task = self.finish_handoff();
        self.begin_entrance();
        task
    }

    fn begin_toast_exit(&mut self) -> Task<Message> {
        if self.ctx.toast.is_none() || self.toast_leaving {
            return Task::none();
        }
        if widgets::anim::reduced() {
            self.ctx.toast = None;
            return Task::none();
        }
        self.toast_leaving = true;
        let wait = widgets::anim::FAST + std::time::Duration::from_millis(40);
        Task::perform(blocking(move || std::thread::sleep(wait)), |_| {
            Message::ToastGone
        })
    }

    /// Leaves the welcome by any route and remembers that it was shown.
    fn leave_welcome(&mut self, check: bool) -> Task<Message> {
        self.welcome = None;
        self.ctx.prefs.welcome_seen = true;
        let saved = Task::perform(persist::save_prefs(self.ctx.prefs.clone()), |_| {
            Message::Noop
        });
        if check {
            Task::batch([saved, self.update(Message::CheckNow)])
        } else {
            saved
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let p = Palette::of(self.ctx.palette.mode);
        if let Some(state) = &self.welcome {
            return welcome::view(state, &self.ctx);
        }
        let content: Element<'_, Message> = match self.page {
            Page::Home => home::view(&self.home, &self.ctx),
            Page::Fixes => fixes::view(&self.fixes, &self.ctx, &self.app_access),
            Page::Debloat => debloat::view(&self.debloat, &self.ctx),
            Page::Web => web::view(&self.web, &self.ctx),
            Page::Tools => tools::view(&self.tools, &self.ctx),
            Page::History => history::view(&self.history, &self.ctx),
            Page::Settings => settings::view(&self.settings, &self.ctx),
        };
        let fills = match self.page {
            Page::Home => home::fills_window(&self.ctx),
            Page::Fixes => fixes::fills_window(&self.ctx),
            _ => false,
        };
        let look = if self.handoff.as_ref().is_some_and(|h| h.leaving.is_some()) {
            widgets::appear::leave_look(self.leave_t)
        } else {
            widgets::appear::page_look(self.enter_t)
        };
        let column_content = widgets::appear::enter(
            container(content)
                .max_width(PAGE_MAX_WIDTH)
                .width(Length::Fill)
                .height(if fills { Length::Fill } else { Length::Shrink }),
            look,
            p.bg,
        );
        let footer = match self.page {
            Page::Debloat => debloat::footer(&self.debloat, &self.ctx),
            _ => None,
        };
        let footer_bar: Element<'_, Message> = match footer {
            Some(bar) => column![
                container(iced::widget::space::horizontal())
                    .height(theme::HAIRLINE)
                    .width(Length::Fill)
                    .style(move |_| container::Style {
                        background: Some(Background::Color(p.border)),
                        ..container::Style::default()
                    }),
                container(container(bar).max_width(PAGE_MAX_WIDTH).width(Length::Fill))
                    .center_x(Length::Fill)
                    .padding([theme::S4, theme::S10])
                    .style(move |_| container::Style {
                        background: Some(Background::Color(p.surface)),
                        ..container::Style::default()
                    }),
            ]
            .into(),
            None => iced::widget::space().into(),
        };
        let page = container(column_content)
            .center_x(Length::Fill)
            .padding([theme::S8, theme::S10])
            .width(Length::Fill);
        let scroll: Element<'_, Message> = if fills {
            page.height(Length::Fill).into()
        } else {
            container(
                scrollable(page)
                    .id(PAGE_SCROLL)
                    .direction(widgets::controls::scrollbar())
                    .style(widgets::controls::scroll_style(p)),
            )
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
        };
        let main = container(widgets::focus::page(column![scroll, footer_bar]))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(p.bg)),
                ..container::Style::default()
            });
        let body: Element<'_, Message> = row![self.sidebar(), main].into();
        let none = || -> Element<'_, Message> { iced::widget::space().into() };
        let modal = match self.page {
            Page::Debloat => debloat::modal(&self.debloat, &self.ctx),
            Page::Tools => tools::modal(&self.tools, &self.ctx),
            Page::Settings => settings::modal(&self.settings, &self.ctx),
            _ => None,
        };
        let modal_layer = match modal {
            Some(content) => widgets::sheet_layer(p, content),
            None => none(),
        };
        let fix_layer = match fixflow::overlay_content(&self.fix, &self.ctx) {
            Some(content) => widgets::sheet_layer(p, content),
            None => none(),
        };
        let news_layer = if self.whats_new {
            widgets::sheet_layer(p, self.whats_new_panel(p))
        } else {
            none()
        };
        let info_layer = match &self.ctx.info {
            Some(sheet) => widgets::dismissable_sheet_layer(
                p,
                widgets::info::dialog(&self.ctx, sheet),
                Message::Info(None),
            ),
            None => none(),
        };
        let toast_layer = match &self.ctx.toast {
            Some((message, tone)) => container(widgets::toast(
                p,
                message.clone(),
                *tone,
                self.toast_leaving,
            ))
            .center_x(Length::Fill)
            .align_bottom(Length::Fill)
            .padding(theme::S6)
            .into(),
            None => none(),
        };
        stack![
            body,
            modal_layer,
            fix_layer,
            news_layer,
            info_layer,
            toast_layer
        ]
        .into()
    }

    fn whats_new_panel(&self, p: Palette) -> Element<'_, Message> {
        let mut notes = column![].spacing(theme::S2);
        for note in app::whats_new::NOTES {
            notes = notes.push(
                row![
                    widgets::icon(Icon::Check, 16.0, p.tone(Tone::Good)),
                    widgets::body(p, self.ctx.t(note))
                ]
                .spacing(theme::S2)
                .align_y(Alignment::Center),
            );
        }
        column![
            row![
                widgets::icon(Icon::Sparkles, theme::ICON_ROW, p.text_muted),
                widgets::h2(p, self.ctx.t("What's new in Secblitz"))
            ]
            .spacing(theme::S3)
            .align_y(Alignment::Center),
            widgets::muted(
                p,
                format!("{} {}", self.ctx.t("Version"), app::whats_new::VERSION)
            ),
            notes,
            row![
                iced::widget::space::horizontal(),
                widgets::action(
                    p,
                    widgets::ButtonKind::Primary,
                    self.ctx.t("Got it"),
                    None,
                    Some(Message::CloseWhatsNew),
                )
            ],
        ]
        .spacing(theme::S4)
        .width(Length::Fill)
        .into()
    }

    fn verdict_tone(&self) -> Tone {
        match self.ctx.report.as_deref().map(app::score::overall) {
            Some(app::score::Verdict::Protected) => Tone::Good,
            Some(app::score::Verdict::Attention) => Tone::Warn,
            _ => Tone::Neutral,
        }
    }

    fn sidebar(&self) -> Element<'_, Message> {
        let p = Palette::of(self.ctx.palette.mode);
        let brand = row![
            widgets::brand_mark(24.0, p.text),
            text("Secblitz")
                .size(theme::H2)
                .font(theme::SEMIBOLD)
                .color(p.text)
        ]
        .spacing(theme::S3)
        .align_y(Alignment::Center)
        .padding([0.0, theme::S3]);
        let mut nav = column![].spacing(NAV_GAP);
        for page in Page::ALL {
            let active = self.page == page;
            let fg = if active { p.text } else { p.text_muted };
            let glyph = if active {
                widgets::icon_filled(page.icon(), 18.0, fg)
            } else {
                widgets::icon(page.icon(), 18.0, fg)
            };
            let mut item = row![
                glyph,
                text(self.ctx.t(page.label()))
                    .size(theme::BODY)
                    .line_height(iced::widget::text::LineHeight::Absolute(iced::Pixels(
                        theme::LINE_BODY
                    )))
                    .font(if active {
                        theme::SEMIBOLD
                    } else {
                        theme::MEDIUM
                    })
                    .color(fg),
                iced::widget::space::horizontal(),
            ]
            .spacing(theme::S3)
            .align_y(Alignment::Center);
            if page == Page::Home && self.ctx.checking.is_none() && self.ctx.report.is_some() {
                let dot = p.tone(self.verdict_tone());
                item = item.push(
                    container(iced::widget::space::horizontal())
                        .width(theme::DOT)
                        .height(theme::DOT)
                        .style(move |_| container::Style {
                            background: Some(Background::Color(dot)),
                            border: Border {
                                radius: theme::R_PILL.into(),
                                ..Border::default()
                            },
                            ..container::Style::default()
                        }),
                );
            }
            nav = nav.push(widgets::arrow(
                widgets::press::button(container(item).center_y(Length::Fill))
                    .width(Length::Fill)
                    .height(theme::CONTROL)
                    .padding([0.0, theme::S3])
                    .scale(false)
                    .on_press(Message::Navigate(page))
                    .style(move |_, status| button::Style {
                        background: match status {
                            button::Status::Pressed => Some(Background::Color(p.pressed)),
                            button::Status::Hovered if !active => {
                                Some(Background::Color(p.hover_strong))
                            }
                            _ => None,
                        },
                        text_color: fg,
                        border: Border {
                            radius: theme::R.into(),
                            ..Border::default()
                        },
                        shadow: iced::Shadow::default(),
                        snap: true,
                    }),
            ));
        }
        let index = Page::ALL.iter().position(|q| *q == self.page).unwrap_or(0);
        let nav = stack![
            widgets::slide_marker(p, index, Page::ALL.len(), theme::CONTROL, NAV_GAP),
            nav
        ]
        .width(Length::Fill);
        let version = container(widgets::small(
            p,
            format!("{} {}", self.ctx.t("Version"), env!("CARGO_PKG_VERSION")),
        ))
        .padding([0.0, theme::S3]);
        container(column![brand, nav, iced::widget::space::vertical(), version].spacing(theme::S6))
            .padding([theme::S6, theme::S3])
            .width(232)
            .height(Length::Fill)
            .style(move |_| container::Style {
                background: Some(Background::Color(p.sidebar)),
                border: Border {
                    width: 0.0,
                    ..Border::default()
                },
                ..container::Style::default()
            })
            .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        let escape = keyboard::listen().filter_map(|event| match event {
            keyboard::Event::KeyPressed {
                key: keyboard::Key::Named(keyboard::key::Named::Escape),
                ..
            } => Some(Message::Escape),
            keyboard::Event::KeyPressed {
                key: keyboard::Key::Named(keyboard::key::Named::Tab),
                modifiers,
                ..
            } => Some(Message::Tab(modifiers.shift())),
            keyboard::Event::KeyPressed {
                key,
                modifiers,
                physical_key,
                ..
            } if modifiers.command() && key.to_latin(physical_key) == Some('f') => {
                Some(Message::Find)
            }
            _ => None,
        });
        // A search box that has the keyboard keeps Escape for itself, so the
        // plain listener above never sees it.
        let search_escape = iced::event::listen_with(|event, status, _| match (event, status) {
            (
                iced::Event::Keyboard(keyboard::Event::KeyPressed {
                    key: keyboard::Key::Named(keyboard::key::Named::Escape),
                    ..
                }),
                iced::event::Status::Captured,
            ) => Some(Message::SearchEscape),
            _ => None,
        });
        let entrance = if self.entered.is_some()
            || self.handoff.as_ref().is_some_and(|h| h.leaving.is_some())
        {
            iced::window::frames().map(Message::PageFrame)
        } else {
            Subscription::none()
        };
        let focus = iced::event::listen_with(|event, _, _| match event {
            iced::Event::Window(iced::window::Event::Focused) => Some(Message::WindowFocus(true)),
            iced::Event::Window(iced::window::Event::Unfocused) => {
                Some(Message::WindowFocus(false))
            }
            _ => None,
        });
        let welcome = if self.welcome.is_some() {
            welcome::subscription()
        } else {
            Subscription::none()
        };
        Subscription::batch([
            escape,
            welcome,
            search_escape,
            focus,
            iced::window::close_requests().map(Message::CloseRequested),
            open_requests(),
            entrance,
            // Frame clocks run only for the page on screen: a job started on
            // Tools must not keep the whole window redrawing from another page.
            // Each page catches up on its next frame when it is shown again.
            // The score counts up once the fix result is closed, where it can be seen.
            if self.fix.is_open() {
                Subscription::none()
            } else {
                self.on_page(Page::Home, home::subscription(&self.home, &self.ctx))
            },
            self.on_page(Page::Fixes, fixes::subscription(&self.ctx)),
            fixflow::subscription(&self.fix),
            self.on_page(Page::Debloat, debloat::subscription(&self.debloat)),
            self.on_page(Page::Web, web::subscription()),
            self.on_page(Page::Tools, tools::subscription(&self.tools, &self.ctx)),
            self.on_page(Page::Settings, settings::subscription(&self.settings)),
        ])
    }
}

/// The person's own history is tried first: it needs no password. The system's history is only reset when the
/// person's was not the damaged one.
#[cfg(target_os = "linux")]
fn start_fresh_on_linux() -> anyhow::Result<()> {
    match secblitz::linux::person::start_fresh() {
        Err(e)
            if e.downcast_ref::<secblitz::engine::recover::NotDamaged>()
                .is_some() =>
        {
            crate::linux_bus::client::start_fresh()
        }
        other => other,
    }
}

/// Pages asked for by a second start, read on their own thread so the window
/// only wakes when there is one.
fn open_requests() -> Subscription<Message> {
    Subscription::run(|| {
        let (tx, rx) = iced::futures::channel::mpsc::unbounded();
        std::thread::spawn(move || {
            let mut seen = app::history::now();
            while !tx.is_closed() {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if let Some((page, at)) = app::open_request::read(app::history::now(), seen) {
                    seen = at;
                    if tx.unbounded_send(page).is_err() {
                        break;
                    }
                }
            }
        });
        rx
    })
    .map(Message::OpenRequested)
}

const NAV_GAP: f32 = theme::S1;
const PAGE_SCROLL: &str = "page-scroll";
const WARM_TTL: std::time::Duration = std::time::Duration::from_secs(60);

const WARM_HISTORY: usize = 0;
const WARM_DEBLOAT: usize = 1;
const WARM_SETTINGS: usize = 2;

const PAGE_MAX_WIDTH: f32 = 960.0;
const TOAST_SECONDS: u64 = 4;

pub fn status_of(report: &Report, score: &Score, now: u64) -> secblitz::status::Status {
    let attention: Vec<String> = app::score::to_check_ids(report)
        .into_iter()
        .take(64)
        .collect();
    secblitz::status::Status {
        schema: secblitz::status::SCHEMA,
        t: now,
        protected: score.protected as u32,
        total: score.total as u32,
        state: match app::score::overall(report) {
            app::score::Verdict::Protected => secblitz::status::State::Ok,
            app::score::Verdict::Attention => secblitz::status::State::Attention,
            app::score::Verdict::Unknown => secblitz::status::State::Unknown,
        },
        reverted: Vec::new(),
        attention,
    }
}

const USUAL_SIZE: iced::Size = iced::Size::new(1100.0, 720.0);
/// The title bar and borders, plus a little room, around the drawn page.
const FRAME: iced::Size = iced::Size::new(16.0, 48.0);

/// The usual size, made smaller when the screen leaves less room, as on a laptop
/// set to 150%, so the bottom of the window is never under the taskbar.
fn first_size(free: Option<iced::Rectangle>) -> iced::Size {
    let Some(free) = free else {
        return USUAL_SIZE;
    };
    iced::Size::new(
        USUAL_SIZE
            .width
            .min(free.width - FRAME.width)
            .max(theme::WINDOW_MIN_WIDTH),
        USUAL_SIZE
            .height
            .min(free.height - FRAME.height)
            .max(theme::WINDOW_MIN_HEIGHT),
    )
}

/// Centred in the free part of the screen. Windows centres a new window on the whole
/// screen, which puts the bottom of a tall window under the taskbar.
fn first_position(free: Option<iced::Rectangle>, size: iced::Size) -> Option<iced::Point> {
    free.map(|free| {
        iced::Point::new(
            free.x + ((free.width - size.width - FRAME.width) / 2.0).max(0.0),
            free.y + ((free.height - size.height - FRAME.height) / 2.0).max(0.0),
        )
    })
}

/// The part of the main screen that taskbars leave free, at the screen's scale.
#[cfg(windows)]
fn free_area() -> Option<iced::Rectangle> {
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::Graphics::Gdi::{
        GetMonitorInfoW, MonitorFromPoint, MONITORINFO, MONITOR_DEFAULTTOPRIMARY,
    };
    use windows_sys::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
    // SAFETY: `info` is a MONITORINFO with its size set, and the DPI outputs are locals.
    unsafe {
        let monitor = MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY);
        if monitor.is_null() {
            return None;
        }
        let mut info: MONITORINFO = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        let (mut dpi, mut dpi_y) = (0u32, 0u32);
        if GetMonitorInfoW(monitor, &mut info) == 0
            || GetDpiForMonitor(monitor, MDT_EFFECTIVE_DPI, &mut dpi, &mut dpi_y) != 0
            || dpi == 0
        {
            return None;
        }
        let scale = dpi as f32 / 96.0;
        let work = info.rcWork;
        Some(iced::Rectangle::new(
            iced::Point::new(work.left as f32 / scale, work.top as f32 / scale),
            iced::Size::new(
                (work.right - work.left) as f32 / scale,
                (work.bottom - work.top) as f32 / scale,
            ),
        ))
    }
}

#[cfg(not(windows))]
fn free_area() -> Option<iced::Rectangle> {
    None
}

pub fn run(options: Options) -> anyhow::Result<()> {
    let renderer = render::select();
    let free = free_area();
    let size = first_size(free);
    let mut application =
        iced::application(move || App::new(options.clone()), App::update, App::view)
            .title(|app: &App| app.ctx.t("Secblitz"))
            .theme(|app: &App| app.ctx.palette.theme())
            .subscription(App::subscription)
            .window_size(size)
            .default_font(theme::REGULAR)
            .antialiasing(render::use_msaa(renderer));
    for font in theme::FONT_FILES {
        application = application.font(font);
    }
    application
        .window(iced::window::Settings {
            size,
            position: first_position(free, size).map_or(
                iced::window::Position::Centered,
                iced::window::Position::Specific,
            ),
            min_size: Some(iced::Size::new(
                theme::WINDOW_MIN_WIDTH,
                theme::WINDOW_MIN_HEIGHT,
            )),
            exit_on_close_request: false,
            icon: window_icon(),
            #[cfg(target_os = "linux")]
            platform_specific: iced::window::settings::PlatformSpecific {
                application_id: "org.secblitz.Secblitz".into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .run()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    wait_persisted();
    Ok(())
}
#[cfg(test)]
mod size_tests {
    use super::*;

    fn area(x: f32, y: f32, width: f32, height: f32) -> Option<iced::Rectangle> {
        Some(iced::Rectangle::new(
            iced::Point::new(x, y),
            iced::Size::new(width, height),
        ))
    }

    #[test]
    fn the_window_fits_the_free_part_of_the_screen() {
        assert_eq!(first_size(None), USUAL_SIZE);
        assert_eq!(first_size(area(0.0, 0.0, 2560.0, 1400.0)), USUAL_SIZE);
        let laptop = area(0.0, 0.0, 1280.0, 672.0);
        assert_eq!(first_size(laptop), iced::Size::new(1100.0, 624.0));
        assert_eq!(
            first_size(area(0.0, 0.0, 800.0, 500.0)),
            iced::Size::new(theme::WINDOW_MIN_WIDTH, theme::WINDOW_MIN_HEIGHT)
        );
    }

    #[test]
    fn the_window_opens_in_the_middle_of_the_free_part() {
        assert_eq!(first_position(None, USUAL_SIZE), None);
        let laptop = area(0.0, 0.0, 1280.0, 672.0);
        assert_eq!(
            first_position(laptop, first_size(laptop)),
            Some(iced::Point::new(82.0, 0.0))
        );
        let taskbar_on_top = area(0.0, 40.0, 1920.0, 1000.0);
        assert_eq!(
            first_position(taskbar_on_top, USUAL_SIZE),
            Some(iced::Point::new(402.0, 156.0))
        );
    }
}

#[cfg(test)]
mod recheck_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn returning_to_the_window_rechecks_once() {
        let t0 = Instant::now();
        let mut r = Recheck::default();
        assert!(!r.focus(true, t0, true), "nothing opened yet");
        r.arm(t0, true);
        assert!(
            !r.focus(true, t0, true),
            "focus before leaving does nothing"
        );
        assert!(!r.focus(false, t0, true));
        assert!(r.focus(true, t0 + Duration::from_secs(60), true));
        assert!(
            !r.focus(false, t0 + Duration::from_secs(70), true)
                && !r.focus(true, t0 + Duration::from_secs(80), true),
            "at most once per open"
        );
    }

    #[test]
    fn unfocused_before_armed_still_counts_as_left() {
        let t0 = Instant::now();
        let mut r = Recheck::default();
        r.arm(t0, false);
        assert!(r.focus(true, t0 + Duration::from_secs(20), true));
    }

    #[test]
    fn busy_waits_and_late_returns_are_ignored() {
        let t0 = Instant::now();
        let mut r = Recheck::default();
        r.arm(t0, true);
        assert!(!r.focus(false, t0, true));
        assert!(!r.focus(true, t0 + Duration::from_secs(5), false), "busy");
        assert!(
            r.focus(true, t0 + Duration::from_secs(9), true),
            "still armed"
        );
        r.arm(t0, true);
        assert!(!r.focus(false, t0, true));
        assert!(!r.focus(true, t0 + RECHECK_WINDOW + Duration::from_secs(1), true));
        assert!(
            !r.focus(true, t0 + Duration::from_secs(5), true),
            "disarmed"
        );
    }
}
