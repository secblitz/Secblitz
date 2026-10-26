//! The warning over a browser when Web protection stops a dangerous or scam site.
//!
//! Started by the tray as `secblitz warn --kind K --site S --window H`. It never takes the
//! keyboard from the browser, follows the browser window, and goes away by itself when the
//! person leaves the page.
use super::icons::Icon;
use super::theme::{self, Mode, Palette, Tone};
use super::widgets::{self, anim, press, ButtonKind};
use crate::i18n::Lang;
use crate::launcher::AllowOnce;
use crate::tray::warn_logic::{self, Browser, Rect, WarnArgs};
use iced::widget::text::{LineHeight, Wrapping};
use iced::widget::{column, container, row, space, svg, text};
use iced::{keyboard, Alignment, Element, Length, Pixels, Subscription, Task};
use secblitz::filter::matcher::Kind;
use std::time::{Duration, Instant};

#[cfg(windows)]
use crate::tray::browser as sys;
#[cfg(not(windows))]
use stub as sys;

const FOLLOW_EVERY: Duration = Duration::from_millis(150);
const ADDRESS_EVERY: Duration = Duration::from_secs(2);
/// The spinner turns while the Windows permission prompt is up, often for a while, so it runs at
/// a gentle rate instead of every screen refresh.
const SPIN_EVERY: Duration = Duration::from_millis(50);
const ADDRESS_WAIT: Duration = Duration::from_millis(1500);
const SITE_SHOWN: usize = 36;
/// Not the app's own window title, which the launcher uses to find a running Secblitz.
const PANEL_TITLE: &str = "Secblitz warning";

#[derive(Debug, Clone)]
enum Message {
    Follow(Instant),
    Frame,
    Opened(Option<usize>),
    GoBack,
    Allow,
    Allowed(AllowOnce),
    Address(Option<String>),
    Sent(bool),
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Ready,
    Leaving,
    Waiting,
    Declined,
    Failed,
    NoBrowser,
}

struct Panel {
    args: WarnArgs,
    lang: Lang,
    palette: Palette,
    browser: Browser,
    phase: Phase,
    waiting_since: Instant,
    panel: Option<usize>,
    shown: bool,
    escape_was_down: bool,
    address_check: Option<Instant>,
    address_read: Option<Instant>,
}

/// Runs the panel and returns the exit code. Anything the tray could not have sent exits quietly.
pub fn run(args: &[std::ffi::OsString], lang: Lang) -> i32 {
    let value = |flag| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|at| args.get(at + 1))
            .and_then(|v| v.to_str())
            .unwrap_or("")
    };
    let Some(args) = warn_logic::parse_args(value("--kind"), value("--site"), value("--window"))
    else {
        return 0;
    };
    let Some(browser) = sys::browser_of(args.window) else {
        return 0;
    };
    if let Err(error) = show(args, browser, lang) {
        eprintln!("{error:#}");
        return 1;
    }
    0
}

fn show(args: WarnArgs, browser: Browser, lang: Lang) -> anyhow::Result<()> {
    // A small panel needs no graphics card probe.
    std::env::set_var("ICED_BACKEND", "tiny-skia");
    let size = iced::Size::new(warn_logic::PANEL_WIDTH, warn_logic::PANEL_HEIGHT);
    let mut application = iced::application(
        move || Panel::new(args.clone(), browser, lang),
        Panel::update,
        Panel::view,
    )
    .title(|_: &Panel| PANEL_TITLE.to_owned())
    .theme(|panel: &Panel| panel.palette.theme())
    .subscription(Panel::subscription)
    .window_size(size)
    .default_font(theme::REGULAR);
    for font in theme::FONT_FILES {
        application = application.font(font);
    }
    application
        .window(window_settings(size))
        .run()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

fn window_settings(size: iced::Size) -> iced::window::Settings {
    iced::window::Settings {
        size,
        visible: false,
        resizable: false,
        minimizable: false,
        decorations: false,
        level: iced::window::Level::AlwaysOnTop,
        #[cfg(windows)]
        platform_specific: iced::window::settings::PlatformSpecific {
            skip_taskbar: true,
            undecorated_shadow: true,
            corner_preference: iced::window::settings::platform::CornerPreference::Round,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn ticks() -> impl iced::futures::Stream<Item = Message> {
    super::blocking_stream(|emit| loop {
        std::thread::sleep(FOLLOW_EVERY);
        emit(Message::Follow(Instant::now()));
    })
}

fn spin() -> impl iced::futures::Stream<Item = Message> {
    super::blocking_stream(|emit| loop {
        std::thread::sleep(SPIN_EVERY);
        emit(Message::Frame);
    })
}

/// The address bar, unlike a title, cannot be set by the page.
fn tab_shows(browser: Browser, window: usize, site: &str) -> bool {
    sys::address(window, browser, ADDRESS_WAIT)
        .is_some_and(|address| warn_logic::address_shows(&address, site))
}

fn glyph<'a>(bytes: &'static [u8], size: f32, color: iced::Color) -> Element<'a, Message> {
    svg(svg::Handle::from_memory(bytes))
        .width(size)
        .height(size)
        .style(move |_, _| svg::Style { color: Some(color) })
        .into()
}

fn heading_key(kind: Kind) -> &'static str {
    match kind {
        Kind::Dangerous => "This site looks dangerous",
        _ => "This site looks like a scam",
    }
}

fn sentence_key(kind: Kind) -> &'static str {
    match kind {
        Kind::Dangerous => "Secblitz stopped {site} before it opened. Sites like this try to steal passwords, money or control of your computer.",
        _ => "Secblitz stopped {site} before it opened. Sites like this try to trick you into paying or giving away your details.",
    }
}

/// Site names can be long; the panel has room for a line or two.
fn shown_site(site: &str) -> String {
    if site.chars().count() <= SITE_SHOWN {
        return site.to_owned();
    }
    let cut: String = site.chars().take(SITE_SHOWN - 3).collect();
    format!("{cut}...")
}

fn system_mode() -> Mode {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Registry::{
            RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD,
        };
        let key: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize\0"
            .encode_utf16()
            .collect();
        let value: Vec<u16> = "AppsUseLightTheme\0".encode_utf16().collect();
        let mut data = 1u32;
        let mut len = 4u32;
        // SAFETY: `data` is a u32 and `len` says so; both names end in a null.
        let rc = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                key.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&raw mut data).cast(),
                &mut len,
            )
        };
        if rc == 0 && data == 0 {
            return Mode::Dark;
        }
    }
    Mode::Light
}

impl Panel {
    fn new(args: WarnArgs, browser: Browser, lang: Lang) -> (Self, Task<Message>) {
        let panel = Panel {
            args,
            lang,
            palette: Palette::of(system_mode()),
            browser,
            phase: Phase::Ready,
            waiting_since: Instant::now(),
            panel: None,
            shown: false,
            escape_was_down: sys::escape_down(),
            address_check: None,
            address_read: None,
        };
        let opened = iced::window::oldest().and_then(|id| {
            iced::window::run(id, |window| native::handle_of(window)).map(Message::Opened)
        });
        (panel, opened)
    }

    fn subscription(&self) -> Subscription<Message> {
        let follow = Subscription::run(ticks);
        let escape = keyboard::listen().filter_map(|event| match event {
            keyboard::Event::KeyPressed {
                key: keyboard::Key::Named(keyboard::key::Named::Escape),
                ..
            } => Some(Message::Close),
            _ => None,
        });
        let frames = if self.phase == Phase::Waiting {
            Subscription::run(spin)
        } else {
            Subscription::none()
        };
        Subscription::batch([follow, escape, frames])
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Opened(handle) => {
                let Some(handle) = handle else {
                    return iced::exit();
                };
                self.panel = Some(handle);
                native::prepare(handle);
                self.place(true);
                Task::none()
            }
            Message::Follow(now) => self.follow(now),
            Message::Frame => Task::none(),
            Message::GoBack if self.phase != Phase::Leaving && self.phase != Phase::Waiting => {
                self.phase = Phase::Leaving;
                let window = self.args.window;
                Task::perform(super::blocking(move || sys::go_back(window)), Message::Sent)
            }
            Message::Allow if self.phase != Phase::Leaving && self.phase != Phase::Waiting => {
                self.phase = Phase::Waiting;
                self.waiting_since = Instant::now();
                let (site, lang) = (self.args.site.clone(), self.lang);
                Task::perform(
                    super::blocking(move || crate::launcher::allow_site_once(&site, lang)),
                    Message::Allowed,
                )
            }
            Message::Allowed(AllowOnce::Done) => {
                self.phase = Phase::Leaving;
                let (window, browser) = (self.args.window, self.browser);
                let site = self.args.site.clone();
                // The prompt can stay up for a while; a tab that moved on is not reloaded.
                Task::perform(
                    super::blocking(move || {
                        !tab_shows(browser, window, &site) || sys::reload(window)
                    }),
                    Message::Sent,
                )
            }
            Message::Allowed(AllowOnce::Declined) => {
                self.phase = Phase::Declined;
                Task::none()
            }
            Message::Allowed(AllowOnce::Failed) => {
                self.phase = Phase::Failed;
                Task::none()
            }
            Message::Address(address) => {
                self.address_check = None;
                if address.is_some_and(|a| !warn_logic::address_shows(&a, &self.args.site)) {
                    return iced::exit();
                }
                Task::none()
            }
            Message::Sent(true) | Message::Close => iced::exit(),
            Message::Sent(false) => {
                self.phase = Phase::NoBrowser;
                Task::none()
            }
            Message::GoBack | Message::Allow => Task::none(),
        }
    }

    /// The tab still shows the blocked site. Firefox titles its error page in the person's
    /// language and changes the title while loading, so its address bar is checked instead.
    fn still_there(&self) -> bool {
        match self.browser {
            Browser::Chromium => {
                warn_logic::title_shows(&sys::title(self.args.window), &self.args.site)
            }
            Browser::Firefox => true,
        }
    }

    fn follow(&mut self, now: Instant) -> Task<Message> {
        let window = self.args.window;
        if !sys::is_shown(window) || !self.still_there() {
            return iced::exit();
        }
        let front = sys::foreground();
        let ours = self.panel.is_some_and(|panel| front == panel);
        let near = front == window || ours || self.phase == Phase::Waiting;
        let escape = sys::escape_down();
        let pressed = escape && !self.escape_was_down;
        self.escape_was_down = escape;
        if pressed && (front == window || ours) {
            return iced::exit();
        }
        if near != self.shown {
            self.shown = near;
            native::set_shown(self.panel, near);
        }
        if near {
            self.place(false);
        }
        if self.browser == Browser::Firefox
            && self.address_check.is_none()
            && self
                .address_read
                .is_none_or(|at| now.duration_since(at) >= ADDRESS_EVERY)
            && front == window
            && self.phase == Phase::Ready
        {
            self.address_check = Some(now);
            self.address_read = Some(now);
            return Task::perform(
                super::blocking(move || sys::address(window, Browser::Firefox, ADDRESS_WAIT)),
                Message::Address,
            );
        }
        if let Some(started) = self.address_check {
            // A lookup that never answered must not stop later ones.
            if now.duration_since(started) > ADDRESS_EVERY * 4 {
                self.address_check = None;
            }
        }
        Task::none()
    }

    /// Keeps the panel over the browser. `first` shows it the first time.
    fn place(&mut self, first: bool) {
        let Some(panel) = self.panel else {
            return;
        };
        let window = self.args.window;
        let (Some(bounds), Some(work)) = (sys::bounds(window), sys::work_area(window)) else {
            return;
        };
        if first {
            // Moving first lets Windows pick the screen's scale before the size is set.
            let rough = warn_logic::place(bounds, work, sys::dpi(window));
            native::move_only(panel, rough);
        }
        let wanted = warn_logic::place(bounds, work, native::dpi(panel));
        if first {
            self.shown = true;
            native::show_at(panel, wanted);
        } else if native::rect_of(panel) != Some(wanted) {
            native::place(panel, wanted);
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let p = self.palette;
        let tone = match self.args.kind {
            Kind::Dangerous => Tone::Bad,
            _ => Tone::Warn,
        };
        let busy = matches!(self.phase, Phase::Leaving | Phase::Waiting);
        let heading = text(self.lang.t(heading_key(self.args.kind)))
            .size(theme::BODY + 1.0)
            .font(theme::SEMIBOLD)
            .color(p.text)
            .wrapping(Wrapping::None);
        let header = row![
            glyph(Icon::ShieldAlert.svg_filled(), 24.0, p.tone(tone)),
            heading,
            space::horizontal(),
            self.close_button(),
        ]
        .spacing(theme::S2)
        .align_y(Alignment::Center);
        let sentence = self
            .lang
            .t(sentence_key(self.args.kind))
            .replace("{site}", &shown_site(&self.args.site));
        let body = container(
            text(sentence)
                .size(theme::SMALL)
                .line_height(LineHeight::Absolute(Pixels(theme::LINE_SMALL)))
                .font(theme::REGULAR)
                .color(p.text_muted),
        )
        .height(Length::Fixed(64.0))
        .clip(true);
        let buttons = row![
            self.button(
                ButtonKind::Primary,
                self.lang.t("Go back"),
                (!busy).then_some(Message::GoBack)
            ),
            self.button(
                ButtonKind::Secondary,
                self.lang.t("Let me through once"),
                (!busy).then_some(Message::Allow)
            ),
        ]
        .spacing(theme::S2);
        column![header, body, buttons, self.footer()]
            .spacing(theme::S2)
            .padding([theme::S3, theme::S4])
            .into()
    }

    fn close_button(&self) -> Element<'_, Message> {
        let p = self.palette;
        widgets::arrow(
            press::button(container(glyph(Icon::X.svg(), 14.0, p.text_muted)).center(Length::Fill))
                .width(theme::CONTROL_SMALL)
                .height(theme::CONTROL_SMALL)
                .padding(0)
                .on_press(Message::Close)
                .style(widgets::button_style(p, ButtonKind::Ghost)),
        )
    }

    fn button(
        &self,
        kind: ButtonKind,
        label: String,
        on_press: Option<Message>,
    ) -> Element<'_, Message> {
        widgets::arrow(
            press::button(
                container(
                    text(label)
                        .size(theme::SMALL)
                        .line_height(LineHeight::Absolute(Pixels(theme::LINE_SMALL)))
                        .font(theme::MEDIUM)
                        .wrapping(Wrapping::None),
                )
                .center_y(Length::Fill),
            )
            .height(theme::CONTROL_SMALL)
            .padding([0.0, theme::S3])
            .on_press_maybe(on_press)
            .style(widgets::button_style(self.palette, kind)),
        )
    }

    fn footer(&self) -> Element<'_, Message> {
        let p = self.palette;
        let small = |s: String, color| {
            text(s)
                .size(theme::SMALL)
                .line_height(LineHeight::Absolute(Pixels(theme::LINE_SMALL)))
                .font(theme::REGULAR)
                .color(color)
        };
        match self.phase {
            Phase::Waiting => row![
                anim::spinner(16.0, p.text_muted, self.waiting_since.elapsed()),
                small(self.lang.t("Letting you through…"), p.text_muted),
            ]
            .spacing(theme::S2)
            .align_y(Alignment::Center)
            .into(),
            Phase::Declined => small(self.lang.t("Nothing changed."), p.text_muted).into(),
            Phase::Failed => small(
                self.lang.t("Couldn't let this site through. Open Secblitz, then Web protection, to try again."),
                p.bad_text,
            )
            .into(),
            Phase::NoBrowser => small(
                self.lang.t("Secblitz couldn't reach the browser. Use its own back or reload button."),
                p.bad_text,
            )
            .into(),
            Phase::Ready | Phase::Leaving => row![
                glyph(super::icons::BRAND_SVG, 14.0, p.text_muted),
                small("Secblitz".to_owned(), p.text_muted),
            ]
            .spacing(theme::S1)
            .align_y(Alignment::Center)
            .into(),
        }
    }
}

#[cfg(windows)]
mod native {
    use super::Rect;
    use core::ffi::c_void;
    use iced::window::raw_window_handle::RawWindowHandle;
    use windows_sys::Win32::{
        Foundation::{HWND, RECT},
        UI::HiDpi::GetDpiForWindow,
        UI::WindowsAndMessaging::{
            GetWindowLongPtrW, GetWindowRect, SetWindowLongPtrW, SetWindowPos, ShowWindow,
            GWL_EXSTYLE, HWND_TOPMOST, SWP_NOACTIVATE, SWP_NOSIZE, SWP_SHOWWINDOW, SW_HIDE,
            WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW,
        },
    };

    fn hwnd(window: usize) -> HWND {
        window as *mut c_void
    }

    pub fn handle_of(window: &dyn iced::window::Window) -> Option<usize> {
        match window.window_handle().ok()?.as_raw() {
            RawWindowHandle::Win32(win32) => Some(win32.hwnd.get() as usize),
            _ => None,
        }
    }

    /// Clicks reach the panel but never move the keyboard away from the browser, and the panel
    /// stays out of the taskbar and Alt+Tab.
    pub fn prepare(panel: usize) {
        // SAFETY: the panel's own live window.
        unsafe {
            let style = GetWindowLongPtrW(hwnd(panel), GWL_EXSTYLE);
            SetWindowLongPtrW(
                hwnd(panel),
                GWL_EXSTYLE,
                style | (WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW) as isize,
            );
        }
    }

    pub fn dpi(panel: usize) -> u32 {
        // SAFETY: plain query.
        unsafe { GetDpiForWindow(hwnd(panel)) }
    }

    pub fn move_only(panel: usize, at: Rect) {
        // SAFETY: the panel's own live window.
        unsafe {
            SetWindowPos(
                hwnd(panel),
                HWND_TOPMOST,
                at.left,
                at.top,
                0,
                0,
                SWP_NOSIZE | SWP_NOACTIVATE,
            );
        }
    }

    fn set(panel: usize, at: Rect, flags: u32) {
        // SAFETY: the panel's own live window.
        unsafe {
            SetWindowPos(
                hwnd(panel),
                HWND_TOPMOST,
                at.left,
                at.top,
                at.width(),
                at.height(),
                SWP_NOACTIVATE | flags,
            );
        }
    }

    pub fn show_at(panel: usize, at: Rect) {
        set(panel, at, SWP_SHOWWINDOW);
    }

    pub fn place(panel: usize, at: Rect) {
        set(panel, at, 0);
    }

    pub fn set_shown(panel: Option<usize>, shown: bool) {
        let Some(panel) = panel else {
            return;
        };
        if shown {
            if let Some(at) = rect_of(panel) {
                set(panel, at, SWP_SHOWWINDOW);
            }
        } else {
            // SAFETY: the panel's own live window.
            unsafe { ShowWindow(hwnd(panel), SW_HIDE) };
        }
    }

    pub fn rect_of(panel: usize) -> Option<Rect> {
        // SAFETY: `r` is a RECT.
        unsafe {
            let mut r: RECT = std::mem::zeroed();
            (GetWindowRect(hwnd(panel), &mut r) != 0).then_some(Rect {
                left: r.left,
                top: r.top,
                right: r.right,
                bottom: r.bottom,
            })
        }
    }
}

#[cfg(not(windows))]
mod native {
    use super::Rect;

    pub fn handle_of(_: &dyn iced::window::Window) -> Option<usize> {
        None
    }
    pub fn prepare(_: usize) {}
    pub fn dpi(_: usize) -> u32 {
        96
    }
    pub fn move_only(_: usize, _: Rect) {}
    pub fn show_at(_: usize, _: Rect) {}
    pub fn place(_: usize, _: Rect) {}
    pub fn set_shown(_: Option<usize>, _: bool) {}
    pub fn rect_of(_: usize) -> Option<Rect> {
        None
    }
}

/// There is no browser to watch off Windows.
#[cfg(not(windows))]
mod stub {
    use super::{Browser, Rect};
    use std::time::Duration;

    pub fn browser_of(_: usize) -> Option<Browser> {
        None
    }
    pub fn is_shown(_: usize) -> bool {
        false
    }
    pub fn title(_: usize) -> String {
        String::new()
    }
    pub fn bounds(_: usize) -> Option<Rect> {
        None
    }
    pub fn dpi(_: usize) -> u32 {
        96
    }
    pub fn work_area(_: usize) -> Option<Rect> {
        None
    }
    pub fn foreground() -> usize {
        0
    }
    pub fn escape_down() -> bool {
        false
    }
    pub fn go_back(_: usize) -> bool {
        false
    }
    pub fn reload(_: usize) -> bool {
        false
    }
    pub fn address(_: usize, _: Browser, _: Duration) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced::advanced::layout::Limits;
    use iced::advanced::renderer::Headless;
    use iced::advanced::widget::Tree;

    fn panel(kind: Kind, site: &str, lang: Lang, mode: Mode, phase: Phase) -> Panel {
        let args = WarnArgs {
            kind,
            site: site.into(),
            window: 1,
        };
        let mut panel = Panel::new(args, Browser::Chromium, lang).0;
        panel.palette = Palette::of(mode);
        panel.phase = phase;
        panel
    }

    fn renderer() -> iced::Renderer {
        // Measure with the app's own fonts, not whatever this system falls back to.
        for bytes in theme::FONT_FILES {
            iced::advanced::graphics::text::font_system()
                .write()
                .expect("font system")
                .load_font(std::borrow::Cow::Borrowed(bytes));
        }
        iced::futures::executor::block_on(<iced::Renderer as Headless>::new(
            theme::REGULAR,
            14.0.into(),
            Some("tiny-skia"),
        ))
        .expect("tiny-skia renderer")
    }

    const LANGS: [Lang; 6] = [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It];
    const PHASES: [Phase; 6] = [
        Phase::Ready,
        Phase::Leaving,
        Phase::Waiting,
        Phase::Declined,
        Phase::Failed,
        Phase::NoBrowser,
    ];

    #[test]
    fn the_panel_fits_its_window_in_every_language_kind_and_state() {
        let renderer = renderer();
        let long = format!("{}.example", "a".repeat(60));
        let size = iced::Size::new(warn_logic::PANEL_WIDTH, warn_logic::PANEL_HEIGHT);
        for lang in LANGS {
            for kind in [Kind::Dangerous, Kind::Scam] {
                for site in ["accountgiveaway.com", long.as_str()] {
                    for phase in PHASES {
                        let panel = panel(kind, site, lang, Mode::Light, phase);
                        let mut element = panel.view();
                        let mut tree = Tree::new(&element);
                        let node = element.as_widget_mut().layout(
                            &mut tree,
                            &renderer,
                            &Limits::new(iced::Size::ZERO, size),
                        );
                        let what = format!("{lang:?} {kind:?} {phase:?} {site}");
                        assert!(node.size().height <= size.height, "too tall: {what}");
                        let edge = size.width - theme::S4 + 0.5;
                        let rows = node.children();
                        for row in &rows[..3] {
                            for part in row.children() {
                                let right = row.bounds().x + part.bounds().x + part.bounds().width;
                                assert!(right <= edge, "too wide: {what} {right}");
                            }
                        }
                        let footer = rows[3].bounds();
                        assert!(
                            footer.y + footer.height <= size.height - theme::S3 + 0.5,
                            "footer cut off: {what}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_panel_words_are_translated_and_plain() {
        for lang in LANGS {
            for key in [
                "This site looks dangerous",
                "This site looks like a scam",
                sentence_key(Kind::Dangerous),
                sentence_key(Kind::Scam),
                "Go back",
                "Let me through once",
                "Letting you through…",
                "Nothing changed.",
                "Couldn't let this site through. Open Secblitz, then Web protection, to try again.",
                "Secblitz couldn't reach the browser. Use its own back or reload button.",
            ] {
                let text = lang.t(key);
                assert!(!text.contains('\u{2014}'), "{key}");
                if lang != Lang::En {
                    assert_ne!(text, key, "{lang:?} {key}");
                }
            }
            let sentence = lang.t(sentence_key(Kind::Scam));
            assert!(sentence.contains("{site}"));
        }
    }

    #[test]
    fn the_panel_window_is_not_titled_like_the_app() {
        assert_ne!(PANEL_TITLE, "Secblitz");
    }

    #[test]
    fn long_site_names_are_shortened() {
        assert_eq!(shown_site("a.example"), "a.example");
        let long = format!("{}.example", "b".repeat(80));
        let shown = shown_site(&long);
        assert_eq!(shown.chars().count(), SITE_SHOWN);
        assert!(shown.ends_with("..."));
    }

    #[test]
    #[ignore]
    fn draw_the_panel_to_png_files() {
        let Some(dir) = std::env::var_os("SECBLITZ_WARN_PNG") else {
            return;
        };
        use iced::advanced::{layout::Layout, mouse, renderer::Style, Renderer as _};
        let mut renderer = renderer();
        let size = iced::Size::new(warn_logic::PANEL_WIDTH, warn_logic::PANEL_HEIGHT);
        for (lang, kind, mode, phase, name) in [
            (
                Lang::En,
                Kind::Dangerous,
                Mode::Light,
                Phase::Ready,
                "en-dangerous-light",
            ),
            (
                Lang::En,
                Kind::Scam,
                Mode::Dark,
                Phase::Ready,
                "en-scam-dark",
            ),
            (
                Lang::De,
                Kind::Dangerous,
                Mode::Light,
                Phase::Ready,
                "de-dangerous-light",
            ),
            (
                Lang::It,
                Kind::Scam,
                Mode::Dark,
                Phase::Failed,
                "it-scam-failed",
            ),
            (
                Lang::Fr,
                Kind::Scam,
                Mode::Light,
                Phase::Declined,
                "fr-scam-declined",
            ),
        ] {
            let panel = panel(kind, "accountgiveaway.com", lang, mode, phase);
            let mut element = panel.view();
            let mut tree = Tree::new(&element);
            let node = element.as_widget_mut().layout(
                &mut tree,
                &renderer,
                &Limits::new(iced::Size::ZERO, size),
            );
            let viewport = iced::Rectangle::with_size(size);
            renderer.reset(viewport);
            renderer.fill_quad(
                iced::advanced::renderer::Quad {
                    bounds: viewport,
                    ..Default::default()
                },
                panel.palette.surface,
            );
            let theme = panel.palette.theme();
            element.as_widget().draw(
                &tree,
                &mut renderer,
                &theme,
                &Style {
                    text_color: panel.palette.text,
                },
                Layout::new(&node),
                mouse::Cursor::Unavailable,
                &viewport,
            );
            let pixels = renderer.screenshot(
                iced::Size::new(size.width as u32 * 2, size.height as u32 * 2),
                2.0,
                panel.palette.surface,
            );
            let file =
                std::fs::File::create(std::path::Path::new(&dir).join(format!("{name}.png")))
                    .unwrap();
            let mut encoder =
                png::Encoder::new(file, size.width as u32 * 2, size.height as u32 * 2);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            encoder
                .write_header()
                .unwrap()
                .write_image_data(&pixels)
                .unwrap();
        }
    }
}
