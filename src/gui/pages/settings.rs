//! Settings page: appearance, language, background protection, updates, about.
use crate::app::settings::{self as prefs_store, ThemeChoice};
use crate::gui::icons::Icon;
use crate::gui::pages::{remove, support};
use crate::gui::theme::{self, Mode, Palette, Tone};
use crate::gui::widgets::{self, anim, ButtonKind};
use crate::gui::{blocking, Ctx, Message};
use crate::i18n::Lang;
use iced::widget::{column, container, row, space};
use iced::{Alignment, Element, Length, Subscription, Task};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Remote<T> {
    Loading,
    Ready(T),
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateView {
    UpToDate,
    Ready,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Waiting,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Installing,
    Checking,
    Unknown,
    NotChecked,
    Off,
}

pub fn update_view(status: &secblitz::updater::UpdateStatus) -> UpdateView {
    use secblitz::updater::UpdateOutcome as O;
    match &status.result {
        O::UpToDate | O::Installed { .. } | O::DeferredRollout { .. } => UpdateView::UpToDate,
        O::DeferredBusy if status.checked_at == 0 => UpdateView::Checking,
        O::WorkerStarted { .. } | O::Available { .. } | O::DeferredBusy => UpdateView::Ready,
        O::Failed { .. } => UpdateView::Unknown,
        O::NotConfigured if status.checked_at == 0 => UpdateView::NotChecked,
        O::NotConfigured => UpdateView::Off,
    }
}

/// On Linux a waiting version is installed by the software app when the Secblitz repository is set up, and by Secblitz
/// itself otherwise; a started install is its own state.
#[cfg(target_os = "linux")]
pub fn linux_update_view(
    status: &secblitz::updater::UpdateStatus,
    by_software_app: bool,
) -> UpdateView {
    use secblitz::updater::UpdateOutcome as O;
    match (&status.result, by_software_app) {
        (O::Available { .. }, true) => UpdateView::Waiting,
        (O::WorkerStarted { .. }, _) => UpdateView::Installing,
        _ => update_view(status),
    }
}

fn shown_update(installed: bool, update: Option<UpdateView>) -> Remote<UpdateView> {
    match update {
        _ if !installed => Remote::Ready(UpdateView::Off),
        Some(view) => Remote::Ready(view),
        None => Remote::Failed,
    }
}

/// Windows copies run from the install folder; the other systems install through their package manager.
fn updates_apply(os: secblitz::os::Os, installed: bool) -> bool {
    os != secblitz::os::Os::Windows || installed
}

/// The tray icon and the notifications about switched back settings and blocked websites exist on Windows only.
fn has_background_extras(os: secblitz::os::Os) -> bool {
    os == secblitz::os::Os::Windows
}

fn shown_tray(installed: bool, tray: bool) -> bool {
    installed && tray
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Confirm {
    Background(bool),
    Tray(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    General,
    Help,
}

impl Tab {
    const ALL: [Tab; 2] = [Tab::General, Tab::Help];
}

#[derive(Debug)]
pub struct State {
    tab: Tab,
    help: support::State,
    background: Remote<bool>,
    update: Remote<UpdateView>,
    confirm: Option<Confirm>,
    working: bool,
    generation: u32,
    tray: bool,
    installed: bool,
    technical: bool,
    clock: anim::Clock,
    remove: remove::State,
    points: widgets::point::Opened,
}

impl Default for State {
    fn default() -> Self {
        State {
            tab: Tab::General,
            help: support::State::default(),
            background: Remote::Loading,
            update: Remote::Loading,
            confirm: None,
            working: false,
            generation: 0,
            tray: prefs_store::tray_enabled(),
            installed: prefs_store::installed_exe().is_some(),
            technical: false,
            clock: anim::Clock::new(),
            remove: remove::State::default(),
            points: widgets::point::Opened::default(),
        }
    }
}

impl State {
    fn busy(&self) -> bool {
        self.working
            || matches!(self.background, Remote::Loading)
            || matches!(self.update, Remote::Loading)
            || self.help.saving()
    }
}

pub fn subscription(state: &State) -> Subscription<Message> {
    let spinner = if state.busy() && !anim::reduced() {
        iced::window::frames().map(|_| Message::Settings(Msg::Frame))
    } else {
        Subscription::none()
    };
    Subscription::batch([spinner, remove::subscription(&state.remove)])
}

pub fn modal<'a>(state: &'a State, ctx: &'a Ctx) -> Option<Element<'a, Message>> {
    support::modal(&state.help, ctx, &state.clock).or_else(|| remove::modal(&state.remove, ctx))
}

pub fn escape(state: &mut State) {
    if !state.help.escape() && !remove::escape(&mut state.remove) {
        state.confirm = None;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LangItem(Lang);

impl LangItem {
    const ALL: [LangItem; 6] = [
        LangItem(Lang::En),
        LangItem(Lang::Es),
        LangItem(Lang::Fr),
        LangItem(Lang::De),
        LangItem(Lang::Pt),
        LangItem(Lang::It),
    ];
}

impl std::fmt::Display for LangItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            Lang::En => "English",
            Lang::Es => "Español",
            Lang::Fr => "Français",
            Lang::De => "Deutsch",
            Lang::Pt => "Português",
            Lang::It => "Italiano",
        })
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    Load,
    Loaded {
        generation: u32,
        background: Result<bool, String>,
        update: Option<UpdateView>,
    },
    SetTheme(ThemeChoice),
    SetLang(LangItem),
    SetNotifyReverted(bool),
    SetNotifyDangerous(bool),
    Ask(bool),
    AskTray(bool),
    CancelConfirm,
    Confirmed,
    Point(String),
    BackgroundDone(bool, Result<(), String>),
    TrayDone(bool, Result<(), String>),
    TrayStarted(bool),
    ToggleTechnical,
    Feedback(crate::broker::Request),
    FeedbackOpened(bool),
    PrivacyOpened(bool),
    Frame,
    InstallUpdate,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    UpdateInstalled(Result<UpdateView, String>),
    PrefsSaved(bool),
    Remove(remove::Msg),
    Help(support::Msg),
    SetTab(Tab),
}

pub fn on_enter(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    state.tab = Tab::General;
    state.help.reset();
    update(state, Msg::Load, ctx)
}

fn toast(text: &str, tone: Tone, ctx: &Ctx) -> Task<Message> {
    Task::done(Message::Toast(ctx.t(text), tone))
}

fn save_prefs(ctx: &Ctx) -> Task<Message> {
    Task::perform(crate::gui::save_prefs(ctx.prefs.clone()), |saved| {
        Message::Settings(Msg::PrefsSaved(saved))
    })
}

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    match msg {
        Msg::Frame => Task::none(),
        Msg::PrefsSaved(true) => Task::none(),
        Msg::PrefsSaved(false) => toast(
            "We couldn't save that choice. Please try again. If it keeps happening, restart your computer.",
            Tone::Warn,
            ctx,
        ),
        Msg::InstallUpdate => {
            #[cfg(target_os = "linux")]
            if !state.working {
                state.working = true;
                state.generation = state.generation.wrapping_add(1);
                state.clock.restart();
                return Task::perform(
                    blocking(|| {
                        prefs_store::install_update()
                            .map(|status| linux_update_view(&status, false))
                            .map_err(|e| format!("{e:#}"))
                    }),
                    |result| Message::Settings(Msg::UpdateInstalled(result)),
                );
            }
            Task::none()
        }
        Msg::UpdateInstalled(result) => {
            state.working = false;
            state.generation = state.generation.wrapping_add(1);
            match result {
                Ok(view) => {
                    state.update = Remote::Ready(view);
                    toast(
                        "Secblitz is installing the update. It is ready the next time you open it.",
                        Tone::Good,
                        ctx,
                    )
                }
                Err(message) => toast(&message, Tone::Warn, ctx),
            }
        }
        Msg::Remove(m) => remove::update(&mut state.remove, m, ctx),
        Msg::SetTab(tab) => {
            state.tab = tab;
            Task::none()
        }
        Msg::Help(m) => {
            if matches!(m, support::Msg::Save) {
                state.clock.restart();
            }
            let facts = support::Facts {
                background: match state.background {
                    Remote::Ready(on) => Some(on),
                    _ => None,
                },
                tray: shown_tray(state.installed, state.tray),
                installed: state.installed,
            };
            support::update(&mut state.help, m, ctx, facts)
        }
        Msg::Load => {
            state.clock.restart();
            state.background = Remote::Loading;
            state.update = Remote::Loading;
            load_task(state)
        }
        Msg::Loaded {
            generation,
            background,
            update,
        } => {
            // A read that started before a change (or lands mid-change) is stale.
            if generation != state.generation || state.working {
                return Task::none();
            }
            state.background = match background {
                Ok(on) => Remote::Ready(on),
                Err(_) => Remote::Failed,
            };
            state.update = shown_update(
                updates_apply(secblitz::os::Os::CURRENT, state.installed),
                update,
            );
            Task::none()
        }
        Msg::SetTheme(choice) => {
            ctx.prefs.theme = choice;
            ctx.palette = Palette::of(match choice {
                ThemeChoice::Light => Mode::Light,
                ThemeChoice::Dark => Mode::Dark,
            });
            save_prefs(ctx)
        }
        Msg::SetLang(LangItem(lang)) => {
            ctx.lang = lang;
            ctx.info = None;
            ctx.prefs.lang = Some(lang.code().to_owned());
            save_prefs(ctx)
        }
        Msg::SetNotifyReverted(on) => {
            ctx.prefs.notify_reverted = on;
            save_prefs(ctx)
        }
        Msg::SetNotifyDangerous(on) => {
            ctx.prefs.notify_dangerous = on;
            save_prefs(ctx)
        }
        Msg::Point(key) => {
            if state.confirm.is_some() {
                state.points.toggle(&key);
            }
            Task::none()
        }
        Msg::Ask(on) => {
            if !state.working {
                state.points.clear();
                state.confirm = Some(Confirm::Background(on));
            }
            Task::none()
        }
        Msg::AskTray(on) => {
            if !state.working && state.installed {
                state.points.clear();
                state.confirm = Some(Confirm::Tray(on));
            }
            Task::none()
        }
        Msg::CancelConfirm => {
            state.confirm = None;
            state.points.clear();
            Task::none()
        }
        Msg::Confirmed => {
            let Some(confirm) = state.confirm.take() else {
                return Task::none();
            };
            if state.working {
                return Task::none();
            }
            state.working = true;
            state.generation = state.generation.wrapping_add(1);
            state.clock.restart();
            match confirm {
                Confirm::Background(on) => Task::perform(
                    blocking(move || {
                        if on {
                            prefs_store::enable_background()
                        } else {
                            prefs_store::disable_background()
                        }
                        .map_err(|e| format!("{e:#}"))
                    }),
                    move |result| Message::Settings(Msg::BackgroundDone(on, result)),
                ),
                Confirm::Tray(on) => Task::perform(
                    blocking(move || {
                        prefs_store::set_tray_enabled(on).map_err(|e| format!("{e:#}"))
                    }),
                    move |result| Message::Settings(Msg::TrayDone(on, result)),
                ),
            }
        }
        Msg::BackgroundDone(on, result) => {
            state.working = false;
            state.generation = state.generation.wrapping_add(1);
            match result {
                Ok(()) => {
                    state.background = Remote::Ready(on);
                    toast(
                        if on {
                            "Automatic checks are on."
                        } else {
                            "Automatic checks are off."
                        },
                        Tone::Good,
                        ctx,
                    )
                }
                #[cfg(target_os = "linux")]
                Err(message) => toast(&message, Tone::Warn, ctx),
                #[cfg(not(target_os = "linux"))]
                Err(_) => toast(
                    "We couldn't change that. Nothing was changed on your computer. Please try again, or restart your computer first.",
                    Tone::Warn,
                    ctx,
                ),
            }
        }
        Msg::TrayDone(on, result) => {
            state.working = false;
            state.generation = state.generation.wrapping_add(1);
            match result {
                Ok(()) if on => {
                    state.tray = true;
                    ctx.broker_task(crate::broker::Request::StartTray, |reply| {
                        Message::Settings(Msg::TrayStarted(matches!(
                            reply,
                            Ok(crate::broker::Reply::Done)
                        )))
                    })
                }
                Ok(()) => {
                    state.tray = false;
                    toast(
                        "Secblitz no longer shows in the system tray.",
                        Tone::Good,
                        ctx,
                    )
                }
                Err(_) => toast(
                    "We couldn't change that. Nothing was changed on your computer. Please try again, or restart your computer first.",
                    Tone::Warn,
                    ctx,
                ),
            }
        }
        Msg::TrayStarted(started) => toast(
            if started {
                "Secblitz now shows in the system tray."
            } else {
                "Secblitz will show in the system tray the next time you sign in."
            },
            Tone::Good,
            ctx,
        ),
        Msg::ToggleTechnical => {
            state.technical = !state.technical;
            Task::none()
        }
        Msg::Feedback(request) => ctx.broker_task(request, move |reply| {
            let opened = matches!(reply, Ok(crate::broker::Reply::Done));
            Message::Settings(if request == crate::broker::Request::OpenPrivacyPolicy {
                Msg::PrivacyOpened(opened)
            } else {
                Msg::FeedbackOpened(opened)
            })
        }),
        Msg::FeedbackOpened(true) | Msg::PrivacyOpened(true) => Task::none(),
        Msg::PrivacyOpened(false) => toast(
            "We couldn't open your web browser. Visit secblitz.lol/privacy.html to read the privacy policy.",
            Tone::Warn,
            ctx,
        ),
        Msg::FeedbackOpened(false) => toast(
            "We couldn't open your web browser. Visit github.com/secblitz/Secblitz/issues to write to us.",
            Tone::Warn,
            ctx,
        ),
    }
}

const CONTROL_WIDTH: f32 = 168.0;

fn busy<'a>(p: Palette, state: &State, label: String) -> Element<'a, Message> {
    row![
        anim::spinner(16.0, p.text_muted, state.clock.elapsed()),
        widgets::muted(p, label),
    ]
    .spacing(theme::S2)
    .align_y(Alignment::Center)
    .into()
}

fn confirm_text(confirm: Confirm) -> (&'static str, &'static str, &'static str) {
    if cfg!(target_os = "linux") {
        match confirm {
            Confirm::Background(true) => {
                return (
                    "Look for updates automatically?",
                    "Once a day, Secblitz looks for a newer version of itself. It never changes anything on its own.",
                    "Turn on",
                )
            }
            Confirm::Background(false) => {
                return (
                    "Stop looking for updates?",
                    "Secblitz stops looking for updates by itself. You can still update it from your software app or from our website.",
                    "Turn off",
                )
            }
            _ => {}
        }
    }
    match confirm {
        Confirm::Background(true) => (
            "Check my computer automatically?",
            "Secblitz checks your computer every 15 minutes in the background. It never changes anything on its own.",
            "Turn on",
        ),
        Confirm::Background(false) => (
            "Stop checking automatically?",
            "Secblitz stops checking in the background. You can still check any time from Home.",
            "Turn off",
        ),
        Confirm::Tray(true) => (
            "Show Secblitz in the system tray?",
            "A small shield will appear near the clock when you sign in. It shows whether your computer looks safe.",
            "Turn on",
        ),
        Confirm::Tray(false) => (
            "Hide Secblitz from the system tray?",
            "The small shield will no longer appear when you sign in.",
            "Turn off",
        ),
    }
}

fn confirm_row<'a>(p: Palette, ctx: &Ctx, state: &State, confirm: Confirm) -> Element<'a, Message> {
    let (title, text_key, yes) = confirm_text(confirm);
    let body = column![
        widgets::body(p, ctx.t(title)),
        widgets::point::text_point(
            p,
            &ctx.t(text_key),
            widgets::point::Words::Muted,
            state.points.has("confirm"),
            Message::Settings(Msg::Point("confirm".to_owned())),
        ),
        row![
            space::horizontal(),
            widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t("Cancel"),
                None,
                Some(Message::Settings(Msg::CancelConfirm))
            ),
            widgets::action(
                p,
                ButtonKind::Primary,
                ctx.t(yes),
                None,
                Some(Message::Settings(Msg::Confirmed))
            ),
        ]
        .spacing(theme::S2),
    ]
    .spacing(theme::S3);
    container(body)
        .padding(theme::S4)
        .width(Length::Fill)
        .style(widgets::well_style(p))
        .into()
}

fn reload_menu<'a>(p: Palette, label: String) -> Element<'a, Message> {
    widgets::overflow_menu(
        p,
        vec![(Icon::Refresh, label, Message::Settings(Msg::Load), false)],
    )
}

pub fn view<'a>(state: &'a State, ctx: &'a Ctx) -> Element<'a, Message> {
    let p = Palette::of(ctx.palette.mode);
    let t = |s: &str| ctx.t(s);

    let theme_options = [
        (ThemeChoice::Light, t("Light")),
        (ThemeChoice::Dark, t("Dark")),
    ];
    let selected_lang = LangItem::ALL.iter().find(|l| l.0 == ctx.lang);
    let appearance = widgets::group(
        p,
        t("Appearance"),
        None,
        None,
        vec![
            widgets::row_item(
                p,
                Some(Icon::Sun),
                t("Theme"),
                None,
                widgets::segmented(p, &theme_options, ctx.prefs.theme, |v| {
                    Message::Settings(Msg::SetTheme(v))
                }),
                None,
            ),
            widgets::row_item(
                p,
                Some(Icon::Globe),
                t("Language"),
                None,
                container(widgets::dropdown(
                    p,
                    &LangItem::ALL[..],
                    selected_lang,
                    t("Choose a language"),
                    |l| Message::Settings(Msg::SetLang(l)),
                ))
                .width(CONTROL_WIDTH),
                None,
            ),
        ],
    );

    let background_control: Element<'a, Message> = if state.working {
        busy(p, state, t("Working"))
    } else {
        match &state.background {
            Remote::Loading => busy(p, state, t("Checking…")),
            Remote::Failed => row![
                widgets::pill(p, t("Couldn't check"), Tone::Warn),
                reload_menu(p, t("Try again")),
            ]
            .spacing(theme::S2)
            .align_y(Alignment::Center)
            .into(),
            Remote::Ready(on) => widgets::switch(p, *on, Some(|v| Message::Settings(Msg::Ask(v)))),
        }
    };
    let mut rows = vec![widgets::row_item(
        p,
        Some(Icon::Scan),
        t(if cfg!(target_os = "linux") {
            "Look for updates automatically"
        } else {
            "Check my computer automatically"
        }),
        Some(t(if cfg!(target_os = "linux") {
            "Once a day, Secblitz looks for a newer version of itself."
        } else {
            "Looks for problems in the background and tells you if something changes."
        })),
        background_control,
        None,
    )];
    if let Some(c @ Confirm::Background(_)) = state.confirm {
        rows.push(confirm_row(p, ctx, state, c));
    }
    if has_background_extras(secblitz::os::Os::CURRENT) {
        let tray_toggle =
            (state.installed && !state.working).then_some(|v| Message::Settings(Msg::AskTray(v)));
        rows.push(widgets::row_item(
            p,
            Some(Icon::Bell),
            t("System tray icon"),
            Some(if state.installed {
                t("A small shield tells you at a glance if your computer looks safe.")
            } else {
                t("Available once Secblitz is installed.")
            }),
            widgets::switch(p, shown_tray(state.installed, state.tray), tray_toggle),
            None,
        ));
        if let Some(c @ Confirm::Tray(_)) = state.confirm {
            rows.push(confirm_row(p, ctx, state, c));
        }
    }
    let protection = widgets::group(p, t("Background protection"), None, None, rows);

    let needs_background = matches!(state.background, Remote::Ready(false));
    let notifications = has_background_extras(secblitz::os::Os::CURRENT).then(|| {
        widgets::group(
            p,
            t("Notifications"),
            None,
            None,
            vec![
                widgets::row_item(
                    p,
                    Some(Icon::Bell),
                    t("Tell me when a setting is switched back"),
                    needs_background.then(|| t("Needs background checks, above.")),
                    widgets::switch(
                        p,
                        ctx.prefs.notify_reverted,
                        Some(|v| Message::Settings(Msg::SetNotifyReverted(v))),
                    ),
                    None,
                ),
                widgets::row_item(
                    p,
                    Some(Icon::ShieldAlert),
                    t("Tell me when a website is blocked"),
                    None,
                    widgets::switch(
                        p,
                        ctx.prefs.notify_dangerous,
                        Some(|v| Message::Settings(Msg::SetNotifyDangerous(v))),
                    ),
                    None,
                ),
            ],
        )
    });

    let (status, line): (Element<'a, Message>, String) = match &state.update {
        Remote::Loading | Remote::Ready(UpdateView::Checking) => {
            (busy(p, state, t("Checking…")), t("Looking for updates."))
        }
        Remote::Failed | Remote::Ready(UpdateView::Unknown) => (
            widgets::pill(p, t("Couldn't check"), Tone::Warn),
            t("We couldn't check for updates. Connect to the internet and we'll try again later."),
        ),
        Remote::Ready(UpdateView::UpToDate) => (
            widgets::pill(p, t("Up to date"), Tone::Good),
            t("You have the latest version of Secblitz."),
        ),
        Remote::Ready(UpdateView::Ready) => (
            widgets::pill(p, t("Update ready"), Tone::Warn),
            t(if cfg!(target_os = "linux") {
                "A new version is ready to install."
            } else {
                "An update is ready. It installs when Secblitz is closed."
            }),
        ),
        Remote::Ready(UpdateView::Waiting) => (
            widgets::pill(p, t("Update ready"), Tone::Warn),
            t("A new version is ready. Install it from your software app."),
        ),
        Remote::Ready(UpdateView::Installing) => (
            widgets::pill(p, t("Installing"), Tone::Neutral),
            t("Secblitz is installing the update. It is ready the next time you open it."),
        ),
        Remote::Ready(UpdateView::NotChecked) => (
            widgets::pill(p, t("Not checked yet"), Tone::Neutral),
            t(if cfg!(target_os = "linux") {
                "Secblitz has not looked for updates yet."
            } else {
                "Automatic updates are on. Secblitz looks for new versions every hour."
            }),
        ),
        Remote::Ready(UpdateView::Off) => (
            widgets::pill(p, t("Not set up"), Tone::Neutral),
            t("Automatic updates aren't turned on for this copy of Secblitz."),
        ),
    };
    let mut trailing = row![status].spacing(theme::S2).align_y(Alignment::Center);
    if !matches!(
        state.update,
        Remote::Loading | Remote::Ready(UpdateView::Off | UpdateView::Checking)
    ) {
        trailing = trailing.push(
            if cfg!(target_os = "linux")
                && matches!(state.update, Remote::Ready(UpdateView::Ready))
                && !state.working
            {
                widgets::overflow_menu(
                    p,
                    vec![
                        (
                            Icon::Download,
                            t("Install now"),
                            Message::Settings(Msg::InstallUpdate),
                            false,
                        ),
                        (
                            Icon::Refresh,
                            t("Check now"),
                            Message::Settings(Msg::Load),
                            false,
                        ),
                    ],
                )
            } else {
                reload_menu(p, t("Check now"))
            },
        );
    }
    let updates = widgets::group(
        p,
        t("Updates"),
        None,
        None,
        vec![widgets::row_item(
            p,
            Some(Icon::Download),
            line,
            None,
            trailing,
            None,
        )],
    );

    let mut details = column![
        widgets::small(p, t("A safer computer. Without headaches.")),
        widgets::small(p, t("Fonts: Lexend (SIL Open Font License).")),
        widgets::small(p, t("Icons: Fluent UI System Icons (MIT license).")),
        widgets::small(
            p,
            t("App clean-up lists draw on the Win11Debloat and WinUtil projects (MIT license).")
        ),
        widgets::small(
            p,
            format!(
                "{}: {}",
                t("Data folder"),
                ctx.state_dir
                    .as_ref()
                    .map(|d| d.display().to_string())
                    .unwrap_or_else(|| "-".into())
            )
        ),
        widgets::small(
            p,
            format!(
                "{}: {}",
                t("Protection checks available"),
                ctx.catalog.available.len()
            )
        ),
    ]
    .spacing(theme::S2);
    if let Some(error) = &ctx.engine_error {
        details = details.push(widgets::small(
            p,
            format!(
                "{}: {}",
                t("Last problem"),
                t(crate::app::flow::plain_failure(error))
            ),
        ));
    }
    let about = widgets::collapsible(
        p,
        "Secblitz",
        Some(format!("{} {}", t("Version"), env!("CARGO_PKG_VERSION"))),
        state.technical,
        Message::Settings(Msg::ToggleTechnical),
        container(details).padding([theme::S2, theme::S4 + theme::ICON_ROW + theme::S4]),
    );

    let link = |label: &str, request| {
        widgets::action(
            p,
            ButtonKind::Secondary,
            t(label),
            Some(Icon::ExternalLink),
            ctx.can_open_pages()
                .then_some(Message::Settings(Msg::Feedback(request))),
        )
    };
    let feedback = widgets::group(
        p,
        t("Help and feedback"),
        None,
        None,
        vec![
            widgets::row_item(
                p,
                Some(Icon::Bug),
                t("Report a problem"),
                Some(t("Tell us what went wrong.")),
                link("Open form", crate::broker::Request::OpenReportProblem),
                None,
            ),
            widgets::row_item(
                p,
                Some(Icon::Sparkles),
                t("Suggest a feature"),
                Some(t("Share an idea to make Secblitz better.")),
                link("Open form", crate::broker::Request::OpenSuggestFeature),
                None,
            ),
            widgets::row_item(
                p,
                Some(Icon::Eye),
                t("Privacy"),
                Some(t("See what Secblitz stores and when it uses the internet.")),
                link(
                    "Open privacy policy",
                    crate::broker::Request::OpenPrivacyPolicy,
                ),
                None,
            ),
            widgets::row_item(
                p,
                Some(Icon::Lock),
                t("Found a security problem?"),
                Some(t(
                    "Please don't post it publicly. Email support@secblitz.lol instead.",
                )),
                space::horizontal().width(0),
                None,
            ),
            support::row_item(ctx),
        ],
    );

    let removal = widgets::group(
        p,
        t(remove::SECTION_TITLE),
        None,
        None,
        vec![widgets::row_item(
            p,
            Some(Icon::Trash),
            t(remove::SECTION_ROW),
            Some(t(remove::SECTION_HELP)),
            widgets::action(
                p,
                ButtonKind::Danger,
                t(remove::SECTION_TITLE),
                None,
                (!ctx.busy).then(|| Message::Settings(Msg::Remove(remove::Msg::Open))),
            ),
            None,
        )],
    );

    let tabs = widgets::segmented(
        p,
        &Tab::ALL.map(|tab| {
            (
                tab,
                t(match tab {
                    Tab::General => "General",
                    Tab::Help => "Help",
                }),
            )
        }),
        state.tab,
        |tab| Message::Settings(Msg::SetTab(tab)),
    );
    let body: Element<'a, Message> = match state.tab {
        Tab::General => {
            let mut sections = column![appearance, protection].spacing(theme::S8);
            if let Some(notifications) = notifications {
                sections = sections.push(notifications);
            }
            sections.push(updates).push(removal).push(about).into()
        }
        Tab::Help => column![support::questions(&state.help, ctx), feedback]
            .spacing(theme::S8)
            .into(),
    };
    column![
        widgets::page_header(p, t("Settings"), Some(t("Make Secblitz work your way."))),
        column![tabs, body].spacing(theme::S6),
    ]
    .spacing(theme::S6)
    .into()
}

pub fn preload(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    let _ = ctx;
    if state.working {
        return Task::none();
    }
    load_task(state)
}

fn load_task(state: &mut State) -> Task<Message> {
    state.generation = state.generation.wrapping_add(1);
    let generation = state.generation;
    Task::perform(
        blocking(|| {
            let background = prefs_store::background_on().map_err(|e| format!("{e:#}"));
            let update = prefs_store::update_status().ok().map(|s| {
                #[cfg(target_os = "linux")]
                {
                    linux_update_view(&s, prefs_store::updates_by_software_app())
                }
                #[cfg(not(target_os = "linux"))]
                {
                    update_view(&s)
                }
            });
            (background, update)
        }),
        move |(background, update)| {
            Message::Settings(Msg::Loaded {
                generation,
                background,
                update,
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use secblitz::updater::{UpdateOutcome as O, UpdateStatus};

    fn status(result: O, checked_at: u64) -> UpdateStatus {
        UpdateStatus { checked_at, result }
    }

    #[test]
    fn update_status_is_shown_in_three_plain_states() {
        assert_eq!(update_view(&status(O::UpToDate, 5)), UpdateView::UpToDate);
        assert_eq!(
            update_view(&status(
                O::Installed {
                    version: "1.0.0".into()
                },
                5
            )),
            UpdateView::UpToDate
        );
        assert_eq!(
            update_view(&status(
                O::WorkerStarted {
                    version: "1.0.0".into()
                },
                5
            )),
            UpdateView::Ready
        );
        assert_eq!(update_view(&status(O::DeferredBusy, 5)), UpdateView::Ready);
        assert_eq!(
            update_view(&status(O::DeferredBusy, 0)),
            UpdateView::Checking
        );
        assert_eq!(
            update_view(&status(O::Failed { reason: "x".into() }, 5)),
            UpdateView::Unknown
        );
        assert_eq!(
            update_view(&status(O::NotConfigured, 0)),
            UpdateView::NotChecked
        );
        assert_eq!(update_view(&status(O::NotConfigured, 5)), UpdateView::Off);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tells_a_waiting_version_from_one_being_installed() {
        let waiting = status(
            O::Available {
                version: "2.0.0".into(),
            },
            5,
        );
        assert_eq!(linux_update_view(&waiting, true), UpdateView::Waiting);
        assert_eq!(linux_update_view(&waiting, false), UpdateView::Ready);
        let started = status(
            O::WorkerStarted {
                version: "2.0.0".into(),
            },
            5,
        );
        assert_eq!(linux_update_view(&started, false), UpdateView::Installing);
        assert_eq!(
            linux_update_view(&status(O::UpToDate, 5), true),
            UpdateView::UpToDate
        );
    }

    #[test]
    fn a_copy_that_is_not_installed_says_updates_are_not_set_up() {
        assert!(matches!(
            shown_update(false, Some(UpdateView::Unknown)),
            Remote::Ready(UpdateView::Off)
        ));
        assert!(matches!(
            shown_update(false, None),
            Remote::Ready(UpdateView::Off)
        ));
        assert!(matches!(
            shown_update(true, Some(UpdateView::Unknown)),
            Remote::Ready(UpdateView::Unknown)
        ));
        assert!(matches!(shown_update(true, None), Remote::Failed));
    }

    #[test]
    fn linux_always_shows_the_update_status_and_hides_the_windows_only_rows() {
        use secblitz::os::Os;
        assert!(updates_apply(Os::Linux, false));
        assert!(updates_apply(Os::Windows, true));
        assert!(!updates_apply(Os::Windows, false));
        assert!(has_background_extras(Os::Windows));
        assert!(!has_background_extras(Os::Linux));
        assert!(!has_background_extras(Os::Macos));
    }

    #[test]
    fn a_copy_that_is_not_installed_shows_the_tray_switch_off() {
        assert!(!shown_tray(false, true));
        assert!(!shown_tray(false, false));
        assert!(shown_tray(true, true));
        assert!(!shown_tray(true, false));
    }

    #[test]
    fn all_six_languages_are_offered_with_native_names() {
        let names: Vec<String> = LangItem::ALL.iter().map(ToString::to_string).collect();
        assert_eq!(
            names,
            [
                "English",
                "Español",
                "Français",
                "Deutsch",
                "Português",
                "Italiano"
            ]
        );
        let codes: Vec<_> = LangItem::ALL.iter().map(|l| l.0.code()).collect();
        assert_eq!(codes, ["en", "es", "fr", "de", "pt", "it"]);
    }
}
