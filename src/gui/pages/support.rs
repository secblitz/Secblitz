//! The Help tab in Settings and the support file sheet.
use crate::app::support::{self, Inputs, Saver};
use crate::gui::icons::Icon;
use crate::gui::pages::settings;
use crate::gui::theme::{self, Palette, Tone};
use crate::gui::widgets::{self, anim, ButtonKind};
use crate::gui::{blocking, Ctx, Helper, Message};
use iced::widget::{column, container, row, space};
use iced::{Alignment, Element, Task};

type El<'a> = Element<'a, Message>;

pub const QUESTIONS: [(&str, &str); 8] = [
    (
        "What does Secblitz do?",
        "Secblitz checks the security and privacy settings of your computer and your web browsers. It shows what could be safer and fixes it when you say yes. It can also remove apps you don't want and block dangerous websites.",
    ),
    (
        "Will Secblitz change anything without asking?",
        "No. Checking never changes anything. Secblitz only changes a setting after you have read what will happen and agreed. Checks that run in the background only look.",
    ),
    (
        "How do I undo a fix?",
        "Open History and use Undo your last fixes, or Put back chosen settings to pick which ones. If a fix can't be undone, Secblitz tells you before you agree.",
    ),
    (
        "How do I bring back an app I removed?",
        "Open Clean up apps, then the Removed apps tab, and choose Restore next to the app. If Secblitz didn't keep a copy, it gets the app from the Microsoft Store, which needs an internet connection.",
    ),
    (
        "A website won't open. What can I do?",
        "Web protection may have blocked it. Open Web protection and look under Recent blocks. Choose Let me through once to open that site for 10 minutes. To switch protection off for a while, choose Pause web protection.",
    ),
    (
        "Why did a warning appear over my browser?",
        "Web protection stopped a site that looks dangerous or like a scam. Choose Go back to leave it. Choose Let me through once only if you are sure it is safe.",
    ),
    (
        "How do I stop background checks or the icon near the clock?",
        "Open Settings and stay on General. Turn off Check my computer automatically to stop background checks. Turn off System tray icon to hide the small shield near the clock.",
    ),
    (
        "How do I remove Secblitz?",
        "Open Settings, General, and choose Remove Secblitz. You decide whether your computer stays as it is now or Secblitz puts everything back the way it was first.",
    ),
];

const GOES_IN: [&str; 6] = [
    "Your Secblitz and Windows versions and a few settings",
    "Which checks passed and which need attention",
    "How many changes Secblitz made, and when",
    "Which apps Secblitz removed",
    "Web protection switches and when its lists were updated",
    "Whether the Secblitz background services are running",
];

const NEVER_IN: [&str; 4] = [
    "Your files",
    "Your user name",
    "The websites you visit or Secblitz blocked",
    "Passwords",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sheet {
    Closed,
    Ask,
    Saving,
    Saved(String),
    Failed,
}

#[derive(Debug)]
pub struct State {
    pub sheet: Sheet,
    open: u16,
}

impl Default for State {
    fn default() -> Self {
        State {
            sheet: Sheet::Closed,
            open: 0,
        }
    }
}

impl State {
    pub fn saving(&self) -> bool {
        self.sheet == Sheet::Saving
    }

    pub fn is_open(&self, question: usize) -> bool {
        self.open & (1 << question) != 0
    }

    pub fn reset(&mut self) {
        if !self.saving() {
            *self = State::default();
        }
    }

    pub fn escape(&mut self) -> bool {
        if self.sheet == Sheet::Closed {
            return false;
        }
        if !self.saving() {
            self.sheet = Sheet::Closed;
        }
        true
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    Toggle(usize),
    Ask,
    Cancel,
    Save,
    Saved(Result<String, String>),
    Show,
    Shown(bool, Vec<isize>),
}

pub fn wrap(msg: Msg) -> Message {
    Message::Settings(settings::Msg::Help(msg))
}

pub struct Facts {
    pub background: Option<bool>,
    pub tray: bool,
    pub installed: bool,
}

pub fn update(state: &mut State, msg: Msg, ctx: &Ctx, facts: Facts) -> Task<Message> {
    match msg {
        Msg::Toggle(question) if question < QUESTIONS.len() => {
            state.open ^= 1 << question;
            Task::none()
        }
        Msg::Toggle(_) => Task::none(),
        Msg::Ask => {
            if state.sheet == Sheet::Closed {
                state.sheet = Sheet::Ask;
            }
            Task::none()
        }
        Msg::Cancel => {
            state.escape();
            Task::none()
        }
        Msg::Save => {
            if !matches!(state.sheet, Sheet::Ask | Sheet::Failed) {
                return Task::none();
            }
            let saver = match (&ctx.broker, ctx.helper) {
                (Some(client), _) => Saver::Launcher(client.clone()),
                (None, Helper::NotOnThisAccount) => Saver::Here,
                (None, _) => {
                    return Task::done(Message::Toast(
                        ctx.t(crate::gui::REOPEN_TO_DO_THIS),
                        Tone::Warn,
                    ))
                }
            };
            state.sheet = Sheet::Saving;
            let inputs = inputs(ctx, facts);
            Task::perform(blocking(move || support::create(inputs, saver)), |result| {
                wrap(Msg::Saved(result))
            })
        }
        Msg::Saved(result) => {
            if state.sheet == Sheet::Saving {
                state.sheet = match result {
                    Ok(name) => Sheet::Saved(name),
                    Err(_) => Sheet::Failed,
                };
            }
            Task::none()
        }
        Msg::Show => match &state.sheet {
            Sheet::Saved(_) => {
                let before = support::folder::windows();
                if ctx.broker.is_none() && ctx.helper == Helper::NotOnThisAccount {
                    return Task::perform(blocking(support::show_in_folder), move |shown| {
                        wrap(Msg::Shown(shown, before))
                    });
                }
                ctx.broker_task(crate::broker::Request::ShowSupportFile, move |reply| {
                    let shown = matches!(reply, Ok(crate::broker::Reply::Done));
                    wrap(Msg::Shown(shown, before.clone()))
                })
            }
            _ => Task::none(),
        },
        Msg::Shown(true, before) => Task::perform(
            blocking(move || support::folder::bring_forward(&before)),
            |()| Message::Noop,
        ),
        Msg::Shown(false, _) => Task::done(Message::Toast(
            ctx.t("We couldn't open the folder. Look for the file in your Downloads folder."),
            Tone::Warn,
        )),
    }
}

fn inputs(ctx: &Ctx, facts: Facts) -> Inputs {
    let mut problems: Vec<String> = ctx
        .engine_error
        .iter()
        .chain(ctx.check_error.iter())
        .cloned()
        .collect();
    if ctx.damage.is_some() {
        problems.push("The undo history is damaged.".to_owned());
    }
    Inputs {
        language: ctx.lang.code().to_owned(),
        theme: match ctx.prefs.theme {
            crate::app::settings::ThemeChoice::Light => "light",
            crate::app::settings::ThemeChoice::Dark => "dark",
        }
        .to_owned(),
        installed: facts.installed,
        background: facts.background,
        tray: facts.tray,
        checked_at: ctx.checked_at,
        checks: ctx
            .report
            .as_deref()
            .map(|r| {
                r.results
                    .iter()
                    .map(|o| (o.id.clone(), o.status.as_str().to_owned()))
                    .collect()
            })
            .unwrap_or_default(),
        problems,
    }
}

pub fn questions<'a>(state: &State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    let rows = QUESTIONS
        .iter()
        .enumerate()
        .map(|(i, (question, answer))| {
            widgets::collapsible(
                p,
                ctx.t(question),
                None,
                state.is_open(i),
                wrap(Msg::Toggle(i)),
                container(widgets::muted(p, ctx.t(answer)))
                    .padding([theme::S2, theme::S4 + theme::ICON_ROW + theme::S4]),
            )
        })
        .collect();
    widgets::group(p, ctx.t("Common questions"), None, None, rows)
}

pub fn row_item<'a>(ctx: &Ctx) -> El<'a> {
    let p = ctx.palette;
    widgets::row_item(
        p,
        Some(Icon::Download),
        ctx.t("Save a support file"),
        Some(ctx.t("A file you can attach when you report a problem.")),
        widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("Save file"),
            None,
            (!ctx.busy).then(|| wrap(Msg::Ask)),
        ),
        None,
    )
}

fn marked<'a>(p: Palette, mark: Icon, color: iced::Color, s: String) -> El<'a> {
    row![widgets::icon(mark, 16.0, color), widgets::body(p, s)]
        .spacing(theme::S2)
        .align_y(Alignment::Center)
        .into()
}

fn block<'a>(p: Palette, label: String, lines: Vec<El<'a>>) -> El<'a> {
    let mut c = column![widgets::section_label(p, label)].spacing(theme::S2);
    for l in lines {
        c = c.push(l);
    }
    c.into()
}

pub fn modal<'a>(state: &State, ctx: &'a Ctx, clock: &anim::Clock) -> Option<El<'a>> {
    let p = ctx.palette;
    let buttons = |cancel: &str, go: &str, go_msg: Msg| -> El<'a> {
        row![
            space::horizontal(),
            widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t(cancel),
                None,
                Some(wrap(Msg::Cancel))
            ),
            widgets::action(p, ButtonKind::Primary, ctx.t(go), None, Some(wrap(go_msg))),
        ]
        .spacing(theme::S2)
        .into()
    };
    Some(match &state.sheet {
        Sheet::Closed => return None,
        Sheet::Ask => {
            let goes_in = GOES_IN
                .iter()
                .map(|s| marked(p, Icon::Check, p.good, ctx.t(s)))
                .collect();
            let never = NEVER_IN
                .iter()
                .map(|s| marked(p, Icon::X, p.text_muted, ctx.t(s)))
                .collect();
            column![
                widgets::h2(p, ctx.t("Save a support file?")),
                widgets::muted(
                    p,
                    ctx.t("It is a small file you can attach when you report a problem. Secblitz does not send it anywhere. It is saved in your Downloads folder."),
                ),
                block(p, ctx.t("What goes in"), goes_in),
                block(p, ctx.t("What never goes in"), never),
                buttons("Cancel", "Save", Msg::Save),
            ]
            .spacing(theme::S3)
            .into()
        }
        Sheet::Saving => container(
            column![
                anim::spinner(32.0, p.text_muted, clock.elapsed()),
                widgets::h2(p, ctx.t("Saving the support file…")),
                widgets::muted(p, ctx.t("This only takes a moment.")),
            ]
            .spacing(theme::S3)
            .align_x(Alignment::Center),
        )
        .center_x(iced::Length::Fill)
        .padding([theme::S6, theme::S5])
        .into(),
        Sheet::Saved(name) => column![
            widgets::h2(p, ctx.t("Support file saved")),
            widgets::muted(
                p,
                ctx.t("You can find it in your Downloads folder. Attach it when you report a problem."),
            ),
            widgets::small(p, name.clone()),
            row![
                space::horizontal(),
                widgets::action(
                    p,
                    ButtonKind::Secondary,
                    ctx.t("Show in folder"),
                    Some(Icon::ExternalLink),
                    Some(wrap(Msg::Show))
                ),
                widgets::action(
                    p,
                    ButtonKind::Primary,
                    ctx.t("Done"),
                    None,
                    Some(wrap(Msg::Cancel))
                ),
            ]
            .spacing(theme::S2),
        ]
        .spacing(theme::S3)
        .into(),
        Sheet::Failed => column![
            widgets::h2(p, ctx.t("We couldn't save the support file")),
            widgets::muted(
                p,
                ctx.t("Nothing was changed on your computer. Check that your Downloads folder exists and has room, then try again."),
            ),
            buttons("Close", "Try again", Msg::Save),
        ]
        .spacing(theme::S3)
        .into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    const OTHERS: [Lang; 5] = [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It];

    fn texts() -> Vec<&'static str> {
        let mut all: Vec<&str> = QUESTIONS.iter().flat_map(|(q, a)| [*q, *a]).collect();
        all.extend(GOES_IN);
        all.extend(NEVER_IN);
        all.extend([
            "Common questions",
            "Save a support file",
            "A file you can attach when you report a problem.",
            "Save file",
            "Save a support file?",
            "It is a small file you can attach when you report a problem. Secblitz does not send it anywhere. It is saved in your Downloads folder.",
            "What goes in",
            "What never goes in",
            "Saving the support file…",
            "Support file saved",
            "You can find it in your Downloads folder. Attach it when you report a problem.",
            "Show in folder",
            "Done",
            "We couldn't save the support file",
            "Nothing was changed on your computer. Check that your Downloads folder exists and has room, then try again.",
            "We couldn't open the folder. Look for the file in your Downloads folder.",
        ]);
        all
    }

    #[test]
    fn every_help_and_support_text_is_translated_in_all_languages() {
        for text in texts() {
            for lang in OTHERS {
                let translated = lang.t(text);
                assert_ne!(translated, text, "{lang:?}: {text}");
                assert!(!translated.contains('\u{2014}'), "em dash in {translated}");
            }
            assert!(!text.contains('\u{2014}'), "em dash in {text}");
        }
    }

    #[test]
    fn questions_open_and_close_one_by_one_and_reset_with_the_page() {
        let mut s = State::default();
        assert!(!s.is_open(0));
        s.open ^= 1 << 3;
        assert!(s.is_open(3) && !s.is_open(2));
        s.open ^= 1 << 3;
        assert!(!s.is_open(3));
        s.open = 0b101;
        s.reset();
        assert!(!s.is_open(0) && !s.is_open(2));
    }

    #[test]
    fn escape_closes_the_sheet_except_while_saving() {
        let mut s = State::default();
        assert!(!s.escape(), "nothing open");
        s.sheet = Sheet::Ask;
        assert!(s.escape());
        assert_eq!(s.sheet, Sheet::Closed);
        s.sheet = Sheet::Saving;
        assert!(s.escape(), "handled, but the save keeps going");
        assert_eq!(s.sheet, Sheet::Saving);
        s.reset();
        assert_eq!(
            s.sheet,
            Sheet::Saving,
            "leaving the page cannot cancel a save"
        );
        s.sheet = Sheet::Saved("x.zip".to_owned());
        assert!(s.escape());
        assert_eq!(s.sheet, Sheet::Closed);
    }

    #[test]
    fn every_question_has_an_answer_and_no_two_share_a_title() {
        let mut titles: Vec<_> = QUESTIONS.iter().map(|(q, _)| *q).collect();
        titles.sort_unstable();
        titles.dedup();
        assert_eq!(titles.len(), QUESTIONS.len());
        assert!(QUESTIONS
            .iter()
            .all(|(q, a)| q.ends_with(['?', '.']) && a.len() > 40));
        assert!(QUESTIONS.len() <= 16, "open state is a 16-bit mask");
    }
}
