//! The welcome on a fresh install: three short steps, then the question.
use crate::gui::icons::Icon;
use crate::gui::theme::{self, Palette};
use crate::gui::widgets::hairline::magnifier::{self, Labels, Magnifier, Status};
use crate::gui::widgets::hairline::{Plate, Rewind, Run, ShieldFill};
use crate::gui::widgets::{self, anim, ButtonKind};
use crate::gui::{Ctx, Message};
use iced::widget::{column, container, row};
use iced::{Alignment, Background, Border, Element, Length, Subscription};
use std::time::Instant;

const STEPS: usize = 3;
const ART_SCALE: f32 = 0.8;

#[derive(Debug)]
pub struct State {
    step: usize,
    since: Instant,
    now: Instant,
}

impl Default for State {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            step: 0,
            since: now,
            now,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    Next,
    Back,
    Skip,
    Check,
    /// Enter: the main button of the step on screen.
    Primary,
    Frame(Instant),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Stay,
    Leave { check: bool },
}

pub fn update(state: &mut State, msg: Msg) -> Outcome {
    match msg {
        Msg::Next => go(state, state.step + 1),
        Msg::Back => go(state, state.step.saturating_sub(1)),
        Msg::Skip => return Outcome::Leave { check: false },
        Msg::Check => return Outcome::Leave { check: true },
        Msg::Primary if state.step + 1 < STEPS => go(state, state.step + 1),
        Msg::Primary => return Outcome::Leave { check: true },
        Msg::Frame(now) => state.now = now,
    }
    Outcome::Stay
}

fn go(state: &mut State, step: usize) {
    let step = step.min(STEPS - 1);
    if step != state.step {
        state.step = step;
        state.since = Instant::now();
        state.now = state.since;
    }
}

pub fn subscription() -> Subscription<Message> {
    let enter = iced::event::listen_with(|event, status, _| match (event, status) {
        (
            iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                key: iced::keyboard::Key::Named(iced::keyboard::key::Named::Enter),
                ..
            }),
            iced::event::Status::Ignored,
        ) => Some(Message::Welcome(Msg::Primary)),
        _ => None,
    });
    if anim::animating() {
        Subscription::batch([
            enter,
            iced::window::frames().map(|now| Message::Welcome(Msg::Frame(now))),
        ])
    } else {
        enter
    }
}

fn art<'a>(state: &State, ctx: &Ctx) -> Element<'a, Message> {
    let p = ctx.palette;
    let (changed, now) = (state.since, state.now.max(state.since));
    let drawing: Element<'a, Message> = match state.step {
        0 => Magnifier {
            p,
            plate: Plate::Bg,
            status: Status::Ready,
            progress: None,
            changed,
            now,
            labels: Labels::new(|s| ctx.t(s)),
        }
        .view(ART_SCALE),
        1 => ShieldFill {
            p,
            plate: Plate::Bg,
            run: Run::Done,
            progress: None,
            changed,
            now,
            label: ctx.t("You decide what changes"),
        }
        .view(),
        _ => Rewind {
            p,
            plate: Plate::Bg,
            run: Run::Done,
            progress: None,
            changed,
            now,
            label: ctx.t("You can undo anything"),
        }
        .view(),
    };
    container(drawing)
        .center_x(Length::Fill)
        .height(magnifier::VIEW.height * ART_SCALE)
        .align_y(Alignment::Center)
        .into()
}

fn dots<'a>(p: Palette, step: usize) -> Element<'a, Message> {
    let mut dots = row![].spacing(theme::S2).align_y(Alignment::Center);
    for i in 0..STEPS {
        let color = if i == step { p.text } else { p.border };
        dots = dots.push(
            container(iced::widget::space::horizontal())
                .width(theme::DOT)
                .height(theme::DOT)
                .style(move |_| container::Style {
                    background: Some(Background::Color(color)),
                    border: Border {
                        radius: theme::R_PILL.into(),
                        ..Border::default()
                    },
                    ..container::Style::default()
                }),
        );
    }
    dots.into()
}

pub fn view<'a>(state: &State, ctx: &Ctx) -> Element<'a, Message> {
    let p = ctx.palette;
    let (title, text) = match state.step {
        0 => (
            "Secblitz checks how your computer is set up",
            "It looks at the security and privacy settings of Windows and your browsers. Checking never changes anything.",
        ),
        1 => (
            "You decide what changes",
            "Secblitz explains what it found and fixes only what you agree to.",
        ),
        _ => (
            "You can undo anything",
            "Every fix can be put back from History, and Secblitz says first if one can't.",
        ),
    };
    let button = |kind, label: &str, msg| widgets::action(p, kind, ctx.t(label), None, Some(msg));
    let mut words = column![
        widgets::h1(p, ctx.t(title)),
        widgets::muted_centred(p, ctx.t(text)),
    ]
    .spacing(theme::S2)
    .align_x(Alignment::Center);
    let mut buttons: Vec<Element<'a, Message>> = Vec::new();
    if state.step > 0 {
        buttons.push(button(
            ButtonKind::Ghost,
            "Back",
            Message::Welcome(Msg::Back),
        ));
    }
    if state.step + 1 < STEPS {
        buttons.push(button(
            ButtonKind::Ghost,
            "Skip",
            Message::Welcome(Msg::Skip),
        ));
        buttons.push(button(
            ButtonKind::Primary,
            "Next",
            Message::Welcome(Msg::Next),
        ));
    } else {
        words = words
            .push(iced::widget::space::vertical().height(theme::S2))
            .push(
                column![
                    widgets::h2(p, ctx.t("Check your computer now?")),
                    widgets::muted(p, ctx.t("It takes about a minute.")),
                ]
                .spacing(theme::S1)
                .align_x(Alignment::Center),
            );
        buttons.push(button(
            ButtonKind::Secondary,
            "Not now",
            Message::Welcome(Msg::Skip),
        ));
        buttons.push(widgets::action(
            p,
            ButtonKind::Primary,
            ctx.t("Check my computer"),
            Some(Icon::Refresh),
            Some(Message::Welcome(Msg::Check)),
        ));
    }
    let buttons = row(buttons).spacing(theme::S3).align_y(Alignment::Center);
    let body = column![
        art(state, ctx),
        words.max_width(theme::MAX_READABLE * 1.15),
        buttons,
        dots(p, state.step)
    ]
    .spacing(theme::S6)
    .align_x(Alignment::Center)
    .width(Length::Fill);
    container(body)
        .center(Length::Fill)
        .padding(theme::S8)
        .style(move |_| container::Style {
            background: Some(Background::Color(p.bg)),
            ..container::Style::default()
        })
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_one_and_two_go_forward_and_the_last_asks_the_question() {
        let mut s = State::default();
        assert_eq!(update(&mut s, Msg::Next), Outcome::Stay);
        assert_eq!(s.step, 1);
        assert_eq!(update(&mut s, Msg::Primary), Outcome::Stay);
        assert_eq!(s.step, 2);
        assert_eq!(update(&mut s, Msg::Next), Outcome::Stay);
        assert_eq!(s.step, 2, "there is no step after the question");
        assert_eq!(update(&mut s, Msg::Primary), Outcome::Leave { check: true });
    }

    #[test]
    fn back_stops_at_the_first_step() {
        let mut s = State::default();
        update(&mut s, Msg::Back);
        assert_eq!(s.step, 0);
        update(&mut s, Msg::Next);
        update(&mut s, Msg::Back);
        assert_eq!(s.step, 0);
    }

    #[test]
    fn skip_and_not_now_leave_without_checking() {
        let mut s = State::default();
        assert_eq!(update(&mut s, Msg::Skip), Outcome::Leave { check: false });
        update(&mut s, Msg::Next);
        update(&mut s, Msg::Next);
        assert_eq!(update(&mut s, Msg::Skip), Outcome::Leave { check: false });
        assert_eq!(update(&mut s, Msg::Check), Outcome::Leave { check: true });
    }

    #[test]
    fn every_welcome_text_is_translated_into_every_language() {
        use crate::i18n::Lang;
        let texts = [
            "Secblitz checks how your computer is set up",
            "It looks at the security and privacy settings of Windows and your browsers. Checking never changes anything.",
            "You decide what changes",
            "Secblitz explains what it found and fixes only what you agree to.",
            "You can undo anything",
            "Every fix can be put back from History, and Secblitz says first if one can't.",
            "Check your computer now?",
            "It takes about a minute.",
            "Next",
            "Skip",
            "Back",
            "Not now",
            "Check my computer",
            "Not checked yet",
            "Check your computer to see what's protected. Nothing is changed.",
        ];
        for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            for text in texts {
                let shown = lang.t(text);
                assert_ne!(shown, text, "{text}");
                assert!(!shown.contains('\u{2014}'), "{text}");
            }
        }
    }
}
