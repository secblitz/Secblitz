//! The Ads and tips tab: switches for the tips, suggestions and ads Windows shows the signed-in person.
use crate::broker::{Reply, Request};
use crate::gui::icons::Icon;
use crate::gui::theme::{self, Tone};
use crate::gui::widgets;
use crate::gui::{Ctx, Helper, Message};
use iced::widget::{row, space};
use iced::{Alignment, Element, Task};
use secblitz::user_settings::{Op, Setting};

type El<'a> = Element<'a, Message>;

const COUNT: usize = Setting::ADS_AND_TIPS.len();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cell {
    Idle,
    Loading,
    Known(Reply),
    Working,
}

#[derive(Debug)]
pub struct State {
    cells: [Cell; COUNT],
}

impl Default for State {
    fn default() -> Self {
        State {
            cells: [Cell::Idle; COUNT],
        }
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    Reported(Setting, Result<Reply, String>),
    Toggle(Setting, bool),
    Changed(Setting, Result<Reply, String>),
}

fn wrap(msg: Msg) -> Message {
    Message::Debloat(super::Msg::Ads(msg))
}

fn slot(setting: Setting) -> Option<usize> {
    Setting::ADS_AND_TIPS.iter().position(|s| *s == setting)
}

fn query(ctx: &Ctx, setting: Setting) -> Task<Message> {
    ctx.broker_task(Request::UserSetting(setting, Op::Query), move |r| {
        wrap(Msg::Reported(setting, r))
    })
}

/// Asks Windows how each switch stands right now.
pub fn load(state: &mut State, ctx: &Ctx) -> Task<Message> {
    if ctx.helper != Helper::Ready {
        return Task::none();
    }
    let mut tasks = Vec::new();
    for (i, setting) in Setting::ADS_AND_TIPS.into_iter().enumerate() {
        if !matches!(state.cells[i], Cell::Working | Cell::Loading) {
            state.cells[i] = Cell::Loading;
            tasks.push(query(ctx, setting));
        }
    }
    Task::batch(tasks)
}

/// What a switch shows right now, for tests.
#[cfg(test)]
pub fn shown_as(state: &State, setting: Setting) -> &'static str {
    let Some(i) = slot(setting) else {
        return "none";
    };
    match state.cells[i] {
        Cell::Idle => "idle",
        Cell::Loading => "loading",
        Cell::Working => "working",
        Cell::Known(Reply::NeedsAttention) => "off",
        Cell::Known(Reply::SafeByUs) => "on, can be switched back",
        Cell::Known(Reply::Safe) => "on",
        Cell::Known(_) => "unknown",
    }
}

fn toast(text: String, tone: Tone) -> Task<Message> {
    Task::done(Message::Toast(text, tone))
}

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    match msg {
        Msg::Reported(setting, reply) => {
            let Some(i) = slot(setting) else {
                return Task::none();
            };
            state.cells[i] = Cell::Known(match reply {
                Ok(
                    r @ (Reply::Safe
                    | Reply::SafeByUs
                    | Reply::NeedsAttention
                    | Reply::NotApplicable),
                ) => r,
                _ => Reply::Unknown,
            });
            Task::none()
        }
        Msg::Toggle(setting, on) => {
            let Some(i) = slot(setting) else {
                return Task::none();
            };
            let Cell::Known(now) = state.cells[i] else {
                return Task::none();
            };
            let op = match (on, now) {
                (true, Reply::NeedsAttention) => Op::Apply,
                (false, Reply::SafeByUs) => Op::Undo,
                _ => return Task::none(),
            };
            state.cells[i] = Cell::Working;
            ctx.broker_task(Request::UserSetting(setting, op), move |r| {
                wrap(Msg::Changed(setting, r))
            })
        }
        Msg::Changed(setting, reply) => {
            let note = match reply {
                Ok(Reply::Done) => None,
                Ok(Reply::Unavailable) => Some(ctx.t("This setting can't be changed on this PC. Your work or school may control it.")),
                Ok(Reply::ChangedSince) => Some(ctx.t("This setting was changed again after Secblitz set it. Whatever you changed was left as it is.")),
                Err(e) if e == "unavailable" => Some(ctx.t(ctx.helper.blocker().unwrap_or(crate::gui::REOPEN_TO_DO_THIS))),
                _ => Some(ctx.t("We couldn't change that setting. It was left as it was. Please try again.")),
            };
            let reread = query(ctx, setting);
            match note {
                Some(text) => Task::batch([toast(text, Tone::Warn), reread]),
                None => reread,
            }
        }
    }
}

pub(crate) fn label(ctx: &Ctx, setting: Setting) -> (Icon, String) {
    match setting {
        Setting::LockScreenTips => (Icon::Bell, ctx.t("Hide tips and offers on the lock screen")),
        Setting::StartSettingsTips => (
            Icon::Sparkles,
            ctx.t("Hide suggestions in Start and Settings"),
        ),
        Setting::ExplorerAds => (Icon::EyeOff, ctx.t("Hide ads in File Explorer")),
        Setting::SearchWebResults => (Icon::Search, ctx.t("Hide web results in Start search")),
        Setting::GameBarPopups => (
            Icon::Gamepad,
            ctx.t("Stop Game Bar pop-ups and its controller button"),
        ),
        Setting::StorageSense => (
            Icon::Trash,
            ctx.t("Let Windows remove temporary files on its own"),
        ),
        _ => (Icon::Settings, ctx.t("Windows settings")),
    }
}

fn switch_row<'a>(state: &State, ctx: &Ctx, setting: Setting) -> Option<El<'a>> {
    let p = ctx.palette;
    let (icon, title) = label(ctx, setting);
    let toggle = move |on: bool| wrap(Msg::Toggle(setting, on));
    let (sub, control): (String, El<'a>) = match state.cells[slot(setting)?] {
        Cell::Idle => return None,
        Cell::Loading => (ctx.t("Checking…"), space::horizontal().width(0).into()),
        Cell::Working => (
            ctx.t("Changing…"),
            widgets::switch(p, false, None::<fn(bool) -> Message>),
        ),
        Cell::Known(Reply::NotApplicable) => return None,
        Cell::Known(Reply::Unknown) => (
            ctx.t("We couldn't check this. Leave this page and open it again to try once more."),
            space::horizontal().width(0).into(),
        ),
        Cell::Known(Reply::NeedsAttention) => {
            (ctx.t("Off"), widgets::switch(p, false, Some(toggle)))
        }
        Cell::Known(Reply::SafeByUs) => (ctx.t("On"), widgets::switch(p, true, Some(toggle))),
        Cell::Known(_) => (
            ctx.t("On"),
            widgets::switch(p, true, None::<fn(bool) -> Message>),
        ),
    };
    let sheet = widgets::info::for_check(ctx, title.clone(), setting.id(), false)
        .map(|s| s.without(&[sub.as_str()]));
    let control = match widgets::info::button(ctx, sheet) {
        Some(info) => row![info, control]
            .spacing(theme::S1)
            .align_y(Alignment::Center)
            .into(),
        None => control,
    };
    Some(widgets::row_item(
        p,
        Some(icon),
        title,
        Some(sub),
        control,
        None,
    ))
}

pub fn view<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    let mut rows: Vec<El<'a>> = Vec::new();
    if let Some(blocker) = ctx.helper.blocker() {
        rows.push(widgets::row_item(
            p,
            Some(Icon::Info),
            ctx.t(blocker),
            None,
            space::horizontal().width(0),
            None,
        ));
    } else {
        for setting in Setting::ADS_AND_TIPS {
            rows.extend(switch_row(state, ctx, setting));
        }
        if rows.is_empty() {
            rows.push(widgets::row_item(
                p,
                Some(Icon::CheckCircle),
                ctx.t("Nothing to change here."),
                None,
                space::horizontal().width(0),
                None,
            ));
        }
    }
    widgets::group(
        p,
        ctx.t("Ads and tips"),
        Some(ctx.t("Nothing changes until you switch one on. You can switch it back any time, and it only affects your account.")),
        None,
        rows,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_switch_has_a_slot_a_label_and_an_explainer() {
        for (i, setting) in Setting::ADS_AND_TIPS.iter().enumerate() {
            assert_eq!(slot(*setting), Some(i));
            assert!(secblitz::explain::for_check(setting.id()).is_some());
        }
        assert_eq!(slot(Setting::SuggestedApps), None);
    }
}
