//! Per-account settings for the apps the user installed, not Windows apps or Secblitz.
use crate::broker::{Reply, Request};
use crate::gui::icons::Icon;
use crate::gui::pages::tools;
use crate::gui::theme::{self, Palette, Tone};
use crate::gui::widgets::{self, ButtonKind};
use crate::gui::{Ctx, Helper, Message};
use iced::widget::{row, space};
use iced::{Alignment, Element, Task};
use secblitz::user_settings::{Op, Setting};

type El<'a> = Element<'a, Message>;

#[derive(Debug, Clone)]
pub enum Msg {
    Load,
    Reported(Setting, Result<Reply, String>),
    Toggle(Setting, bool),
    Changed(Setting, Result<Reply, String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cell {
    Idle,
    Loading,
    Known(Reply),
    Working,
}

#[derive(Debug)]
pub struct State {
    cells: [Cell; Setting::PERSONAL.len()],
}

impl Default for State {
    fn default() -> Self {
        Self {
            cells: [Cell::Idle; Setting::PERSONAL.len()],
        }
    }
}

fn wrap(msg: Msg) -> Message {
    Message::Tools(tools::Msg::Personal(msg))
}

fn cell(setting: Setting) -> usize {
    usize::from(setting.to_byte())
}

fn toast(text: String, tone: Tone) -> Task<Message> {
    Task::done(Message::Toast(text, tone))
}

pub fn on_enter(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    if ctx.helper != Helper::Ready {
        return Task::none();
    }
    if state.cells.iter().all(|c| *c == Cell::Idle) {
        return update(state, Msg::Load, ctx);
    }
    Task::none()
}

fn query(ctx: &Ctx, setting: Setting) -> Task<Message> {
    ctx.broker_task(Request::UserSetting(setting, Op::Query), move |r| {
        wrap(Msg::Reported(setting, r))
    })
}

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    match msg {
        Msg::Load => {
            let mut tasks = Vec::new();
            for setting in Setting::PERSONAL {
                if !matches!(state.cells[cell(setting)], Cell::Working | Cell::Loading) {
                    state.cells[cell(setting)] = Cell::Loading;
                    tasks.push(query(ctx, setting));
                }
            }
            Task::batch(tasks)
        }
        Msg::Reported(setting, reply) => {
            state.cells[cell(setting)] = Cell::Known(match reply {
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
            let Cell::Known(now) = state.cells[cell(setting)] else {
                return Task::none();
            };
            let op = match (on, now) {
                (true, Reply::NeedsAttention) => Op::Apply,
                (false, Reply::SafeByUs) => Op::Undo,
                _ => return Task::none(),
            };
            state.cells[cell(setting)] = Cell::Working;
            ctx.broker_task(Request::UserSetting(setting, op), move |r| {
                wrap(Msg::Changed(setting, r))
            })
        }
        Msg::Changed(setting, reply) => {
            let note = match reply {
                Ok(Reply::Done) => None,
                Ok(Reply::Unavailable) => Some(ctx.t("This setting can't be changed on this computer. Your work or school may control it.")),
                Ok(Reply::ChangedSince) => Some(ctx.t("This setting was changed again after Secblitz set it. Whatever you changed was left as it is.")),
                Err(e) if e == "unavailable" => Some(helper_text(ctx)),
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

fn helper_text(ctx: &Ctx) -> String {
    ctx.t(ctx
        .helper
        .blocker()
        .unwrap_or(crate::gui::REOPEN_TO_DO_THIS))
}

/// One section's content, ready for the Tools page to put under its header.
pub struct Part<'a> {
    pub subtitle: String,
    pub rows: Vec<El<'a>>,
}

pub fn account<'a>(state: &'a State, ctx: &'a Ctx) -> Part<'a> {
    Part {
        subtitle: ctx.t("Settings that belong to the person signed in to this computer."),
        rows: account_rows(state, ctx),
    }
}

pub fn account_busy(state: &State) -> bool {
    state.cells.iter().any(|c| matches!(c, Cell::Working))
}

fn secondary<'a>(p: Palette, label: String, msg: Option<Msg>) -> El<'a> {
    widgets::action(p, ButtonKind::Secondary, label, None, msg.map(wrap))
}

fn label(ctx: &Ctx, setting: Setting) -> (Icon, String) {
    match setting {
        Setting::StoreAppsWebCheck => (Icon::Package, ctx.t("Web check for Store apps")),
        Setting::ShowExtensions => (Icon::Eye, ctx.t("Show file endings like .pdf")),
        Setting::NearbySharing => (Icon::Globe, ctx.t("Nearby sharing with your devices only")),
        Setting::TailoredExperiences => (
            Icon::EyeOff,
            ctx.t("Keep your computer habits out of tips and ads"),
        ),
        Setting::OfficeMacros => (
            Icon::Lock,
            ctx.t("Block macros in Office files from the internet"),
        ),
        Setting::SuggestedApps => (
            Icon::Package,
            ctx.t("Stop Windows from adding suggested apps again"),
        ),
        Setting::LockScreenTips
        | Setting::StartSettingsTips
        | Setting::ExplorerAds
        | Setting::SearchWebResults
        | Setting::GameBarPopups
        | Setting::StorageSense => super::debloat::ads::label(ctx, setting),
    }
}

fn is_on(reply: Reply) -> bool {
    matches!(reply, Reply::Safe | Reply::SafeByUs)
}

fn account_rows<'a>(state: &'a State, ctx: &'a Ctx) -> Vec<El<'a>> {
    let p = ctx.palette;
    let mut rows: Vec<El<'a>> = Vec::new();
    if ctx.helper != Helper::Ready {
        rows.push(widgets::row_item(
            p,
            Some(Icon::Info),
            helper_text(ctx),
            None,
            space::horizontal().width(0),
            None,
        ));
    } else if state.cells.iter().all(|c| *c == Cell::Idle) {
        rows.push(widgets::row_item(
            p,
            Some(Icon::Scan),
            ctx.t("Check my account settings"),
            None,
            secondary(p, ctx.t("Check"), Some(Msg::Load)),
            None,
        ));
    } else {
        for setting in Setting::PERSONAL {
            if let Some(r) = setting_row(state, ctx, setting) {
                rows.push(r);
            }
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
    rows
}

fn setting_row<'a>(state: &'a State, ctx: &'a Ctx, setting: Setting) -> Option<El<'a>> {
    let p = ctx.palette;
    let (icon, title) = label(ctx, setting);
    let cell = state.cells[cell(setting)];
    let toggle = move |on: bool| wrap(Msg::Toggle(setting, on));
    let (sub, control): (String, El<'a>) = match cell {
        Cell::Idle => return None,
        Cell::Loading => (ctx.t("Checking…"), space::horizontal().width(0).into()),
        Cell::Working => (
            ctx.t("Changing…"),
            widgets::switch(p, false, None::<fn(bool) -> Message>),
        ),
        Cell::Known(Reply::NotApplicable) => return None,
        Cell::Known(Reply::Unknown) if setting == Setting::NearbySharing => return None,
        Cell::Known(Reply::Unknown) => (
            ctx.t("We couldn't check this. Leave this page and open it again to try once more."),
            space::horizontal().width(0).into(),
        ),
        Cell::Known(Reply::NeedsAttention) => {
            (ctx.t("Off"), widgets::switch(p, false, Some(toggle)))
        }
        Cell::Known(Reply::SafeByUs) => (ctx.t("On"), widgets::switch(p, true, Some(toggle))),
        Cell::Known(reply) => (
            ctx.t("On"),
            widgets::switch(p, is_on(reply), None::<fn(bool) -> Message>),
        ),
    };
    let control = match widgets::info::button(
        ctx,
        widgets::info::for_check(ctx, title.clone(), setting.id(), false),
    ) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_setting_has_a_cell_and_a_label_and_an_explainer() {
        let state = State::default();
        assert_eq!(state.cells.len(), Setting::PERSONAL.len());
        for (i, setting) in Setting::PERSONAL.iter().enumerate() {
            assert_eq!(cell(*setting), i);
            assert!(secblitz::explain::for_check(setting.id()).is_some());
        }
    }
}
