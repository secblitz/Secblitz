//! Drawing code for the Remove Secblitz sheet.
use super::*;
use crate::gui::icons::Icon;
use crate::gui::theme::{self, Palette, Tone};
use crate::gui::widgets::hairline::{self, rewind, Plate, Run};
use crate::gui::widgets::point::{self, Words};
use crate::gui::widgets::{self, anim, progress, ButtonKind};
use crate::gui::{Ctx, Message};
use iced::widget::{column, container, row, space};
use iced::{Alignment, Background, Border, Length};
use std::time::Instant;

fn pal(ctx: &Ctx) -> Palette {
    Palette::of(ctx.palette.mode)
}

pub fn modal<'a>(state: &'a State, ctx: &'a Ctx) -> Option<El<'a>> {
    let p = pal(ctx);
    Some(match &state.sheet {
        Sheet::Closed => return None,
        Sheet::Loading { .. } => loading_sheet(state, ctx, p),
        Sheet::Choose { plan, safe, choice } => choose_sheet(state, ctx, p, plan, safe, *choice),
        Sheet::Working { steps } => working_sheet(state, ctx, p, steps),
        Sheet::Result { lines, at } => result_sheet(state, ctx, p, lines, *at),
        Sheet::Leaving => centered(
            p,
            anim::spinner(32.0, p.text_muted, state.spin.elapsed_at(state.now)),
            ctx.t(LEAVING_TITLE),
            ctx.t(LEAVING_HELP),
        ),
    })
}

fn centered<'a>(p: Palette, lead: El<'a>, title: String, help: String) -> El<'a> {
    container(
        column![lead, widgets::h2(p, title), widgets::muted(p, help)]
            .spacing(theme::S3)
            .align_x(Alignment::Center),
    )
    .center_x(Length::Fill)
    .padding([theme::S6, theme::S5])
    .into()
}

fn loading_sheet<'a>(state: &State, ctx: &Ctx, p: Palette) -> El<'a> {
    centered(
        p,
        anim::spinner(32.0, p.text_muted, state.spin.elapsed_at(state.now)),
        ctx.t(LOADING),
        ctx.t("This only takes a moment."),
    )
}

fn option_row<'a>(
    p: Palette,
    selected: bool,
    glyph: Icon,
    title: String,
    help: String,
    on_press: Option<Message>,
) -> El<'a> {
    let mark: El<'a> = if selected {
        widgets::icon(Icon::CheckCircle, theme::ICON_ROW, p.brand)
    } else {
        space::horizontal().width(theme::ICON_ROW).into()
    };
    container(widgets::row_item(
        p,
        Some(glyph),
        title,
        Some(help),
        mark,
        on_press,
    ))
    .style(move |_| container::Style {
        background: selected.then_some(Background::Color(p.selected)),
        border: Border {
            radius: theme::R.into(),
            ..Border::default()
        },
        ..container::Style::default()
    })
    .into()
}

fn choose_sheet<'a>(
    state: &State,
    ctx: &Ctx,
    p: Palette,
    plan: &Option<Plan>,
    safe: &[Setting],
    choice: Option<Choice>,
) -> El<'a> {
    let n = counts(plan.as_ref(), safe);
    let offered = choices(can_put_back(n), state.installed);
    let mut col = column![widgets::h2(p, ctx.t(SECTION_TITLE))].spacing(theme::S3);
    if offered.is_empty() {
        col = col.push(widgets::muted(p, ctx.t(NOTHING_TO_PUT_BACK)));
        col = col.push(widgets::muted(p, ctx.t(delete_note())));
        return col
            .push(row![
                space::horizontal(),
                widgets::action(
                    p,
                    ButtonKind::Primary,
                    ctx.t(CLOSE),
                    None,
                    Some(wrap(Msg::Cancel))
                )
            ])
            .into();
    }
    col = col.push(widgets::muted(
        p,
        ctx.t(if can_put_back(n) {
            QUESTION
        } else {
            NOTHING_TO_PUT_BACK
        }),
    ));
    let mut options = column![].spacing(theme::S1);
    let single = offered.len() == 1;
    for option in &offered {
        let on = (!single).then(|| wrap(Msg::Pick(*option)));
        options = options.push(match option {
            Choice::Keep => option_row(
                p,
                choice == Some(Choice::Keep),
                Icon::Shield,
                ctx.t(KEEP_TITLE),
                ctx.t(keep_help()),
                on,
            ),
            Choice::PutBack => option_row(
                p,
                choice == Some(Choice::PutBack),
                Icon::Undo,
                ctx.t(PUT_BACK_TITLE),
                put_back_text(ctx.lang, n),
                on,
            ),
        });
    }
    col = col.push(options);
    if offered.contains(&Choice::PutBack) && !on_linux() {
        for limit in limits(ctx.helper, plan.as_ref()) {
            let n = match limit {
                Limit::StoreApps(n) => n,
                Limit::Personal => 0,
            };
            col = col.push(widgets::inline_notice(
                p,
                Tone::Warn,
                ctx.t(limit_key(ctx.helper, limit))
                    .replace("{n}", &n.to_string()),
            ));
        }
    }
    if plan.as_ref().is_some_and(|pl| pl.history_damaged) {
        col = col.push(widgets::inline_notice(
            p,
            Tone::Warn,
            ctx.t(crate::uninstall::HISTORY_DAMAGED),
        ));
    }
    col = col.push(widgets::small(p, ctx.t(stay_note())));
    if let Some(note) = web_note(plan.as_ref()) {
        col = col.push(widgets::small(p, ctx.t(note)));
    }
    let store_only = plan.as_ref().is_some_and(|pl| pl.apps_store_only > 0);
    match choice {
        Some(Choice::Keep) => match keep_note(plan.as_ref()) {
            Some((Tone::Warn, key)) => {
                let n = plan.as_ref().map_or(0, |pl| pl.apps_copy_only);
                col = col.push(widgets::inline_notice(
                    p,
                    Tone::Warn,
                    ctx.t(key).replace("{n}", &n.to_string()),
                ));
            }
            Some((_, key)) => col = col.push(widgets::small(p, ctx.t(key))),
            None => {}
        },
        Some(Choice::PutBack) => {
            col = col.push(widgets::small(p, ctx.t(OWN_ACCOUNT_ONLY)));
            if store_only {
                col = col.push(widgets::small(p, ctx.t(STORE_NEEDS_INTERNET)));
            }
        }
        _ => {}
    }
    let label = match (choice, state.installed) {
        (_, false) => ctx.t(PUT_BACK_TITLE),
        _ => ctx.t(SECTION_TITLE),
    };
    let go = widgets::action(
        p,
        ButtonKind::Danger,
        label,
        Some(Icon::Trash),
        (choice.is_some() && !ctx.busy).then(|| wrap(Msg::Confirm)),
    );
    col.push(space::vertical().height(theme::S1))
        .push(
            row![
                space::horizontal(),
                widgets::action(
                    p,
                    ButtonKind::Secondary,
                    ctx.t(CANCEL),
                    None,
                    Some(wrap(Msg::Cancel))
                ),
                go,
            ]
            .spacing(theme::S2),
        )
        .into()
}

fn rewind_art<'a>(
    ctx: &Ctx,
    p: Palette,
    run: Run,
    progress: Option<f32>,
    changed: Instant,
    now: Instant,
) -> El<'a> {
    let drawing = hairline::Rewind {
        p,
        plate: Plate::Surface,
        run,
        progress,
        changed,
        now: now.max(changed),
        label: ctx.t(rewind::label_key(rewind::Undo::Everything, run)),
    }
    .view();
    container(drawing).center_x(Length::Fill).into()
}

pub(super) fn result_run(lines: &[String]) -> Run {
    if lines.is_empty() {
        Run::Done
    } else {
        Run::Partial
    }
}

fn working_sheet<'a>(state: &State, ctx: &Ctx, p: Palette, steps: &[StepState; 5]) -> El<'a> {
    let spin = state.spin.elapsed_at(state.now);
    let mut list = column![].spacing(theme::S3);
    for item in Item::shown() {
        let (lead, note): (El<'a>, String) = match steps[item.index()] {
            StepState::Waiting => (
                space::horizontal().width(theme::CHECK).into(),
                ctx.t(STEP_WAITING),
            ),
            StepState::Working => (anim::spinner(20.0, p.text, spin), ctx.t(STEP_RUNNING)),
            StepState::Done(true, at) => (
                anim::check_draw(18.0, p.good, anim::slow_progress(at, state.now)),
                ctx.t(STEP_DONE),
            ),
            StepState::Done(false, at) => (
                anim::warn_draw(18.0, p.warn, anim::slow_progress(at, state.now)),
                ctx.t(STEP_PARTLY),
            ),
        };
        list = list.push(widgets::step_row(
            p,
            lead,
            vec![widgets::body(p, ctx.t(item.label()))],
            note,
        ));
    }
    let ratio = state.finished_steps() as f32 / Item::shown().len() as f32;
    column![
        rewind_art(ctx, p, Run::Working, Some(ratio), state.since, state.now),
        widgets::h2_centred(p, ctx.t(WORKING_TITLE)),
        widgets::muted_centred(p, ctx.t(WORKING_HELP)),
        progress::bar_eased(p, ratio, Tone::Brand),
        container(list)
            .padding(theme::S3)
            .style(widgets::well_style(p)),
    ]
    .spacing(theme::S3)
    .height(Length::Fixed(widgets::SHEET_FIT_HEIGHT))
    .into()
}

fn result_sheet<'a>(state: &State, ctx: &Ctx, p: Palette, lines: &[String], at: Instant) -> El<'a> {
    let mut col =
        column![rewind_art(ctx, p, result_run(lines), None, at, state.now)].spacing(theme::S3);
    if lines.is_empty() {
        col = col
            .push(widgets::h2_centred(p, ctx.t(RESULT_DONE_TITLE)))
            .push(widgets::muted_centred(p, ctx.t(delete_note())));
    } else {
        let mut list = column![].spacing(theme::S2);
        for (i, line) in lines.iter().enumerate() {
            let key = format!("left:{i}");
            list = list.push(point::text_point(
                p,
                line,
                Words::Body,
                state.points.has(&key),
                wrap(Msg::Point(key)),
            ));
        }
        col = col
            .push(widgets::h2_centred(p, ctx.t(RESULT_LEFT_TITLE)))
            .push(widgets::muted_centred(
                p,
                ctx.t(if state.installed {
                    RESULT_LEFT_HELP
                } else {
                    delete_note()
                }),
            ))
            .push(widgets::scroll_well(p, list, 168.0));
    }
    let mut buttons = row![space::horizontal()].spacing(theme::S2);
    for action in result_actions(state.installed) {
        buttons = buttons.push(match action {
            ResultAction::Keep => widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t(KEEP_SECBLITZ),
                None,
                Some(wrap(Msg::Cancel)),
            ),
            ResultAction::RemoveAnyway => widgets::action(
                p,
                ButtonKind::Danger,
                ctx.t(REMOVE_ANYWAY),
                Some(Icon::Trash),
                Some(wrap(Msg::RemoveAnyway)),
            ),
            ResultAction::Close => widgets::action(
                p,
                ButtonKind::Primary,
                ctx.t(CLOSE),
                None,
                Some(wrap(Msg::Cancel)),
            ),
        });
    }
    col.push(space::vertical().height(Length::Fill))
        .push(buttons)
        .height(Length::Fixed(widgets::SHEET_FIT_HEIGHT))
        .into()
}
