//! Drawing code for the Clean up apps page.
use super::*;
use crate::gui::icons::Icon;
use crate::gui::theme::{self, Palette, Tone};
use crate::gui::widgets::hairline::start_menu::{
    self, Fate, Filler, Labels, MenuApp, Outcome, StartMenu,
};
use crate::gui::widgets::hairline::{Glyph, Plate};
use crate::gui::widgets::point::{self, Words};
use crate::gui::widgets::{self, anim, progress, ButtonKind, CheckState};
use crate::gui::{Ctx, Message};
use crate::i18n::Lang;
use iced::widget::{column, container, row, scrollable, space};
use iced::{Alignment, Element, Length, Padding};
use secblitz::debloat::{self, Group, ItemResult, Kept};
use std::time::Instant;

pub fn view<'a>(state: &'a State, ctx: &'a Ctx) -> Element<'a, Message> {
    let p = pal(ctx);
    let header = widgets::page_header(
        p,
        ctx.t("Clean up apps"),
        Some(ctx.t("Remove apps you don't need. You can bring them back any time.")),
    );
    let removed_label = if state.removed.is_empty() {
        ctx.t("Removed apps")
    } else {
        format!("{} ({})", ctx.t("Removed apps"), state.removed.len())
    };
    let tabs = widgets::segmented(
        p,
        &[
            (Tab::Apps, ctx.t("Apps to remove")),
            (Tab::Removed, removed_label),
            (Tab::Ads, ctx.t("Ads and tips")),
            (Tab::Space, ctx.t("Free up space")),
        ],
        state.tab,
        |t| wrap(Msg::SetTab(t)),
    );
    let body: Element<'a, Message> = match state.tab {
        Tab::Apps => apps_tab(state, ctx),
        Tab::Removed => removed_tab(state, ctx),
        Tab::Ads => ads::view(&state.ads, ctx),
        Tab::Space => super::space::view(&state.space, ctx),
    };
    let mut page = column![header, column![tabs, body].spacing(theme::S4)]
        .spacing(theme::S6)
        .width(Length::Fill);
    if suggested_blocked(state) {
        page = page.push(
            row![
                widgets::muted(p, ctx.t(BLOCKED_NOTE)),
                space::horizontal(),
                widgets::link(p, ctx.t(ALLOW_AGAIN), wrap(Msg::AllowSuggested),),
            ]
            .spacing(theme::S3)
            .align_y(Alignment::Center),
        );
    }
    page.into()
}

pub fn modal<'a>(state: &'a State, ctx: &'a Ctx) -> Option<Element<'a, Message>> {
    match &state.sheet {
        Sheet::None => super::space::modal(&state.space, ctx),
        Sheet::Review => Some(review_sheet(state, ctx)),
        Sheet::Working(items) => Some(working_sheet(state, items, ctx)),
        Sheet::Done(done) => Some(widgets::appear::settle(
            result_sheet(state, done, ctx),
            pal(ctx).surface,
        )),
        Sheet::Delete(index) => Some(delete_sheet(*index, ctx)),
    }
}

fn loading_state<'a>(state: &State, ctx: &Ctx) -> Element<'a, Message> {
    let p = pal(ctx);
    container(
        column![
            anim::spinner(32.0, p.text_muted, state.spin.elapsed_at(state.now)),
            widgets::h2(p, ctx.t("Looking for apps you can remove…")),
        ]
        .spacing(theme::S3)
        .align_x(Alignment::Center),
    )
    .center_x(Length::Fill)
    .padding([theme::S10, theme::S5])
    .into()
}

fn apps_tab<'a>(state: &'a State, ctx: &'a Ctx) -> Element<'a, Message> {
    let p = pal(ctx);
    match &state.scan {
        Scan::Loading if state.groups.is_empty() => loading_state(state, ctx),
        Scan::Failed(technical) => column![widgets::empty_state(
            p,
            Icon::AlertTriangle,
            ctx.t("We couldn't look at your apps"),
            ctx.t(debloat::friendly::run_failure(technical)),
            Some(widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t("Try again"),
                Some(Icon::Refresh),
                Some(wrap(Msg::Rescan)),
            )),
        ),]
        .spacing(theme::S4)
        .into(),
        _ if state.groups.is_empty() => widgets::empty_state(
            p,
            Icon::CheckCircle,
            ctx.t("Nothing to clean up"),
            ctx.t("None of the apps we know about are on this PC."),
            None,
        ),
        _ => {
            let bar = widgets::search_field(
                p,
                SEARCH_ID,
                &ctx.t("Search apps"),
                &state.search,
                |text| wrap(Msg::Search(text)),
                wrap(Msg::ClearSearch),
            );
            let mut col = column![].spacing(theme::S1);
            let mut any = false;
            for (group, members) in &state.groups {
                let shown = shown_members(state, ctx, members);
                if !shown.is_empty() {
                    any = true;
                    col = col.push(group_card(state, ctx, *group, &shown));
                }
            }
            let list: Element<'a, Message> = if any {
                col.into()
            } else {
                widgets::no_matches(ctx, &state.search, wrap(Msg::ClearSearch))
            };
            column![bar, list].spacing(theme::S4).into()
        }
    }
}

pub fn footer<'a>(state: &'a State, ctx: &'a Ctx) -> Option<Element<'a, Message>> {
    let listing = state.tab == Tab::Apps
        && !state.groups.is_empty()
        && !matches!(state.scan, Scan::Failed(_));
    listing.then(|| action_bar(state, ctx))
}

fn action_bar<'a>(state: &'a State, ctx: &'a Ctx) -> Element<'a, Message> {
    let p = pal(ctx);
    let n = state.selected.len();
    let can = n > 0 && !ctx.busy;
    let button_label = if n == 0 {
        ctx.t("Remove apps")
    } else {
        count_text(ctx, n, "Remove {n} app", "Remove {n} apps")
    };
    let hidden = if searching(state) {
        let on_screen: BTreeSet<u16> = state
            .groups
            .iter()
            .flat_map(|(_, members)| shown_members(state, ctx, members))
            .collect();
        state
            .selected
            .iter()
            .filter(|i| !on_screen.contains(i))
            .count()
    } else {
        0
    };
    let hint = if ctx.busy {
        ctx.t("Please wait until the current task has finished.")
    } else if hidden > 0 {
        ctx.t("Some chosen apps are hidden by your search.")
    } else if n == 0 {
        ctx.t("Tick the apps you want to remove.")
    } else {
        ctx.t("You will be able to review before anything is removed.")
    };
    let title = if n == 0 {
        ctx.t("No apps selected")
    } else {
        count_text(ctx, n, "{n} app selected", "{n} apps selected")
    };
    row![
        column![widgets::h2(p, title), widgets::small(p, hint)].spacing(theme::S1),
        space::horizontal(),
        widgets::action(
            p,
            ButtonKind::Primary,
            button_label,
            Some(Icon::Trash),
            can.then(|| wrap(Msg::Review))
        )
    ]
    .align_y(Alignment::Center)
    .spacing(theme::S4)
    .into()
}

fn group_text(group: Group) -> (&'static str, &'static str, Icon) {
    match group {
        Group::Recommended => (
            "Recommended to remove",
            "Apps most people never use.",
            Icon::Sparkles,
        ),
        Group::Sponsored => (
            "Ads and games",
            "Sponsored apps and games that come pre-installed.",
            Icon::Bell,
        ),
        Group::Promotions => (
            "Microsoft extras",
            "Newer Microsoft features pushed to you.",
            Icon::Bot,
        ),
        Group::Utilities => (
            "Everyday tools",
            "Handy tools you may already use. Leave these unticked unless you're sure.",
            Icon::Wrench,
        ),
        Group::Gaming => ("Gaming", "Xbox and Game Bar.", Icon::Gamepad),
    }
}

const GROUP_ROWS: usize = 8;

fn group_card<'a>(
    state: &'a State,
    ctx: &'a Ctx,
    group: Group,
    members: &[u16],
) -> Element<'a, Message> {
    let p = pal(ctx);
    let narrowed = searching(state);
    let (title, subtitle, _) = group_text(group);
    let chosen = members
        .iter()
        .filter(|i| state.selected.contains(i))
        .count();
    let check = if chosen == 0 {
        CheckState::Off
    } else if chosen == members.len() {
        CheckState::On
    } else {
        CheckState::Mixed
    };
    let count = ctx
        .t("{a} of {b} selected")
        .replace("{a}", &chosen.to_string())
        .replace("{b}", &members.len().to_string());
    let open = state.open.contains(&group) || narrowed;
    let expanded = state.expanded.contains(&group) || narrowed;
    let mut body = column![].spacing(theme::S1);
    body = body.push(
        container(widgets::small(p, ctx.t(subtitle))).padding(Padding {
            top: theme::S1,
            right: theme::S4,
            bottom: theme::S1,
            left: widgets::INDENT,
        }),
    );
    if group == Group::Gaming {
        body = body.push(widgets::inline_notice(
            p,
            Tone::Warn,
            ctx.t("Game Bar recording and Xbox games may stop working"),
        ));
    }
    for &index in widgets::limited(members, GROUP_ROWS, expanded) {
        let app = app_of(index);
        let box_ = widgets::checkbox(
            p,
            state.selected.contains(&index).into(),
            None,
            Some(wrap(Msg::Toggle(index))),
        );
        body = body.push(widgets::row_item_lead(
            p,
            Some(app_glyph(p, state, index, theme::ICON_ROW)),
            ctx.t(app.name),
            debloat::note_on(app.family, debloat::is_windows_11()).map(|note| ctx.t(note)),
            box_,
            Vec::new(),
            Some(wrap(Msg::Toggle(index))),
        ));
    }
    if members.len() > GROUP_ROWS && !narrowed {
        let label = if expanded {
            ctx.t("Show less")
        } else {
            ctx.t("Show {n} more")
                .replace("{n}", &(members.len() - GROUP_ROWS).to_string())
        };
        body = body.push(widgets::show_more_button(
            p,
            label,
            wrap(Msg::ToggleMore(group)),
        ));
    }
    row![
        container(widgets::checkbox(
            p,
            check,
            None,
            Some(wrap(Msg::ToggleGroup(group)))
        ))
        .padding([0.0, theme::S2])
        .height(theme::CONTROL + theme::S2)
        .center_y(theme::CONTROL + theme::S2),
        widgets::collapsible(
            p,
            ctx.t(title),
            Some(count),
            open,
            wrap(Msg::ToggleOpen(group)),
            body,
        ),
    ]
    .align_y(Alignment::Start)
    .into()
}

fn days_since(now: u64, t: u64) -> u64 {
    use secblitz::clock::local_day;
    local_day(now).saturating_sub(local_day(t))
}

fn ago(ctx: &Ctx, t: u64) -> String {
    match days_since(debloat::now(), t) {
        0 => ctx.t("Removed today"),
        1 => ctx.t("Removed yesterday"),
        n => ctx.t("Removed {n} days ago").replace("{n}", &n.to_string()),
    }
}

fn removed_tab<'a>(state: &'a State, ctx: &'a Ctx) -> Element<'a, Message> {
    let p = pal(ctx);
    if state.removed.is_empty() {
        return widgets::empty_state(
            p,
            Icon::Package,
            ctx.t("No removed apps"),
            ctx.t("Apps you remove show up here."),
            None,
        );
    }
    let mut rows: Vec<Element<'a, Message>> = Vec::new();
    for &(index, t) in &state.removed {
        let app = app_of(index);
        let has_copy = state.copies.contains(&index);
        let enabled = state.restoring.is_none() && state.batch.is_none() && !ctx.busy;
        let (subtitle, trailing): (String, Element<'a, Message>) = if state.restoring == Some(index)
        {
            let text = if state.restoring_copy {
                ctx.t("Bringing back {name}…")
                    .replace("{name}", &ctx.t(app.name))
            } else {
                ctx.t("Restoring…")
            };
            (
                text,
                anim::spinner(16.0, p.text_muted, state.spin.elapsed_at(state.now)),
            )
        } else if state.queue.contains(&index) {
            (ctx.t("Waiting"), space().into())
        } else if state.offline == Some(index) {
            (
                ctx.t("You're offline. Connect to the internet, then press Retry."),
                widgets::action(
                    p,
                    widgets::ButtonKind::Secondary,
                    ctx.t("Retry"),
                    Some(Icon::Refresh),
                    enabled.then(|| wrap(Msg::RestoreStore(index))),
                ),
            )
        } else if has_copy {
            (
                ago(ctx, t),
                actions_view(p, ctx, row_actions(state, ctx.helper, index, enabled)),
            )
        } else if let Some(note) = app.store_id.and(super::store_blocker(ctx.helper)) {
            (
                format!("{} · {}", ago(ctx, t), ctx.t(note)),
                widgets::icon(Icon::Info, 16.0, p.text_muted),
            )
        } else if app.store_id.is_none() {
            (
                format!(
                    "{} · {}",
                    ago(ctx, t),
                    ctx.t("You can look for it in the Microsoft Store yourself.")
                ),
                widgets::icon(Icon::Info, 16.0, p.text_muted),
            )
        } else {
            (
                ago(ctx, t),
                actions_view(p, ctx, row_actions(state, ctx.helper, index, enabled)),
            )
        };
        rows.push(widgets::row_item_lead(
            p,
            Some(app_glyph(p, state, index, theme::ICON_ROW)),
            ctx.t(app.name),
            Some(subtitle),
            trailing,
            Vec::new(),
            None,
        ));
    }
    let summary = (state.saved_bytes > 0).then(|| {
        ctx.t("Saved copies use about {size} and bring apps back without internet.")
            .replace(
                "{size}",
                &crate::app::maintenance::size_phrase(state.saved_bytes),
            )
    });
    widgets::group(
        p,
        ctx.t("Removed apps"),
        summary,
        restore_all_view(state, ctx),
        rows,
    )
}

fn restore_all_view<'a>(state: &'a State, ctx: &'a Ctx) -> Option<Element<'a, Message>> {
    let p = pal(ctx);
    if let Some(batch) = &state.batch {
        let done = batch.total - state.queue.len();
        return Some(widgets::small(
            p,
            ctx.t("Restoring {i} of {n}…")
                .replace("{i}", &done.to_string())
                .replace("{n}", &batch.total.to_string()),
        ));
    }
    if super::restorable(state).len() < 2 {
        return None;
    }
    let enabled = state.restoring.is_none() && !state.probing && !ctx.busy;
    Some(widgets::action(
        p,
        widgets::ButtonKind::Secondary,
        ctx.t("Restore all"),
        Some(Icon::Undo),
        enabled.then(|| wrap(Msg::RestoreAll)),
    ))
}

struct RowActions {
    primary: Option<Msg>,
    menu: Vec<(Icon, &'static str, Msg, bool)>,
}

fn row_actions(state: &State, helper: Helper, index: u16, enabled: bool) -> RowActions {
    let mut actions = RowActions {
        primary: None,
        menu: Vec::new(),
    };
    if !enabled {
        return actions;
    }
    if state.copies.contains(&index) {
        actions.primary = Some(Msg::Restore(index));
        if app_of(index).store_id.is_some() && super::store_blocker(helper).is_none() {
            actions.menu.push((
                Icon::Undo,
                "Get it from the Microsoft Store",
                Msg::RestoreStore(index),
                false,
            ));
        }
        actions.menu.push((
            Icon::Trash,
            "Delete saved copy",
            Msg::AskDelete(index),
            true,
        ));
    } else if app_of(index).store_id.is_some() && super::store_blocker(helper).is_none() {
        actions.primary = Some(Msg::Restore(index));
    }
    actions
}

fn actions_view<'a>(p: Palette, ctx: &Ctx, actions: RowActions) -> Element<'a, Message> {
    let mut trailing = row![].spacing(theme::S2).align_y(Alignment::Center);
    if let Some(m) = actions.primary {
        trailing = trailing.push(widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("Restore"),
            None,
            Some(wrap(m)),
        ));
    }
    let items = actions
        .menu
        .into_iter()
        .map(|(icon, label, m, danger)| (icon, ctx.t(label), wrap(m), danger))
        .collect();
    trailing.push(widgets::overflow_menu(p, items)).into()
}

fn delete_sheet<'a>(index: u16, ctx: &'a Ctx) -> Element<'a, Message> {
    let p = pal(ctx);
    let name = ctx.t(app_of(index).name);
    let body = if app_of(index).store_id.is_some() {
        ctx.t("{name} can then only come back from the Microsoft Store.")
    } else {
        ctx.t("{name} can't come back after this.")
    }
    .replace("{name}", &name);
    column![
        widgets::h2(p, ctx.t("Delete the saved copy?")),
        widgets::muted(p, body),
        space::vertical().height(theme::S1),
        row![
            space::horizontal(),
            widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t("Cancel"),
                None,
                Some(wrap(Msg::Cancel))
            ),
            widgets::action(
                p,
                ButtonKind::Danger,
                ctx.t("Delete"),
                Some(Icon::Trash),
                Some(wrap(Msg::Delete(index))),
            ),
        ]
        .spacing(theme::S2),
    ]
    .spacing(theme::S3)
    .into()
}

const WORKING_LIST_MAX: f32 = 200.0;
const RESULT_BODY_MAX: f32 = 200.0;

fn review_sheet<'a>(state: &'a State, ctx: &'a Ctx) -> Element<'a, Message> {
    let p = pal(ctx);
    let indices: Vec<u16> = state.selected.iter().copied().collect();
    let n = indices.len();
    let mut list = column![].spacing(theme::S2);
    for &i in &indices {
        list = list.push(
            row![
                app_glyph(p, state, i, 16.0),
                widgets::body(p, ctx.t(app_of(i).name))
            ]
            .spacing(theme::S3)
            .align_y(Alignment::Center),
        );
    }
    let mut col = column![
        widgets::h2(p, count_text(ctx, n, "Remove {n} app?", "Remove {n} apps?")),
        point::text_point(
            p,
            &if n == 1 {
                ctx.t("This app will be removed for everyone who uses this PC. Your own files are not touched.")
            } else {
                ctx.t("These apps will be removed for everyone who uses this PC. Your own files are not touched.")
            },
            Words::Muted,
            state.points.has("review:intro"),
            wrap(Msg::Point("review:intro".to_owned())),
        ),
        widgets::scroll_well(p, list, 220.0),
    ]
    .spacing(theme::S3);
    col = col.push(widgets::inline_notice(
        p,
        Tone::Neutral,
        if n == 1 {
            ctx.t("Secblitz keeps a copy, so you can bring it back any time from the Removed apps tab, even without internet.")
        } else {
            ctx.t("Secblitz keeps a copy, so you can bring them back any time from the Removed apps tab, even without internet.")
        },
    ));
    col = col.push(widgets::small(
        p,
        if n == 1 {
            ctx.t("If this app is open, Secblitz closes it first.")
        } else {
            ctx.t("If any of these apps are open, Secblitz closes them first.")
        },
    ));
    if indices.iter().any(|i| app_of(*i).group == Group::Gaming) {
        col = col.push(widgets::inline_notice(
            p,
            Tone::Warn,
            ctx.t("Game Bar recording and Xbox games may stop working"),
        ));
    }
    col = col.push(match super::store_blocker(ctx.helper) {
        Some(_) => column![widgets::small(p, ctx.t(suggested_blocker(ctx.helper)))],
        None => column![
            widgets::checkbox(
                p,
                state.block_again.into(),
                Some(ctx.t("Stop Windows from adding suggested apps again")),
                Some(wrap(Msg::ToggleBlock)),
            ),
            container(point::text_point(
                p,
                &ctx.t("Windows sometimes installs apps on its own. Tick this to ask it to stop."),
                Words::Small,
                state.points.has("review:block"),
                wrap(Msg::Point("review:block".to_owned())),
            ))
            .padding(Padding {
                left: theme::S1 + theme::CHECK + theme::S3,
                ..Padding::ZERO
            }),
        ]
        .spacing(theme::S1),
    });
    col.push(space::vertical().height(theme::S1))
        .push(
            row![
                space::horizontal(),
                widgets::action(
                    p,
                    ButtonKind::Secondary,
                    ctx.t("Cancel"),
                    None,
                    Some(wrap(Msg::Cancel))
                ),
                widgets::action(
                    p,
                    ButtonKind::Danger,
                    count_text(ctx, n, "Remove {n} app", "Remove {n} apps"),
                    Some(Icon::Trash),
                    (!ctx.busy).then(|| wrap(Msg::Confirm)),
                ),
            ]
            .spacing(theme::S2),
        )
        .into()
}

fn working_sheet<'a>(
    state: &'a State,
    items: &'a [(u16, Step)],
    ctx: &'a Ctx,
) -> Element<'a, Message> {
    let p = pal(ctx);
    let finished = items
        .iter()
        .filter(|(_, s)| matches!(s, Step::Done(..)))
        .count();
    let mut list = column![].spacing(theme::S3);
    for (index, step) in items {
        let blank = || -> Element<'a, Message> { space::horizontal().width(theme::CHECK).into() };
        let (lead, note): (Element<'a, Message>, String) = match step {
            Step::Waiting => (blank(), ctx.t("Waiting")),
            Step::Saving => (blank(), ctx.t("Saving a copy…")),
            Step::Working => (blank(), ctx.t("Removing…")),
            Step::Done(ItemResult::Removed, at) => (
                anim::check_draw(18.0, p.good, anim::slow_progress(*at, state.now)),
                ctx.t("Removed"),
            ),
            Step::Done(ItemResult::Protected, _) => (
                widgets::icon(Icon::Info, 18.0, p.text_muted),
                ctx.t("Windows protects this app"),
            ),
            Step::Done(ItemResult::Kept(kept), _) => (
                widgets::icon(Icon::Info, 18.0, p.text_muted),
                ctx.t(kept_text(kept)),
            ),
            Step::Done(ItemResult::Failed(_), at) => (
                anim::cross_draw(18.0, p.bad, anim::slow_progress(*at, state.now)),
                ctx.t("Couldn't remove"),
            ),
        };
        list = list.push(widgets::step_row(
            p,
            lead,
            vec![
                app_glyph(p, state, *index, theme::CHECK),
                widgets::body(p, ctx.t(app_of(*index).name)),
            ],
            note,
        ));
    }
    let ratio = if items.is_empty() {
        0.0
    } else {
        finished as f32 / items.len() as f32
    };
    let title = ctx.t("Removing apps…");
    let drawing = removal_menu(
        state,
        ctx,
        items.iter().map(|(i, step)| (*i, fate_of(step))),
        Outcome::Working,
        state.run_at,
        title.clone(),
    );
    column![
        drawing,
        widgets::h2(p, title),
        widgets::muted(
            p,
            ctx.t("Please keep this window open. This can take a few minutes.")
        ),
        progress::bar_eased(p, ratio, Tone::Brand),
        widgets::scroll_well(p, list, WORKING_LIST_MAX),
    ]
    .spacing(theme::S3)
    .into()
}

fn fate_of(step: &Step) -> Fate {
    match step {
        Step::Waiting => Fate::Waiting,
        Step::Saving => Fate::Saving,
        Step::Working => Fate::Busy,
        Step::Done(ItemResult::Removed, at) => Fate::Removed(*at),
        Step::Done(ItemResult::Protected, at) => Fate::Stays(*at),
        Step::Done(ItemResult::Kept(_), at) => Fate::Kept(*at),
        Step::Done(ItemResult::Failed(_), at) => Fate::Refused(*at),
    }
}

fn final_fate(index: u16, step: &Step, done: &Finished) -> Fate {
    if matches!(step, Step::Done(..)) {
        return fate_of(step);
    }
    let at = done.at;
    let Some(batch) = &done.batch else {
        return Fate::Refused(at);
    };
    if batch.removed.iter().any(|r| r.index == index) {
        Fate::Removed(at)
    } else if batch.failed.iter().any(|f| f.index == index) {
        Fate::Refused(at)
    } else if batch.kept.contains(&index) || done.kept.iter().any(|(i, _)| *i == index) {
        Fate::Kept(at)
    } else if batch.skipped.contains(&index) {
        Fate::Stays(at)
    } else {
        Fate::Absent(at)
    }
}

fn menu_fillers(state: &State, lang: Lang) -> Vec<Filler> {
    [
        (Glyph::Gear, lang.t("Settings")),
        (Glyph::Folder, lang.t("File Explorer")),
        (Glyph::Shield, lang.t("Windows Security")),
        (Glyph::Cart, lang.t("Microsoft Store")),
        (Glyph::Doc, lang.t("Notepad")),
    ]
    .into_iter()
    .map(|(glyph, name)| Filler { glyph, name })
    .chain(state.menu_fillers.iter().map(|i| Filler {
        glyph: start_menu::glyph_for(app_of(*i).family),
        name: lang.t(app_of(*i).name),
    }))
    .collect()
}

fn menu_labels(lang: Lang, result: String) -> Labels {
    Labels {
        waiting: lang.t("Waiting to remove {name}"),
        saving: lang.t("Saving a copy of {name}"),
        removing: lang.t("Removing {name}"),
        refused: lang.t("Couldn't remove {name}"),
        kept: lang.t("{name} stays on your PC"),
        protected: lang.t("Windows protects {name}"),
        more_one: lang.t("1 more app"),
        more_many: lang.t("{n} more apps"),
        result,
    }
}

fn removal_menu<'a>(
    state: &State,
    ctx: &Ctx,
    apps: impl Iterator<Item = (u16, Fate)>,
    outcome: Outcome,
    changed: Instant,
    result: String,
) -> Element<'a, Message> {
    start_menu::start_menu(menu_model(
        state,
        pal(ctx),
        ctx.lang,
        apps,
        outcome,
        changed,
        result,
    ))
}

fn menu_model(
    state: &State,
    palette: theme::Palette,
    lang: Lang,
    apps: impl Iterator<Item = (u16, Fate)>,
    outcome: Outcome,
    changed: Instant,
    result: String,
) -> StartMenu {
    StartMenu {
        palette,
        plate: Plate::Surface,
        outcome,
        changed,
        now: state.now,
        apps: apps
            .map(|(i, fate)| MenuApp {
                glyph: start_menu::glyph_for(app_of(i).family),
                name: lang.t(app_of(i).name),
                fate,
            })
            .collect(),
        fillers: menu_fillers(state, lang),
        labels: menu_labels(lang, result),
    }
}

fn suggested_blocker(helper: Helper) -> &'static str {
    helper.blocker().unwrap_or(crate::gui::REOPEN_TO_DO_THIS)
}

fn kept_text(kept: &Kept) -> &'static str {
    match kept {
        Kept::NoSpace => {
            "Kept: not enough free space to save a copy. Free up some space and try again."
        }
        Kept::NoCopy(_) => "Kept: couldn't save a copy first. Restart your PC and try again.",
    }
}

fn names(ctx: &Ctx, indices: impl Iterator<Item = u16>) -> Vec<(u16, String)> {
    let mut v: Vec<u16> = indices.collect();
    v.sort_unstable();
    v.dedup();
    v.into_iter().map(|i| (i, ctx.t(app_of(i).name))).collect()
}

fn result_block<'a>(
    p: theme::Palette,
    state: &State,
    icon: Icon,
    tone: Tone,
    title: String,
    list: Vec<(u16, String)>,
) -> Element<'a, Message> {
    let head = row![
        widgets::icon(icon, 18.0, p.tone(tone)),
        widgets::body(p, title)
    ]
    .spacing(theme::S2)
    .align_y(Alignment::Center);
    if !list.iter().any(|(i, _)| state.icons.contains_key(i)) {
        let line = list.into_iter().map(|(_, n)| n).collect::<Vec<_>>();
        return column![head, widgets::muted(p, line.join(", "))]
            .spacing(theme::S1)
            .into();
    }
    let mut col = column![head].spacing(theme::S1);
    for (i, name) in list {
        col = col.push(
            row![app_glyph(p, state, i, 16.0), widgets::muted(p, name)]
                .spacing(theme::S2)
                .align_y(Alignment::Center),
        );
    }
    col.into()
}

struct Report<'a> {
    head: Element<'a, Message>,
    body: Vec<Element<'a, Message>>,
    technical: Vec<String>,
}

type MenuFn<'m, 'a> = &'m dyn Fn(Outcome, &str) -> Element<'a, Message>;

fn push_unique(lines: &mut Vec<String>, line: String) {
    if !lines.contains(&line) {
        lines.push(line);
    }
}

fn result_sheet<'a>(state: &'a State, done: &'a Finished, ctx: &'a Ctx) -> Element<'a, Message> {
    let p = pal(ctx);
    let fates = done
        .steps
        .iter()
        .map(|(i, step)| (*i, final_fate(*i, step, done)))
        .collect::<Vec<_>>();
    let menu = |outcome: Outcome, title: &str| {
        removal_menu(
            state,
            ctx,
            fates.iter().copied(),
            outcome,
            done.at,
            title.to_string(),
        )
    };
    let mut report = match &done.batch {
        Some(batch) => batch_report(state, done, batch, ctx, &menu),
        None => failure_report(done, ctx, &menu),
    };
    if done.asked_to_block {
        report.body.push(suggested_note(state, done, ctx));
    }
    if !report.technical.is_empty() {
        report.body.push(details(ctx, report.technical));
    }
    let mut sheet = column![report.head].spacing(theme::S3);
    if !report.body.is_empty() {
        sheet = sheet.push(result_scroll(p, report.body));
    }
    sheet
        .push(space::vertical().height(theme::S1))
        .push(row![
            space::horizontal(),
            widgets::action(
                p,
                ButtonKind::Primary,
                ctx.t("Done"),
                None,
                Some(wrap(Msg::CloseResult))
            )
        ])
        .into()
}

fn result_head<'a>(
    p: Palette,
    menu: MenuFn<'_, 'a>,
    outcome: Outcome,
    title: String,
) -> Element<'a, Message> {
    column![menu(outcome, &title), widgets::h2(p, title)]
        .spacing(theme::S3)
        .into()
}

fn result_scroll<'a>(p: Palette, body: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    container(
        scrollable(
            container(column(body).spacing(theme::S3))
                .padding(Padding::ZERO.right(theme::S3))
                .width(Length::Fill),
        )
        .direction(widgets::controls::scrollbar())
        .style(widgets::controls::scroll_style(p)),
    )
    .max_height(RESULT_BODY_MAX)
    .into()
}

fn batch_report<'a>(
    state: &'a State,
    done: &'a Finished,
    batch: &Batch,
    ctx: &'a Ctx,
    menu: MenuFn<'_, 'a>,
) -> Report<'a> {
    let p = pal(ctx);
    let removed = names(ctx, batch.removed.iter().map(|r| r.index));
    let protected = names(ctx, batch.skipped.iter().copied());
    let failed = names(ctx, batch.failed.iter().map(|f| f.index));
    let title = if batch.removed.is_empty()
        && failed.is_empty()
        && protected.is_empty()
        && done.kept.is_empty()
    {
        ctx.t("Nothing needed removing")
    } else if removed.is_empty() {
        ctx.t("No apps were removed")
    } else {
        count_text(ctx, removed.len(), "{n} app removed", "{n} apps removed")
    };
    let outcome = if failed.is_empty() && done.kept.is_empty() && !removed.is_empty() {
        Outcome::Removed
    } else if failed.is_empty() && done.kept.is_empty() {
        Outcome::Unchanged
    } else {
        Outcome::Partly
    };
    let head = result_head(p, menu, outcome, title);
    let mut body: Vec<Element<'a, Message>> = Vec::new();
    let mut block = |icon: Icon, tone: Tone, title: String, list: Vec<(u16, String)>| {
        if !list.is_empty() {
            body.push(result_block(p, state, icon, tone, title, list));
        }
    };
    block(Icon::CheckCircle, Tone::Good, ctx.t("Removed"), removed);
    block(
        Icon::Info,
        Tone::Neutral,
        ctx.t("Windows protects these apps"),
        protected,
    );
    for reason in [Kept::NoSpace, Kept::NoCopy(String::new())] {
        let list = names(
            ctx,
            done.kept
                .iter()
                .filter(|(_, k)| std::mem::discriminant(k) == std::mem::discriminant(&reason))
                .map(|(i, _)| *i),
        );
        block(Icon::Info, Tone::Neutral, ctx.t(kept_text(&reason)), list);
    }
    let any_failed = !failed.is_empty();
    block(
        Icon::AlertTriangle,
        Tone::Bad,
        ctx.t("Couldn't remove"),
        failed,
    );
    if any_failed {
        body.push(widgets::small(
            p,
            ctx.t("Restart your PC and try again. Nothing else was changed."),
        ));
    }
    let mut technical = Vec::new();
    for f in &batch.failed {
        push_unique(
            &mut technical,
            format!(
                "{}: {}",
                ctx.t(app_of(f.index).name),
                ctx.t(debloat::friendly::removal_failure(&f.reason))
            ),
        );
    }
    for (i, k) in &done.kept {
        if let Kept::NoCopy(reason) = k {
            push_unique(
                &mut technical,
                format!(
                    "{}: {}",
                    ctx.t(app_of(*i).name),
                    ctx.t(debloat::friendly::no_copy(reason))
                ),
            );
        }
    }
    Report {
        head,
        body,
        technical,
    }
}

fn failure_report<'a>(done: &'a Finished, ctx: &'a Ctx, menu: MenuFn<'_, 'a>) -> Report<'a> {
    let p = pal(ctx);
    let head = result_head(
        p,
        menu,
        Outcome::Failed,
        ctx.t("We couldn't remove the apps"),
    );
    let body = vec![widgets::muted(
        p,
        ctx.t("Nothing was changed. Please try again."),
    )];
    let technical = done
        .error
        .iter()
        .map(|e| ctx.t(debloat::friendly::removal_run_failure(e)))
        .collect();
    Report {
        head,
        body,
        technical,
    }
}

fn suggested_note<'a>(state: &State, done: &Finished, ctx: &Ctx) -> Element<'a, Message> {
    let p = pal(ctx);
    match (done.policy_ok, done.user_ok) {
        (_, None) => row![
            anim::spinner(16.0, p.text_muted, state.spin.elapsed_at(state.now)),
            widgets::muted(p, ctx.t("Asking Windows not to add suggested apps…"))
        ]
        .spacing(theme::S3)
        .align_y(Alignment::Center)
        .into(),
        (Some(true), Some(true)) => widgets::inline_notice(
            p,
            Tone::Good,
            ctx.t("Windows was asked not to add suggested apps again. This works best on Windows Enterprise and Education."),
        ),
        (Some(false), Some(false)) | (None, Some(false)) => widgets::inline_notice(
            p,
            Tone::Warn,
            ctx.t("We couldn't change the setting that stops suggested apps."),
        ),
        _ => widgets::inline_notice(
            p,
            Tone::Neutral,
            ctx.t("Windows was asked not to add suggested apps again, but this may not stop every suggestion."),
        ),
    }
}

fn details<'a>(ctx: &Ctx, lines: Vec<String>) -> Element<'a, Message> {
    let sheet =
        widgets::info::InfoSheet::new(ctx.t("What happened")).list(ctx.t("More details"), lines);
    widgets::info::link(ctx, ctx.t("More details"), Some(sheet))
        .unwrap_or_else(|| iced::widget::space().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secblitz::debloat::{Failure, Removed};
    use std::time::Duration;

    #[test]
    fn removal_days_count_calendar_days_not_hours() {
        let day = 86_400;
        let now = 1_791_500_000;
        let midnight = now - secblitz::clock::local_seconds(now) % day;
        assert_eq!(days_since(midnight + 100, midnight - 100), 1);
        assert_eq!(days_since(midnight + 40_000, midnight + 100), 0);
        assert_eq!(days_since(midnight + 100, midnight - 2 * day - 100), 3);
        assert_eq!(days_since(midnight, midnight + day), 0);
    }

    #[test]
    fn the_start_menu_follows_each_apps_real_step() {
        let t = Instant::now();
        let t2 = t + Duration::from_secs(2);
        assert_eq!(fate_of(&Step::Waiting), Fate::Waiting);
        assert_eq!(fate_of(&Step::Saving), Fate::Saving);
        assert_eq!(fate_of(&Step::Working), Fate::Busy);
        assert_eq!(
            fate_of(&Step::Done(ItemResult::Removed, t)),
            Fate::Removed(t)
        );
        assert_eq!(
            fate_of(&Step::Done(ItemResult::Failed("x".into()), t)),
            Fate::Refused(t)
        );
        assert_eq!(
            fate_of(&Step::Done(ItemResult::Protected, t)),
            Fate::Stays(t)
        );
        assert_eq!(
            fate_of(&Step::Done(ItemResult::Kept(Kept::NoSpace), t)),
            Fate::Kept(t)
        );
        let done = Finished {
            batch: Some(Batch {
                removed: vec![Removed {
                    index: 1,
                    package: "p".into(),
                    version: "1".into(),
                    restored: false,
                }],
                failed: vec![Failure {
                    index: 2,
                    reason: "r".into(),
                }],
                skipped: vec![3],
                ..Batch::default()
            }),
            at: t2,
            ..Finished::default()
        };
        assert_eq!(
            final_fate(1, &Step::Done(ItemResult::Removed, t), &done),
            Fate::Removed(t)
        );
        assert_eq!(final_fate(1, &Step::Working, &done), Fate::Removed(t2));
        assert_eq!(final_fate(2, &Step::Waiting, &done), Fate::Refused(t2));
        assert_eq!(final_fate(3, &Step::Waiting, &done), Fate::Stays(t2));
        assert_eq!(final_fate(4, &Step::Waiting, &done), Fate::Absent(t2));
        let failed = Finished {
            at: t2,
            ..Finished::default()
        };
        assert_eq!(final_fate(1, &Step::Working, &failed), Fate::Refused(t2));
        let steps = [
            (1, Step::Done(ItemResult::Removed, t)),
            (2, Step::Working),
            (4, Step::Waiting),
        ];
        let fates = steps.iter().map(|(i, s)| (*i, final_fate(*i, s, &done)));
        let state = State::default();
        let m = menu_model(
            &state,
            theme::LIGHT,
            Lang::En,
            fates,
            Outcome::Partly,
            t2,
            "x".into(),
        );
        let sc = m.scene(t2 + Duration::from_millis(300));
        assert_eq!(m.label(start_menu::Part::Tile(6), &sc), app_of(4).name);
        assert_eq!(
            m.label(start_menu::Part::Tile(5), &sc),
            format!("Couldn't remove {}", app_of(2).name)
        );
        let sc = m.scene(t2 + Duration::from_secs(2));
        use start_menu::Place::{Gone, Slot};
        assert_eq!(sc.hidden, 0);
        assert_eq!(
            sc.places,
            vec![
                Slot(0),
                Gone,
                Slot(1),
                Slot(2),
                Slot(3),
                Slot(4),
                Gone,
                Slot(5)
            ]
        );
    }

    #[test]
    fn start_menu_labels_and_fillers_are_translated() {
        let l = menu_labels(Lang::Fr, "x".into());
        assert_eq!(l.removing, "Suppression de {name}");
        assert_eq!(l.more_many, "{n} applications de plus");
        assert_eq!(l.refused, "Impossible de supprimer {name}");
        let state = State {
            menu_fillers: vec![debloat::catalog::owner("Microsoft.BingWeather").unwrap()],
            ..State::default()
        };
        let fillers = menu_fillers(&state, Lang::De);
        assert_eq!(fillers[0].name, "Einstellungen");
        assert_eq!(fillers[1].name, "Datei-Explorer");
        assert_eq!(fillers.last().unwrap().name, Lang::De.t("Weather"));
        assert_eq!(fillers.len(), 6);
    }

    fn debug(m: &Option<Msg>) -> Option<String> {
        m.as_ref().map(|m| format!("{m:?}"))
    }

    #[test]
    fn saved_copy_rows_offer_restore_and_delete() {
        let index = debloat::catalog::owner("Microsoft.BingWeather").unwrap();
        let mut state = State::default();
        state.copies.insert(index);
        let actions = row_actions(&state, Helper::Ready, index, true);
        assert_eq!(
            debug(&actions.primary),
            Some(format!("{:?}", Msg::Restore(index)))
        );
        let menu: Vec<String> = actions.menu.iter().map(|m| format!("{:?}", m.2)).collect();
        assert!(menu.iter().any(|m| m.contains("AskDelete")));
        assert!(menu.iter().any(|m| m.contains("RestoreStore")));
        state.copies.clear();
        let actions = row_actions(&state, Helper::Ready, index, true);
        assert!(!actions
            .menu
            .iter()
            .any(|m| format!("{:?}", m.2).contains("AskDelete")));
        assert_eq!(
            debug(&actions.primary),
            Some(format!("{:?}", Msg::Restore(index)))
        );
    }

    #[test]
    fn app_glyph_falls_back_and_uses_a_known_icon() {
        let index = debloat::catalog::owner("Microsoft.BingWeather").unwrap();
        let mut state = State::default();
        // No icon known: builds the generic glyph (and does not panic).
        let _ = app_glyph(theme::LIGHT, &state, index, theme::ICON_ROW);
        assert!(!state.icons.contains_key(&index));
        state
            .icons
            .insert(index, Handle::from_rgba(1, 1, vec![1, 2, 3, 255]));
        let _ = app_glyph(theme::LIGHT, &state, index, theme::ICON_ROW);
    }

    #[test]
    fn store_restore_is_not_offered_without_the_helper() {
        let index = debloat::catalog::owner("Microsoft.BingWeather").unwrap();
        let mut state = State::default();
        let actions = row_actions(&state, Helper::Reopen, index, true);
        assert!(actions.primary.is_none());
        state.copies.insert(index);
        let actions = row_actions(&state, Helper::NotOnThisAccount, index, true);
        assert_eq!(
            debug(&actions.primary),
            Some(format!("{:?}", Msg::Restore(index)))
        );
        assert!(!actions
            .menu
            .iter()
            .any(|m| format!("{:?}", m.2).contains("RestoreStore")));
        assert!(super::store_blocker(Helper::Ready).is_none());
        assert_eq!(
            super::store_blocker(Helper::Reopen),
            Some(crate::gui::REOPEN_TO_DO_THIS)
        );
    }

    #[test]
    fn rows_offer_nothing_while_busy() {
        let index = debloat::catalog::owner("Microsoft.BingWeather").unwrap();
        let mut state = State::default();
        state.copies.insert(index);
        let actions = row_actions(&state, Helper::Ready, index, false);
        assert!(actions.primary.is_none() && actions.menu.is_empty());
    }
}
