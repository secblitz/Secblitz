//! History: score trend, compact Undo / removed-apps rows and a timeline of
//! checks, fixes, undos and app clean-ups grouped by day.
use crate::app::history::{self as log, Day, DayScore, Entry, Kind};
use crate::app::worker::{self, Job};
use crate::gui::icons::Icon;
use crate::gui::theme::{self, Palette, Tone};
use crate::gui::widgets::progress;
use crate::gui::widgets::{self};
use crate::gui::{blocking, Ctx, Message, Page};
use crate::i18n::Lang;
use iced::widget::canvas::Cache;
use iced::widget::{column, row, space};
use iced::{Alignment, Element, Task};
use secblitz::debloat;
use std::collections::HashSet;

const TREND_POINTS: usize = 30;
const DAYS_PAGE: usize = 10;
const CHART_HEIGHT: f32 = 160.0;

#[derive(Debug)]
pub struct State {
    visited: bool,
    data: Option<Data>,
    engine: Option<Result<Vec<String>, String>>,
    days_shown: usize,
    flipped: HashSet<u64>,
    chart: Cache,
}

impl Default for State {
    fn default() -> Self {
        Self {
            visited: false,
            data: None,
            engine: None,
            days_shown: DAYS_PAGE,
            flipped: HashSet::new(),
            chart: Cache::new(),
        }
    }
}

#[derive(Debug)]
struct Data {
    scores: Vec<DayScore>,
    points: Vec<(u64, f32)>,
    latest: Option<(usize, usize)>,
    removed: usize,
    days: Vec<Day>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Progress {
    Nothing,
    StartingPoint(DayScore),
    Line,
}

fn progress(scores: &[DayScore]) -> Progress {
    match scores {
        [] => Progress::Nothing,
        [only] => Progress::StartingPoint(*only),
        _ => Progress::Line,
    }
}

impl Data {
    fn of(entries: &[Entry], removed: usize) -> Self {
        let scores = log::daily_scores(entries, TREND_POINTS);
        Self {
            points: scores.iter().map(|s| (s.day, s.ratio())).collect(),
            scores,
            latest: entries
                .iter()
                .rev()
                .find(|e| e.total > 0)
                .map(|e| (e.protected, e.total)),
            removed,
            days: log::timeline(entries),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    Loaded(Vec<Entry>, usize),
    ShowMore,
    ToggleDay(u64),
}

fn refresh(ctx: &Ctx) -> Task<Message> {
    let load = match ctx.state_dir.clone() {
        Some(dir) => Task::perform(
            blocking(move || {
                crate::gui::wait_persisted();
                let removed = debloat::journal::still_removed(
                    &debloat::journal::load_from(&dir.join(debloat::journal::FILE)),
                    debloat::catalog().len(),
                );
                (log::load(&dir), removed.len())
            }),
            |(e, removed)| Message::History(Msg::Loaded(e, removed)),
        ),
        None => Task::done(Message::History(Msg::Loaded(Vec::new(), 0))),
    };
    let engine = Task::run(ctx.worker.run(Job::History), Message::Worker);
    Task::batch([load, engine])
}

pub fn on_enter(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    state.visited = true;
    state.days_shown = DAYS_PAGE;
    refresh(ctx)
}

pub fn on_worker(state: &mut State, event: &worker::Event, ctx: &mut Ctx) -> Task<Message> {
    use worker::Event as E;
    match event {
        E::History(result) => {
            state.engine = Some(result.clone());
            Task::none()
        }
        E::Checked(_) | E::Applied { .. } | E::Undone { .. } | E::Recovered(Ok(_))
            if state.visited =>
        {
            refresh(ctx)
        }
        _ => Task::none(),
    }
}

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    let _ = ctx;
    match msg {
        Msg::Loaded(entries, removed) => {
            state.data = Some(Data::of(&entries, removed));
            state.chart.clear();
        }
        Msg::ShowMore => state.days_shown += DAYS_PAGE,
        Msg::ToggleDay(day) => {
            if !state.flipped.remove(&day) {
                state.flipped.insert(day);
            }
        }
    }
    Task::none()
}

fn can_undo(state: &State) -> bool {
    matches!(&state.engine, Some(Ok(lines)) if lines.iter().any(|l| l.ends_with(" applied")))
}

fn kind_icon(kind: Kind) -> (Icon, Tone) {
    match kind {
        Kind::Check => (Icon::Scan, Tone::Neutral),
        Kind::Fix => (Icon::Wrench, Tone::Good),
        Kind::Undo | Kind::UndoSome => (Icon::Undo, Tone::Warn),
        Kind::Debloat => (Icon::Package, Tone::Neutral),
        Kind::Restore => (Icon::Refresh, Tone::Good),
        Kind::Recovery => (Icon::Refresh, Tone::Neutral),
        Kind::FreedSpace => (Icon::Trash, Tone::Good),
        Kind::SecureBootRenewal => (Icon::ShieldCheck, Tone::Neutral),
    }
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn full_date(ctx: &Ctx, day: u64) -> String {
    let (y, m, d) = log::civil(day);
    format!("{} {} {}", d, ctx.t(MONTHS[(m as usize - 1) % 12]), y)
}

pub(super) fn day_title(ctx: &Ctx, day: u64, today: u64) -> String {
    if day == today {
        return ctx.t("Today");
    }
    if day + 1 == today {
        return ctx.t("Yesterday");
    }
    full_date(ctx, day)
}

fn short_date(lang: Lang, day: u64) -> String {
    let (_, m, d) = log::civil(day);
    format!("{} {}", d, lang.t(MONTHS[(m as usize - 1) % 12]))
}

fn date_fn(lang: Lang) -> &'static dyn Fn(u64) -> String {
    match lang {
        Lang::En => &|day| short_date(Lang::En, day),
        Lang::Es => &|day| short_date(Lang::Es, day),
        Lang::Fr => &|day| short_date(Lang::Fr, day),
        Lang::De => &|day| short_date(Lang::De, day),
        Lang::Pt => &|day| short_date(Lang::Pt, day),
        Lang::It => &|day| short_date(Lang::It, day),
    }
}

fn removed_text(ctx: &Ctx, removed: usize) -> String {
    match removed {
        0 => ctx.t("No apps are removed right now."),
        1 => ctx.t("1 app is removed."),
        n => ctx
            .t("{n} apps are removed.")
            .replace("{n}", &n.to_string()),
    }
}

fn nothing<'a>() -> Element<'a, Message> {
    space::horizontal().width(0.0).into()
}

fn items_text(ctx: &Ctx, n: usize) -> String {
    if n == 1 {
        ctx.t("1 item")
    } else {
        ctx.t("{n} items").replace("{n}", &n.to_string())
    }
}

fn day_section<'a>(state: &State, ctx: &Ctx, day: &Day, today: u64) -> Element<'a, Message> {
    let p = ctx.palette;
    let open = (day.day == today) != state.flipped.contains(&day.day);
    let mut rows = column![].spacing(theme::S1);
    if open {
        for item in &day.items {
            let (icon, tone) = kind_icon(item.kind);
            let label = ctx
                .t(log::label(item.kind, item.n))
                .replace("{n}", &item.n.to_string())
                .replace(
                    "{size}",
                    &secblitz::space::size_phrase((item.n as u64).saturating_mul(1 << 20)),
                );
            let mut detail = Vec::new();
            if item.total > 0 {
                detail.push(
                    ctx.t("{a} of {b} protected")
                        .replace("{a}", &item.protected.to_string())
                        .replace("{b}", &item.total.to_string()),
                );
            }
            if item.repeats > 1 {
                detail.push(
                    ctx.t("{n} checks")
                        .replace("{n}", &item.repeats.to_string()),
                );
            }
            let line = (!detail.is_empty()).then(|| detail.join(" · "));
            rows = rows.push(widgets::row_item_tinted(
                p,
                Some(icon),
                Some(tone),
                label,
                line,
                nothing(),
                None,
            ));
        }
    }
    widgets::collapsible(
        p,
        day_title(ctx, day.day, today),
        Some(items_text(ctx, day.items.len())),
        open,
        Message::History(Msg::ToggleDay(day.day)),
        rows,
    )
}

fn timeline<'a>(state: &State, ctx: &Ctx, days: &[Day]) -> Element<'a, Message> {
    let p = ctx.palette;
    let today = log::local_day(log::now());
    let shown = widgets::limited(days, state.days_shown, false);
    let mut rows: Vec<Element<'a, Message>> = shown
        .iter()
        .map(|d| day_section(state, ctx, d, today))
        .collect();
    if days.len() > shown.len() {
        rows.push(widgets::show_more_button(
            p,
            ctx.t("See {n} more")
                .replace("{n}", &(days.len() - shown.len()).to_string()),
            Message::History(Msg::ShowMore),
        ));
    }
    widgets::group(p, ctx.t("What happened"), None, None, rows)
}

fn starting_point<'a>(ctx: &Ctx, score: DayScore) -> Element<'a, Message> {
    let p = ctx.palette;
    let all = score.protected >= score.total;
    let big = iced::widget::text(format!("{}%", (score.ratio() * 100.0).round() as i32))
        .size(theme::DISPLAY)
        .font(theme::SEMIBOLD)
        .color(if all { p.good_text } else { p.text });
    column![
        big,
        widgets::body(
            p,
            ctx.t("{a} of {b} protected on {date}")
                .replace("{a}", &score.protected.to_string())
                .replace("{b}", &score.total.to_string())
                .replace("{date}", &full_date(ctx, score.day)),
        ),
        widgets::muted(
            p,
            ctx.t("Your progress line appears after you check on another day."),
        ),
    ]
    .spacing(theme::S1)
    .into()
}

pub fn view<'a>(state: &'a State, ctx: &'a Ctx) -> Element<'a, Message> {
    let p = ctx.palette;
    let header = widgets::page_header(
        p,
        ctx.t("History"),
        Some(ctx.t("What you checked, fixed and undid.")),
    );
    let spacer = space::vertical().height(theme::S6);

    let Some(data) = &state.data else {
        return column![
            header,
            spacer,
            widgets::region(
                p,
                column![
                    widgets::h2(p, ctx.t("Loading your history")),
                    widgets::muted(p, ctx.t("This only takes a moment.")),
                    space::vertical().height(theme::S2),
                    progress::indeterminate(p, Tone::Neutral),
                ]
                .spacing(theme::S1),
            )
        ]
        .into();
    };

    let solid = Palette::of(p.mode);
    let shown = progress(&data.scores);
    let trend_body: Element<'a, Message> = match shown {
        Progress::Nothing => widgets::muted(p, ctx.t("Check a few times to see your progress.")),
        Progress::StartingPoint(score) => starting_point(ctx, score),
        Progress::Line => widgets::chart::trend(
            solid,
            Tone::Good,
            &data.points,
            &state.chart,
            date_fn(ctx.lang),
            CHART_HEIGHT,
        ),
    };
    let summary = match (shown, data.latest) {
        (Progress::Line, Some((a, b))) => ctx
            .t("{a} of {b} protected")
            .replace("{a}", &a.to_string())
            .replace("{b}", &b.to_string()),
        _ => String::new(),
    };
    let trend = widgets::region(
        p,
        column![
            row![
                widgets::h2(p, ctx.t("Your protection over time")),
                space::horizontal(),
                widgets::muted(p, summary),
            ]
            .align_y(Alignment::Center),
            trend_body,
        ]
        .spacing(theme::S3),
    );

    let (undo_body, undo_enabled) = match &state.engine {
        None => (ctx.t("Checking what can be undone…"), false),
        Some(Err(_)) if ctx.damage.is_some() => (
            ctx.t("Undo isn't available until the damaged undo history is sorted out."),
            false,
        ),
        Some(Err(_)) => (
            ctx.t("We couldn't read your list of fixes. Close Secblitz and open it again."),
            false,
        ),
        Some(Ok(_)) if can_undo(state) => (ctx.t("Go back to how things were before."), true),
        Some(Ok(_)) => (ctx.t("There's nothing to undo yet."), false),
    };
    let undo_trailing: Element<'a, Message> = if undo_enabled && !ctx.busy {
        widgets::overflow_menu(
            p,
            vec![(Icon::Undo, ctx.t("Undo…"), Message::ReviewUndo, true)],
        )
    } else {
        nothing()
    };
    let undo = widgets::row_item(
        p,
        Some(Icon::Undo),
        ctx.t("Undo your last fixes"),
        Some(undo_body),
        undo_trailing,
        None,
    );

    let choose_trailing: Element<'a, Message> = if undo_enabled && !ctx.busy {
        widgets::overflow_menu(
            p,
            vec![(Icon::Undo, ctx.t("Choose…"), Message::PutBackChosen, true)],
        )
    } else {
        nothing()
    };
    let choose = widgets::row_item(
        p,
        Some(Icon::Undo),
        ctx.t("Put back chosen settings"),
        Some(ctx.t("Pick which settings to put back.")),
        choose_trailing,
        None,
    );

    let removed = widgets::row_item(
        p,
        Some(Icon::Package),
        ctx.t("Removed apps"),
        Some(removed_text(ctx, data.removed)),
        widgets::overflow_menu(
            p,
            vec![(
                Icon::Package,
                ctx.t("Manage apps"),
                Message::Navigate(Page::Debloat),
                false,
            )],
        ),
        None,
    );
    let quick = column![undo, choose, removed].spacing(theme::S1);

    let mut page = column![].spacing(theme::S8);
    if let Some(info) = &ctx.damage {
        page = page.push(super::recovery::card(ctx, info));
    }
    page = page.push(trend).push(quick);
    if data.days.is_empty() {
        page = page.push(widgets::empty_state(
            p,
            Icon::History,
            ctx.t("Nothing here yet"),
            ctx.t("When you check your computer or fix something, it will show up here."),
            None,
        ));
    } else {
        page = page.push(timeline(state, ctx, &data.days));
    }
    column![header, spacer, page].into()
}

pub fn preload(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    state.visited = true;
    refresh(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn undo_needs_an_applied_batch() {
        let mut s = State::default();
        assert!(!can_undo(&s));
        s.engine = Some(Ok(vec!["b reverted".into(), "a pending".into()]));
        assert!(!can_undo(&s));
        s.engine = Some(Ok(vec!["c applied".into(), "b reverted".into()]));
        assert!(can_undo(&s));
        s.engine = Some(Err("x".into()));
        assert!(!can_undo(&s));
    }

    fn e(t: u64, kind: Kind, protected: usize, total: usize, n: usize) -> Entry {
        Entry {
            t,
            kind,
            protected,
            total,
            n,
        }
    }

    const DAY: u64 = 86_400;

    #[test]
    fn data_is_derived_once_from_the_log() {
        let d = Data::of(
            &[
                e(1, Kind::Check, 3, 5, 0),
                e(2, Kind::Debloat, 0, 0, 2),
                e(3, Kind::Debloat, 0, 0, 1),
                e(4, Kind::Check, 4, 5, 0),
            ],
            1,
        );
        assert_eq!(d.removed, 1);
        assert_eq!(d.latest, Some((4, 5)));
        assert_eq!(d.points.len(), 1, "four checks on one day are one point");
        assert_eq!(d.scores[0].protected, 4);
    }

    #[test]
    fn the_chart_card_follows_how_many_days_have_a_result() {
        let none = Data::of(&[e(1, Kind::Debloat, 0, 0, 2)], 0);
        assert_eq!(progress(&none.scores), Progress::Nothing);

        let one_day = Data::of(
            &[
                e(10, Kind::Check, 3, 5, 0),
                e(20, Kind::Check, 5, 5, 0),
                e(30, Kind::Check, 5, 5, 0),
            ],
            0,
        );
        assert!(matches!(
            progress(&one_day.scores),
            Progress::StartingPoint(s) if s.protected == 5
        ));

        let two_days = Data::of(
            &[
                e(10, Kind::Check, 3, 5, 0),
                e(50 * DAY, Kind::Check, 5, 5, 0),
            ],
            0,
        );
        assert_eq!(progress(&two_days.scores), Progress::Line);
        assert_eq!(two_days.points.len(), 2);
    }

    #[test]
    fn chart_points_hold_the_day_and_a_share() {
        let d = Data::of(
            &[
                e(DAY * 3, Kind::Check, 4, 4, 0),
                e(DAY * 9, Kind::Check, 1, 4, 0),
            ],
            0,
        );
        assert_eq!(d.points[0].1, 1.0);
        assert_eq!(d.points[1].1, 0.25);
        assert!(d.points[0].0 < d.points[1].0);
    }
}
