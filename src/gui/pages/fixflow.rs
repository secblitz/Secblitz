//! Fix / undo flow drawn over any page: review sheet → working → result.
use super::fixes::row_text;
use crate::app::flow::{self, Summary, SummaryKind};
use crate::app::worker::{self, Job, Phase};
use crate::gui::icons::Icon;
use crate::gui::theme::{self, Palette, Tone};
use crate::gui::widgets::anim::{self, Clock, Tween};
use crate::gui::widgets::controls::{fade_below, more_below, scroll_style, scrollbar};
use crate::gui::widgets::hairline::{self, rewind, shield_fill, Plate, Run};
use crate::gui::widgets::handoff;
use crate::gui::widgets::info::InfoSheet;
use crate::gui::widgets::point::{self, Opened, Words};
use crate::gui::widgets::{self, progress, ButtonKind, CheckState};
use crate::gui::{Ctx, Message};
use iced::widget::{column, container, row, scrollable, space};
use iced::{Alignment, Background, Border, Element, Length, Subscription, Task};
use secblitz::engine::ItemChoice;
use secblitz::model::CheckStatus;
use std::collections::BTreeSet;
use std::time::Instant;

const ADDONS: &str = "browser.extensions_off";
const LIST_MAX_HEIGHT: f32 = 300.0;
const MARK: f32 = theme::ICON_ROW;
const WAIT_DOT: f32 = 6.0;
const STEP_LIST: &str = "fix-steps";
const STEP_LIST_WIDTH: f32 = 400.0;

#[derive(Debug)]
pub struct State {
    stage: Stage,
    now: Instant,
    frames_seen: bool,
    work: Clock,
    bar: Option<Tween>,
    since: Instant,
    plan: Vec<PlanRow>,
    /// Browser add-ons the person can pick from, and the ones picked. Nothing starts picked.
    addons: Vec<Addon>,
    addons_picked: BTreeSet<String>,
    /// Putting back chosen settings, not the last fixes.
    chosen: bool,
    /// A protection was added to the list because another one needs it.
    together: bool,
    checking: bool,
    held: Option<Held>,
    steps_view: Option<scrollable::Viewport>,
    follow: Option<Follow>,
    /// The person scrolled the step list themselves, so it stops following.
    steps_held: bool,
    result_view: Option<scrollable::Viewport>,
    points: Opened,
}

/// The step list gliding to keep the running step in its middle.
#[derive(Debug)]
struct Follow {
    glide: Tween,
    shown: f32,
    /// Where the list was before the last step of the glide.
    before: f32,
}

impl Follow {
    fn at(now: Instant, from: f32, to: f32) -> Self {
        Self {
            glide: Tween::starting(now, from, to, anim::SLOW),
            shown: from,
            before: from,
        }
    }

    /// Whether the list being at `y` could be this glide's doing. Offsets are
    /// reported a few frames late, so anywhere on its path counts.
    fn put_it_at(&self, y: f32) -> bool {
        let ends = [self.glide.from, self.glide.to, self.before];
        let lo = ends.iter().fold(self.shown, |a, b| a.min(*b));
        let hi = ends.iter().fold(self.shown, |a, b| a.max(*b));
        (lo - 2.0..=hi + 2.0).contains(&y)
    }
}

impl Default for State {
    fn default() -> Self {
        Self {
            stage: Stage::Closed,
            now: Instant::now(),
            frames_seen: false,
            work: Clock::new(),
            bar: None,
            since: Instant::now(),
            plan: Vec::new(),
            addons: Vec::new(),
            addons_picked: BTreeSet::new(),
            chosen: false,
            together: false,
            checking: false,
            held: None,
            steps_view: None,
            follow: None,
            steps_held: false,
            result_view: None,
            points: Opened::default(),
        }
    }
}

/// A finished result kept back for a moment so the progress can settle.
#[derive(Debug)]
struct Held {
    at: Instant,
    undo: bool,
    summary: Summary,
    technical: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Addon {
    key: String,
    name: String,
    browser: &'static str,
    why: Vec<&'static str>,
}

impl Addon {
    fn of(item: &secblitz::model::ItemLabel) -> Option<Self> {
        let browser = if item.key.starts_with("chromium:chrome:") {
            "Chrome"
        } else if item.key.starts_with("chromium:edge:") {
            "Edge"
        } else {
            return None;
        };
        let why = item
            .why
            .split(',')
            .filter_map(|w| match w {
                "sites" => Some("Can read every site you visit"),
                "programs" => Some("Can talk to other programs on your computer"),
                _ => None,
            })
            .collect();
        Some(Self {
            key: item.key.clone(),
            name: item.name.clone(),
            browser,
            why,
        })
    }
}

#[derive(Debug, Clone, Default)]
struct PlanRow {
    id: String,
    name: String,
    line: Option<String>,
    restart: bool,
    managed: bool,
    undoable: bool,
}

#[derive(Debug, Clone)]
struct Done {
    id: String,
    name: String,
    status: String,
    at: Instant,
}

#[derive(Debug, Default)]
enum Stage {
    #[default]
    Closed,
    Review {
        ids: Vec<String>,
        undo: bool,
    },
    Blocked {
        ids: Vec<String>,
        undo: bool,
        reason: String,
        retry: bool,
    },
    Working {
        undo: bool,
        phase: Option<Phase>,
        items: Vec<Done>,
    },
    Result {
        undo: bool,
        summary: Summary,
        technical: Vec<String>,
    },
}

#[derive(Debug, Clone)]
pub enum Msg {
    PickAddon(String),
    Point(String),
    Confirm,
    Cancel,
    Done,
    CheckAgain,
    Retry,
    Frame(Instant),
    Steps(scrollable::Viewport),
    ResultList(scrollable::Viewport),
}

impl State {
    pub fn is_open(&self) -> bool {
        !matches!(self.stage, Stage::Closed)
    }

    fn progress(&self, start: Instant) -> f32 {
        if self.frames_seen {
            Clock::at(start).progress_at(anim::SLOW, self.now)
        } else {
            1.0
        }
    }

    fn live(&self) -> bool {
        matches!(self.stage, Stage::Working { .. })
    }
}

pub fn subscription(state: &State) -> Subscription<Message> {
    if state.live() && anim::animating() {
        iced::window::frames().map(|at| Message::Fix(Msg::Frame(at)))
    } else {
        Subscription::none()
    }
}

fn notices_of(id: &str) -> secblitz::hardening::Notices {
    secblitz::hardening::spec(id).map_or(
        secblitz::hardening::Notices {
            managed: false,
            restart: false,
            undoable: true,
        },
        secblitz::hardening::notices,
    )
}

fn plan_row(ctx: &Ctx, id: &str, with_impact: bool) -> PlanRow {
    let notices = notices_of(id);
    let impact = secblitz::advice::control_impact(id);
    let items = ctx
        .report
        .as_deref()
        .and_then(|r| r.results.iter().find(|o| o.id == id))
        .and_then(|o| super::fixes::items_line(ctx, o));
    let impact_line =
        (!impact.is_empty()).then(|| format!("{} {}", ctx.t("Protects you from:"), ctx.t(impact)));
    let consequence = secblitz::advice::is_choice_check_id(id)
        .then(|| secblitz::advice::choice_consequence(id))
        .filter(|c| !c.is_empty())
        .map(|c| ctx.t(c));
    let lines: Vec<String> = [impact_line, consequence, items]
        .into_iter()
        .flatten()
        .collect();
    PlanRow {
        id: id.to_owned(),
        name: ctx.lang.control(id),
        line: (with_impact && !lines.is_empty()).then(|| lines.join("\n")),
        restart: ctx.catalog.restart.iter().any(|x| x == id) || notices.restart,
        managed: with_impact && notices.managed,
        undoable: !with_impact || notices.undoable,
    }
}

pub fn open_fixes(state: &mut State, ids: Vec<String>, ctx: &mut Ctx) -> Task<Message> {
    if ctx.busy || state.is_open() || ctx.check_error.is_some() || ctx.checking.is_some() {
        return Task::none();
    }
    // Only fixes the latest check still offers; stale selections are dropped.
    let Some(report) = ctx.report.as_deref() else {
        return Task::none();
    };
    if flow::repairs_blocked(report).is_some() {
        return Task::none();
    }
    let allowed = flow::candidates(report, &ctx.catalog.available);
    let mut chosen: Vec<String> = Vec::new();
    for id in ids {
        if allowed.contains(&id) && !chosen.contains(&id) {
            chosen.push(id);
        }
    }
    if chosen.is_empty() {
        return Task::none();
    }
    ctx.info = None;
    state.points.clear();
    state.chosen = false;
    state.together = false;
    state.addons = chosen
        .iter()
        .find(|id| id.as_str() == ADDONS)
        .and_then(|id| report.results.iter().find(|o| o.id == *id))
        .map(|o| o.items.iter().filter_map(Addon::of).collect())
        .unwrap_or_default();
    state.addons_picked.clear();
    chosen.retain(|id| id != ADDONS || !state.addons.is_empty());
    if chosen.is_empty() {
        return Task::none();
    }
    state.plan = chosen.iter().map(|id| plan_row(ctx, id, true)).collect();
    state.stage = Stage::Review {
        ids: chosen,
        undo: false,
    };
    Task::none()
}

fn undo_row(ctx: &Ctx, id: &str) -> PlanRow {
    let impact = secblitz::advice::control_impact(id);
    PlanRow {
        id: id.to_owned(),
        name: ctx.lang.control(id),
        line: (!impact.is_empty()).then(|| {
            format!(
                "{} {}",
                ctx.t("You'll be less protected from:"),
                ctx.t(impact)
            )
        }),
        restart: ctx.catalog.restart.iter().any(|x| x == id),
        managed: false,
        undoable: true,
    }
}

/// Only settings the last check says Secblitz changed can be put back; anything else is dropped.
pub fn open_undo_some(state: &mut State, ids: Vec<String>, ctx: &mut Ctx) -> Task<Message> {
    if ctx.busy || state.is_open() || ctx.check_error.is_some() || ctx.checking.is_some() {
        return Task::none();
    }
    let Some(report) = ctx.report.as_deref() else {
        return Task::none();
    };
    let undoable: Vec<String> = report
        .results
        .iter()
        .filter(|r| r.undoable)
        .map(|r| r.id.clone())
        .collect();
    let mut chosen: Vec<String> = Vec::new();
    for id in ids {
        if undoable.contains(&id) && !chosen.contains(&id) {
            chosen.push(id);
        }
    }
    if chosen.is_empty() {
        return Task::none();
    }
    let (chosen, together) = flow::with_dependents(chosen, &undoable);
    ctx.info = None;
    state.points.clear();
    state.chosen = true;
    state.together = together;
    state.plan = chosen.iter().map(|id| undo_row(ctx, id)).collect();
    state.stage = Stage::Review {
        ids: chosen,
        undo: true,
    };
    Task::none()
}

pub fn open_undo(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    if ctx.busy || state.is_open() {
        return Task::none();
    }
    ctx.info = None;
    state.points.clear();
    state.chosen = false;
    state.together = false;
    state.plan = ctx
        .report
        .as_deref()
        .map(|r| {
            r.undo_next
                .iter()
                .map(|id| plan_row(ctx, id, false))
                .collect()
        })
        .unwrap_or_default();
    state.stage = Stage::Review {
        ids: Vec::new(),
        undo: true,
    };
    Task::none()
}

pub fn escape(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    let _ = ctx;
    if matches!(
        state.stage,
        Stage::Review { .. } | Stage::Blocked { .. } | Stage::Result { .. }
    ) {
        close(state);
    }
    Task::none()
}

fn close(state: &mut State) {
    state.points.clear();
    state.addons.clear();
    state.addons_picked.clear();
    state.held = None;
    state.stage = Stage::Closed;
    state.bar = None;
    state.checking = false;
}

fn planned(state: &State) -> usize {
    state.plan.len()
}

fn bar_target(planned: usize, finished: usize, verifying: bool) -> f32 {
    let total = planned + 1;
    let done = if verifying {
        planned
    } else {
        finished.min(planned)
    };
    done as f32 / total as f32
}

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    match msg {
        Msg::Point(key) => {
            if matches!(state.stage, Stage::Review { .. } | Stage::Result { .. }) {
                state.points.toggle(&key);
            }
            Task::none()
        }
        Msg::PickAddon(key) => {
            if matches!(state.stage, Stage::Review { undo: false, .. })
                && state.addons.iter().any(|a| a.key == key)
                && !state.addons_picked.remove(&key)
            {
                state.addons_picked.insert(key);
            }
            Task::none()
        }
        Msg::Frame(at) => {
            state.now = at;
            state.frames_seen = true;
            if state
                .held
                .as_ref()
                .is_some_and(|h| at.saturating_duration_since(h.at) >= handoff::sheet_hold())
            {
                if let Some(h) = state.held.take() {
                    show_result(state, h.undo, h.summary, h.technical);
                }
            }
            glide(state, at)
        }
        Msg::ResultList(view) => {
            state.result_view = Some(view);
            Task::none()
        }
        Msg::Steps(view) => {
            // A new row is measured only after the event that added it, so a
            // change in size is the moment to follow again.
            let resized = state.steps_view.is_none_or(|v| {
                v.bounds().height != view.bounds().height
                    || v.content_bounds().height != view.content_bounds().height
            });
            let y = view.absolute_offset().y;
            if !resized && !state.follow.as_ref().is_some_and(|f| f.put_it_at(y)) {
                state.steps_held = true;
                state.follow = None;
            }
            state.steps_view = Some(view);
            if resized {
                follow(state, Instant::now())
            } else {
                Task::none()
            }
        }
        Msg::Cancel | Msg::Done => {
            if matches!(
                state.stage,
                Stage::Review { .. } | Stage::Blocked { .. } | Stage::Result { .. }
            ) {
                close(state);
            }
            Task::none()
        }
        Msg::CheckAgain => {
            if matches!(state.stage, Stage::Result { .. }) {
                close(state);
                return Task::done(Message::CheckNow);
            }
            Task::none()
        }
        Msg::Retry => {
            if let Stage::Blocked { ids, undo, .. } = std::mem::take(&mut state.stage) {
                state.stage = Stage::Review { ids, undo };
                return update(state, Msg::Confirm, ctx);
            }
            Task::none()
        }
        Msg::Confirm => {
            let Stage::Review { ids, undo } = &state.stage else {
                return Task::none();
            };
            if ctx.busy || state.checking || (!*undo && waiting_for_a_pick(state, ids)) {
                return Task::none();
            }
            let undo = *undo;
            state.checking = true;
            Task::run(ctx.worker.run(Job::Preflight { undo }), Message::Worker)
        }
    }
}

/// Browser add-ons are only touched when some were picked; with none picked that fix is left out.
fn apply_job(state: &State, mut ids: Vec<String>) -> Job {
    if state.addons_picked.is_empty() {
        ids.retain(|id| id != ADDONS);
        return Job::Apply(ids);
    }
    let picked = ItemChoice::from([(
        ADDONS.to_owned(),
        state.addons_picked.iter().cloned().collect(),
    )]);
    Job::ApplyPicked { ids, picked }
}

fn waiting_for_a_pick(state: &State, ids: &[String]) -> bool {
    ids.iter().any(|id| id == ADDONS)
        && state.addons_picked.is_empty()
        && ids.iter().all(|id| id == ADDONS)
}

fn start(state: &mut State, ids: Vec<String>, undo: bool, ctx: &mut Ctx) -> Task<Message> {
    ctx.busy = true;
    let chosen = undo && !ids.is_empty();
    state.chosen = chosen;
    let job = if chosen {
        Job::UndoSome(ids)
    } else if undo {
        Job::Undo
    } else {
        apply_job(state, ids)
    };
    state.now = Instant::now();
    state.work = Clock::at(state.now);
    state.since = state.now;
    state.bar = (!undo || planned(state) > 0).then(|| Tween::new(0.0, 0.0, anim::NORMAL));
    state.steps_view = None;
    state.follow = None;
    state.steps_held = false;
    state.result_view = None;
    state.stage = Stage::Working {
        undo,
        phase: None,
        items: Vec::new(),
    };
    Task::run(ctx.worker.run(job), Message::Worker)
}

pub fn on_worker(state: &mut State, event: &worker::Event, ctx: &mut Ctx) -> Task<Message> {
    use worker::Event as E;
    if let E::Preflight {
        undo: asked,
        result,
    } = event
    {
        if !state.checking {
            return Task::none();
        }
        state.checking = false;
        let Stage::Review { ids, undo } = std::mem::take(&mut state.stage) else {
            return Task::none();
        };
        if undo != *asked {
            state.stage = Stage::Review { ids, undo };
            return Task::none();
        }
        return match result {
            Ok(()) => start(state, ids, undo, ctx),
            Err(raw) => {
                state.stage = Stage::Blocked {
                    ids,
                    undo,
                    reason: flow::plain_failure(raw).to_owned(),
                    retry: flow::can_retry(raw),
                };
                Task::none()
            }
        };
    }
    let planned = planned(state);
    let Stage::Working {
        undo, phase, items, ..
    } = &mut state.stage
    else {
        return Task::none();
    };
    match event {
        E::Progress {
            phase: p,
            id,
            status,
        } => {
            *phase = Some(*p);
            if matches!(p, Phase::Applying | Phase::Undoing) {
                items.push(Done {
                    id: id.clone(),
                    name: ctx.lang.control(id),
                    status: status.clone(),
                    at: Instant::now(),
                });
            }
            let target = bar_target(planned, items.len(), *p == Phase::Verifying);
            if let Some(bar) = &mut state.bar {
                bar.retarget(Instant::now(), target);
            }
            return follow(state, Instant::now());
        }
        E::Applied {
            attempted,
            result,
            verify,
        } if !*undo => {
            let picked: Vec<String> = state.addons_picked.iter().cloned().collect();
            let summary = flow::summarize(
                Some(attempted),
                &picked,
                result.as_deref().map_err(String::as_str),
                verify.as_deref().map_err(String::as_str),
            );
            let technical = technical_lines(
                ctx,
                attempted,
                result.as_deref().map_err(String::as_str),
                verify.as_deref().map_err(String::as_str),
            );
            finish(state, false, summary, technical);
            ctx.busy = false;
        }
        E::Undone {
            chosen,
            result,
            verify,
        } if *undo => {
            let (result, verify) = (
                result.as_deref().map_err(String::as_str),
                verify.as_deref().map_err(String::as_str),
            );
            let summary = if chosen.is_empty() {
                flow::summarize(None, &[], result, verify)
            } else {
                flow::summarize_chosen(chosen, result, verify)
            };
            let technical = technical_lines(ctx, chosen, result, verify);
            finish(state, true, summary, technical);
            ctx.busy = false;
        }
        _ => {}
    }
    Task::none()
}

/// Which step row is running, and how many rows the list has.
fn running_step(state: &State) -> Option<(usize, usize)> {
    let Stage::Working { undo, phase, items } = &state.stage else {
        return None;
    };
    let verifying = *phase == Some(Phase::Verifying) || state.held.is_some();
    let by_progress = *undo && !state.chosen;
    let rows = if by_progress {
        items.len().max(1) + 1
    } else {
        state.plan.len() + 1
    };
    let running = if verifying || by_progress {
        rows - 1
    } else {
        state
            .plan
            .iter()
            .position(|r| items.iter().all(|d| d.id != r.id))
            .unwrap_or(rows - 1)
    };
    Some((running, rows))
}

/// The scroll offset that puts the running step in the middle of the list.
fn centred_offset(shown: f32, whole: f32, running: usize, rows: usize) -> Option<f32> {
    if whole <= shown || rows == 0 {
        return None;
    }
    let pitch = (whole + theme::S3) / rows as f32;
    let middle = running as f32 * pitch + (pitch - theme::S3) / 2.0;
    Some((middle - shown / 2.0).clamp(0.0, whole - shown))
}

fn follow(state: &mut State, now: Instant) -> Task<Message> {
    let Some(view) = state.steps_view else {
        return Task::none();
    };
    let (shown, whole) = (view.bounds().height, view.content_bounds().height);
    let Some((running, rows)) = running_step(state) else {
        return Task::none();
    };
    let Some(to) = centred_offset(shown, whole, running, rows) else {
        return Task::none();
    };
    if state.steps_held {
        // Following picks up again once the person scrolls back near the step running.
        let row = (whole + theme::S3) / rows as f32;
        if (view.absolute_offset().y - to).abs() > row * 2.0 {
            return Task::none();
        }
        state.steps_held = false;
    }
    if !anim::animating() {
        // Remembered so the move itself is not taken for the person scrolling.
        state.follow = Some(Follow::at(now, to, to));
        return scroll_steps(to);
    }
    match &mut state.follow {
        Some(f) => f.glide.retarget(now, to),
        None => state.follow = Some(Follow::at(now, view.absolute_offset().y, to)),
    }
    glide(state, now)
}

fn glide(state: &mut State, now: Instant) -> Task<Message> {
    let Some(f) = &mut state.follow else {
        return Task::none();
    };
    let y = f.glide.value(now);
    if (y - f.shown).abs() < 0.5 {
        return Task::none();
    }
    f.before = f.shown;
    f.shown = y;
    scroll_steps(y)
}

fn scroll_steps(y: f32) -> Task<Message> {
    iced::widget::operation::scroll_to(
        STEP_LIST,
        iced::widget::operation::AbsoluteOffset {
            x: None,
            y: Some(y),
        },
    )
}

fn finish(state: &mut State, undo: bool, summary: Summary, technical: Vec<String>) {
    let hold = handoff::sheet_hold();
    if hold.is_zero() || !state.frames_seen {
        show_result(state, undo, summary, technical);
        return;
    }
    let now = Instant::now();
    if let Some(bar) = &mut state.bar {
        bar.retarget(now, 1.0);
    }
    state.held = Some(Held {
        at: now,
        undo,
        summary,
        technical,
    });
}

fn show_result(state: &mut State, undo: bool, summary: Summary, technical: Vec<String>) {
    state.points.clear();
    state.now = Instant::now();
    state.since = state.now;
    state.bar = None;
    state.held = None;
    state.result_view = None;
    state.stage = Stage::Result {
        undo,
        summary,
        technical,
    };
}

fn technical_lines(
    ctx: &Ctx,
    attempted: &[String],
    result: Result<&secblitz::engine::Report, &str>,
    verify: Result<&secblitz::engine::Report, &str>,
) -> Vec<String> {
    let mut lines = Vec::new();
    match result {
        Ok(report) => {
            for r in &report.results {
                if attempted.is_empty() || attempted.contains(&r.id) {
                    let a = secblitz::advice::for_outcome(r);
                    let (status, next) = if r.status == CheckStatus::Error {
                        ("Not done", flow::NOT_DONE)
                    } else if r.status == CheckStatus::Skipped
                        && r.detail.contains("readiness blocks")
                    {
                        ("Not done", flow::REASON_DISK)
                    } else {
                        flow::plain_detail(&r.status, &a)
                    };
                    lines.push(format!(
                        "{} · {} · {}",
                        ctx.lang.control(&r.id),
                        ctx.t(status),
                        ctx.t(next)
                    ));
                }
            }
        }
        Err(e) => lines.push(ctx.t(flow::plain_failure(e))),
    }
    if let Err(e) = verify {
        let line = ctx.t(flow::plain_failure(e));
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    lines.truncate(60);
    lines
}

pub fn overlay_content<'a>(state: &'a State, ctx: &'a Ctx) -> Option<Element<'a, Message>> {
    match &state.stage {
        Stage::Closed => None,
        Stage::Review { ids, undo } => Some(review_view(state, ctx, ids, *undo)),
        Stage::Blocked {
            ids,
            undo,
            reason,
            retry,
        } => Some(blocked_view(
            ctx,
            *undo,
            *undo && !ids.is_empty(),
            reason,
            *retry,
        )),
        Stage::Working { undo, phase, items } => {
            Some(working_view(state, ctx, *undo, *phase, items))
        }
        Stage::Result {
            undo,
            summary,
            technical,
        } => Some(widgets::appear::settle(
            result_view(state, ctx, *undo, summary, technical),
            ctx.palette.surface,
        )),
    }
}

fn bounded<'a>(p: Palette, content: Element<'a, Message>) -> Element<'a, Message> {
    container(
        scrollable(content)
            .direction(scrollbar())
            .style(scroll_style(p)),
    )
    .max_height(LIST_MAX_HEIGHT)
    .into()
}

fn below_art<'a>(state: &State, p: Palette, content: Element<'a, Message>) -> Element<'a, Message> {
    fade_below(
        scrollable(container(content).padding([0.0, theme::S3]))
            .on_scroll(|v| Message::Fix(Msg::ResultList(v)))
            .direction(scrollbar())
            .style(scroll_style(p))
            .width(Length::Fill)
            .height(Length::Fill),
        p.surface,
        more_below(state.result_view.as_ref()),
    )
}

fn step_list<'a>(state: &State, p: Palette, list: Element<'a, Message>) -> Element<'a, Message> {
    fade_below(
        scrollable(
            container(
                container(list)
                    .width(Length::Fill)
                    .max_width(STEP_LIST_WIDTH),
            )
            .center_x(Length::Fill)
            .padding([0.0, theme::S3]),
        )
        .id(STEP_LIST)
        .on_scroll(|v| Message::Fix(Msg::Steps(v)))
        .direction(scrollbar())
        .style(scroll_style(p))
        .width(Length::Fill)
        .height(Length::Fill),
        p.surface,
        more_below(state.steps_view.as_ref()),
    )
}

fn art<'a>(
    state: &State,
    ctx: &Ctx,
    undo: bool,
    run: Run,
    progress: Option<f32>,
) -> Element<'a, Message> {
    let p = ctx.palette;
    let (changed, now) = (state.since, state.now.max(state.since));
    let drawing = if undo {
        hairline::Rewind {
            p,
            plate: Plate::Surface,
            run,
            progress,
            changed,
            now,
            label: ctx.t(rewind::label_key(rewind::Undo::Fixes, run)),
        }
        .view()
    } else {
        hairline::ShieldFill {
            p,
            plate: Plate::Surface,
            run,
            progress,
            changed,
            now,
            label: ctx.t(shield_fill::label_key(run)),
        }
        .view()
    };
    container(drawing).center_x(Length::Fill).into()
}

fn work_share(planned: usize, finished: usize, verifying: bool) -> Option<f32> {
    (planned > 0).then(|| {
        if verifying {
            1.0
        } else {
            finished.min(planned) as f32 / planned as f32
        }
    })
}

fn result_art(s: &Summary) -> (Run, Option<f32>) {
    let run = match s.kind {
        SummaryKind::Success => Run::Done,
        SummaryKind::Partial => Run::Partial,
        SummaryKind::Failed => Run::Failed,
    };
    let total = s.done.len() + s.not_done.len();
    (run, (total > 0).then(|| s.done.len() as f32 / total as f32))
}

fn note<'a>(p: Palette, icon: Icon, s: String) -> Element<'a, Message> {
    row![
        widgets::icon(icon, 16.0, p.text_muted),
        widgets::small(p, s),
    ]
    .spacing(theme::S2)
    .align_y(Alignment::Center)
    .into()
}

fn footer<'a>(buttons: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    let mut r = row![space::horizontal()]
        .spacing(theme::S2)
        .align_y(Alignment::Center);
    for b in buttons {
        r = r.push(b);
    }
    r.into()
}

fn plan_list<'a>(
    ctx: &Ctx,
    plan: &[PlanRow],
    restart_label: &str,
    opened: &Opened,
) -> Element<'a, Message> {
    let p = ctx.palette;
    let mut list = column![].spacing(theme::S3);
    for r in plan {
        let mut trailing = Vec::new();
        if r.restart {
            trailing.push(widgets::tag(
                p,
                Some(Icon::Restart),
                restart_label.to_owned(),
            ));
        }
        let sheet = widgets::info::for_check(ctx, r.name.clone(), &r.id, false)
            .map(|s| s.without(&[r.line.as_deref().unwrap_or_default()]));
        if let Some(info) = widgets::info::button(ctx, sheet) {
            trailing.push(info);
        }
        let key = format!("plan:{}", r.id);
        let mut item = column![point::point(
            p,
            row_text(p, r.name.clone(), None),
            trailing,
            r.line.as_ref().map(|l| widgets::small(p, l.clone())),
            opened.has(&key),
            Message::Fix(Msg::Point(key)),
        )]
        .spacing(theme::S2);
        if r.managed {
            item = item.push(note(
                p,
                Icon::Info,
                ctx.t("Your browser will say 'Managed by your organization'."),
            ));
        }
        if !r.undoable {
            item = item.push(note(p, Icon::AlertTriangle, ctx.t("Can't be undone")));
        }
        list = list.push(item);
    }
    bounded(p, list.into())
}

fn addon_picker<'a>(state: &'a State, ctx: &'a Ctx) -> Element<'a, Message> {
    let p = ctx.palette;
    let mut list = column![].spacing(theme::S2);
    for addon in &state.addons {
        let mut parts = vec![addon.browser.to_owned()];
        parts.extend(addon.why.iter().map(|w| ctx.t(w)));
        list = list.push(
            row![
                widgets::checkbox(
                    p,
                    CheckState::from(state.addons_picked.contains(&addon.key)),
                    None,
                    Some(Message::Fix(Msg::PickAddon(addon.key.clone()))),
                ),
                row_text(p, addon.name.clone(), Some(parts.join(" · "))),
            ]
            .spacing(theme::S2)
            .align_y(Alignment::Center),
        );
    }
    let mut c = column![
        widgets::section_label(p, ctx.t("Choose the add-ons to turn off")),
        bounded(p, list.into()),
    ]
    .spacing(theme::S2);
    if state.addons_picked.is_empty() {
        c = c.push(widgets::small(
            p,
            ctx.t("Tick at least one add-on to continue."),
        ));
    }
    c.into()
}

fn review_view<'a>(
    state: &'a State,
    ctx: &'a Ctx,
    ids: &'a [String],
    undo: bool,
) -> Element<'a, Message> {
    let p = ctx.palette;
    let n = ids.len();
    let chosen = undo && n > 0;
    let title = if chosen && n == 1 {
        ctx.t("Put back 1 setting?")
    } else if chosen {
        ctx.t("Put back {n} settings?")
            .replace("{n}", &n.to_string())
    } else if undo {
        ctx.t("Undo your last fixes?")
    } else if n == 1 {
        ctx.t("Fix 1 problem?")
    } else {
        ctx.t("Fix {n} problems?").replace("{n}", &n.to_string())
    };
    let mut c = column![widgets::h2(p, title)].spacing(theme::S3);
    let restart_label = ctx.t("Needs restart");
    if chosen {
        let one = n == 1 && state.plan.len() <= 1;
        c = c.push(widgets::muted(
            p,
            ctx.t(if one {
                "We'll put this setting back the way it was:"
            } else {
                "We'll put these settings back the way they were:"
            }),
        ));
        c = c.push(plan_list(ctx, &state.plan, &restart_label, &state.points));
        if state.together {
            c = c.push(widgets::small(
                p,
                ctx.t("These go back together, because one needs the other."),
            ));
        }
        c = c.push(note(
            p,
            Icon::AlertTriangle,
            ctx.t(if one {
                "Your computer will be less protected after this. You can fix it again at any time."
            } else {
                "Your computer will be less protected after this. You can fix these again at any time."
            }),
        ));
        c = c.push(widgets::small(
            p,
            ctx.t("Anything you changed yourself since then is left as it is."),
        ));
    } else if undo {
        if state.plan.is_empty() {
            c = c.push(widgets::muted(
                p,
                ctx.t("We'll put your settings back the way they were before your last fix."),
            ));
        } else {
            c = c.push(widgets::muted(
                p,
                ctx.t("We'll put these settings back the way they were:"),
            ));
            c = c.push(plan_list(ctx, &state.plan, &restart_label, &state.points));
        }
        c = c.push(widgets::small(
            p,
            ctx.t("Anything you changed yourself since then is left as it is."),
        ));
    } else {
        c = c.push(plan_list(ctx, &state.plan, &restart_label, &state.points));
        if !state.addons.is_empty() && ids.iter().any(|id| id == ADDONS) {
            c = c.push(addon_picker(state, ctx));
        }
        if state.plan.iter().any(|r| r.restart) {
            c = c.push(note(
                p,
                Icon::Restart,
                ctx.t("Some fixes need a restart. We'll never restart without asking."),
            ));
        }
        if state.plan.iter().all(|r| r.undoable) {
            c = c.push(note(
                p,
                Icon::History,
                ctx.t("You can undo this later from History."),
            ));
        }
    }
    let confirm = widgets::action(
        p,
        if undo {
            ButtonKind::Danger
        } else {
            ButtonKind::Primary
        },
        ctx.t(if state.checking {
            "Checking…"
        } else if chosen {
            "Put back now"
        } else if undo {
            "Undo fixes"
        } else {
            "Fix now"
        }),
        None,
        (!state.checking && (undo || !waiting_for_a_pick(state, ids)))
            .then_some(Message::Fix(Msg::Confirm)),
    );
    c.push(space::vertical().height(theme::S3))
        .push(footer(vec![
            widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t("Cancel"),
                None,
                Some(Message::Fix(Msg::Cancel)),
            ),
            confirm,
        ]))
        .into()
}

fn blocked_view<'a>(
    ctx: &'a Ctx,
    undo: bool,
    chosen: bool,
    reason: &str,
    retry: bool,
) -> Element<'a, Message> {
    let p = ctx.palette;
    let title = if chosen {
        "We can't put these settings back right now"
    } else if undo {
        "We can't undo your fixes right now"
    } else {
        "We can't make these fixes right now"
    };
    let mut buttons = vec![widgets::action(
        p,
        ButtonKind::Secondary,
        ctx.t("Close"),
        None,
        Some(Message::Fix(Msg::Cancel)),
    )];
    if retry {
        buttons.push(widgets::action(
            p,
            ButtonKind::Primary,
            ctx.t("Try again"),
            Some(Icon::Refresh),
            Some(Message::Fix(Msg::Retry)),
        ));
    }
    column![
        widgets::h2(p, ctx.t(title)),
        widgets::muted(p, ctx.t(reason)),
        space::vertical().height(theme::S3),
        footer(buttons),
    ]
    .spacing(theme::S3)
    .into()
}

fn waiting_mark<'a>(p: Palette) -> Element<'a, Message> {
    container(
        container(space::horizontal())
            .width(WAIT_DOT)
            .height(WAIT_DOT)
            .style(move |_| container::Style {
                background: Some(Background::Color(p.disabled_fg)),
                border: Border {
                    radius: (WAIT_DOT / 2.0).into(),
                    ..Border::default()
                },
                ..container::Style::default()
            }),
    )
    .center(MARK)
    .into()
}

fn done_mark<'a>(state: &State, p: Palette, status: &str, at: Instant) -> Element<'a, Message> {
    let t = state.progress(at);
    match status {
        "error" | "conflict" => anim::cross_draw(MARK, p.bad, t),
        "skipped" | "attention" | "pending" => anim::warn_draw(MARK, p.warn, t),
        _ => anim::check_draw(MARK, p.good, t),
    }
}

fn step<'a>(
    p: Palette,
    mark: Element<'a, Message>,
    label: String,
    active: bool,
) -> Element<'a, Message> {
    row![
        mark,
        iced::widget::text(label)
            .size(theme::BODY)
            .font(if active {
                theme::MEDIUM
            } else {
                theme::REGULAR
            })
            .color(if active { p.text } else { p.text_muted }),
    ]
    .spacing(theme::S3)
    .align_y(Alignment::Center)
    .into()
}

fn working_view<'a>(
    state: &'a State,
    ctx: &'a Ctx,
    undo: bool,
    phase: Option<Phase>,
    items: &'a [Done],
) -> Element<'a, Message> {
    let p = ctx.palette;
    let spin = |size: f32| anim::spinner(size, p.text, state.work.elapsed_at(state.now));
    let title = if undo {
        ctx.t("Putting your settings back…")
    } else {
        ctx.t("Fixing your computer…")
    };
    let settled = state.held.is_some();
    let verifying = phase == Some(Phase::Verifying) || settled;
    let share = work_share(planned(state), items.len(), verifying);
    let mut c = column![
        art(state, ctx, undo, Run::Working, share),
        widgets::h2_centred(p, title),
        widgets::muted_centred(
            p,
            ctx.t("Please keep this window open. This can take a minute.")
        ),
    ]
    .spacing(theme::S3)
    .height(Length::Fixed(widgets::SHEET_FIT_HEIGHT));
    if let Some(bar) = &state.bar {
        c = c.push(progress::bar(p, bar, Tone::Brand, state.now));
    } else if undo {
        c = c.push(progress::indeterminate(p, Tone::Brand));
    }

    let mut list = column![].spacing(theme::S3);
    let finished = |d: &Done| done_mark(state, p, &d.status, d.at);
    if undo && !state.chosen {
        for d in items {
            list = list.push(step(p, finished(d), d.name.clone(), false));
        }
        if items.is_empty() {
            list = list.push(step(
                p,
                spin(MARK),
                ctx.t("Putting your settings back"),
                true,
            ));
        }
    } else {
        let mut running_shown = false;
        for r in &state.plan {
            let (mark, active) = match items.iter().find(|d| d.id == r.id) {
                Some(d) => (finished(d), false),
                None if !running_shown && !verifying => {
                    running_shown = true;
                    (spin(MARK), true)
                }
                None => (waiting_mark(p), false),
            };
            list = list.push(step(p, mark, r.name.clone(), active));
        }
    }
    let last = match &state.held {
        Some(h) => anim::check_draw(MARK, p.good, state.progress(h.at)),
        None if verifying => spin(MARK),
        None => waiting_mark(p),
    };
    list = list.push(step(
        p,
        last,
        ctx.t("Checking the result"),
        verifying && !settled,
    ));
    c.push(step_list(state, p, list.into())).into()
}

fn bullet<'a>(p: Palette, tone: Tone, s: String) -> Element<'a, Message> {
    marked(p, Icon::Check, tone, s)
}

fn marked<'a>(p: Palette, mark: Icon, tone: Tone, s: String) -> Element<'a, Message> {
    row![widgets::icon(mark, 16.0, p.tone(tone)), widgets::body(p, s)]
        .spacing(theme::S2)
        .align_y(Alignment::Center)
        .into()
}

fn block<'a>(p: Palette, label: String, lines: Vec<Element<'a, Message>>) -> Element<'a, Message> {
    let mut c = column![widgets::section_label(p, label)].spacing(theme::S2);
    for l in lines {
        c = c.push(l);
    }
    c.into()
}

fn result_view<'a>(
    state: &'a State,
    ctx: &'a Ctx,
    undo: bool,
    s: &'a Summary,
    technical: &'a [String],
) -> Element<'a, Message> {
    let p = ctx.palette;
    let title = match (undo, s.kind) {
        (true, SummaryKind::Success) if state.chosen => "Your settings were put back",
        (true, SummaryKind::Partial) if state.chosen => "Some settings were put back",
        (true, SummaryKind::Failed) if state.chosen => "We couldn't put these settings back",
        (false, SummaryKind::Success) => "You're now more protected",
        (false, SummaryKind::Partial) => "Some fixes are done",
        (false, SummaryKind::Failed) => "We couldn't make these fixes",
        (true, SummaryKind::Success) => "Your fixes were undone",
        (true, SummaryKind::Partial) => "Some fixes were undone",
        (true, SummaryKind::Failed) => "We couldn't undo your fixes",
    };
    let (run, share) = result_art(s);

    let mut body = column![].spacing(theme::S4);
    if !s.protected_now.is_empty() {
        body = body.push(block(
            p,
            ctx.t("You're now protected from:"),
            s.protected_now
                .iter()
                .map(|k| bullet(p, Tone::Good, ctx.t(k)))
                .collect(),
        ));
    }
    if !s.after_restart.is_empty() {
        body = body.push(block(
            p,
            ctx.t("After you restart, you'll also be protected from:"),
            s.after_restart
                .iter()
                .map(|k| bullet(p, Tone::Neutral, ctx.t(k)))
                .collect(),
        ));
    }
    if undo && !s.done.is_empty() {
        body = body.push(block(
            p,
            ctx.t("Put back:"),
            s.done
                .iter()
                .map(|id| bullet(p, Tone::Good, ctx.lang.control(id)))
                .collect(),
        ));
    }
    if !s.less_protected.is_empty() {
        body = body.push(block(
            p,
            ctx.t("You're now less protected from:"),
            s.less_protected
                .iter()
                .map(|k| marked(p, Icon::Shield, Tone::Neutral, ctx.t(k)))
                .collect(),
        ));
    }
    if !s.not_done.is_empty() {
        body = body.push(block(
            p,
            ctx.t(if undo {
                "Couldn't undo"
            } else {
                "Couldn't fix"
            }),
            s.not_done
                .iter()
                .map(|(id, reason)| {
                    let key = format!("fail:{id}");
                    let reason = ctx.t(reason);
                    let (first, rest) = point::first_sentence(&reason);
                    point::point(
                        p,
                        row_text(p, ctx.lang.control(id), Some(first.to_owned())),
                        Vec::new(),
                        rest.map(|r| widgets::small(p, r.to_owned())),
                        state.points.has(&key),
                        Message::Fix(Msg::Point(key)),
                    )
                })
                .collect(),
        ));
    } else if let Some(why) = &s.failure {
        body = body.push(point::text_point(
            p,
            &ctx.t(why),
            Words::Muted,
            state.points.has("failure"),
            Message::Fix(Msg::Point("failure".to_owned())),
        ));
    } else if s.kind == SummaryKind::Failed && s.done.is_empty() {
        body = body.push(widgets::muted(
            p,
            ctx.t("Nothing was changed that we could confirm. You can try again in a moment."),
        ));
    }
    if s.restart {
        body = body.push(widgets::inline_notice(
            p,
            Tone::Neutral,
            ctx.t("Restart your computer when you're ready to finish. We'll never restart it for you."),
        ));
    }
    if s.unverified {
        body = body.push(widgets::inline_notice(
            p,
            Tone::Warn,
            ctx.t("We couldn't confirm the result. Check again to be sure."),
        ));
    }
    let sheet = InfoSheet::new(ctx.t(title)).list(ctx.t("More details"), technical.to_vec());
    if let Some(more) = widgets::info::link(ctx, ctx.t("More details"), Some(sheet)) {
        body = body.push(more);
    }

    let mut buttons = Vec::new();
    if s.unverified {
        buttons.push(widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("Check again"),
            Some(Icon::Refresh),
            Some(Message::Fix(Msg::CheckAgain)),
        ));
    }
    buttons.push(widgets::action(
        p,
        ButtonKind::Primary,
        ctx.t("Done"),
        None,
        Some(Message::Fix(Msg::Done)),
    ));
    column![
        art(state, ctx, undo, run, share),
        container(widgets::h1(p, ctx.t(title))).center_x(Length::Fill),
        below_art(state, p, body.into()),
        space::vertical().height(theme::S3),
        footer(buttons),
    ]
    .spacing(theme::S3)
    .height(Length::Fixed(widgets::SHEET_FIT_HEIGHT))
    .into()
}

#[cfg(test)]
pub fn review(state: &State) -> Option<(Vec<String>, bool)> {
    match &state.stage {
        Stage::Review { ids, undo } => Some((ids.clone(), *undo)),
        _ => None,
    }
}

#[cfg(test)]
pub fn plan_ids(state: &State) -> Vec<String> {
    state.plan.iter().map(|r| r.id.clone()).collect()
}

#[cfg(test)]
pub fn added_together(state: &State) -> bool {
    state.together
}

#[cfg(test)]
pub fn stage_name(state: &State) -> &'static str {
    match &state.stage {
        Stage::Closed => "closed",
        Stage::Review { .. } => "review",
        Stage::Blocked { .. } => "blocked",
        Stage::Working { .. } => "working",
        Stage::Result { .. } => "result",
    }
}

#[cfg(test)]
pub fn result_summary(state: &State) -> Option<&Summary> {
    match &state.stage {
        Stage::Result { summary, .. } => Some(summary),
        _ => None,
    }
}

#[cfg(test)]
pub fn addons_waiting(state: &State) -> bool {
    match &state.stage {
        Stage::Review { ids, undo: false } => waiting_for_a_pick(state, ids),
        _ => false,
    }
}

#[cfg(test)]
pub fn addon_apply_job(state: &State) -> Job {
    apply_job(state, vec![ADDONS.to_owned()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_running_step_is_kept_in_the_middle_of_the_list() {
        let (rows, row) = (11, MARK);
        let whole = rows as f32 * (row + theme::S3) - theme::S3;
        let shown = 150.0;
        assert_eq!(centred_offset(shown, whole, 0, rows), Some(0.0));
        let mid = centred_offset(shown, whole, 5, rows).unwrap();
        let centre = 5.0 * (row + theme::S3) + row / 2.0;
        assert!((mid + shown / 2.0 - centre).abs() < 0.01);
        assert_eq!(centred_offset(shown, whole, 10, rows), Some(whole - shown));
        assert_eq!(centred_offset(whole, whole, 5, rows), None);
    }

    #[test]
    fn the_plan_decides_how_many_steps_there_are() {
        let mut state = State::default();
        assert_eq!(planned(&state), 0);
        state.plan = vec![PlanRow::default(), PlanRow::default()];
        assert_eq!(planned(&state), 2);
    }

    #[test]
    fn the_list_only_counts_moves_it_made_itself() {
        let _m = anim::forced::set(false);
        let now = Instant::now();
        let mut f = Follow::at(now, 0.0, 100.0);
        assert!(f.put_it_at(0.0) && f.put_it_at(1.5) && f.put_it_at(40.0) && f.put_it_at(101.5));
        assert!(
            !f.put_it_at(140.0),
            "the person scrolled somewhere the glide never goes"
        );
        f.before = f.shown;
        f.shown = 30.0;
        f.glide.retarget(now, 60.0);
        assert!(f.put_it_at(0.0), "the offset may trail behind a new target");
        assert!(!f.put_it_at(90.0));
        let rest = Follow::at(now, 80.0, 80.0);
        assert!(rest.put_it_at(80.0) && !rest.put_it_at(60.0));
    }

    #[test]
    fn drawing_follows_the_real_work() {
        assert_eq!(work_share(0, 0, false), None);
        assert_eq!(work_share(4, 1, false), Some(0.25));
        assert_eq!(work_share(4, 9, false), Some(1.0));
        assert_eq!(work_share(4, 0, true), Some(1.0));
        let mut s = Summary::default();
        assert_eq!(result_art(&s), (Run::Done, None));
        s.kind = SummaryKind::Partial;
        s.done = vec!["a".into(), "b".into(), "c".into()];
        s.not_done = vec![("d".into(), "why".into())];
        assert_eq!(result_art(&s), (Run::Partial, Some(0.75)));
        s.kind = SummaryKind::Failed;
        assert_eq!(result_art(&s).0, Run::Failed);
    }

    #[test]
    fn bar_moves_forward_and_never_completes_before_the_check() {
        assert_eq!(bar_target(3, 0, false), 0.0);
        assert!((bar_target(3, 3, false) - 0.75).abs() < 1e-6);
        assert!((bar_target(3, 9, false) - 0.75).abs() < 1e-6);
        assert!((bar_target(3, 0, true) - 0.75).abs() < 1e-6);
        assert!(bar_target(0, 0, true) <= 0.0 + f32::EPSILON);
    }

    #[test]
    fn open_points_reset_when_the_window_closes() {
        let (mut app, _) = crate::gui::App::new(crate::gui::Options {
            lang: crate::i18n::Lang::En,
            broker: None,
            start: None,
        });
        let mut state = State::default();
        let _ = update(&mut state, Msg::Point("plan:a".into()), &mut app.ctx);
        assert!(!state.points.has("plan:a"), "nothing opens while closed");
        state.stage = Stage::Review {
            ids: Vec::new(),
            undo: false,
        };
        let _ = update(&mut state, Msg::Point("plan:a".into()), &mut app.ctx);
        assert!(state.points.has("plan:a"));
        let _ = update(&mut state, Msg::Point("plan:a".into()), &mut app.ctx);
        assert!(!state.points.has("plan:a"));
        let _ = update(&mut state, Msg::Point("plan:a".into()), &mut app.ctx);
        let _ = update(&mut state, Msg::Cancel, &mut app.ctx);
        assert!(!state.points.has("plan:a"));
    }
}
