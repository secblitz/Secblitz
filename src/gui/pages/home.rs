//! Home: one hero region (score ring, verdict, one primary, extras in the
//! overflow menu), then flat row groups; first-run PC-check view.
use crate::app::flow;
use crate::app::score::{self, Score, ToCheck, Verdict};
use crate::gui::icons::Icon;
use crate::gui::theme::{self, Tone};
use crate::gui::widgets::hairline::magnifier::{Labels, Magnifier, Status};
use crate::gui::widgets::hairline::Plate;
use crate::gui::widgets::{self, anim, ring, scan, ButtonKind};
use crate::gui::{CheckProgress, Ctx, Message, Page};
use iced::widget::{column, row};
use iced::{Alignment, Element, Length, Subscription, Task};
use secblitz::advice::{self, Group, NextStep};
use secblitz::engine::Report;
use secblitz::model::Probe;
use std::time::Instant;

#[derive(Debug, Clone, Copy)]
struct Count {
    from: i64,
    to: i64,
    clock: anim::Clock,
}

#[derive(Debug)]
pub struct State {
    now: Instant,
    scan: Option<anim::Clock>,
    lines: Vec<(String, Instant)>,
    processed: usize,
    protected_open: bool,
    protected_all: bool,
    web_suggest: bool,
    seen_check: Option<u64>,
    shown: i64,
    count: Option<Count>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            now: Instant::now(),
            scan: None,
            lines: Vec::new(),
            processed: 0,
            protected_open: false,
            protected_all: false,
            web_suggest: false,
            seen_check: None,
            shown: 0,
            count: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    Frame(Instant),
    ToggleProtected,
    ToggleProtectedAll,
    WebSuggest(bool),
    OpenDownload,
    DownloadOpened(bool),
    HideProcessorTip,
}

const LOW_DISK_BYTES: u64 = 5_000_000_000;
const KEPT_LINES: usize = 8;
const PROTECTED_ROWS: usize = 8;
const ATTENTION_ROWS: usize = 4;

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    match msg {
        Msg::Frame(now) => frame(state, ctx, now),
        Msg::ToggleProtected => state.protected_open = !state.protected_open,
        Msg::ToggleProtectedAll => state.protected_all = !state.protected_all,
        Msg::WebSuggest(on) => state.web_suggest = on,
        Msg::OpenDownload => {
            return ctx.broker_task(crate::broker::Request::OpenDownloadPage, |reply| {
                Message::Home(Msg::DownloadOpened(matches!(
                    reply,
                    Ok(crate::broker::Reply::Done)
                )))
            })
        }
        Msg::DownloadOpened(true) => {}
        Msg::DownloadOpened(false) => {
            return Task::done(Message::Toast(
                ctx.t("We couldn't open your web browser. Visit secblitz.lol to get the version made for your computer."),
                Tone::Warn,
            ))
        }
        Msg::HideProcessorTip => return hide_processor_tip(ctx),
    }
    Task::none()
}

fn hide_processor_tip(ctx: &mut Ctx) -> Task<Message> {
    mark_tip_seen(&mut ctx.prefs);
    Task::perform(crate::gui::save_prefs(ctx.prefs.clone()), |_| Message::Noop)
}

fn mark_tip_seen(prefs: &mut crate::app::settings::Prefs) {
    prefs.processor_tip_seen = true;
}

fn processor_tip_due(ctx: &Ctx) -> bool {
    tip_due(ctx.x64_on_arm, ctx.prefs.processor_tip_seen)
}

fn tip_due(x64_on_arm: bool, seen: bool) -> bool {
    x64_on_arm && !seen
}

fn frame(state: &mut State, ctx: &Ctx, now: Instant) {
    state.now = now;
    if let Some(progress) = &ctx.checking {
        if state.scan.is_none() {
            state.scan = Some(anim::Clock::at(now));
            state.lines.clear();
            state.lines.push((ctx.t("Looking at your settings…"), now));
            state.processed = 0;
        }
        if state.processed > progress.items.len() {
            state.processed = 0;
        }
        for (id, _) in progress.items.iter().skip(state.processed) {
            let label = ctx.t(advice::control_label(id));
            if !state.lines.iter().any(|(l, _)| *l == label) {
                state.lines.push((label, now));
            }
        }
        if state.lines.len() > KEPT_LINES {
            let extra = state.lines.len() - KEPT_LINES;
            state.lines.drain(..extra);
        }
        state.processed = progress.items.len();
    } else {
        state.scan = None;
        state.lines.clear();
    }
    if ctx.checking.is_none() && ctx.checked_at != state.seen_check {
        state.seen_check = ctx.checked_at;
        if let Some(report) = ctx.report.as_deref() {
            let to = Score::of(report).protected as i64;
            if to != state.shown {
                state.count = Some(Count {
                    from: state.shown,
                    to,
                    clock: anim::Clock::at(now),
                });
            }
        }
    }
    if let Some(c) = &state.count {
        if c.clock.done(anim::SLOW, now) {
            state.shown = c.to;
            state.count = None;
        }
    }
}

pub fn subscription(state: &State, ctx: &Ctx) -> Subscription<Message> {
    let live = ctx.checking.is_some()
        || state.count.is_some()
        || (ctx.checked_at != state.seen_check && ctx.report.is_some());
    if live && anim::animating() {
        iced::window::frames().map(|now| Message::Home(Msg::Frame(now)))
    } else {
        Subscription::none()
    }
}

pub fn fills_window(ctx: &Ctx) -> bool {
    ctx.engine_error.is_none() && ctx.full_check().is_some()
}

pub fn view<'a>(state: &'a State, ctx: &'a Ctx) -> Element<'a, Message> {
    if let Some(info) = &ctx.damage {
        return super::recovery::card(ctx, info);
    }
    if let Some(error) = &ctx.engine_error {
        return error_card(ctx, "We couldn't start Secblitz", error, false);
    }
    if let Some(progress) = ctx.full_check() {
        return scanning(state, ctx, progress);
    }
    let Some(report) = ctx.report.as_deref() else {
        if let Some(error) = &ctx.check_error {
            return error_card(ctx, "We couldn't check your computer", error, true);
        }
        return not_checked(ctx);
    };
    assessed(state, ctx, report)
}

fn not_checked<'a>(ctx: &'a Ctx) -> Element<'a, Message> {
    let p = ctx.palette;
    let ring_view = ring::ring(
        ring::Ring {
            p,
            ratio: 0.0,
            tone: Tone::Neutral,
            label: String::new(),
            caption: String::new(),
        },
        176.0,
    );
    let texts = column![
        widgets::h1(p, ctx.t("Not checked yet")),
        widgets::muted(
            p,
            ctx.t("Check your computer to see what's protected. Nothing is changed.")
        ),
    ]
    .spacing(theme::S1);
    let check = widgets::action(
        p,
        ButtonKind::Primary,
        ctx.t("Check my computer"),
        Some(Icon::Refresh),
        (!ctx.busy).then_some(Message::CheckNow),
    );
    widgets::region(
        p,
        row![
            ring_view,
            column![texts, check].spacing(theme::S6).width(Length::Fill)
        ]
        .spacing(theme::S8)
        .align_y(Alignment::Center),
    )
    .into()
}

fn scanning<'a>(state: &'a State, ctx: &'a Ctx, progress: &CheckProgress) -> Element<'a, Message> {
    let p = ctx.palette;
    let mut seen: Vec<&str> = Vec::new();
    for (id, _) in &progress.items {
        if !seen.contains(&id.as_str()) {
            seen.push(id);
        }
    }
    let n = seen.len();
    let total = ctx.catalog.available.len().max(n + 1);
    let ratio = if ctx.finishing {
        1.0
    } else if ctx.catalog.available.is_empty() {
        n as f32 / (n as f32 + 6.0)
    } else {
        (n as f32 / total as f32).min(0.96)
    };
    let art = Magnifier {
        p,
        plate: Plate::Bg,
        status: if ctx.finishing {
            Status::Done
        } else {
            Status::Checking
        },
        progress: (!ctx.catalog.available.is_empty()).then_some(ratio),
        changed: state.scan.map_or(state.now, |c| c.start()),
        now: state.now,
        labels: Labels::new(|s| ctx.t(s)),
    };
    scan::checking_screen(
        p,
        ctx.t("Checking your computer"),
        ctx.t("This takes about a minute. Nothing is changed."),
        ratio,
        art,
        scan::Feed {
            lines: &state.lines,
            now: state.now,
            finished: ctx.finishing,
        },
    )
}

fn error_card<'a>(
    ctx: &'a Ctx,
    title: &str,
    reason: &'a str,
    can_retry: bool,
) -> Element<'a, Message> {
    let p = ctx.palette;
    let advice = if can_retry {
        ctx.t("Something got in the way. Trying again usually fixes it.")
    } else {
        ctx.t("Close Secblitz and open it again. If this keeps happening, restart your computer.")
    };
    let mut content = column![
        widgets::icon(Icon::ShieldAlert, theme::ICON_ROW, p.bad_text),
        widgets::h2(p, ctx.t(title)),
        widgets::muted(p, advice),
    ]
    .spacing(theme::S4)
    .align_x(Alignment::Start);
    if can_retry {
        content = content.push(widgets::action(
            p,
            ButtonKind::Primary,
            ctx.t("Try again"),
            Some(Icon::Refresh),
            Some(Message::CheckNow),
        ));
    }
    let sheet =
        widgets::info::InfoSheet::new(ctx.t(title)).text(ctx.t("More details"), reason.to_owned());
    if let Some(more) = widgets::info::link(ctx, ctx.t("More details"), Some(sheet)) {
        content = content.push(more);
    }
    widgets::region(p, content).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Split {
    fixable: usize,
    choices: usize,
    manual: usize,
}

fn split(report: &Report, available: &[String], items: &mut [ToCheck]) -> (Vec<String>, Split) {
    let recommended = crate::app::flow::recommended(report, available);
    let candidates = crate::app::flow::candidates(report, available);
    let part = |item: &ToCheck| match item {
        ToCheck::Control(r) if recommended.contains(&r.id) => 0,
        ToCheck::Control(r) if candidates.contains(&r.id) && advice::is_choice_check_id(&r.id) => 1,
        _ => 2,
    };
    items.sort_by_key(|item| part(item));
    let ids: Vec<String> = items
        .iter()
        .filter_map(|item| match item {
            ToCheck::Control(r) if part(item) == 0 => Some(r.id.clone()),
            _ => None,
        })
        .collect();
    let fixable = ids.len();
    let choices = items.iter().filter(|item| part(item) == 1).count();
    let manual = items.len() - fixable - choices;
    (
        ids,
        Split {
            fixable,
            choices,
            manual,
        },
    )
}

fn protected_labels(report: &Report) -> (usize, Vec<&'static str>) {
    let mut count = 0;
    let mut labels: Vec<&'static str> = Vec::new();
    for r in &report.results {
        let a = advice::for_outcome(r);
        if a.group == Group::Protected && advice::extra_section(&r.id).is_none() {
            count += 1;
            let label = advice::control_label(&r.id);
            if !labels.contains(&label) {
                labels.push(label);
            }
        }
    }
    (count, labels)
}

fn readiness_notices(ctx: &Ctx, report: &Report) -> Vec<(Tone, String)> {
    let mut out = Vec::new();
    let Some(r) = &report.readiness else {
        return out;
    };
    if let Some(sentence) = flow::repairs_blocked(report) {
        out.push((Tone::Warn, ctx.t(sentence)));
    } else if let Probe::Known(v) = &r.system_volume {
        if v.available_bytes < LOW_DISK_BYTES {
            out.push((
                Tone::Warn,
                ctx.t(
                    "Your disk is almost full. Free up some space so updates and fixes can finish.",
                ),
            ));
        }
    }
    if let Probe::Known(pw) = &r.power {
        if pw.battery_present == Some(true) && pw.ac_connected == Some(false) {
            out.push((
                Tone::Neutral,
                ctx.t("Your computer is running on battery. Plug it in before making changes."),
            ));
        }
    }
    if matches!(r.windows_update_reboot, Probe::Known(true)) {
        out.push((
            Tone::Neutral,
            ctx.t("A restart is waiting. Save your work and restart when you're ready."),
        ));
    }
    out
}

fn count_text(ctx: &Ctx, one: &str, many: &str, n: usize) -> String {
    ctx.t(if n == 1 { one } else { many })
        .replace("{n}", &n.to_string())
}

fn last_checked(ctx: &Ctx) -> Option<String> {
    let at = ctx.checked_at?;
    let secs = crate::app::history::now().saturating_sub(at);
    Some(match secs {
        0..=59 => ctx.t("Last checked just now"),
        60..=3599 => count_text(
            ctx,
            "Last checked {n} minute ago",
            "Last checked {n} minutes ago",
            (secs / 60) as usize,
        ),
        3600..=86399 => count_text(
            ctx,
            "Last checked {n} hour ago",
            "Last checked {n} hours ago",
            (secs / 3600) as usize,
        ),
        _ => count_text(
            ctx,
            "Last checked {n} day ago",
            "Last checked {n} days ago",
            (secs / 86400) as usize,
        ),
    })
}

fn assessed<'a>(state: &State, ctx: &'a Ctx, report: &'a Report) -> Element<'a, Message> {
    let p = ctx.palette;
    let score = Score::of(report);
    let mut items = score::to_check(report);
    // After a failed check the report is stale: never claim protection from it
    // and offer no fix that cannot open.
    let stale = ctx.check_error.is_some();
    let (ids, split) = if stale {
        (
            Vec::new(),
            Split {
                fixable: 0,
                choices: 0,
                manual: items.len(),
            },
        )
    } else {
        split(report, &ctx.catalog.available, &mut items)
    };
    let verdict = if stale {
        Verdict::Unknown
    } else {
        score::overall(report)
    };
    let attention = items.len().max(1);
    let fixable = split.fixable;
    let (tone, title, subtitle) = match verdict {
        Verdict::Protected => (
            Tone::Good,
            ctx.t("You're protected"),
            ctx.t("Everything we checked is switched on and working."),
        ),
        Verdict::Attention => {
            let subtitle = if fixable == 0 && split.choices == 0 {
                ctx.t("Each one needs a step from you, and we show you how.")
            } else if fixable == 0 && split.manual == 0 {
                ctx.t("Each one is your choice, and we explain what changes first.")
            } else if fixable == attention {
                if attention == 1 {
                    ctx.t("We can fix it for you, and you can undo it later.")
                } else {
                    ctx.t("We can fix all of them for you, and you can undo it later.")
                }
            } else if fixable > 0 {
                count_text(
                    ctx,
                    "We can fix 1 of them for you, and you can undo it later.",
                    "We can fix {n} of them for you, and you can undo it later.",
                    fixable,
                )
            } else {
                ctx.t("Some are your choice and some need a step from you.")
            };
            (
                Tone::Warn,
                count_text(
                    ctx,
                    "{n} thing needs your attention",
                    "{n} things need your attention",
                    attention,
                ),
                subtitle,
            )
        }
        Verdict::Unknown => (
            Tone::Neutral,
            ctx.t("We couldn't finish checking"),
            ctx.t("Some checks didn't finish. Press Check again."),
        ),
    };

    let protected = i64::try_from(score.protected).unwrap_or(0);
    let shown = if anim::reduced() {
        protected
    } else if let Some(c) = &state.count {
        anim::count_up_int(c.from, c.to, c.clock.progress_at(anim::SLOW, state.now))
    } else if ctx.checked_at != state.seen_check {
        state.shown
    } else {
        protected
    };
    let ring_view = ring::ring(
        ring::Ring {
            p,
            ratio: score.ratio(),
            tone: if !stale && score.total > 0 && score.protected == score.total {
                Tone::Good
            } else {
                tone
            },
            label: shown.to_string(),
            caption: ctx
                .t("of {n} protected")
                .replace("{n}", &score.total.to_string()),
        },
        176.0,
    );

    let check_item = (
        Icon::Refresh,
        ctx.t("Check again"),
        Message::CheckNow,
        false,
    );
    let mut extras: Vec<(Icon, String, Message, bool)> = Vec::new();
    let mut buttons = row![].spacing(theme::S2).align_y(Alignment::Center);
    if ctx.checking.is_some() {
        let elapsed = state
            .scan
            .map(|c| c.elapsed_at(state.now))
            .unwrap_or_default();
        buttons = buttons
            .push(anim::spinner(theme::CHECK, p.text_muted, elapsed))
            .push(widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t("Checking…"),
                None,
                None,
            ));
    } else if verdict == Verdict::Attention
        && fixable > 0
        && flow::repairs_blocked(report).is_none()
    {
        buttons = buttons.push(widgets::action(
            p,
            ButtonKind::Primary,
            count_text(ctx, "Fix it for me", "Fix {n} for me", fixable),
            Some(Icon::Wrench),
            (!ctx.busy).then(|| Message::ReviewFixes(ids.clone())),
        ));
        extras.push(check_item);
    } else if verdict == Verdict::Attention {
        buttons = buttons.push(widgets::action(
            p,
            ButtonKind::Primary,
            ctx.t("See what to do"),
            None,
            Some(Message::Navigate(Page::Fixes)),
        ));
        extras.push(check_item);
    } else {
        buttons = buttons.push(widgets::action(
            p,
            ButtonKind::Primary,
            ctx.t("Check again"),
            Some(Icon::Refresh),
            (!ctx.busy).then_some(Message::CheckNow),
        ));
    }
    if ctx.checking.is_none() && !ctx.busy && !extras.is_empty() {
        buttons = buttons.push(widgets::overflow_menu(p, extras));
    }

    let mut texts = column![widgets::h1(p, title)].spacing(theme::S1);
    if !subtitle.is_empty() {
        texts = texts.push(widgets::muted(p, subtitle));
    }
    if let Some(when) = last_checked(ctx) {
        texts = texts.push(widgets::small(p, when));
    }
    let hero = widgets::region(
        p,
        row![
            ring_view,
            column![texts, buttons]
                .spacing(theme::S6)
                .width(Length::Fill)
        ]
        .spacing(theme::S8)
        .align_y(Alignment::Center),
    );

    let mut page = column![].spacing(theme::S8);
    if ctx.check_error.is_some() {
        page = page.push(widgets::inline_notice(
            p,
            Tone::Warn,
            ctx.t("The last check didn't finish, so this may be out of date."),
        ));
    }
    let later = |i: usize, card: Element<'a, Message>| {
        widgets::appear::settle_after(card, p.bg, widgets::appear::stagger_delay(i))
    };
    page = page.push(later(0, hero.into()));
    for (tone, msg) in readiness_notices(ctx, report) {
        page = page.push(widgets::inline_notice(p, tone, msg));
    }

    if !items.is_empty() {
        page = page.push(later(1, attention_group(ctx, report, &items)));
    }
    if processor_tip_due(ctx) {
        page = page.push(later(2, processor_card(ctx)));
    }
    if shows_web_suggestion(state, secblitz::os::Os::CURRENT) {
        page = page.push(later(2, web_card(ctx)));
    }
    let (count, labels) = protected_labels(report);
    if count > 0 {
        page = page.push(later(3, protected_group(state, ctx, count, &labels)));
    }
    page.into()
}

/// Web protection exists on Windows and Linux.
fn shows_web_suggestion(state: &State, os: secblitz::os::Os) -> bool {
    state.web_suggest && matches!(os, secblitz::os::Os::Windows | secblitz::os::Os::Linux)
}

fn processor_card<'a>(ctx: &'a Ctx) -> Element<'a, Message> {
    let p = ctx.palette;
    widgets::group(
        p,
        ctx.t("Tip"),
        None,
        Some(widgets::action(
            p,
            ButtonKind::Ghost,
            ctx.t("Hide"),
            None,
            Some(Message::Home(Msg::HideProcessorTip)),
        )),
        vec![widgets::row_item(
            p,
            Some(Icon::Download),
            ctx.t("A version made for your computer's processor is available"),
            Some(ctx.t("Your settings and history stay when you switch.")),
            widgets::icon(Icon::ChevronRight, 16.0, p.text_muted),
            Some(Message::Home(Msg::OpenDownload)),
        )],
    )
}

fn web_card<'a>(ctx: &'a Ctx) -> Element<'a, Message> {
    let p = ctx.palette;
    widgets::group(
        p,
        ctx.t("Suggestion"),
        None,
        None,
        vec![widgets::row_item(
            p,
            Some(Icon::Globe),
            ctx.t("Block ads, trackers and dangerous websites"),
            Some(ctx.t("Stops many ads and scam websites before they load.")),
            widgets::icon(Icon::ChevronRight, 16.0, p.text_muted),
            Some(Message::Navigate(Page::Web)),
        )],
    )
}

fn attention_group<'a>(ctx: &'a Ctx, report: &Report, items: &[ToCheck]) -> Element<'a, Message> {
    let p = ctx.palette;
    let mut rows: Vec<Element<'a, Message>> = items
        .iter()
        .take(ATTENTION_ROWS)
        .map(|item| {
            let (id, report_only, title, line) = match item {
                ToCheck::Control(r) => {
                    let a = advice::for_outcome(r);
                    let line = if a.step == NextStep::Repair && !a.impact.is_empty() {
                        format!("{} {}", ctx.t(a.impact_prefix()), ctx.t(a.impact))
                    } else {
                        ctx.t(a.next)
                    };
                    (
                        r.id.as_str(),
                        false,
                        ctx.t(advice::control_label(&r.id)),
                        line,
                    )
                }
                ToCheck::Finding(f) => {
                    let a = score::finding_advice(report, f);
                    (f.title.as_str(), true, ctx.t(a.label), ctx.t(a.next))
                }
            };
            let sheet = widgets::info::for_check(ctx, title.clone(), id, report_only)
                .map(|s| s.without(&[line.as_str()]));
            let head = widgets::row_item_tinted(
                p,
                Some(Icon::AlertTriangle),
                Some(Tone::Warn),
                title,
                Some(line),
                widgets::icon(Icon::ChevronRight, 16.0, p.text_muted),
                Some(Message::Navigate(Page::Fixes)),
            );
            match widgets::info::button(ctx, sheet) {
                Some(info) => row![head, info]
                    .spacing(theme::S1)
                    .align_y(Alignment::Center)
                    .into(),
                None => head,
            }
        })
        .collect();
    if items.len() > ATTENTION_ROWS {
        rows.push(widgets::show_more_button(
            p,
            count_text(
                ctx,
                "See {n} more",
                "See {n} more",
                items.len() - ATTENTION_ROWS,
            ),
            Message::Navigate(Page::Fixes),
        ));
    }
    widgets::group(
        p,
        ctx.t("Needs your attention"),
        None,
        Some(widgets::pill(p, items.len().to_string(), Tone::Warn)),
        rows,
    )
}

fn protected_group<'a>(
    state: &State,
    ctx: &'a Ctx,
    count: usize,
    labels: &[&'static str],
) -> Element<'a, Message> {
    let p = ctx.palette;
    let names: Vec<String> = labels.iter().take(3).map(|l| ctx.t(l)).collect();
    let mut summary = names.join(", ");
    if labels.len() > 3 {
        summary.push('…');
    }
    let shown = widgets::limited(labels, PROTECTED_ROWS, state.protected_all);
    let mut body = column![].spacing(theme::S1);
    for l in shown {
        body = body.push(widgets::row_item_tinted(
            p,
            Some(Icon::ShieldCheck),
            Some(Tone::Good),
            ctx.t(l),
            None,
            iced::widget::space::horizontal(),
            None,
        ));
    }
    if labels.len() > PROTECTED_ROWS {
        body = body.push(widgets::show_more_button(
            p,
            if state.protected_all {
                ctx.t("Show less")
            } else {
                count_text(
                    ctx,
                    "Show {n} more",
                    "Show {n} more",
                    labels.len() - PROTECTED_ROWS,
                )
            },
            Message::Home(Msg::ToggleProtectedAll),
        ));
    }
    widgets::collapsible(
        p,
        ctx.t("Protected"),
        Some(format!("{count} · {summary}")),
        state.protected_open,
        Message::Home(Msg::ToggleProtected),
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use secblitz::engine::Outcome;

    #[test]
    fn the_processor_tip_shows_only_on_an_x64_build_on_an_arm_pc_until_seen() {
        assert!(tip_due(true, false));
        assert!(!tip_due(true, true));
        assert!(!tip_due(false, false));
        assert!(!tip_due(false, true));
    }

    #[test]
    fn only_the_hide_button_records_the_processor_tip_as_seen() {
        let mut prefs = crate::app::settings::Prefs::default();
        assert!(tip_due(true, prefs.processor_tip_seen));
        mark_tip_seen(&mut prefs);
        assert!(prefs.processor_tip_seen);
        assert!(!tip_due(true, prefs.processor_tip_seen));
    }

    fn outcome(id: &str, status: &str) -> Outcome {
        Outcome {
            id: id.into(),
            status: status.into(),
            ..Outcome::default()
        }
    }

    #[test]
    fn attention_and_protected_are_split_by_advice_group() {
        let report = Report {
            results: vec![
                outcome("uac.enabled", "compliant"),
                outcome("uac.consent", "attention"),
                outcome("ai.paint", "compliant"),
            ],
            ..Report::default()
        };
        assert_eq!(score::to_check(&report).len(), 1);
        assert_eq!(
            protected_labels(&report).0,
            1,
            "a switched-on extra is not counted"
        );
        assert_eq!(protected_labels(&report).0, Score::of(&report).protected);
    }

    #[test]
    fn the_web_protection_card_is_never_offered_on_a_mac() {
        use secblitz::os::Os;
        let mut state = State::default();
        assert!(!shows_web_suggestion(&state, Os::Windows));
        update_flag(&mut state);
        assert!(shows_web_suggestion(&state, Os::Windows));
        assert!(shows_web_suggestion(&state, Os::Linux));
        assert!(!shows_web_suggestion(&state, Os::Macos));
    }

    fn update_flag(state: &mut State) {
        state.web_suggest = true;
    }

    #[test]
    fn home_card_not_scored() {
        let report = Report {
            results: vec![
                outcome("uac.enabled", "compliant"),
                outcome("uac.consent", "attention"),
            ],
            ..Report::default()
        };
        let before = Score::of(&report);
        let mut state = State::default();
        assert!(!state.web_suggest);
        update_flag(&mut state);
        assert!(state.web_suggest);
        assert_eq!(Score::of(&report), before);
        assert_eq!(score::to_check(&report).len(), 1);
    }

    #[test]
    fn headline_parts_add_up() {
        let report = Report {
            results: vec![
                outcome("uac.consent", "attention"),
                outcome("autorun.disabled", "attention"),
                Outcome {
                    detail: "Preference applied; restart required".into(),
                    ..outcome("uac.enabled", "applied")
                },
            ],
            ..Report::default()
        };
        let available: Vec<String> = ["uac.consent", "autorun.disabled"]
            .map(String::from)
            .to_vec();
        let mut items = score::to_check(&report);
        let (ids, split) = split(&report, &available, &mut items);
        assert_eq!(split.fixable + split.choices + split.manual, items.len());
        assert_eq!(ids.len(), split.fixable);
        assert!(ids.iter().all(|id| !advice::is_choice_check_id(id)));
        let lead: Vec<&str> = items
            .iter()
            .take(ids.len())
            .filter_map(|item| match item {
                ToCheck::Control(r) => Some(r.id.as_str()),
                ToCheck::Finding(_) => None,
            })
            .collect();
        assert_eq!(lead, ids.iter().map(String::as_str).collect::<Vec<_>>());
    }
}
