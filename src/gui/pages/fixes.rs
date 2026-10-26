//! Protection page: every check grouped, attention rows selectable.
use crate::app::flow;
use crate::app::score::{self, Class};
use crate::app::search::{Haystack, Query};
use crate::app::topics::{self, Counts, Line, Topic};
use crate::broker::Reply;
use crate::gui::icons::Icon;
use crate::gui::theme::{self, Palette, Tone};
use crate::gui::widgets::anim;
use crate::gui::widgets::hairline::magnifier::{self, Labels, Magnifier, Status};
use crate::gui::widgets::hairline::Plate;
use crate::gui::widgets::info::InfoSheet;
use crate::gui::widgets::scan;
use crate::gui::widgets::tile::{self, Tile};
use crate::gui::widgets::{self, ButtonKind, CheckState};
use crate::gui::{Ctx, Message};
use crate::guide::{self, Guide, Page};
use crate::i18n::Lang;
use iced::widget::{column, container, row, space, Column};
use iced::{Alignment, Element, Length};
use iced::{Subscription, Task};
use secblitz::advice::{self, Group, NextStep};
use secblitz::engine::Report;
use secblitz::model::CheckStatus;
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

pub const SEARCH_ID: &str = "fixes-search";
const FIRST_ROWS: usize = 8;
const FEW_PROTECTED: usize = 5;
const TICKER_LINES: usize = 6;
const INDENT_PLAIN: f32 = theme::S4 + theme::ICON_ROW + theme::S4;

#[derive(Debug)]
pub struct State {
    synced_at: Option<u64>,
    selected: HashSet<String>,
    /// Settings Secblitz changed that the person ticked to put back. Never filled for them.
    undo_selected: HashSet<String>,
    flipped_protected: HashSet<Topic>,
    open_more: HashSet<Topic>,
    topic: Cell<Option<Topic>>,
    all_attention: bool,
    all_protected: bool,
    search: String,
    cache: RefCell<Option<Cached>>,
    scan: Option<Instant>,
    now: Instant,
    lines: Vec<(String, Instant)>,
    processed: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            synced_at: None,
            selected: HashSet::new(),
            undo_selected: HashSet::new(),
            flipped_protected: HashSet::new(),
            open_more: HashSet::new(),
            topic: Cell::new(None),
            all_attention: false,
            all_protected: false,
            search: String::new(),
            cache: RefCell::new(None),
            scan: None,
            now: Instant::now(),
            lines: Vec::new(),
            processed: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    Toggle(String),
    SelectAll,
    SelectNone,
    ToggleUndo(String),
    UndoSelectAll,
    UndoSelectNone,
    /// Opens the group of protected settings, with the ones Secblitz changed first.
    FocusUndo,
    ShowProtected(Topic),
    ToggleMore(Topic),
    Topic(Topic),
    SelectTopic(Topic),
    SelectNoneTopic(Topic),
    UndoSelectTopic(Topic),
    UndoSelectNoneTopic(Topic),
    ReviewRecommended,
    PutBack,
    AllAttention,
    AllProtected,
    Search(String),
    ClearSearch,
    Frame(Instant),
    Open(Page),
}

#[derive(Debug)]
struct Cached {
    key: (usize, Lang, usize),
    rows: Rows,
}

#[derive(Debug, Default)]
struct Rows {
    attention: Vec<Att>,
    privacy: Vec<Att>,
    others: Vec<Other>,
    protected: Vec<Prot>,
}

/// The rows that match what was typed, in their normal order.
struct Shown<'r> {
    attention: Vec<&'r Att>,
    privacy: Vec<&'r Att>,
    others: Vec<&'r Other>,
    protected: Vec<&'r Prot>,
}

impl Rows {
    fn shown(&self, query: &Query) -> Shown<'_> {
        Shown {
            attention: self
                .attention
                .iter()
                .filter(|r| query.matches(&r.hay))
                .collect(),
            privacy: self
                .privacy
                .iter()
                .filter(|r| query.matches(&r.hay))
                .collect(),
            others: self
                .others
                .iter()
                .filter(|r| query.matches(&r.hay))
                .collect(),
            protected: self
                .protected
                .iter()
                .filter(|r| query.matches(&r.hay))
                .collect(),
        }
    }
}

impl<'r> Shown<'r> {
    fn in_topic(&self, topic: Topic) -> Shown<'r> {
        Shown {
            attention: self
                .attention
                .iter()
                .copied()
                .filter(|r| r.topic == topic)
                .collect(),
            privacy: self
                .privacy
                .iter()
                .copied()
                .filter(|r| r.topic == topic)
                .collect(),
            others: self
                .others
                .iter()
                .copied()
                .filter(|r| r.topic == topic)
                .collect(),
            protected: self
                .protected
                .iter()
                .copied()
                .filter(|r| r.topic == topic)
                .collect(),
        }
    }
}

impl Rows {
    fn counts(&self, topic: Topic) -> Counts {
        let fix = |r: &&Att| r.topic == topic;
        let back = |r: &&Att| r.switched_back;
        Counts {
            to_fix: self
                .attention
                .iter()
                .filter(fix)
                .filter(|r| !back(r))
                .count(),
            to_look: self
                .others
                .iter()
                .filter(|o| o.topic == topic && o.bucket == Bucket::Look)
                .count(),
            switched_back: self
                .attention
                .iter()
                .chain(&self.privacy)
                .filter(fix)
                .filter(back)
                .count(),
            options: self.privacy.iter().filter(fix).filter(|r| !back(r)).count(),
        }
    }

    fn line(&self, topic: Topic) -> Line {
        Line::of(Some(self.counts(topic)))
    }

    fn switched_back(&self) -> Vec<String> {
        self.attention
            .iter()
            .chain(&self.privacy)
            .filter(|r| r.switched_back)
            .map(|r| r.id.clone())
            .collect()
    }

    fn first_topic_to_act_on(&self) -> Option<Topic> {
        topics::first_needing_action(|t| self.line(t))
    }

    fn protected_count(&self, topic: Topic) -> usize {
        self.protected.iter().filter(|r| r.topic == topic).count()
    }
}

impl Shown<'_> {
    fn is_empty(&self) -> bool {
        self.attention.is_empty()
            && self.privacy.is_empty()
            && self.others.is_empty()
            && self.protected.is_empty()
    }

    fn selectable(&self) -> impl Iterator<Item = &str> {
        self.attention
            .iter()
            .chain(&self.privacy)
            .map(|a| a.id.as_str())
    }
}

#[derive(Debug)]
struct Att {
    id: String,
    topic: Topic,
    switched_back: bool,
    name: String,
    line: String,
    restart: bool,
    #[cfg(test)]
    choice: bool,
    info: Option<InfoSheet>,
    hay: Haystack,
}

#[derive(Debug)]
struct Other {
    #[cfg(test)]
    key: String,
    topic: Topic,
    #[cfg(test)]
    explain: String,
    name: String,
    line: String,
    status: String,
    step: NextStep,
    tone: Tone,
    bucket: Bucket,
    icon: Icon,
    info: Option<InfoSheet>,
    guide: Option<&'static Guide>,
    page: Option<Page>,
    hay: Haystack,
}

#[derive(Debug)]
struct Prot {
    id: String,
    topic: Topic,
    name: String,
    line: String,
    /// Secblitz changed this setting and can put it back.
    undoable: bool,
    info: Option<InfoSheet>,
    hay: Haystack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Bucket {
    Look,
    Managed,
    Unavailable,
    GoodToKnow,
}

fn named(ctx: &Ctx, template: &str, names: Option<String>) -> Option<String> {
    names.map(|names| ctx.t(template).replace("{names}", &names))
}

/// The setting's explainer, then what will change and anything new, minus what the row shows.
fn sheet(
    ctx: &Ctx,
    id: &str,
    name: &str,
    report_only: bool,
    changes: Vec<String>,
    more: Vec<String>,
    shown: &[&str],
) -> Option<InfoSheet> {
    let sheet = widgets::info::for_check(ctx, name.to_owned(), id, report_only)
        .unwrap_or_else(|| InfoSheet::new(name))
        .list(ctx.t("What will change"), changes)
        .list(ctx.t("More details"), more)
        .without(shown);
    (!sheet.is_empty()).then_some(sheet)
}

/// What a typed search is compared with: the row as shown, the same row in
/// English (so English words work in every language), and its id.
fn search_text(shown: &[&str], sources: &[&str], id: &str) -> Haystack {
    let english: Vec<String> = sources.iter().map(|s| Lang::En.t(s)).collect();
    Haystack::new(
        shown
            .iter()
            .copied()
            .chain(english.iter().map(String::as_str))
            .chain([id]),
    )
}

fn plain_status(status: &CheckStatus, a: &advice::Advice, lang: Lang) -> (String, String) {
    let (st, next) = crate::app::flow::plain_detail(status, a);
    (lang.t(st), lang.t(next))
}

pub fn items_line(ctx: &Ctx, r: &secblitz::engine::Outcome) -> Option<String> {
    let (key, names) = item_names(r)?;
    let names: Vec<String> = names
        .iter()
        .map(|n| {
            if r.id == "defender.cfa_allowed_apps" {
                app_label(ctx.lang, n)
            } else {
                (*n).to_owned()
            }
        })
        .collect();
    Some(ctx.t(key).replace("{names}", &names.join(", ")))
}

/// The helper writes who published a blocked app in English after its path, as "path (note)".
fn app_label(lang: Lang, label: &str) -> String {
    let Some((path, note)) = label.strip_suffix(')').and_then(|l| l.rsplit_once(" (")) else {
        return label.to_owned();
    };
    let note = match note.strip_prefix("by ") {
        Some(who) => lang.t("by {name}").replace("{name}", who),
        None => lang.t(note),
    };
    format!("{path} ({note})")
}

fn item_names(r: &secblitz::engine::Outcome) -> Option<(&'static str, Vec<&str>)> {
    let (key, kind) = match r.id.as_str() {
        "accounts.stale_enabled" => ("Accounts: {names}", "account"),
        "smb.shares_exposed" => ("Folders: {names}", "share"),
        "defender.cfa_allowed_apps" => ("Apps: {names}", "app"),
        _ => return None,
    };
    let mut names: Vec<&str> = Vec::new();
    for item in r.items.iter().filter(|i| i.kind == kind) {
        if !names.contains(&item.name.as_str()) {
            names.push(&item.name);
        }
    }
    (!names.is_empty()).then_some((key, names))
}

fn build(ctx: &Ctx, report: &Report) -> Rows {
    let lang = ctx.lang;
    let mut rows = Rows::default();
    let fixable = candidates(ctx);

    for id in &fixable {
        let Some(r) = report.results.iter().find(|r| r.id == *id) else {
            continue;
        };
        let a = advice::for_outcome(r);
        let impact = advice::control_impact(id);
        let choice = advice::is_choice_check_id(id);
        let line = if choice || impact.is_empty() {
            match items_line(ctx, r) {
                Some(items) => format!("{}\n{}", ctx.t(a.next), items),
                None => ctx.t(a.next),
            }
        } else {
            format!("{} {}", ctx.t(a.impact_prefix()), ctx.t(impact))
        };
        let restart = ctx.catalog.restart.iter().any(|x| x == id)
            || r.detail.to_lowercase().contains("restart");
        let list = if score::classify(r) == Class::Excluded {
            &mut rows.privacy
        } else {
            &mut rows.attention
        };
        let name = lang.control(id);
        let hay = search_text(
            &[&name, &line, &ctx.t(impact)],
            &[advice::control_label(id), a.next, impact],
            id,
        );
        let (status, next) = plain_status(&r.status, &a, lang);
        let (back, restart_text) = (ctx.t("Switched back"), ctx.t("Restart needed"));
        let mut shown = vec![line.as_str(), status.as_str()];
        if r.switched_back {
            shown.push(&back);
        }
        if restart {
            shown.push(&restart_text);
        }
        let info = sheet(
            ctx,
            id,
            &name,
            false,
            item_lines(ctx, &r.items),
            vec![next],
            &shown,
        );
        list.push(Att {
            id: id.clone(),
            topic: Topic::of(id),
            switched_back: r.switched_back,
            name,
            line,
            restart,
            #[cfg(test)]
            choice,
            info,
            hay,
        });
    }

    for r in &report.results {
        if fixable.contains(&r.id) {
            continue;
        }
        let class = score::classify_in(report, r);
        if class == Class::Excluded
            && secblitz::vbs::is_vbs_check_id(&r.id)
            && score::classify(r) == Class::Protected
        {
            continue;
        }
        let a = advice::for_outcome(r);
        if class == Class::Protected {
            let impact = advice::control_impact(&r.id);
            let line = if impact.is_empty() {
                ctx.t(a.next)
            } else {
                format!("{} {}", ctx.t(a.impact_prefix()), ctx.t(impact))
            };
            let name = lang.control(&r.id);
            let hay = search_text(
                &[&name, &line, &ctx.t(impact)],
                &[advice::control_label(&r.id), a.next, impact],
                &r.id,
            );
            let info = sheet(ctx, &r.id, &name, false, Vec::new(), Vec::new(), &[&line]);
            rows.protected.push(Prot {
                id: r.id.clone(),
                topic: Topic::of(&r.id),
                name,
                line,
                undoable: r.undoable,
                info,
                hay,
            });
            continue;
        }
        let (bucket, tone) = if class == Class::Managed {
            (Bucket::Managed, Tone::Neutral)
        } else if class == Class::Excluded {
            (Bucket::GoodToKnow, Tone::Neutral)
        } else if class == Class::Unknown {
            (Bucket::Unavailable, Tone::Neutral)
        } else {
            (Bucket::Look, Tone::Warn)
        };
        let finding_listed = report.findings.iter().any(|f| {
            advice::control_for_finding(&f.title) == Some(r.id.as_str())
                && !score::finding_has_fix(report, f)
        });
        rows.others.push(other(
            ctx,
            &a,
            OtherSource {
                #[cfg(test)]
                index: rows.others.len(),
                topic: Topic::of(&r.id),
                explain: (r.id.as_str(), false),
                name: lang.control(&r.id),
                name_source: advice::control_label(&r.id),
                bucket,
                tone,
                more: vec![
                    plain_status(&r.status, &a, lang).1,
                    named(
                        ctx,
                        "Drivers we were unsure about: {names}",
                        secblitz::vbs::reason_names(&r.detail),
                    )
                    .unwrap_or_default(),
                ],
                detail: if finding_listed {
                    None
                } else {
                    Some(r.detail.as_str())
                },
            },
        ));
    }
    rows.protected.sort_by_key(|r| !r.undoable);
    for f in &report.findings {
        if score::finding_has_fix(report, f) {
            continue;
        }
        let a = score::finding_advice(report, f);
        if a.group == Group::Protected {
            continue;
        }
        let (bucket, tone) = match score::classify_finding(f) {
            Class::Managed => (Bucket::Managed, Tone::Neutral),
            Class::Excluded => (Bucket::GoodToKnow, Tone::Neutral),
            Class::Unknown => (Bucket::Unavailable, Tone::Neutral),
            Class::Protected | Class::Fixable | Class::Review => (Bucket::Look, Tone::Warn),
        };
        let row = other(
            ctx,
            &a,
            OtherSource {
                #[cfg(test)]
                index: rows.others.len(),
                topic: Topic::of_finding(&f.title),
                explain: (f.title.as_str(), true),
                name: ctx.t(a.label),
                name_source: a.label,
                bucket,
                tone,
                more: vec![
                    plain_status(&f.status, &a, lang).1,
                    named(
                        ctx,
                        "Windows blocked: {names}",
                        secblitz::vbs::blocked_names(&f.detail),
                    )
                    .unwrap_or_default(),
                ],
                detail: None,
            },
        );
        rows.others.push(row);
    }
    rows
}

struct OtherSource<'a> {
    #[cfg(test)]
    index: usize,
    topic: Topic,
    explain: (&'a str, bool),
    name: String,
    name_source: &'a str,
    bucket: Bucket,
    tone: Tone,
    more: Vec<String>,
    detail: Option<&'a str>,
}

fn other(ctx: &Ctx, a: &advice::Advice, source: OtherSource<'_>) -> Other {
    let OtherSource {
        #[cfg(test)]
        index,
        topic,
        explain,
        name,
        name_source,
        bucket,
        tone,
        more,
        detail,
    } = source;
    let managed = bucket == Bucket::Managed;
    let restart_finding = explain.1 && a.step == NextStep::Restart;
    let guide = match bucket {
        _ if restart_finding => None,
        Bucket::Look => guide::guide(explain.0),
        Bucket::GoodToKnow => detail.and_then(|d| guide::guide_not_offered(explain.0, d)),
        _ => None,
    };
    let page = if restart_finding {
        None
    } else {
        other_page(bucket, explain, guide, a.step)
    };
    let icon = match bucket {
        Bucket::Managed => Icon::Lock,
        Bucket::Unavailable => Icon::Info,
        Bucket::GoodToKnow => Icon::Info,
        Bucket::Look => Icon::AlertTriangle,
    };
    let line = match other_line(bucket, guide.is_some(), a) {
        _ if restart_finding => ctx.t(a.next),
        (Some(prefix), text) => format!("{} {}", ctx.t(prefix), ctx.t(text)),
        (None, text) => ctx.t(text),
    };
    let status = if restart_finding {
        ctx.t(a.status)
    } else if managed {
        ctx.t("For your information")
    } else if guide.is_some() && bucket == Bucket::Look {
        ctx.t("To do")
    } else {
        ctx.t(a.status)
    };
    let info = sheet(
        ctx,
        explain.0,
        &name,
        explain.1,
        Vec::new(),
        more,
        &[&line, &status],
    );
    let hay = search_text(
        &[&name, &line, &ctx.t(a.impact)],
        &[name_source, a.next, a.impact],
        explain.0,
    );
    Other {
        #[cfg(test)]
        key: format!("other:{index}"),
        topic,
        #[cfg(test)]
        explain: explain.0.to_owned(),
        name,
        line,
        status,
        step: if managed { NextStep::None } else { a.step },
        tone,
        bucket,
        icon,
        info,
        guide,
        page,
        hay,
    }
}

fn other_line(
    bucket: Bucket,
    has_guide: bool,
    a: &advice::Advice,
) -> (Option<&'static str>, &'static str) {
    if bucket == Bucket::Managed {
        (
            None,
            "This PC's owner controls this setting, so we leave it as it is.",
        )
    } else if has_guide && bucket == Bucket::Look && !a.impact.is_empty() {
        (Some("Turning it on protects you from:"), a.impact)
    } else {
        (None, a.next)
    }
}

fn other_page(
    bucket: Bucket,
    explain: (&str, bool),
    guide: Option<&guide::Guide>,
    step: NextStep,
) -> Option<Page> {
    match bucket {
        Bucket::Look => guide
            .map(|g| g.page)
            .or_else(|| Page::for_finding(explain.0))
            .or_else(|| Page::for_step(step)),
        Bucket::GoodToKnow if explain.1 => {
            Page::for_finding(explain.0).or_else(|| Page::for_step(step))
        }
        Bucket::GoodToKnow => guide.map(|g| g.page),
        _ => None,
    }
}

fn ensure(state: &State, ctx: &Ctx, report: &Arc<Report>) {
    let key = (
        Arc::as_ptr(report) as usize,
        ctx.lang,
        ctx.catalog.available.len(),
    );
    let mut cache = state.cache.borrow_mut();
    if cache.as_ref().is_some_and(|c| c.key == key) {
        return;
    }
    *cache = Some(Cached {
        key,
        rows: build(ctx, report),
    });
}

fn item_lines(ctx: &Ctx, items: &[secblitz::model::ItemLabel]) -> Vec<String> {
    items
        .iter()
        .filter(|item| !matches!(item.kind.as_str(), "account" | "share" | "app"))
        .map(|item| match item.kind.as_str() {
            "skip_missing" => format!(
                "{}: {}. {}",
                ctx.t("Left alone"),
                item.name,
                ctx.t("Its program file could not be found.")
            ),
            "skip_shadow" => format!(
                "{}: {}. {}",
                ctx.t("Left alone"),
                item.name,
                ctx.t("A file that could be started instead was found. Run a virus scan from the Tools page.")
            ),
            "more" => format!("{}: {}", ctx.t("More items not listed"), item.name),
            "addon" => {
                let mut parts = vec![
                    item.name.clone(),
                    if item.key.starts_with("chromium:edge:") {
                        "Edge"
                    } else {
                        "Chrome"
                    }
                    .to_owned(),
                ];
                for why in item.why.split(',') {
                    parts.push(match why {
                        "sites" => ctx.t("Can read every site you visit"),
                        "programs" => ctx.t("Can talk to other programs on your PC"),
                        _ => continue,
                    });
                }
                format!("{}: {}", ctx.t("Browser add-on"), parts.join(" · "))
            }
            kind => {
                let kind = match kind {
                    "service" => "Background program",
                    "rule" => "Firewall rule",
                    "startup" => "Start-up entry",
                    "task" => "Scheduled task",
                    _ => "Hosts file line",
                };
                format!("{}: {}", ctx.t(kind), item.name)
            }
        })
        .collect()
}

fn candidates(ctx: &Ctx) -> Vec<String> {
    ctx.report
        .as_deref()
        .map(|r| flow::candidates(r, &ctx.catalog.available))
        .unwrap_or_default()
}

fn starting_choice(ctx: &Ctx) -> Vec<String> {
    ctx.report
        .as_deref()
        .map(|r| topics::default_selection(r, &ctx.catalog.available))
        .unwrap_or_default()
}

fn sync(state: &mut State, ctx: &Ctx) {
    if state.synced_at != ctx.checked_at || state.synced_at.is_none() {
        state.synced_at = ctx.checked_at;
        state.selected = starting_choice(ctx).into_iter().collect();
        let undoable = |id: &String| {
            ctx.report
                .as_deref()
                .is_some_and(|r| r.results.iter().any(|o| o.id == *id && o.undoable))
        };
        state.undo_selected.retain(undoable);
    }
}

fn selection(state: &State, ctx: &Ctx, all: &[String]) -> Vec<String> {
    if state.synced_at == ctx.checked_at && ctx.checked_at.is_some() {
        all.iter()
            .filter(|id| state.selected.contains(*id))
            .cloned()
            .collect()
    } else {
        let recommended = starting_choice(ctx);
        all.iter()
            .filter(|id| recommended.contains(*id))
            .cloned()
            .collect()
    }
}

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    sync(state, ctx);
    match msg {
        Msg::Toggle(id) => {
            if !state.selected.remove(&id) && candidates(ctx).contains(&id) {
                state.selected.insert(id);
            }
        }
        Msg::SelectAll if !searching(state) => {
            state.selected = candidates(ctx).into_iter().collect();
        }
        Msg::SelectAll => state.selected.extend(visible_candidates(state, ctx)),
        Msg::SelectNone if !searching(state) => state.selected.clear(),
        Msg::SelectNone => {
            for id in visible_candidates(state, ctx) {
                state.selected.remove(&id);
            }
        }
        Msg::ToggleUndo(id) => {
            if !state.undo_selected.remove(&id) && undoable_ids(state, ctx).contains(&id) {
                state.undo_selected.insert(id);
            }
        }
        Msg::UndoSelectAll if !searching(state) => {
            state.undo_selected = undoable_ids(state, ctx).into_iter().collect();
        }
        Msg::UndoSelectAll => {
            let shown = visible_undoable(state, ctx);
            state.undo_selected.extend(shown);
        }
        Msg::UndoSelectNone if !searching(state) => state.undo_selected.clear(),
        Msg::UndoSelectNone => {
            for id in visible_undoable(state, ctx) {
                state.undo_selected.remove(&id);
            }
        }
        Msg::FocusUndo => {
            state.search.clear();
            focus_undo(state, ctx);
        }
        Msg::SelectTopic(topic) => {
            let ids = topic_candidates(state, ctx, topic);
            state.selected.extend(ids);
        }
        Msg::SelectNoneTopic(topic) => {
            for id in topic_candidates(state, ctx, topic) {
                state.selected.remove(&id);
            }
        }
        Msg::UndoSelectTopic(topic) => {
            let ids = topic_undoable(state, ctx, topic);
            state.undo_selected.extend(ids);
        }
        Msg::UndoSelectNoneTopic(topic) => {
            for id in topic_undoable(state, ctx, topic) {
                state.undo_selected.remove(&id);
            }
        }
        Msg::Topic(topic) => {
            state.topic.set(Some(topic));
            if ctx.prefs.protection_topic != Some(topic) {
                ctx.prefs.protection_topic = Some(topic);
                return Task::perform(crate::gui::save_prefs(ctx.prefs.clone()), |_| Message::Noop);
            }
        }
        Msg::ReviewRecommended => {
            let ids = flow::recommended(
                ctx.report.as_deref().unwrap_or(&Report::default()),
                &ctx.catalog.available,
            );
            state.selected.extend(ids);
            return Task::done(Message::ReviewFixes(chosen_in_order(state, ctx)));
        }
        Msg::PutBack => {
            let ids = switched_back_ids(state, ctx);
            state.selected.extend(ids.iter().cloned());
            return Task::done(Message::ReviewFixes(ids));
        }
        Msg::Search(text) => state.search = text,
        Msg::ClearSearch => {
            state.search.clear();
            return iced::widget::operation::focus(SEARCH_ID);
        }
        Msg::ShowProtected(topic) => flip_topic(&mut state.flipped_protected, topic),
        Msg::ToggleMore(topic) => flip_topic(&mut state.open_more, topic),
        Msg::AllAttention => state.all_attention = !state.all_attention,
        Msg::AllProtected => state.all_protected = !state.all_protected,
        Msg::Frame(now) => track_scan(state, ctx, now),
        Msg::Open(page) => return open_page(ctx, page),
    }
    Task::none()
}

/// The ids of the fixable rows that match the search.
fn visible_candidates(state: &State, ctx: &Ctx) -> Vec<String> {
    let Some(report) = ctx.report.as_ref() else {
        return Vec::new();
    };
    ensure(state, ctx, report);
    let cache = state.cache.borrow();
    let rows = &cache.as_ref().expect("filled by ensure").rows;
    let shown = rows.shown(&Query::new(&state.search));
    shown.selectable().map(str::to_owned).collect()
}

/// The protected settings Secblitz changed, whatever the search says.
fn undoable_ids(state: &State, ctx: &Ctx) -> Vec<String> {
    let Some(report) = ctx.report.as_ref() else {
        return Vec::new();
    };
    ensure(state, ctx, report);
    let cache = state.cache.borrow();
    let rows = &cache.as_ref().expect("filled by ensure").rows;
    rows.protected
        .iter()
        .filter(|r| r.undoable)
        .map(|r| r.id.clone())
        .collect()
}

/// The same, limited to the rows that match the search.
fn visible_undoable(state: &State, ctx: &Ctx) -> Vec<String> {
    let Some(report) = ctx.report.as_ref() else {
        return Vec::new();
    };
    ensure(state, ctx, report);
    let cache = state.cache.borrow();
    let rows = &cache.as_ref().expect("filled by ensure").rows;
    rows.shown(&Query::new(&state.search))
        .protected
        .iter()
        .filter(|r| r.undoable)
        .map(|r| r.id.clone())
        .collect()
}

fn flip_topic(set: &mut HashSet<Topic>, topic: Topic) {
    if !set.remove(&topic) {
        set.insert(topic);
    }
}

fn with_rows<T>(state: &State, ctx: &Ctx, read: impl FnOnce(&Rows) -> T) -> Option<T> {
    let report = ctx.report.as_ref()?;
    ensure(state, ctx, report);
    let cache = state.cache.borrow();
    Some(read(&cache.as_ref().expect("filled by ensure").rows))
}

fn protected_open(state: &State, topic: Topic, count: usize) -> bool {
    (count <= FEW_PROTECTED) != state.flipped_protected.contains(&topic)
}

fn focus_undo(state: &mut State, ctx: &Ctx) {
    let found = with_rows(state, ctx, |rows| {
        let topic = Topic::ALL
            .into_iter()
            .find(|t| rows.protected.iter().any(|r| r.undoable && r.topic == *t))?;
        Some((topic, rows.protected_count(topic)))
    })
    .flatten();
    if let Some((topic, count)) = found {
        state.topic.set(Some(topic));
        if !protected_open(state, topic, count) {
            flip_topic(&mut state.flipped_protected, topic);
        }
    }
}

fn topic_candidates(state: &State, ctx: &Ctx, topic: Topic) -> Vec<String> {
    with_rows(state, ctx, |rows| {
        rows.attention
            .iter()
            .chain(&rows.privacy)
            .filter(|r| r.topic == topic)
            .map(|r| r.id.clone())
            .collect()
    })
    .unwrap_or_default()
}

fn topic_undoable(state: &State, ctx: &Ctx, topic: Topic) -> Vec<String> {
    with_rows(state, ctx, |rows| {
        rows.protected
            .iter()
            .filter(|r| r.undoable && r.topic == topic)
            .map(|r| r.id.clone())
            .collect()
    })
    .unwrap_or_default()
}

fn switched_back_ids(state: &State, ctx: &Ctx) -> Vec<String> {
    with_rows(state, ctx, Rows::switched_back).unwrap_or_default()
}

fn chosen_in_order(state: &State, ctx: &Ctx) -> Vec<String> {
    candidates(ctx)
        .into_iter()
        .filter(|id| state.selected.contains(id))
        .collect()
}

#[cfg(test)]
pub fn undo_selected_ids(state: &State) -> Vec<String> {
    let mut ids: Vec<String> = state.undo_selected.iter().cloned().collect();
    ids.sort();
    ids
}

#[cfg(test)]
pub fn shown_undoable(state: &State, ctx: &Ctx) -> Vec<String> {
    visible_undoable(state, ctx)
}

#[cfg(test)]
pub fn all_undoable(state: &State, ctx: &Ctx) -> Vec<String> {
    undoable_ids(state, ctx)
}

#[cfg(test)]
pub fn open_protected(state: &State, ctx: &Ctx) -> bool {
    let Some(topic) = state.topic.get() else {
        return false;
    };
    with_rows(state, ctx, |rows| {
        protected_open(state, topic, rows.protected_count(topic))
    })
    .unwrap_or(false)
}

pub fn topic_on_show(state: &State) -> Option<Topic> {
    state.topic.get()
}

/// The keys of every row on screen, section by section.
#[cfg(test)]
pub fn visible_rows(state: &State, ctx: &Ctx) -> Vec<String> {
    let Some(report) = ctx.report.as_ref() else {
        return Vec::new();
    };
    ensure(state, ctx, report);
    let cache = state.cache.borrow();
    let rows = &cache.as_ref().expect("filled by ensure").rows;
    let shown = rows.shown(&Query::new(&state.search));
    let mut keys: Vec<String> = shown.selectable().map(str::to_owned).collect();
    keys.extend(shown.others.iter().map(|o| o.explain.clone()));
    keys.extend(shown.protected.iter().map(|r| r.id.clone()));
    keys
}

#[cfg(test)]
pub fn rows_by_topic(state: &State, ctx: &Ctx) -> Vec<(Topic, String)> {
    with_rows(state, ctx, |rows| {
        let mut out: Vec<(Topic, String)> = Vec::new();
        out.extend(rows.attention.iter().map(|r| (r.topic, r.id.clone())));
        out.extend(rows.privacy.iter().map(|r| (r.topic, r.id.clone())));
        out.extend(rows.others.iter().map(|r| (r.topic, r.key.clone())));
        out.extend(rows.protected.iter().map(|r| (r.topic, r.id.clone())));
        out
    })
    .unwrap_or_default()
}

#[cfg(test)]
pub fn tile_lines(state: &State, ctx: &Ctx) -> Vec<(Topic, Line)> {
    with_rows(state, ctx, |rows| {
        Topic::ALL.into_iter().map(|t| (t, rows.line(t))).collect()
    })
    .unwrap_or_default()
}

#[cfg(test)]
pub fn first_topic_for_test(state: &State, ctx: &Ctx) -> Option<Topic> {
    with_rows(state, ctx, Rows::first_topic_to_act_on).flatten()
}

#[cfg(test)]
pub fn chosen_in_topic(state: &State, ctx: &Ctx, topic: Topic) -> Vec<String> {
    with_rows(state, ctx, |rows| chosen_in(state, ctx, rows, Some(topic))).unwrap_or_default()
}

#[cfg(test)]
pub fn banner_ids(state: &State, ctx: &Ctx) -> Vec<String> {
    switched_back_ids(state, ctx)
}

#[cfg(test)]
pub fn selected_ids(state: &State) -> Vec<String> {
    let mut ids: Vec<String> = state.selected.iter().cloned().collect();
    ids.sort();
    ids
}

#[cfg(test)]
pub fn shown_fixable(state: &State, ctx: &Ctx) -> Vec<String> {
    visible_candidates(state, ctx)
}

pub fn escape(state: &mut State) {
    state.search.clear();
}

fn searching(state: &State) -> bool {
    !Query::new(&state.search).is_empty()
}

/// Whether the page has its search box on screen right now.
pub fn shows_search(ctx: &Ctx) -> bool {
    ctx.engine_error.is_none() && !fills_window(ctx) && ctx.report.is_some()
}

fn track_scan(state: &mut State, ctx: &Ctx, now: Instant) {
    state.now = now;
    let Some(progress) = &ctx.checking else {
        state.scan = None;
        state.lines.clear();
        state.processed = 0;
        return;
    };
    if state.scan.is_none() {
        state.scan = Some(now);
        state.lines = vec![(ctx.t("Looking at your settings…"), now)];
        state.processed = 0;
    }
    if state.processed > progress.items.len() {
        state.processed = 0;
    }
    for (id, _) in progress.items.iter().skip(state.processed) {
        let label = ctx.t(advice::control_label(id));
        if state.lines.last().is_none_or(|(l, _)| *l != label) {
            state.lines.push((label, now));
        }
    }
    state.processed = progress.items.len();
    let extra = state.lines.len().saturating_sub(TICKER_LINES);
    state.lines.drain(..extra);
}

pub fn open_page(ctx: &Ctx, page: Page) -> Task<Message> {
    ctx.broker_task(page.request(), move |reply| {
        Message::PageOpened(page, matches!(reply, Ok(Reply::Done | Reply::OpenedStore)))
    })
}

pub fn row_text<'a>(p: Palette, title: String, line: Option<String>) -> Element<'a, Message> {
    let mut c = column![iced::widget::text(title)
        .size(theme::BODY)
        .font(theme::MEDIUM)
        .color(p.text)]
    .spacing(theme::S1)
    .width(Length::Fill);
    if let Some(l) = line {
        c = c.push(widgets::small(p, l));
    }
    c.into()
}

fn line<'a>(
    lead: Option<Element<'a, Message>>,
    content: Element<'a, Message>,
    trailing: Element<'a, Message>,
) -> Element<'a, Message> {
    let mut r = row![].spacing(theme::S1).align_y(Alignment::Center);
    if let Some(l) = lead {
        r = r.push(container(l).padding([0.0, theme::S2]));
    }
    r.push(content).push(trailing).into()
}

pub fn guide_block<'a>(
    ctx: &Ctx,
    g: &'static Guide,
    indent: f32,
    buttons: bool,
) -> Element<'a, Message> {
    let p = ctx.palette;
    let mut steps = column![].spacing(theme::S1);
    for (i, step) in g.steps.iter().enumerate() {
        steps = steps.push(widgets::small(p, format!("{}. {}", i + 1, ctx.t(step))));
    }
    let open = |page: Page, kind: ButtonKind| {
        widgets::action(
            p,
            kind,
            ctx.t(page.button()),
            Some(Icon::ExternalLink),
            Some(Message::Fixes(Msg::Open(page))),
        )
    };
    let mut body = column![steps].spacing(theme::S3).width(Length::Fill);
    if buttons {
        let mut bar = row![open(g.page, ButtonKind::Secondary)]
            .spacing(theme::S2)
            .align_y(Alignment::Center);
        if let Some(alt) = g.alt {
            bar = bar.push(open(alt, ButtonKind::Ghost));
        }
        body = body.push(bar);
    }
    row![space::horizontal().width(indent), body].into()
}

fn nothing<'a>() -> Element<'a, Message> {
    space::horizontal().width(0.0).into()
}

fn attention_row<'a>(
    ctx: &Ctx,
    a: &Att,
    checked: bool,
    restart_label: &str,
    extra: bool,
) -> Element<'a, Message> {
    let p = ctx.palette;
    let trailing: Element<'a, Message> = if a.switched_back {
        widgets::pill(p, ctx.t("Switched back"), Tone::Warn)
    } else if a.restart {
        widgets::tag(p, Some(Icon::Restart), restart_label.to_owned())
    } else {
        nothing()
    };
    let toggle = Message::Fixes(Msg::Toggle(a.id.clone()));
    let mut tools = row![].spacing(theme::S1).align_y(Alignment::Center);
    if let Some(t) = widgets::info::button(ctx, a.info.clone()) {
        tools = tools.push(t);
    }
    let head = line(
        Some(widgets::checkbox(
            p,
            CheckState::from(checked),
            None,
            Some(toggle.clone()),
        )),
        widgets::row_item_tinted(
            p,
            Some(if extra {
                Icon::Eye
            } else {
                Icon::AlertTriangle
            }),
            Some(if extra { Tone::Neutral } else { Tone::Warn }),
            a.name.clone(),
            Some(a.line.clone()),
            trailing,
            Some(toggle),
        ),
        tools.into(),
    );
    head
}

fn other_row<'a>(ctx: &Ctx, o: &Other) -> Element<'a, Message> {
    let p = ctx.palette;
    let mut tools = row![].spacing(theme::S1).align_y(Alignment::Center);
    if let Some(t) = widgets::info::button(ctx, o.info.clone()) {
        tools = tools.push(t);
    }
    if o.bucket == Bucket::Unavailable || o.step == NextStep::CheckAgain {
        tools = tools.push(widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("Check again"),
            Some(Icon::Refresh),
            (!ctx.busy && ctx.checking.is_none()).then_some(Message::CheckNow),
        ));
    } else if o.step == NextStep::ReviewUndo {
        tools = tools.push(widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("Undo…"),
            Some(Icon::Undo),
            (!ctx.busy).then_some(Message::ReviewUndo),
        ));
    } else if o.step == NextStep::OpenHistory {
        tools = tools.push(widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("Open History"),
            Some(Icon::History),
            Some(Message::Navigate(crate::gui::Page::History)),
        ));
    }
    let page_bar = match (o.bucket, o.step, o.page, o.guide) {
        (Bucket::Unavailable, ..)
        | (_, NextStep::CheckAgain | NextStep::ReviewUndo | NextStep::OpenHistory, ..) => None,
        (_, _, Some(page), None) => Some(row![
            space::horizontal().width(INDENT_PLAIN),
            widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t(page.button()),
                Some(Icon::ExternalLink),
                Some(Message::Fixes(Msg::Open(page))),
            )
        ]),
        _ => None,
    };
    let head = line(
        None,
        widgets::row_item_tinted(
            p,
            Some(o.icon),
            Some(o.tone),
            o.name.clone(),
            Some(o.line.clone()),
            widgets::pill(p, o.status.clone(), o.tone),
            None,
        ),
        tools.into(),
    );
    let mut rows = column![head].spacing(theme::S1);
    if let Some(g) = o.guide {
        rows = rows.push(guide_block(ctx, g, INDENT_PLAIN, true));
    }
    if let Some(bar) = page_bar {
        rows = rows.push(bar);
    }
    rows.into()
}

fn protected_row<'a>(ctx: &Ctx, r: &Prot) -> Element<'a, Message> {
    let p = ctx.palette;
    let head = widgets::row_item_tinted(
        p,
        Some(Icon::Check),
        Some(Tone::Good),
        r.name.clone(),
        Some(r.line.clone()),
        nothing(),
        None,
    );
    line(
        None,
        head,
        widgets::info::button(ctx, r.info.clone()).unwrap_or_else(nothing),
    )
}

fn undoable_row<'a>(ctx: &Ctx, r: &Prot, checked: bool, tag: &str) -> Element<'a, Message> {
    let p = ctx.palette;
    let ready = !ctx.busy && ctx.checking.is_none() && ctx.check_error.is_none();
    let toggle = Message::Fixes(Msg::ToggleUndo(r.id.clone()));
    let mut tools = row![].spacing(theme::S1).align_y(Alignment::Center);
    if let Some(t) = widgets::info::button(ctx, r.info.clone()) {
        tools = tools.push(t);
    }
    tools = tools.push(widgets::action(
        p,
        ButtonKind::Ghost,
        ctx.t("Undo…"),
        Some(Icon::Undo),
        ready.then(|| Message::ReviewUndoSome(vec![r.id.clone()])),
    ));
    let head = line(
        Some(widgets::checkbox(
            p,
            CheckState::from(checked),
            None,
            Some(toggle.clone()),
        )),
        widgets::row_item_tinted(
            p,
            Some(Icon::Check),
            Some(Tone::Good),
            r.name.clone(),
            Some(r.line.clone()),
            widgets::tag(p, Some(Icon::Wrench), tag.to_owned()),
            Some(toggle),
        ),
        tools.into(),
    );
    head
}

fn more<'a>(ctx: &Ctx, total: usize, all: bool, msg: Msg) -> Option<Element<'a, Message>> {
    (total > FIRST_ROWS).then(|| {
        let label = if all {
            ctx.t("Show less")
        } else {
            ctx.t("See {n} more")
                .replace("{n}", &(total - FIRST_ROWS).to_string())
        };
        widgets::show_more_button(ctx.palette, label, Message::Fixes(msg))
    })
}

fn count_text(ctx: &Ctx, n: usize) -> String {
    if n == 1 {
        ctx.t("1 item")
    } else {
        ctx.t("{n} items").replace("{n}", &n.to_string())
    }
}

fn check_status(ctx: &Ctx) -> (f32, String) {
    let seen = ctx.checking.as_ref().map_or(0, |c| c.items.len());
    let (done, total, ratio) = if ctx.finishing {
        let all = ctx.catalog.available.len().max(seen);
        (all, all, 1.0)
    } else {
        let total = ctx.catalog.available.len().max(seen + 1);
        (seen, total, (seen as f32 / total as f32).min(0.96))
    };
    let sub = if done > 0 {
        ctx.t("{a} of {b} checked")
            .replace("{a}", &done.to_string())
            .replace("{b}", &total.to_string())
    } else {
        ctx.t("This takes about a minute. Nothing is changed.")
    };
    (ratio, sub)
}

fn check_art(state: &State, ctx: &Ctx, plate: Plate, ratio: f32) -> Magnifier {
    Magnifier {
        p: ctx.palette,
        plate,
        status: if ctx.finishing {
            Status::Done
        } else {
            Status::Checking
        },
        progress: (!ctx.catalog.available.is_empty()).then_some(ratio),
        changed: state.scan.unwrap_or(state.now),
        now: state.now,
        labels: Labels::new(|s| ctx.t(s)),
    }
}

fn first_check<'a>(state: &'a State, ctx: &'a Ctx) -> Element<'a, Message> {
    let (ratio, sub) = check_status(ctx);
    scan::checking_screen(
        ctx.palette,
        ctx.t("Checking your PC"),
        sub,
        ratio,
        check_art(state, ctx, Plate::Bg, ratio),
        scan::Feed {
            lines: &state.lines,
            now: state.now,
            finished: ctx.finishing,
        },
    )
}

fn checking_region<'a>(state: &'a State, ctx: &'a Ctx) -> Element<'a, Message> {
    let p = ctx.palette;
    let (ratio, sub) = check_status(ctx);
    let live = anim::animating();
    let mut text = column![
        widgets::h2(p, ctx.t("Checking your PC")),
        widgets::muted(p, sub)
    ]
    .spacing(theme::S1)
    .width(Length::Fill);
    if live {
        text = text
            .push(space::vertical().height(theme::S2))
            .push(scan::status_ticker(p, &state.lines, state.now, false));
    }
    let content = row![
        check_art(state, ctx, Plate::Surface, ratio).view(magnifier::COMPACT),
        text,
    ]
    .spacing(theme::S6)
    .align_y(Alignment::Center);
    widgets::region(p, content).into()
}

pub fn subscription(ctx: &Ctx) -> Subscription<Message> {
    if ctx.checking.is_some() && anim::animating() {
        iced::window::frames().map(|now| Message::Fixes(Msg::Frame(now)))
    } else {
        Subscription::none()
    }
}

pub fn fills_window(ctx: &Ctx) -> bool {
    ctx.engine_error.is_none() && ctx.full_check().is_some()
}

pub fn view<'a>(
    state: &'a State,
    ctx: &'a Ctx,
    access: &'a super::app_access::State,
) -> Element<'a, Message> {
    let p = ctx.palette;
    let to_check = ctx
        .report
        .as_deref()
        .filter(|_| ctx.checking.is_none())
        .map_or(0, score::to_check_count);
    let subtitle = if to_check > 0 {
        ctx.t("To check ({n})")
            .replace("{n}", &to_check.to_string())
    } else {
        ctx.t("Everything we check on your PC, in plain words.")
    };
    let header = widgets::page_header(p, ctx.t("Protection"), Some(subtitle));
    let bar = shows_search(ctx).then(|| search_bar(state, ctx));
    let page =
        |strips: Vec<Element<'a, Message>>, body: Column<'a, Message>| -> Element<'a, Message> {
            // iced keeps widget state by position, so the strips share one slot and the
            // search box keeps its focus when they disappear on the first typed letter.
            let strips = strips.into_iter().fold(column![], |col, strip| {
                col.push(strip).push(space::vertical().height(theme::S3))
            });
            let mut top = column![header, space::vertical().height(theme::S4), strips];
            if let Some(bar) = bar {
                top = top.push(bar).push(space::vertical().height(theme::S6));
            }
            top.push(body).into()
        };
    let mut body = column![].spacing(theme::S8);

    if let Some(info) = &ctx.damage {
        return page(Vec::new(), body.push(super::recovery::card(ctx, info)));
    }
    if let Some(error) = &ctx.engine_error {
        return page(
            Vec::new(),
            body.push(widgets::region(
                p,
                widgets::empty_state(
                    p,
                    Icon::ShieldAlert,
                    ctx.t("We couldn't start the protection check"),
                    ctx.t(
                        "Close Secblitz and open it again. If this keeps happening, restart your PC.",
                    ),
                    Some(error_details(
                        ctx,
                        "We couldn't start the protection check",
                        error,
                    )),
                ),
            )),
        );
    }

    if fills_window(ctx) {
        return page(
            Vec::new(),
            column![first_check(state, ctx)].height(Length::Fill),
        );
    }
    let Some(report) = ctx.report.as_ref() else {
        if let Some(error) = &ctx.check_error {
            return page(Vec::new(), body.push(check_failed(ctx, error)));
        }
        return page(Vec::new(), body.push(not_checked(ctx)));
    };

    ensure(state, ctx, report);
    let cache = state.cache.borrow();
    let rows = &cache.as_ref().expect("filled by ensure").rows;
    let query = Query::new(&state.search);
    let shown = rows.shown(&query);
    let narrowed = !query.is_empty();
    let topic = current_topic(state, ctx, rows);

    if ctx.checking.is_some() {
        body = body.push(checking_region(state, ctx));
    } else if ctx.check_error.is_some() {
        body = body.push(widgets::inline_notice(
            p,
            Tone::Warn,
            ctx.t("We couldn't refresh the check. You're seeing the last result we could confirm."),
        ));
    }
    if report
        .results
        .iter()
        .any(|r| r.status == CheckStatus::Pending)
        || report
            .findings
            .iter()
            .any(|f| f.status == CheckStatus::Pending)
    {
        body = body.push(unfinished_change(ctx));
    }
    if let Some(sentence) = flow::repairs_blocked(report) {
        body = body.push(widgets::inline_notice(p, Tone::Warn, ctx.t(sentence)));
    }

    let mut strips = Vec::new();
    if narrowed {
        if shown.is_empty() {
            body = body.push(widgets::region(p, no_matches(ctx, &state.search)));
        } else {
            let mut results = column![].spacing(theme::S8);
            if shown.selectable().next().is_some() {
                results = results.push(search_bar_controls(state, ctx, report, rows, &shown));
            }
            for t in Topic::ALL {
                let part = shown.in_topic(t);
                if part.is_empty() {
                    continue;
                }
                let mut section = column![container(widgets::h2(
                    p,
                    ctx.t(t.display_label(secblitz::os::Os::CURRENT))
                ))
                .padding([0.0, theme::S4])]
                .spacing(theme::S3);
                for group in topic_groups(state, ctx, rows, &part, t, true) {
                    section = section.push(group);
                }
                results = results.push(section);
            }
            body = body.push(results);
        }
    } else {
        let ready = ready_to_change(ctx, report);
        let back = rows.switched_back().len();
        if back > 0 {
            strips.push(switched_back_strip(ctx, back, ready));
        }
        let recommended = flow::recommended(report, &ctx.catalog.available).len();
        if recommended > 0 {
            strips.push(review_strip(ctx, recommended, ready));
        }
        body = body.push(tile::grid(p, tiles(ctx, rows, topic)));
        let part = shown.in_topic(topic);
        let title = widgets::h2(p, ctx.t(topic.display_label(secblitz::os::Os::CURRENT)));
        let head: Element<'_, Message> = if part.selectable().next().is_some() {
            let (count, buttons) = fix_controls(state, ctx, report, rows, &part, Some(topic));
            row![
                column![title, widgets::small(p, count)]
                    .spacing(theme::S1)
                    .width(Length::Fill),
                buttons,
            ]
            .spacing(theme::S3)
            .align_y(Alignment::Center)
            .into()
        } else {
            title
        };
        let head = container(head).padding([0.0, theme::S4]);
        let mut section = column![head].spacing(theme::S3);
        if topic == Topic::Privacy {
            section = section.push(super::app_access::view(access, ctx));
        }
        let mut groups = topic_groups(state, ctx, rows, &part, topic, false).into_iter();
        if let Some(first) = groups.next() {
            section = section.push(first);
        }
        body = body.push(section);
        for (i, group) in groups.enumerate() {
            body = body.push(widgets::appear::settle_after(
                group,
                p.bg,
                widgets::appear::stagger_delay(i),
            ));
        }
    }
    page(strips, body)
}

/// The first result shown opens the first topic with something to act on, otherwise the one viewed last.
fn current_topic(state: &State, ctx: &Ctx, rows: &Rows) -> Topic {
    if let Some(topic) = state.topic.get() {
        return topic;
    }
    let topic = rows
        .first_topic_to_act_on()
        .or(ctx.prefs.protection_topic)
        .unwrap_or(Topic::Threats);
    state.topic.set(Some(topic));
    topic
}

fn ready_to_change(ctx: &Ctx, report: &Report) -> bool {
    !ctx.busy
        && ctx.checking.is_none()
        && ctx.check_error.is_none()
        && flow::repairs_blocked(report).is_none()
}

fn topic_icon(topic: Topic) -> Icon {
    match topic {
        Topic::Threats => Icon::Shield,
        Topic::SignIn => Icon::Key,
        Topic::Network => Icon::Wifi,
        Topic::Windows => Icon::Desktop,
        Topic::Browsers => Icon::Globe,
        Topic::Privacy => Icon::Eye,
        Topic::Ai => Icon::Bot,
        Topic::Clutter => Icon::Apps,
    }
}

fn line_text(ctx: &Ctx, line: Line) -> String {
    match line {
        Line::ToFix(n) => ctx.t("{n} to fix").replace("{n}", &n.to_string()),
        Line::SwitchedBack(n) => ctx.t("{n} switched back").replace("{n}", &n.to_string()),
        Line::ToLookAt(n) => ctx.t("{n} to look at").replace("{n}", &n.to_string()),
        Line::Options(1) => ctx.t("1 option"),
        Line::Options(n) => ctx.t("{n} options").replace("{n}", &n.to_string()),
        Line::AllSet => ctx.t("All set"),
        Line::Checking => ctx.t("Checking…"),
    }
}

fn line_tone(line: Line) -> Tone {
    match line {
        Line::ToFix(_) | Line::SwitchedBack(_) => Tone::Warn,
        Line::AllSet => Tone::Good,
        Line::ToLookAt(_) | Line::Options(_) | Line::Checking => Tone::Neutral,
    }
}

fn tiles(ctx: &Ctx, rows: &Rows, on_show: Topic) -> Vec<Tile> {
    Topic::ALL
        .into_iter()
        .map(|topic| {
            let line = rows.line(topic);
            Tile {
                glyph: topic_icon(topic),
                title: ctx.t(topic.display_label(secblitz::os::Os::CURRENT)),
                status: line_text(ctx, line),
                tone: line_tone(line),
                done: line == Line::AllSet,
                selected: topic == on_show,
                on_press: Message::Fixes(Msg::Topic(topic)),
            }
        })
        .collect()
}

fn strip<'a>(
    ctx: &Ctx,
    tone: Tone,
    glyph: Icon,
    text: String,
    button: Element<'a, Message>,
) -> Element<'a, Message> {
    let p = ctx.palette;
    let tint = p.tint(tone);
    container(
        row![
            widgets::icon(glyph, 18.0, p.tone(tone)),
            iced::widget::text(text)
                .size(theme::BODY)
                .font(theme::REGULAR)
                .color(p.text)
                .width(Length::Fill),
            button,
        ]
        .spacing(theme::S3)
        .align_y(Alignment::Center),
    )
    .padding(iced::Padding {
        top: theme::S2,
        right: theme::S3,
        bottom: theme::S2,
        left: theme::S4,
    })
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(iced::Background::Color(tint)),
        border: iced::Border {
            radius: theme::R.into(),
            ..iced::Border::default()
        },
        ..container::Style::default()
    })
    .into()
}

fn switched_back_strip<'a>(ctx: &Ctx, n: usize, ready: bool) -> Element<'a, Message> {
    let (text, label) = if n == 1 {
        (
            ctx.t("1 setting was switched back since Secblitz fixed it."),
            ctx.t("Put it back"),
        )
    } else {
        (
            ctx.t("{n} settings were switched back since Secblitz fixed them.")
                .replace("{n}", &n.to_string()),
            ctx.t("Put them back"),
        )
    };
    let button = widgets::action(
        ctx.palette,
        ButtonKind::Secondary,
        label,
        Some(Icon::Undo),
        ready.then_some(Message::Fixes(Msg::PutBack)),
    );
    strip(ctx, Tone::Warn, Icon::AlertTriangle, text, button)
}

fn review_strip<'a>(ctx: &Ctx, n: usize, ready: bool) -> Element<'a, Message> {
    let text = if n == 1 {
        ctx.t("1 recommended fix")
    } else {
        ctx.t("{n} recommended fixes")
            .replace("{n}", &n.to_string())
    };
    let button = widgets::action(
        ctx.palette,
        ButtonKind::Primary,
        ctx.t("Review fixes"),
        Some(Icon::Wrench),
        ready.then_some(Message::Fixes(Msg::ReviewRecommended)),
    );
    strip(ctx, Tone::Neutral, Icon::ShieldCheck, text, button)
}

fn search_bar<'a>(state: &State, ctx: &Ctx) -> Element<'a, Message> {
    widgets::search_field(
        ctx.palette,
        SEARCH_ID,
        &ctx.t("Search settings"),
        &state.search,
        |text| Message::Fixes(Msg::Search(text)),
        Message::Fixes(Msg::ClearSearch),
    )
}

fn no_matches<'a>(ctx: &Ctx, typed: &str) -> Element<'a, Message> {
    widgets::no_matches(ctx, typed, Message::Fixes(Msg::ClearSearch))
}

fn error_details<'a>(ctx: &Ctx, title: &str, error: &str) -> Element<'a, Message> {
    let sheet = InfoSheet::new(ctx.t(title)).text(
        ctx.t("More details"),
        ctx.t(crate::app::flow::plain_failure(error)),
    );
    widgets::info::link(ctx, ctx.t("More details"), Some(sheet)).unwrap_or_else(nothing)
}

fn not_checked<'a>(ctx: &Ctx) -> Element<'a, Message> {
    let p = ctx.palette;
    widgets::region(
        p,
        widgets::empty_state(
            p,
            Icon::ShieldCheck,
            ctx.t("Not checked yet"),
            ctx.t("Check your PC to see what's protected. Nothing is changed."),
            Some(widgets::action(
                p,
                ButtonKind::Primary,
                ctx.t("Check my PC"),
                Some(Icon::Refresh),
                (!ctx.busy).then_some(Message::CheckNow),
            )),
        ),
    )
    .into()
}

fn check_failed<'a>(ctx: &Ctx, error: &str) -> Element<'a, Message> {
    let p = ctx.palette;
    let again = widgets::action(
        p,
        ButtonKind::Primary,
        ctx.t("Check again"),
        Some(Icon::Refresh),
        (ctx.checking.is_none() && !ctx.busy).then_some(Message::CheckNow),
    );
    widgets::region(
        p,
        widgets::empty_state(
            p,
            Icon::ShieldAlert,
            ctx.t("We couldn't finish checking"),
            ctx.t("Nothing was changed. Press Check again. If it keeps failing, restart your PC."),
            Some(
                column![
                    again,
                    error_details(ctx, "We couldn't finish checking", error)
                ]
                .spacing(theme::S3)
                .align_x(Alignment::Center)
                .into(),
            ),
        ),
    )
    .into()
}

fn unfinished_change<'a>(ctx: &Ctx) -> Element<'a, Message> {
    let p = ctx.palette;
    widgets::row_item_tinted(
        p,
        Some(Icon::Undo),
        Some(Tone::Warn),
        ctx.t("An earlier change isn't finished"),
        Some(ctx.t("Undo your last fixes before making new ones.")),
        widgets::action(
            p,
            ButtonKind::Secondary,
            ctx.t("Undo"),
            None,
            (!ctx.busy).then_some(Message::ReviewUndo),
        ),
        None,
    )
}

/// The chosen fixes in one topic, or in every topic when `topic` is `None`.
fn chosen_in(state: &State, ctx: &Ctx, rows: &Rows, topic: Option<Topic>) -> Vec<String> {
    let all: Vec<String> = rows
        .attention
        .iter()
        .chain(&rows.privacy)
        .filter(|a| topic.is_none_or(|t| a.topic == t))
        .map(|a| a.id.clone())
        .collect();
    selection(state, ctx, &all)
}

/// `scope` is `None` while searching; the buttons then act on the rows the search shows.
fn fix_controls<'a>(
    state: &State,
    ctx: &Ctx,
    report: &Report,
    rows: &Rows,
    shown: &Shown,
    scope: Option<Topic>,
) -> (String, Element<'a, Message>) {
    let narrowed = searching(state);
    let p = ctx.palette;
    let topic = scope.filter(|_| !narrowed);
    let chosen = chosen_in(state, ctx, rows, topic);
    let n = chosen.len();
    let hidden = if narrowed {
        let on_screen: HashSet<&str> = shown.selectable().collect();
        chosen
            .iter()
            .filter(|id| !on_screen.contains(id.as_str()))
            .count()
    } else {
        0
    };
    let count = match n {
        0 => ctx.t("Nothing selected"),
        _ if hidden > 0 => ctx
            .t("{n} selected, {k} hidden by search")
            .replace("{n}", &n.to_string())
            .replace("{k}", &hidden.to_string()),
        1 => ctx.t("1 selected"),
        _ => ctx.t("{n} selected").replace("{n}", &n.to_string()),
    };
    let label = match n {
        0 => ctx.t("Fix selected"),
        1 => ctx.t("Fix 1 selected"),
        _ => ctx.t("Fix {n} selected").replace("{n}", &n.to_string()),
    };
    let fix = widgets::action(
        p,
        ButtonKind::Primary,
        label,
        Some(Icon::Wrench),
        (ready_to_change(ctx, report) && n > 0).then(|| Message::ReviewFixes(chosen.clone())),
    );
    let mut buttons = row![fix].spacing(theme::S1).align_y(Alignment::Center);
    let in_scope: Vec<&str> = match topic {
        Some(topic) => rows
            .attention
            .iter()
            .chain(&rows.privacy)
            .filter(|a| a.topic == topic)
            .map(|a| a.id.as_str())
            .collect(),
        None => shown.selectable().collect(),
    };
    if !in_scope.is_empty() {
        let every = in_scope.iter().all(|id| chosen.iter().any(|c| c == id));
        let item = match (topic, every) {
            (Some(t), true) => (
                Icon::X,
                ctx.t("Select none"),
                Message::Fixes(Msg::SelectNoneTopic(t)),
            ),
            (Some(t), false) => (
                Icon::Check,
                ctx.t("Select all"),
                Message::Fixes(Msg::SelectTopic(t)),
            ),
            (None, true) => (
                Icon::X,
                ctx.t("Select none"),
                Message::Fixes(Msg::SelectNone),
            ),
            (None, false) => (
                Icon::Check,
                ctx.t("Select all"),
                Message::Fixes(Msg::SelectAll),
            ),
        };
        buttons = buttons.push(widgets::overflow_menu(
            p,
            vec![(item.0, item.1, item.2, false)],
        ));
    }
    (count, buttons.into())
}

fn search_bar_controls<'a>(
    state: &State,
    ctx: &Ctx,
    report: &Report,
    rows: &Rows,
    shown: &Shown,
) -> Element<'a, Message> {
    let (count, buttons) = fix_controls(state, ctx, report, rows, shown, None);
    container(
        row![
            widgets::muted(ctx.palette, count),
            space::horizontal(),
            buttons
        ]
        .spacing(theme::S3)
        .align_y(Alignment::Center),
    )
    .padding([0.0, theme::S4])
    .into()
}

fn topic_groups<'a>(
    state: &'a State,
    ctx: &'a Ctx,
    rows: &Rows,
    shown: &Shown,
    topic: Topic,
    narrowed: bool,
) -> Vec<Element<'a, Message>> {
    let p = ctx.palette;
    let all: Vec<String> = rows
        .attention
        .iter()
        .chain(&rows.privacy)
        .map(|a| a.id.clone())
        .collect();
    let chosen = selection(state, ctx, &all);
    let restart_label = ctx.t("Restart needed");
    let rows_of = |list: &[&Att], extra: bool| -> Vec<Element<'a, Message>> {
        list.iter()
            .map(|a| attention_row(ctx, a, chosen.contains(&a.id), &restart_label, extra))
            .collect()
    };
    let look: Vec<&Other> = shown
        .others
        .iter()
        .copied()
        .filter(|o| o.bucket == Bucket::Look)
        .collect();
    let mut groups = Vec::new();
    if shown.attention.is_empty()
        && shown.privacy.is_empty()
        && look.is_empty()
        && ctx.checking.is_none()
        && !narrowed
    {
        groups.push(widgets::inline_notice(
            p,
            Tone::Good,
            ctx.t("Nothing needs fixing right now"),
        ));
    }
    if !shown.attention.is_empty() {
        let visible = widgets::limited(
            &shown.attention,
            FIRST_ROWS,
            state.all_attention || narrowed,
        );
        let mut list = rows_of(visible, false);
        if let Some(m) = more(
            ctx,
            shown.attention.len(),
            state.all_attention,
            Msg::AllAttention,
        )
        .filter(|_| !narrowed)
        {
            list.push(m);
        }
        groups.push(widgets::group(
            p,
            ctx.t("Needs your attention"),
            None,
            None,
            list,
        ));
    }
    if !look.is_empty() {
        groups.push(widgets::group(
            p,
            ctx.t("Worth a look"),
            Some(ctx.t("You do these in Windows itself. We show the steps.")),
            None,
            look.iter().map(|o| other_row(ctx, o)).collect(),
        ));
    }
    if !shown.privacy.is_empty() {
        groups.push(widgets::group(
            p,
            ctx.t("Your choices"),
            Some(ctx.t("None of these are chosen for you, and they don't change your score.")),
            None,
            rows_of(&shown.privacy, true),
        ));
    }
    if let Some(group) = more_group(state, ctx, shown, topic, narrowed) {
        groups.push(group);
    }
    if !shown.protected.is_empty() {
        groups.push(protected_group(state, ctx, rows, shown, topic, narrowed));
    }
    if topic == Topic::Clutter && !narrowed {
        groups.push(widgets::row_item(
            p,
            Some(Icon::Apps),
            ctx.t("More in Clean up apps"),
            Some(ctx.t("Remove apps you don't use.")),
            widgets::icon(Icon::ChevronRight, 16.0, p.text_muted),
            Some(Message::Navigate(crate::gui::Page::Debloat)),
        ));
    }
    if topic == Topic::Ai && !narrowed && ctx.copilot_installed {
        groups.push(widgets::row_item_tinted(
            p,
            Some(Icon::Apps),
            None,
            ctx.t("The Copilot app is installed"),
            Some(ctx.t("You can remove it in Clean up apps and bring it back later.")),
            widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t("Open Clean up apps"),
                None,
                Some(Message::OpenCleanUp(
                    crate::gui::pages::debloat::COPILOT_APP,
                )),
            ),
            None,
        ));
    }
    groups
}

fn more_group<'a>(
    state: &State,
    ctx: &Ctx,
    shown: &Shown,
    topic: Topic,
    narrowed: bool,
) -> Option<Element<'a, Message>> {
    let p = ctx.palette;
    let mut total = 0;
    let mut body = column![].spacing(theme::S1);
    for (bucket, title) in [
        (Bucket::Unavailable, "Can't check right now"),
        (Bucket::Managed, "Managed elsewhere"),
        (Bucket::GoodToKnow, "Left alone"),
    ] {
        let list: Vec<&&Other> = shown.others.iter().filter(|o| o.bucket == bucket).collect();
        if list.is_empty() {
            continue;
        }
        total += list.len();
        body = body.push(
            container(widgets::section_label(p, ctx.t(title))).padding([theme::S2, theme::S4]),
        );
        for o in list {
            body = body.push(other_row(ctx, o));
        }
    }
    (total > 0).then(|| {
        widgets::collapsible(
            p,
            ctx.t("Good to know"),
            Some(count_text(ctx, total)),
            narrowed || state.open_more.contains(&topic),
            Message::Fixes(Msg::ToggleMore(topic)),
            body,
        )
    })
}

fn protected_group<'a>(
    state: &State,
    ctx: &Ctx,
    rows: &Rows,
    shown: &Shown,
    topic: Topic,
    narrowed: bool,
) -> Element<'a, Message> {
    let p = ctx.palette;
    let undoable: Vec<&Prot> = rows
        .protected
        .iter()
        .filter(|r| r.undoable && r.topic == topic)
        .collect();
    let chosen: Vec<String> = undoable
        .iter()
        .filter(|r| state.undo_selected.contains(&r.id))
        .map(|r| r.id.clone())
        .collect();
    let n = chosen.len();
    let tag = ctx.t("Changed by Secblitz");
    let open = narrowed || protected_open(state, topic, rows.protected_count(topic));
    let visible = widgets::limited(
        &shown.protected,
        FIRST_ROWS,
        state.all_protected || narrowed,
    );
    let mut list = column![].spacing(theme::S1);
    let offers_undo = shown.protected.iter().any(|r| r.undoable);
    if offers_undo {
        list = list
            .push(widgets::muted(
                p,
                ctx.t("You can put any setting Secblitz changed back the way it was."),
            ))
            .push(widgets::small(
                p,
                ctx.t("Personal settings you changed are on the Tools page."),
            ));
    }
    for r in visible {
        list = list.push(if r.undoable {
            undoable_row(ctx, r, state.undo_selected.contains(&r.id), &tag)
        } else {
            protected_row(ctx, r)
        });
    }
    if let Some(m) = more(
        ctx,
        shown.protected.len(),
        state.all_protected,
        Msg::AllProtected,
    )
    .filter(|_| !narrowed)
    {
        list = list.push(m);
    }
    let mut summary = count_text(ctx, shown.protected.len());
    if n > 0 {
        let on_screen: HashSet<&str> = shown
            .protected
            .iter()
            .filter(|r| r.undoable)
            .map(|r| r.id.as_str())
            .collect();
        let hidden = chosen
            .iter()
            .filter(|id| !on_screen.contains(id.as_str()))
            .count();
        let picked = if narrowed && hidden > 0 {
            ctx.t("{n} selected, {k} hidden by search")
                .replace("{n}", &n.to_string())
                .replace("{k}", &hidden.to_string())
        } else if n == 1 {
            ctx.t("1 selected")
        } else {
            ctx.t("{n} selected").replace("{n}", &n.to_string())
        };
        summary = format!("{summary} · {picked}");
    }
    let trailing = offers_undo.then(|| {
        let ready = !ctx.busy && ctx.checking.is_none() && ctx.check_error.is_none();
        let every_shown_chosen = shown
            .protected
            .iter()
            .filter(|r| r.undoable)
            .all(|r| state.undo_selected.contains(&r.id));
        let select = if (narrowed && every_shown_chosen) || (!narrowed && n == undoable.len()) {
            (
                Icon::X,
                ctx.t("Select none"),
                Message::Fixes(if narrowed {
                    Msg::UndoSelectNone
                } else {
                    Msg::UndoSelectNoneTopic(topic)
                }),
            )
        } else {
            (
                Icon::Check,
                ctx.t("Select all"),
                Message::Fixes(if narrowed {
                    Msg::UndoSelectAll
                } else {
                    Msg::UndoSelectTopic(topic)
                }),
            )
        };
        row![
            widgets::action(
                p,
                ButtonKind::Secondary,
                ctx.t("Undo selected"),
                Some(Icon::Undo),
                (ready && n > 0).then(|| Message::ReviewUndoSome(chosen.clone())),
            ),
            widgets::overflow_menu(p, vec![(select.0, select.1, select.2, false)]),
        ]
        .spacing(theme::S1)
        .align_y(Alignment::Center)
        .into()
    });
    widgets::collapsible_with(
        p,
        ctx.t("Already protected"),
        Some(summary),
        open,
        Message::Fixes(Msg::ShowProtected(topic)),
        trailing,
        list,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn who_published_an_allowed_app_is_said_in_the_chosen_language() {
        assert_eq!(
            app_label(Lang::De, r"C:\Users\Public\NoteWriter2.exe (not signed)"),
            r"C:\Users\Public\NoteWriter2.exe (nicht signiert)"
        );
        assert_eq!(
            app_label(
                Lang::Fr,
                r"C:\Program Files (x86)\Tool\tool.exe (by Example Ltd)"
            ),
            r"C:\Program Files (x86)\Tool\tool.exe (par Example Ltd)"
        );
        assert_eq!(
            app_label(
                Lang::Es,
                r"C:\Users\a\Downloads\x.exe (not signed, in a temporary or download folder)"
            ),
            r"C:\Users\a\Downloads\x.exe (sin firma, en una carpeta temporal o de descargas)"
        );
        assert_eq!(
            app_label(Lang::It, r"C:\a\b.exe (signature not valid)"),
            r"C:\a\b.exe (firma non valida)"
        );
        assert_eq!(
            app_label(Lang::Pt, r"C:\Program Files (x86)\b.exe"),
            r"C:\Program Files (x86)\b.exe"
        );
    }

    fn test_ctx() -> Ctx {
        let (app, _) = crate::gui::App::new(crate::gui::Options {
            lang: Lang::En,
            broker: None,
            start: None,
        });
        app.ctx
    }

    fn report_with(status: &str) -> Report {
        Report {
            results: secblitz::hardening::all()
                .iter()
                .map(|spec| secblitz::engine::Outcome {
                    id: spec.id.into(),
                    title: spec.title.into(),
                    status: status.into(),
                    detail: spec.description.into(),
                    ..secblitz::engine::Outcome::default()
                })
                .collect(),
            ..Report::default()
        }
    }

    fn assert_clean(who: &str, sheet: &Option<InfoSheet>, shown: &[&str]) {
        let Some(sheet) = sheet else { return };
        let mut seen: Vec<String> = shown
            .iter()
            .flat_map(|s| s.lines())
            .map(str::to_owned)
            .collect();
        let mut check = |text: &str| {
            assert!(!text.trim().is_empty(), "{who}: an empty line");
            let same = |s: &String| {
                let (a, b) = (s.trim().to_lowercase(), text.trim().to_lowercase());
                a == b || (a.split(' ').count() >= 2 && b.contains(&a) && b.len() < a.len() * 2)
            };
            assert!(!seen.iter().any(same), "{who}: {text:?} is said twice");
            seen.push(text.to_owned());
        };
        assert!(!sheet.is_empty(), "{who}: an empty sheet");
        for block in &sheet.blocks {
            match block {
                widgets::info::InfoBlock::Text { label, body } => {
                    assert!(!label.trim().is_empty(), "{who}: a block without a label");
                    check(body);
                }
                widgets::info::InfoBlock::List { label, items } => {
                    assert!(!label.trim().is_empty(), "{who}: a list without a label");
                    assert!(!items.is_empty(), "{who}: an empty list");
                    items.iter().for_each(|i| check(i));
                }
            }
        }
    }

    #[test]
    fn a_row_dialog_never_repeats_the_row_the_pill_or_itself() {
        let mut ctx = test_ctx();
        let mut choices = 0;
        for status in ["attention", "compliant", "applied", "skipped", "unknown"] {
            let report = report_with(status);
            ctx.catalog.available = report.results.iter().map(|r| r.id.clone()).collect();
            ctx.report = Some(Arc::new(report));
            let report = ctx.report.clone().unwrap();
            let rows = build(&ctx, &report);
            for a in rows.attention.iter().chain(&rows.privacy) {
                let r = report.results.iter().find(|r| r.id == a.id).unwrap();
                let status = plain_status(&r.status, &advice::for_outcome(r), Lang::En).0;
                let mut shown = vec![a.line.as_str(), status.as_str()];
                if a.choice {
                    choices += 1;
                    assert_eq!(status, "Your choice", "{}", a.id);
                    shown.push("Your choice");
                }
                assert_clean(&a.id, &a.info, &shown);
                let pill = status.trim().to_lowercase();
                if let Some(sheet) = &a.info {
                    let text = format!("{:?}", sheet.blocks).to_lowercase();
                    assert!(
                        !text.contains(&format!("\"{pill}\"")),
                        "{}: the status {pill:?} is in the dialog",
                        a.id
                    );
                }
            }
            for o in &rows.others {
                assert_clean(&o.name, &o.info, &[&o.line, &o.status]);
            }
            for r in &rows.protected {
                assert_clean(&r.id, &r.info, &[&r.line]);
            }
        }
        assert!(choices > 0, "no choice check was built");
    }

    #[test]
    fn a_choice_row_gets_no_dialog_that_only_says_your_choice() {
        let mut ctx = test_ctx();
        let report = report_with("attention");
        ctx.catalog.available = report.results.iter().map(|r| r.id.clone()).collect();
        let rows = build(&ctx, &Arc::new(report));
        for a in rows
            .attention
            .iter()
            .chain(&rows.privacy)
            .filter(|a| a.choice)
        {
            let text = format!("{:?}", a.info).to_lowercase();
            assert!(!text.contains("your choice"), "{}", a.id);
        }
    }

    #[test]
    fn accounts_and_folders_are_named_once_and_only_on_their_rows() {
        use secblitz::model::ItemLabel;
        let label = |kind: &str, name: &str| ItemLabel {
            kind: kind.into(),
            name: name.into(),
            ..ItemLabel::default()
        };
        let outcome = |id: &str, items: Vec<ItemLabel>| secblitz::engine::Outcome {
            id: id.into(),
            status: CheckStatus::Attention,
            items,
            ..secblitz::engine::Outcome::default()
        };
        let r = outcome(
            "accounts.stale_enabled",
            vec![
                label("account", "bob"),
                label("account", "amy"),
                label("more", "3"),
            ],
        );
        assert_eq!(
            item_names(&r),
            Some(("Accounts: {names}", vec!["bob", "amy"]))
        );
        let r = outcome(
            "smb.shares_exposed",
            vec![
                label("share", "Photos"),
                label("share", "Photos"),
                label("share", "Work"),
            ],
        );
        assert_eq!(
            item_names(&r),
            Some(("Folders: {names}", vec!["Photos", "Work"]))
        );
        assert_eq!(item_names(&outcome("smb.shares_exposed", vec![])), None);
        let r = outcome("services.unquoted_paths", vec![label("service", "Updater")]);
        assert_eq!(item_names(&r), None);
    }

    #[test]
    fn a_not_offered_row_with_steps_keeps_its_reason() {
        use secblitz::vbs::{DRIVER, MEMORY_INTEGRITY, NEEDS_MEMORY_INTEGRITY, STACK_PROTECTION};
        for (id, detail) in [
            (MEMORY_INTEGRITY, DRIVER.to_owned()),
            (MEMORY_INTEGRITY, format!("{DRIVER}: x.sys")),
            (STACK_PROTECTION, NEEDS_MEMORY_INTEGRITY.to_owned()),
        ] {
            let r = secblitz::engine::Outcome {
                id: id.into(),
                status: CheckStatus::Skipped,
                detail: detail.clone(),
                ..secblitz::engine::Outcome::default()
            };
            let a = advice::for_outcome(&r);
            assert_eq!(a.status, "Not offered", "{detail}");
            assert!(!a.impact.is_empty(), "{detail}");
            assert!(guide::guide_not_offered(id, &detail).is_some(), "{detail}");
            assert_eq!(
                other_line(Bucket::GoodToKnow, true, &a),
                (None, a.next),
                "{detail}"
            );
        }
        let a = advice::for_finding("SMB1", &CheckStatus::Attention, "");
        assert_eq!(
            other_line(Bucket::Look, true, &a),
            (Some("Turning it on protects you from:"), a.impact)
        );
    }

    #[test]
    fn an_information_row_that_names_a_page_opens_it() {
        for (title, page) in [
            ("Security providers", Some(Page::WindowsSecurity)),
            ("Windows lifecycle", Some(Page::WindowsUpdate)),
            ("Windows updates", Some(Page::WindowsUpdate)),
            ("SmartScreen", Some(Page::AppBrowser)),
            (
                "Management and mutation eligibility",
                Some(Page::WorkAccounts),
            ),
            ("Service permissions: BITS", None),
        ] {
            let a = advice::for_finding(title, &CheckStatus::Info, "");
            assert_eq!(
                other_page(Bucket::GoodToKnow, (title, true), None, a.step),
                page,
                "{title}"
            );
        }
        let a = advice::for_control("accounts.autologon", &CheckStatus::Skipped, "");
        assert_eq!(
            other_page(
                Bucket::GoodToKnow,
                ("accounts.autologon", false),
                None,
                a.step
            ),
            None
        );
        let a = advice::for_finding("Windows updates", &CheckStatus::Info, "");
        assert_eq!(
            other_page(Bucket::Managed, ("Windows updates", true), None, a.step),
            None
        );
    }

    #[test]
    fn protected_settings_start_folded_away_only_when_there_are_many() {
        let mut state = State::default();
        for count in 0..=FEW_PROTECTED {
            assert!(protected_open(&state, Topic::Windows, count), "{count}");
        }
        assert!(!protected_open(&state, Topic::Windows, FEW_PROTECTED + 1));
        flip_topic(&mut state.flipped_protected, Topic::Windows);
        assert!(!protected_open(&state, Topic::Windows, 1));
        assert!(protected_open(&state, Topic::Windows, 30));
        assert!(
            protected_open(&state, Topic::Network, 1),
            "other topics keep their own state"
        );
    }
}
