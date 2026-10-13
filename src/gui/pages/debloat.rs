//! Clean up apps: removes the built-in Windows apps from a catalog, never apps the user installed.
use crate::app::search::{Haystack, Query};
use crate::gui::icons::Icon;
use crate::gui::theme::{Palette, Tone};
use crate::gui::widgets::{self, anim, handoff};
use crate::gui::{blocking, blocking_stream, Ctx, Helper, Message};
use iced::widget::image::Handle;
use iced::{Element, Subscription, Task};
use secblitz::debloat::offline::Restored;
use secblitz::debloat::{self, Batch, Group, Installed, ItemResult, Kept, Progress};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

pub const SEARCH_ID: &str = "debloat-search";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Apps,
    Removed,
    Ads,
    Space,
}

#[derive(Debug, Default)]
enum Scan {
    #[default]
    Loading,
    Ready,
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Waiting,
    Saving,
    Working,
    Done(ItemResult, Instant),
}

#[derive(Debug, Default)]
enum Sheet {
    #[default]
    None,
    Review,
    Working(Vec<(u16, Step)>),
    Done(Box<Finished>),
    Delete(u16),
}

#[derive(Debug)]
struct Finished {
    batch: Option<Batch>,
    error: Option<String>,
    policy_ok: Option<bool>,
    user_ok: Option<bool>,
    asked_to_block: bool,
    /// Apps left installed because no copy could be saved first.
    kept: Vec<(u16, Kept)>,
    steps: Vec<(u16, Step)>,
    at: Instant,
}

impl Default for Finished {
    fn default() -> Self {
        Finished {
            batch: None,
            error: None,
            policy_ok: None,
            user_ok: None,
            asked_to_block: false,
            kept: Vec::new(),
            steps: Vec::new(),
            at: Instant::now(),
        }
    }
}

#[derive(Debug)]
pub struct State {
    scan_gen: u32,
    tab: Tab,
    scan: Scan,
    search: String,
    installed: Vec<Installed>,
    selected: BTreeSet<u16>,
    block_again: bool,
    sheet: Sheet,
    open: Vec<Group>,
    expanded: Vec<Group>,
    journal: Vec<Batch>,
    restoring: Option<u16>,
    restoring_copy: bool,
    /// Apps still waiting in a Restore all run, in list order.
    queue: Vec<u16>,
    batch: Option<BatchRestore>,
    probing: bool,
    icons: BTreeMap<u16, Handle>,
    copies: BTreeSet<u16>,
    saved_bytes: u64,
    /// App whose restore failed because the PC is offline (shows Retry).
    offline: Option<u16>,
    policy: Option<bool>,
    groups: Vec<(Group, Vec<u16>)>,
    removed: Vec<(u16, u64)>,
    suggested_machine: bool,
    suggested_user: bool,
    allowing: Option<(u8, bool)>,
    spin: anim::Clock,
    now: Instant,
    run_at: Instant,
    /// The result, kept back for a moment so the finished progress can settle.
    held: Option<(Instant, Box<Finished>)>,
    menu_fillers: Vec<u16>,
    ads: ads::State,
    space: space::State,
    points: widgets::point::Opened,
}

impl Default for State {
    fn default() -> Self {
        State {
            scan_gen: 0,
            tab: Tab::Apps,
            scan: Scan::Loading,
            search: String::new(),
            installed: Vec::new(),
            selected: BTreeSet::new(),
            block_again: false,
            sheet: Sheet::None,
            open: vec![Group::Recommended],
            expanded: Vec::new(),
            journal: Vec::new(),
            restoring: None,
            restoring_copy: false,
            queue: Vec::new(),
            batch: None,
            probing: false,
            icons: BTreeMap::new(),
            copies: BTreeSet::new(),
            saved_bytes: 0,
            offline: None,
            policy: None,
            groups: Vec::new(),
            removed: Vec::new(),
            suggested_machine: false,
            suggested_user: false,
            allowing: None,
            spin: anim::Clock::new(),
            now: Instant::now(),
            run_at: Instant::now(),
            held: None,
            menu_fillers: Vec::new(),
            ads: ads::State::default(),
            space: space::State::default(),
            points: widgets::point::Opened::default(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BatchRestore {
    pub total: usize,
    pub back: usize,
    pub failed: Vec<u16>,
}

#[derive(Debug, Clone)]
pub enum Run {
    Step(Progress),
    Policy(bool),
    Done(Result<Batch, String>),
}

#[derive(Debug, Clone)]
pub enum Msg {
    Scanned(u32, Result<Vec<Installed>, String>),
    JournalLoaded(Vec<Batch>),
    Rescan,
    SetTab(Tab),
    Search(String),
    Show(&'static str),
    ClearSearch,
    Toggle(u16),
    ToggleGroup(Group),
    ToggleOpen(Group),
    ToggleMore(Group),
    ToggleBlock,
    Review,
    Cancel,
    Confirm,
    Run(Run),
    UserBlocked(bool),
    Frame(Instant),
    CloseResult,
    Restore(u16),
    RestoreAll,
    RestoreStore(u16),
    StoreProbed(u16, bool),
    Restored(u16, Result<crate::broker::Reply, String>),
    RestoredOffline(u16, Result<Restored, String>),
    AskDelete(u16),
    Delete(u16),
    SuggestedMachine(bool),
    SuggestedUser(Result<crate::broker::Reply, String>),
    AllowSuggested,
    SuggestedAllowed(bool),
    Deleted(Result<(), String>),
    Copies(BTreeSet<u16>, u64),
    Icons(BTreeMap<u16, Handle>),
    Ads(ads::Msg),
    Space(space::Msg),
    Point(String),
}

fn wrap(msg: Msg) -> Message {
    Message::Debloat(msg)
}

fn inventory_task(state: &mut State) -> Task<Message> {
    state.scan_gen = state.scan_gen.wrapping_add(1);
    let generation = state.scan_gen;
    Task::perform(
        blocking(|| debloat::inventory().map_err(|e| format!("{e:#}"))),
        move |r| wrap(Msg::Scanned(generation, r)),
    )
}

fn icons_task(installed: Vec<Installed>) -> Task<Message> {
    Task::perform(
        blocking(move || {
            debloat::icons::load(&installed)
                .into_iter()
                .map(|(i, img)| (i, Handle::from_rgba(img.width, img.height, img.pixels)))
                .collect::<BTreeMap<u16, Handle>>()
        }),
        |icons| wrap(Msg::Icons(icons)),
    )
}

fn app_glyph<'a>(p: Palette, state: &State, index: u16, size: f32) -> Element<'a, Message> {
    match state.icons.get(&index) {
        Some(handle) => iced::widget::image(handle.clone())
            .width(size)
            .height(size)
            .into(),
        None => widgets::icon(Icon::Package, size, p.text_muted),
    }
}

fn copies_task() -> Task<Message> {
    Task::perform(
        blocking(|| {
            let copies = debloat::catalog()
                .iter()
                .enumerate()
                .map(|(i, _)| i as u16)
                .filter(|i| debloat::offline::has_copy(*i))
                .collect::<BTreeSet<u16>>();
            (copies, debloat::offline::saved_bytes())
        }),
        |(c, b)| wrap(Msg::Copies(c, b)),
    )
}

fn suggested_task(ctx: &Ctx) -> Task<Message> {
    Task::batch([
        Task::perform(
            blocking(|| {
                debloat::suggested::journal_path()
                    .map(|p| debloat::suggested::recorded(&p))
                    .unwrap_or(false)
            }),
            |on| wrap(Msg::SuggestedMachine(on)),
        ),
        ctx.broker_task(
            crate::broker::Request::UserSetting(
                secblitz::user_settings::Setting::SuggestedApps,
                secblitz::user_settings::Op::Query,
            ),
            |r| wrap(Msg::SuggestedUser(r)),
        ),
    ])
}

fn allow_machine() -> bool {
    #[cfg(windows)]
    {
        use debloat::suggested;
        suggested::journal_path()
            .and_then(|p| suggested::undo(&mut suggested::MachinePolicy, &p))
            .is_ok()
    }
    #[cfg(not(windows))]
    {
        true
    }
}

fn scan_task(state: &mut State) -> Task<Message> {
    Task::batch([
        inventory_task(state),
        copies_task(),
        Task::perform(blocking(debloat::journal::load), |j| {
            wrap(Msg::JournalLoaded(j))
        }),
    ])
}

/// The leftover folders are only measured while the Free up space tab is the one showing.
fn load_space_tab(state: &mut State, ctx: &Ctx) -> Task<Message> {
    if state.tab == Tab::Space {
        space::load(&mut state.space, ctx)
    } else {
        Task::none()
    }
}

pub fn on_enter(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    if !matches!(state.sheet, Sheet::None) {
        return Task::none();
    }
    start_scan(state);
    Task::batch([
        scan_task(state),
        suggested_task(ctx),
        ads::load(&mut state.ads, ctx),
        load_space_tab(state, ctx),
    ])
}

fn start_scan(state: &mut State) {
    state.scan = Scan::Loading;
    state.now = Instant::now();
    state.spin = anim::Clock::at(state.now);
}

pub fn subscription(state: &State) -> Subscription<Message> {
    if is_animating(state) {
        iced::window::frames().map(|t| wrap(Msg::Frame(t)))
    } else {
        Subscription::none()
    }
}

fn is_animating(state: &State) -> bool {
    if !anim::animating() {
        return false;
    }
    if space::is_animating(&state.space) {
        return true;
    }
    if matches!(state.scan, Scan::Loading) || state.restoring.is_some() || state.batch.is_some() {
        return true;
    }
    match &state.sheet {
        Sheet::Working(items) => {
            state.held.is_some()
                || items.iter().any(|(_, step)| match step {
                    Step::Done(_, at) => !anim::Clock::at(*at).done(anim::SLOW, state.now),
                    _ => false,
                })
        }
        Sheet::Done(done) => done.asked_to_block && done.user_ok.is_none(),
        _ => false,
    }
}

fn refresh_removed(state: &mut State) {
    state.removed = debloat::journal::still_removed(&state.journal, debloat::catalog().len());
}

pub fn escape(state: &mut State) {
    if matches!(
        state.sheet,
        Sheet::Review | Sheet::Done(_) | Sheet::Delete(_)
    ) {
        state.sheet = Sheet::None;
    } else if !space::is_busy(&state.space) {
        clear_search(state);
    } else {
        space::escape(&mut state.space);
    }
}

pub fn clear_search(state: &mut State) {
    state.search.clear();
}

/// Whether the page has its search box on screen right now.
pub fn shows_search(state: &State) -> bool {
    state.tab == Tab::Apps
        && matches!(state.sheet, Sheet::None)
        && !state.groups.is_empty()
        && !matches!(state.scan, Scan::Failed(_))
}

fn searching(state: &State) -> bool {
    !Query::new(&state.search).is_empty()
}

/// What a typed search is compared with: the app's name in the current
/// language and in English, and its package names.
fn app_text(ctx: &Ctx, state: &State, index: u16) -> Haystack {
    let app = app_of(index);
    let packages = state
        .installed
        .iter()
        .filter(|found| found.index == index)
        .map(|found| found.package.as_str());
    Haystack::new(
        [ctx.t(app.name).as_str(), app.name, app.family]
            .into_iter()
            .chain(packages),
    )
}

/// The members of a group that match the search, in their normal order.
fn shown_members(state: &State, ctx: &Ctx, members: &[u16]) -> Vec<u16> {
    let query = Query::new(&state.search);
    members
        .iter()
        .copied()
        .filter(|index| query.is_empty() || query.matches(&app_text(ctx, state, *index)))
        .collect()
}

#[cfg(test)]
pub fn ads_shown_as(state: &State, setting: secblitz::user_settings::Setting) -> &'static str {
    ads::shown_as(&state.ads, setting)
}

#[cfg(test)]
pub fn selected_apps(state: &State) -> Vec<u16> {
    state.selected.iter().copied().collect()
}

/// The apps on screen, group by group.
#[cfg(test)]
pub fn visible_apps(state: &State, ctx: &Ctx) -> Vec<u16> {
    state
        .groups
        .iter()
        .flat_map(|(_, members)| shown_members(state, ctx, members))
        .collect()
}

const BLOCKED_NOTE: &str = "Windows was asked not to add suggested apps.";
const ALLOW_AGAIN: &str = "Allow suggested apps again";
const ALLOWED_AGAIN: &str = "Windows can add suggested apps again.";

fn suggested_blocked(state: &State) -> bool {
    state.suggested_machine || state.suggested_user
}

fn app_of(index: u16) -> &'static debloat::App {
    &debloat::catalog()[index as usize]
}

pub const COPILOT_APP: &str = "Microsoft.Copilot";

pub fn is_installed(state: &State, family: &str) -> bool {
    installed_indices(state)
        .into_iter()
        .any(|index| app_of(index).family == family)
}

fn installed_indices(state: &State) -> Vec<u16> {
    let mut v: Vec<u16> = state.installed.iter().map(|p| p.index).collect();
    v.sort_unstable();
    v.dedup();
    v
}

fn toast(text: String, tone: Tone) -> Task<Message> {
    Task::done(Message::Toast(text, tone))
}

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    let task = apply(state, msg, ctx);
    if matches!(state.sheet, Sheet::None) {
        state.points.clear();
    }
    task
}

fn apply(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    match msg {
        Msg::Point(key) => {
            if !matches!(state.sheet, Sheet::None) {
                state.points.toggle(&key);
            }
            Task::none()
        }
        Msg::Scanned(generation, result) => on_scanned(state, generation, result),
        Msg::Icons(found) => {
            state.icons.extend(found);
            Task::none()
        }
        Msg::JournalLoaded(j) => {
            state.journal = j;
            refresh_removed(state);
            Task::none()
        }
        Msg::Rescan => {
            start_scan(state);
            scan_task(state)
        }
        Msg::SetTab(tab) => {
            state.tab = tab;
            load_space_tab(state, ctx)
        }
        Msg::Search(text) => {
            state.search = text;
            Task::none()
        }
        Msg::Show(family) => {
            state.tab = Tab::Apps;
            state.search = installed_indices(state)
                .into_iter()
                .map(app_of)
                .find(|app| app.family == family)
                .map_or_else(String::new, |app| app.name.to_owned());
            Task::none()
        }
        Msg::ClearSearch => {
            clear_search(state);
            iced::widget::operation::focus(SEARCH_ID)
        }
        Msg::Toggle(i) => {
            toggle_app(state, i);
            Task::none()
        }
        Msg::ToggleGroup(group) => {
            toggle_group(state, ctx, group);
            Task::none()
        }
        Msg::ToggleOpen(g) => {
            flip(&mut state.open, g);
            Task::none()
        }
        Msg::ToggleMore(g) => {
            flip(&mut state.expanded, g);
            Task::none()
        }
        Msg::Frame(now) => {
            on_frame(state, now);
            Task::none()
        }
        Msg::ToggleBlock => {
            state.block_again = !state.block_again && ctx.helper == Helper::Ready;
            Task::none()
        }
        Msg::Review => {
            open_review(state, ctx);
            Task::none()
        }
        Msg::Cancel => {
            cancel_sheet(state);
            Task::none()
        }
        Msg::Confirm => confirm(state, ctx),
        Msg::Run(run) => on_run(state, ctx, run),
        Msg::UserBlocked(ok) => {
            on_user_blocked(state, ok);
            Task::none()
        }
        Msg::CloseResult => {
            close_result(state);
            Task::none()
        }
        Msg::Restore(index) => restore(state, ctx, index),
        Msg::RestoreAll => restore_all(state, ctx),
        Msg::RestoreStore(index) => restore_from_store(state, ctx, index),
        Msg::StoreProbed(index, offline) => on_store_probed(state, ctx, index, offline),
        Msg::Restored(index, result) => on_restored(state, ctx, index, result),
        Msg::RestoredOffline(index, result) => on_restored_offline(state, ctx, index, result),
        Msg::SuggestedMachine(on) => {
            state.suggested_machine = on;
            Task::none()
        }
        Msg::SuggestedUser(reply) => {
            state.suggested_user = matches!(reply, Ok(crate::broker::Reply::SafeByUs));
            Task::none()
        }
        Msg::AllowSuggested => allow_suggested(state, ctx),
        Msg::SuggestedAllowed(ok) => on_suggested_allowed(state, ctx, ok),
        Msg::AskDelete(index) => {
            ask_delete(state, ctx, index);
            Task::none()
        }
        Msg::Delete(index) => delete(state, ctx, index),
        Msg::Deleted(result) => on_deleted(ctx, result),
        Msg::Copies(copies, bytes) => {
            state.copies = copies;
            state.saved_bytes = bytes;
            Task::none()
        }
        Msg::Ads(msg) => ads::update(&mut state.ads, msg, ctx),
        Msg::Space(msg) => space::update(&mut state.space, msg, ctx),
    }
}

fn toggle_app(state: &mut State, index: u16) {
    if !state.selected.remove(&index) {
        state.selected.insert(index);
    }
}

fn on_frame(state: &mut State, now: Instant) {
    state.now = now;
    space::on_frame(&mut state.space, now);
    let held = state.held.as_ref().map(|(at, _)| *at);
    if held.is_some_and(|at| now.saturating_duration_since(at) >= handoff::sheet_hold()) {
        show_held(state);
    }
}

fn open_review(state: &mut State, ctx: &Ctx) {
    if !ctx.busy && !state.selected.is_empty() {
        state.block_again &= ctx.helper == Helper::Ready;
        state.sheet = Sheet::Review;
    }
}

fn cancel_sheet(state: &mut State) {
    if matches!(state.sheet, Sheet::Review | Sheet::Delete(_)) {
        state.sheet = Sheet::None;
    }
}

fn on_user_blocked(state: &mut State, ok: bool) {
    if let Sheet::Done(done) = &mut state.sheet {
        done.user_ok = Some(ok);
    } else if let Some((_, done)) = &mut state.held {
        done.user_ok = Some(ok);
    }
}

fn restore_from_store(state: &mut State, ctx: &mut Ctx, index: u16) -> Task<Message> {
    if state.restoring.is_some() || state.probing || ctx.busy {
        return Task::none();
    }
    store_restore(state, ctx, index)
}

fn on_store_probed(state: &mut State, ctx: &mut Ctx, index: u16, offline: bool) -> Task<Message> {
    state.probing = false;
    if offline {
        state.offline = Some(index);
        return Task::none();
    }
    start_store_restore(state, ctx, index)
}

fn on_scanned(
    state: &mut State,
    generation: u32,
    result: Result<Vec<Installed>, String>,
) -> Task<Message> {
    if generation != state.scan_gen {
        return Task::none();
    }
    let found = match result {
        Ok(found) => found,
        Err(e) => {
            state.scan = Scan::Failed(e);
            return Task::none();
        }
    };
    state.installed = found;
    let icons = icons_task(state.installed.clone());
    let present: BTreeSet<u16> = installed_indices(state).into_iter().collect();
    state.selected.retain(|i| present.contains(i));
    state.groups = Group::ALL
        .iter()
        .filter_map(|g| {
            let members: Vec<u16> = present
                .iter()
                .copied()
                .filter(|i| app_of(*i).group == *g)
                .collect();
            (!members.is_empty()).then_some((*g, members))
        })
        .collect();
    state.scan = Scan::Ready;
    icons
}

fn toggle_group(state: &mut State, ctx: &Ctx, group: Group) {
    let members: Vec<u16> = installed_indices(state)
        .into_iter()
        .filter(|i| app_of(*i).group == group)
        .collect();
    let members = shown_members(state, ctx, &members);
    if members.iter().all(|i| state.selected.contains(i)) {
        for i in members {
            state.selected.remove(&i);
        }
    } else {
        state.selected.extend(members);
    }
}

fn close_result(state: &mut State) {
    if matches!(state.sheet, Sheet::Done(_)) {
        state.sheet = Sheet::None;
    }
}

fn restore(state: &mut State, ctx: &mut Ctx, index: u16) -> Task<Message> {
    if state.restoring.is_some() || state.probing || ctx.busy {
        return Task::none();
    }
    if state.copies.contains(&index) {
        state.restoring = Some(index);
        state.restoring_copy = true;
        state.offline = None;
        state.now = Instant::now();
        state.spin = anim::Clock::at(state.now);
        return Task::perform(
            blocking(move || debloat::offline::restore_index(index).map_err(|e| format!("{e:#}"))),
            move |r| wrap(Msg::RestoredOffline(index, r)),
        );
    }
    store_restore(state, ctx, index)
}

/// Apps that Restore all would bring back: every removed app with a saved copy.
pub fn restorable(state: &State) -> Vec<u16> {
    state
        .removed
        .iter()
        .map(|(i, _)| *i)
        .filter(|i| state.copies.contains(i))
        .collect()
}

fn restore_all(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    if state.batch.is_some() || state.restoring.is_some() || state.probing || ctx.busy {
        return Task::none();
    }
    let mut targets = restorable(state);
    if targets.is_empty() {
        return Task::none();
    }
    let first = targets.remove(0);
    state.batch = Some(BatchRestore {
        total: targets.len() + 1,
        ..BatchRestore::default()
    });
    state.queue = targets;
    restore(state, ctx, first)
}

fn on_batch_restored(
    state: &mut State,
    ctx: &mut Ctx,
    index: u16,
    result: Result<Restored, String>,
) -> Task<Message> {
    let back = matches!(
        result,
        Ok(Restored::Back | Restored::BackWithoutSomeData | Restored::AlreadyThere)
    );
    let mut tasks = Vec::new();
    if back {
        tasks.push(mark_back(state, index));
    }
    if let Some(next) = batch_step(state, index, back) {
        tasks.push(restore(state, ctx, next));
        return Task::batch(tasks);
    }
    let batch = state.batch.take().unwrap_or_default();
    if batch.back > 0 {
        record_restore(ctx, batch.back);
    }
    tasks.push(inventory_task(state));
    tasks.push(copies_task());
    tasks.push(batch_toast(ctx, &batch));
    Task::batch(tasks)
}

/// Counts one finished app and picks the next one that still has a copy.
/// `None` means the run is over.
fn batch_step(state: &mut State, index: u16, back: bool) -> Option<u16> {
    let batch = state.batch.as_mut()?;
    if back {
        batch.back += 1;
    } else {
        batch.failed.push(index);
    }
    while !state.queue.is_empty() {
        let next = state.queue.remove(0);
        if state.copies.contains(&next) {
            return Some(next);
        }
        batch.failed.push(next);
    }
    None
}

fn batch_toast(ctx: &Ctx, batch: &BatchRestore) -> Task<Message> {
    let names: Vec<String> = batch
        .failed
        .iter()
        .map(|i| ctx.t(app_of(*i).name))
        .collect();
    if names.is_empty() {
        let text = if batch.back == 1 {
            ctx.t("1 app is back on your PC.")
        } else {
            ctx.t("{n} apps are back on your PC.")
                .replace("{n}", &batch.back.to_string())
        };
        return toast(text, Tone::Good);
    }
    let text = ctx
        .t("{n} of {total} apps are back. These couldn't be brought back: {names}. Try them one at a time below.")
        .replace("{n}", &batch.back.to_string())
        .replace("{total}", &batch.total.to_string())
        .replace("{names}", &names.join(", "));
    toast(
        text,
        if batch.back > 0 {
            Tone::Warn
        } else {
            Tone::Bad
        },
    )
}

fn on_restored(
    state: &mut State,
    ctx: &mut Ctx,
    index: u16,
    result: Result<crate::broker::Reply, String>,
) -> Task<Message> {
    state.restoring = None;
    state.restoring_copy = false;
    let name = ctx.t(app_of(index).name);
    match result {
        Ok(crate::broker::Reply::Done) => {
            let text = format!("{name} {}", ctx.t("is back on your PC."));
            restored_ok(state, ctx, index, text, Tone::Good)
        }
        Ok(crate::broker::Reply::Offline) => {
            state.offline = Some(index);
            Task::none()
        }
        Ok(crate::broker::Reply::OpenedStore) => toast(
            format!(
                "{} {name}.",
                ctx.t("We opened the Microsoft Store so you can install")
            ),
            Tone::Neutral,
        ),
        Err(e) if e == "unavailable" => toast(
            format!(
                "{} {name}. {}",
                ctx.t("We couldn't bring back"),
                ctx.t(store_note(ctx.helper))
            ),
            Tone::Bad,
        ),
        _ => couldnt_bring_back(ctx, &name),
    }
}

fn allow_suggested(state: &mut State, ctx: &Ctx) -> Task<Message> {
    if state.allowing.is_some() || !suggested_blocked(state) {
        return Task::none();
    }
    let user = state.suggested_user;
    state.allowing = Some((1 + u8::from(user), true));
    let mut tasks = vec![Task::perform(blocking(allow_machine), |ok| {
        wrap(Msg::SuggestedAllowed(ok))
    })];
    if user {
        tasks.push(ctx.broker_task(
            crate::broker::Request::UserSetting(
                secblitz::user_settings::Setting::SuggestedApps,
                secblitz::user_settings::Op::Undo,
            ),
            |r| {
                wrap(Msg::SuggestedAllowed(matches!(
                    r,
                    Ok(crate::broker::Reply::Done)
                )))
            },
        ));
    }
    Task::batch(tasks)
}

fn on_suggested_allowed(state: &mut State, ctx: &Ctx, ok: bool) -> Task<Message> {
    let Some((left, all_ok)) = state.allowing else {
        return Task::none();
    };
    let (left, all_ok) = (left - 1, all_ok && ok);
    if left > 0 {
        state.allowing = Some((left, all_ok));
        return Task::none();
    }
    state.allowing = None;
    let text = if all_ok {
        ctx.t(ALLOWED_AGAIN)
    } else {
        ctx.t("We couldn't change that setting. It was left as it was. Please try again, or restart your PC first.")
    };
    Task::batch([
        toast(text, if all_ok { Tone::Good } else { Tone::Warn }),
        suggested_task(ctx),
    ])
}

fn ask_delete(state: &mut State, ctx: &Ctx, index: u16) {
    if matches!(state.sheet, Sheet::None)
        && !ctx.busy
        && state.restoring.is_none()
        && state.copies.contains(&index)
    {
        state.sheet = Sheet::Delete(index);
    }
}

fn delete(state: &mut State, ctx: &Ctx, index: u16) -> Task<Message> {
    if !matches!(state.sheet, Sheet::Delete(i) if i == index) {
        return Task::none();
    }
    state.sheet = Sheet::None;
    if ctx.busy || state.restoring.is_some() {
        return Task::none();
    }
    Task::perform(
        blocking(move || debloat::offline::delete_index(index).map_err(|e| format!("{e:#}"))),
        move |r| wrap(Msg::Deleted(r)),
    )
}

fn on_deleted(ctx: &Ctx, result: Result<(), String>) -> Task<Message> {
    let (text, tone) = match result {
        Ok(()) => (ctx.t("Saved copy deleted."), Tone::Neutral),
        Err(_) => (
            ctx.t("We couldn't delete the saved copy. Please try again. If it keeps failing, restart your PC."),
            Tone::Bad,
        ),
    };
    Task::batch([copies_task(), toast(text, tone)])
}

fn couldnt_bring_back(ctx: &Ctx, name: &str) -> Task<Message> {
    toast(
        format!(
            "{} {name}. {}",
            ctx.t("We couldn't bring back"),
            ctx.t("Restart your PC and try again.")
        ),
        Tone::Bad,
    )
}

const NOT_ON_ACCOUNT_STORE: &str = "Windows doesn't let Secblitz do this from the built-in Administrator account or when account protection (UAC) is off. Get the app from the Microsoft Store instead.";

/// Why a Store reinstall cannot be offered, or nothing when it can.
pub fn store_blocker(helper: Helper) -> Option<&'static str> {
    match helper {
        Helper::Ready => None,
        Helper::Reopen => Some(crate::gui::REOPEN_TO_DO_THIS),
        Helper::NotOnThisAccount => Some(NOT_ON_ACCOUNT_STORE),
    }
}

fn store_note(helper: Helper) -> &'static str {
    store_blocker(helper).unwrap_or("Restart your PC and try again.")
}

fn store_restore(state: &mut State, ctx: &mut Ctx, index: u16) -> Task<Message> {
    if app_of(index).store_id.is_none() {
        return Task::none();
    }
    if let Some(note) = store_blocker(ctx.helper) {
        return toast(ctx.t(note), Tone::Bad);
    }
    state.probing = true;
    state.offline = None;
    Task::perform(
        blocking(secblitz::software_install::dns_offline),
        move |offline| wrap(Msg::StoreProbed(index, offline)),
    )
}

fn start_store_restore(state: &mut State, ctx: &mut Ctx, index: u16) -> Task<Message> {
    state.restoring = Some(index);
    state.restoring_copy = false;
    state.offline = None;
    state.now = Instant::now();
    state.spin = anim::Clock::at(state.now);
    ctx.broker_task(crate::broker::Request::ReinstallStoreApp(index), move |r| {
        wrap(Msg::Restored(index, r))
    })
}

fn restored_ok(
    state: &mut State,
    ctx: &mut Ctx,
    index: u16,
    text: String,
    tone: Tone,
) -> Task<Message> {
    record_restore(ctx, 1);
    Task::batch([
        mark_back(state, index),
        inventory_task(state),
        toast(text, tone),
    ])
}

fn mark_back(state: &mut State, index: u16) -> Task<Message> {
    for batch in &mut state.journal {
        for r in batch.removed.iter_mut().filter(|r| r.index == index) {
            r.restored = true;
        }
    }
    refresh_removed(state);
    Task::batch([
        Task::perform(
            blocking(move || {
                let _ = debloat::journal::mark_restored(index);
                debloat::journal::load()
            }),
            |j| wrap(Msg::JournalLoaded(j)),
        ),
        Task::perform(blocking(move || debloat::finish_restore(index)), |_| ())
            .then(|_| copies_task()),
    ])
}

fn record_restore(ctx: &Ctx, n: usize) {
    if let Some(dir) = &ctx.state_dir {
        let score = ctx.score().unwrap_or_default();
        let _ = crate::app::history::record(
            dir,
            &crate::app::history::Entry {
                t: crate::app::history::now(),
                kind: crate::app::history::Kind::Restore,
                protected: score.protected,
                total: score.total,
                n,
            },
        );
    }
}

fn on_restored_offline(
    state: &mut State,
    ctx: &mut Ctx,
    index: u16,
    result: Result<Restored, String>,
) -> Task<Message> {
    state.restoring = None;
    state.restoring_copy = false;
    if state.batch.is_some() {
        return on_batch_restored(state, ctx, index, result);
    }
    let name = ctx.t(app_of(index).name);
    let can_use_store = app_of(index).store_id.is_some();
    match result {
        Ok(Restored::Back) => {
            let text = format!("{name} {}", ctx.t("is back on your PC."));
            restored_ok(state, ctx, index, text, Tone::Good)
        }
        Ok(Restored::BackWithoutSomeData) => {
            let text = ctx
                .t("{name} is back. Some of its saved data couldn't be put back.")
                .replace("{name}", &name);
            restored_ok(state, ctx, index, text, Tone::Neutral)
        }
        Ok(Restored::AlreadyThere) => {
            let text = ctx
                .t("{name} is already on your PC.")
                .replace("{name}", &name);
            restored_ok(state, ctx, index, text, Tone::Neutral)
        }
        Ok(Restored::Damaged) => {
            let text = ctx
                .t(if can_use_store {
                    "The saved copy of {name} is damaged, so Secblitz is getting it from the Microsoft Store instead."
                } else {
                    "The saved copy of {name} is damaged, so it can't be brought back from Secblitz."
                })
                .replace("{name}", &name);
            let mut tasks = vec![toast(text, Tone::Warn), copies_task()];
            if can_use_store {
                tasks.push(store_restore(state, ctx, index));
            }
            Task::batch(tasks)
        }
        Ok(Restored::NoCopy) => {
            if can_use_store {
                Task::batch([copies_task(), store_restore(state, ctx, index)])
            } else {
                Task::batch([copies_task(), couldnt_bring_back(ctx, &name)])
            }
        }
        Err(_) => couldnt_bring_back(ctx, &name),
    }
}

fn flip(list: &mut Vec<Group>, g: Group) {
    if let Some(pos) = list.iter().position(|x| *x == g) {
        list.remove(pos);
    } else {
        list.push(g);
    }
}

fn pal(ctx: &Ctx) -> Palette {
    Palette::of(ctx.palette.mode)
}

#[cfg(test)]
mod restore_all_tests {
    use super::*;

    #[test]
    fn restore_all_takes_every_app_with_a_copy_in_list_order() {
        let mut state = State {
            removed: vec![(4, 0), (9, 0), (2, 0), (7, 0)],
            copies: [2, 4, 7].into_iter().collect(),
            ..State::default()
        };
        assert_eq!(restorable(&state), vec![4, 2, 7]);

        state.batch = Some(BatchRestore {
            total: 3,
            ..BatchRestore::default()
        });
        state.queue = vec![2, 7];
        assert_eq!(batch_step(&mut state, 4, true), Some(2));
        assert_eq!(batch_step(&mut state, 2, false), Some(7));
        assert_eq!(batch_step(&mut state, 7, true), None);
        let batch = state.batch.as_ref().unwrap();
        assert_eq!((batch.back, batch.failed.clone()), (2, vec![2]));
    }

    #[test]
    fn an_app_whose_copy_went_missing_counts_as_not_back() {
        let mut state = State {
            copies: [5].into_iter().collect(),
            queue: vec![3, 5],
            batch: Some(BatchRestore {
                total: 3,
                ..BatchRestore::default()
            }),
            ..State::default()
        };
        assert_eq!(batch_step(&mut state, 1, true), Some(5));
        assert_eq!(batch_step(&mut state, 5, true), None);
        let batch = state.batch.as_ref().unwrap();
        assert_eq!((batch.back, batch.failed.clone()), (2, vec![3]));
    }

    #[test]
    fn a_single_restore_is_not_part_of_a_run() {
        let mut state = State::default();
        assert_eq!(batch_step(&mut state, 1, true), None);
        assert!(state.batch.is_none());
    }
}

#[cfg(test)]
mod default_selection_tests {
    use super::*;

    #[test]
    fn nothing_is_ticked_after_the_first_scan() {
        let mut state = State::default();
        let found: Vec<Installed> = (0..debloat::catalog().len() as u16)
            .map(|index| Installed {
                index,
                package: format!("pkg{index}"),
                version: "1".into(),
            })
            .collect();
        let generation = state.scan_gen;
        let _ = on_scanned(&mut state, generation, Ok(found));
        assert!(!state.installed.is_empty());
        assert!(state.selected.is_empty());
    }
}

fn confirm(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    if ctx.busy || !matches!(state.sheet, Sheet::Review) {
        return Task::none();
    }
    let indices: Vec<u16> = state.selected.iter().copied().collect();
    if indices.is_empty() {
        state.sheet = Sheet::None;
        return Task::none();
    }
    ctx.busy = true;
    state.now = Instant::now();
    state.spin = anim::Clock::at(state.now);
    state.run_at = state.now;
    state.menu_fillers = installed_indices(state)
        .into_iter()
        .filter(|i| !state.selected.contains(i))
        .collect();
    state.sheet = Sheet::Working(indices.iter().map(|i| (*i, Step::Waiting)).collect());
    let block = state.block_again;
    let stream = blocking_stream(move |emit: &dyn Fn(Run)| {
        let result =
            debloat::remove(&indices, &|p| emit(Run::Step(p))).map_err(|e| format!("{e:#}"));
        if block && result.is_ok() {
            emit(Run::Policy(debloat::set_consumer_features_policy().is_ok()));
        }
        emit(Run::Done(result));
    });
    Task::run(stream, |r| wrap(Msg::Run(r)))
}

fn on_run(state: &mut State, ctx: &mut Ctx, run: Run) -> Task<Message> {
    match run {
        Run::Step(Progress::Saving(i)) => {
            set_step(state, i, Step::Saving);
            Task::none()
        }
        Run::Step(Progress::Started(i)) => {
            set_step(state, i, Step::Working);
            Task::none()
        }
        Run::Step(Progress::Finished(i, result)) => {
            if let Sheet::Working(items) = &mut state.sheet {
                if let Some(item) = items.iter_mut().find(|(n, _)| *n == i) {
                    item.1 = Step::Done(result, Instant::now());
                }
            }
            Task::none()
        }
        Run::Policy(ok) => {
            state.policy = Some(ok);
            Task::none()
        }
        Run::Done(result) => {
            ctx.busy = false;
            let policy_ok = state.policy.take();
            let asked = state.block_again && result.is_ok();
            let steps = match &state.sheet {
                Sheet::Working(items) => items.clone(),
                _ => Vec::new(),
            };
            let kept = steps
                .iter()
                .filter_map(|(i, step)| match step {
                    Step::Done(ItemResult::Kept(k), _) => Some((*i, k.clone())),
                    _ => None,
                })
                .collect();
            let mut done = Finished {
                asked_to_block: asked,
                kept,
                steps,
                policy_ok,
                ..Finished::default()
            };
            let mut tasks = vec![];
            match result {
                Ok(batch) => {
                    let removed = batch.removed_apps();
                    if removed > 0 {
                        record_history(ctx, removed);
                        state.journal.push(batch.clone());
                        refresh_removed(state);
                    }
                    done.batch = Some(batch);
                    if asked {
                        tasks.push(ctx.broker_task(
                            crate::broker::Request::BlockSuggestedApps,
                            |r| {
                                wrap(Msg::UserBlocked(matches!(
                                    r,
                                    Ok(crate::broker::Reply::Done)
                                )))
                            },
                        ));
                    }
                }
                Err(e) => done.error = Some(e),
            }
            if handoff::sheet_hold().is_zero() {
                state.now = done.at;
                state.sheet = Sheet::Done(Box::new(done));
            } else {
                state.now = Instant::now();
                state.held = Some((state.now, Box::new(done)));
            }
            tasks.push(scan_task(state));
            Task::batch(tasks)
        }
    }
}

fn show_held(state: &mut State) {
    if let Some((_, mut done)) = state.held.take() {
        done.at = Instant::now();
        state.now = done.at;
        state.sheet = Sheet::Done(done);
    }
}

fn set_step(state: &mut State, i: u16, step: Step) {
    if let Sheet::Working(items) = &mut state.sheet {
        if let Some(item) = items.iter_mut().find(|(n, _)| *n == i) {
            item.1 = step;
        }
    }
}

fn record_history(ctx: &Ctx, removed: usize) {
    if let Some(dir) = &ctx.state_dir {
        let score = ctx.score().unwrap_or_default();
        let _ = crate::app::history::record(
            dir,
            &crate::app::history::Entry {
                t: crate::app::history::now(),
                kind: crate::app::history::Kind::Debloat,
                protected: score.protected,
                total: score.total,
                n: removed,
            },
        );
    }
}

fn count_text(ctx: &Ctx, n: usize, one: &str, many: &str) -> String {
    let key = if n == 1 { one } else { many };
    ctx.t(key).replace("{n}", &n.to_string())
}

pub(crate) mod ads;
mod space;
mod view;
pub use view::{footer, modal, view};

pub fn is_current_scan(state: &State, generation: u32) -> bool {
    state.scan_gen == generation
}

/// The app list must not be reloaded under an open sheet.
pub fn is_busy(state: &State) -> bool {
    !matches!(state.sheet, Sheet::None) || space::is_busy(&state.space)
}

pub fn preload(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    if is_busy(state) {
        return Task::none();
    }
    if !matches!(state.scan, Scan::Ready) {
        start_scan(state);
    }
    Task::batch([
        scan_task(state),
        suggested_task(ctx),
        ads::load(&mut state.ads, ctx),
        load_space_tab(state, ctx),
    ])
}
