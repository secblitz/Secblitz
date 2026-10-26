//! The Free up space tab: measures four kinds of leftover files and removes the ones the person ticks.
use super::ads::Cell;
use super::system;
use crate::broker::{Reply, Request, SpaceOp};
use crate::gui::icons::Icon;
use crate::gui::theme::{self, Tone};
use crate::gui::widgets::{self, anim, ButtonKind};
use crate::gui::{blocking, Ctx, Helper, Message};
use iced::widget::{column, row, space};
use iced::{Alignment, Element, Task};
use secblitz::space::{Item, Tally, UserArea};
use secblitz::user_settings::{Op, Setting};
use std::time::Instant;

type El<'a> = Element<'a, Message>;

const COUNT: usize = Item::EVERY.len();
const STORAGE: Setting = Setting::StorageSense;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Size {
    Unknown,
    Measuring,
    Known(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Waiting,
    Working,
    Done(Instant, bool),
}

#[derive(Debug)]
enum Sheet {
    None,
    Review,
    Working(Vec<(Item, Step)>),
    Done {
        freed: u64,
        left_alone: u64,
        failed: bool,
        approx: bool,
        restart: bool,
    },
}

#[derive(Debug, Default)]
struct Run {
    machine_waiting: bool,
    pending: u8,
    total: Tally,
    item_failed: bool,
    failed: bool,
    approx: bool,
    restart: bool,
}

#[derive(Debug)]
pub struct State {
    sizes: [Size; COUNT],
    ticked: [bool; COUNT],
    pending: [u8; COUNT],
    found: [Tally; COUNT],
    got: [bool; COUNT],
    generation: u32,
    sheet: Sheet,
    run: Run,
    /// What the helper has finished cleaning for items that are not the one being shown yet.
    stash: Vec<(Item, Result<Tally, String>)>,
    storage: Cell,
    spin: anim::Clock,
    now: Instant,
}

impl Default for State {
    fn default() -> Self {
        State {
            sizes: [Size::Unknown; COUNT],
            ticked: [false; COUNT],
            pending: [0; COUNT],
            found: [Tally::default(); COUNT],
            got: [false; COUNT],
            generation: 0,
            sheet: Sheet::None,
            run: Run::default(),
            stash: Vec::new(),
            storage: Cell::Idle,
            spin: anim::Clock::new(),
            now: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Msg {
    Measured(u32, Item, Result<Tally, String>),
    Toggle(Item),
    Review,
    Cancel,
    Confirm,
    Cleaned(Item, Result<Tally, String>),
    /// The helper's answer for an item, which may arrive before that item's turn.
    MachineCleaned(Item, Result<Tally, String>),
    CloseResult,
    StorageReported(Result<Reply, String>),
    StorageToggle(bool),
    StorageChanged(Result<Reply, String>),
}

fn wrap(msg: Msg) -> Message {
    Message::Debloat(super::Msg::Space(msg))
}

fn slot(item: Item) -> usize {
    Item::EVERY.iter().position(|i| *i == item).unwrap_or(0)
}

fn user_area(item: Item) -> Option<UserArea> {
    match item {
        Item::Temp => Some(UserArea::Temp),
        Item::CrashDumps => Some(UserArea::CrashDumps),
        Item::Thumbnails => Some(UserArea::Thumbnails),
        Item::ThumbnailCache => Some(UserArea::ThumbnailCache),
        Item::FlatpakRuntimes => Some(UserArea::FlatpakUser),
        Item::Trash => Some(UserArea::Trash),
        Item::UpdateLeftovers
        | Item::PackageCaches
        | Item::CrashReports
        | Item::OldSnaps
        | Item::OldKernels => None,
    }
}

fn has_machine_part(item: Item) -> bool {
    !matches!(item, Item::Thumbnails | Item::ThumbnailCache | Item::Trash)
}

/// Whether the person's own folders can be handled right now: through the Windows helper, or directly on Linux.
fn person_ready(ctx: &Ctx) -> bool {
    if cfg!(windows) {
        ctx.helper == Helper::Ready
    } else {
        system::person_ready()
    }
}

/// Why the person's own folders cannot be handled, which only the Windows helper can say.
fn blocker(ctx: &Ctx) -> Option<&'static str> {
    if cfg!(windows) {
        ctx.helper.blocker()
    } else {
        None
    }
}

fn parts(item: Item, helper_ready: bool) -> u8 {
    u8::from(has_machine_part(item)) + u8::from(helper_ready && user_area(item).is_some())
}

impl State {
    #[cfg(test)]
    fn ticked(&self, item: Item) -> bool {
        self.ticked[slot(item)]
    }

    fn set_measured(&mut self, item: Item, bytes: Option<u64>) {
        let i = slot(item);
        self.sizes[i] = bytes.map_or(Size::Unknown, Size::Known);
        if !self.can_tick(item) {
            self.ticked[i] = false;
        }
    }

    fn can_tick(&self, item: Item) -> bool {
        match item {
            Item::UpdateLeftovers => true,
            _ => matches!(self.sizes[slot(item)], Size::Known(n) if n > 0),
        }
    }

    fn toggle(&mut self, item: Item) {
        let i = slot(item);
        if self.ticked[i] {
            self.ticked[i] = false;
        } else if self.can_tick(item) {
            self.ticked[i] = true;
        }
    }

    fn selected_bytes(&self) -> u64 {
        Item::EVERY
            .iter()
            .filter(|i| self.ticked[slot(**i)])
            .map(|i| match self.sizes[slot(*i)] {
                Size::Known(n) => n,
                _ => 0,
            })
            .sum()
    }

    fn selected(&self) -> Vec<Item> {
        Item::EVERY
            .into_iter()
            .filter(|i| self.ticked[slot(*i)])
            .collect()
    }

    /// Items that only exist in the signed-in person's own folders.
    fn needs_helper(&self, item: Item) -> bool {
        user_area(item).is_some() && !has_machine_part(item)
    }

    fn measuring(&self) -> bool {
        self.pending.iter().any(|n| *n > 0)
    }
}

fn count_result(run: &mut Run, item: Item, result: Result<Tally, String>) {
    match result {
        Ok(tally) => run.total.add(tally),
        Err(e) if e == "unavailable" && user_area(item).is_none() => {}
        Err(e) if e == secblitz::space::NEEDS_RESTART => {
            run.item_failed = true;
            run.restart = true;
        }
        Err(_) => run.item_failed = true,
    }
}

fn user_result(result: Result<(Reply, Tally), String>) -> Result<Tally, String> {
    match result {
        Ok((Reply::Done, tally)) => Ok(tally),
        Ok(_) => Err("failed".into()),
        Err(e) => Err(e),
    }
}

/// Starts the machine-wide part of `item`. On Windows that runs here; elsewhere it joins the one request made to the helper.
fn machine_measure(
    item: Item,
    generation: u32,
    helper: &mut Vec<Item>,
    tasks: &mut Vec<Task<Message>>,
) {
    if cfg!(windows) {
        tasks.push(Task::perform(
            blocking(move || Ok(secblitz::space::measure_machine(item))),
            move |r| wrap(Msg::Measured(generation, item, r)),
        ));
    } else {
        helper.push(item);
    }
}

fn measure_all(state: &mut State, ctx: &Ctx) -> Task<Message> {
    state.generation = state.generation.wrapping_add(1);
    let generation = state.generation;
    let ready = person_ready(ctx);
    let mut tasks = Vec::new();
    let mut helper = Vec::new();
    for item in Item::offered() {
        let i = slot(item);
        state.pending[i] = parts(item, ready);
        state.found[i] = Tally::default();
        state.got[i] = false;
        state.sizes[i] = if state.pending[i] == 0 {
            Size::Unknown
        } else {
            Size::Measuring
        };
        if !state.can_tick(item) {
            state.ticked[i] = false;
        }
        if has_machine_part(item) {
            machine_measure(item, generation, &mut helper, &mut tasks);
        }
        if let (true, Some(area)) = (ready, user_area(item)) {
            tasks.push(person_task(ctx, area, false, move |r| {
                wrap(Msg::Measured(generation, item, r))
            }));
        }
    }
    if !helper.is_empty() {
        tasks.push(Task::run(
            system::machine(helper, false),
            move |(item, r)| wrap(Msg::Measured(generation, item, r)),
        ));
    }
    Task::batch(tasks)
}

/// Measures or cleans the person's own part of an item: through the Windows helper, or directly on Linux.
fn person_task(
    ctx: &Ctx,
    area: UserArea,
    clean: bool,
    map: impl Fn(Result<Tally, String>) -> Message + Send + 'static,
) -> Task<Message> {
    if cfg!(windows) {
        let op = if clean {
            SpaceOp::Clean
        } else {
            SpaceOp::Measure
        };
        ctx.space_task(area, op, move |r| map(user_result(r)))
    } else {
        Task::perform(blocking(move || system::person(area, clean)), map)
    }
}

fn storage_query(ctx: &Ctx) -> Task<Message> {
    ctx.broker_task(Request::UserSetting(STORAGE, Op::Query), |r| {
        wrap(Msg::StorageReported(r))
    })
}

/// Measures every row once and asks Windows how Storage Sense stands.
pub fn load(state: &mut State, ctx: &Ctx) -> Task<Message> {
    if !matches!(state.sheet, Sheet::None) || state.measuring() {
        return Task::none();
    }
    let mut tasks = vec![measure_all(state, ctx)];
    if cfg!(windows)
        && ctx.helper == Helper::Ready
        && !matches!(state.storage, Cell::Working | Cell::Loading)
    {
        state.storage = Cell::Loading;
        tasks.push(storage_query(ctx));
    }
    Task::batch(tasks)
}

pub fn is_busy(state: &State) -> bool {
    !matches!(state.sheet, Sheet::None)
}

pub fn is_animating(state: &State) -> bool {
    match &state.sheet {
        Sheet::Working(items) => items.iter().any(|(_, step)| match step {
            Step::Working => true,
            Step::Done(at, _) => !anim::Clock::at(*at).done(anim::SLOW, state.now),
            Step::Waiting => false,
        }),
        _ => false,
    }
}

pub fn on_frame(state: &mut State, now: Instant) {
    state.now = now;
}

pub fn escape(state: &mut State) {
    if matches!(state.sheet, Sheet::Review | Sheet::Done { .. }) {
        state.sheet = Sheet::None;
    }
}

fn toast(text: String, tone: Tone) -> Task<Message> {
    Task::done(Message::Toast(text, tone))
}

fn start_next(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    loop {
        let Sheet::Working(items) = &mut state.sheet else {
            return Task::none();
        };
        let Some((item, step)) = items.iter_mut().find(|(_, s)| *s == Step::Waiting) else {
            return finish(state, ctx);
        };
        let item = *item;
        *step = Step::Working;
        let ready = person_ready(ctx);
        state.run.pending = parts(item, ready);
        state.run.item_failed = false;
        state.run.machine_waiting = false;
        if state.run.pending == 0 {
            state.run.item_failed = true;
            end_item(state, item);
            continue;
        }
        let mut tasks = Vec::new();
        if has_machine_part(item) {
            if cfg!(windows) {
                tasks.push(Task::perform(
                    blocking(move || {
                        secblitz::space::clean_machine(item).map_err(|e| format!("{e:#}"))
                    }),
                    move |r| wrap(Msg::Cleaned(item, r)),
                ));
            } else if let Some(at) = state.stash.iter().position(|(i, _)| *i == item) {
                let (_, result) = state.stash.remove(at);
                tasks.push(Task::done(wrap(Msg::Cleaned(item, result))));
            } else {
                state.run.machine_waiting = true;
            }
        }
        if let (true, Some(area)) = (ready, user_area(item)) {
            tasks.push(person_task(ctx, area, true, move |r| {
                wrap(Msg::Cleaned(item, r))
            }));
        }
        return Task::batch(tasks);
    }
}

fn end_item(state: &mut State, item: Item) {
    let failed = state.run.item_failed;
    state.run.failed |= failed && !(item == Item::UpdateLeftovers && state.run.restart);
    if let Sheet::Working(items) = &mut state.sheet {
        if let Some(entry) = items.iter_mut().find(|(i, _)| *i == item) {
            entry.1 = Step::Done(Instant::now(), failed);
        }
    }
}

fn finish(state: &mut State, ctx: &mut Ctx) -> Task<Message> {
    ctx.busy = false;
    let total = state.run.total;
    state.sheet = Sheet::Done {
        freed: total.bytes,
        left_alone: total.left_alone,
        failed: state.run.failed,
        approx: state.run.approx,
        restart: state.run.restart,
    };
    state.ticked = [false; COUNT];
    if total.bytes > 0 {
        record_history(ctx, total.bytes);
    }
    measure_all(state, ctx)
}

/// Whole megabytes, rounded the way `size_phrase` rounds, so History says the same size as the result did.
fn history_mb(bytes: u64) -> usize {
    ((bytes + (1 << 19)) >> 20).max(1) as usize
}

fn record_history(ctx: &Ctx, bytes: u64) {
    if let Some(dir) = &ctx.state_dir {
        let _ = crate::app::history::record(
            dir,
            &crate::app::history::Entry {
                t: crate::app::history::now(),
                kind: crate::app::history::Kind::FreedSpace,
                protected: 0,
                total: 0,
                n: history_mb(bytes),
            },
        );
    }
}

fn apply_cleaned(
    state: &mut State,
    ctx: &mut Ctx,
    item: Item,
    result: Result<Tally, String>,
) -> Task<Message> {
    let current = match &state.sheet {
        Sheet::Working(items) => items
            .iter()
            .any(|(i, step)| *i == item && *step == Step::Working),
        _ => false,
    };
    if !current || state.run.pending == 0 {
        return Task::none();
    }
    state.run.pending -= 1;
    count_result(&mut state.run, item, result);
    if state.run.pending > 0 {
        return Task::none();
    }
    end_item(state, item);
    start_next(state, ctx)
}

pub fn update(state: &mut State, msg: Msg, ctx: &mut Ctx) -> Task<Message> {
    match msg {
        Msg::Measured(generation, item, result) => {
            if generation != state.generation {
                return Task::none();
            }
            let i = slot(item);
            if state.pending[i] == 0 {
                return Task::none();
            }
            state.pending[i] -= 1;
            if let Ok(tally) = result {
                state.found[i].add(tally);
                state.got[i] = true;
            }
            if state.pending[i] == 0 {
                let bytes = state.got[i].then_some(state.found[i].bytes);
                state.set_measured(item, bytes);
            }
            Task::none()
        }
        Msg::Toggle(item) => {
            if matches!(state.sheet, Sheet::None) {
                state.toggle(item);
            }
            Task::none()
        }
        Msg::Review => {
            if !ctx.busy && matches!(state.sheet, Sheet::None) && !state.selected().is_empty() {
                state.sheet = Sheet::Review;
            }
            Task::none()
        }
        Msg::Cancel => {
            if matches!(state.sheet, Sheet::Review) {
                state.sheet = Sheet::None;
            }
            Task::none()
        }
        Msg::Confirm => {
            let items = state.selected();
            if ctx.busy || !matches!(state.sheet, Sheet::Review) || items.is_empty() {
                return Task::none();
            }
            ctx.busy = true;
            state.run = Run {
                approx: items.contains(&Item::UpdateLeftovers),
                ..Run::default()
            };
            state.now = Instant::now();
            state.spin = anim::Clock::at(state.now);
            state.stash.clear();
            let helper: Vec<Item> = items
                .iter()
                .copied()
                .filter(|i| !cfg!(windows) && has_machine_part(*i))
                .collect();
            state.sheet = Sheet::Working(items.into_iter().map(|i| (i, Step::Waiting)).collect());
            let first = start_next(state, ctx);
            if helper.is_empty() {
                first
            } else {
                Task::batch([
                    first,
                    Task::run(system::machine(helper, true), |(item, r)| {
                        wrap(Msg::MachineCleaned(item, r))
                    }),
                ])
            }
        }
        Msg::MachineCleaned(item, result) => {
            let waiting = state.run.machine_waiting
                && matches!(&state.sheet, Sheet::Working(items)
                    if items.iter().any(|(i, step)| *i == item && *step == Step::Working));
            if waiting {
                state.run.machine_waiting = false;
                apply_cleaned(state, ctx, item, result)
            } else {
                state.stash.push((item, result));
                Task::none()
            }
        }
        Msg::Cleaned(item, result) => apply_cleaned(state, ctx, item, result),
        Msg::CloseResult => {
            if matches!(state.sheet, Sheet::Done { .. }) {
                state.sheet = Sheet::None;
            }
            Task::none()
        }
        Msg::StorageReported(reply) => {
            state.storage = Cell::Known(match reply {
                Ok(
                    r @ (Reply::Safe
                    | Reply::SafeByUs
                    | Reply::NeedsAttention
                    | Reply::NotApplicable
                    | Reply::Unavailable),
                ) => r,
                _ => Reply::Unknown,
            });
            Task::none()
        }
        Msg::StorageToggle(on) => {
            let Cell::Known(now) = state.storage else {
                return Task::none();
            };
            let op = match (on, now) {
                (true, Reply::NeedsAttention) => Op::Apply,
                (false, Reply::SafeByUs) => Op::Undo,
                _ => return Task::none(),
            };
            state.storage = Cell::Working;
            ctx.broker_task(Request::UserSetting(STORAGE, op), |r| {
                wrap(Msg::StorageChanged(r))
            })
        }
        Msg::StorageChanged(reply) => {
            let note = match reply {
                Ok(Reply::Done) => None,
                Ok(Reply::Unavailable) => Some(ctx.t("This setting can't be changed on this computer. Your work or school may control it.")),
                Ok(Reply::ChangedSince) => Some(ctx.t("This setting was changed again after Secblitz set it. Whatever you changed was left as it is.")),
                Err(e) if e == "unavailable" => Some(ctx.t(ctx.helper.blocker().unwrap_or(crate::gui::REOPEN_TO_DO_THIS))),
                _ => Some(ctx.t("We couldn't change that setting. It was left as it was. Please try again.")),
            };
            let reread = storage_query(ctx);
            match note {
                Some(text) => Task::batch([toast(text, Tone::Warn), reread]),
                None => reread,
            }
        }
    }
}

fn icon_of(item: Item) -> Icon {
    match item {
        Item::Temp => Icon::Trash,
        Item::UpdateLeftovers => Icon::Download,
        Item::CrashDumps => Icon::Bug,
        Item::Thumbnails | Item::ThumbnailCache => Icon::Eye,
        Item::PackageCaches => Icon::Package,
        Item::CrashReports => Icon::Bug,
        Item::FlatpakRuntimes => Icon::Download,
        Item::Trash => Icon::Trash,
        Item::OldSnaps | Item::OldKernels => Icon::Package,
    }
}

pub(crate) fn title(ctx: &Ctx, item: Item) -> String {
    ctx.t(match item {
        Item::Temp => "Old temporary files",
        Item::UpdateLeftovers => "Leftovers from Windows updates",
        Item::CrashDumps => "Crash memory files",
        Item::Thumbnails | Item::ThumbnailCache => "Saved picture previews",
        Item::PackageCaches => "Downloaded install files",
        Item::CrashReports => "Old crash reports",
        Item::FlatpakRuntimes => "Unused app parts",
        Item::Trash => "Trash",
        Item::OldSnaps => "Older copies of apps",
        Item::OldKernels => "Old system versions",
    })
}

fn describe(ctx: &Ctx, item: Item) -> String {
    ctx.t(match item {
        Item::Temp => "Files apps and installers left behind more than a week ago.",
        Item::UpdateLeftovers => {
            "Old copies of system files that updates replaced, and update downloads."
        }
        Item::CrashDumps => {
            "Copies of memory saved when something crashed. They can hold passwords."
        }
        Item::Thumbnails => "Small previews Windows keeps, even of pictures you deleted.",
        Item::PackageCaches => {
            "Copies of programs and updates your computer keeps after installing them."
        }
        Item::CrashReports => {
            "Reports your computer saved when a program crashed, more than a week ago."
        }
        Item::ThumbnailCache => {
            "Small previews your computer keeps of your pictures, even ones you deleted."
        }
        Item::FlatpakRuntimes => {
            "Shared parts that apps once needed. No app on this computer uses them now."
        }
        Item::Trash => "Files you moved to the Trash and have not emptied yet.",
        Item::OldSnaps => {
            "Earlier copies of apps that stayed behind after an update. The copy in use is not touched."
        }
        Item::OldKernels => {
            "Earlier versions of your system that updates left behind. The one in use and the newest one stay."
        }
    })
}

fn size_text(state: &State, ctx: &Ctx, item: Item) -> String {
    if item == Item::UpdateLeftovers {
        return ctx.t("Windows decides");
    }
    match state.sizes[slot(item)] {
        Size::Measuring => ctx.t("Measuring…"),
        Size::Unknown => {
            let waiting = state.needs_helper(item) && !person_ready(ctx);
            if state.generation == 0 || state.measuring() || waiting {
                String::new()
            } else {
                ctx.t("Couldn't measure")
            }
        }
        Size::Known(0) => ctx.t("Nothing to remove"),
        Size::Known(n) => secblitz::space::size_phrase(n),
    }
}

fn item_row<'a>(state: &State, ctx: &Ctx, item: Item) -> El<'a> {
    let p = ctx.palette;
    let name = title(ctx, item);
    let sub = describe(ctx, item);
    let tick = widgets::checkbox(
        p,
        state.ticked[slot(item)].into(),
        None,
        (state.can_tick(item) && !ctx.busy).then(|| wrap(Msg::Toggle(item))),
    );
    let size = widgets::muted(p, size_text(state, ctx, item));
    let sheet = widgets::info::for_check(ctx, name.clone(), item.id(), false)
        .map(|s| s.without(&[sub.as_str()]));
    let mut trailing = row![size].spacing(theme::S3).align_y(Alignment::Center);
    if let Some(info) = widgets::info::button(ctx, sheet) {
        trailing = trailing.push(info);
    }
    trailing = trailing.push(tick);
    widgets::row_item(p, Some(icon_of(item)), name, Some(sub), trailing, None)
}

fn button_label(state: &State, ctx: &Ctx) -> String {
    let bytes = state.selected_bytes();
    let update = state.ticked[slot(Item::UpdateLeftovers)];
    if bytes == 0 {
        ctx.t("Clean up selected")
    } else if update {
        ctx.t("Clean up selected ({size}, plus what Windows removes)")
            .replace("{size}", &secblitz::space::size_phrase(bytes))
    } else {
        ctx.t("Clean up selected ({size})")
            .replace("{size}", &secblitz::space::size_phrase(bytes))
    }
}

fn storage_row<'a>(state: &State, ctx: &Ctx) -> Option<El<'a>> {
    if !cfg!(windows) {
        return None;
    }
    let p = ctx.palette;
    let (icon, name) = super::ads::label(ctx, STORAGE);
    let toggle = |on: bool| wrap(Msg::StorageToggle(on));
    let (sub, control): (String, El<'a>) = match state.storage {
        _ if ctx.helper.blocker().is_some() => (
            ctx.t(ctx.helper.blocker().unwrap_or_default()),
            widgets::switch(p, false, None::<fn(bool) -> Message>),
        ),
        Cell::Idle => return None,
        Cell::Loading => (ctx.t("Checking…"), space::horizontal().width(0).into()),
        Cell::Working => (
            ctx.t("Changing…"),
            widgets::switch(p, false, None::<fn(bool) -> Message>),
        ),
        Cell::Known(Reply::NotApplicable) => return None,
        Cell::Known(Reply::Unavailable) => (
            ctx.t("Your organisation controls this setting."),
            widgets::switch(p, false, None::<fn(bool) -> Message>),
        ),
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
    let sheet = widgets::info::for_check(ctx, name.clone(), STORAGE.id(), false)
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
        name,
        Some(sub),
        control,
        None,
    ))
}

pub fn view<'a>(state: &'a State, ctx: &'a Ctx) -> El<'a> {
    let p = ctx.palette;
    let mut rows: Vec<El<'a>> = Vec::new();
    if let Some(blocker) = blocker(ctx) {
        rows.push(widgets::row_item(
            p,
            Some(Icon::Info),
            ctx.t(blocker),
            None,
            space::horizontal().width(0),
            None,
        ));
    }
    rows.extend(
        Item::offered()
            .into_iter()
            .map(|item| item_row(state, ctx, item)),
    );
    let can = !state.selected().is_empty() && !ctx.busy && matches!(state.sheet, Sheet::None);
    let button = row![
        space::horizontal(),
        widgets::action(
            p,
            ButtonKind::Primary,
            button_label(state, ctx),
            Some(Icon::Trash),
            can.then(|| wrap(Msg::Review)),
        )
    ];
    let mut page = column![
        widgets::group(
            p,
            ctx.t("Free up space"),
            Some(ctx.t(if cfg!(windows) {
                "Windows and apps leave files behind. Secblitz shows what they take and removes the ones you tick."
            } else {
                "Programs leave files behind. Secblitz shows what they take and removes the ones you tick."
            })),
            None,
            rows,
        ),
        button,
    ]
    .spacing(theme::S4);
    if let Some(row) = storage_row(state, ctx) {
        page = page.push(widgets::group(
            p,
            ctx.t("Keep it tidy automatically"),
            None,
            None,
            vec![row],
        ));
    }
    page.into()
}

pub fn modal<'a>(state: &'a State, ctx: &'a Ctx) -> Option<El<'a>> {
    match &state.sheet {
        Sheet::None => None,
        Sheet::Review => Some(review_sheet(state, ctx)),
        Sheet::Working(items) => Some(working_sheet(state, items, ctx)),
        Sheet::Done {
            freed,
            left_alone,
            failed,
            approx,
            restart,
        } => Some(widgets::appear::settle(
            result_sheet(ctx, *freed, *left_alone, *failed, *approx, *restart),
            ctx.palette.surface,
        )),
    }
}

fn review_sheet<'a>(state: &State, ctx: &Ctx) -> El<'a> {
    let p = ctx.palette;
    let mut list = column![].spacing(theme::S2);
    for item in state.selected() {
        list = list.push(
            row![
                widgets::icon(icon_of(item), 16.0, p.text_muted),
                widgets::body(p, title(ctx, item))
            ]
            .spacing(theme::S3)
            .align_y(Alignment::Center),
        );
    }
    let selected = state.selected();
    let mut col = column![
        widgets::h2(p, ctx.t("Clean up these files?")),
        widgets::scroll_well(p, list, 220.0),
        widgets::muted(
            p,
            ctx.t("These files are deleted for good and can't be brought back. Nothing you saved yourself is touched."),
        ),
    ]
    .spacing(theme::S3);
    if selected.contains(&Item::Trash) {
        col = col.push(widgets::inline_notice(
            p,
            Tone::Warn,
            ctx.t("Everything in the Trash will be deleted for good, including the Trash of drives you have connected."),
        ));
    }
    if !cfg!(windows) && selected.iter().any(|i| has_machine_part(*i)) {
        col = col.push(widgets::small(
            p,
            ctx.t("Your computer will ask for your password first."),
        ));
    }
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
                    ctx.t("Clean up"),
                    Some(Icon::Trash),
                    (!ctx.busy).then(|| wrap(Msg::Confirm)),
                ),
            ]
            .spacing(theme::S2),
        )
        .into()
}

fn working_sheet<'a>(state: &State, items: &[(Item, Step)], ctx: &Ctx) -> El<'a> {
    let p = ctx.palette;
    let mut list = column![].spacing(theme::S3);
    let mut slow = false;
    for (item, step) in items {
        let blank = || -> El<'a> { space::horizontal().width(theme::CHECK).into() };
        let (lead, note): (El<'a>, String) = match step {
            Step::Waiting => (blank(), ctx.t("Waiting")),
            Step::Working => {
                slow |= *item == Item::UpdateLeftovers;
                (
                    anim::spinner(18.0, p.text_muted, state.spin.elapsed_at(state.now)),
                    ctx.t("Cleaning up…"),
                )
            }
            Step::Done(at, false) => (
                anim::check_draw(18.0, p.good, anim::slow_progress(*at, state.now)),
                ctx.t("Done"),
            ),
            Step::Done(at, true) => (
                anim::cross_draw(18.0, p.bad, anim::slow_progress(*at, state.now)),
                ctx.t("Couldn't finish"),
            ),
        };
        list = list.push(widgets::step_row(
            p,
            lead,
            vec![widgets::body(p, title(ctx, *item))],
            note,
        ));
    }
    let mut col = column![
        widgets::h2(p, ctx.t("Cleaning up…")),
        widgets::scroll_well(p, list, 200.0),
    ]
    .spacing(theme::S3);
    if slow {
        col = col.push(widgets::muted(
            p,
            ctx.t("This can take a few minutes. You can keep using your computer."),
        ));
    }
    col.into()
}

fn result_sheet<'a>(
    ctx: &Ctx,
    freed: u64,
    left_alone: u64,
    failed: bool,
    approx: bool,
    restart: bool,
) -> El<'a> {
    let p = ctx.palette;
    let headline = if freed > 0 {
        ctx.t(if approx {
            "Freed about {size}."
        } else {
            "Freed {size}."
        })
        .replace("{size}", &secblitz::space::size_phrase(freed))
    } else {
        ctx.t("There was nothing to remove.")
    };
    let mut col = column![widgets::h2(p, headline)].spacing(theme::S3);
    if left_alone > 0 {
        col = col.push(widgets::muted(
            p,
            ctx.t("Some files were in use, so Secblitz left them alone."),
        ));
    }
    if failed {
        col = col.push(widgets::inline_notice(
            p,
            Tone::Warn,
            ctx.t("Some files couldn't be removed. Nothing else was changed."),
        ));
    }
    if restart {
        col = col.push(widgets::inline_notice(
            p,
            Tone::Warn,
            ctx.t("Windows needs to restart to finish an update before it can tidy the update leftovers. Restart when it suits you, then try again."),
        ));
    }
    col.push(space::vertical().height(theme::S1))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_shows_the_size_the_result_showed() {
        use secblitz::space::size_phrase;
        for bytes in [1, 524_287, 524_288, 168_296_448, 168_820_735, 1_073_741_000] {
            let mb = history_mb(bytes) as u64;
            assert_eq!(size_phrase(mb << 20), size_phrase(bytes), "{bytes}");
        }
    }

    #[test]
    fn nothing_is_ticked_when_the_tab_opens() {
        let state = State::default();
        assert!(Item::ALL.iter().all(|i| !state.ticked(*i)));
    }

    #[test]
    fn rows_with_nothing_to_remove_cannot_be_ticked() {
        let mut state = State::default();
        state.set_measured(Item::Temp, Some(0));
        assert!(!state.can_tick(Item::Temp));
        state.set_measured(Item::Temp, Some(10 << 20));
        assert!(state.can_tick(Item::Temp));
        assert!(state.can_tick(Item::UpdateLeftovers));
    }

    #[test]
    fn the_button_total_adds_only_ticked_measured_rows() {
        let mut state = State::default();
        state.set_measured(Item::Temp, Some(1 << 30));
        state.set_measured(Item::CrashDumps, Some(2 << 30));
        state.toggle(Item::Temp);
        assert_eq!(state.selected_bytes(), 1 << 30);
    }

    #[test]
    fn a_row_that_measures_as_empty_loses_its_tick() {
        let mut state = State::default();
        state.set_measured(Item::Thumbnails, Some(5 << 20));
        state.toggle(Item::Thumbnails);
        assert!(state.ticked(Item::Thumbnails));
        state.set_measured(Item::Thumbnails, Some(0));
        assert!(!state.ticked(Item::Thumbnails));
    }

    #[test]
    fn user_items_wait_for_the_helper() {
        let state = State::default();
        assert!(state.needs_helper(Item::Thumbnails));
        assert!(!state.needs_helper(Item::UpdateLeftovers));
        assert_eq!(parts(Item::Thumbnails, false), 0);
        assert_eq!(parts(Item::Temp, false), 1);
        assert_eq!(parts(Item::Temp, true), 2);
        assert_eq!(parts(Item::UpdateLeftovers, true), 1);
    }

    fn test_ctx() -> Ctx {
        let (app, _) = crate::gui::App::new(crate::gui::Options {
            lang: crate::i18n::Lang::En,
            broker: None,
            start: None,
        });
        app.ctx
    }

    #[test]
    fn a_failed_helper_part_marks_the_item_failed() {
        let mut run = Run::default();
        count_result(&mut run, Item::Temp, Err("unavailable".into()));
        assert!(run.item_failed);
        let mut run = Run::default();
        count_result(&mut run, Item::Thumbnails, Err("failed".into()));
        assert!(run.item_failed);
        let mut run = Run::default();
        count_result(&mut run, Item::UpdateLeftovers, Err("unavailable".into()));
        assert!(!run.item_failed);
        count_result(
            &mut run,
            Item::UpdateLeftovers,
            Err("Windows stopped".into()),
        );
        assert!(run.item_failed);
        let mut run = Run::default();
        let t = Tally {
            bytes: 5,
            files: 1,
            left_alone: 0,
        };
        count_result(&mut run, Item::Temp, Ok(t));
        assert_eq!(run.total.bytes, 5);
        assert!(!run.item_failed);
    }

    #[test]
    fn a_pending_restart_asks_for_a_restart_instead_of_a_failure() {
        let mut ctx = test_ctx();
        let mut state = State {
            sheet: Sheet::Working(vec![(Item::UpdateLeftovers, Step::Working)]),
            ..State::default()
        };
        state.run.pending = 1;
        let _ = update(
            &mut state,
            Msg::Cleaned(
                Item::UpdateLeftovers,
                Err(secblitz::space::NEEDS_RESTART.into()),
            ),
            &mut ctx,
        );
        assert!(matches!(
            state.sheet,
            Sheet::Done {
                failed: false,
                restart: true,
                ..
            }
        ));
    }

    #[test]
    fn a_policy_controlled_storage_sense_is_reported_as_such() {
        let mut ctx = test_ctx();
        let mut state = State::default();
        let _ = update(
            &mut state,
            Msg::StorageReported(Ok(Reply::Unavailable)),
            &mut ctx,
        );
        assert_eq!(state.storage, Cell::Known(Reply::Unavailable));
        let _ = update(&mut state, Msg::StorageToggle(true), &mut ctx);
        assert_eq!(state.storage, Cell::Known(Reply::Unavailable));
    }

    #[test]
    fn leftover_folders_are_measured_only_on_the_free_up_space_tab() {
        let mut ctx = test_ctx();
        let mut state = super::super::State::default();
        let _ = super::super::load_space_tab(&mut state, &ctx);
        assert_eq!(state.space.generation, 0);
        state.tab = super::super::Tab::Space;
        let _ = super::super::load_space_tab(&mut state, &ctx);
        assert_eq!(state.space.generation, 1);
        state.space.pending = [1; COUNT];
        let _ = super::super::load_space_tab(&mut state, &ctx);
        assert_eq!(state.space.generation, 1);
        let _ = &mut ctx;
    }

    #[test]
    fn every_item_has_an_explainer() {
        for item in Item::ALL {
            assert!(
                secblitz::explain::for_check(item.id()).is_some(),
                "{}",
                item.id()
            );
        }
    }
}
