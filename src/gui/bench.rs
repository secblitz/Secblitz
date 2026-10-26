//! Timing of the interface on the CPU renderer. Run with
//! `CARGO_PROFILE_DEV_OPT_LEVEL=2 cargo test bench_pages -- --ignored --nocapture`.
use super::*;
use crate::app::settings::ToolsTab;
use iced::advanced::layout::{Layout, Limits};
use iced::advanced::renderer::Headless;
use iced::advanced::renderer::Renderer as _;
use iced::advanced::widget::Tree;
use iced::advanced::{mouse, renderer};
use iced::Rectangle;
use secblitz::engine::Outcome;
use secblitz::user_settings::Setting;
use std::time::Instant;

const SIZE: iced::Size = iced::Size::new(1100.0, 720.0);
const RUNS: u32 = 20;

fn report() -> Report {
    let statuses = [
        "attention",
        "compliant",
        "applied",
        "attention",
        "compliant",
    ];
    Report {
        results: secblitz::hardening::all()
            .iter()
            .enumerate()
            .map(|(i, spec)| Outcome {
                id: spec.id.into(),
                title: spec.title.into(),
                status: statuses[i % statuses.len()].into(),
                detail: spec.description.into(),
                ..Outcome::default()
            })
            .collect(),
        ..Report::default()
    }
}

fn app() -> App {
    let (mut app, _) = App::new(Options {
        lang: Lang::En,
        broker: None,
        start: None,
    });
    // Whether the what's new note opens depends on this PC's earlier use of Secblitz.
    app.whats_new = false;
    let report = report();
    app.ctx.catalog.available = report.results.iter().map(|r| r.id.clone()).collect();
    app.ctx.checking = None;
    app.ctx.checked_at = Some(app::history::now());
    app.ctx.report = Some(Arc::new(report));
    let installed = (0..secblitz::debloat::catalog::CATALOG.len() as u16)
        .map(|index| secblitz::debloat::Installed {
            index,
            package: secblitz::debloat::catalog::CATALOG[index as usize]
                .family
                .into(),
            version: "1.0.0.0".into(),
        })
        .collect();
    let _ = app.update(Message::Debloat(debloat::Msg::Scanned(0, Ok(installed))));
    app
}

fn avg(f: &mut dyn FnMut()) -> f64 {
    f();
    let start = Instant::now();
    for _ in 0..RUNS {
        f();
    }
    start.elapsed().as_secs_f64() * 1000.0 / RUNS as f64
}

#[test]
fn the_toast_leaves_four_seconds_after_the_latest_one() {
    let mut app = app();
    drop(app.update(Message::Toast("First.".into(), Tone::Good)));
    drop(app.update(Message::Toast("Second.".into(), Tone::Good)));
    drop(app.update(Message::ToastExpire(1)));
    assert!(
        app.ctx.toast.is_some() && !app.toast_leaving,
        "an old timer must not close a newer toast"
    );
    drop(app.update(Message::ToastExpire(2)));
    assert!(app.toast_leaving || app.ctx.toast.is_none());
}

#[test]
fn checking_again_shows_the_whole_checking_screen_then_hands_off() {
    let _motion = widgets::anim::forced::set(false);
    let mut app = app();
    drop(app.update(Message::CheckNow));
    assert!(home::fills_window(&app.ctx) && fixes::fills_window(&app.ctx));
    let done = Ok(app.ctx.report.clone().expect("a report"));
    drop(app.update(Message::Worker(worker::Event::Checked(done))));
    assert!(
        app.ctx.finishing && app.handoff.is_some(),
        "the result waits for the screen to settle"
    );
    drop(app.update(Message::Navigate(Page::Settings)));
    assert!(!app.ctx.finishing && app.ctx.checking.is_none());
}

#[test]
fn a_fresh_start_checks_the_pc_instead_of_waiting_on_a_check_that_never_began() {
    let mut app = app();
    app.ctx.damage = Some(pages::recovery::DamageInfo::new(
        secblitz::engine::recover::JournalDamaged {
            kind: secblitz::engine::recover::DamageKind::Total,
            files: 1,
        },
    ));
    let catalog = app.ctx.catalog.clone();
    drop(app.update(Message::Worker(worker::Event::Recovered(Ok(catalog)))));
    assert!(app.ctx.damage.is_none() && app.ctx.report.is_none());
    assert!(
        app.ctx.checking.is_some(),
        "the checking screen must belong to a check that is running"
    );
}

#[test]
fn the_check_after_a_fix_keeps_the_results_on_screen() {
    let mut app = app();
    app.ctx.checking = Some(CheckProgress {
        phase: Some(worker::Phase::Verifying),
        items: Vec::new(),
    });
    assert!(!home::fills_window(&app.ctx) && !fixes::fills_window(&app.ctx));
}

fn type_into_protection(app: &mut App, text: &str) {
    drop(app.update(Message::Fixes(fixes::Msg::Search(text.into()))));
}

fn shown_on_protection(app: &App) -> Vec<String> {
    fixes::visible_rows(&app.fixes, &app.ctx)
}

#[test]
fn typing_in_protection_keeps_only_matching_rows_in_their_normal_order() {
    let mut app = app();
    app.page = Page::Fixes;
    let all = shown_on_protection(&app);
    assert!(all.len() > 20, "{}", all.len());
    type_into_protection(&mut app, "firewall");
    let some = shown_on_protection(&app);
    assert!(
        !some.is_empty() && some.len() < all.len(),
        "{} of {}",
        some.len(),
        all.len()
    );
    let in_order: Vec<_> = all.iter().filter(|key| some.contains(key)).collect();
    assert_eq!(
        in_order,
        some.iter().collect::<Vec<_>>(),
        "rows must not jump around"
    );
    type_into_protection(&mut app, "firewall zzzqqq");
    assert!(
        shown_on_protection(&app).is_empty(),
        "every word has to match"
    );
    type_into_protection(&mut app, "  ");
    assert_eq!(shown_on_protection(&app), all, "blank means no filter");
    drop(app.view());
}

#[test]
fn a_row_is_found_by_its_id_and_by_a_typo() {
    let mut app = app();
    let all = shown_on_protection(&app);
    let id = all[0].clone();
    type_into_protection(&mut app, &id);
    assert!(shown_on_protection(&app).contains(&id));
    type_into_protection(&mut app, "frewall");
    assert!(!shown_on_protection(&app).is_empty());
}

#[test]
fn english_words_still_find_rows_while_the_app_is_in_another_language() {
    let mut app = app();
    type_into_protection(&mut app, "firewall");
    let english = shown_on_protection(&app);
    app.ctx.lang = Lang::De;
    drop(app.update(Message::Fixes(fixes::Msg::Search("firewall".into()))));
    let german = shown_on_protection(&app);
    assert!(!english.is_empty());
    assert!(
        english.iter().all(|key| german.contains(key)),
        "{english:?} vs {german:?}"
    );
    drop(app.view());
}

#[test]
fn a_search_with_no_match_shows_the_calm_page_and_clearing_brings_everything_back() {
    let mut app = app();
    app.page = Page::Fixes;
    let all = shown_on_protection(&app);
    type_into_protection(&mut app, "qqqzzzxxx");
    assert!(shown_on_protection(&app).is_empty());
    drop(app.view());
    drop(app.update(Message::Fixes(fixes::Msg::ClearSearch)));
    assert_eq!(shown_on_protection(&app), all);
    type_into_protection(&mut app, "firewall");
    drop(app.update(Message::Escape));
    assert_eq!(shown_on_protection(&app), all, "Escape clears the search");
}

#[test]
fn select_all_in_protection_takes_only_the_rows_shown_and_hidden_choices_stay() {
    let mut app = app();
    let none = |app: &mut App| drop(app.update(Message::Fixes(fixes::Msg::SelectNone)));
    none(&mut app);
    assert!(fixes::selected_ids(&app.fixes).is_empty());
    type_into_protection(&mut app, "firewall");
    let first = fixes::shown_fixable(&app.fixes, &app.ctx);
    assert!(
        !first.is_empty(),
        "the test report needs a fixable firewall row"
    );
    drop(app.update(Message::Fixes(fixes::Msg::SelectAll)));
    let mut expected = first.clone();
    expected.sort();
    assert_eq!(fixes::selected_ids(&app.fixes), expected);

    let others: Vec<String> = fixes::shown_fixable(&app.fixes, &app.ctx);
    type_into_protection(&mut app, "");
    let every: Vec<String> = fixes::shown_fixable(&app.fixes, &app.ctx);
    assert!(
        every.len() > others.len(),
        "the unfiltered list has more fixable rows"
    );
    let outside = every.iter().find(|id| !first.contains(id)).unwrap().clone();
    type_into_protection(&mut app, &outside);
    assert!(!fixes::shown_fixable(&app.fixes, &app.ctx)
        .iter()
        .any(|id| first.contains(id)));
    assert_eq!(
        fixes::selected_ids(&app.fixes),
        expected,
        "typing never changes the choice"
    );
    drop(app.update(Message::Fixes(fixes::Msg::SelectAll)));
    let selected = fixes::selected_ids(&app.fixes);
    assert!(selected.contains(&outside) && first.iter().all(|id| selected.contains(id)));
    drop(app.update(Message::Fixes(fixes::Msg::SelectNone)));
    let left = fixes::selected_ids(&app.fixes);
    assert!(
        !left.contains(&outside) && first.iter().all(|id| left.contains(id)),
        "none only clears what is shown"
    );
    drop(app.view());
    type_into_protection(&mut app, "");
    drop(app.update(Message::Fixes(fixes::Msg::SelectAll)));
    assert_eq!(fixes::selected_ids(&app.fixes).len(), every.len());
}

fn with_report(app: &mut App, edit: impl FnOnce(&mut Report)) {
    let mut r = report();
    edit(&mut r);
    app.ctx.catalog.available = r.results.iter().map(|o| o.id.clone()).collect();
    app.ctx.checked_at = Some(app.ctx.checked_at.unwrap_or(0) + 1);
    app.ctx.report = Some(Arc::new(r));
}

/// Marks the first `n` protected settings as ones Secblitz changed.
fn mark_undoable(r: &mut Report, n: usize) -> Vec<String> {
    let mut ids = Vec::new();
    for o in r
        .results
        .iter_mut()
        .filter(|o| o.status == CheckStatus::Compliant)
    {
        if ids.len() == n {
            break;
        }
        o.undoable = true;
        ids.push(o.id.clone());
    }
    ids
}

fn app_with_undoable(n: usize) -> (App, Vec<String>) {
    let mut app = app();
    let mut ids = Vec::new();
    with_report(&mut app, |r| ids = mark_undoable(r, n));
    assert_eq!(ids.len(), n);
    (app, ids)
}

fn lays_out(app: &mut App, renderer: &iced::Renderer) {
    app.enter_t = 1.0;
    let mut element = app.view();
    let mut tree = Tree::new(&element);
    let node =
        element
            .as_widget_mut()
            .layout(&mut tree, renderer, &Limits::new(iced::Size::ZERO, SIZE));
    assert!(node.size().width > 0.0 && node.size().height > 0.0);
}

fn restored(id: &str) -> Outcome {
    Outcome {
        id: id.into(),
        status: CheckStatus::Restored,
        ..Outcome::default()
    }
}

#[test]
fn settings_secblitz_changed_come_first_and_nothing_starts_chosen() {
    let (mut app, ids) = app_with_undoable(3);
    app.page = Page::Fixes;
    assert!(fixes::undo_selected_ids(&app.fixes).is_empty());
    assert_eq!(fixes::all_undoable(&app.fixes, &app.ctx).len(), 3);
    let rows = fixes::visible_rows(&app.fixes, &app.ctx);
    let at = |id: &String| rows.iter().position(|k| k == id).expect("shown");
    let plain: Vec<String> = app
        .ctx
        .report
        .as_deref()
        .unwrap()
        .results
        .iter()
        .filter(|o| o.status == CheckStatus::Compliant && !o.undoable)
        .map(|o| o.id.clone())
        .collect();
    assert!(!plain.is_empty());
    let last_changed = ids.iter().map(at).max().unwrap();
    assert!(
        plain.iter().all(|id| at(id) > last_changed),
        "changed settings sort first"
    );
    drop(app.update(Message::Fixes(fixes::Msg::ToggleUndo(plain[0].clone()))));
    assert!(
        fixes::undo_selected_ids(&app.fixes).is_empty(),
        "only changed settings can be chosen"
    );
    drop(app.update(Message::Fixes(fixes::Msg::ToggleUndo(ids[0].clone()))));
    assert_eq!(fixes::undo_selected_ids(&app.fixes), vec![ids[0].clone()]);
    drop(app.update(Message::Fixes(fixes::Msg::ToggleUndo(ids[0].clone()))));
    assert!(fixes::undo_selected_ids(&app.fixes).is_empty());
    drop(app.update(Message::Fixes(fixes::Msg::FocusUndo)));
    assert!(fixes::open_protected(&app.fixes, &app.ctx));
    drop(app.view());
}

#[test]
fn a_chosen_selection_acts_on_the_rows_shown_and_is_pruned_by_a_new_check() {
    let (mut app, ids) = app_with_undoable(3);
    drop(app.update(Message::Fixes(fixes::Msg::UndoSelectAll)));
    assert_eq!(fixes::undo_selected_ids(&app.fixes).len(), 3);
    drop(app.update(Message::Fixes(fixes::Msg::UndoSelectNone)));
    assert!(fixes::undo_selected_ids(&app.fixes).is_empty());

    type_into_protection(&mut app, &ids[0]);
    let shown = fixes::shown_undoable(&app.fixes, &app.ctx);
    assert!(shown.contains(&ids[0]) && shown.len() < 3, "{shown:?}");
    drop(app.update(Message::Fixes(fixes::Msg::UndoSelectAll)));
    let mut want = shown.clone();
    want.sort();
    assert_eq!(
        fixes::undo_selected_ids(&app.fixes),
        want,
        "only what the search shows"
    );
    type_into_protection(&mut app, "");
    drop(app.update(Message::Fixes(fixes::Msg::UndoSelectAll)));
    assert_eq!(fixes::undo_selected_ids(&app.fixes).len(), 3);
    type_into_protection(&mut app, &ids[0]);
    drop(app.update(Message::Fixes(fixes::Msg::UndoSelectNone)));
    let left = fixes::undo_selected_ids(&app.fixes);
    assert!(
        !left.contains(&ids[0]) && left.len() == 3 - shown.len(),
        "none only clears what is shown"
    );
    drop(app.view());
    type_into_protection(&mut app, "");

    let keep = left[0].clone();
    with_report(&mut app, |r| {
        for o in &mut r.results {
            o.undoable = o.id == keep;
        }
    });
    drop(app.update(Message::Fixes(fixes::Msg::Search(String::new()))));
    assert_eq!(
        fixes::undo_selected_ids(&app.fixes),
        vec![keep],
        "a new check keeps only what can still be put back"
    );
    with_report(&mut app, |_| {});
    drop(app.update(Message::Fixes(fixes::Msg::Search(String::new()))));
    assert!(fixes::undo_selected_ids(&app.fixes).is_empty());
}

#[test]
fn putting_back_chosen_settings_goes_from_review_to_working_to_a_calm_result() {
    let _motion = widgets::anim::forced::set(false);
    let (mut app, ids) = app_with_undoable(3);
    let stranger = "not.changed.by.us".to_owned();
    drop(app.update(Message::ReviewUndoSome(vec![
        ids[1].clone(),
        stranger,
        ids[1].clone(),
        ids[0].clone(),
    ])));
    assert_eq!(
        fixflow::review(&app.fix),
        Some((vec![ids[1].clone(), ids[0].clone()], true)),
        "only settings Secblitz changed, once each, in the order chosen"
    );
    assert_eq!(
        fixflow::plan_ids(&app.fix),
        vec![ids[1].clone(), ids[0].clone()]
    );
    assert!(!fixflow::added_together(&app.fix));
    drop(app.view());

    drop(app.update(Message::Fix(fixflow::Msg::Cancel)));
    assert_eq!(fixflow::stage_name(&app.fix), "closed");
    drop(app.update(Message::ReviewUndoSome(vec![ids[0].clone()])));
    drop(app.update(Message::Escape));
    assert_eq!(fixflow::stage_name(&app.fix), "closed");

    app.ctx.busy = true;
    drop(app.update(Message::ReviewUndoSome(vec![ids[0].clone()])));
    assert_eq!(
        fixflow::stage_name(&app.fix),
        "closed",
        "nothing opens while another job runs"
    );
    app.ctx.busy = false;
    app.ctx.checking = Some(CheckProgress::default());
    drop(app.update(Message::ReviewUndoSome(vec![ids[0].clone()])));
    assert_eq!(
        fixflow::stage_name(&app.fix),
        "closed",
        "nor while a check runs"
    );
    app.ctx.checking = None;

    drop(app.update(Message::ReviewUndoSome(vec![
        ids[0].clone(),
        ids[1].clone(),
    ])));
    drop(app.update(Message::Fix(fixflow::Msg::Confirm)));
    assert_eq!(
        fixflow::stage_name(&app.fix),
        "review",
        "a pre-flight check comes first"
    );
    drop(app.update(Message::Worker(worker::Event::Preflight {
        undo: true,
        result: Ok(()),
    })));
    assert_eq!(fixflow::stage_name(&app.fix), "working");
    assert!(app.ctx.busy);
    drop(app.view());
    for id in [&ids[0], &ids[1]] {
        drop(app.update(Message::Worker(worker::Event::Progress {
            phase: worker::Phase::Undoing,
            id: id.clone(),
            status: "restored".into(),
        })));
    }
    drop(app.view());

    let result = Report {
        results: vec![
            restored(&ids[0]),
            Outcome {
                id: ids[1].clone(),
                status: CheckStatus::Conflict,
                ..Outcome::default()
            },
        ],
        ..Report::default()
    };
    drop(app.update(Message::Worker(worker::Event::Undone {
        chosen: vec![ids[0].clone(), ids[1].clone()],
        result: Ok(Arc::new(result)),
        verify: Ok(app.ctx.report.clone().unwrap()),
    })));
    assert!(!app.ctx.busy);
    assert_eq!(fixflow::stage_name(&app.fix), "result");
    let summary = fixflow::result_summary(&app.fix).expect("a result");
    assert_eq!(summary.done, vec![ids[0].clone()]);
    assert_eq!(
        summary.not_done,
        vec![(ids[1].clone(), app::flow::REASON_LEFT_AS_IS.to_owned())]
    );
    assert!(!summary.less_protected.is_empty());
    drop(app.view());
    drop(app.update(Message::Fix(fixflow::Msg::Done)));
    assert_eq!(fixflow::stage_name(&app.fix), "closed");
}

#[test]
fn a_protection_another_one_needs_is_added_and_said_so() {
    use secblitz::vbs::{MEMORY_INTEGRITY, STACK_PROTECTION};
    let mut app = app();
    with_report(&mut app, |r| {
        for o in &mut r.results {
            if o.id == MEMORY_INTEGRITY || o.id == STACK_PROTECTION {
                o.status = CheckStatus::Compliant;
                o.undoable = true;
            }
        }
    });
    drop(app.update(Message::ReviewUndoSome(vec![MEMORY_INTEGRITY.into()])));
    assert_eq!(
        fixflow::plan_ids(&app.fix),
        vec![STACK_PROTECTION.to_owned(), MEMORY_INTEGRITY.to_owned()]
    );
    assert!(fixflow::added_together(&app.fix));
    let renderer = iced::futures::executor::block_on(<iced::Renderer as Headless>::new(
        theme::REGULAR,
        14.0.into(),
        Some("tiny-skia"),
    ))
    .expect("tiny-skia renderer");
    for lang in [Lang::En, Lang::De] {
        app.ctx.lang = lang;
        lays_out(&mut app, &renderer);
    }
    drop(app.update(Message::Fix(fixflow::Msg::Cancel)));
    drop(app.update(Message::ReviewUndoSome(vec![STACK_PROTECTION.into()])));
    assert!(!fixflow::added_together(&app.fix));
}

#[test]
fn the_last_fixes_come_from_the_check_and_follow_a_partial_undo() {
    let (mut app, ids) = app_with_undoable(3);
    with_report(&mut app, |r| {
        r.undo_next = vec![ids[0].clone(), ids[1].clone()]
    });
    drop(app.update(Message::ReviewUndo));
    assert_eq!(fixflow::review(&app.fix), Some((Vec::new(), true)));
    assert_eq!(
        fixflow::plan_ids(&app.fix),
        vec![ids[0].clone(), ids[1].clone()]
    );
    drop(app.update(Message::Fix(fixflow::Msg::Cancel)));
    with_report(&mut app, |r| r.undo_next = vec![ids[1].clone()]);
    drop(app.update(Message::ReviewUndo));
    assert_eq!(
        fixflow::plan_ids(&app.fix),
        vec![ids[1].clone()],
        "no stale rows"
    );
    drop(app.update(Message::Fix(fixflow::Msg::Cancel)));
    with_report(&mut app, |_| {});
    drop(app.update(Message::ReviewUndo));
    assert!(fixflow::plan_ids(&app.fix).is_empty());
    drop(app.view());
}

#[test]
fn the_history_row_opens_the_protection_page_on_the_changed_settings() {
    let (mut app, _) = app_with_undoable(2);
    drop(app.update(Message::Navigate(Page::History)));
    assert_eq!(app.page, Page::History);
    drop(app.update(Message::PutBackChosen));
    assert_eq!(app.page, Page::Fixes);
    assert!(fixes::open_protected(&app.fixes, &app.ctx));
}

#[test]
fn the_protection_page_lays_out_with_changed_settings_chosen_and_while_busy() {
    let renderer = iced::futures::executor::block_on(<iced::Renderer as Headless>::new(
        theme::REGULAR,
        14.0.into(),
        Some("tiny-skia"),
    ))
    .expect("tiny-skia renderer");
    let (mut app, ids) = app_with_undoable(3);
    app.page = Page::Fixes;
    drop(app.update(Message::Fixes(fixes::Msg::FocusUndo)));
    lays_out(&mut app, &renderer);
    drop(app.update(Message::Fixes(fixes::Msg::ToggleUndo(ids[0].clone()))));
    lays_out(&mut app, &renderer);
    app.ctx.busy = true;
    lays_out(&mut app, &renderer);
    app.ctx.busy = false;
    for typed in [ids[0].as_str(), "qqqzzz"] {
        type_into_protection(&mut app, typed);
        lays_out(&mut app, &renderer);
    }
    app.ctx.lang = Lang::Fr;
    type_into_protection(&mut app, "");
    lays_out(&mut app, &renderer);
}

fn type_into_clean_up(app: &mut App, text: &str) {
    drop(app.update(Message::Debloat(debloat::Msg::Search(text.into()))));
}

#[test]
fn the_copilot_row_follows_the_app_scan_and_opens_clean_up_apps_on_it() {
    let mut scanned = app();
    assert!(scanned.ctx.copilot_installed);
    drop(scanned.update(Message::Debloat(debloat::Msg::Scanned(0, Ok(Vec::new())))));
    assert!(!scanned.ctx.copilot_installed);

    let mut app = app();
    app.page = Page::Fixes;
    drop(app.update(Message::OpenCleanUp(debloat::COPILOT_APP)));
    assert_eq!(app.page, Page::Debloat);
    let names: Vec<&str> = debloat::visible_apps(&app.debloat, &app.ctx)
        .into_iter()
        .map(|i| secblitz::debloat::catalog()[i as usize].name)
        .collect();
    assert!(names.contains(&"Copilot") && !names.contains(&"Solitaire games"));
    drop(app.view());
}

#[test]
fn typing_in_clean_up_apps_hides_other_apps_and_finds_typos_and_package_names() {
    let mut app = app();
    app.page = Page::Debloat;
    let all = debloat::visible_apps(&app.debloat, &app.ctx);
    assert!(all.len() > 20);
    type_into_clean_up(&mut app, "xbox");
    let xbox = debloat::visible_apps(&app.debloat, &app.ctx);
    assert!(!xbox.is_empty() && xbox.len() < all.len());
    drop(app.view());
    type_into_clean_up(&mut app, "solitare");
    let names: Vec<&str> = debloat::visible_apps(&app.debloat, &app.ctx)
        .into_iter()
        .map(|i| secblitz::debloat::catalog()[i as usize].name)
        .collect();
    assert_eq!(names, ["Solitaire games"]);
    type_into_clean_up(&mut app, "GamingOverlay");
    let by_package = debloat::visible_apps(&app.debloat, &app.ctx);
    assert!(by_package
        .iter()
        .any(|i| secblitz::debloat::catalog()[*i as usize].name == "Game Bar"));
    type_into_clean_up(&mut app, "qqqzzz");
    assert!(debloat::visible_apps(&app.debloat, &app.ctx).is_empty());
    drop(app.view());
    drop(app.update(Message::Escape));
    assert_eq!(
        debloat::visible_apps(&app.debloat, &app.ctx),
        all,
        "Escape clears the search"
    );
}

#[test]
fn choosing_a_whole_group_while_searching_takes_only_the_apps_shown() {
    let mut app = app();
    type_into_clean_up(&mut app, "xbox");
    let shown = debloat::visible_apps(&app.debloat, &app.ctx);
    let group = secblitz::debloat::catalog()[shown[0] as usize].group;
    drop(app.update(Message::Debloat(debloat::Msg::ToggleGroup(group))));
    let chosen = debloat::selected_apps(&app.debloat);
    let in_group: Vec<u16> = shown
        .iter()
        .copied()
        .filter(|i| secblitz::debloat::catalog()[*i as usize].group == group)
        .collect();
    assert_eq!(chosen, in_group);
    type_into_clean_up(&mut app, "weather");
    assert_eq!(
        debloat::selected_apps(&app.debloat),
        in_group,
        "hidden choices stay"
    );
    drop(app.update(Message::Debloat(debloat::Msg::ToggleGroup(
        secblitz::debloat::catalog()[0].group,
    ))));
    let after = debloat::selected_apps(&app.debloat);
    assert!(in_group.iter().all(|i| after.contains(i)) && after.len() > in_group.len());
    drop(app.update(Message::Debloat(debloat::Msg::ClearSearch)));
    drop(app.view());
}

#[test]
fn both_pages_lay_out_with_a_search_active_and_with_nothing_found() {
    let renderer = iced::futures::executor::block_on(<iced::Renderer as Headless>::new(
        theme::REGULAR,
        14.0.into(),
        Some("tiny-skia"),
    ))
    .expect("tiny-skia renderer");
    let mut app = app();
    for (page, found, nothing) in [
        (Page::Fixes, "firewall", "qqqzzz"),
        (Page::Debloat, "xbox", "qqqzzz"),
    ] {
        app.page = page;
        app.enter_t = 1.0;
        for typed in ["", found, nothing] {
            match page {
                Page::Fixes => type_into_protection(&mut app, typed),
                _ => type_into_clean_up(&mut app, typed),
            }
            let mut element = app.view();
            let mut tree = Tree::new(&element);
            let node = element.as_widget_mut().layout(
                &mut tree,
                &renderer,
                &Limits::new(iced::Size::ZERO, SIZE),
            );
            assert!(
                node.size().width > 0.0 && node.size().height > 0.0,
                "{page:?} {typed:?}"
            );
        }
    }
}

fn tools_msg(app: &mut App, msg: tools::Msg) {
    drop(app.update(Message::Tools(msg)));
}

const TOOLS_TABS: [ToolsTab; 4] = [
    ToolsTab::Tips,
    ToolsTab::Viruses,
    ToolsTab::Updates,
    ToolsTab::Account,
];

fn open_tools_tab(app: &mut App, tab: ToolsTab) {
    tools_msg(app, tools::Msg::SetTab(tab));
}

#[test]
fn the_tools_page_opens_on_pc_health_tips() {
    let mut app = app();
    assert_eq!(app.ctx.prefs.tools_tab, ToolsTab::Tips);
    app.page = Page::Tools;
    drop(app.view());
}

#[test]
fn every_tools_tab_draws_in_every_language_with_work_finished() {
    let mut app = app();
    tools_msg(&mut app, tools::Msg::ScanDone(Ok(())));
    tools_msg(&mut app, tools::Msg::DefenderDone(Err("offline".into())));
    tools_msg(&mut app, tools::Msg::Found(Err(("raw".into(), "network"))));
    tools_msg(
        &mut app,
        tools::Msg::BitwardenDone(Ok(crate::broker::Reply::Done)),
    );
    app.page = Page::Tools;
    for lang in [Lang::En, Lang::De, Lang::Fr] {
        app.ctx.lang = lang;
        for tab in TOOLS_TABS {
            open_tools_tab(&mut app, tab);
            assert_eq!(app.ctx.prefs.tools_tab, tab);
            drop(app.view());
        }
    }
}

#[test]
fn the_tools_tabs_fit_the_narrowest_window_in_every_language_with_work_on_every_tab() {
    // Measure with the app's own fonts, not whatever this system falls back to.
    for bytes in theme::FONT_FILES {
        iced::advanced::graphics::text::font_system()
            .write()
            .expect("font system")
            .load_font(std::borrow::Cow::Borrowed(bytes));
    }
    let renderer = iced::futures::executor::block_on(<iced::Renderer as Headless>::new(
        theme::REGULAR,
        14.0.into(),
        Some("tiny-skia"),
    ))
    .expect("tiny-skia renderer");
    let mut app = app();
    // Window minus the 232 px sidebar, the 40 px page padding on both sides and a scrollbar.
    let room = (theme::WINDOW_MIN_WIDTH - 232.0 - 2.0 * theme::S10 - 16.0).min(PAGE_MAX_WIDTH);
    for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
        app.ctx.lang = lang;
        let options = TOOLS_TABS.map(|t| {
            (
                t,
                format!("{}{}", tools::tab_name(&app.ctx, t), tools::BUSY_MARK),
            )
        });
        let mut element = widgets::segmented(app.ctx.palette, &options, ToolsTab::Tips, |_| {
            Message::Toast(String::new(), Tone::Good)
        });
        let mut tree = Tree::new(&element);
        let node = element.as_widget_mut().layout(
            &mut tree,
            &renderer,
            &Limits::new(iced::Size::ZERO, iced::Size::INFINITE),
        );
        assert!(
            node.size().width > 200.0,
            "{lang:?}: the tabs were not measured"
        );
        assert!(
            node.size().width <= room,
            "{lang:?}: tabs are {} wide, {room} is free",
            node.size().width
        );
    }
}

#[test]
fn picking_a_tools_tab_changes_only_that_choice() {
    let mut app = app();
    app.ctx.lang = Lang::De;
    app.ctx.prefs.lang = Some("de".into());
    open_tools_tab(&mut app, ToolsTab::Viruses);
    assert_eq!(app.ctx.prefs.tools_tab, ToolsTab::Viruses);
    assert_eq!(app.ctx.prefs.lang.as_deref(), Some("de"));
    open_tools_tab(&mut app, ToolsTab::Viruses);
    assert_eq!(app.ctx.prefs.tools_tab, ToolsTab::Viruses);
}

#[test]
fn the_tools_tab_stays_as_left_after_leaving_the_page_and_after_a_restart() {
    let mut app = app();
    open_tools_tab(&mut app, ToolsTab::Account);
    drop(app.update(Message::Navigate(Page::Tools)));
    drop(app.update(Message::Navigate(Page::Home)));
    drop(app.update(Message::Navigate(Page::Fixes)));
    drop(app.update(Message::Navigate(Page::Tools)));
    assert_eq!(app.ctx.prefs.tools_tab, ToolsTab::Account);
    let saved = serde_json::to_vec(&app.ctx.prefs).expect("prefs serialize");
    assert_eq!(app::settings::parse(&saved).tools_tab, ToolsTab::Account);
}

#[test]
fn the_history_page_draws_with_no_days_one_day_two_days_and_a_month() {
    use app::history::{Entry, Kind};
    let check = |day: u64, protected: usize| Entry {
        t: day * 86_400 + 43_200,
        kind: Kind::Check,
        protected,
        total: 5,
        n: 0,
    };
    let sets: Vec<Vec<Entry>> = vec![
        Vec::new(),
        vec![check(20_000, 5), check(20_000, 5)],
        vec![check(20_000, 5), check(20_400, 2)],
        (0..45)
            .map(|d| check(20_000 + d, 5 - (d % 5) as usize))
            .collect(),
    ];
    let renderer = iced::futures::executor::block_on(<iced::Renderer as Headless>::new(
        theme::REGULAR,
        14.0.into(),
        Some("tiny-skia"),
    ))
    .expect("tiny-skia renderer");
    let mut app = app();
    app.page = Page::History;
    for entries in sets {
        drop(app.update(Message::History(history::Msg::Loaded(entries, 0))));
        for lang in [Lang::En, Lang::De] {
            app.ctx.lang = lang;
            lays_out(&mut app, &renderer);
        }
    }
}

#[test]
fn a_tab_shows_a_dot_while_its_work_is_running() {
    let mut app = app();
    let label = |app: &App, tab| tools::tab_label(&app.tools, &app.ctx, tab);
    for tab in TOOLS_TABS {
        assert!(!app.tools.tab_busy(tab), "{tab:?} is quiet at the start");
        assert!(!label(&app, tab).contains('\u{2022}'));
    }

    tools_msg(&mut app, tools::Msg::LookForUpdates);
    assert!(app.tools.tab_busy(ToolsTab::Updates));
    assert!(label(&app, ToolsTab::Updates).ends_with(" \u{2022}"));
    assert!(!app.tools.tab_busy(ToolsTab::Viruses));
    assert!(!label(&app, ToolsTab::Viruses).contains('\u{2022}'));

    tools_msg(&mut app, tools::Msg::Found(Err(("raw".into(), "network"))));
    assert!(!app.tools.tab_busy(ToolsTab::Updates));
    assert!(!label(&app, ToolsTab::Updates).contains('\u{2022}'));

    tools_msg(&mut app, tools::Msg::Ask(tools::Sheet::Scan));
    tools_msg(&mut app, tools::Msg::Confirm);
    assert!(app.tools.tab_busy(ToolsTab::Viruses));
    tools_msg(&mut app, tools::Msg::ScanDone(Ok(())));
    assert!(!app.tools.tab_busy(ToolsTab::Viruses));

    tools_msg(
        &mut app,
        tools::Msg::PickTips(app::maintenance::TipProfile::Everyday),
    );
    assert!(app.tools.tab_busy(ToolsTab::Tips));
    assert!(label(&app, ToolsTab::Tips).ends_with(" \u{2022}"));
    app.page = Page::Tools;
    drop(app.view());
}

fn ads(app: &mut App, msg: debloat::ads::Msg) {
    drop(app.update(Message::Debloat(debloat::Msg::Ads(msg))));
}

fn on_ads_tab() -> App {
    let mut app = app();
    app.page = Page::Debloat;
    app.ctx.helper = Helper::Ready;
    drop(app.update(Message::Debloat(debloat::Msg::SetTab(debloat::Tab::Ads))));
    app
}

fn answer_all(app: &mut App, reply: crate::broker::Reply) {
    for setting in Setting::ADS_AND_TIPS {
        ads(app, debloat::ads::Msg::Reported(setting, Ok(reply)));
    }
}

#[test]
fn the_ads_and_tips_tab_shows_five_switches_and_none_is_on_until_asked() {
    use crate::broker::Reply;
    let mut app = on_ads_tab();
    for setting in Setting::ADS_AND_TIPS {
        assert_eq!(debloat::ads_shown_as(&app.debloat, setting), "idle");
    }
    drop(app.view());
    answer_all(&mut app, Reply::NeedsAttention);
    for setting in Setting::ADS_AND_TIPS {
        assert_eq!(debloat::ads_shown_as(&app.debloat, setting), "off");
    }
    drop(app.view());
    assert!(
        !debloat::shows_search(&app.debloat),
        "the app search belongs to the Apps tab"
    );
    assert!(
        debloat::footer(&app.debloat, &app.ctx).is_none(),
        "no Remove bar on this tab"
    );
}

#[test]
fn a_switch_only_changes_when_the_person_flips_it() {
    use crate::broker::Reply;
    let mut app = on_ads_tab();
    answer_all(&mut app, Reply::NeedsAttention);
    let lock = Setting::LockScreenTips;
    ads(&mut app, debloat::ads::Msg::Toggle(lock, false));
    assert_eq!(
        debloat::ads_shown_as(&app.debloat, lock),
        "off",
        "off stays off"
    );
    ads(&mut app, debloat::ads::Msg::Toggle(lock, true));
    assert_eq!(debloat::ads_shown_as(&app.debloat, lock), "working");
    for other in Setting::ADS_AND_TIPS.into_iter().filter(|s| *s != lock) {
        assert_eq!(debloat::ads_shown_as(&app.debloat, other), "off");
    }
    drop(app.view());
    ads(&mut app, debloat::ads::Msg::Changed(lock, Ok(Reply::Done)));
    ads(
        &mut app,
        debloat::ads::Msg::Reported(lock, Ok(Reply::SafeByUs)),
    );
    assert_eq!(
        debloat::ads_shown_as(&app.debloat, lock),
        "on, can be switched back"
    );
    ads(&mut app, debloat::ads::Msg::Toggle(lock, false));
    assert_eq!(
        debloat::ads_shown_as(&app.debloat, lock),
        "working",
        "undo starts"
    );
    ads(&mut app, debloat::ads::Msg::Changed(lock, Ok(Reply::Done)));
    ads(
        &mut app,
        debloat::ads::Msg::Reported(lock, Ok(Reply::NeedsAttention)),
    );
    assert_eq!(debloat::ads_shown_as(&app.debloat, lock), "off");
}

#[test]
fn a_switch_that_was_already_on_without_secblitz_cannot_be_flipped() {
    use crate::broker::Reply;
    let mut app = on_ads_tab();
    let game = Setting::GameBarPopups;
    ads(&mut app, debloat::ads::Msg::Reported(game, Ok(Reply::Safe)));
    assert_eq!(debloat::ads_shown_as(&app.debloat, game), "on");
    ads(&mut app, debloat::ads::Msg::Toggle(game, false));
    ads(&mut app, debloat::ads::Msg::Toggle(game, true));
    assert_eq!(debloat::ads_shown_as(&app.debloat, game), "on");
    drop(app.view());
}

#[test]
fn an_unreadable_or_unavailable_answer_is_shown_calmly_and_cannot_be_flipped() {
    use crate::broker::Reply;
    let mut app = on_ads_tab();
    let web = Setting::SearchWebResults;
    ads(
        &mut app,
        debloat::ads::Msg::Reported(web, Err("unavailable".into())),
    );
    assert_eq!(debloat::ads_shown_as(&app.debloat, web), "unknown");
    ads(&mut app, debloat::ads::Msg::Toggle(web, true));
    assert_eq!(debloat::ads_shown_as(&app.debloat, web), "unknown");
    ads(
        &mut app,
        debloat::ads::Msg::Reported(web, Ok(Reply::NeedsAttention)),
    );
    ads(&mut app, debloat::ads::Msg::Toggle(web, true));
    ads(
        &mut app,
        debloat::ads::Msg::Changed(web, Ok(Reply::Unavailable)),
    );
    ads(
        &mut app,
        debloat::ads::Msg::Reported(web, Ok(Reply::NeedsAttention)),
    );
    assert_eq!(
        debloat::ads_shown_as(&app.debloat, web),
        "off",
        "a refused change leaves it off"
    );
    drop(app.view());
}

#[test]
fn without_the_helper_the_tab_explains_instead_of_offering_switches() {
    let mut app = on_ads_tab();
    app.ctx.helper = Helper::Reopen;
    drop(app.view());
    for setting in Setting::ADS_AND_TIPS {
        assert_eq!(debloat::ads_shown_as(&app.debloat, setting), "idle");
    }
}

#[test]
fn the_apps_tab_keeps_its_search_after_a_visit_to_ads_and_tips() {
    use crate::broker::Reply;
    let mut app = on_ads_tab();
    drop(app.update(Message::Debloat(debloat::Msg::SetTab(debloat::Tab::Apps))));
    type_into_clean_up(&mut app, "xbox");
    let found = debloat::visible_apps(&app.debloat, &app.ctx);
    assert!(!found.is_empty());
    drop(app.update(Message::Debloat(debloat::Msg::SetTab(debloat::Tab::Ads))));
    answer_all(&mut app, Reply::NeedsAttention);
    drop(app.view());
    drop(app.update(Message::Debloat(debloat::Msg::SetTab(debloat::Tab::Apps))));
    assert!(debloat::shows_search(&app.debloat));
    assert_eq!(debloat::visible_apps(&app.debloat, &app.ctx), found);
    assert!(
        debloat::selected_apps(&app.debloat).is_empty(),
        "nothing is ticked by a visit"
    );
}

#[test]
fn the_ads_and_tips_tab_lays_out_in_every_language_with_the_info_dialog_open() {
    use crate::broker::Reply;
    let renderer = iced::futures::executor::block_on(<iced::Renderer as Headless>::new(
        theme::REGULAR,
        14.0.into(),
        Some("tiny-skia"),
    ))
    .expect("tiny-skia renderer");
    let mut app = on_ads_tab();
    app.enter_t = 1.0;
    for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
        app.ctx.lang = lang;
        app.ctx.info =
            widgets::info::for_check(&app.ctx, "Title".into(), "defender.pua", false).map(Box::new);
        for reply in [
            Reply::NeedsAttention,
            Reply::SafeByUs,
            Reply::Safe,
            Reply::Unknown,
        ] {
            answer_all(&mut app, reply);
            let mut element = app.view();
            let mut tree = Tree::new(&element);
            let node = element.as_widget_mut().layout(
                &mut tree,
                &renderer,
                &Limits::new(iced::Size::ZERO, SIZE),
            );
            assert!(
                node.size().width > 0.0 && node.size().height > 0.0,
                "{lang:?} {reply:?}"
            );
        }
    }
}

#[test]
fn every_new_app_in_the_catalog_has_a_row_on_the_apps_tab() {
    let mut app = app();
    app.page = Page::Debloat;
    let shown = debloat::visible_apps(&app.debloat, &app.ctx);
    let catalog = secblitz::debloat::catalog();
    for family in [
        "Microsoft.WidgetsPlatformRuntime",
        "microsoft.windowscommunicationsapps",
        "MicrosoftCorporationII.MicrosoftFamily",
    ] {
        let index = catalog.iter().position(|a| a.family == family).unwrap() as u16;
        assert!(shown.contains(&index), "{family}");
    }
    assert!(debloat::selected_apps(&app.debloat).is_empty());
    drop(app.view());
    type_into_clean_up(&mut app, "copilot");
    assert!(!debloat::visible_apps(&app.debloat, &app.ctx).is_empty());
}

#[test]
#[ignore]
fn bench_pages() {
    let mut renderer = iced::futures::executor::block_on(<iced::Renderer as Headless>::new(
        theme::REGULAR,
        14.0.into(),
        Some("tiny-skia"),
    ))
    .expect("tiny-skia renderer");
    let mut app = app();
    let theme = app.ctx.palette.theme();
    let style = renderer::Style {
        text_color: theme.palette().text,
    };
    renderer.reset(Rectangle::with_size(SIZE));
    let empty = avg(&mut || {
        let _ = renderer.screenshot(iced::Size::new(1100, 720), 1.0, iced::Color::WHITE);
    });
    println!("empty frame {empty:.2}");
    println!("page        view   layout  draw   raster (ms, average of {RUNS})");
    for page in Page::ALL {
        app.page = page;
        app.enter_t = 1.0;
        let view = avg(&mut || drop(app.view()));
        let layout_ms = avg(&mut || {
            let mut element = app.view();
            let mut tree = Tree::new(&element);
            let _ = element.as_widget_mut().layout(
                &mut tree,
                &renderer,
                &Limits::new(iced::Size::ZERO, SIZE),
            );
        });
        let mut element = app.view();
        let mut tree = Tree::new(&element);
        let node = element.as_widget_mut().layout(
            &mut tree,
            &renderer,
            &Limits::new(iced::Size::ZERO, SIZE),
        );
        let viewport = Rectangle::with_size(SIZE);
        let draw = avg(&mut || {
            renderer.reset(viewport);
            element.as_widget().draw(
                &tree,
                &mut renderer,
                &theme,
                &style,
                Layout::new(&node),
                mouse::Cursor::Unavailable,
                &viewport,
            );
        });
        let raster = avg(&mut || {
            let _ = renderer.screenshot(
                iced::Size::new(SIZE.width as u32, SIZE.height as u32),
                1.0,
                iced::Color::WHITE,
            );
        });
        println!(
            "{page:<10?} {view:6.2} {:6.2} {draw:6.2} {raster:6.2}",
            layout_ms - view
        );
    }
    println!("update handlers (ms, average of {RUNS})");
    for page in Page::ALL {
        let t = avg(&mut || {
            app.page = Page::Home;
            drop(app.update(Message::Navigate(page)));
        });
        println!("navigate to {page:<10?} {t:6.3}");
    }
    let checked = Arc::new(report());
    let t = avg(&mut || {
        drop(app.update(Message::Worker(worker::Event::Checked(Ok(checked.clone())))));
    });
    println!("check finished      {t:6.3}");
    let t = avg(&mut || {
        drop(app.update(Message::Toast("Saved.".into(), Tone::Good)));
    });
    println!("toast               {t:6.3}");
}

use crate::app::topics::{Line, Topic};

fn report_with(app: &mut App, open: &[&str], changed: &[&str]) {
    with_report(app, |r| {
        for o in &mut r.results {
            o.status = if open.contains(&o.id.as_str()) {
                CheckStatus::Attention
            } else {
                CheckStatus::Compliant
            };
            o.undoable = changed.contains(&o.id.as_str());
            o.switched_back = o.undoable;
        }
    });
}

fn all_protected_except(app: &mut App, open: &[&str]) {
    report_with(app, open, &[]);
}

fn line_of(app: &App, topic: Topic) -> Line {
    fixes::tile_lines(&app.fixes, &app.ctx)
        .into_iter()
        .find(|(t, _)| *t == topic)
        .map(|(_, line)| line)
        .expect("every topic has a tile")
}

#[test]
fn every_protection_row_is_in_exactly_one_topic() {
    let app = app();
    let rows = fixes::rows_by_topic(&app.fixes, &app.ctx);
    assert!(rows.len() > 50, "{}", rows.len());
    let mut keys: Vec<&String> = rows.iter().map(|(_, key)| key).collect();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), rows.len(), "a row must not be listed twice");
    let mut counted = 0;
    for topic in Topic::ALL {
        let here: Vec<&String> = rows
            .iter()
            .filter(|(t, _)| *t == topic)
            .map(|(_, key)| key)
            .collect();
        assert!(!here.is_empty(), "{topic:?} has nothing to show");
        counted += here.len();
        for key in here {
            if !key.starts_with("other:") {
                assert_eq!(Topic::of(key), topic, "{key}");
            }
        }
    }
    assert_eq!(counted, rows.len());
}

#[test]
fn each_tile_says_what_its_topic_needs() {
    let mut app = app();
    all_protected_except(
        &mut app,
        &[
            "smartscreen.browser_policy",
            "privacy.advertising_id",
            "defender.pua",
        ],
    );
    assert_eq!(line_of(&app, Topic::Browsers), Line::ToFix(1));
    assert_eq!(line_of(&app, Topic::Threats), Line::ToFix(1));
    assert_eq!(line_of(&app, Topic::Privacy), Line::Options(1));
    assert_eq!(line_of(&app, Topic::Ai), Line::AllSet);
    assert_eq!(line_of(&app, Topic::Network), Line::AllSet);
    assert_eq!(line_of(&app, Topic::SignIn), Line::AllSet);
}

#[test]
fn a_setting_secblitz_fixed_that_is_off_again_is_counted_and_chosen() {
    let mut app = app();
    report_with(
        &mut app,
        &[
            "net.llmnr",
            "privacy.advertising_id",
            "wsh.disabled",
            "defender.pua",
            "autorun.disabled",
        ],
        &[
            "net.llmnr",
            "privacy.advertising_id",
            "defender.pua",
            "autorun.disabled",
        ],
    );
    let mut back = fixes::banner_ids(&app.fixes, &app.ctx);
    back.sort();
    assert_eq!(
        back,
        [
            "autorun.disabled",
            "defender.pua",
            "net.llmnr",
            "privacy.advertising_id"
        ]
    );
    assert_eq!(line_of(&app, Topic::Network), Line::SwitchedBack(1));
    assert_eq!(line_of(&app, Topic::Privacy), Line::SwitchedBack(1));
    assert_eq!(line_of(&app, Topic::Windows), Line::ToFix(1));
    drop(app.update(Message::Fixes(fixes::Msg::Search(String::new()))));
    let chosen = fixes::selected_ids(&app.fixes);
    for id in ["defender.pua", "net.llmnr"] {
        assert!(
            chosen.contains(&id.to_owned()),
            "{id} is recommended, so it is chosen again"
        );
    }
    for id in ["autorun.disabled", "privacy.advertising_id"] {
        assert!(
            !chosen.contains(&id.to_owned()),
            "{id} is a choice, so it is not chosen for the person even when it was fixed before"
        );
    }
    drop(app.update(Message::Fixes(fixes::Msg::SelectNone)));
    drop(app.update(Message::Fixes(fixes::Msg::PutBack)));
    let mut chosen = fixes::selected_ids(&app.fixes);
    chosen.retain(|id| back.contains(id));
    assert_eq!(chosen, back, "putting them back chooses exactly those");
    assert!(
        !fixes::selected_ids(&app.fixes).contains(&"wsh.disabled".to_owned()),
        "other settings are not swept along"
    );
    drop(app.view());
}

#[test]
fn a_topic_counts_only_its_own_chosen_fixes() {
    let mut app = app();
    all_protected_except(&mut app, &["defender.pua", "net.llmnr"]);
    drop(app.update(Message::Fixes(fixes::Msg::SelectAll)));
    assert_eq!(
        fixes::chosen_in_topic(&app.fixes, &app.ctx, Topic::Threats),
        ["defender.pua"]
    );
    assert_eq!(
        fixes::chosen_in_topic(&app.fixes, &app.ctx, Topic::Network),
        ["net.llmnr"]
    );
}

#[test]
fn an_add_on_left_on_after_others_were_turned_off_is_not_switched_back() {
    let mut app = app();
    let id = "browser.extensions_off";
    let set = |app: &mut App, undoable: bool, switched_back: bool| {
        with_report(app, |r| {
            for o in &mut r.results {
                o.status = CheckStatus::Compliant;
            }
            let o = r.results.iter_mut().find(|o| o.id == id).expect("the spec");
            o.status = CheckStatus::Attention;
            o.items = vec![secblitz::model::ItemLabel {
                kind: "addon".into(),
                name: "Add-on".into(),
                key: format!("chromium:edge:{}", "b".repeat(32)),
                why: "sites".into(),
            }];
            o.undoable = undoable;
            o.switched_back = switched_back;
        });
    };
    set(&mut app, false, false);
    let untouched = line_of(&app, Topic::Browsers);
    set(&mut app, true, false);
    assert_eq!(line_of(&app, Topic::Browsers), untouched);
    set(&mut app, true, true);
    assert_eq!(line_of(&app, Topic::Browsers), Line::SwitchedBack(1));
}

#[test]
fn settings_nobody_switched_back_are_not_flagged() {
    let mut app = app();
    all_protected_except(&mut app, &["net.llmnr", "wsh.disabled"]);
    assert!(fixes::banner_ids(&app.fixes, &app.ctx).is_empty());
    assert_eq!(line_of(&app, Topic::Network), Line::ToFix(1));
    report_with(&mut app, &["net.llmnr"], &["defender.pua"]);
    assert!(
        fixes::banner_ids(&app.fixes, &app.ctx).is_empty(),
        "a protected setting is not switched back"
    );
}

#[test]
fn the_review_strip_chooses_every_recommended_fix_in_every_topic() {
    let mut app = app();
    all_protected_except(
        &mut app,
        &["defender.pua", "smartscreen.browser_policy", "net.llmnr"],
    );
    let report = app.ctx.report.clone().expect("a report");
    let recommended = app::flow::recommended(&report, &app.ctx.catalog.available);
    assert!(recommended.len() >= 2, "{recommended:?}");
    drop(app.update(Message::Fixes(fixes::Msg::SelectNone)));
    assert!(fixes::selected_ids(&app.fixes).is_empty());
    drop(app.update(Message::Fixes(fixes::Msg::ReviewRecommended)));
    let chosen = fixes::selected_ids(&app.fixes);
    for id in &recommended {
        assert!(chosen.contains(id), "{id}");
    }
}

#[test]
fn the_first_result_opens_the_first_topic_with_something_to_fix_and_later_ones_the_remembered_topic(
) {
    let mut app = app();
    app.page = Page::Fixes;
    app.ctx.prefs.protection_topic = Some(Topic::Privacy);
    all_protected_except(&mut app, &["smartscreen.browser_policy", "ai.paint"]);
    drop(app.view());
    assert_eq!(fixes::topic_on_show(&app.fixes), Some(Topic::Browsers));

    let mut app = self::app();
    app.page = Page::Fixes;
    app.ctx.prefs.protection_topic = Some(Topic::Privacy);
    all_protected_except(&mut app, &["ai.paint"]);
    drop(app.view());
    assert_eq!(
        fixes::topic_on_show(&app.fixes),
        Some(Topic::Privacy),
        "nothing to fix: the remembered topic"
    );

    let mut app = self::app();
    app.page = Page::Fixes;
    all_protected_except(&mut app, &[]);
    drop(app.view());
    assert_eq!(fixes::topic_on_show(&app.fixes), Some(Topic::Threats));

    drop(app.update(Message::Fixes(fixes::Msg::Topic(Topic::Windows))));
    assert_eq!(fixes::topic_on_show(&app.fixes), Some(Topic::Windows));
    assert_eq!(app.ctx.prefs.protection_topic, Some(Topic::Windows));
    all_protected_except(&mut app, &["smartscreen.browser_policy"]);
    drop(app.view());
    assert_eq!(
        fixes::topic_on_show(&app.fixes),
        Some(Topic::Windows),
        "a new check does not move the person"
    );
}

#[test]
fn searching_shows_matches_from_every_topic() {
    let mut app = app();
    type_into_protection(&mut app, "fire");
    let shown = shown_on_protection(&app);
    let rows = fixes::rows_by_topic(&app.fixes, &app.ctx);
    let topics: std::collections::HashSet<Topic> = rows
        .iter()
        .filter(|(_, key)| shown.contains(key))
        .map(|(t, _)| *t)
        .collect();
    assert!(topics.len() >= 2, "{topics:?}");
    drop(app.view());
}

#[test]
fn every_topic_lays_out_in_two_and_four_columns() {
    let renderer = iced::futures::executor::block_on(<iced::Renderer as Headless>::new(
        theme::REGULAR,
        14.0.into(),
        Some("tiny-skia"),
    ))
    .expect("tiny-skia renderer");
    let mut app = app();
    app.page = Page::Fixes;
    app.enter_t = 1.0;
    for topic in Topic::ALL {
        drop(app.update(Message::Fixes(fixes::Msg::Topic(topic))));
        for width in [1100.0, 880.0] {
            let size = iced::Size::new(width, 720.0);
            let mut element = app.view();
            let mut tree = Tree::new(&element);
            let node = element.as_widget_mut().layout(
                &mut tree,
                &renderer,
                &Limits::new(iced::Size::ZERO, size),
            );
            assert!(node.size().height > 0.0, "{topic:?} {width}");
        }
    }
}

#[test]
fn a_setting_secblitz_cannot_fix_is_something_to_look_at_not_to_fix() {
    let mut app = app();
    with_report(&mut app, |r| {
        for o in &mut r.results {
            o.status = if o.id == "autorun.disabled" {
                CheckStatus::Review
            } else {
                CheckStatus::Compliant
            };
            o.undoable = false;
        }
    });
    assert_eq!(line_of(&app, Topic::Windows), Line::ToLookAt(1));
    assert!(!line_of(&app, Topic::Windows).needs_action());
    assert_eq!(
        fixes::first_topic_for_test(&app.fixes, &app.ctx),
        None,
        "nothing to fix means no topic is opened for the person"
    );
}

fn access_entry(
    name: &str,
    in_use: bool,
    last_used: Option<u64>,
    allowed: bool,
) -> access_model::Entry {
    access_model::Entry {
        key: format!("Vendor.{}_8wekyb3d8bbwe", name.replace(' ', "")),
        name: name.into(),
        allowed,
        in_use,
        last_used,
    }
}

use crate::app::app_access as access_model;

fn access_listing(capability: access_model::Capability) -> access_model::Listing {
    let now = app::history::now();
    access_model::Listing {
        capability,
        master: true,
        apps: vec![
            access_entry("Windows Camera", true, Some(now), true),
            access_entry("Skype", false, Some(now - 7200), false),
            access_entry(
                "A very long app name that goes on and on and on forever",
                false,
                None,
                true,
            ),
        ],
        desktop_allowed: true,
        controlled: false,
        desktop: vec![
            access_entry("Zoom", false, Some(now - 90), true),
            access_entry("Firefox", false, Some(now - 90_000), true),
            access_entry("OBS Studio", false, None, true),
            access_entry("Discord", false, None, true),
            access_entry("Teams", false, None, true),
        ],
    }
}

fn access(app: &mut App, msg: app_access::Msg) {
    drop(app.update(Message::AppAccess(msg)));
}

#[test]
fn the_app_access_panel_loads_lazily_and_shows_what_it_read() {
    use crate::broker::Reply;
    use access_model::Capability;
    let mut app = app();
    app.ctx.helper = Helper::Ready;
    assert_eq!(
        app_access::shown_as(&app.app_access, Capability::Camera),
        "idle"
    );
    drop(app_access::view(&app.app_access, &app.ctx));
    access(
        &mut app,
        app_access::Msg::Listed(Capability::Camera, Ok(Reply::Failed)),
    );
    assert_eq!(
        app_access::shown_as(&app.app_access, Capability::Camera),
        "failed"
    );
    drop(app_access::view(&app.app_access, &app.ctx));
    access(
        &mut app,
        app_access::Msg::Read(Capability::Camera, Ok(access_listing(Capability::Camera))),
    );
    assert_eq!(
        app_access::shown_as(&app.app_access, Capability::Camera),
        "listed"
    );
    access(&mut app, app_access::Msg::Select(Capability::Location));
    assert_eq!(
        app_access::shown_as(&app.app_access, Capability::Location),
        "loading"
    );
    access(
        &mut app,
        app_access::Msg::Read(Capability::Location, Err("x".into())),
    );
    assert_eq!(
        app_access::shown_as(&app.app_access, Capability::Location),
        "failed"
    );
    drop(app_access::view(&app.app_access, &app.ctx));
}

#[test]
fn only_one_app_access_switch_changes_at_a_time() {
    use crate::broker::Reply;
    use access_model::{Capability, Target};
    let mut app = app();
    app.ctx.helper = Helper::Ready;
    access(&mut app, app_access::Msg::Toggle(Target::Master, 0, false));
    assert!(
        !app_access::is_changing(&app.app_access),
        "nothing to switch before the list is read"
    );
    access(
        &mut app,
        app_access::Msg::Read(Capability::Camera, Ok(access_listing(Capability::Camera))),
    );
    access(&mut app, app_access::Msg::Toggle(Target::App(1), 0, true));
    assert!(app_access::is_changing(&app.app_access));
    drop(app_access::view(&app.app_access, &app.ctx));
    access(&mut app, app_access::Msg::Toggle(Target::Master, 0, false));
    access(
        &mut app,
        app_access::Msg::Changed(Capability::Camera, Ok(Reply::Done)),
    );
    assert!(!app_access::is_changing(&app.app_access));
    assert_eq!(
        app_access::shown_as(&app.app_access, Capability::Camera),
        "reloading"
    );
    access(&mut app, app_access::Msg::Toggle(Target::Master, 0, false));
    access(
        &mut app,
        app_access::Msg::Changed(Capability::Camera, Err("unavailable".into())),
    );
    assert!(!app_access::is_changing(&app.app_access));
}

#[test]
fn app_access_switches_wait_while_the_list_is_read_again() {
    use crate::broker::Reply;
    use access_model::{Capability, Target};
    let mut app = app();
    app.ctx.helper = Helper::Ready;
    access(
        &mut app,
        app_access::Msg::Read(Capability::Camera, Ok(access_listing(Capability::Camera))),
    );
    access(&mut app, app_access::Msg::Toggle(Target::Master, 0, false));
    access(
        &mut app,
        app_access::Msg::Changed(Capability::Camera, Ok(Reply::Done)),
    );
    assert_eq!(
        app_access::shown_as(&app.app_access, Capability::Camera),
        "reloading"
    );
    access(&mut app, app_access::Msg::Toggle(Target::App(1), 0, true));
    assert!(
        !app_access::is_changing(&app.app_access),
        "a switch pressed while the list is being read again does nothing"
    );
    drop(app_access::view(&app.app_access, &app.ctx));
    access(
        &mut app,
        app_access::Msg::Read(Capability::Camera, Ok(access_listing(Capability::Camera))),
    );
    access(&mut app, app_access::Msg::Toggle(Target::App(1), 0, true));
    assert!(app_access::is_changing(&app.app_access));
}

#[test]
fn the_app_access_list_is_read_again_and_never_left_stale() {
    use access_model::Capability;
    let mut app = app();
    app.ctx.helper = Helper::Ready;
    access(
        &mut app,
        app_access::Msg::Read(Capability::Camera, Ok(access_listing(Capability::Camera))),
    );
    drop(app_access::on_enter(&mut app.app_access, &mut app.ctx));
    assert_eq!(
        app_access::shown_as(&app.app_access, Capability::Camera),
        "reloading",
        "opening the panel again reads the list again"
    );
    access(
        &mut app,
        app_access::Msg::Read(Capability::Camera, Ok(access_listing(Capability::Camera))),
    );
    access(&mut app, app_access::Msg::Select(Capability::Camera));
    assert_eq!(
        app_access::shown_as(&app.app_access, Capability::Camera),
        "reloading",
        "picking a tab reads its list again"
    );
    access(
        &mut app,
        app_access::Msg::Read(Capability::Camera, Err("x".into())),
    );
    assert_eq!(
        app_access::shown_as(&app.app_access, Capability::Camera),
        "failed",
        "a failed read hides the old switch positions"
    );
    access(
        &mut app,
        app_access::Msg::Read(Capability::Camera, Ok(access_listing(Capability::Camera))),
    );
    access(
        &mut app,
        app_access::Msg::Listed(Capability::Camera, Ok(crate::broker::Reply::Failed)),
    );
    assert_eq!(
        app_access::shown_as(&app.app_access, Capability::Camera),
        "failed"
    );
}

#[test]
fn app_access_switches_do_nothing_when_windows_or_the_organization_decides() {
    use access_model::{Capability, Target};
    let mut app = app();
    app.ctx.helper = Helper::Ready;
    let mut listing = access_listing(Capability::Camera);
    listing.controlled = true;
    access(
        &mut app,
        app_access::Msg::Read(Capability::Camera, Ok(listing)),
    );
    access(&mut app, app_access::Msg::Toggle(Target::Master, 0, false));
    assert!(!app_access::is_changing(&app.app_access));
    drop(app_access::view(&app.app_access, &app.ctx));
}

#[test]
fn the_app_access_panel_lays_out_in_every_language() {
    use access_model::Capability;
    let renderer = iced::futures::executor::block_on(<iced::Renderer as Headless>::new(
        theme::REGULAR,
        14.0.into(),
        Some("tiny-skia"),
    ))
    .expect("tiny-skia renderer");
    let mut app = app();
    app.ctx.helper = Helper::Ready;
    for lang in [Lang::En, Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
        app.ctx.lang = lang;
        for capability in Capability::ALL {
            let mut listing = access_listing(capability);
            for master in [true, false] {
                listing.master = master;
                access(&mut app, app_access::Msg::Select(capability));
                access(
                    &mut app,
                    app_access::Msg::Read(capability, Ok(listing.clone())),
                );
                let mut element = app_access::view(&app.app_access, &app.ctx);
                let mut tree = Tree::new(&element);
                let node = element.as_widget_mut().layout(
                    &mut tree,
                    &renderer,
                    &Limits::new(iced::Size::ZERO, iced::Size::new(640.0, 900.0)),
                );
                assert!(node.size().width > 0.0 && node.size().height > 0.0);
            }
            access(
                &mut app,
                app_access::Msg::Read(capability, Ok(access_model::Listing::empty(capability))),
            );
            drop(app_access::view(&app.app_access, &app.ctx));
        }
    }
    app.ctx.helper = Helper::Reopen;
    drop(app_access::view(&app.app_access, &app.ctx));
}

#[test]
fn browser_add_ons_start_unpicked_and_only_the_picked_ones_are_turned_off() {
    let _motion = widgets::anim::forced::set(false);
    let mut app = app();
    let id = "browser.extensions_off";
    let key = |n: char| format!("chromium:chrome:{}", n.to_string().repeat(32));
    with_report(&mut app, |r| {
        let o = r.results.iter_mut().find(|o| o.id == id).expect("the spec");
        o.status = "attention".into();
        o.items = ['a', 'b']
            .iter()
            .map(|c| secblitz::model::ItemLabel {
                kind: "addon".into(),
                name: format!("Add-on {c}"),
                key: key(*c),
                why: "sites,programs".into(),
            })
            .collect();
    });
    drop(app.update(Message::ReviewFixes(vec![id.into()])));
    assert_eq!(fixflow::stage_name(&app.fix), "review");
    assert!(fixflow::addons_waiting(&app.fix), "nothing starts picked");
    assert_eq!(
        fixflow::addon_apply_job(&app.fix),
        worker::Job::Apply(Vec::new()),
        "with nothing picked the fix is left out"
    );
    drop(app.view());

    drop(app.update(Message::Fix(fixflow::Msg::PickAddon("not.listed".into()))));
    assert!(
        fixflow::addons_waiting(&app.fix),
        "unknown keys are ignored"
    );
    drop(app.update(Message::Fix(fixflow::Msg::PickAddon(key('b')))));
    assert!(!fixflow::addons_waiting(&app.fix));
    assert_eq!(
        fixflow::addon_apply_job(&app.fix),
        worker::Job::ApplyPicked {
            ids: vec![id.into()],
            picked: [(id.to_owned(), vec![key('b')])].into(),
        }
    );
    drop(app.view());
    drop(app.update(Message::Fix(fixflow::Msg::PickAddon(key('b')))));
    assert!(fixflow::addons_waiting(&app.fix), "a second tap unpicks");

    drop(app.update(Message::Fix(fixflow::Msg::Cancel)));
    drop(app.update(Message::ReviewFixes(vec![id.into()])));
    assert!(fixflow::addons_waiting(&app.fix), "picks do not carry over");
}

#[test]
fn the_info_dialog_opens_closes_and_gives_way_to_escape_first() {
    let mut app = app();
    let sheet = widgets::info::InfoSheet::new("Title").text("What it is", "A plain sentence.");
    drop(app.update(Message::Info(Some(Box::new(sheet.clone())))));
    let shown = app.ctx.info.as_deref().expect("the dialog is open");
    assert_eq!((&shown.title, &shown.blocks), (&sheet.title, &sheet.blocks));
    drop(app.view());
    drop(app.update(Message::Info(None)));
    assert!(app.ctx.info.is_none());

    app.whats_new = true;
    drop(app.update(Message::Info(Some(Box::new(sheet.clone())))));
    drop(app.update(Message::Escape));
    assert!(app.ctx.info.is_none(), "Escape closes the dialog first");
    assert!(app.whats_new, "the note underneath stays open");
    drop(app.update(Message::Escape));
    assert!(!app.whats_new);

    for leave in [Message::Navigate(Page::Settings), Message::CheckNow] {
        drop(app.update(Message::Info(Some(Box::new(sheet.clone())))));
        drop(app.update(leave));
        assert!(app.ctx.info.is_none());
    }
}

fn fresh_install() -> App {
    let mut app = app();
    app.ctx.report = None;
    app.ctx.checked_at = None;
    app.ctx.checking = None;
    app.may_check = false;
    app.welcome = Some(pages::welcome::State::default());
    app
}

#[test]
fn leaving_the_welcome_by_any_route_remembers_it_and_checks_only_on_a_yes() {
    for (leave, checks) in [
        (Message::Welcome(pages::welcome::Msg::Skip), false),
        (Message::Escape, false),
        (Message::Welcome(pages::welcome::Msg::Check), true),
    ] {
        let mut app = fresh_install();
        drop(app.update(leave));
        assert!(app.welcome.is_none());
        assert!(app.ctx.prefs.welcome_seen);
        assert_eq!(app.ctx.checking.is_some(), checks);
        assert_eq!(app.may_check, checks);
    }
}

#[test]
fn a_check_after_a_change_waits_for_the_persons_agreement() {
    let mut app = fresh_install();
    drop(app.update(Message::Welcome(pages::welcome::Msg::Skip)));
    drop(app.update(Message::CheckIfAgreed));
    assert!(app.ctx.checking.is_none());
    app.may_check = true;
    drop(app.update(Message::CheckIfAgreed));
    assert!(app.ctx.checking.is_some());
}

#[test]
fn nothing_checks_on_its_own_before_the_person_agrees() {
    let mut app = fresh_install();
    drop(app.update(Message::Welcome(pages::welcome::Msg::Skip)));
    assert!(app.ctx.checking.is_none() && app.ctx.report.is_none());
    drop(app.update(Message::WindowFocus(false)));
    drop(app.update(Message::PageOpened(crate::guide::Page::Firewall, true)));
    drop(app.update(Message::WindowFocus(true)));
    assert!(app.ctx.checking.is_none());
    let catalog = app.ctx.catalog.clone();
    drop(app.update(Message::Worker(worker::Event::Recovered(Ok(catalog)))));
    assert!(app.ctx.checking.is_none());
    assert!(!home::fills_window(&app.ctx) && !fixes::fills_window(&app.ctx));
}

#[test]
fn pages_without_a_check_ask_for_one_and_the_welcome_covers_the_window() {
    let _motion = widgets::anim::forced::set(false);
    let mut app = fresh_install();
    drop(app.view());
    for step in 0..3 {
        drop(app.view());
        drop(app.update(Message::Welcome(pages::welcome::Msg::Next)));
        assert!(app.welcome.is_some(), "step {step}");
    }
    drop(app.update(Message::Welcome(pages::welcome::Msg::Skip)));
    for page in Page::ALL {
        drop(app.update(Message::Navigate(page)));
        drop(app.view());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn on_linux_a_way_to_tools_lands_on_home() {
    let _motion = widgets::anim::forced::set(false);
    let mut app = app();
    drop(app.update(Message::Navigate(Page::Settings)));
    drop(app.update(Message::Navigate(Page::Tools)));
    assert_eq!(app.page, Page::Home);
    drop(app.view());
    drop(app.update(Message::Navigate(Page::Web)));
    assert_eq!(app.page, Page::Web);
    drop(app.view());
    drop(app.update(Message::Navigate(Page::Fixes)));
    assert_eq!(app.page, Page::Fixes);
}
