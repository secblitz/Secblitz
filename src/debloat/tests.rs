use super::*;
use std::cell::RefCell;
use std::collections::HashSet;

const KNOWN_PROTECTED: &[&str] = &[
    "Microsoft.WindowsStore",
    "Microsoft.DesktopAppInstaller",
    "Microsoft.SecHealthUI",
    "Microsoft.VCLibs.140.00",
    "Microsoft.UI.Xaml.2.8",
    "Microsoft.NET.Native.Runtime.2.2",
    "Microsoft.WindowsTerminal",
    "Microsoft.WindowsNotepad",
    "Microsoft.WindowsCalculator",
    "Microsoft.ScreenSketch",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.MicrosoftEdge.Stable",
    "Microsoft.OneDriveSync",
    "Microsoft.HEIFImageExtension",
    "Microsoft.VP9VideoExtensions",
    "Microsoft.WebMediaExtensions",
    "Microsoft.WebpImageExtension",
    "Microsoft.AV1VideoExtension",
    "Microsoft.HEVCVideoExtension",
    "Microsoft.RawImageExtension",
    "Microsoft.Windows.ShellExperienceHost",
    "Microsoft.StorePurchaseApp",
    "Microsoft.Services.Store.Engagement",
];

#[test]
fn indices_are_unique_and_names_are_unique() {
    let mut families = HashSet::new();
    let mut names = HashSet::new();
    for app in catalog() {
        assert!(
            families.insert(app.family.to_ascii_lowercase()),
            "{}",
            app.family
        );
        assert!(names.insert(app.name), "{}", app.name);
    }
    assert!(catalog().len() < u16::MAX as usize);
}

#[test]
fn protected_packages_are_protected_and_never_in_the_catalog() {
    for name in KNOWN_PROTECTED {
        assert!(is_protected(name), "{name} must be protected");
        assert_eq!(catalog::owner(name), None, "{name} must not be removable");
        assert!(
            !catalog().iter().any(|a| pattern_matches(a.family, name)),
            "{name} matched by catalog"
        );
    }
    for app in catalog::CATALOG {
        let stem = app.family.trim_end_matches('*');
        assert!(
            !is_protected(stem),
            "catalog entry {} is protected",
            app.family
        );
        assert!(catalog::is_valid_package_name(stem), "{}", app.family);
        if let Some(rest) = app.family.strip_suffix('*') {
            assert!(
                !rest.is_empty() && rest.ends_with(['.', '-']),
                "{}",
                app.family
            );
        }
    }
}

#[test]
fn catalog_has_recommended_and_gaming_groups() {
    assert!(catalog().iter().any(|a| a.group == Group::Recommended));
    assert!(catalog().iter().any(|a| a.group == Group::Gaming));
}

#[test]
fn store_ids_look_like_store_ids() {
    for app in catalog() {
        if let Some(id) = app.store_id {
            assert!(
                id.len() == 12 || (id.len() == 14 && id.starts_with("XP")),
                "{}",
                app.name
            );
            assert!(id
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()));
        }
    }
    let ids: Vec<_> = catalog().iter().filter_map(|a| a.store_id).collect();
    assert_eq!(ids.len(), ids.iter().collect::<HashSet<_>>().len());
}

#[test]
fn prefix_patterns_match_only_their_publisher() {
    assert!(pattern_matches("king.com.*", "king.com.CandyCrushSaga"));
    assert!(pattern_matches("king.com.*", "King.com.CandyCrushSodaSaga"));
    assert!(!pattern_matches("king.com.*", "kingdom.thing"));
    assert!(pattern_matches("Microsoft.BingNews", "microsoft.bingnews"));
    assert!(!pattern_matches(
        "Microsoft.BingNews",
        "Microsoft.BingNewsPlus"
    ));
}

#[test]
fn invalid_names_never_match() {
    for bad in [
        "",
        "king.com.x; calc",
        "Microsoft.BingNews\"",
        "a b",
        "Microsoft.BingNews\n",
    ] {
        assert_eq!(catalog::owner(bad), None, "{bad:?}");
    }
}

#[test]
fn inventory_json_is_filtered_strictly_to_the_catalog() {
    let json = r#"[
      {"name":"Microsoft.BingNews","version":"1.0","installed":true,"provisioned":true,"nonRemovable":false,"framework":false},
      {"name":"Microsoft.WindowsStore","version":"2","installed":true,"provisioned":false,"nonRemovable":false,"framework":false},
      {"name":"Microsoft.Xbox.TCUI","version":"1","installed":true,"provisioned":false,"nonRemovable":true,"framework":false},
      {"name":"king.com.CandyCrushSaga","version":"3","installed":true,"provisioned":false,"nonRemovable":false,"framework":false},
      {"name":"Contoso.Unknown","version":"1","installed":true,"provisioned":false,"nonRemovable":false,"framework":false},
      {"name":"Microsoft.UI.Xaml.2.8","version":"8","installed":true,"provisioned":false,"nonRemovable":false,"framework":true}
    ]"#;
    let found = parse_inventory(json).unwrap();
    let names: Vec<_> = found.iter().map(|p| p.package.as_str()).collect();
    assert_eq!(names, ["Microsoft.BingNews", "king.com.CandyCrushSaga"]);
    // A lone object (PowerShell unwraps single items) is accepted too.
    let one =
        r#"{"name":"Microsoft.BingNews","version":"1.0","nonRemovable":false,"framework":false}"#;
    assert_eq!(parse_inventory(one).unwrap().len(), 1);
    assert_eq!(parse_inventory("[]").unwrap().len(), 0);
    assert!(parse_inventory("garbage").is_err());
}

#[test]
fn outcome_parsing() {
    assert_eq!(
        parse_outcome(r#"{"removed":true,"protected":false,"error":null}"#),
        PackageOutcome::Removed
    );
    assert_eq!(
        parse_outcome(r#"{"removed":false,"protected":true}"#),
        PackageOutcome::Protected
    );
    assert!(
        matches!(parse_outcome(r#"{"removed":false,"protected":false,"error":"x"}"#), PackageOutcome::Failed(e) if e == "x")
    );
    assert!(matches!(parse_outcome("nope"), PackageOutcome::Failed(_)));
}

fn idx(family: &str) -> u16 {
    catalog().iter().position(|a| a.family == family).unwrap() as u16
}

#[test]
fn request_for_unknown_index_is_refused() {
    let out = remove_with(
        &[u16::MAX],
        &[],
        &|_| Ok(()),
        &|_| PackageOutcome::Removed,
        &|_| {},
    );
    assert!(out.is_err());
}

#[test]
fn removal_never_runs_for_protected_or_foreign_packages() {
    let news = idx("Microsoft.BingNews");
    let installed = vec![
        Installed {
            index: news,
            package: "Microsoft.BingNews".into(),
            version: "1".into(),
        },
        Installed {
            index: news,
            package: "Microsoft.WindowsStore".into(),
            version: "1".into(),
        },
        Installed {
            index: news,
            package: "Evil; calc".into(),
            version: "1".into(),
        },
    ];
    let seen = RefCell::new(Vec::new());
    let batch = remove_with(
        &[news],
        &installed,
        &|_| Ok(()),
        &|p| {
            seen.borrow_mut().push(p.to_string());
            PackageOutcome::Removed
        },
        &|_| {},
    )
    .unwrap();
    assert_eq!(*seen.borrow(), ["Microsoft.BingNews"]);
    assert_eq!(batch.removed.len(), 1);
    assert_eq!(batch.removed_apps(), 1);
}

#[test]
fn removal_reports_removed_protected_and_failed() {
    let news = idx("Microsoft.BingNews");
    let weather = idx("Microsoft.BingWeather");
    let maps = idx("Microsoft.WindowsMaps");
    let installed = vec![
        Installed {
            index: news,
            package: "Microsoft.BingNews".into(),
            version: "1".into(),
        },
        Installed {
            index: weather,
            package: "Microsoft.BingWeather".into(),
            version: "2".into(),
        },
        Installed {
            index: maps,
            package: "Microsoft.WindowsMaps".into(),
            version: "3".into(),
        },
    ];
    let events = RefCell::new(Vec::new());
    let batch = remove_with(
        &[news, weather, maps, news],
        &installed,
        &|_| Ok(()),
        &|p| match p {
            "Microsoft.BingNews" => PackageOutcome::Removed,
            "Microsoft.BingWeather" => PackageOutcome::Protected,
            _ => PackageOutcome::Failed("boom".into()),
        },
        &|e| events.borrow_mut().push(e),
    )
    .unwrap();
    assert_eq!(batch.removed.len(), 1);
    assert_eq!(batch.skipped, [weather]);
    assert_eq!(
        batch.failed,
        [Failure {
            index: maps,
            reason: "boom".into()
        }]
    );
    let events = events.into_inner();
    assert_eq!(events.len(), 9, "each app saves, starts and finishes once");
    assert_eq!(events[0], Progress::Saving(news));
    assert_eq!(events[1], Progress::Started(news));
    assert_eq!(events[2], Progress::Finished(news, ItemResult::Removed));
    assert_eq!(
        events[5],
        Progress::Finished(weather, ItemResult::Protected)
    );
}

#[test]
fn no_copy_means_no_removal() {
    let index = catalog::owner("Microsoft.BingWeather").unwrap();
    let installed = vec![Installed {
        index,
        package: "Microsoft.BingWeather".into(),
        version: "1".into(),
    }];
    let ran = std::cell::Cell::new(false);
    let batch = remove_with(
        &[index],
        &installed,
        &|_| Err(Kept::NoSpace),
        &|_| {
            ran.set(true);
            PackageOutcome::Removed
        },
        &|_| {},
    )
    .unwrap();
    assert!(!ran.get(), "never removed without a copy");
    assert!(batch.removed.is_empty() && batch.failed.is_empty());
    assert_eq!(batch.kept, vec![index]);
}

#[test]
fn apps_that_are_not_installed_are_ignored() {
    let news = idx("Microsoft.BingNews");
    let batch = remove_with(
        &[news],
        &[],
        &|_| panic!("must not save"),
        &|_| panic!("must not run"),
        &|_| {},
    )
    .unwrap();
    assert_eq!(
        batch,
        Batch {
            t: batch.t,
            ..Batch::default()
        }
    );
}

#[test]
fn an_unreadable_removed_apps_list_is_kept_not_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(journal::FILE);
    let kept = dir.path().join(format!("{}.damaged", journal::FILE));
    let batch = Batch {
        t: 1,
        removed: Vec::new(),
        skipped: vec![2],
        failed: Vec::new(),
        kept: Vec::new(),
    };
    let good = serde_json::to_string(&batch).unwrap();
    std::fs::write(&path, format!("{good}\nnot json\n")).unwrap();
    assert_eq!(journal::load_from(&path), vec![batch.clone()]);
    assert_eq!(std::fs::read(&kept).unwrap(), std::fs::read(&path).unwrap());
    std::fs::write(&path, b"\xff\xfe").unwrap();
    assert!(journal::load_from(&path).is_empty());
    assert!(!path.exists());
    assert_eq!(std::fs::read(&kept).unwrap(), b"\xff\xfe");
    std::fs::write(&path, format!("{good}\n")).unwrap();
    assert_eq!(journal::load_from(&path), vec![batch]);
}

#[test]
fn journal_round_trip_and_restore_marking() {
    let dir = std::env::temp_dir().join(format!("secblitz-debloat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(journal::FILE);
    let _ = std::fs::remove_file(&path);
    assert!(journal::load_from(&path).is_empty());
    let batch = Batch {
        t: 42,
        removed: vec![Removed {
            index: 3,
            package: "Microsoft.GetHelp".into(),
            version: "1".into(),
            restored: false,
        }],
        skipped: vec![5],
        failed: vec![Failure {
            index: 7,
            reason: "x".into(),
        }],
        kept: vec![],
    };
    journal::append_to(&path, &batch).unwrap();
    journal::append_to(&path, &batch).unwrap();
    assert_eq!(
        journal::load_from(&path),
        vec![batch.clone(), batch.clone()]
    );
    journal::mark_restored_in(&path, 3).unwrap();
    assert!(journal::load_from(&path)
        .iter()
        .all(|b| b.removed[0].restored));
    std::fs::write(&path, "not json\n").unwrap();
    assert!(journal::load_from(&path).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_run_cut_short_still_leaves_every_removed_app_on_the_list() {
    use std::cell::RefCell;
    let news = idx("Microsoft.BingNews");
    let weather = idx("Microsoft.BingWeather");
    let installed = vec![
        Installed {
            index: news,
            package: "Microsoft.BingNews".into(),
            version: "1".into(),
        },
        Installed {
            index: weather,
            package: "Microsoft.BingWeather".into(),
            version: "1".into(),
        },
    ];
    let dir = std::env::temp_dir().join(format!("secblitz-ckpt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("debloat.jsonl");
    let _ = std::fs::remove_file(&path);
    let seen = RefCell::new(Vec::new());
    let batch = remove_with_checkpoint(
        &[news, weather],
        &installed,
        &|_| Ok(()),
        &|_| PackageOutcome::Removed,
        &|_| {},
        &|b| {
            journal::upsert_to(&path, b).unwrap();
            seen.borrow_mut().push(journal::load_from(&path));
            Ok(())
        },
    )
    .unwrap();
    let seen = seen.into_inner();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].len(), 1);
    assert_eq!(
        seen[0][0].removed.len(),
        1,
        "first app is on record already"
    );
    assert_eq!(seen[1].len(), 1, "one line per run, not one per app");
    assert_eq!(seen[1][0].removed.len(), 2);
    assert_eq!(journal::load_from(&path), vec![batch]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_run_stops_removing_when_its_record_cannot_be_saved() {
    use std::cell::Cell;
    let news = idx("Microsoft.BingNews");
    let weather = idx("Microsoft.BingWeather");
    let installed: Vec<Installed> = [
        (news, "Microsoft.BingNews"),
        (weather, "Microsoft.BingWeather"),
    ]
    .into_iter()
    .map(|(index, package)| Installed {
        index,
        package: package.into(),
        version: "1".into(),
    })
    .collect();
    let ran = Cell::new(0);
    let batch = remove_with_checkpoint(
        &[news, weather],
        &installed,
        &|_| Ok(()),
        &|_| {
            ran.set(ran.get() + 1);
            PackageOutcome::Removed
        },
        &|_| {},
        &|_| anyhow::bail!("disk full"),
    )
    .unwrap();
    assert_eq!(ran.get(), 1, "the second app is not touched");
    assert_eq!(batch.removed.len(), 1);
    assert_eq!(batch.failed.len(), 1);
    assert_eq!(batch.failed[0].index, weather);
}

#[test]
fn a_second_run_in_the_same_second_is_a_new_line() {
    let item = |index| Removed {
        index,
        package: "p".into(),
        version: "1".into(),
        restored: false,
    };
    let dir = std::env::temp_dir().join(format!("secblitz-upsert-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("debloat.jsonl");
    let _ = std::fs::remove_file(&path);
    let first = Batch {
        t: 5,
        removed: vec![item(1)],
        ..Batch::default()
    };
    let other = Batch {
        t: 5,
        removed: vec![item(2)],
        ..Batch::default()
    };
    let grown = Batch {
        t: 5,
        removed: vec![item(2), item(3)],
        ..Batch::default()
    };
    journal::upsert_to(&path, &first).unwrap();
    journal::upsert_to(&path, &other).unwrap();
    assert_eq!(journal::load_from(&path), vec![first.clone(), other]);
    journal::upsert_to(&path, &grown).unwrap();
    assert_eq!(journal::load_from(&path), vec![first, grown]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn offline_scripts_are_plain_ascii_and_emit_json() {
    for (name, text) in [
        ("describe", include_str!("scripts/describe.ps1")),
        ("register", include_str!("scripts/register.ps1")),
    ] {
        assert!(text.is_ascii(), "{name}.ps1 must be ASCII");
        assert!(!text.contains('\r'), "{name}.ps1 must use LF endings");
        assert!(text.contains("ConvertTo-Json"), "{name}.ps1 prints JSON");
    }
}

#[test]
fn still_removed_lists_each_app_once_and_skips_restored_ones() {
    let item = |index, restored| Removed {
        index,
        package: "p".into(),
        version: "1".into(),
        restored,
    };
    let batch = |t, removed| Batch {
        t,
        removed,
        skipped: vec![],
        failed: vec![],
        kept: vec![],
    };
    let journal = [
        batch(10, vec![item(3, true), item(4, true), item(5, false)]),
        batch(
            20,
            vec![item(3, false), item(5, false), item(u16::MAX, false)],
        ),
    ];
    assert_eq!(
        journal::still_removed(&journal, catalog().len()),
        vec![(3, 20), (5, 20)]
    );
    assert!(journal::still_removed(&[], catalog().len()).is_empty());
}

#[test]
fn restore_all_sorts_outcomes() {
    use super::offline::Restored::*;
    assert_eq!(classify(Some(Ok(Back)), false), Bucket::Restored);
    assert_eq!(
        classify(Some(Ok(BackWithoutSomeData)), true),
        Bucket::Restored
    );
    assert_eq!(classify(Some(Ok(AlreadyThere)), false), Bucket::Restored);
    assert_eq!(classify(Some(Ok(Damaged)), true), Bucket::NeedsStore);
    assert_eq!(classify(Some(Ok(NoCopy)), false), Bucket::Failed);
    assert_eq!(
        classify(Some(Err(anyhow::anyhow!("x"))), true),
        Bucket::NeedsStore
    );
    assert_eq!(
        classify(Some(Err(anyhow::anyhow!("x"))), false),
        Bucket::Failed
    );
    assert_eq!(classify(None, true), Bucket::NeedsStore);
    assert_eq!(classify(None, false), Bucket::Failed);
}

#[test]
fn the_catalog_only_grows_at_the_end() {
    for (i, family) in [
        (0, "Microsoft.BingNews"),
        (6, "Microsoft.MicrosoftOfficeHub"),
        (55, "Microsoft.XboxApp"),
        (56, "Microsoft.BingFinance"),
    ] {
        assert_eq!(catalog()[i].family, family);
    }
}

#[test]
fn newer_apps_are_exact_names_never_patterns() {
    for app in &catalog::CATALOG[56..] {
        assert!(!app.family.contains('*'), "{}", app.family);
        assert_eq!(catalog::owner(app.family), Some(idx(app.family)));
        assert!(!is_protected(app.family), "{}", app.family);
        assert!(matches!(
            app.group,
            Group::Recommended | Group::Promotions | Group::Utilities
        ));
    }
}

#[test]
fn paint_3d_is_not_the_normal_paint_app() {
    assert_eq!(catalog::owner("Microsoft.Paint"), None);
    assert_eq!(
        catalog::owner("Microsoft.MSPaint"),
        Some(idx("Microsoft.MSPaint"))
    );
    assert_eq!(
        catalog()[idx("Microsoft.MSPaint") as usize].name,
        "Paint 3D"
    );
}

#[test]
fn the_duolingo_row_matches_its_real_package_and_nothing_wider() {
    let duolingo = catalog::owner("D5EA27B7.Duolingo-LearnLanguagesforFree").unwrap();
    assert_eq!(catalog()[duolingo as usize].name, "Duolingo");
    assert_eq!(catalog::owner("Duolingo-Other"), None);
    assert_eq!(catalog::owner("D5EA27B7.SomethingElse"), None);
}

#[test]
fn the_office_hub_row_uses_its_current_name_and_warns_about_the_copilot_key_on_windows_11() {
    let hub = &catalog()[idx("Microsoft.MicrosoftOfficeHub") as usize];
    assert_eq!(hub.name, "Microsoft 365 Copilot app");
    assert!(catalog::note(hub.family).unwrap().contains("Copilot key"));
    assert!(catalog::note_on(hub.family, true)
        .unwrap()
        .contains("Copilot key"));
    assert_eq!(catalog::note_on(hub.family, false), None);
    assert_eq!(
        catalog::note_on("microsoft.windowscommunicationsapps", false),
        catalog::note("microsoft.windowscommunicationsapps")
    );
}

#[test]
fn widgets_and_their_engine_say_they_stop_everywhere() {
    for family in [
        "MicrosoftWindows.Client.WebExperience",
        "Microsoft.WidgetsPlatformRuntime",
    ] {
        assert_eq!(catalog()[idx(family) as usize].group, Group::Promotions);
        let note = catalog::note(family).unwrap();
        assert!(note.contains("everywhere"), "{note}");
    }
}

#[test]
fn mail_and_calendar_and_family_carry_their_plain_warnings() {
    let mail = catalog::note("microsoft.windowscommunicationsapps").unwrap();
    assert!(mail.contains("end of 2024"), "{mail}");
    assert_eq!(
        catalog()[idx("microsoft.windowscommunicationsapps") as usize].group,
        Group::Promotions
    );
    let family = "MicrosoftCorporationII.MicrosoftFamily";
    assert_eq!(catalog()[idx(family) as usize].group, Group::Utilities);
    assert!(catalog::note(family).unwrap().contains("Parents"));
}

#[test]
fn notes_belong_to_catalog_apps_and_stay_plain() {
    let with_notes = catalog()
        .iter()
        .filter(|a| catalog::note(a.family).is_some())
        .count();
    assert_eq!(with_notes, 14);
    for app in catalog() {
        if let Some(note) = catalog::note(app.family) {
            assert!(note.ends_with('.'), "{note}");
            assert!(!note.contains('\u{2014}') && !note.contains('!'), "{note}");
            assert!(note.chars().count() <= 130, "{note}");
        }
    }
    assert_eq!(catalog::note("Not.InTheCatalog"), None);
}

#[test]
fn a_name_that_starts_like_a_protected_prefix_is_left_out() {
    assert!(is_protected("Microsoft.NetworkSpeedTest"));
    assert_eq!(catalog::owner("Microsoft.NetworkSpeedTest"), None);
}
