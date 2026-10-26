// Each operating system trusts only its own compiled catalog.
mod os_catalogs {
    use super::*;
    use crate::os::Os;

    #[test]
    fn the_windows_catalog_lists_every_id_the_engine_accepts() {
        let mut expected: Vec<&str> = crate::hardening::all().iter().map(|s| s.id).collect();
        expected.extend([
            "defender.realtime",
            "defender.behavior",
            "defender.ioav",
            "defender.archive",
            "firewall.domain.enabled",
            "firewall.private.enabled",
            "firewall.public.enabled",
            "firewall.domain.inbound",
            "firewall.private.inbound",
            "firewall.public.inbound",
            "uac.enabled",
            "uac.consent",
            "installer.always_install_elevated",
            "wdigest.use_logon_credential",
            "lsa.restrict_anonymous_sam",
            "lsa.limit_blank_password_use",
            "permissions.service.bits",
            "permissions.service.wuauserv",
        ]);
        let listed = ids(Os::Windows);
        for id in &expected {
            assert!(listed.contains(id), "{id} is missing from the list");
        }
        for id in &listed {
            assert!(target(id).is_ok(), "{id} is listed but not accepted");
        }
        assert_eq!(listed.len(), expected.len());
    }

    #[test]
    fn macos_has_no_checks_yet() {
        assert!(ids(Os::Macos).is_empty());
    }

    #[test]
    fn the_linux_catalog_lists_the_linux_ids_and_none_of_windows() {
        let linux = ids(Os::Linux);
        assert!(linux.contains(&"linux.firewall"));
        let windows = ids(Os::Windows);
        for id in &linux {
            assert!(!windows.contains(id), "{id}");
            assert!(target_in(Os::Linux, id).is_ok(), "{id}");
            assert!(target_in(Os::Windows, id).is_err(), "{id}");
            assert!(target_in(Os::Macos, id).is_err(), "{id}");
        }
        for id in &windows {
            assert!(target_in(Os::Linux, id).is_err(), "{id}");
        }
    }

    #[test]
    fn a_linux_engine_checks_fixes_and_undoes_a_linux_control() {
        const SSH: &str = "linux.ssh_server";
        let dir = tempfile::tempdir().unwrap();
        let state = Rc::new(RefCell::new(FakeState::default()));
        let on = json!({"items": {"enabled": 1}});
        let off = json!({"items": {"enabled": 0}});
        state.borrow_mut().values.insert(SSH.into(), on.clone());
        state.borrow_mut().catalog_target = Some(target_in(Os::Linux, SSH).unwrap());
        let open = || {
            Engine::open_for(Os::Linux, dir.path().into(), backend(&state, &[SSH], "machine-a"))
                .unwrap()
        };
        let mut e = open();
        assert_eq!(e.audit().unwrap().results[0].status, CheckStatus::Attention);
        e.apply(|_| {}).unwrap();
        assert_eq!(state.borrow().values[SSH], off);
        assert_eq!(e.audit().unwrap().results[0].status, CheckStatus::Compliant);
        drop(e);
        let mut e = open();
        e.revert(|_| {}).unwrap();
        assert_eq!(state.borrow().values[SSH], on);
    }

    #[test]
    fn a_linux_engine_refuses_a_value_that_is_not_a_legal_setting() {
        const SSH: &str = "linux.ssh_server";
        let dir = tempfile::tempdir().unwrap();
        let state = Rc::new(RefCell::new(FakeState::default()));
        state
            .borrow_mut()
            .values
            .insert(SSH.into(), json!({"items": {"enabled": 7}}));
        state.borrow_mut().catalog_target = Some(target_in(Os::Linux, SSH).unwrap());
        let mut e = Engine::open_for(
            Os::Linux,
            dir.path().into(),
            backend(&state, &[SSH], "machine-a"),
        )
        .unwrap();
        assert!(e.apply(|_| {}).is_err());
        assert!(state.borrow().writes.is_empty());
    }

    #[test]
    fn a_linux_engine_refuses_a_backend_control_with_a_windows_id() {
        for os in [Os::Linux, Os::Macos] {
            let dir = tempfile::tempdir().unwrap();
            let state = Rc::new(RefCell::new(FakeState::default()));
            state
                .borrow_mut()
                .values
                .insert("uac.enabled".into(), json!({"present":true,"value":1}));
            let error = Engine::open_for(
                os,
                dir.path().into(),
                backend(&state, &["uac.enabled"], "machine-a"),
            )
            .err()
            .expect("a Windows id must be refused");
            assert!(error.to_string().contains("Unknown control id"), "{error}");
        }
    }

    #[test]
    fn a_linux_engine_refuses_to_recover_a_journal_naming_a_windows_id() {
        let (dir, state, mut e) = fixture(DEFENDER, json!(false));
        prepare(&mut e, 1, DEFENDER, json!(true));
        drop(e);
        for os in [Os::Linux, Os::Macos] {
            let error = Engine::open_for(os, dir.path().into(), backend(&state, &[], "machine-a"))
                .err()
                .expect("a Windows journal must not load on another system");
            assert!(
                format!("{error:#}").contains("Unknown control id"),
                "{error:#}"
            );
        }
        reopen(&dir, &state, &[DEFENDER]);
    }

    #[test]
    fn a_windows_engine_still_opens_with_its_own_catalog() {
        let dir = tempfile::tempdir().unwrap();
        let state = Rc::new(RefCell::new(FakeState::default()));
        state
            .borrow_mut()
            .values
            .insert(DEFENDER.into(), json!(true));
        let e = Engine::open_for(
            Os::Windows,
            dir.path().into(),
            backend(&state, &[DEFENDER], "machine-a"),
        )
        .unwrap();
        assert_eq!(e.available_controls().len(), 1);
    }

    #[test]
    fn firewall_evidence_is_rejected_outside_windows() {
        let obs = Observation {
            value: json!(true),
            eligible: true,
            effective: Some(EffectiveFirewall::Enabled(true)),
            authority: Some(Authority::Local),
            ..Default::default()
        };
        crate::model::validate_observation_for(Os::Windows, "firewall.public.enabled", &obs)
            .unwrap();
        for os in [Os::Linux, Os::Macos] {
            assert!(
                crate::model::validate_observation_for(os, "firewall.public.enabled", &obs)
                    .is_err()
            );
        }
        crate::model::validate_observation_for(Os::Linux, "ufw.enabled", &Observation::default())
            .unwrap();
    }
}
