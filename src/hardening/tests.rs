use super::specs::*;
use super::*;

fn items(spec: &Spec, vals: &[Option<u32>]) -> Value {
    let mut m = Map::new();
    for (k, v) in spec.keys.iter().zip(vals) {
        m.insert(k.name.into(), v.map_or(Value::Null, Value::from));
    }
    json!({ "items": m })
}

fn items_of(spec: &Spec, vals: &[Value]) -> Value {
    let mut m = Map::new();
    for (k, v) in spec.keys.iter().zip(vals) {
        m.insert(k.name.into(), v.clone());
    }
    json!({ "items": m })
}

fn safe_value(k: &Key) -> Value {
    match k.rule {
        Rule::Set { safe, .. } => json!(safe[0]),
        Rule::Text { safe, .. } => json!(safe[0]),
        Rule::Exposure => json!(0),
    }
}

fn fixed_value(k: &Key) -> Value {
    match k.rule {
        Rule::Set { fix, .. } => json!(fix),
        Rule::Text { fix, .. } => json!(fix),
        Rule::Exposure => Value::Null,
    }
}

fn unsafe_values(k: &Key) -> Vec<Value> {
    let (mut out, absent_safe) = match k.rule {
        Rule::Set {
            safe, absent_safe, ..
        } => (
            candidate_values(k)
                .into_iter()
                .filter(|n| !safe.contains(n))
                .map(|n| json!(n))
                .collect::<Vec<_>>(),
            absent_safe,
        ),
        Rule::Text {
            safe, absent_safe, ..
        } => (
            ["automatic", "secure", "OFF", ""]
                .into_iter()
                .filter(|t| !safe.contains(t))
                .map(|t| json!(t))
                .collect::<Vec<_>>(),
            absent_safe,
        ),
        Rule::Exposure => return Vec::new(),
    };
    if !absent_safe {
        out.push(Value::Null);
    }
    out
}

fn candidate_values(k: &Key) -> Vec<u32> {
    if k.allowed.is_empty() {
        // Wide ranges (timestamps, minutes) are sampled at the low end.
        (0..=k.max.min(300)).collect()
    } else {
        k.allowed.to_vec()
    }
}

#[test]
fn catalog_is_well_formed() {
    assert!(all().len() >= 20);
    let mut ids = std::collections::HashSet::new();
    for s in all() {
        assert!(ids.insert(s.id), "duplicate id {}", s.id);
        assert!(!s.keys.is_empty());
        for k in s.keys {
            if let Rule::Set {
                safe,
                absent_safe,
                fix,
            } = k.rule
            {
                match fix {
                    Some(f) => {
                        assert!(safe.contains(&f), "{} fix {f} is not safe", s.id);
                        assert!(f <= k.max);
                    }
                    None => assert!(absent_safe, "{} removal needs absent_safe", s.id),
                }
                assert!(safe.iter().all(|n| *n <= k.max));
                assert!(k.allowed.is_empty() || safe.iter().all(|n| k.allowed.contains(n)));
            }
            if let Rule::Text {
                safe,
                absent_safe,
                fix,
            } = k.rule
            {
                match fix {
                    Some(f) => assert!(safe.contains(&f), "{} fix {f} is not safe", s.id),
                    None => assert!(absent_safe, "{} removal needs absent_safe", s.id),
                }
                assert!(
                    safe.iter().all(|t| text_ok(t, k.max) && !t.is_empty()),
                    "{}",
                    s.id
                );
                assert!(k.allowed.is_empty(), "{}", s.id);
            }
            if s.source == Source::Registry {
                assert!(k.path.starts_with("HKLM:\\"), "{}", s.id);
                assert!(!k.path.contains('\''));
            }
        }
        assert_eq!(s.dynamic(), s.keys[0].name == "*");
        assert!(!s.script_json().contains("\\u0027"));
        assert!(!s.script_json().contains('\''));
        if !s.dynamic() {
            s.validate(&s.catalog_target()).unwrap();
            assert!(!s.any_unsafe(&s.catalog_target()), "{}", s.id);
        }
    }
    assert!(all().iter().filter(|s| !s.ask).count() >= 6);
    assert!(all().iter().filter(|s| s.ask).count() >= 10);
}

#[test]
fn fixed_controls_repair_only_unsafe_keys_and_converge() {
    for s in all().iter().filter(|s| !s.dynamic()) {
        let safe_vals: Vec<Value> = s.keys.iter().map(safe_value).collect();
        for (i, k) in s.keys.iter().enumerate() {
            if matches!(k.rule, Rule::Exposure) {
                continue;
            }
            for bad in unsafe_values(k) {
                let mut vals = safe_vals.clone();
                vals[i] = bad.clone();
                let before = items_of(s, &vals);
                s.validate(&before).unwrap();
                assert!(s.any_unsafe(&before), "{} {bad:?}", s.id);
                let target = s.derive_target(&before).unwrap();
                s.validate(&target).unwrap();
                assert!(!s.any_unsafe(&target), "{} target unsafe", s.id);
                assert_ne!(before, target);
                for (j, v) in vals.iter().enumerate() {
                    if j != i {
                        assert_eq!(target["items"][s.keys[j].name], *v);
                    }
                }
                assert_eq!(target["items"][k.name], fixed_value(k));
            }
        }
        let st = items_of(s, &safe_vals);
        assert!(!s.any_unsafe(&st));
        assert_eq!(s.derive_target(&st).unwrap(), st);
    }
}

#[test]
fn safe_absent_defaults_count_as_protected() {
    let pnp = spec("printer.point_and_print").unwrap();
    let absent = items(pnp, &[None, None, None]);
    assert!(!pnp.any_unsafe(&absent));
    let bad = items(pnp, &[Some(0), Some(1), Some(2)]);
    assert!(pnp.any_unsafe(&bad));
    assert_eq!(
        pnp.derive_target(&bad).unwrap(),
        items(pnp, &[None, None, None])
    );
    let part = items(pnp, &[Some(1), Some(1), Some(1)]);
    assert_eq!(
        pnp.derive_target(&part).unwrap(),
        items(pnp, &[Some(1), None, Some(1)])
    );
    for id in [
        "net.llmnr",
        "lsa.run_as_ppl",
        "wsh.disabled",
        "defender.asr.standard",
    ] {
        let s = spec(id).unwrap();
        let vals = vec![None; s.keys.len()];
        assert!(s.any_unsafe(&items(s, &vals)), "{id}");
    }
    let ppl = spec("lsa.run_as_ppl").unwrap();
    assert!(!ppl.any_unsafe(&items(ppl, &[Some(1)])));
    let asr = spec("defender.asr.standard").unwrap();
    assert!(!asr.any_unsafe(&items(asr, &[Some(1), Some(6), Some(1)])));
    assert!(asr.any_unsafe(&items(asr, &[Some(1), Some(2), Some(1)])));
}

#[test]
fn validation_rejects_malformed_states() {
    let ppl = spec("lsa.run_as_ppl").unwrap();
    for bad in [
        json!(null),
        json!({}),
        json!({"items": {}}),
        json!({"items": {"RunAsPPL": 3}}),
        json!({"items": {"RunAsPPL": -1}}),
        json!({"items": {"RunAsPPL": 1.5}}),
        json!({"items": {"RunAsPPL": "1"}}),
        json!({"items": {"RunAsPPL": true}}),
        json!({"items": {"Other": 1}}),
        json!({"items": {"RunAsPPL": 1, "Other": 1}}),
        json!({"items": {"RunAsPPL": 1}, "path": "x"}),
        json!({"present": true, "value": 1}),
    ] {
        assert!(ppl.validate(&bad).is_err(), "accepted {bad}");
    }
    for ok in [
        json!({"items": {"RunAsPPL": null}}),
        json!({"items": {"RunAsPPL": 0}}),
    ] {
        ppl.validate(&ok).unwrap();
    }
    let asr = spec("defender.asr.standard").unwrap();
    let g = "56a863a9-875e-4185-98a7-b882c64b5ce5";
    let bad_action = json!({"items": {g: 3,
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2": 1,
        "e6db77e5-3df2-4cf1-b95a-636979351e5b": 1}});
    assert!(asr.validate(&bad_action).is_err());
    let lock = spec("accounts.lockout_policy").unwrap();
    assert!(lock
        .validate(&json!({"items": {"LockoutThreshold": 1000}}))
        .is_err());
    lock.validate(&json!({"items": {"LockoutThreshold": 0}}))
        .unwrap();
}

#[test]
fn dynamic_controls_validate_names_and_narrow_views() {
    let fw = spec("net.public_sharing_exposure").unwrap();
    fw.validate(&json!({"items": {}})).unwrap();
    fw.validate(&json!({"items": {"FPS-SMB-In-TCP": 15, "NETDIS-LLMNR-In-UDP": 6}}))
        .unwrap();
    for bad in [
        json!({"items": {"RemoteDesktop-UserMode-In-TCP": 15}}),
        json!({"items": {"FPS-x'; calc": 15}}),
        json!({"items": {"FPS-ok": 16}}),
        json!({"items": {"FPS-ok": null}}),
        json!({"items": {"fps-ok": 1}}),
    ] {
        assert!(fw.validate(&bad).is_err(), "accepted {bad}");
    }
    let before = json!({"items": {"FPS-A": 15, "FPS-B": 12, "FPS-C": 3, "FPS-D": 7}});
    assert!(fw.any_unsafe(&before));
    assert_eq!(
        fw.derive_target(&before).unwrap(),
        json!({"items": {"FPS-A": 11, "FPS-B": 4, "FPS-C": 3, "FPS-D": 7}})
    );
    let now = json!({"items": {"FPS-A": 11, "FPS-B": 4, "FPS-C": 3, "FPS-D": 7, "FPS-NEW": 15}});
    assert_eq!(
        fw.view(&now, &before),
        json!({"items": {"FPS-A": 11, "FPS-B": 4, "FPS-C": 3, "FPS-D": 7}})
    );
    assert_eq!(fw.catalog_target(), json!("derived-items-v1"));

    let wifi = spec("wifi.risky_profiles").unwrap();
    wifi.validate(&json!({"items": {"Cafe Guest": 1, "John's WiFi": 0}}))
        .unwrap();
    for bad in [
        json!({"items": {"": 1}}),
        json!({"items": {"a\"b": 1}}),
        json!({"items": {"a\nb": 1}}),
        json!({"items": {"x": 2}}),
        json!({"items": {" padded": 1}}),
    ] {
        assert!(wifi.validate(&bad).is_err(), "accepted {bad}");
    }
    assert_eq!(
        wifi.derive_target(&json!({"items": {"Open": 1, "Done": 0}}))
            .unwrap(),
        json!({"items": {"Open": 0, "Done": 0}})
    );
    let ppl = spec("lsa.run_as_ppl").unwrap();
    let v = json!({"items": {"RunAsPPL": 2}});
    assert_eq!(ppl.view(&v, &json!({"items": {}})), v);
}

#[test]
fn network_and_defender_extensions_follow_the_research_specs() {
    for id in [
        "defender.asr.office",
        "defender.asr.ransomware_usb",
        "defender.network_protection",
        "defender.cloud_block_level",
        "net.stack_hardening",
        "net.netbios",
        "net.mdns",
        "net.wpad",
        "firewall.outbound_smb_internet",
        "tls.legacy_protocols",
    ] {
        assert!(spec(id).unwrap().ask, "{id} must be an ASK item");
    }
    for id in ["defender.asr.office", "defender.asr.ransomware_usb"] {
        assert_eq!(spec(id).unwrap().source, Source::DefenderAsr);
        assert!(spec(id).unwrap().gate.tamper_exempt);
    }
    // Office rules must be Block; Warn is not enough for them.
    let office = spec("defender.asr.office").unwrap();
    let mut vals = vec![Some(1); 4];
    assert!(!office.any_unsafe(&items(office, &vals)));
    vals[2] = Some(6);
    assert!(office.any_unsafe(&items(office, &vals)));
    let usb = spec("defender.asr.ransomware_usb").unwrap();
    let before = items(usb, &[Some(0), None]);
    assert_eq!(
        usb.derive_target(&before).unwrap(),
        items(usb, &[Some(6), Some(6)])
    );
    assert!(!usb.any_unsafe(&items(usb, &[Some(1), Some(6)])));
    // Network protection: Enabled only; audit mode is not protection.
    let np = spec("defender.network_protection").unwrap();
    assert!(np.any_unsafe(&items(np, &[Some(2)])));
    assert_eq!(
        np.derive_target(&items(np, &[Some(0)])).unwrap(),
        items(np, &[Some(1)])
    );
    let cbl = spec("defender.cloud_block_level").unwrap();
    assert_eq!(
        cbl.derive_target(&items(cbl, &[Some(0), Some(0)])).unwrap(),
        items(cbl, &[Some(2), Some(20)])
    );
    assert!(!cbl.any_unsafe(&items(cbl, &[Some(6), Some(35)])));
    assert!(!cbl.any_unsafe(&items(cbl, &[Some(4), Some(20)])));
    assert!(cbl.any_unsafe(&items(cbl, &[Some(2), Some(10)])));
    for k in cbl.keys {
        if let Rule::Set { fix, .. } = k.rule {
            assert_ne!(fix, Some(6));
        }
    }
    let stack = spec("net.stack_hardening").unwrap();
    let ver: Vec<Value> = serde_json::from_str::<Value>(&stack.script_json()).unwrap()["keys"]
        .as_array()
        .unwrap()
        .clone();
    let by_name = |n: &str| ver.iter().find(|k| k["name"] == n).unwrap().clone();
    assert_eq!(
        by_name("DisableIPSourceRouting")["valueName"],
        "DisableIPSourceRouting"
    );
    assert_eq!(
        by_name("DisableIPSourceRouting6")["valueName"],
        "DisableIPSourceRouting"
    );
    assert!(by_name("DisableIPSourceRouting6")["path"]
        .as_str()
        .unwrap()
        .contains("Tcpip6"));
    assert_eq!(by_name("EnableICMPRedirect")["fix"], 0);
    assert_eq!(by_name("NoNameReleaseOnDemand")["fix"], 1);
    assert!(stack.reboot);
    // TLS: the six protocol sides, Enabled 0 and DisabledByDefault 1; 0xFFFFFFFF is a legal original.
    let tls = spec("tls.legacy_protocols").unwrap();
    assert_eq!(tls.keys.len(), 12);
    let names: std::collections::HashSet<_> = tls.keys.iter().map(|k| k.name).collect();
    assert_eq!(names.len(), 12);
    for proto in ["SSL 3.0", "TLS 1.0", "TLS 1.1"] {
        for side in ["Client", "Server"] {
            let path_end = format!("{proto}\\{side}");
            assert_eq!(
                tls.keys
                    .iter()
                    .filter(|k| k.path.ends_with(&path_end))
                    .count(),
                2,
                "{path_end}"
            );
        }
    }
    let mut m = Map::new();
    for k in tls.keys {
        m.insert(
            k.name.into(),
            if k.value == "Enabled" {
                json!(u32::MAX)
            } else {
                Value::Null
            },
        );
    }
    let before = json!({ "items": m });
    tls.validate(&before).unwrap();
    let target = tls.derive_target(&before).unwrap();
    for k in tls.keys {
        let want = if k.value == "Enabled" { 0 } else { 1 };
        assert_eq!(target["items"][k.name], want);
    }
    assert!(tls
        .validate(&json!({"items": {"ssl3.client.enabled": 2}}))
        .is_err());
    let nb = spec("net.netbios").unwrap();
    assert!(nb.dynamic());
    let a = "{11111111-1111-1111-1111-111111111111}";
    let b = "{abcdefAB-2222-2222-2222-222222222222}";
    nb.validate(&json!({"items": {a: 0, b: 1}})).unwrap();
    for bad in [
        json!({"items": {"Ethernet": 1}}),
        json!({"items": {"{1111}": 1}}),
        json!({"items": {"{1111111g-1111-1111-1111-111111111111}": 1}}),
        json!({"items": {"{11111111-1111-1111-1111-111111111111}'; x": 1}}),
        json!({"items": {a: 3}}),
    ] {
        assert!(nb.validate(&bad).is_err(), "accepted {bad}");
    }
    assert_eq!(
        nb.derive_target(&json!({"items": {a: 0, b: 2}})).unwrap(),
        json!({"items": {a: 2, b: 2}})
    );
    let fw = spec("firewall.outbound_smb_internet").unwrap();
    assert!(fw.any_unsafe(&json!({"items": {"RulePresent": 0}})));
    assert!(!fw.any_unsafe(&json!({"items": {"RulePresent": 1}})));
    assert!(spec("net.mdns").unwrap().keys[0].name == "EnableMDNS");
    assert!(spec("net.wpad").unwrap().keys[0].name == "DisableWpad");
}

#[test]
fn core_protections_write_only_the_documented_values_and_never_a_lock() {
    for (id, scenario) in [
        ("vbs.memory_integrity", "HypervisorEnforcedCodeIntegrity"),
        ("vbs.kernel_stack_protection", "KernelShadowStacks"),
    ] {
        let s = spec(id).unwrap();
        assert!(s.reboot && s.ask && !s.dynamic(), "{id}");
        let names: Vec<&str> = s.keys.iter().map(|k| k.name).collect();
        assert_eq!(names, ["Enabled", "WasEnabledBy"], "{id}");
        for k in s.keys {
            assert!(k.path.ends_with(&format!("Scenarios\\{scenario}")), "{id}");
            assert!(!k.name.contains("Lock") && !k.value.contains("Lock"));
        }
        let absent = items(s, &[None, None]);
        assert!(s.any_unsafe(&absent));
        assert_eq!(
            s.derive_target(&absent).unwrap(),
            items(s, &[Some(1), Some(2)])
        );
        let off = items(s, &[Some(0), Some(2)]);
        assert_eq!(
            s.derive_target(&off).unwrap(),
            items(s, &[Some(1), Some(2)])
        );
        let marker = items(s, &[Some(0), Some(1)]);
        assert_eq!(
            s.derive_target(&marker).unwrap(),
            items(s, &[Some(1), Some(2)])
        );
        let on = items(s, &[Some(1), Some(2)]);
        assert!(!s.any_unsafe(&on));
        assert_eq!(s.derive_target(&on).unwrap(), on);
        assert!(s
            .validate(&json!({"items": {"Enabled": 2, "WasEnabledBy": 2}}))
            .is_err());
        assert!(s.validate(&json!({"items": {"Enabled": 1}})).is_err());
        let gate = serde_json::from_str::<Value>(&s.script_json()).unwrap()["gate"].clone();
        assert!(gate["ownPolicyKey"]
            .as_str()
            .unwrap()
            .ends_with("Windows\\DeviceGuard"));
        assert!(gate["areas"].as_array().unwrap().len() >= 2);
    }
}

/// With SECBLITZ_PARITY_OUT set, writes every spec with the Rust verdict (safe / fix) per candidate value; the PowerShell fixture replays it so both implementations provably agree.
#[test]
fn export_rule_parity_fixture_for_powershell() {
    let Ok(path) = std::env::var("SECBLITZ_PARITY_OUT") else {
        return;
    };
    let mut out = Vec::new();
    for s in all() {
        let mut cases = Vec::new();
        for k in s.keys {
            if let Rule::Text { safe, .. } = k.rule {
                let mut values = vec![Item::Absent, Item::Text(String::new())];
                values.extend(
                    safe.iter()
                        .map(|t| Item::Text(t.to_string()))
                        .chain([Item::Text("automatic".into()), Item::Text("OFF".into())]),
                );
                for v in values {
                    cases.push(json!({
                        "key": k.name, "value": v.to_json(),
                        "safe": item_is_safe(k.rule, &v), "fix": item_fix(k.rule, &v).to_json(),
                    }));
                }
                continue;
            }
            let mut values: Vec<Option<u32>> = vec![None];
            values.extend((0..=k.max.min(16)).map(Some));
            values.push(Some(k.max));
            values.extend(k.allowed.iter().map(|n| Some(*n)));
            values.extend(match k.rule {
                Rule::Set { safe, .. } => safe.iter().map(|n| Some(*n)).collect::<Vec<_>>(),
                Rule::Exposure | Rule::Text { .. } => vec![],
            });
            values.sort_unstable();
            values.dedup();
            for v in values {
                cases.push(json!({
                    "key": k.name, "value": v,
                    "safe": is_safe(k.rule, v), "fix": fix_of(k.rule, v),
                }));
            }
        }
        out.push(json!({
            "id": s.id,
            "spec": serde_json::from_str::<Value>(&s.script_json()).unwrap(),
            "cases": cases,
        }));
    }
    std::fs::write(path, serde_json::to_string(&out).unwrap()).unwrap();
}

#[test]
fn system_dynamic_controls_accept_only_their_own_names() {
    let svc = spec("services.legacy_remote").unwrap();
    svc.validate(&json!({"items": {"RemoteRegistry": 10, "sshd": 4, "WinRM": 13}}))
        .unwrap();
    for bad in [
        json!({"items": {"Spooler": 4}}),
        json!({"items": {"winrm": 4}}),
        json!({"items": {"WinRM": 1}}),
        json!({"items": {"WinRM": 14}}),
        json!({"items": {"WinRM'; calc": 4}}),
    ] {
        assert!(svc.validate(&bad).is_err(), "accepted {bad}");
    }
    let before = json!({"items": {"WinRM": 10, "sshd": 3, "SNMP": 12, "FTPSVC": 5}});
    assert_eq!(
        svc.derive_target(&before).unwrap(),
        json!({"items": {"WinRM": 4, "sshd": 3, "SNMP": 4, "FTPSVC": 4}})
    );

    let ex = spec("defender.exclusions_risky").unwrap();
    ex.validate(&json!({"items": {
        "path:C:\\Users\\Bob\\Downloads": 1, "ext:exe": 0, "proc:powershell.exe": 1,
        "path:D:\\Gäme's": 1,
    }}))
    .unwrap();
    for bad in [
        json!({"items": {"": 1}}),
        json!({"items": {"path:": 1}}),
        json!({"items": {"file:C:\\x": 1}}),
        json!({"items": {"PATH:C:\\x": 1}}),
        json!({"items": {"path:C:\\\"x": 1}}),
        json!({"items": {"ext:exe\n": 1}}),
        json!({"items": {" path:C:\\x": 1}}),
        json!({"items": {"ext:exe": 2}}),
    ] {
        assert!(ex.validate(&bad).is_err(), "accepted {bad}");
    }
    let template = json!({"items": {"ext:exe": 1, "path:C:\\": 1}});
    let now = json!({"items": {"ext:dll": 1}});
    assert_eq!(
        ex.view(&now, &template),
        json!({"items": {"ext:dll": 1, "ext:exe": 0, "path:C:\\": 0}})
    );
    let fw = spec("net.public_sharing_exposure").unwrap();
    assert_eq!(
        fw.view(&json!({"items": {}}), &json!({"items": {"FPS-A": 15}})),
        json!({"items": {}})
    );
}

#[test]
fn handled_item_controls_accept_only_their_own_names_and_values() {
    let svc = spec("services.unquoted_paths").unwrap();
    svc.validate(&json!({"items": {"Acme Updater": 1, "MSSQL$SQLEXPRESS": 0, "a.b-c_d": 2, "Intel(R) Update {1}+x": 1}}))
        .unwrap();
    for bad in [
        json!({"items": {"": 1}}),
        json!({"items": {" Acme": 1}}),
        json!({"items": {"Acme\\Run": 1}}),
        json!({"items": {"Acme\"x": 1}}),
        json!({"items": {"Acme/Run": 1}}),
        json!({"items": {"Acme*": 1}}),
        json!({"items": {"Acme[1]": 1}}),
        json!({"items": {"Acme\n": 1}}),
        json!({"items": {"Acme": 3}}),
        json!({"items": {"x".repeat(257): 1}}),
    ] {
        assert!(svc.validate(&bad).is_err(), "accepted {bad}");
    }
    let fw = spec("firewall.user_dir_inbound_allow").unwrap();
    fw.validate(
        &json!({"items": {"{8C1D4B7E-0000-4000-8000-000000000000}": 1, "uTorrent (TCP-In)": 0}}),
    )
    .unwrap();
    for bad in [
        json!({"items": {"*": 1}}),
        json!({"items": {"Any*": 1}}),
        json!({"items": {"a?b": 1}}),
        json!({"items": {"[x]": 1}}),
        json!({"items": {"a\"b": 1}}),
        json!({"items": {"a\nb": 1}}),
        json!({"items": {"x".repeat(201): 1}}),
    ] {
        assert!(fw.validate(&bad).is_err(), "accepted {bad}");
    }
    let hosts = spec("net.hosts_file").unwrap();
    hosts.validate(&json!({"items": {"hosts": 1}})).unwrap();
    assert!(hosts.validate(&json!({"items": {"hosts2": 1}})).is_err());
    assert!(hosts.validate(&json!({"items": {"hosts": 3}})).is_err());
    let startup = spec("persistence.run_and_tasks").unwrap();
    startup
        .validate(&json!({"items": {
            "run-machine:Updater": 1, "run-machine32:Old": 0, "run-user:My App": 1,
            "folder-user:Helper.lnk": 2, "folder-machine:x.bat": 1, "task:\\Vendor\\Sync": 1,
            "task:\\Top": 0,
        }}))
        .unwrap();
    for bad in [
        json!({"items": {"run-user:": 1}}),
        json!({"items": {"run:Updater": 1}}),
        json!({"items": {"task:Vendor\\Sync": 1}}),
        json!({"items": {"task:\\Vendor\\": 1}}),
        json!({"items": {"run-user:a*": 1}}),
        json!({"items": {"run-user:a\"b": 1}}),
        json!({"items": {" run-user:a": 1}}),
        json!({"items": {"run-user:a": 4}}),
    ] {
        assert!(startup.validate(&bad).is_err(), "accepted {bad}");
    }
    for id in [
        "services.unquoted_paths",
        "firewall.user_dir_inbound_allow",
        "net.hosts_file",
        "persistence.run_and_tasks",
    ] {
        let s = spec(id).unwrap();
        assert!(s.ask && s.dynamic() && !s.reboot, "{id}");
        let key = match id {
            "net.hosts_file" => "hosts",
            "persistence.run_and_tasks" => "run-user:A",
            _ => "A",
        };
        let before = json!({"items": {key: 1}});
        assert!(s.any_unsafe(&before));
        assert_eq!(
            s.derive_target(&before).unwrap(),
            json!({"items": {key: 0}})
        );
        for safe in [0, 2] {
            let state = json!({"items": {key: safe}});
            assert!(!s.any_unsafe(&state), "{id} {safe}");
            assert_eq!(s.derive_target(&state).unwrap(), state);
        }
        let template = json!({"items": {key: 1}});
        assert_eq!(
            s.view(&json!({"items": {key: 2, "other": 1}}), &template),
            json!({"items": {key: 2}})
        );
    }
}

#[test]
fn hosts_rules_match_the_security_check_probe() {
    // The fix and the Tools check must flag exactly the same lines: both
    // scripts carry the same two patterns (\z in the fix is $ in the probe).
    let probe = include_str!("../diagnostics/probes.ps1");
    let handled = include_str!("../platform/hardening.handled.ps1");
    for var in ["$hHostsBroad", "$hHostsUpdate"] {
        let line = handled
            .lines()
            .find(|l| l.starts_with(&format!("{var} = '")))
            .unwrap_or_else(|| panic!("{var}"));
        let pattern = line.split('\'').nth(1).unwrap().replace("\\z", "$");
        assert!(probe.contains(&pattern), "{var} drifted from the probe");
    }
    let risky = handled
        .lines()
        .find(|l| l.starts_with("$hUserDirPattern = '"))
        .unwrap();
    let pattern = risky.split('\'').nth(1).unwrap();
    let rules = include_str!("../diagnostics/probes.ps1");
    assert!(
        rules.contains(pattern),
        "the firewall pattern drifted from the probe"
    );
}

#[test]
fn old_accounts_are_named_by_user_sid_and_never_built_in_ones() {
    let st = spec("accounts.stale_enabled").unwrap();
    assert!(st.ask && st.dynamic() && !st.reboot);
    let a = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    st.validate(&json!({"items": {a: 1, "S-1-5-21-1-2-3-1000": 0}}))
        .unwrap();
    for bad in [
        // Built-in Administrator, Guest, DefaultAccount, WDAGUtilityAccount.
        "S-1-5-21-1111111111-2222222222-3333333333-500",
        "S-1-5-21-1111111111-2222222222-3333333333-501",
        "S-1-5-21-1111111111-2222222222-3333333333-503",
        "S-1-5-21-1111111111-2222222222-3333333333-504",
        "S-1-5-21-1111111111-2222222222-3333333333-999",
        "S-1-5-21-1111111111-2222222222-3333333333-01001",
        "S-1-5-21-1111111111-2222222222-3333333333",
        "S-1-5-21-1111111111-2222222222-3333333333-1001-5",
        "S-1-5-32-544",
        "S-1-1-0",
        "Bob",
        "s-1-5-21-1-2-3-1001",
        "S-1-5-21-1-2-3-1001'; x",
        "S-1-5-21-1-2-3-99999999999",
    ] {
        assert!(
            st.validate(&json!({"items": {bad: 1}})).is_err(),
            "accepted {bad}"
        );
    }
    assert!(st.validate(&json!({"items": {a: 2}})).is_err());
    assert!(st.any_unsafe(&json!({"items": {a: 1}})));
    assert!(!st.any_unsafe(&json!({"items": {a: 0}})));
    assert_eq!(
        st.derive_target(&json!({"items": {a: 1}})).unwrap(),
        json!({"items": {a: 0}})
    );
    assert_eq!(st.catalog_target(), json!("derived-items-v1"));
}

#[test]
fn broad_share_entries_name_one_share_one_broad_sid_and_one_right() {
    let sh = spec("smb.shares_exposed").unwrap();
    assert!(sh.ask && sh.dynamic() && !sh.reboot);
    for ok in [
        "Photos|S-1-1-0|Change",
        "Work files|S-1-5-32-546|Full",
        "Public|S-1-5-7|Change",
        "Fotos für alle|S-1-1-0|Full",
        "Mom's files|S-1-1-0|Change",
        "Backup$|S-1-1-0|Full",
    ] {
        sh.validate(&json!({"items": {ok: 1}})).unwrap();
    }
    for bad in [
        "C$|S-1-1-0|Full",
        "ADMIN$|S-1-1-0|Full",
        "IPC$|S-1-1-0|Change",
        "print$|S-1-1-0|Full",
        "c$|S-1-1-0|Full",
        "Print$|S-1-1-0|Full",
        "Photos|S-1-5-11|Change",
        "Photos|S-1-1-0|Read",
        "Photos|S-1-1-0|change",
        "Photos|Everyone|Change",
        "Photos|S-1-1-0",
        "Photos|S-1-1-0|Change|x",
        "|S-1-1-0|Change",
        " Photos|S-1-1-0|Change",
        "Pho\"tos|S-1-1-0|Change",
        "Pho\ntos|S-1-1-0|Change",
        "Pho\\tos|S-1-1-0|Change",
        "Pho:tos|S-1-1-0|Change",
    ] {
        assert!(
            sh.validate(&json!({"items": {bad: 1}})).is_err(),
            "accepted {bad}"
        );
    }
    assert!(sh
        .validate(&json!({"items": {"Photos|S-1-1-0|Full": 2}}))
        .is_err());
    let long = format!("{}|S-1-1-0|Full", "x".repeat(81));
    assert!(sh.validate(&json!({"items": {long: 1}})).is_err());
}

#[test]
fn recorded_items_are_compared_exactly_and_new_items_never_block_undo() {
    for id in ["accounts.stale_enabled", "smb.shares_exposed"] {
        let s = spec(id).unwrap();
        assert!(s.exact_recorded(), "{id}");
        let (a, b, new) = if id == "smb.shares_exposed" {
            (
                "Photos|S-1-1-0|Change",
                "Work|S-1-1-0|Full",
                "New|S-1-1-0|Full",
            )
        } else {
            (
                "S-1-5-21-1-2-3-1001",
                "S-1-5-21-1-2-3-1002",
                "S-1-5-21-1-2-3-1003",
            )
        };
        let recorded = json!({"items": {a: 1, b: 1}});
        let observed = json!({"items": {a: 0, new: 1}});
        assert_eq!(s.view(&observed, &recorded), json!({"items": {a: 0, b: 0}}));
        assert_eq!(s.view(&json!({"items": {a: 1, b: 1}}), &recorded), recorded);
    }
    assert!(!spec("net.public_sharing_exposure")
        .unwrap()
        .exact_recorded());
    assert!(!spec("defender.exclusions_risky").unwrap().exact_recorded());
}

#[test]
fn browser_warning_policy_only_removes_values_that_switch_the_warning_off() {
    let b = spec("smartscreen.browser_policy").unwrap();
    assert!(b.ask && !b.dynamic() && !b.reboot);
    assert_eq!(b.source, Source::Registry);
    let names: Vec<_> = b.keys.iter().map(|k| k.name).collect();
    assert_eq!(
        names,
        [
            "SmartScreenEnabled",
            "SafeBrowsingProtectionLevel",
            "SafeBrowsingEnabled"
        ]
    );
    for k in b.keys {
        let Rule::Set {
            fix, absent_safe, ..
        } = k.rule
        else {
            unreachable!()
        };
        assert_eq!(fix, None, "{}", k.name);
        assert!(absent_safe, "{}", k.name);
        assert!(
            k.path.starts_with("HKLM:\\SOFTWARE\\Policies\\"),
            "{}",
            k.name
        );
    }
    assert!(!b.any_unsafe(&items(b, &[None, None, None])));
    assert!(!b.any_unsafe(&items(b, &[Some(1), Some(2), Some(1)])));
    assert!(b.any_unsafe(&items(b, &[Some(0), None, None])));
    assert!(b.any_unsafe(&items(b, &[None, Some(0), None])));
    assert!(b.any_unsafe(&items(b, &[None, None, Some(0)])));
    assert_eq!(
        b.derive_target(&items(b, &[Some(0), Some(2), Some(0)]))
            .unwrap(),
        items(b, &[None, Some(2), None])
    );
    assert!(b.validate(&items(b, &[Some(3), None, None])).is_err());
    assert!(b.gate.areas.contains(&"Edge"));
    assert!(b
        .gate
        .policy_values
        .contains(&(CHROME_POLICY, "CloudManagementEnrollmentToken")));
    assert!(b
        .gate
        .policy_values
        .contains(&(EDGE_POLICY, "EdgeManagementEnrollmentToken")));
}

#[test]
fn system_controls_follow_the_research_exclusions() {
    // Never ForceRelocateImages, never telemetry 0, never RunAsPPL 1-style locks.
    let mit = spec("system.exploit_mitigations").unwrap();
    let names: Vec<_> = mit.keys.iter().map(|k| k.name).collect();
    assert_eq!(names, ["DEP", "SEHOP", "BottomUp", "HighEntropy", "CFG"]);
    let diag = spec("privacy.diagnostic_data_level").unwrap();
    let Rule::Set { fix, .. } = diag.keys[0].rule else {
        unreachable!()
    };
    assert_eq!(fix, Some(1));
    assert!(spec("ntlm.extras")
        .unwrap()
        .keys
        .iter()
        .all(|k| k.name != "UseMachineId"));
    for id in [
        "ntlm.extras",
        "driver.vulnerable_blocklist",
        "ps.v2_engine",
        "printer.spooler_remote",
        "services.legacy_remote",
        "session.lock_on_wake",
        "update.store_autoupdate_policy",
        "update.paused",
        "smartscreen.apps",
        "privacy.recall",
        "privacy.diagnostic_data_level",
        "privacy.delivery_optimization",
        "privacy.clipboard_sync",
        "privacy.online_speech",
        "privacy.typing_inking",
        "privacy.lock_screen_notifications",
        "privacy.signin_email",
        "privacy.wifi_random_address",
        "defender.exclusions_risky",
        "ai.click_to_do",
        "ai.paint",
        "ai.notepad",
        "debloat.widgets_policy",
        "debloat.device_companion_apps",
        "browser.shopping_ai",
        "browser.data_collection",
        "browser.safety_mode",
        "browser.dns_bypass",
        "browser.extensions_off",
    ] {
        assert!(is_ask_check_id(id), "{id} must be a choice");
    }
    assert!(!is_ask_check_id("system.exploit_mitigations"));
    assert!(spec("update.paused")
        .unwrap()
        .keys
        .iter()
        .all(|k| k.max <= i32::MAX as u32));
}

#[test]
fn access_controls_are_choices_that_change_exactly_one_thing() {
    for id in [
        "accounts.autologon",
        "remote_desktop.disabled",
        "smb1.disabled",
    ] {
        assert!(is_ask_check_id(id), "{id} must be a choice");
    }
    let a = spec("accounts.autologon").unwrap();
    assert_eq!(a.source, Source::WinlogonAutoLogon);
    assert!(!a.reboot && !a.dynamic());
    assert_eq!(a.keys.len(), 1);
    assert_eq!(a.keys[0].name, "AutoAdminLogon");
    assert!(a.keys[0].path.ends_with(r"\Winlogon"));
    let on = items(a, &[Some(1)]);
    assert!(a.any_unsafe(&on));
    assert_eq!(a.derive_target(&on).unwrap(), items(a, &[Some(0)]));
    assert!(!a.any_unsafe(&items(a, &[None])));
    assert!(!a.any_unsafe(&items(a, &[Some(0)])));
    assert!(a.validate(&items(a, &[Some(2)])).is_err());
    let json = a.script_json();
    for never in ["DefaultPassword", "DefaultUserName", "AutoLogonCount"] {
        assert!(!json.contains(never), "{never} must never be touched");
    }
    let r = spec("remote_desktop.disabled").unwrap();
    assert_eq!(r.source, Source::Registry);
    assert!(!r.reboot && r.keys.len() == 1);
    assert_eq!(r.keys[0].name, "fDenyTSConnections");
    assert!(r
        .gate
        .policy_values
        .iter()
        .any(|(p, n)| { p.ends_with(r"\Terminal Services") && *n == "fDenyTSConnections" }));
    assert!(r.any_unsafe(&items(r, &[Some(0)])));
    assert!(!r.any_unsafe(&items(r, &[Some(1)])));
    assert_eq!(
        r.derive_target(&items(r, &[Some(0)])).unwrap(),
        items(r, &[Some(1)])
    );
    let s = spec("smb1.disabled").unwrap();
    assert_eq!(s.source, Source::SmbFeature);
    assert!(s.reboot && !s.dynamic());
    let names: Vec<_> = s.keys.iter().map(|k| k.name).collect();
    assert_eq!(
        names,
        [
            "SMB1Protocol",
            "SMB1Protocol-Client",
            "SMB1Protocol-Server",
            "SMB1Protocol-Deprecation"
        ]
    );
    let before = items(s, &[Some(1), Some(1), Some(0), Some(1)]);
    assert_eq!(
        s.derive_target(&before).unwrap(),
        items(s, &[Some(0), Some(0), Some(0), Some(0)])
    );
    assert!(!s.any_unsafe(&items(s, &[Some(0), Some(0), Some(0), Some(0)])));
    assert!(s.validate(&json!({"items": {"SMB1Protocol": 1}})).is_err());
}

#[test]
fn recovery_tools_are_a_plain_fix_that_only_turns_them_back_on() {
    let r = spec("recovery.winre_enabled").unwrap();
    assert_eq!(r.source, Source::RecoveryTools);
    assert!(!r.ask && !r.reboot && !r.dynamic());
    assert_eq!(r.keys.len(), 1);
    assert_eq!((r.keys[0].name, r.keys[0].path), ("Enabled", ""));
    let off = items(r, &[Some(0)]);
    assert!(r.any_unsafe(&off));
    assert_eq!(r.derive_target(&off).unwrap(), items(r, &[Some(1)]));
    assert!(!r.any_unsafe(&items(r, &[Some(1)])));
    assert!(r.any_unsafe(&items(r, &[None])));
    assert!(r.validate(&items(r, &[Some(2)])).is_err());
    assert!(r
        .validate(&json!({"items": {"Enabled": 1, "Other": 0}}))
        .is_err());
    assert!(r.validate(&json!({"items": {}})).is_err());
    let json = r.script_json();
    assert!(json.contains("\"source\":\"RecoveryTools\""), "{json}");
    for never in ["bcdedit", "BitLocker", "manage-bde", "diskpart"] {
        assert!(!json.contains(never), "{never}");
    }
    // Only ReAgentc.exe (two changes) and netsh.exe (one Wi-Fi address) are started, through the one hidden-window launcher.
    let script = include_str!("../platform/hardening.ps1");
    let start = script.find("function HRunReagent(").unwrap();
    let reagent = &script[start..start + script[start..].find("\n}\n").unwrap()];
    assert!(reagent.contains("@('/enable', '/disable') -cnotcontains $verb"));
    let start = script.find("function HRunHidden(").unwrap();
    let body = &script[start..start + script[start..].find("\n}\n").unwrap()];
    for must in [
        "$start.UseShellExecute = $false",
        "$start.CreateNoWindow = $true",
        "$start.RedirectStandardInput = $true",
        "$start.RedirectStandardOutput = $true",
        "$start.RedirectStandardError = $true",
    ] {
        assert!(body.contains(must), "{must}");
    }
    assert!(script.contains("'System32\\ReAgentc.exe'"));
    assert_eq!(script.matches("[Diagnostics.Process]::Start(").count(), 1);
    for script in [script, include_str!("../platform/hardening.handled.ps1")] {
        for never in [
            "bcdedit",
            "manage-bde",
            "diskpart",
            "Start-Process",
            "/boottore",
            "/setreimage",
        ] {
            assert!(
                !script.to_lowercase().contains(&never.to_lowercase()),
                "{never}"
            );
        }
    }
}

#[test]
fn script_json_round_trips_and_is_single_quote_free() {
    for s in all() {
        let v: Value = serde_json::from_str(&s.script_json()).unwrap();
        assert_eq!(v["id"], s.id);
        assert_eq!(v["keys"].as_array().unwrap().len(), s.keys.len());
    }
}

#[test]
fn optional_switches_set_exactly_the_documented_policy_values_and_undo_by_the_journal() {
    for (id, path, names) in [
        (
            "debloat.widgets_policy",
            r"HKLM:\SOFTWARE\Policies\Microsoft\Dsh",
            &["AllowNewsAndInterests"][..],
        ),
        (
            "debloat.device_companion_apps",
            r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata",
            &["PreventDeviceMetadataFromNetwork"][..],
        ),
        (
            "ai.paint",
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint",
            &[
                "DisableCocreator",
                "DisableGenerativeFill",
                "DisableImageCreator",
            ][..],
        ),
        (
            "ai.notepad",
            r"HKLM:\SOFTWARE\Policies\WindowsNotepad",
            &["DisableAIFeatures"][..],
        ),
        (
            "ai.click_to_do",
            r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
            &["DisableClickToDo"][..],
        ),
    ] {
        let s = spec(id).unwrap();
        assert!(s.ask && !s.reboot && !s.dynamic(), "{id}");
        assert_eq!(s.source, Source::Registry, "{id}");
        assert_eq!(
            s.keys.iter().map(|k| k.name).collect::<Vec<_>>(),
            names,
            "{id}"
        );
        assert!(s.keys.iter().all(|k| k.path == path), "{id}");
        let off = if id == "debloat.widgets_policy" { 0 } else { 1 };
        let on = 1 - off;
        for k in s.keys {
            let Rule::Set {
                safe,
                absent_safe,
                fix,
            } = k.rule
            else {
                unreachable!()
            };
            assert_eq!(
                (safe, absent_safe, fix),
                (&[off][..], false, Some(off)),
                "{id}"
            );
        }
        let untouched = vec![None; names.len()];
        assert!(
            s.any_unsafe(&items(s, &untouched)),
            "{id}: absent means still on"
        );
        assert!(
            s.any_unsafe(&items(s, &vec![Some(on); names.len()])),
            "{id}"
        );
        assert!(
            !s.any_unsafe(&items(s, &vec![Some(off); names.len()])),
            "{id}"
        );
        assert_eq!(
            s.derive_target(&items(s, &untouched)).unwrap(),
            items(s, &vec![Some(off); names.len()]),
            "{id}"
        );
        assert!(
            s.validate(&items(s, &vec![Some(2); names.len()])).is_err(),
            "{id}"
        );
        assert_eq!(s.gate.own_policy_key, path, "{id}");
    }
}

#[test]
fn paint_turns_off_only_the_three_documented_tools_one_at_a_time() {
    let s = spec("ai.paint").unwrap();
    let partly = items(s, &[Some(1), None, Some(1)]);
    assert!(s.any_unsafe(&partly));
    assert_eq!(
        s.derive_target(&partly).unwrap(),
        items(s, &[Some(1), Some(1), Some(1)])
    );
}

#[test]
fn click_to_do_and_recall_share_one_policy_key_without_blocking_each_other() {
    let recall = spec("privacy.recall").unwrap();
    let click = spec("ai.click_to_do").unwrap();
    assert_eq!(recall.gate.own_policy_key, click.gate.own_policy_key);
    assert_eq!(recall.gate.areas, click.gate.areas);
    assert!(recall.gate.shared_values.contains(&"DisableClickToDo"));
    assert!(click.gate.shared_values.contains(&"DisableAIDataAnalysis"));
    for s in all() {
        for shared in s.gate.shared_values {
            assert!(!s.keys.iter().any(|k| k.name == *shared), "{}", s.id);
            assert!(!s.gate.own_policy_key.is_empty(), "{}", s.id);
        }
    }
    let gate = serde_json::from_str::<Value>(&click.script_json()).unwrap()["gate"].clone();
    assert_eq!(gate["sharedValues"], json!(["DisableAIDataAnalysis"]));
}

#[test]
fn privacy_extras_set_only_their_documented_policy_values() {
    const SYSTEM: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";
    for (id, path, name, off, reboot, area, pattern) in [
        (
            "privacy.online_speech",
            r"HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization",
            "AllowInputPersonalization",
            0,
            false,
            "Privacy",
            "^AllowInputPersonalization",
        ),
        (
            "privacy.typing_inking",
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput",
            "AllowLinguisticDataCollection",
            0,
            false,
            "TextInput",
            "^AllowLinguisticDataCollection",
        ),
        (
            "privacy.lock_screen_notifications",
            SYSTEM,
            "DisableLockScreenAppNotifications",
            1,
            false,
            "WindowsLogon",
            "^DisableLockScreenAppNotifications",
        ),
        (
            "privacy.signin_email",
            SYSTEM,
            "BlockUserFromShowingAccountDetailsOnSignin",
            1,
            false,
            "ADMX_Logon",
            "^BlockUserFromShowingAccountDetailsOnSignin",
        ),
    ] {
        let s = spec(id).unwrap();
        assert!(s.ask && !s.dynamic(), "{id}");
        assert_eq!(s.reboot, reboot, "{id}");
        assert_eq!(s.source, Source::Registry, "{id}");
        assert_eq!(s.keys.len(), 1, "{id}");
        let k = &s.keys[0];
        assert_eq!((k.name, k.path, k.value), (name, path, ""), "{id}");
        let Rule::Set {
            safe,
            absent_safe,
            fix,
        } = k.rule
        else {
            unreachable!()
        };
        assert_eq!(
            (safe, absent_safe, fix),
            (&[off][..], false, Some(off)),
            "{id}"
        );
        assert_eq!(s.gate.areas, [area], "{id}");
        assert_eq!(s.gate.pattern, pattern, "{id}");
        // These keys hold unrelated policies, so none is this control's own key.
        assert_eq!(s.gate.own_policy_key, "", "{id}");
        assert!(
            s.any_unsafe(&items(s, &[None])),
            "{id}: absent means still on"
        );
        assert!(s.any_unsafe(&items(s, &[Some(1 - off)])), "{id}");
        assert!(!s.any_unsafe(&items(s, &[Some(off)])), "{id}");
        assert_eq!(
            s.derive_target(&items(s, &[None])).unwrap(),
            items(s, &[Some(off)]),
            "{id}"
        );
        assert!(s.validate(&items(s, &[Some(2)])).is_err(), "{id}");
    }
}

#[test]
fn random_wifi_address_is_a_per_adapter_choice_that_undoes_each_adapter() {
    let w = spec("privacy.wifi_random_address").unwrap();
    assert_eq!(w.source, Source::WifiRandomAddress);
    assert!(w.ask && w.dynamic() && !w.reboot);
    let a = "{11111111-1111-1111-1111-111111111111}";
    let b = "{abcdefAB-2222-2222-2222-222222222222}";
    w.validate(&json!({"items": {a: 0, b: 1}})).unwrap();
    for bad in [
        json!({"items": {"Wi-Fi": 0}}),
        json!({"items": {"{1111}": 0}}),
        json!({"items": {"{1111111g-1111-1111-1111-111111111111}": 0}}),
        json!({"items": {"{11111111-1111-1111-1111-111111111111}\"; x": 0}}),
        json!({"items": {a: 2}}),
    ] {
        assert!(w.validate(&bad).is_err(), "accepted {bad}");
    }
    assert!(w.any_unsafe(&json!({"items": {a: 0, b: 1}})));
    assert!(!w.any_unsafe(&json!({"items": {a: 1, b: 1}})));
    assert_eq!(
        w.derive_target(&json!({"items": {a: 0, b: 1}})).unwrap(),
        json!({"items": {a: 1, b: 1}})
    );
    assert_eq!(
        w.view(&json!({"items": {a: 1, b: 0}}), &json!({"items": {a: 1}})),
        json!({"items": {a: 1}})
    );

    let script = include_str!("../platform/hardening.ps1");
    let start = script.find("function HWifiAdapters(").unwrap();
    let find = &script[start..start + script[start..].find("\n}\n").unwrap()];
    assert!(find.contains("MSFT_NetAdapter") && find.contains("-ne 9"));
    assert!(script.contains(r"SOFTWARE\Microsoft\WlanSvc\Interfaces\"));
    assert!(script.contains("'RandomMacState'"));
    let start = script.find("function HSetWifiRandom(").unwrap();
    let set = &script[start..start + script[start..].find("\n}\n").unwrap()];
    for must in [
        "!(HNameOk $name) -or $null -eq $v -or @(0,1) -notcontains [int]$v",
        "'wlan set randomization enabled='",
        "'System32\\netsh.exe'",
    ] {
        assert!(
            set.contains(must) || script.contains(must),
            "{must} is missing"
        );
    }
    assert_eq!(script.matches("[Diagnostics.Process]::Start(").count(), 1);
    assert_eq!(script.matches("HRunHidden $exe").count(), 2);
    assert!(!script.to_lowercase().contains("show randomization"));
    assert!(!script.contains("Start-Process"));
}

#[test]
fn the_home_edition_rule_names_every_machine_policy_privacy_switch() {
    let script = include_str!("../platform/hardening.ps1");
    let start = script.find("function HPreflight()").unwrap();
    let line = script[start..]
        .lines()
        .find(|l| l.contains("$_ -in @(") && l.contains("'privacy.clipboard_sync'"))
        .expect("the Windows Home case");
    for id in [
        "privacy.clipboard_sync",
        "privacy.online_speech",
        "privacy.typing_inking",
        "privacy.lock_screen_notifications",
        "privacy.signin_email",
    ] {
        assert!(spec(id).is_some(), "{id}");
        assert!(
            line.contains(&format!("'{id}'")),
            "{id} is not refused on Windows Home"
        );
    }
}

const TEXT_KEYS: &[Key] = &[
    Key {
        name: "Mode",
        path: r"HKLM:\SOFTWARE\Policies\Example",
        value: "",
        rule: Rule::Text {
            safe: &["off"],
            absent_safe: false,
            fix: Some("off"),
        },
        max: 64,
        allowed: &[],
    },
    Key {
        name: "Lookups",
        path: r"HKLM:\SOFTWARE\Policies\Example",
        value: "",
        rule: Rule::Text {
            safe: &["a", "b"],
            absent_safe: true,
            fix: None,
        },
        max: 64,
        allowed: &[],
    },
    Key {
        name: "Count",
        path: r"HKLM:\SOFTWARE\Policies\Example",
        value: "",
        rule: Rule::Set {
            safe: &[1],
            absent_safe: false,
            fix: Some(1),
        },
        max: 1,
        allowed: &[],
    },
];

const TEXT_SPEC: Spec = Spec {
    id: "example.text",
    title: "Example",
    description: "Example",
    source: Source::Registry,
    reboot: false,
    ask: true,
    keys: TEXT_KEYS,
    gate: Gate {
        areas: &[],
        pattern: ".",
        tamper_exempt: false,
        secedit: false,
        own_policy_key: "",
        shared_values: &[],
        policy_values: &[],
    },
};

fn text_state(mode: Value, lookups: Value, count: Value) -> Value {
    json!({"items": {"Mode": mode, "Lookups": lookups, "Count": count}})
}

#[test]
fn a_text_value_is_safe_only_when_it_matches_exactly() {
    let rule = TEXT_KEYS[0].rule;
    assert!(item_is_safe(rule, &Item::Text("off".into())));
    for bad in ["OFF", "Off", "off ", " off", "", "automatic", "secure"] {
        assert!(!item_is_safe(rule, &Item::Text(bad.into())), "{bad:?}");
    }
    assert!(!item_is_safe(rule, &Item::Absent));
    assert!(!item_is_safe(rule, &Item::Num(0)));
    assert!(!item_is_safe(rule, &Item::Num(1)));
    let optional = TEXT_KEYS[1].rule;
    assert!(item_is_safe(optional, &Item::Absent));
    assert!(item_is_safe(optional, &Item::Text("b".into())));
    assert!(!item_is_safe(optional, &Item::Text("c".into())));
    assert!(!item_is_safe(TEXT_KEYS[2].rule, &Item::Text("1".into())));
}

#[test]
fn a_text_repair_writes_the_fixed_text_or_removes_the_value() {
    let rule = TEXT_KEYS[0].rule;
    assert_eq!(
        item_fix(rule, &Item::Text("automatic".into())),
        Item::Text("off".into())
    );
    assert_eq!(item_fix(rule, &Item::Absent), Item::Text("off".into()));
    assert_eq!(
        item_fix(rule, &Item::Text("off".into())),
        Item::Text("off".into())
    );
    let removable = TEXT_KEYS[1].rule;
    assert_eq!(item_fix(removable, &Item::Text("c".into())), Item::Absent);
    assert_eq!(
        item_fix(removable, &Item::Text("a".into())),
        Item::Text("a".into())
    );
    assert_eq!(item_fix(removable, &Item::Absent), Item::Absent);
}

#[test]
fn a_state_with_text_values_derives_a_target_and_keeps_the_original_exact() {
    let s = &TEXT_SPEC;
    let before = text_state(json!("automatic"), json!("c"), json!(0));
    s.validate(&before).unwrap();
    assert!(s.any_unsafe(&before));
    let target = s.derive_target(&before).unwrap();
    assert_eq!(target, text_state(json!("off"), Value::Null, json!(1)));
    s.validate(&target).unwrap();
    assert!(!s.any_unsafe(&target));
    assert_eq!(
        s.derive_target(&target).unwrap(),
        target,
        "a repaired state is stable"
    );
    for original in [
        "",
        "automatic",
        "https://dns.example/dns-query{?dns}",
        "Gr\u{fc}\u{df}e \u{4e16}\u{754c}",
        "OFF",
    ] {
        let before = text_state(json!(original), json!("a"), json!(1));
        s.validate(&before).unwrap();
        assert_eq!(before["items"]["Mode"], original);
        let target = s.derive_target(&before).unwrap();
        assert!(s.any_unsafe(&before));
        assert_eq!(target["items"]["Mode"], "off");
        assert_eq!(target["items"]["Lookups"], "a");
    }
    assert_eq!(
        s.catalog_target(),
        json!({"items": {"Mode": "off", "Lookups": null, "Count": 1}})
    );
}

#[test]
fn text_states_with_the_wrong_kind_of_value_are_rejected() {
    let s = &TEXT_SPEC;
    for bad in [
        text_state(json!(0), json!("a"), json!(1)),
        text_state(json!(1), json!("a"), json!(1)),
        text_state(json!(true), json!("a"), json!(1)),
        text_state(json!(["off"]), json!("a"), json!(1)),
        text_state(json!({"v": "off"}), json!("a"), json!(1)),
        text_state(json!("off"), json!(2), json!(1)),
        text_state(json!("off"), json!("a"), json!("1")),
        text_state(json!("off"), json!("a"), json!("")),
        text_state(json!("o\nff"), json!("a"), json!(1)),
        text_state(json!("o\u{0}ff"), json!("a"), json!(1)),
        text_state(json!("o\u{7f}ff"), json!("a"), json!(1)),
        text_state(json!("x".repeat(65)), json!("a"), json!(1)),
    ] {
        assert!(s.validate(&bad).is_err(), "accepted {bad}");
        assert!(!s.any_unsafe(&bad), "an unreadable state is never offered");
        assert!(s.derive_target(&bad).is_err(), "derived from {bad}");
    }
    s.validate(&text_state(json!("x".repeat(64)), json!("a"), json!(1)))
        .unwrap();
}

#[test]
fn the_script_description_of_a_text_key_carries_the_text_rule() {
    let v: Value = serde_json::from_str(&TEXT_SPEC.script_json()).unwrap();
    let keys = v["keys"].as_array().unwrap();
    assert_eq!(keys[0]["rule"], "text");
    assert_eq!(keys[0]["safe"], json!(["off"]));
    assert_eq!(keys[0]["fix"], "off");
    assert_eq!(keys[0]["absentSafe"], false);
    assert_eq!(keys[0]["max"], 64);
    assert_eq!(keys[1]["safe"], json!(["a", "b"]));
    assert_eq!(keys[1]["fix"], Value::Null);
    assert_eq!(keys[1]["absentSafe"], true);
    assert_eq!(keys[2]["rule"], "set");
    assert_eq!(keys[2]["safe"], json!([1]));
    assert!(!TEXT_SPEC.script_json().contains('\''));
}

const BROWSER_EDGE: &str = r"HKLM:\SOFTWARE\Policies\Microsoft\Edge";
const BROWSER_CHROME: &str = r"HKLM:\SOFTWARE\Policies\Google\Chrome";
const BROWSER_BRAVE: &str = r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave";
const BROWSER_FIREFOX: &str = r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox";

#[test]
fn browser_controls_set_exactly_the_documented_policy_values() {
    let tracking = format!(r"{BROWSER_FIREFOX}\EnableTrackingProtection");
    let doh = format!(r"{BROWSER_FIREFOX}\DNSOverHTTPS");
    type Expected<'a> = (&'a str, &'a str, &'a str, Value);
    let table: Vec<(&str, Vec<Expected>)> = vec![
        (
            "browser.shopping_ai",
            vec![
                (
                    "EdgeShoppingAssistantEnabled",
                    BROWSER_EDGE,
                    "EdgeShoppingAssistantEnabled",
                    json!(0),
                ),
                (
                    "HubsSidebarEnabled",
                    BROWSER_EDGE,
                    "HubsSidebarEnabled",
                    json!(0),
                ),
                (
                    "ShoppingListEnabled",
                    BROWSER_CHROME,
                    "ShoppingListEnabled",
                    json!(0),
                ),
                ("GeminiSettings", BROWSER_CHROME, "GeminiSettings", json!(1)),
            ],
        ),
        (
            "browser.data_collection",
            vec![
                ("DiagnosticData", BROWSER_EDGE, "DiagnosticData", json!(0)),
                (
                    "PersonalizationReportingEnabled",
                    BROWSER_EDGE,
                    "PersonalizationReportingEnabled",
                    json!(0),
                ),
                (
                    "MetricsReportingEnabled",
                    BROWSER_CHROME,
                    "MetricsReportingEnabled",
                    json!(0),
                ),
                (
                    "UrlKeyedAnonymizedDataCollectionEnabled",
                    BROWSER_CHROME,
                    "UrlKeyedAnonymizedDataCollectionEnabled",
                    json!(0),
                ),
                (
                    "PrivacySandboxAdTopicsEnabled",
                    BROWSER_CHROME,
                    "PrivacySandboxAdTopicsEnabled",
                    json!(0),
                ),
                (
                    "PrivacySandboxSiteEnabledAdsEnabled",
                    BROWSER_CHROME,
                    "PrivacySandboxSiteEnabledAdsEnabled",
                    json!(0),
                ),
                (
                    "PrivacySandboxAdMeasurementEnabled",
                    BROWSER_CHROME,
                    "PrivacySandboxAdMeasurementEnabled",
                    json!(0),
                ),
                (
                    "PrivacySandboxPromptEnabled",
                    BROWSER_CHROME,
                    "PrivacySandboxPromptEnabled",
                    json!(0),
                ),
                (
                    "DisableTelemetry",
                    BROWSER_FIREFOX,
                    "DisableTelemetry",
                    json!(1),
                ),
                (
                    "DisableFirefoxStudies",
                    BROWSER_FIREFOX,
                    "DisableFirefoxStudies",
                    json!(1),
                ),
            ],
        ),
        (
            "browser.safety_mode",
            vec![
                (
                    "EnhanceSecurityMode",
                    BROWSER_EDGE,
                    "EnhanceSecurityMode",
                    json!(1),
                ),
                (
                    "FirefoxTrackingProtection",
                    tracking.as_str(),
                    "Value",
                    json!(1),
                ),
            ],
        ),
        (
            "browser.dns_bypass",
            vec![
                (
                    "EdgeDnsOverHttpsMode",
                    BROWSER_EDGE,
                    "DnsOverHttpsMode",
                    json!("off"),
                ),
                (
                    "ChromeDnsOverHttpsMode",
                    BROWSER_CHROME,
                    "DnsOverHttpsMode",
                    json!("off"),
                ),
                (
                    "BraveDnsOverHttpsMode",
                    BROWSER_BRAVE,
                    "DnsOverHttpsMode",
                    json!("off"),
                ),
                (
                    "FirefoxDnsOverHttpsEnabled",
                    doh.as_str(),
                    "Enabled",
                    json!(0),
                ),
                (
                    "FirefoxDnsOverHttpsLocked",
                    doh.as_str(),
                    "Locked",
                    json!(1),
                ),
            ],
        ),
    ];
    for (id, expected) in table {
        let s = spec(id).unwrap();
        assert!(s.ask && !s.reboot && !s.dynamic(), "{id}");
        assert_eq!(s.source, Source::Registry, "{id}");
        assert_eq!(s.keys.len(), expected.len(), "{id}");
        for (k, (name, path, value, fix)) in s.keys.iter().zip(&expected) {
            assert_eq!(
                (
                    k.name,
                    k.path,
                    if k.value.is_empty() { k.name } else { k.value }
                ),
                (*name, *path, *value),
                "{id}"
            );
            assert_eq!(fixed_value(k), *fix, "{id} {name}");
            assert_eq!(safe_value(k).is_string(), fix.is_string(), "{id} {name}");
            let absent_safe = matches!(
                k.rule,
                Rule::Set {
                    absent_safe: true,
                    ..
                } | Rule::Text {
                    absent_safe: true,
                    ..
                }
            );
            assert!(
                !absent_safe,
                "{id} {name}: not set means the browser's own choice is on"
            );
        }
        let names: std::collections::HashSet<_> = s.keys.iter().map(|k| k.name).collect();
        assert_eq!(names.len(), s.keys.len(), "{id}");
        let nothing_set = items_of(s, &vec![Value::Null; s.keys.len()]);
        assert!(s.any_unsafe(&nothing_set), "{id}");
        let fixed = items_of(s, &expected.iter().map(|e| e.3.clone()).collect::<Vec<_>>());
        assert_eq!(s.derive_target(&nothing_set).unwrap(), fixed, "{id}");
        assert!(!s.any_unsafe(&fixed), "{id}");
        assert_eq!(s.catalog_target(), fixed, "{id}");
        // Never an own-key gate: Edge and Chrome policy keys hold many other values.
        assert_eq!(s.gate.own_policy_key, "", "{id}");
        assert!(s.gate.areas.contains(&"Edge"), "{id}");
        for token in [
            (CHROME_POLICY, "CloudManagementEnrollmentToken"),
            (EDGE_POLICY, "EdgeManagementEnrollmentToken"),
        ] {
            assert!(s.gate.policy_values.contains(&token), "{id}");
        }
        assert!(s
            .keys
            .iter()
            .all(|k| k.path.starts_with(r"HKLM:\SOFTWARE\Policies\")));
    }
}

#[test]
fn browser_lookup_texts_are_off_only_and_other_kinds_are_refused() {
    let s = spec("browser.dns_bypass").unwrap();
    let state = |edge: Value| {
        json!({"items": {
            "EdgeDnsOverHttpsMode": edge, "ChromeDnsOverHttpsMode": "off",
            "BraveDnsOverHttpsMode": "off", "FirefoxDnsOverHttpsEnabled": 0, "FirefoxDnsOverHttpsLocked": 1,
        }})
    };
    assert!(!s.any_unsafe(&state(json!("off"))));
    for unsafe_text in ["automatic", "secure", "Off", "OFF", ""] {
        let before = state(json!(unsafe_text));
        s.validate(&before).unwrap();
        assert!(s.any_unsafe(&before), "{unsafe_text:?}");
        assert_eq!(s.derive_target(&before).unwrap(), state(json!("off")));
    }
    assert!(s.any_unsafe(&state(Value::Null)));
    for wrong in [json!(0), json!(1), json!(true), json!(["off"])] {
        assert!(s.validate(&state(wrong.clone())).is_err(), "{wrong}");
    }
    let bad_firefox = json!({"items": {
        "EdgeDnsOverHttpsMode": "off", "ChromeDnsOverHttpsMode": "off",
        "BraveDnsOverHttpsMode": "off", "FirefoxDnsOverHttpsEnabled": "0", "FirefoxDnsOverHttpsLocked": 1,
    }});
    assert!(s.validate(&bad_firefox).is_err());
    let by_name = |n: &str| s.keys.iter().find(|k| k.name == n).unwrap();
    assert_eq!(by_name("EdgeDnsOverHttpsMode").value, "DnsOverHttpsMode");
    assert_eq!(by_name("ChromeDnsOverHttpsMode").value, "DnsOverHttpsMode");
    assert_eq!(by_name("BraveDnsOverHttpsMode").value, "DnsOverHttpsMode");
    assert_eq!(
        by_name("BraveDnsOverHttpsMode").path,
        r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
    );
    let brave_wrong = json!({"items": {
        "EdgeDnsOverHttpsMode": "off", "ChromeDnsOverHttpsMode": "off",
        "BraveDnsOverHttpsMode": 0, "FirefoxDnsOverHttpsEnabled": 0, "FirefoxDnsOverHttpsLocked": 1,
    }});
    assert!(s.validate(&brave_wrong).is_err());
    assert_ne!(
        by_name("EdgeDnsOverHttpsMode").path,
        by_name("ChromeDnsOverHttpsMode").path
    );
}

#[test]
fn browser_stronger_modes_accept_the_safe_levels_and_flag_the_rest() {
    let s = spec("browser.safety_mode").unwrap();
    let state =
        |edge: u32| json!({"items": {"EnhanceSecurityMode": edge, "FirefoxTrackingProtection": 1}});
    assert!(s.any_unsafe(&state(0)));
    assert!(s.any_unsafe(&state(3)));
    assert!(!s.any_unsafe(&state(1)));
    assert!(!s.any_unsafe(&state(2)));
    assert_eq!(s.derive_target(&state(0)).unwrap(), state(1));
    assert_eq!(s.derive_target(&state(2)).unwrap(), state(2));
    assert!(s.validate(&state(4)).is_err());
    let d = spec("browser.data_collection").unwrap();
    let diag = |n: u32| {
        let mut vals: Vec<Value> = d.keys.iter().map(safe_value).collect();
        vals[0] = json!(n);
        items_of(d, &vals)
    };
    assert!(!d.any_unsafe(&diag(0)));
    assert!(!d.any_unsafe(&diag(1)));
    assert!(d.any_unsafe(&diag(2)));
    assert!(d.validate(&diag(3)).is_err());
}

#[test]
fn notices_follow_the_table() {
    for s in all() {
        let n = notices(s);
        assert_eq!(n.restart, s.reboot, "{}", s.id);
        assert!(n.undoable, "{}", s.id);
    }
    assert!(notices(spec("browser.shopping_ai").unwrap()).managed);
    assert!(notices(spec("browser.dns_bypass").unwrap()).managed);
    assert!(notices(spec("browser.extensions_off").unwrap()).managed);
    assert!(!notices(spec("smartscreen.browser_policy").unwrap()).managed);
    assert!(!notices(spec("smb1.disabled").unwrap()).managed);
}

#[test]
fn only_real_browser_policy_paths_count_as_managed() {
    assert!(is_browser_policy(
        r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS"
    ));
    assert!(is_browser_policy(r"hklm:\software\policies\microsoft\edge"));
    assert!(is_browser_policy(
        r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave"
    ));
    assert!(!is_browser_policy(
        r"HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
    ));
    assert!(!is_browser_policy(
        r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
    ));
    assert!(!is_browser_policy("é"));
}

fn says_restart(text: &str) -> bool {
    let t = text.to_lowercase();
    [
        "needs a restart",
        "needs restart",
        "restart to apply",
        "restart your computer",
        "after a restart",
        "after you restart",
        "you restart",
    ]
    .iter()
    .any(|p| t.contains(p))
}

fn says_managed(text: &str) -> bool {
    text.to_lowercase().contains("managed by your organization")
}

#[test]
fn every_fix_says_before_the_person_agrees_what_the_notices_promise() {
    let mut problems = Vec::new();
    for s in all() {
        let n = notices(s);
        let choice = crate::advice::choice_consequence(s.id);
        let impact = crate::advice::control_impact(s.id);
        let explain = crate::explain::for_check(s.id).unwrap();
        let before_yes = [choice, impact, explain.change];
        if n.managed {
            if ![choice, explain.change]
                .iter()
                .all(|l| says_managed(l) && l.contains("only means a setting was made"))
            {
                problems.push(format!("{}: managed notice missing", s.id));
            }
        } else if before_yes.iter().any(|l| says_managed(l)) {
            problems.push(format!(
                "{}: mentions the managed notice but is not flagged",
                s.id
            ));
        }
        let mentions_restart = before_yes.iter().any(|l| says_restart(l));
        if n.restart && !mentions_restart {
            problems.push(format!("{}: needs a restart but never says so", s.id));
        }
        if !n.restart && mentions_restart {
            problems.push(format!("{}: mentions a restart but is not flagged", s.id));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

#[test]
fn the_run_box_switch_sets_one_machine_wide_value_without_a_restart() {
    let s = spec("clickfix.run_box").unwrap();
    assert!(s.ask && !s.reboot && !s.dynamic());
    assert_eq!(s.source, Source::Registry);
    assert_eq!(s.keys.len(), 1);
    let k = &s.keys[0];
    assert_eq!((k.name, k.path), ("NoRun", EXPLORER));
    assert!(k.path.starts_with("HKLM:"));
    assert!(s.any_unsafe(&items(s, &[None])));
    assert!(s.any_unsafe(&items(s, &[Some(0)])));
    assert!(!s.any_unsafe(&items(s, &[Some(1)])));
    assert_eq!(
        s.derive_target(&items(s, &[None])).unwrap(),
        items(s, &[Some(1)])
    );
    assert!(s.validate(&items(s, &[Some(2)])).is_err());
    assert!(s.gate.own_policy_key.is_empty());
}

const ADDON_A: &str = "chromium:chrome:abcdefghijklmnopabcdefghijklmnop";
const ADDON_B: &str = "chromium:edge:ponmlkjihgfedcbaponmlkjihgfedcba";

#[test]
fn browser_add_ons_are_named_by_browser_and_extension_id() {
    let s = spec("browser.extensions_off").unwrap();
    assert!(s.ask && s.dynamic() && !s.reboot && s.needs_choice() && s.adds_batches());
    assert_eq!(s.source, Source::BrowserExtensions);
    s.validate(&json!({"items": {ADDON_A: 1, ADDON_B: 0}}))
        .unwrap();
    s.validate(&json!({"items": {ADDON_A: 2}})).unwrap();
    for bad in [
        "",
        "chromium:chrome:",
        "chromium:chrome:abcdefghijklmnopabcdefghijklmno",
        "chromium:chrome:abcdefghijklmnopabcdefghijklmnopp",
        "chromium:chrome:abcdefghijklmnopabcdefghijklmnoq",
        "chromium:chrome:ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP",
        "chromium:chrome:abcdefghijklmnopabcdefghijklmno\n",
        "chromium:opera:abcdefghijklmnopabcdefghijklmnop",
        "firefox:abcdefghijklmnopabcdefghijklmnop",
        "chrome:abcdefghijklmnopabcdefghijklmnop",
        " chromium:chrome:abcdefghijklmnopabcdefghijklmnop",
        "*",
    ] {
        assert!(
            s.validate(&json!({"items": {bad: 1}})).is_err(),
            "accepted {bad:?}"
        );
        assert!(!s.item_name_ok(bad), "{bad:?}");
    }
    assert!(s.validate(&json!({"items": {ADDON_A: 3}})).is_err());
    assert!(s.item_name_ok(ADDON_A) && s.item_name_ok(ADDON_B));
    assert!(spec("net.hosts_file").unwrap().item_name_ok("hosts"));
    assert!(!s.item_name_ok("hosts"));
}

#[test]
fn browser_add_on_targets_views_and_picks_only_touch_what_was_named() {
    let s = spec("browser.extensions_off").unwrap();
    let before = json!({"items": {ADDON_A: 1}});
    assert!(s.any_unsafe(&before));
    assert_eq!(
        s.derive_target(&before).unwrap(),
        json!({"items": {ADDON_A: 0}})
    );
    for safe in [0, 2] {
        let state = json!({"items": {ADDON_A: safe}});
        assert!(!s.any_unsafe(&state));
        assert_eq!(s.derive_target(&state).unwrap(), state);
    }
    assert_eq!(
        s.view(&json!({"items": {ADDON_A: 2, ADDON_B: 1}}), &before),
        json!({"items": {ADDON_A: 2}})
    );
    let seen = json!({"items": {ADDON_A: 1, ADDON_B: 1}});
    assert_eq!(
        s.narrow(&seen, &[ADDON_B.to_string()]),
        json!({"items": {ADDON_B: 1}})
    );
    assert_eq!(s.narrow(&seen, &[]), json!({"items": {}}));
    assert!(!s.any_unsafe(&s.narrow(&seen, &[])));
    assert!(s.has_unrecorded_unsafe(&seen, &before));
    assert!(!s.has_unrecorded_unsafe(&json!({"items": {ADDON_A: 1}}), &before));
    assert!(!s.has_unrecorded_unsafe(&json!({"items": {ADDON_A: 0, ADDON_B: 0}}), &before));
    assert!(!s.has_recorded_unsafe(&seen, &json!({"items": {}})));
    assert!(!s.has_recorded_unsafe(&json!({"items": {ADDON_A: 2, ADDON_B: 1}}), &before));
    assert!(s.has_recorded_unsafe(&seen, &before));
    assert!(!spec("persistence.run_and_tasks").unwrap().needs_choice());
}

#[test]
fn browser_add_ons_are_left_alone_where_the_browser_is_managed() {
    let s = spec("browser.extensions_off").unwrap();
    let guarded: Vec<_> = s.gate.policy_values.iter().map(|(_, n)| *n).collect();
    for name in [
        "CloudManagementEnrollmentToken",
        "EdgeManagementEnrollmentToken",
        "ExtensionSettings",
    ] {
        assert!(guarded.contains(&name), "{name}");
    }
    assert!(s
        .gate
        .policy_values
        .iter()
        .all(|(p, _)| p.starts_with(r"HKLM:\SOFTWARE\Policies\")));
    let script = include_str!("../platform/hardening.handled.ps1");
    assert!(script.contains(r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist"));
    assert!(script.contains(r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist"));
}

#[test]
fn folder_protection_controls_set_only_the_documented_modes() {
    let watch = spec("defender.cfa_watch").unwrap();
    let block = spec("defender.cfa_block").unwrap();
    for s in [watch, block] {
        assert_eq!(s.source, Source::DefenderPref);
        assert!(s.ask && !s.reboot && !s.dynamic());
        assert_eq!(s.keys.len(), 1);
        assert_eq!(s.keys[0].name, "EnableControlledFolderAccess");
        assert_eq!(s.keys[0].allowed, &[0, 1, 2, 3, 4]);
        assert!(s.validate(&items(s, &[Some(5)])).is_err());
    }
    let state = |n| items(watch, &[Some(n)]);
    for (mode, watch_unsafe, block_unsafe) in [
        (0, true, true),
        (1, false, false),
        (2, false, true),
        (3, false, false),
        (4, false, true),
    ] {
        assert_eq!(watch.any_unsafe(&state(mode)), watch_unsafe, "watch {mode}");
        assert_eq!(block.any_unsafe(&state(mode)), block_unsafe, "block {mode}");
    }
    assert_eq!(watch.derive_target(&state(0)).unwrap(), state(2));
    assert_eq!(block.derive_target(&state(2)).unwrap(), state(1));
    assert_eq!(block.derive_target(&state(4)).unwrap(), state(1));
    assert_eq!(watch.derive_target(&state(3)).unwrap(), state(3));
    assert!(watch.gate.tamper_exempt && block.gate.tamper_exempt);
    assert!(
        spec("defender.cfa_allowed_apps")
            .unwrap()
            .gate
            .tamper_exempt
    );
}

#[test]
fn allowed_apps_name_one_existing_style_exe_and_never_a_script_tool() {
    let apps = spec("defender.cfa_allowed_apps").unwrap();
    assert!(apps.dynamic() && apps.exact_recorded() && apps.ask);
    apps.validate(&json!({"items": {
        "app:C:\\Tools\\PhotoTool.exe": 0,
        "app:D:\\Games\\Save Helper\\helper.EXE": 1,
        "app:C:\\Program Files (x86)\\Vendor\\app.exe": 1,
        "app:E:\\Ünï\\ápp.exe": 0,
    }}))
    .unwrap();
    for bad in [
        "",
        "app:",
        "C:\\Tools\\a.exe",
        "App:C:\\Tools\\a.exe",
        "app:Tools\\a.exe",
        "app:\\\\server\\share\\a.exe",
        "app:C:a.exe",
        "app:C:\\",
        "app:C:\\a.exe\\",
        "app:C:\\Tools\\a.dll",
        "app:C:\\Tools\\.exe",
        "app:C:\\Tools\\*.exe",
        "app:C:\\Tools\\a?.exe",
        "app:C:\\*\\a.exe",
        "app:C:\\Tools\\..\\a.exe",
        "app:C:\\Tools\\.\\a.exe",
        "app:C:\\Tools\\\\a.exe",
        "app:%ProgramFiles%\\a.exe",
        "app:C:/Tools/a.exe",
        "app:C:\\Tools\\a.exe:stream",
        "app:C:\\Tools\\a\".exe",
        "app:C:\\Tools\\a\n.exe",
        "app: C:\\Tools\\a.exe",
        "app:C:\\Tools\\a.exe ",
        "app:C:\\Tools \\a.exe",
        "app:C:\\Tools\\a|b.exe",
        "app:C:\\Windows\\System32\\cmd.exe",
        "app:C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\POWERSHELL.EXE",
        "app:C:\\Program Files\\PowerShell\\7\\pwsh.exe",
        "app:C:\\Windows\\System32\\wscript.exe",
        "app:C:\\Windows\\System32\\cscript.exe",
        "app:C:\\Windows\\System32\\mshta.exe",
        "app:C:\\Windows\\System32\\rundll32.exe",
    ] {
        assert!(
            apps.validate(&json!({"items": {bad: 0}})).is_err(),
            "accepted {bad:?}"
        );
    }
    assert!(apps
        .validate(&json!({"items": {"app:C:\\Tools\\a.exe": 2}}))
        .is_err());
    let long = format!("app:C:\\{}.exe", "a".repeat(260));
    assert!(apps.validate(&json!({"items": {long: 0}})).is_err());

    let a = "app:C:\\Tools\\a.exe";
    let b = "app:C:\\Tools\\b.exe";
    let before = json!({"items": {a: 0, b: 1}});
    assert!(apps.any_unsafe(&before));
    assert_eq!(
        apps.derive_target(&before).unwrap(),
        json!({"items": {a: 1, b: 1}})
    );
    assert_eq!(
        apps.view(&json!({"items": {b: 1, "app:C:\\new.exe": 0}}), &before),
        json!({"items": {a: 0, b: 1}})
    );
}

#[test]
fn the_script_tool_list_matches_the_powershell_backend() {
    let script = include_str!("../platform/hardening.ps1");
    let start = script.find("function HCfaScriptHosts").unwrap();
    let body = &script[start..start + script[start..].find('\n').unwrap()];
    for host in SCRIPT_HOSTS {
        assert!(body.contains(&format!("'{host}'")), "{host}");
    }
    assert_eq!(body.matches('\'').count(), SCRIPT_HOSTS.len() * 2);
}
