use super::*;
use ed25519_dalek::{Signer, SigningKey};

pub(super) fn attempt(phase: InstallPhase) -> InstallAttempt {
    InstallAttempt {
        schema: 1,
        version: "9.0.0".into(),
        before: UpdateHealth {
            schema: 1,
            version: "8.0.0".into(),
            task: TaskHealth::Ready,
            monitor: MonitorHealth::Running,
        },
        health: InstallHealth::DeliveryV1,
        phase,
    }
}

#[test]
fn leftover_files_are_only_staged_payloads_and_only_when_resolved() {
    const PROTECTED: [&str; 6] = [
        "release-floor.json",
        "delivery-floor.json",
        "rollout-device-id",
        "update.lock",
        "update-status.json",
        "install-attempt.json",
    ];
    for phase in [InstallPhase::Started, InstallPhase::Exited] {
        let pending = attempt(phase);
        assert!(leftover_files(Some(&pending), true).is_empty());
        assert!(leftover_files(Some(&pending), false).is_empty());
    }
    assert_eq!(
        leftover_files(None, true),
        ["update-installer.exe", "update-manifest.json"]
    );
    assert_eq!(
        leftover_files(None, false),
        [
            "update-installer.exe",
            "update-manifest.json",
            "update-worker.exe"
        ]
    );
    for from_worker in [true, false] {
        for name in leftover_files(None, from_worker) {
            assert!(!PROTECTED.contains(name));
        }
    }
}

#[test]
fn interrupted_installation_never_replays_or_publishes_success() {
    let bytes = serde_json::to_vec(&attempt(InstallPhase::Started)).unwrap();
    let restored = parse_attempt(&bytes).unwrap().unwrap();
    assert!(finish_attempt(
        &restored,
        |_| panic!("unconfirmed exit must not run health"),
        |_| panic!("unconfirmed exit must not publish success"),
        || panic!("unconfirmed exit must not clear intent"),
    )
    .is_err());
}

#[test]
fn other_subsystems_wait_for_health_even_after_installer_zero_exit() {
    for phase in [InstallPhase::Started, InstallPhase::Exited] {
        let bytes = serde_json::to_vec(&attempt(phase)).unwrap();
        assert!(install_idle(&bytes).is_err());
    }
    install_idle(b"null").unwrap();
    for corrupt in [
        b"".as_slice(),
        b"{}",
        b"{",
        b"true",
        b"null null",
        b"{\"phase\":\"idle\"}",
    ] {
        assert!(install_idle(corrupt).is_err());
    }
}

#[test]
fn install_health_and_status_crashes_retain_intent_until_all_checks_succeed() {
    for failure in ["health", "status", "clear", "none"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("install-attempt.json");
        let bytes = serde_json::to_vec(&attempt(InstallPhase::Exited)).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let restored = parse_attempt(&std::fs::read(&path).unwrap())
            .unwrap()
            .unwrap();
        let status = std::cell::RefCell::new(None);
        let finish = |fail: &str| {
            finish_attempt(
                &restored,
                |a| {
                    let mut report = a.before.clone();
                    report.version = a.version.clone();
                    if fail == "health" {
                        report.monitor = MonitorHealth::Stopped;
                    }
                    health::validate(&serde_json::to_vec(&report)?, &a.version, Some(&a.before))?;
                    Ok(())
                },
                |version| {
                    ensure!(fail != "status", "status write failure");
                    let outcome = UpdateOutcome::Installed {
                        version: version.into(),
                    };
                    *status.borrow_mut() = Some(outcome.clone());
                    Ok(outcome)
                },
                || {
                    ensure!(fail != "clear", "intent reset failure");
                    Ok(std::fs::write(&path, b"null")?)
                },
            )
        };
        let result = finish(failure);
        if failure != "none" {
            assert!(result.is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            if failure != "clear" {
                assert!(status.borrow().is_none());
            }
            // A retry of a confirmed exit performs only independent validation
            // and durable publication, never another installation.
            assert_eq!(
                finish("none").unwrap(),
                UpdateOutcome::Installed {
                    version: "9.0.0".into()
                }
            );
        } else {
            assert!(result.is_ok());
        }
        assert!(parse_attempt(&std::fs::read(&path).unwrap())
            .unwrap()
            .is_none());
    }
}

#[test]
fn install_attempt_corruption_never_becomes_idle_or_legacy_health() {
    let value = serde_json::to_value(attempt(InstallPhase::Started)).unwrap();
    for field in ["schema", "version", "before", "health", "phase"] {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(parse_attempt(&serde_json::to_vec(&missing).unwrap()).is_err());
    }
    for (field, bad) in [
        ("schema", serde_json::json!(2)),
        ("version", serde_json::json!("8.0.0")),
        ("version", serde_json::json!("7.0.0")),
        ("phase", serde_json::json!("completed")),
        ("health", serde_json::json!(null)),
        ("health", serde_json::json!("cmd.exe")),
        ("extra", serde_json::json!(true)),
    ] {
        let mut invalid = value.clone();
        invalid[field] = bad;
        assert!(parse_attempt(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    let bytes = serde_json::to_vec(&value).unwrap();
    for cut in 0..bytes.len() {
        assert!(parse_attempt(&bytes[..cut]).is_err());
    }
    assert!(parse_attempt(&vec![b' '; ATTEMPT_LIMIT + 1]).is_err());
}

fn payload() -> serde_json::Value {
    serde_json::json!({"schema":1,"version":"9.0.0","filename":setup_filename("9.0.0"),
        "sha256":hex::encode(Sha256::digest(b"test")),"size":4,"published_at":1000,"expires_at":2000,"target":arch::TARGET})
}
fn signed(raw: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let key = SigningKey::from_bytes(&[42; 32]);
    (serde_json::to_vec(&serde_json::json!({"payload":STANDARD.encode(raw),"signature":STANDARD.encode(key.sign(raw).to_bytes())})).unwrap(),key.verifying_key().to_bytes())
}
#[test]
fn signature_and_raw_bytes_are_binding() {
    let (bytes, key) = signed(&serde_json::to_vec(&payload()).unwrap());
    verify(&bytes, &key, 1500).unwrap();
    assert!(verify(
        &bytes,
        &SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes(),
        1500
    )
    .is_err());
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["payload"] = STANDARD.encode(b"{}").into();
    assert!(verify(&serde_json::to_vec(&v).unwrap(), &key, 1500).is_err());
    v["signature"] = STANDARD.encode([0; 64]).into();
    assert!(verify(&serde_json::to_vec(&v).unwrap(), &key, 1500).is_err());
}
#[test]
fn strict_fields_dates_versions_paths_and_limits() {
    for (field, value) in [
        ("filename", serde_json::json!("../x.exe")),
        ("filename", serde_json::json!("https://evil/x.exe")),
        ("version", serde_json::json!("9.0.0-rc.1")),
        ("size", serde_json::json!(0)),
        ("size", serde_json::json!(INSTALLER_LIMIT + 1)),
        ("expires_at", serde_json::json!(1000 + 91 * 86400)),
        ("extra", serde_json::json!(1)),
    ] {
        let mut p = payload();
        p[field] = value;
        let (b, k) = signed(&serde_json::to_vec(&p).unwrap());
        assert!(verify(&b, &k, 1500).is_err(), "{field}");
    }
    let raw = serde_json::to_string(&payload()).unwrap();
    let (b, k) = signed(raw.replacen('{', "{\"schema\":1,", 1).as_bytes());
    assert!(verify(&b, &k, 1500).is_err());
    let (b, k) = signed(raw.as_bytes());
    assert!(verify(&b, &k, 2601).is_err());
    assert!(verify(&b, &k, 0).is_err());
    let m = verify(&b, &k, 1500).unwrap();
    assert!(newer(&m, "10.0.0").is_err());
    assert!(!newer(&m, "9.0.0").unwrap());
    assert!(newer(&m, "8.0.0").unwrap());
    assert!(installer(&b"test"[..], &m).is_ok());
    for b in [&b"tes"[..], &b"tests"[..], &b"fail"[..]] {
        assert!(installer(b, &m).is_err());
    }
    let duplicate = format!(
        "{{\"payload\":\"\",{}",
        std::str::from_utf8(&b).unwrap().trim_start_matches('{')
    );
    assert!(verify(duplicate.as_bytes(), &k, 1500).is_err());
    assert!(verify(&vec![b' '; MANIFEST_LIMIT + 1], &k, 1500).is_err());
}
#[test]
fn endpoints_are_compile_time_origins_only() {
    assert!(origin("").unwrap().is_none());
    assert!(origin("https://updates.example.org").unwrap().is_some());
    for s in [
        "http://example.org",
        "https://u:p@example.org",
        "https://example.org/a",
        "https://example.org/?x",
        "https://example.org/#x",
        "file:///tmp/x",
    ] {
        assert!(origin(s).is_err(), "{s}");
    }
}

fn verify_value(value: serde_json::Value, time: u64) -> Result<Manifest> {
    let (bytes, key) = signed(&serde_json::to_vec(&value).unwrap());
    verify(&bytes, &key, time)
}

#[test]
fn signature_corruption_is_rejected_with_an_unchanged_valid_payload() {
    let (bytes, key) = signed(&serde_json::to_vec(&payload()).unwrap());
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let signature = STANDARD
        .decode(original["signature"].as_str().unwrap())
        .unwrap();
    for index in 0..signature.len() {
        let mut corrupted = signature.clone();
        corrupted[index] ^= 1;
        let mut envelope = original.clone();
        envelope["signature"] = STANDARD.encode(corrupted).into();
        assert!(
            verify(&serde_json::to_vec(&envelope).unwrap(), &key, 1500).is_err(),
            "byte {index}"
        );
    }
    for length in [0, 1, 63, 65, 1024] {
        let mut envelope = original.clone();
        envelope["signature"] = STANDARD.encode(vec![0; length]).into();
        assert!(verify(&serde_json::to_vec(&envelope).unwrap(), &key, 1500).is_err());
    }
}

#[test]
fn weak_identity_key_and_signature_are_rejected() {
    // Identity A and R with S=0 satisfy the non-strict group equation;
    // strict verification must reject small-order points even for valid JSON.
    let mut key = [0; 32];
    key[0] = 1;
    let mut signature = [0; 64];
    signature[0] = 1;
    let bytes = serde_json::to_vec(&serde_json::json!({
        "payload": STANDARD.encode(serde_json::to_vec(&payload()).unwrap()),
        "signature": STANDARD.encode(signature),
    }))
    .unwrap();
    assert!(verify(&bytes, &key, 1500).is_err());
}

#[test]
fn semantically_identical_json_still_requires_its_own_signature() {
    let raw = serde_json::to_vec(&payload()).unwrap();
    let (bytes, key) = signed(&raw);
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut changed = raw;
    changed.push(b' ');
    envelope["payload"] = STANDARD.encode(&changed).into();
    assert!(verify(&serde_json::to_vec(&envelope).unwrap(), &key, 1500).is_err());
    let (resigned, key) = signed(&changed);
    verify(&resigned, &key, 1500).unwrap();
}

#[test]
fn invalid_base64_and_envelope_shapes_are_rejected() {
    let (bytes, key) = signed(&serde_json::to_vec(&payload()).unwrap());
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for field in ["payload", "signature"] {
        for invalid in [
            serde_json::json!("%%%"),
            serde_json::json!("Zg"),
            serde_json::json!("Zh=="),
            serde_json::json!(null),
            serde_json::json!([]),
        ] {
            let mut envelope = original.clone();
            envelope[field] = invalid;
            assert!(
                verify(&serde_json::to_vec(&envelope).unwrap(), &key, 1500).is_err(),
                "{field}"
            );
        }
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(verify(&serde_json::to_vec(&missing).unwrap(), &key, 1500).is_err());
        let duplicate = format!(
            "{{\"{field}\":{},{}",
            original[field],
            std::str::from_utf8(&bytes).unwrap().trim_start_matches('{')
        );
        assert!(verify(duplicate.as_bytes(), &key, 1500).is_err());
    }
    let mut extra = original;
    extra["extra"] = true.into();
    assert!(verify(&serde_json::to_vec(&extra).unwrap(), &key, 1500).is_err());
    for raw in [&b"\xff"[..], &b"{}{}"[..], &b"[]"[..]] {
        assert!(verify(raw, &key, 1500).is_err());
    }
}

#[test]
fn authentic_but_malformed_payloads_are_rejected() {
    for raw in [
        &b"\xff"[..],
        &b"{"[..],
        &b"{}{}"[..],
        &b"[]"[..],
        &b"null"[..],
    ] {
        let (bytes, key) = signed(raw);
        assert!(verify(&bytes, &key, 1500).is_err());
    }
    let value = payload();
    let raw = serde_json::to_string(&value).unwrap();
    for (field, entry) in value.as_object().unwrap() {
        let duplicate = format!("{{\"{field}\":{entry},{}", raw.trim_start_matches('{'));
        let (bytes, key) = signed(duplicate.as_bytes());
        assert!(verify(&bytes, &key, 1500).is_err(), "duplicate {field}");
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(verify_value(missing, 1500).is_err(), "missing {field}");
    }
    let duplicate = format!(
        "{{\"targ\\u0065t\":\"{}\",{}",
        arch::TARGET,
        raw.trim_start_matches('{')
    );
    let (bytes, key) = signed(duplicate.as_bytes());
    assert!(verify(&bytes, &key, 1500).is_err());
}

#[test]
fn signed_target_path_hash_and_integer_constraints_are_enforced() {
    for (field, value) in [
        ("schema", serde_json::json!(2)),
        ("target", serde_json::json!(arch::OTHER_TARGET)),
        ("target", serde_json::json!(format!("{} ", arch::TARGET))),
        ("filename", serde_json::json!("..\\setup.exe")),
        ("filename", serde_json::json!("C:\\setup.exe")),
        (
            "filename",
            serde_json::json!(format!("{}:payload", setup_filename("9.0.0"))),
        ),
        (
            "filename",
            serde_json::json!(format!("{}\u{0}", setup_filename("9.0.0"))),
        ),
        ("filename", serde_json::json!(setup_filename("8.0.0"))),
        ("sha256", serde_json::json!("a".repeat(63))),
        ("sha256", serde_json::json!("a".repeat(65))),
        ("sha256", serde_json::json!("A".repeat(64))),
        ("sha256", serde_json::json!("g".repeat(64))),
    ] {
        let mut p = payload();
        p[field] = value;
        assert!(verify_value(p, 1500).is_err(), "{field}");
    }
    for field in ["schema", "size", "published_at", "expires_at"] {
        for invalid in [
            serde_json::json!(-1),
            serde_json::json!(1.0),
            serde_json::json!("1"),
            serde_json::json!(true),
        ] {
            let mut p = payload();
            p[field] = invalid;
            assert!(verify_value(p, 1500).is_err(), "{field}");
        }
    }
    let mut p = payload();
    p["size"] = INSTALLER_LIMIT.into();
    verify_value(p, 1500).unwrap();
}

#[test]
fn clock_skew_and_validity_boundaries_are_exact() {
    verify_value(payload(), 400).unwrap(); // Publication exactly 600 seconds ahead.
    assert!(verify_value(payload(), 399).is_err());
    verify_value(payload(), 2600).unwrap(); // Expiration exactly 600 seconds ago.
    assert!(verify_value(payload(), 2601).is_err());
    for expiry in [0, 999, 1000, 1000 + 90 * 86400 + 1] {
        let mut p = payload();
        p["expires_at"] = expiry.into();
        assert!(verify_value(p, 1500).is_err());
    }
    let mut p = payload();
    p["expires_at"] = (1000 + 90 * 86400).into();
    verify_value(p, 1500).unwrap();
    let mut p = payload();
    p["published_at"] = (u64::MAX - 1).into();
    p["expires_at"] = u64::MAX.into();
    verify_value(p.clone(), u64::MAX).unwrap(); // No arithmetic overflow.
    assert!(verify_value(p, 1500).is_err());
}

#[test]
fn expired_feed_is_rejected_even_when_version_matches_current_build() {
    let mut p = payload();
    p["version"] = env!("CARGO_PKG_VERSION").into();
    p["filename"] = setup_filename(env!("CARGO_PKG_VERSION")).into();
    let fresh = verify_value(p.clone(), 1500).unwrap();
    assert!(!newer(&fresh, env!("CARGO_PKG_VERSION")).unwrap());
    assert!(verify_value(p, 2601).is_err());
}

#[test]
fn installed_version_order_and_canonical_versions_are_required() {
    for text in [
        "09.0.0",
        "9.0",
        "v9.0.0",
        "9.0.0+build",
        "9.0.0-rc.1",
        " 9.0.0",
        "9.0.0\n",
    ] {
        assert!(stable(text).is_err(), "{text}");
        let mut p = payload();
        p["version"] = text.into();
        p["filename"] = setup_filename(text).into();
        assert!(verify_value(p, 1500).is_err());
    }
    let m = verify_value(payload(), 1500).unwrap();
    assert!(newer(&m, "8.99.99").unwrap());
    assert!(!newer(&m, "9.0.0").unwrap());
    assert!(newer(&m, "10.0.0").is_err());
    assert!(newer(&m, "8.0.0+build").is_err());
    verify_value(payload(), 1500).unwrap();
    verify_value(payload(), 1500).unwrap();
}

#[test]
fn exact_raw_manifest_and_payload_limits_include_whitespace() {
    let mut raw = serde_json::to_vec(&payload()).unwrap();
    raw.resize(8192, b' ');
    let (bytes, key) = signed(&raw);
    verify(&bytes, &key, 1500).unwrap();
    raw.push(b' ');
    let (oversized, key) = signed(&raw);
    assert!(oversized.len() < MANIFEST_LIMIT);
    assert!(verify(&oversized, &key, 1500).is_err());
    let mut padded = bytes;
    padded.resize(MANIFEST_LIMIT, b' ');
    verify(&padded, &key, 1500).unwrap();
    padded.push(b' ');
    assert!(verify(&padded, &key, 1500).is_err());
}

#[test]
fn installer_reads_only_signed_size_plus_one_and_propagates_io_errors() {
    let m = verify_value(payload(), 1500).unwrap();
    let mut endless = std::io::repeat(b'x');
    struct Counted<'a> {
        inner: &'a mut dyn Read,
        read: usize,
    }
    impl Read for Counted<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.read += n;
            Ok(n)
        }
    }
    let mut counted = Counted {
        inner: &mut endless,
        read: 0,
    };
    assert!(installer(&mut counted, &m).is_err());
    assert_eq!(counted.read, m.size as usize + 1);
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("injected failure"))
        }
    }
    assert!(installer(Broken, &m)
        .unwrap_err()
        .to_string()
        .contains("injected failure"));
}

#[test]
fn noncanonical_scalars_and_small_order_encodings_cannot_forge_releases() {
    let raw = serde_json::to_vec(&payload()).unwrap();
    let (bytes, key) = signed(&raw);
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let signature = STANDARD
        .decode(original["signature"].as_str().unwrap())
        .unwrap();
    let order =
        hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010").unwrap();
    // S + L is the same group scalar but an invalid Ed25519 encoding.
    let mut malleated = signature.clone();
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(malleated[32 + i]) + u16::from(order[i]) + carry;
        malleated[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    let mut envelope = original.clone();
    envelope["signature"] = STANDARD.encode(&malleated).into();
    assert!(verify(&serde_json::to_vec(&envelope).unwrap(), &key, 1500).is_err());
    for scalar in [order, vec![0xff; 32]] {
        malleated[32..].copy_from_slice(&scalar);
        envelope["signature"] = STANDARD.encode(&malleated).into();
        assert!(verify(&serde_json::to_vec(&envelope).unwrap(), &key, 1500).is_err());
    }
    // Order 1, 2, 4 and noncanonical field encodings (p and p+1).
    for encoding in [
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0100000000000000000000000000000000000000000000000000000000000080",
    ] {
        let point: [u8; 32] = hex::decode(encoding).unwrap().try_into().unwrap();
        let mut forged = [0; 64];
        forged[..32].copy_from_slice(&point);
        envelope["signature"] = STANDARD.encode(forged).into();
        let encoded = serde_json::to_vec(&envelope).unwrap();
        assert!(
            verify(&encoded, &point, 1500).is_err(),
            "weak key {encoding}"
        );
        assert!(verify(&encoded, &key, 1500).is_err(), "weak R {encoding}");
        assert!(
            verify(&bytes, &point, 1500).is_err(),
            "wrong key {encoding}"
        );
    }
}

#[test]
fn numeric_overflow_and_encoded_path_inputs_fail_before_download() {
    let raw = serde_json::to_string(&payload()).unwrap();
    for field in ["schema", "size", "published_at", "expires_at"] {
        for number in [
            "18446744073709551616",
            "79228162514264337593543950335",
            "1e1000",
            "-0",
            "01",
            "NaN",
        ] {
            let original = format!("\"{field}\":{}", payload()[field]);
            let changed = raw.replace(&original, &format!("\"{field}\":{number}"));
            assert_ne!(changed, raw);
            let (bytes, key) = signed(changed.as_bytes());
            assert!(verify(&bytes, &key, 1500).is_err(), "{field}: {number}");
        }
    }
    for text in [
        "\\\\server\\share\\setup.exe",
        "\\\\?\\C:\\setup.exe",
        "//evil.example/setup.exe",
        "%2e%2e%2fsetup.exe",
        "%252e%252e%255csetup.exe",
        "9.0.0/../../x",
        "9.0.0?x=1",
        "9.0.0#x",
        "9.0.0:stream",
        "9.0.0\\x",
        "9.0.0\u{2215}x",
        "18446744073709551616.0.0",
        "9.0.0\u{202e}exe",
    ] {
        let mut p = payload();
        p["filename"] = text.into();
        assert!(verify_value(p, 1500).is_err(), "filename {text}");
        let mut p = payload();
        p["version"] = text.into();
        p["filename"] = setup_filename(text).into();
        assert!(verify_value(p, 1500).is_err(), "version {text}");
    }
    let mut p = payload();
    p["schema"] = u64::from(u32::MAX).saturating_add(1).into();
    assert!(verify_value(p, 1500).is_err());
    p = payload();
    p["size"] = u64::MAX.into();
    assert!(verify_value(p, 1500).is_err()); // size + 1 is unreachable with this input.
    assert!(stable("18446744073709551615.18446744073709551615.18446744073709551615").is_ok());
}

#[test]
fn bounded_seeded_mutations_exercise_authentication_and_parser_without_panics() {
    use rand::{rngs::StdRng, Rng, RngExt, SeedableRng};
    let mut rng = StdRng::seed_from_u64(0x5345_4342_4c49_545a);
    let raw = serde_json::to_vec(&payload()).unwrap();
    let (bytes, key) = signed(&raw);
    let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let signature = STANDARD
        .decode(original["signature"].as_str().unwrap())
        .unwrap();
    for case in 0..1024 {
        let mut envelope = original.clone();
        let (field, mut changed) = if case % 2 == 0 {
            ("payload", raw.clone())
        } else {
            ("signature", signature.clone())
        };
        let index = rng.random_range(0..changed.len());
        changed[index] ^= 1 << rng.random_range(0..8);
        envelope[field] = STANDARD.encode(changed).into();
        assert!(
            verify(&serde_json::to_vec(&envelope).unwrap(), &key, 1500).is_err(),
            "mutation {case}"
        );

        let mut garbage = vec![0; rng.random_range(0..=1024)];
        rng.fill_bytes(&mut garbage);
        // A NUL at the start makes these deterministically invalid JSON, rather
        // than assuming every randomly generated string is invalid.
        if let Some(first) = garbage.first_mut() {
            *first = 0;
        }
        assert!(verify(&garbage, &key, 1500).is_err());
        if case < 128 {
            let (signed_garbage, key) = signed(&garbage);
            assert!(verify(&signed_garbage, &key, 1500).is_err());
        }
    }
    for depth in [128, 256, 1024] {
        let nested = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let (bytes, key) = signed(nested.as_bytes());
        assert!(verify(&bytes, &key, 1500).is_err());
    }
    for end in 0..bytes.len() {
        assert!(
            verify(&bytes[..end], &key, 1500).is_err(),
            "truncated at {end}"
        );
    }
}

#[test]
fn seeded_fragmented_installer_streams_require_exact_authenticated_content() {
    use rand::{rngs::StdRng, Rng, RngExt, SeedableRng};
    struct Fragmented<'a> {
        bytes: &'a [u8],
        chunk: usize,
    }
    impl Read for Fragmented<'_> {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = out.len().min(self.chunk).min(self.bytes.len());
            out[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Ok(n)
        }
    }
    let mut rng = StdRng::seed_from_u64(0x424f_554e_4445_4421);
    let mut p = payload();
    p["size"] = 1024.into();
    let mut content = vec![0; 1024];
    rng.fill_bytes(&mut content);
    p["sha256"] = hex::encode(Sha256::digest(&content)).into();
    let m = verify_value(p, 1500).unwrap();
    for case in 0..1024 {
        let chunk = rng.random_range(1..=127);
        assert_eq!(
            installer(
                Fragmented {
                    bytes: &content,
                    chunk
                },
                &m
            )
            .unwrap(),
            content
        );
        let mut changed = content.clone();
        match case % 3 {
            0 => {
                changed[rng.random_range(0..content.len())] ^= 1 << rng.random_range(0..8);
            }
            1 => {
                changed.truncate(rng.random_range(0..content.len()));
            }
            _ => {
                changed.push(rng.random());
            }
        }
        assert!(
            installer(
                Fragmented {
                    bytes: &changed,
                    chunk
                },
                &m
            )
            .is_err(),
            "stream {case}"
        );
    }
}

#[test]
fn signature_authorizes_bytes_not_pe_format_or_installer_behavior() {
    // A signer can authorize non-PE bytes. This is a trust boundary, not an
    // unsigned-input bypass; do not execute any of these fixture payloads.
    for content in [&b"not a PE executable"[..], &b"MZ\0\0truncated"[..]] {
        let mut p = payload();
        p["size"] = content.len().into();
        p["sha256"] = hex::encode(Sha256::digest(content)).into();
        let m = verify_value(p, 1500).unwrap();
        assert_eq!(installer(content, &m).unwrap(), content);
    }
}

#[test]
fn loopback_http_chunking_and_false_lengths_cannot_bypass_body_checks() {
    use std::{io::Write, net::TcpListener, time::Duration};
    // HTTP is intentional for this loopback-only framing test. Production's
    // HTTPS/no-redirect configuration is in windows.rs and is not changed here.
    fn response(wire: Vec<u8>) -> Result<reqwest::blocking::Response, reqwest::Error> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        let request = std::thread::spawn(move || client.get(format!("http://{address}/")).send());
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "loopback accept timeout"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("loopback accept: {e}"),
            }
        };
        // Winsock can inherit the listener's nonblocking mode. Use the bounded
        // blocking reads below consistently on both Windows and Unix.
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut headers = Vec::new();
        for _ in 0..4096 {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            headers.push(byte[0]);
            if headers.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(headers.ends_with(b"\r\n\r\n"));
        socket.write_all(&wire).unwrap();
        drop(socket);
        request.join().unwrap()
    }
    let m = verify_value(payload(), 1500).unwrap();
    let chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
    assert_eq!(
        installer(
            response(format!("{chunked}1\r\nt\r\n3\r\nest\r\n0\r\n\r\n").into_bytes()).unwrap(),
            &m
        )
        .unwrap(),
        b"test"
    );
    for wire in [
        format!("{chunked}5\r\ntests\r\n0\r\n\r\n"),
        format!("{chunked}4\r\ntes"),
        format!("{chunked}4\r\ntest\r\n"), // Missing terminating chunk.
        "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ntes".into(),
        "HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\ntest".into(),
        "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\nConnection: close\r\n\r\ntest"
            .into(),
    ] {
        // Absurd Content-Length can be rejected by HTTP parsing before a body
        // exists; otherwise body I/O/size/hash validation must reject it.
        assert!(response(wire.into_bytes())
            .map_err(anyhow::Error::from)
            .and_then(|body| installer(body, &m))
            .is_err());
    }
    let (bytes, key) = signed(&serde_json::to_vec(&payload()).unwrap());
    let mut padded = bytes;
    padded.resize(MANIFEST_LIMIT + 64, b' ');
    let mut wire = format!("{chunked}{:x}\r\n", padded.len()).into_bytes();
    wire.extend_from_slice(&padded);
    wire.extend_from_slice(b"\r\n0\r\n\r\n");
    let mut body = Vec::new();
    response(wire)
        .unwrap()
        .take((MANIFEST_LIMIT + 1) as u64)
        .read_to_end(&mut body)
        .unwrap();
    assert_eq!(body.len(), MANIFEST_LIMIT + 1);
    assert!(verify(&body, &key, 1500).is_err());
}

#[test]
fn release_floor_survives_restart_and_failed_payload_and_clock_rollback() {
    let older = verify_value(payload(), 1500).unwrap();
    let mut p = payload();
    p["version"] = "10.0.0".into();
    p["filename"] = setup_filename("10.0.0").into();
    let observed = verify_value(p, 1500).unwrap();
    let floor = advance_floor(&observed, "8.0.0", None).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("release-floor.json");
    std::fs::write(&path, serde_json::to_vec(&floor).unwrap()).unwrap();
    assert!(installer(&b"fail"[..], &observed).is_err());
    drop(floor); // Restart: decisions use only reconstructed persisted state.
    let floor = parse_floor(&std::fs::read(path).unwrap()).unwrap();
    assert!(advance_floor(&older, "8.0.0", Some(&floor)).is_err());
    assert!(newer(&older, "10.0.0").is_err()); // Installed 10 is protected.
    assert!(verify_value(payload(), 2601).is_err());
    let revived = verify_value(payload(), 1500).unwrap();
    assert!(advance_floor(&revived, "8.0.0", Some(&floor)).is_err());
    assert!(newer(&older, "10.0.0").is_err()); // Clock cannot lower version floor.
}

#[test]
fn floor_keeps_its_history_when_the_pc_switches_to_the_other_architecture() {
    let m = verify_value(payload(), 1500).unwrap();
    let floor = advance_floor(&m, "9.0.0", None).unwrap();
    let mut other = floor.clone();
    other.target = arch::OTHER_TARGET.into();
    other.sha256 = hex::encode(Sha256::digest(b"other build"));
    let bytes = serde_json::to_vec(&other).unwrap();
    assert_eq!(parse_floor(&bytes).unwrap(), other);
    let switched = advance_floor(&m, "9.0.0", Some(&other)).unwrap();
    assert_eq!(
        (switched.target.as_str(), switched.sha256.as_str()),
        (arch::TARGET, m.sha256.as_str())
    );
    let mut older = payload();
    older["version"] = "8.5.0".into();
    older["filename"] = setup_filename("8.5.0").into();
    let older = verify_value(older, 1500).unwrap();
    assert!(advance_floor(&older, "8.0.0", Some(&other)).is_err());
    other.target = "windows-riscv64".into();
    assert!(parse_floor(&serde_json::to_vec(&other).unwrap()).is_err());
}

#[test]
fn each_build_reads_only_its_own_feed_and_installer() {
    #[cfg(not(target_os = "linux"))]
    assert!(arch::STABLE_FEED.starts_with("releases/stable"));
    assert!(arch::CANDIDATE_FEED.starts_with("releases/candidate"));
    assert!(arch::DELIVERY_FEED.starts_with("releases/delivery"));
    assert!(setup_filename("9.0.0").contains(arch::SETUP_TAG));
    let mut other = payload();
    other["target"] = arch::OTHER_TARGET.into();
    assert!(verify_value(other, 1500).is_err());
    let mut foreign = payload();
    foreign["filename"] = setup_filename("9.0.0")
        .replace(
            arch::SETUP_TAG,
            if arch::SETUP_TAG == "windows-x64" {
                "windows-arm64"
            } else {
                "windows-x64"
            },
        )
        .into();
    assert!(verify_value(foreign, 1500).is_err());
    if cfg!(target_os = "macos") {
        assert_eq!(arch::TARGET, "macos-universal");
        assert_eq!(
            setup_filename("9.0.0"),
            "secblitz-9.0.0-macos-universal.dmg"
        );
    } else if cfg!(target_os = "linux") {
        assert!(arch::TARGET.starts_with("linux-"));
        assert!(setup_filename("9.0.0").ends_with(".deb"));
    } else if cfg!(target_arch = "aarch64") {
        assert_eq!(arch::TARGET, "windows-aarch64");
    } else {
        assert_eq!(arch::TARGET, "windows-x86_64");
        assert_eq!(
            setup_filename("9.0.0"),
            "secblitz-9.0.0-windows-x64-setup.exe"
        );
    }
    #[cfg(all(
        not(any(target_os = "linux", target_os = "macos")),
        target_arch = "aarch64"
    ))]
    assert_eq!(arch::STABLE_FEED, "releases/stable-arm64.json");
    #[cfg(all(
        not(any(target_os = "linux", target_os = "macos")),
        not(target_arch = "aarch64")
    ))]
    assert_eq!(arch::STABLE_FEED, "releases/stable.json");
    #[cfg(target_os = "linux")]
    {
        assert!(arch::STABLE_FEED_DEB.starts_with("releases/stable-linux-"));
        assert!(arch::STABLE_FEED_DEB.ends_with("-deb.json"));
        assert!(arch::STABLE_FEED_RPM.starts_with("releases/stable-linux-"));
        assert!(arch::STABLE_FEED_RPM.ends_with("-rpm.json"));
    }
}

#[test]
fn a_build_refuses_every_other_systems_target() {
    let all = [
        "windows-x86_64",
        "windows-aarch64",
        "linux-x86_64",
        "linux-aarch64",
        "macos-universal",
    ];
    assert!(all.contains(&arch::TARGET));
    for target in all.iter().filter(|t| **t != arch::TARGET) {
        let mut other = payload();
        other["target"] = (*target).into();
        assert!(verify_value(other, 1500).is_err(), "{target}");
    }
    for target in all {
        assert!(known_target(target));
    }
    assert!(!known_target("linux-riscv64"));
    assert!(!known_target("macos-arm64"));
}

#[test]
fn a_build_accepts_only_its_own_package_names() {
    let own = setup_filename("9.0.0");
    assert!(is_setup_filename("9.0.0", &own));
    assert!(!is_setup_filename("9.0.1", &own));
    for foreign in [
        "secblitz-9.0.0-windows-x64-setup.exe",
        "secblitz-9.0.0-windows-arm64-setup.exe",
        "secblitz-9.0.0-linux-x64.deb",
        "secblitz-9.0.0-linux-arm64.rpm",
        "secblitz-9.0.0-macos-universal.dmg",
        "../secblitz-9.0.0-linux-x64.deb",
    ] {
        if foreign != own
            && !arch::SETUP_SUFFIXES
                .iter()
                .any(|s| foreign == format!("secblitz-9.0.0-{}{s}", arch::SETUP_TAG))
        {
            let mut p = payload();
            p["filename"] = foreign.into();
            assert!(verify_value(p, 1500).is_err(), "{foreign}");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_builds_accept_deb_and_rpm_packages_for_their_own_cpu() {
    for suffix in [".deb", ".rpm"] {
        let mut p = payload();
        p["filename"] = format!("secblitz-9.0.0-{}{suffix}", arch::SETUP_TAG).into();
        verify_value(p, 1500).unwrap();
    }
    let mut p = payload();
    p["filename"] = format!("secblitz-9.0.0-{}.dmg", arch::SETUP_TAG).into();
    assert!(verify_value(p, 1500).is_err());
}

#[test]
fn immutable_release_allows_renewal_but_not_hash_or_metadata_rollback() {
    let m = verify_value(payload(), 1500).unwrap();
    let floor = advance_floor(&m, "9.0.0", None).unwrap();
    assert_eq!(advance_floor(&m, "9.0.0", Some(&floor)).unwrap(), floor);
    let mut swapped = payload();
    swapped["sha256"] = hex::encode(Sha256::digest(b"evil")).into();
    let swapped = verify_value(swapped, 1500).unwrap();
    assert!(advance_floor(&swapped, "9.0.0", Some(&floor)).is_err());
    // The old record has expired by this time. Parsing it has no freshness gate.
    let old = parse_floor(&serde_json::to_vec(&floor).unwrap()).unwrap();
    let mut renewed = payload();
    renewed["published_at"] = 3000.into();
    renewed["expires_at"] = 4000.into();
    let renewed = verify_value(renewed, 3500).unwrap();
    let renewed_floor = advance_floor(&renewed, "9.0.0", Some(&old)).unwrap();
    assert!(advance_floor(&m, "9.0.0", Some(&renewed_floor)).is_err());
    for (published, expires) in [(2999, 4500), (3100, 3999)] {
        let mut p = payload();
        p["published_at"] = published.into();
        p["expires_at"] = expires.into();
        assert!(advance_floor(
            &verify_value(p, 3500).unwrap(),
            "9.0.0",
            Some(&renewed_floor)
        )
        .is_err());
    }
    let mut next = payload();
    next["version"] = "10.0.0".into();
    next["filename"] = setup_filename("10.0.0").into();
    let next = verify_value(next, 1500).unwrap();
    assert_eq!(
        advance_floor(&next, "9.0.0", Some(&old)).unwrap().version,
        "10.0.0"
    );
    assert!(advance_floor(&m, "10.0.0", Some(&old)).is_err());
    assert_eq!(
        advance_floor(&next, "10.0.0", Some(&old)).unwrap().version,
        "10.0.0"
    );
}

#[test]
fn release_floor_schema_is_strict_bounded_and_independent_of_wall_clock() {
    let floor = advance_floor(&verify_value(payload(), 1500).unwrap(), "8.0.0", None).unwrap();
    let bytes = serde_json::to_vec(&floor).unwrap();
    assert_eq!(parse_floor(&bytes).unwrap(), floor);
    let value = serde_json::to_value(&floor).unwrap();
    for (key, bad) in [
        ("schema", serde_json::json!(2)),
        ("version", serde_json::json!("09.0.0")),
        ("version", serde_json::json!("9.0.0-rc.1")),
        ("sha256", serde_json::json!("A".repeat(64))),
        ("sha256", serde_json::json!("a".repeat(63))),
        ("target", serde_json::json!("windows-riscv64")),
        ("published_at", serde_json::json!(-1)),
        ("expires_at", serde_json::json!(1000)),
        ("expires_at", serde_json::json!(1000 + 91 * 86400)),
        ("extra", serde_json::json!(true)),
    ] {
        let mut v = value.clone();
        v[key] = bad;
        assert!(
            parse_floor(&serde_json::to_vec(&v).unwrap()).is_err(),
            "{key}"
        );
    }
    for (key, entry) in value.as_object().unwrap() {
        let duplicate = format!(
            "{{\"{key}\":{entry},{}",
            std::str::from_utf8(&bytes).unwrap().trim_start_matches('{')
        );
        assert!(parse_floor(duplicate.as_bytes()).is_err());
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(parse_floor(&serde_json::to_vec(&missing).unwrap()).is_err());
    }
    for end in 0..bytes.len() {
        assert!(parse_floor(&bytes[..end]).is_err());
    }
    let mut padded = bytes;
    padded.resize(FLOOR_LIMIT, b' ');
    parse_floor(&padded).unwrap();
    padded.push(b' ');
    assert!(parse_floor(&padded).is_err());
}

#[test]
#[ignore = "read-only live public 0.4.2 audit; explicit invocation required"]
fn live_public_042_feed_and_installer_match_pinned_trust() -> Result<()> {
    use std::time::{Duration, Instant};
    let origin = origin(include_str!("../../assets/update-origin.txt"))?.unwrap();
    ensure!(
        origin.as_str() == "https://secblitz.lol/",
        "Unexpected audit origin"
    );
    let key: [u8; 32] = hex::decode(include_str!("../../assets/update-public-key.hex").trim())?
        .try_into()
        .unwrap();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .build()?;
    let started = Instant::now();
    let time = now()?;
    let response = client.get(origin.join("releases/stable.json")?).send()?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "Feed HTTP {}",
        response.status()
    );
    let mut raw = Vec::new();
    response
        .take((MANIFEST_LIMIT + 1) as u64)
        .read_to_end(&mut raw)?;
    let m = verify(&raw, &key, time)?;
    ensure!(
        m.version == "0.4.2"
            && m.size == 3_813_017
            && m.sha256 == "28c93869508923b2ea865267025dc6c0d9e92e5d343e5a78f175d32e5b1b83c4",
        "Live release differs from expected audit target"
    );
    ensure!(
        !newer(&m, "0.4.2")? && newer(&m, "0.4.1")?,
        "Unexpected version decision"
    );
    let remaining = Duration::from_secs(120)
        .checked_sub(started.elapsed())
        .context("Audit deadline exceeded")?;
    let response = client
        .get(origin.join(&format!("downloads/{}", m.filename))?)
        .timeout(remaining)
        .send()?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "Installer HTTP {}",
        response.status()
    );
    let mut content = installer(response, &m)?;
    ensure!(content.starts_with(b"MZ"), "Missing DOS header");
    let pe = u32::from_le_bytes(content[0x3c..0x40].try_into().unwrap()) as usize;
    ensure!(
        content.get(pe..pe + 4) == Some(b"PE\0\0"),
        "Missing PE header"
    );
    let optional = pe + 24;
    let magic = u16::from_le_bytes(content[optional..optional + 2].try_into().unwrap());
    let directories = match magic {
        0x10b => optional + 96,
        0x20b => optional + 112,
        _ => anyhow::bail!("Unknown PE optional header"),
    };
    let certificate = directories + 4 * 8;
    ensure!(
        content[certificate..certificate + 8] == [0; 8],
        "Expected Authenticode-unsigned installer"
    );
    content[0] ^= 1;
    ensure!(
        installer(&content[..], &m).is_err(),
        "Local installer bit flip accepted"
    );
    let mut envelope: serde_json::Value = serde_json::from_slice(&raw)?;
    let mut payload = STANDARD.decode(envelope["payload"].as_str().unwrap())?;
    payload[0] ^= 1;
    envelope["payload"] = STANDARD.encode(payload).into();
    ensure!(
        verify(&serde_json::to_vec(&envelope)?, &key, time).is_err(),
        "Local payload bit flip accepted"
    );
    println!("Live audit time={time}; envelope_bytes={}; envelope_sha256={}; manifest={m:?}; PE_magic={magic:#x}; certificate_directory=absent; local bit flips rejected; elapsed={:?}", raw.len(), hex::encode(Sha256::digest(&raw)), started.elapsed());
    Ok(())
}

#[test]
fn corrupt_release_floor_does_not_poison_engine_audit_or_history() {
    use crate::model::{Backend, Control, Finding, Observation};
    struct ReadOnly;
    impl Backend for ReadOnly {
        fn machine_id(&mut self) -> Result<String> {
            Ok("00000000-0000-4000-8000-000000000001".into())
        }
        fn controls(&self) -> Vec<Control> {
            Vec::new()
        }
        fn observe(&mut self, _: &str) -> Result<Observation> {
            unreachable!()
        }
        fn write(&mut self, _: &str, _: &serde_json::Value) -> Result<()> {
            panic!("read-only test")
        }
        fn findings(&mut self) -> Result<Vec<Finding>> {
            Ok(Vec::new())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let updates = dir.path().join("Updates");
    std::fs::create_dir(&updates).unwrap();
    let path = updates.join("release-floor.json");
    std::fs::write(&path, b"{").unwrap();
    assert!(parse_floor(&std::fs::read(&path).unwrap()).is_err());
    let mut engine = crate::engine::Engine::open(dir.path().into(), Box::new(ReadOnly)).unwrap();
    engine.audit().unwrap();
    assert!(engine.history().unwrap().is_empty());
    assert_eq!(std::fs::read(path).unwrap(), b"{");
}
