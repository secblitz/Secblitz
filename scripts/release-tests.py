#!/usr/bin/env python3
"""Offline adversarial tests. Uses disposable fixture keys only; never publishes."""
import base64
import copy
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SPEC = importlib.util.spec_from_file_location("release_authorize", Path(__file__).with_name("release-authorize.py"))
authorize = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(authorize)
renew, sign = authorize.renew, authorize.sign


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.from_private_bytes(bytes([51]) * 32)
        self.public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.artifact = b"fixture-only; never execute"
        self.m = dict(schema=1, version="9.0.0", filename="secblitz-9.0.0-windows-x64-setup.exe",
                      target="windows-x86_64", size=len(self.artifact),
                      sha256=hashlib.sha256(self.artifact).hexdigest(), published_at=1000, expires_at=2000)
        self.raw = sign.signed_envelope(self.m, self.key)

    def test_renewal_changes_only_freshness_and_preserves_old_bytes(self):
        new = renew.renewal(self.raw, self.public, self.artifact, self.m["filename"], 1500)
        self.assertEqual({k: v for k, v in new.items() if k not in ("published_at", "expires_at")},
                         {k: v for k, v in self.m.items() if k not in ("published_at", "expires_at")})
        self.assertEqual(new["published_at"], 1500)
        self.assertEqual(new["expires_at"], 1500 + 90 * 86400)
        self.assertEqual(sign.verify_envelope(self.raw, self.public), self.m)

    def test_renewal_rejects_changed_key_artifact_name_and_stale_feed(self):
        for artifact, filename, now, days in [(b"other", self.m["filename"], 1500, 90),
                (self.artifact, "wrong.exe", 1500, 90), (self.artifact, self.m["filename"], 1000, 90),
                (self.artifact, self.m["filename"], 2000, 90), (self.artifact, self.m["filename"], 2600, 90),
                (self.artifact, self.m["filename"], 999, 90), (self.artifact, self.m["filename"], 1500, 91)]:
            with self.assertRaises(ValueError):
                renew.renewal(self.raw, self.public, artifact, filename, now, days)
        other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        with self.assertRaises(InvalidSignature):
            renew.renewal(self.raw, other, self.artifact, self.m["filename"], 1500)
        long = dict(self.m, expires_at=1000 + 90 * 86400)
        with self.assertRaises(ValueError):
            renew.renewal(sign.signed_envelope(long, self.key), self.public, self.artifact, self.m["filename"], 1500, 1)

    def arm64_manifest(self, **changes):
        m = dict(self.m, filename="secblitz-9.0.0-windows-arm64-setup.exe", target="windows-aarch64")
        m.update(changes)
        return m

    def test_each_architecture_signs_only_its_own_target_and_installer_name(self):
        arm = self.arm64_manifest()
        sign.validate_manifest(self.m, 1500, "x64")
        sign.validate_manifest(arm, 1500, "arm64")
        sign.validate_manifest(arm, 1500)
        for manifest, arch in [(self.m, "arm64"), (arm, "x64")]:
            with self.assertRaises(ValueError): sign.validate_manifest(manifest, 1500, arch)
        for change in [dict(filename=self.m["filename"]), dict(target="windows-x86_64"), dict(target="windows-arm64")]:
            with self.assertRaises(ValueError): sign.validate_manifest(self.arm64_manifest(**change), 1500)
        with self.assertRaises(ValueError): sign.validate_manifest(dict(self.m, filename=arm["filename"]), 1500)
        self.assertEqual(sign.ARCHES["x64"]["feed"], "stable.json")
        self.assertEqual(sign.ARCHES["arm64"]["feed"], "stable-arm64.json")

    def package_manifest(self, target, filename, **changes):
        m = dict(self.m, target=target, filename=filename)
        m.update(changes)
        return m

    def test_linux_and_macos_targets_sign_only_their_own_package_names(self):
        cases = [
            ("linux-x64", "linux-x86_64", ["secblitz-9.0.0-linux-x64.deb", "secblitz-9.0.0-linux-x64.rpm"]),
            ("linux-arm64", "linux-aarch64", ["secblitz-9.0.0-linux-arm64.deb", "secblitz-9.0.0-linux-arm64.rpm"]),
            ("macos", "macos-universal", ["secblitz-9.0.0-macos-universal.dmg"]),
        ]
        for arch, target, names in cases:
            for name in names:
                sign.validate_manifest(self.package_manifest(target, name), 1500, arch)
                sign.validate_manifest(self.package_manifest(target, name), 1500)
                raw = sign.signed_envelope(self.package_manifest(target, name), self.key)
                self.assertEqual(sign.verify_envelope(raw, self.public)["target"], target)
            self.assertEqual(sign.setup_names("9.0.0", arch), names)
            for bad in [self.m["filename"], "secblitz-9.0.0-windows-arm64-setup.exe", "../" + names[0],
                        names[0].replace("9.0.0", "9.0.1"), names[0] + ".exe"]:
                with self.assertRaises(ValueError):
                    sign.validate_manifest(self.package_manifest(target, bad), 1500)
        with self.assertRaises(ValueError):
            sign.validate_manifest(self.package_manifest("linux-x86_64", "secblitz-9.0.0-linux-arm64.deb"), 1500)
        with self.assertRaises(ValueError):
            sign.validate_manifest(self.package_manifest("linux-x86_64", "secblitz-9.0.0-linux-x64.dmg"), 1500)
        for arch, target, names in cases:
            for other in sign.TARGETS:
                if other != arch:
                    with self.assertRaises(ValueError):
                        sign.validate_manifest(self.package_manifest(target, names[0]), 1500, other)
        with self.assertRaises(ValueError):
            sign.validate_manifest(self.package_manifest("linux-riscv64", "secblitz-9.0.0-linux-x64.deb"), 1500)

    def test_pages_gate_verifies_a_linux_feed_against_its_package(self):
        import time
        spec = importlib.util.spec_from_file_location("prepare_pages", Path(__file__).with_name("prepare-pages.py"))
        pages = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pages)
        now = int(time.time())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "assets").mkdir()
            (root / "assets/update-public-key.hex").write_text(self.public.hex())
            site = root / "site"
            (site / "releases").mkdir(parents=True)
            (site / "downloads").mkdir()
            name = "secblitz-9.0.0-linux-x64.rpm"
            (site / "downloads" / name).write_bytes(self.artifact)
            m = self.package_manifest("linux-x86_64", name, published_at=now - 10, expires_at=now + 1000)
            (site / "releases/stable-linux-x64-rpm.json").write_bytes(sign.signed_envelope(m, self.key))
            with patch.object(pages, "ROOT", root):
                self.assertEqual(pages.verify_feed(site, "9.0.0", arch="linux-x64", package="rpm")["target"], "linux-x86_64")
                with self.assertRaises(ValueError):
                    pages.verify_feed(site, "9.0.0", site / "releases/stable-linux-x64-rpm.json", arch="linux-arm64", package="rpm")
                with self.assertRaises(ValueError):
                    pages.verify_feed(site, "9.0.0", arch="linux-x64")
                with self.assertRaises(ValueError):
                    pages.verify_feed(site, "9.0.0", site / "releases/stable-linux-x64-rpm.json", arch="linux-x64", package="deb")
                with self.assertRaises(FileNotFoundError):
                    pages.verify_feed(site, "9.0.0", arch="linux-x64", package="deb")
                with self.assertRaises(KeyError):
                    pages.verify_feed(site, "9.0.0", arch="windows")
                bad = self.package_manifest("linux-x86_64", "secblitz-9.0.0-linux-x64-setup.exe",
                                            published_at=now - 10, expires_at=now + 1000)
                (site / "releases/stable-linux-x64-rpm.json").write_bytes(sign.signed_envelope(bad, self.key))
                with self.assertRaises(ValueError):
                    pages.verify_feed(site, "9.0.0", arch="linux-x64", package="rpm")

    def test_linux_signing_needs_a_package_kind_that_matches_the_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "key.pem"
            key.write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
            os.chmod(key, 0o600)
            (root / "public.hex").write_text(self.public.hex())
            for name in ("secblitz-9.0.0-linux-x64.deb", "secblitz-9.0.0-linux-x64.rpm"):
                (root / name).write_bytes(self.artifact)

            def run(name, *extra):
                args = ["sign-release.py", "--key", str(key), "--public-key", str(root / "public.hex"), "--version", "9.0.0",
                        "--installer", str(root / name), "--output", str(root / "out.json"), *extra]
                with patch("sys.argv", args), redirect_stdout(io.StringIO()):
                    sign.main()

            for refused in [("secblitz-9.0.0-linux-x64.deb", "--arch", "linux-x64"),
                            ("secblitz-9.0.0-linux-x64.deb", "--arch", "linux-x64", "--package", "rpm"),
                            ("secblitz-9.0.0-linux-x64.rpm", "--arch", "linux-x64", "--package", "deb")]:
                with self.assertRaises(SystemExit):
                    run(*refused)
                self.assertFalse((root / "out.json").exists())
            run("secblitz-9.0.0-linux-x64.rpm", "--arch", "linux-x64", "--package", "rpm")
            self.assertEqual(sign.verify_envelope((root / "out.json").read_bytes(), self.public)["filename"],
                             "secblitz-9.0.0-linux-x64.rpm")

    def test_the_windows_tables_are_untouched_by_the_new_targets(self):
        self.assertEqual(set(sign.ARCHES), {"x64", "arm64"})
        self.assertEqual(sign.feed_name("linux-x64", "deb"), "stable-linux-x64-deb.json")
        self.assertEqual(sign.feed_name("linux-x64", "rpm"), "stable-linux-x64-rpm.json")
        self.assertEqual(sign.feed_name("linux-arm64", "deb"), "stable-linux-arm64-deb.json")
        self.assertEqual(sign.feed_name("linux-arm64", "rpm"), "stable-linux-arm64-rpm.json")
        for bad in (("linux-x64", None), ("linux-x64", "dmg"), ("macos", "deb"), ("x64", "deb")):
            with self.assertRaises(ValueError):
                sign.feed_name(*bad)
        self.assertEqual(sign.feed_name("x64"), "stable.json")
        self.assertEqual(sign.feed_name("arm64"), "stable-arm64.json")
        self.assertEqual(sign.package_of("secblitz-9.0.0-linux-x64.deb"), "deb")
        self.assertEqual(sign.package_of("secblitz-9.0.0-linux-x64.rpm"), "rpm")
        self.assertIsNone(sign.package_of("secblitz-9.0.0-macos-universal.dmg"))
        self.assertEqual(sign.PACKAGES["macos"]["feed"], "stable-macos.json")
        self.assertTrue(set(sign.ARCHES).isdisjoint(sign.PACKAGES))
        with self.assertRaises(ValueError):
            authorize.validate_authorization(dict(self.policy(), target="linux-riscv64"), "https://example.org/")
        for target in ("linux-x86_64", "linux-aarch64", "macos-universal"):
            authorize.validate_authorization(dict(self.policy(), target=target), "https://example.org/")

    def test_arm64_renewal_and_delivery_keep_the_arm64_target(self):
        arm = self.arm64_manifest()
        raw = sign.signed_envelope(arm, self.key)
        new = renew.renewal(raw, self.public, self.artifact, arm["filename"], 1500, 90, "arm64")
        self.assertEqual((new["target"], new["filename"]), (arm["target"], arm["filename"]))
        with self.assertRaises(ValueError):
            renew.renewal(raw, self.public, self.artifact, arm["filename"], 1500, 90, "x64")
        a = self.policy(raw=raw)
        self.assertEqual(a["target"], "windows-aarch64")
        self.assertEqual(self.policy()["target"], "windows-x86_64")
        with self.assertRaises(ValueError):
            authorize.validate_authorization(dict(a, target="windows-arm64"), a["origin"])

    def test_strict_json_bounded_fields_and_duplicate_rejection(self):
        for raw in [b'{"schema":1,"schema":1}', b'{"schema":1,"schem\\u0061":1}', b'{"x":NaN}']:
            with self.assertRaises(ValueError): sign.strict_json(raw)
        for key, value in [("size", True), ("schema", 1.0), ("size", 2**64), ("unknown", 1),
                ("version", "9.0.0+build"), ("version", "18446744073709551616.0.0"),
                ("expires_at", 1000 + 90 * 86400 + 1), ("filename", "../x.exe")]:
            m = dict(self.m); m[key] = value
            with self.assertRaises(ValueError): sign.validate_manifest(m, 1500)
        with self.assertRaises(ValueError): sign.verify_envelope(b" " * (sign.MANIFEST_LIMIT + 1), self.public)
        env = sign.strict_json(self.raw)
        env["payload"] = base64.b64encode(sign.canonical(self.m) + b" ").decode()
        with self.assertRaises(InvalidSignature): sign.verify_envelope(sign.canonical(env), self.public)

    def test_weak_ed25519_candidates_cannot_be_root_authorized(self):
        identity = b"\x01" + b"\x00" * 31
        raw = sign.canonical(dict(payload=base64.b64encode(sign.canonical(self.m)).decode(),
                                  signature=base64.b64encode(identity + b"\x00" * 32).decode()))
        # This forgery passes cryptography/OpenSSL's unguarded verify API.
        with self.assertRaises(ValueError): sign.verify_envelope(raw, identity)
        with self.assertRaises(ValueError): self.policy(raw=raw, manifest_key=identity.hex())
        a = self.policy()
        for y in [0, 1, 2**255 - 20, 2**255 - 19, 2**255 - 18,
                  int.from_bytes(bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "little"),
                  int.from_bytes(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "little")]:
            for sign_bit in [0, 1 << 255]:
                point = (y | sign_bit).to_bytes(32, "little")
                bad = dict(a, manifest_key=point.hex())
                with self.assertRaises(ValueError): authorize.validate_authorization(bad, a["origin"])
                env = sign.strict_json(self.raw)
                env["signature"] = base64.b64encode(point + b"\x00" * 32).decode()
                with self.assertRaises(ValueError): sign.verify_envelope(sign.canonical(env), self.public)

    def test_origins_cannot_introduce_paths_credentials_redirects_or_queries(self):
        self.assertEqual(renew.checked_origin("https://example.org"), "https://example.org/")
        for origin in ["http://example.org", "https://example.org/path", "https://example.org?",
                "https://example.org#", "https://user@example.org", "https://example.org\\evil",
                "https://example.org/../", "https://example.org:443", "https://EXAMPLE.org", "https://exa\nmple.org"]:
            with self.assertRaises(ValueError): renew.checked_origin(origin)
        with self.assertRaises(ValueError): renew.NoRedirect().redirect_request(None, None, None, None, None, None)

    def policy(self, **changes):
        kw = dict(raw=self.raw, manifest_key=self.public.hex(), origin="https://example.org/",
                  sequence=1, basis_points=5000, salt="ab" * 32, now=1500, lifetime_hours=1)
        kw.update(changes)
        return authorize.prepare(**kw)

    def test_authorization_scope_key_rotation_and_holdback(self):
        a = self.policy()
        self.assertEqual(a["manifest_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(a["health"], "update_health_v1")
        rotated_key = Ed25519PrivateKey.generate()
        pub = rotated_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        rotated_raw = sign.signed_envelope(self.m, rotated_key)
        b = self.policy(raw=rotated_raw, manifest_key=pub, sequence=2, basis_points=0,
                        previous=a, previous_raw=self.raw)
        self.assertEqual(b["rollout"]["basis_points"], 0)
        self.assertNotEqual(b["manifest_key"], a["manifest_key"])
        for change in [dict(sequence=1), dict(salt="cd" * 32), dict(now=1499),
                       dict(previous_raw=self.raw + b" ")]:
            kw = dict(sequence=2, previous=a, previous_raw=self.raw); kw.update(change)
            with self.assertRaises(ValueError): self.policy(**kw)
        for kw in [dict(sequence=0), dict(basis_points=10001), dict(lifetime_hours=169),
                   dict(lifetime_hours=0), dict(now=2000), dict(salt="bad")]:
            with self.assertRaises(ValueError): self.policy(**kw)

    def test_authorization_cannot_mutate_artifact_or_roll_back_metadata(self):
        a = self.policy()
        for change in [dict(sha256="aa" * 32), dict(size=999), dict(published_at=999), dict(expires_at=1999)]:
            m = dict(self.m); m.update(change)
            with self.assertRaises(ValueError):
                self.policy(raw=sign.signed_envelope(m, self.key), sequence=2, previous=a, previous_raw=self.raw)
        for field, value in [("health", "version_only"), ("threshold", 0), ("origin", "https://other.org/")]:
            changed = copy.deepcopy(a); changed[field] = value
            with self.assertRaises(ValueError): authorize.validate_authorization(changed, a["origin"])

    def cli_fixture(self, directory):
        d = Path(directory)
        paths = {"current":d / "stable.json", "installer":d / self.m["filename"],
                 "public":d / "public.hex", "origin":d / "origin.txt", "key":d / "fixture.pem",
                 "output":d / "renewal.json"}
        for name, value in [("current", self.raw), ("installer", self.artifact),
                ("public", self.public.hex().encode()), ("origin", b"https://example.org")]:
            paths[name].write_bytes(value)
        paths["key"].write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        paths["key"].chmod(0o600)
        args = ["release-renew.py", "--current", str(paths["current"]),
                "--current-sha256", hashlib.sha256(self.raw).hexdigest(),
                "--installer", str(paths["installer"]), "--public-key", str(paths["public"]),
                "--origin-file", str(paths["origin"]), "--expected-origin", "https://example.org",
                "--expected-public-key", self.public.hex()]
        return paths, args

    def test_renew_cli_keyless_check_and_explicit_fixture_signing(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, args = self.cli_fixture(directory)
            with patch("sys.argv", args), patch.object(renew, "live_feed", return_value=self.raw), \
                    patch.object(renew.time, "time", return_value=1500), patch.object(sign, "load_key") as load, redirect_stdout(io.StringIO()):
                renew.main()
                load.assert_not_called()
                self.assertFalse(paths["output"].exists())
            args += ["--sign", "--key", str(paths["key"]), "--output", str(paths["output"])]
            with patch("sys.argv", args), patch.object(renew, "live_feed", return_value=self.raw), \
                    patch.object(renew.time, "time", return_value=1500), redirect_stdout(io.StringIO()):
                renew.main()
                out = sign.verify_envelope(paths["output"].read_bytes(), self.public)
                self.assertEqual(out["sha256"], self.m["sha256"])
                self.assertGreater(out["expires_at"], self.m["expires_at"])
                with self.assertRaises(ValueError): renew.main() # Never replace old output.
            self.assertEqual(paths["current"].read_bytes(), self.raw)

    def test_renew_cli_detects_remote_and_local_input_races(self):
        for mode in ["remote-before", "remote-after", "local-artifact", "local-key", "origin", "snapshot"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                paths, args = self.cli_fixture(directory)
                args += ["--sign", "--key", str(paths["key"]), "--output", str(paths["output"])]
                def fetch_second(_origin, _feed):
                    if mode == "local-artifact": paths["installer"].write_bytes(b"changed")
                    if mode == "local-key": paths["public"].write_bytes(b"00" * 32)
                    return self.raw
                if mode == "origin": paths["origin"].write_bytes(b"https://other.example.org")
                if mode == "snapshot": paths["current"].write_bytes(self.raw + b" ")
                feeds = [self.raw + b" ", self.raw] if mode == "remote-before" else [self.raw, self.raw + b" "]
                with patch("sys.argv", args), patch.object(renew.time, "time", return_value=1500), redirect_stdout(io.StringIO()):
                    if mode.startswith("local"):
                        with patch.object(renew, "live_feed", side_effect=fetch_second), self.assertRaises(ValueError): renew.main()
                    else:
                        with patch.object(renew, "live_feed", side_effect=feeds), self.assertRaises(ValueError): renew.main()
                self.assertFalse(paths["output"].exists())

    def test_private_key_and_input_path_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            paths, _ = self.cli_fixture(directory)
            if os.name == "posix":
                paths["key"].chmod(0o644)
                with self.assertRaises(ValueError): sign.load_key(paths["key"], self.public)
                paths["key"].chmod(0o600)
            with self.assertRaises(ValueError): sign.load_key(paths["key"], b"\0" * 32)
            link = Path(directory) / "link"
            os.link(paths["current"], link)
            with self.assertRaises(ValueError): sign.read_input(link, sign.MANIFEST_LIMIT)

    def test_cohort_cross_language_vector(self):
        digest = hashlib.sha256(b"secblitz-rollout-v1\0" + bytes.fromhex("ab" * 32) + bytes([7]) * 16).digest()
        self.assertEqual(int.from_bytes(digest[:8], "big") % 10000, 9219)


ROOT = Path(__file__).resolve().parents[1]
SIGNING_SENTENCE = "Free code signing provided by SignPath.io, certificate by SignPath Foundation"


class PolicyTests(unittest.TestCase):
    def test_release_body_ends_with_the_code_signing_footer(self):
        spec = importlib.util.spec_from_file_location("release_notes", ROOT / "scripts/release-notes.py")
        notes = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(notes)
        with tempfile.TemporaryDirectory() as directory:
            changelog = Path(directory) / "CHANGELOG.md"
            changelog.write_text("# Changelog\n\n## [9.0.0] - 2026-01-02\n\n- A change.\n", encoding="utf-8")
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(notes.main(["9.0.0", "--changelog", str(changelog), "--with-footer"]), 0)
            plain = io.StringIO()
            with redirect_stdout(plain):
                self.assertEqual(notes.main(["9.0.0", "--changelog", str(changelog)]), 0)
        body = out.getvalue()
        self.assertTrue(body.startswith(plain.getvalue()))
        self.assertIn(SIGNING_SENTENCE, body)
        self.assertIn("https://secblitz.lol/code-signing.html", body)
        self.assertIn("https://secblitz.lol/privacy.html", body)
        self.assertNotIn(SIGNING_SENTENCE, plain.getvalue())
        self.assertIn("--with-footer", (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))

    def test_code_signing_texts_agree(self):
        page = (ROOT / "website/code-signing.html").read_text(encoding="utf-8")
        doc = (ROOT / "docs/CODE_SIGNING.md").read_text(encoding="utf-8")
        for text in (page, doc, (ROOT / "README.md").read_text(encoding="utf-8")):
            self.assertIn("Code signing policy", text)
        for text in (page, doc):
            self.assertIn(SIGNING_SENTENCE, text)
            self.assertIn("https://github.com/secblitz", text)
            self.assertIn("https://secblitz.lol/privacy.html", text)
        self.assertNotIn("will not transfer any information", page + doc)
        for text in (page, doc, (ROOT / "docs/release-footer.md").read_text(encoding="utf-8")):
            self.assertNotIn("\u2014", text)

    def test_installer_and_exe_metadata_name_the_product_and_version(self):
        import re
        cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        version = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.M).group(1)
        iss = (ROOT / "installer/setup.iss").read_text(encoding="utf-8")
        setup = dict(re.findall(r"^(VersionInfo\w+)=(.*)$", iss, re.M))
        self.assertEqual(setup["VersionInfoProductName"], "Secblitz")
        for key in ("VersionInfoVersion", "VersionInfoProductVersion", "VersionInfoProductTextVersion", "VersionInfoTextVersion"):
            self.assertEqual(setup[key], "{#AppVersion}", key)
        rc = (ROOT / "assets/secblitz.rc").read_text(encoding="utf-8")
        self.assertIn('VALUE "ProductName", "Secblitz"', rc)
        self.assertIn(f'VALUE "ProductVersion", "{version}"', rc)
        build = (ROOT / "scripts/build-release.ps1").read_text(encoding="utf-8")
        self.assertIn("Assert-ProductMetadata $exe $version", build)
        self.assertIn("Assert-ProductMetadata $setup $version", build)

    def test_inno_download_is_pinned_by_hash(self):
        script = (ROOT / "scripts/install-inno.ps1").read_text(encoding="utf-8")
        self.assertRegex(script, r"\$expectedHash = '[0-9a-f]{64}'")
        self.assertLess(script.index("Get-FileHash"), script.index("Start-Process"))


if __name__ == "__main__":
    unittest.main()
