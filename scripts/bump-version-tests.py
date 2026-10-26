#!/usr/bin/env python3
"""Tests for bump-version.py and release-notes.py on a temporary copy of the repo files."""
import contextlib
import hashlib
import importlib.util
import io
import re
from pathlib import Path
import shutil
import tempfile
import types
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
FILES = ["Cargo.toml", "Cargo.lock", "assets/secblitz.rc", "assets/secblitz.manifest",
         "CHANGELOG.md", "README.md", "website/index.html", "scripts/stage-pages.py"]
EXTRA = ["website/structured.json", "website/releases/stable.json"]


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bump = load("bump-version")
notes = load("release-notes")
finalize = load("finalize-site")
pages = load("prepare-pages")
live = load("verify-live-site")
historical = load("historical-downloads")


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = bump.main(list(args))
    return code, out.getvalue(), err.getvalue()


class BumpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for rel in FILES:
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / rel, self.root / rel)
        self.old = bump.current_version(self.root)
        (self.root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [Unreleased]\n\n### Fixed\n- A test entry.\n\n"
            f"## [{self.old}] - Unreleased\n\n### Added\n- Work in progress.\n\n"
            "## [0.7.0] - 2026-10-05\n\n### Added\n- Seven.\n\n- More seven.\n\n"
            "## [0.6.1] - 2026-10-04\n\n### Changed\n- Six one.\n", encoding="utf-8")
        self.shown = bump.site_version((self.root / "README.md").read_text(encoding="utf-8"))
        (self.root / "website/releases").mkdir(parents=True, exist_ok=True)
        (self.root / "website/structured.json").write_text(
            '{"@type": "SoftwareApplication", "softwareVersion": "%s"}\n' % self.shown, encoding="utf-8")
        shutil.copyfile(REPO / "website/releases/stable.json", self.root / "website/releases/stable.json")

    def tearDown(self):
        self.tmp.cleanup()

    def snapshot(self):
        return {rel: (self.root / rel).read_bytes() for rel in FILES + EXTRA}

    def bump(self, version, *extra):
        return run(version, "--root", str(self.root), "--date", "2030-01-02", *extra)

    def test_bump_updates_every_place(self):
        before = self.snapshot()
        code, out, err = self.bump("9.8.7")
        self.assertEqual(code, 0, err)
        after = self.snapshot()
        cargo = after["Cargo.toml"].decode()
        self.assertIn('version = "9.8.7"', cargo)
        self.assertIn(f'name = "secblitz"\nversion = "9.8.7"', after["Cargo.lock"].decode())
        rc = after["assets/secblitz.rc"].decode()
        self.assertIn("FILEVERSION 9,8,7,0", rc)
        self.assertIn("PRODUCTVERSION 9,8,7,0", rc)
        self.assertIn('VALUE "FileVersion", "9.8.7"', rc)
        self.assertIn('VALUE "ProductVersion", "9.8.7"', rc)
        self.assertIn('assemblyIdentity version="9.8.7.0"', after["assets/secblitz.manifest"].decode())
        self.assertNotIn(self.old, rc)
        for rel in ("Cargo.toml", "Cargo.lock", "assets/secblitz.rc", "assets/secblitz.manifest"):
            a = before[rel].decode().splitlines()
            b = after[rel].decode().splitlines()
            self.assertEqual(len(a), len(b))
            self.assertLessEqual(sum(x != y for x, y in zip(a, b)), 4)
        page = after["website/index.html"].decode()
        self.assertIn("downloads/secblitz-9.8.7-windows-x64-setup.exe", page)
        self.assertNotIn(f"secblitz-{self.shown}-windows", page + after["README.md"].decode())
        self.assertIn('"softwareVersion": "9.8.7"', after["website/structured.json"].decode())
        self.assertEqual(before["website/releases/stable.json"], after["website/releases/stable.json"])
        self.assertEqual(bump.check_site(self.root, "9.8.7"), [])
        self.assertTrue(bump.check_site(self.root, self.shown))

    def test_bump_moves_the_linux_package_links(self):
        before = (self.root / "website/index.html").read_text()
        self.assertEqual(len(re.findall(r"downloads/secblitz-" + re.escape(self.old) + r"-linux-(?:x64|arm64)\.(?:deb|rpm)", before)), 4)
        code, _, err = self.bump("9.9.9")
        self.assertEqual(code, 0, err)
        after = (self.root / "website/index.html").read_text()
        self.assertEqual(len(re.findall(r"downloads/secblitz-9\.9\.9-linux-(?:x64|arm64)\.(?:deb|rpm)", after)), 4)
        self.assertNotIn(f"secblitz-{self.old}-linux", after)
        self.assertEqual(bump.check_site(self.root, "9.9.9"), [])

    def test_changelog_moves_unreleased_into_dated_section(self):
        self.assertEqual(self.bump("9.8.7")[0], 0)
        text = (self.root / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [Unreleased]\n\n## [9.8.7] - 2030-01-02\n\n### Fixed\n- A test entry.\n", text)
        self.assertEqual(text.count("A test entry."), 1)
        self.assertEqual(notes.section(text, "9.8.7"), "### Fixed\n- A test entry.\n")

    def test_dry_run_leaves_tree_untouched(self):
        before = self.snapshot()
        code, out, err = self.bump("9.8.7", "--dry-run", "--site")
        self.assertEqual(code, 0, err)
        self.assertIn("Dry run", out)
        self.assertEqual(before, self.snapshot())
        self.assertEqual([p.name for p in self.root.rglob(".bump-*")], [])

    def test_refuses_same_older_and_malformed_versions(self):
        before = self.snapshot()
        major, minor, patch = (int(x) for x in self.old.split("."))
        path = self.root / "CHANGELOG.md"
        path.write_text(path.read_text().replace(f"## [{self.old}] - Unreleased", f"## [{self.old}] - 2026-10-07"))
        before = self.snapshot()
        for version in [f"{major}.{minor}.{patch}", "0.0.1", f"{major}.{minor}.{max(patch - 1, 0)}",
                        "1.2", "1.2.3.4", "v1.2.3", "01.2.3", "1.2.3-beta", ""]:
            code, out, err = self.bump(version)
            self.assertEqual(code, 1, version)
            self.assertTrue(err.startswith("error:"), version)
        self.assertEqual(before, self.snapshot())

    def test_numeric_comparison_not_text(self):
        major = int(self.old.split(".")[0])
        self.assertEqual(self.bump(f"{major}.99.0")[0], 0)
        path = self.root / "CHANGELOG.md"
        path.write_text(path.read_text().replace("## [Unreleased]\n", "## [Unreleased]\n\n- Another entry.\n", 1))
        self.assertEqual(self.bump(f"{major}.100.0", "--dry-run")[0], 0)
        self.assertEqual(self.bump(f"{major}.98.9", "--dry-run")[0], 1)

    def test_refuses_empty_unreleased_unless_allowed(self):
        path = self.root / "CHANGELOG.md"
        path.write_text(path.read_text().replace("- A test entry.\n", ""))
        before = self.snapshot()
        self.assertEqual(self.bump("9.8.7")[0], 1)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.bump("9.8.7", "--allow-empty")[0], 0)

    def test_refuses_existing_version_section_and_missing_unreleased(self):
        path = self.root / "CHANGELOG.md"
        original = path.read_text()
        path.write_text(original.replace("## [Unreleased]", "## [Soon]", 1))
        self.assertEqual(self.bump("9.8.7")[0], 1)
        path.write_text(original.replace("## [0.7.0] - 2026-10-05", "## [9.8.7] - 2026-10-05"))
        self.assertEqual(self.bump("9.8.7")[0], 1)

    def test_unreleased_current_version_is_only_dated(self):
        path = self.root / "CHANGELOG.md"
        self.assertIn(f"## [{self.old}] - Unreleased", path.read_text())
        code, out, err = self.bump(self.old)
        self.assertEqual(code, 0, err)
        text = path.read_text()
        self.assertIn(f"## [{self.old}] - 2030-01-02", text)
        self.assertNotIn("Unreleased\n\n## [Unreleased]", text)
        self.assertEqual(self.bump(self.old)[0], 1)  # now already dated, so equal is refused
        self.assertIn("Cargo.toml", self.bump("9.9.9", "--dry-run")[1])

    def test_site_option_moves_download_links(self):
        code, out, err = self.bump("9.8.7", "--site")
        self.assertEqual(code, 0, err)
        readme = (self.root / "README.md").read_text()
        page = (self.root / "website/index.html").read_text()
        self.assertIn("downloads/secblitz-9.8.7-windows-x64-setup.exe", readme)
        self.assertIn("downloads/secblitz-9.8.7-windows-x64-setup.exe", page)
        self.assertIn("version-9.8.7-", readme)
        self.assertIn("Version 9.8.7", page)
        self.assertNotIn(f"secblitz-{self.shown}-windows", readme + page)
        self.assertIn('"softwareVersion": "9.8.7"', (self.root / "website/structured.json").read_text())
        self.assertIn('<code id="sha">' + "0" * 64 + "</code>", page)
        stage = (self.root / "scripts/stage-pages.py").read_text()
        self.assertRegex(stage, rf'    "secblitz-{re.escape(self.shown)}-windows-(?:x64|arm64)-setup\.exe",\n\)')
        self.assertNotIn(f'"secblitz-{self.shown}-windows-x64.exe"', stage)
        self.assertEqual(stage.count(f"secblitz-{self.shown}-windows-x64-setup.exe"), 1)

    def test_arm64_downloads_become_history_from_the_first_arm64_release(self):
        text = (self.root / "scripts/stage-pages.py").read_text()
        before = bump.add_historical(text, "0.10.0")
        self.assertNotIn("0.10.0-windows-arm64", before)
        after = bump.add_historical(text, "0.11.0")
        self.assertIn('"secblitz-0.11.0-windows-x64-setup.exe",', after)
        self.assertIn('"secblitz-0.11.0-windows-arm64-setup.exe",', after)
        self.assertEqual(bump.add_historical(after, "0.11.0"), after)

    def test_site_only_changes_just_the_site_files(self):
        if self.shown == self.old:
            for rel in ("README.md", "website/index.html", "website/structured.json"):
                path = self.root / rel
                path.write_text(path.read_text(encoding="utf-8").replace(self.shown, "0.0.1"), encoding="utf-8")
        before = self.snapshot()
        self.assertEqual(self.bump("9.8.7", "--site-only")[0], 1)  # not the Cargo version
        self.assertEqual(before, self.snapshot())
        code, out, err = self.bump(self.old, "--site-only")
        self.assertEqual(code, 0, err)
        after = self.snapshot()
        changed = {rel for rel in FILES + EXTRA if before[rel] != after[rel]}
        self.assertEqual(changed, {"README.md", "website/index.html", "scripts/stage-pages.py", "website/structured.json"})
        self.assertIn(f"downloads/secblitz-{self.old}-windows-x64-setup.exe", after["README.md"].decode())
        self.assertEqual(bump.check_site(self.root, self.old), [])

    def test_site_check_finds_stale_versions_and_missing_pieces(self):
        self.assertEqual(bump.check_site(self.root, self.shown), [])
        self.assertTrue(any("still shows" in p for p in bump.check_site(self.root, "9.8.7")))
        code, out, err = run("9.8.7", "--root", str(self.root), "--check-site")
        self.assertEqual(code, 1)
        self.assertIn("still shows version", err)
        page = self.root / "website/index.html"
        original = page.read_text()
        for broken in (original.replace('<code id="sha">', '<code id="other">'),
                       original + '<script type="application/ld+json">{"softwareVersion": "0.0.1"}</script>'):
            page.write_text(broken)
            self.assertTrue(bump.check_site(self.root, self.shown))
        page.write_text(original)
        (self.root / "website/structured.json").write_text('{"softwareVersion": "0.0.1"}')
        self.assertTrue(any("structured.json" in p for p in bump.check_site(self.root, self.shown)))
        (self.root / "website/structured.json").write_text("{}")
        (self.root / "website/releases/stable.json").write_text('{"softwareVersion": "0.0.1"}')
        self.assertEqual(bump.check_site(self.root, self.shown), [])

    def test_finalize_writes_checksum_and_size_into_the_staged_page(self):
        setup = self.root / f"secblitz-{self.shown}-windows-x64-setup.exe"
        setup.write_bytes(b"MZ" + b"x" * 8_127_998)
        site = self.root / "website"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = finalize.main(["--site", str(site), "--version", self.shown, "--setup", str(setup)])
        self.assertEqual(code, 0, err.getvalue())
        page = (site / "index.html").read_text()
        self.assertIn('<code id="sha">' + hashlib.sha256(setup.read_bytes()).hexdigest() + "</code>", page)
        self.assertIn(f"<p>Version {self.shown} \u00b7 8.1 MB installer</p>", page)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(finalize.main(["--site", str(site), "--version", "9.9.9", "--setup", str(setup)]), 1)
            other = self.root / "setup.exe"
            other.write_bytes(b"MZ")
            self.assertEqual(finalize.main(["--site", str(site), "--version", self.shown, "--setup", str(other)]), 1)
            (site / "index.html").write_text("<p>nothing</p>")
            self.assertEqual(finalize.main(["--site", str(site), "--version", self.shown, "--setup", str(setup)]), 1)

    def test_historical_downloads_are_pinned_and_verified(self):
        real = historical.load_stage()
        manifest = historical.read_manifest()
        self.assertEqual(historical.check(real, manifest), manifest)  # the real list is fully pinned
        with self.assertRaises(historical.HistoryError):
            historical.check(real, {k: v for k, v in manifest.items() if k != real.HISTORICAL[0]})
        names = [f"secblitz-{v}-windows-x64{kind}.exe" for v in ("0.6.1", "0.7.0") for kind in ("-setup", "")]
        stage = types.SimpleNamespace(HISTORICAL=tuple(names), check_content=real.check_content)
        pe = (b"MZ" + b"\0" * 58 + (64).to_bytes(4, "little") + b"PE\0\0" + (0x8664).to_bytes(2, "little")
              + b"\0" * 18 + (0x20b).to_bytes(2, "little") + b"\0" * 100)
        served = {n: pe for n in names}
        pinned = {n: hashlib.sha256(pe).hexdigest() for n in names}
        base = "https://example.test"
        dest = self.root / "dl"
        self.assertEqual(historical.fetch(dest, base, lambda url: served[url.rsplit("/", 1)[1]], stage, pinned), len(names))
        self.assertEqual(sorted(p.name for p in dest.iterdir()), sorted(names))
        served[names[1]] = pe + b"tampered"
        with self.assertRaises(historical.HistoryError):
            historical.fetch(self.root / "dl2", base, lambda url: served[url.rsplit("/", 1)[1]], stage, pinned)
        path = self.root / "pins.sha256"
        historical.record("0.7.0", base, lambda url: pe, stage, path)
        self.assertEqual(len(historical.read_manifest(path)), 2)
        with self.assertRaises(historical.HistoryError):
            historical.record("0.7.0", base, lambda url: pe + b"x", stage, path)
        with self.assertRaises(historical.HistoryError):
            historical.download("http://insecure.test/x")
        partial = self.root / "partial.sha256"
        keep = {n: h for n, h in pinned.items() if not n.startswith("secblitz-0.6.1-")}
        historical.write_manifest(keep, partial)
        self.assertEqual(historical.record_missing(base, lambda url: pe, stage, partial), ["0.6.1"])
        self.assertEqual(historical.record_missing(base, lambda url: self.fail("nothing is missing"), stage, partial), [])
        ref = self.root / "verified"
        ref.mkdir()
        for n in ("secblitz-0.6.1-windows-x64-setup.exe", "secblitz-0.6.1-windows-x64.exe"):
            (ref / n).write_bytes(pe)
        historical.write_manifest(keep, partial)
        with self.assertRaises(historical.HistoryError):
            historical.record_missing(base, lambda url: pe + b"evil", stage, partial, ref)
        self.assertEqual(historical.record_missing(base, lambda url: pe, stage, partial, ref), ["0.6.1"])
        empty = self.root / "empty"
        empty.mkdir()
        historical.write_manifest(keep, partial)
        with self.assertRaises(historical.HistoryError):
            historical.record_missing(base, lambda url: pe, stage, partial, empty)

    def test_publish_workflow_does_not_clash_with_repo_folders(self):
        text = (Path(__file__).resolve().parents[1] / ".github/workflows/publish-website.yml").read_text()
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("mkdir "):
                folder = line.split()[-1]
                self.assertFalse((Path(__file__).resolve().parents[1] / folder).exists(), f"mkdir {folder} clashes with a repo path")

    def test_failed_plan_writes_nothing(self):
        (self.root / "assets/secblitz.rc").write_text("1 VERSIONINFO\n")
        before = self.snapshot()
        self.assertEqual(self.bump("9.8.7")[0], 1)
        self.assertEqual(before, self.snapshot())

    def test_release_notes_need_dated_section_with_entries(self):
        text = (self.root / "CHANGELOG.md").read_text()
        with self.assertRaises(ValueError):
            notes.section(text, self.old)  # still Unreleased
        with self.assertRaises(ValueError):
            notes.section(text, "9.9.9")
        self.assertIn("### Added", notes.section(text, "0.7.0"))
        self.assertNotIn("Six one", notes.section(text, "0.7.0"))



def fake_pe(machine=0x8664, pad=b""):
    """The smallest bytes that pass stage-pages.py's PE header check."""
    return (b"MZ" + b"\0" * 58 + (64).to_bytes(4, "little") + b"PE\0\0" + machine.to_bytes(2, "little")
            + b"\0" * 18 + (0x20b).to_bytes(2, "little") + b"\0" * 100 + pad)


def fake_deb(pad=b""):
    return b"!<arch>\ndebian-binary   " + b"0" * 30 + pad


def fake_rpm(pad=b""):
    return b"\xed\xab\xee\xdb" + b"\0" * 92 + pad


LINUX_PACKAGES = {("linux-x64", "deb"): fake_deb, ("linux-x64", "rpm"): fake_rpm,
                  ("linux-arm64", "deb"): fake_deb, ("linux-arm64", "rpm"): fake_rpm}


def rewind(root, version):
    """Puts a scratch copy back to an older version, so a test can release one below the repository's."""
    old = bump.current_version(root)
    steps = {"Cargo.toml": bump.bump_cargo_toml, "Cargo.lock": bump.bump_cargo_lock,
             "assets/secblitz.rc": bump.bump_rc, "assets/secblitz.manifest": bump.bump_manifest}
    for rel, step in steps.items():
        (root / rel).write_text(step((root / rel).read_text(), old, version))
    for rel in bump.site_text_files(root):
        (root / rel).write_text(bump.bump_site_text((root / rel).read_text(), old, version, rel, required=False))


class AssembleBase(unittest.TestCase):
    """The whole publish path on a scratch copy of the repo with a throwaway signing key."""

    version = "9.9.9"
    linux = True

    def setUp(self):
        import os
        import subprocess
        import sys
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.subprocess, self.sys = subprocess, sys
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.root = base / "repo"
        for folder in ("scripts", "assets", "website"):
            shutil.copytree(REPO / folder, self.root / folder, ignore=shutil.ignore_patterns("__pycache__", "*.mp4", "*.webm"))
        for rel in ("README.md", "Cargo.toml", "Cargo.lock", "CHANGELOG.md"):
            shutil.copyfile(REPO / rel, self.root / rel)
        for rel in ("website/assets/intro-6bb434a9c067.mp4", "website/assets/secblitz-demo.mp4"):
            (self.root / rel).write_bytes(b"\0\0\0\x18ftypmp42")
        for video in (REPO / "website/assets").glob("intro-*.mp4"):
            shutil.copyfile(video, self.root / "website/assets" / video.name)
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        (self.root / "assets/update-public-key.hex").write_text(public.hex() + "\n")
        self.key = base / "keys" / "test.pem"
        self.key.parent.mkdir()
        self.key.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        os.chmod(self.key, 0o600)
        (self.root / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [Unreleased]\n\n### Fixed\n- A test entry.\n\n"
            "## [0.8.0] - 2026-10-05\n\n### Added\n- Eight.\n", encoding="utf-8")
        if bump.parse(self.version) <= bump.parse(bump.current_version(self.root)):
            rewind(self.root, "0.1.0")
        self.old = bump.current_version(self.root)
        if not self.linux:
            page = self.root / "website/index.html"
            page.write_text(re.sub(r'\n        <div class="linux" id="linux">.*?\n        </div>', "", page.read_text(), flags=re.S))
            (self.root / "website/install.sh").unlink()
        code, out, err = run(self.version, "--root", str(self.root), "--date", "2030-01-02")
        self.assertEqual(code, 0, err)
        self.assets = base / "assets"
        self.assets.mkdir()
        self.setup = self.assets / f"secblitz-{self.version}-windows-x64-setup.exe"
        self.setup.write_bytes(fake_pe(0x8664, b"s" * 5000))
        (self.assets / f"secblitz-{self.version}-windows-x64.exe").write_bytes(fake_pe(0x8664, b"p" * 7000))
        self.setup_arm = self.assets / f"secblitz-{self.version}-windows-arm64-setup.exe"
        self.setup_arm.write_bytes(fake_pe(0xAA64, b"a" * 5200))
        (self.assets / f"secblitz-{self.version}-windows-arm64.exe").write_bytes(fake_pe(0xAA64, b"q" * 7000))
        (self.assets / "SHA256SUMS").write_text("unused here\n")
        for arch in ("x64", "arm64"):
            (self.assets / f"secblitz-{self.version}-windows-{arch}.cdx.json").write_text("{}\n")
        self.packages = {}
        if self.linux:
            for (arch, kind), make in LINUX_PACKAGES.items():
                path = self.assets / f"secblitz-{self.version}-{arch}.{kind}"
                path.write_bytes(make(arch.encode() + kind.encode() * 400))
                self.packages[(arch, kind)] = path
        self.sign()
        spec = importlib.util.spec_from_file_location("stage_copy", self.root / "scripts/stage-pages.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.old_downloads = base / "historical"
        self.old_downloads.mkdir()
        for name in module.HISTORICAL:
            (self.old_downloads / name).write_bytes(fake_pe(0x8664, name.encode()))
        self.out = base / "pages"

    def tearDown(self):
        self.tmp.cleanup()

    def sign(self):
        for arch, setup, feed in (("x64", self.setup, "stable.json"), ("arm64", self.setup_arm, "stable-arm64.json")):
            done = self.subprocess.run([self.sys.executable, str(self.root / "scripts/sign-release.py"), "--key", str(self.key),
                                        "--public-key", str(self.root / "assets/update-public-key.hex"),
                                        "--version", self.version, "--installer", str(setup), "--arch", arch,
                                        "--output", str(self.assets / feed)], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)
        for (arch, kind), path in self.packages.items():
            done = self.subprocess.run([self.sys.executable, str(self.root / "scripts/sign-release.py"), "--key", str(self.key),
                                        "--public-key", str(self.root / "assets/update-public-key.hex"),
                                        "--version", self.version, "--installer", str(path), "--arch", arch, "--package", kind,
                                        "--output", str(self.assets / f"stable-{arch}-{kind}.json")], capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stderr)

    def assemble(self):
        return self.subprocess.run([self.sys.executable, str(self.root / "scripts/assemble-site.py"),
                                    "--version", self.version, "--assets", str(self.assets),
                                    "--historical", str(self.old_downloads), "--output", str(self.out)],
                                   capture_output=True, text=True)


class AssembleTests(AssembleBase):
    def test_verify_feed_command_used_by_the_workflow(self):
        command = [self.sys.executable, str(self.root / "scripts/prepare-pages.py"), "--verify-feed",
                   str(self.assets / "stable.json"), "--installer-directory", str(self.assets),
                   "--expected-version", self.version]
        self.assertEqual(self.subprocess.run(command, capture_output=True, text=True).returncode, 0)
        command[-1] = "9.9.8"
        self.assertNotEqual(self.subprocess.run(command, capture_output=True, text=True).returncode, 0)

    def test_verified_release_becomes_a_complete_site(self):
        done = self.assemble()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        page = (self.out / "index.html").read_text()
        digest = hashlib.sha256(self.setup.read_bytes()).hexdigest()
        self.assertIn(f'<code id="sha">{digest}</code>', page)
        arm_digest = hashlib.sha256(self.setup_arm.read_bytes()).hexdigest()
        self.assertIn(f'<code id="sha-arm64">{arm_digest}</code>', page)
        self.assertIn(f"downloads/secblitz-{self.version}-windows-arm64-setup.exe", page)
        self.assertEqual((self.out / "releases/stable-arm64.json").read_bytes(), (self.assets / "stable-arm64.json").read_bytes())
        self.assertIn(f"downloads/secblitz-{self.version}-windows-x64-setup.exe", page)
        self.assertEqual((self.out / "releases/stable.json").read_bytes(), (self.assets / "stable.json").read_bytes())
        names = {p.name for p in (self.out / "downloads").iterdir()}
        self.assertIn(f"secblitz-{self.version}-windows-x64-setup.exe", names)
        self.assertIn(f"secblitz-{self.version}-windows-arm64-setup.exe", names)
        self.assertNotIn(f"secblitz-{self.version}-windows-x64.exe", names)  # too big for Pages; on GitHub only
        self.assertNotIn(f"secblitz-{self.version}-windows-arm64.exe", names)
        self.assertIn(f"secblitz-{self.shown_before()}-windows-x64-setup.exe", names)  # the replaced version stays

    def test_code_signing_page_is_published_and_checked(self):
        done = self.assemble()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("code-signing.html references verified", done.stdout)
        text = (self.out / "code-signing.html").read_text()
        self.assertIn("Free code signing provided by SignPath.io, certificate by SignPath Foundation", text)
        page = self.root / "website/code-signing.html"
        original = page.read_text()
        for broken in (original.replace("certificate by SignPath Foundation", "certificate"),
                       original.replace("https://secblitz.lol/privacy.html", "https://example.test/"),
                       original.replace("</main>", '<a href="http://example.test/">x</a></main>')):
            page.write_text(broken)
            shutil.rmtree(self.out, ignore_errors=True)
            failed = self.assemble()
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("code-signing.html", failed.stderr)
        page.write_text(original)
        shutil.rmtree(self.out, ignore_errors=True)
        self.assertEqual(self.assemble().returncode, 0)

    def test_live_check_compares_bytes_and_fails_loudly(self):
        self.assertEqual(self.assemble().returncode, 0)
        files = live.expected_files(self.out, self.version)
        served = {"https://secblitz.test" + path: local.read_bytes() for path, local in files.items()}
        args = ["--site", str(self.out), "--version", self.version, "--origin", "https://secblitz.test", "--attempts", "3"]
        sleeps = []
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(live.main(args, lambda url: served[url], sleeps.append), 0)
            setup_url = f"https://secblitz.test/downloads/secblitz-{self.version}-windows-x64-setup.exe"
            self.assertIn("/releases/stable-arm64.json", files)
            self.assertIn(f"/downloads/secblitz-{self.version}-windows-arm64-setup.exe", files)
            served[setup_url] = b"old"
            self.assertEqual(live.main(args, lambda url: served[url], sleeps.append), 1)
            self.assertEqual(len(sleeps), 2)
            calls = []
            def flaky(url):
                calls.append(url)
                return b"old" if url.endswith("stable.json") and len(calls) == 1 else files["/releases/stable.json"].read_bytes() if url.endswith("stable.json") else served[url]
            served[setup_url] = files[f"/downloads/secblitz-{self.version}-windows-x64-setup.exe"].read_bytes()
            self.assertEqual(live.main(args, flaky, lambda _: None), 0)
            legacy = {"https://legacy.test" + path: data for path, data in
                      ((p, l.read_bytes()) for p, l in files.items()) if path != "/"}
            served.update(legacy)
            feed_args = args + ["--feed-origin", "https://legacy.test"]
            self.assertEqual(live.main(feed_args, lambda url: served[url], lambda _: None), 0)
            served["https://legacy.test/releases/stable.json"] = b"old"
            self.assertEqual(live.main(feed_args, lambda url: served[url], lambda _: None), 1)
        self.assertIn("DOES NOT MATCH", err.getvalue())
        self.assertIn(setup_url, err.getvalue())
        self.assertIn("first difference at byte 0: deployed b'{", err.getvalue())
        self.assertEqual(live.first_difference(b"<p>a</p>", b"<p>b</p>", 4),
                         "first difference at byte 3: deployed b'>a</p', served b'>b</p'")

    def shown_before(self):
        return bump.site_version((REPO / "README.md").read_text(encoding="utf-8"))

    def test_arm64_feed_is_checked_against_the_arm64_installer(self):
        command = [self.sys.executable, str(self.root / "scripts/prepare-pages.py"), "--verify-feed",
                   str(self.assets / "stable-arm64.json"), "--installer-directory", str(self.assets),
                   "--expected-version", self.version, "--arch", "arm64"]
        self.assertEqual(self.subprocess.run(command, capture_output=True, text=True).returncode, 0)
        command[command.index("--arch") + 1] = "x64"
        self.assertNotEqual(self.subprocess.run(command, capture_output=True, text=True).returncode, 0)

    def test_arm64_feed_for_other_installer_bytes_is_refused(self):
        self.setup_arm.write_bytes(fake_pe(0xAA64, b"changed after signing"))
        self.assertNotEqual(self.assemble().returncode, 0)
        self.assertFalse(self.out.exists())

    def test_missing_arm64_release_file_is_refused(self):
        (self.assets / "stable-arm64.json").unlink()
        self.assertNotEqual(self.assemble().returncode, 0)

    def test_missing_parts_list_is_refused(self):
        (self.assets / f"secblitz-{self.version}-windows-arm64.cdx.json").unlink()
        self.assertNotEqual(self.assemble().returncode, 0)
        self.assertFalse(self.out.exists())

    def test_parts_lists_are_not_published_on_the_site(self):
        self.assertEqual(self.assemble().returncode, 0)
        self.assertEqual(list(self.out.rglob("*.cdx.json")), [])

    def test_feed_for_other_installer_bytes_is_refused(self):
        self.setup.write_bytes(fake_pe(0x8664, b"changed after signing"))
        done = self.assemble()
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.out.exists())

    def test_feed_signed_by_another_key_is_refused(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        (self.root / "assets/update-public-key.hex").write_text(other.hex() + "\n")
        done = self.assemble()
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(self.out.exists())

    def test_wrong_set_of_release_files_is_refused(self):
        (self.assets / "extra.txt").write_text("x")
        self.assertNotEqual(self.assemble().returncode, 0)
        (self.assets / "extra.txt").unlink()
        (self.assets / "stable.json").unlink()
        self.assertNotEqual(self.assemble().returncode, 0)

    def linux_names(self):
        return {key: f"secblitz-{self.version}-{key[0]}.{key[1]}" for key in self.packages}

    def test_linux_packages_feeds_and_the_one_line_installer_are_published(self):
        done = self.assemble()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        names = {p.name for p in (self.out / "downloads").iterdir()}
        for key, name in self.linux_names().items():
            self.assertIn(name, names)
            self.assertEqual((self.out / "downloads" / name).read_bytes(), self.packages[key].read_bytes())
            feed = f"releases/stable-{key[0]}-{key[1]}.json"
            self.assertEqual((self.out / feed).read_bytes(), (self.assets / Path(feed).name).read_bytes())
        script = (self.out / "install.sh").read_text()
        self.assertEqual(re.findall(r"@[A-Z0-9_]+@", script), [])
        self.assertIn(f'SECBLITZ_VERSION="{self.version}"', script)
        for key in self.linux_names():
            variable = f"SHA256_{key[0].removeprefix('linux-').upper()}_{key[1].upper()}"
            self.assertIn(f'{variable}="{hashlib.sha256(self.packages[key].read_bytes()).hexdigest()}"', script)
        page = (self.out / "index.html").read_text()
        for name in self.linux_names().values():
            self.assertIn(f'href="downloads/{name}"', page)
        self.assertIn("curl -fsSL https://secblitz.lol/install.sh | bash", page)
        self.assertEqual(self.subprocess.run(["bash", "-n", str(self.out / "install.sh")]).returncode, 0)

    def test_installer_script_is_served_as_plain_text_with_the_security_headers(self):
        headers = (REPO / "website/_headers").read_text()
        block = re.search(r"^/install\.sh\n((?:  .*\n)+)", headers, re.M)
        self.assertIsNotNone(block)
        self.assertIn("Content-Type: text/plain; charset=utf-8", block[1])
        self.assertNotIn("Content-Disposition", block[1])
        self.assertIn("X-Content-Type-Options: nosniff", headers.split("\n\n")[0])

    def test_linux_package_changed_after_signing_is_refused(self):
        for key in self.packages:
            path = self.packages[key]
            original = path.read_bytes()
            path.write_bytes(original + b"changed after signing")
            done = self.assemble()
            self.assertNotEqual(done.returncode, 0, key)
            self.assertFalse(self.out.exists())
            path.write_bytes(original)

    def test_linux_feed_signed_for_another_package_kind_is_refused(self):
        shutil.copyfile(self.assets / "stable-linux-x64-rpm.json", self.assets / "stable-linux-x64-deb.json")
        self.assertNotEqual(self.assemble().returncode, 0)
        self.assertFalse(self.out.exists())

    def test_missing_linux_file_is_refused(self):
        for name in ("stable-linux-arm64-rpm.json", f"secblitz-{self.version}-linux-x64.deb"):
            (self.assets / name).unlink()
            self.assertNotEqual(self.assemble().returncode, 0)

    def test_linux_package_over_the_pages_limit_is_refused_clearly(self):
        big = self.assets / f"secblitz-{self.version}-linux-x64.rpm"
        big.write_bytes(fake_rpm(b"\0" * (25 * 1024 * 1024)))
        done = self.assemble()
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("Cloudflare Pages cannot host a file over 25 MiB", done.stderr)
        self.assertIn(big.name, done.stderr)

    def test_site_gate_checks_install_script_against_the_packages(self):
        self.assertEqual(self.assemble().returncode, 0)
        command = [self.sys.executable, str(self.root / "scripts/prepare-pages.py"), "--site", str(self.out),
                   "--require-feed", "--expected-version", self.version]
        self.assertEqual(self.subprocess.run(command, capture_output=True, text=True).returncode, 0)
        script = self.out / "install.sh"
        good = script.read_text()
        digest = hashlib.sha256(self.packages[("linux-x64", "deb")].read_bytes()).hexdigest()
        for broken in (good.replace(digest, "0" * 64), good.replace(f'SECBLITZ_VERSION="{self.version}"', 'SECBLITZ_VERSION="9.9.8"'),
                       good + '\nSHA256_X64_DEB="' + digest + '"\n'):
            script.write_text(broken)
            self.assertNotEqual(self.subprocess.run(command, capture_output=True, text=True).returncode, 0)
        script.write_text(good)
        page = self.out / "index.html"
        original = page.read_text()
        page.write_text(original.replace(f'href="downloads/secblitz-{self.version}-linux-arm64.rpm"', 'href="downloads/other.rpm"'))
        self.assertNotEqual(self.subprocess.run(command, capture_output=True, text=True).returncode, 0)

    def test_live_check_covers_install_script_linux_feeds_and_packages(self):
        self.assertEqual(self.assemble().returncode, 0)
        files = live.expected_files(self.out, self.version)
        self.assertIn("/install.sh", files)
        for key, name in self.linux_names().items():
            self.assertIn(f"/downloads/{name}", files)
            self.assertIn(f"/releases/stable-{key[0]}-{key[1]}.json", files)
        served = {"https://secblitz.test" + path: local.read_bytes() for path, local in files.items()}
        args = ["--site", str(self.out), "--version", self.version, "--origin", "https://secblitz.test", "--attempts", "1"]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(live.main(args, lambda url: served[url], lambda _: None), 0)
            served["https://secblitz.test/install.sh"] = b"#!/usr/bin/env bash\necho hi\n"
            self.assertEqual(live.main(args, lambda url: served[url], lambda _: None), 1)
        self.assertIn("https://secblitz.test/install.sh", err.getvalue())
        legacy = {"https://legacy.test" + path: local.read_bytes() for path, local in files.items()}
        fetched = []

        def fetch(url):
            fetched.append(url)
            return legacy.get(url) or files_by_url[url]

        files_by_url = {"https://secblitz.test" + path: local.read_bytes() for path, local in files.items()}
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(live.main(args + ["--feed-origin", "https://legacy.test"], fetch, lambda _: None), 0)
        self.assertEqual([u for u in fetched if u.startswith("https://legacy.test") and ("linux" in u or "install" in u)], [])


class LegacyAssembleTests(AssembleBase):
    """A release before 1.5.0 has no Linux files and must publish exactly as it did."""

    version = "1.4.0"
    linux = False

    def test_release_without_linux_files_still_publishes(self):
        done = self.assemble()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertFalse((self.out / "install.sh").exists())
        self.assertEqual([p for p in (self.out / "downloads").iterdir() if "linux" in p.name], [])
        self.assertEqual([p for p in (self.out / "releases").iterdir() if "linux" in p.name], [])
        self.assertNotIn("install.sh", (self.out / "index.html").read_text())
        self.assertEqual([path for path in live.expected_files(self.out, self.version) if "linux" in path or "install" in path], [])

    def test_linux_files_in_an_older_release_are_refused(self):
        (self.assets / f"secblitz-{self.version}-linux-x64.deb").write_bytes(fake_deb())
        self.assertNotEqual(self.assemble().returncode, 0)


class GateVersionTests(unittest.TestCase):
    def test_linux_files_start_with_1_5_0(self):
        for version, expected in (("1.4.9", False), ("1.5.0", True), ("1.10.0", True), ("2.0.0", True), ("0.99.0", False)):
            self.assertEqual(pages.has_linux(version), expected, version)

    def test_install_script_template_is_filled_in_once_per_placeholder(self):
        template = (REPO / "website/install.sh").read_text()
        digests = {key: format(i, "x") * 64 for i, key in enumerate(finalize.LINUX_PLACEHOLDERS, 1)}
        filled = finalize.render_install(template, "1.5.0", digests)
        self.assertEqual(re.findall(r"@[A-Z0-9_]+@", filled), [])
        self.assertIn('SECBLITZ_VERSION="1.5.0"', filled)
        self.assertIn('SHA256_ARM64_RPM="' + "4" * 64 + '"', filled)
        with self.assertRaises(finalize.FinalizeError):
            finalize.render_install(template, "1.5.0", {key: d for key, d in digests.items() if key != ("x64", "deb")})
        with self.assertRaises(finalize.FinalizeError):
            finalize.render_install(filled, "1.5.0", digests)


if __name__ == "__main__":
    unittest.main()
