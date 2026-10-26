#!/usr/bin/env python3
"""Tests for website/install.sh, the one-line Linux installer.

    python3 scripts/install-script-tests.py

The script is rendered with fake versions and checksums, then run for real under
bash with stand-ins for curl, uname, id, sudo, apt-get and dnf on the PATH and a
fake os-release file. Nothing is downloaded or installed. The only change made to
the script is the os-release path, so the tests run the script that ships.

shellcheck runs when it is installed. To fetch a pinned release of it into
target/tmp (no sudo), set SECBLITZ_FETCH_SHELLCHECK=1.
"""
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import platform
import pty
import re
import select
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "website" / "install.sh"
FIXTURES = ROOT / "tests" / "fixtures" / "os-release"
VERSION = "9.9.9"
SHELLCHECK_URL = "https://github.com/koalaman/shellcheck/releases/download/v0.10.0/shellcheck-v0.10.0.linux.x86_64.tar.xz"
SHELLCHECK_SHA256 = "6c881ab0698e4e6ea235245f22832860544f17ba386442fe7e9d629f8cbedf87"
KEYS = [("x64", "deb"), ("x64", "rpm"), ("arm64", "deb"), ("arm64", "rpm")]


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


finalize = load("finalize_site", "finalize-site.py")

STUBS = {
    "uname": '''#!/bin/bash
case "${1:-}" in
  -m) echo "$FAKE_MACHINE" ;;
  -s) echo "${FAKE_SYSTEM:-Linux}" ;;
  *) echo "Linux" ;;
esac
''',
    "id": '''#!/bin/bash
echo "$FAKE_UID"
''',
    "curl": '''#!/bin/bash
out="" url=""
while [ $# -gt 0 ]; do
  case "$1" in
    --output) out=$2; shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
echo "curl $url" >>"$FAKE_LOG"
file="$FAKE_DOWNLOADS/${url##*/}"
[ -f "$file" ] || exit 22
cp "$file" "$out"
''',
    "sudo": '''#!/bin/bash
echo "sudo $*" >>"$FAKE_LOG"
[ "${1:-}" = "-v" ] && exit 0
exec "$@"
''',
    "apt-get": '''#!/bin/bash
echo "apt-get $* (in $(basename "$PWD"))" >>"$FAKE_LOG"
''',
    "dnf": '''#!/bin/bash
echo "dnf $* (in $(basename "$PWD"))" >>"$FAKE_LOG"
''',
}


def render(version=VERSION, digests=None):
    digests = digests or {key: hashlib.sha256(package_bytes(*key)).hexdigest() for key in KEYS}
    return finalize.render_install(TEMPLATE.read_text(encoding="utf-8"), version, digests)


def package_bytes(arch, kind):
    return f"fake {arch} {kind} package\n".encode()


def find_shellcheck():
    found = shutil.which("shellcheck")
    if found:
        return found
    if os.environ.get("SECBLITZ_FETCH_SHELLCHECK") != "1" or platform.machine() != "x86_64" or platform.system() != "Linux":
        return None
    folder = ROOT / "target" / "tmp" / "shellcheck"
    binary = folder / "shellcheck-v0.10.0" / "shellcheck"
    if not binary.exists():
        with urllib.request.urlopen(SHELLCHECK_URL, timeout=120) as response:
            data = response.read(20 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != SHELLCHECK_SHA256:
            raise RuntimeError("the shellcheck download does not match its pinned checksum")
        folder.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:xz") as archive:
            member = archive.getmember("shellcheck-v0.10.0/shellcheck")
            archive.extract(member, folder, filter="data")
    return str(binary)


class InstallScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.bin = base / "bin"
        self.bin.mkdir()
        for name, body in STUBS.items():
            path = self.bin / name
            path.write_text(body)
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.downloads = base / "downloads"
        self.downloads.mkdir()
        for arch, kind in KEYS:
            (self.downloads / f"secblitz-{VERSION}-linux-{arch}.{kind}").write_bytes(package_bytes(arch, kind))
        self.log = base / "log"
        self.log.write_text("")
        self.scratch = base / "scratch"
        self.scratch.mkdir()
        self.script = render()

    def tearDown(self):
        self.tmp.cleanup()

    def os_release(self, fixture):
        path = Path(self.tmp.name) / "os-release"
        path.write_text(fixture if "\n" in fixture else (FIXTURES / fixture).read_text())
        return path

    def prepared(self, script, os_release):
        line = 'OS_RELEASE_FILE="/etc/os-release"'
        self.assertEqual(script.count(line), 1)
        return script.replace(line, f'OS_RELEASE_FILE="{os_release}"')

    def env(self, machine="x86_64", uid=1000, **extra):
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": self.tmp.name, "TMPDIR": str(self.scratch),
               "FAKE_MACHINE": machine, "FAKE_UID": str(uid), "FAKE_LOG": str(self.log), "FAKE_DOWNLOADS": str(self.downloads),
               "LANG": "C.UTF-8", "TERM": "xterm"}
        env.update(extra)
        return env

    def run_script(self, script, os_fixture="ubuntu-24.04", **env):
        """Run like `curl ... | bash`: the script arrives on standard input."""
        text = self.prepared(script, self.os_release(os_fixture))
        return subprocess.run(["bash"], input=text, capture_output=True, text=True, env=self.env(**env), timeout=60)

    def calls(self):
        return self.log.read_text().splitlines()

    def test_no_placeholder_remains_after_filling_in(self):
        self.assertEqual(re.findall(r"@[A-Z0-9_]+@", self.script), [])
        self.assertEqual(sorted(set(re.findall(r"@[A-Z0-9_]+@", TEMPLATE.read_text()))),
                         sorted(["@SECBLITZ_VERSION@", "@SHA256_X64_DEB@", "@SHA256_X64_RPM@", "@SHA256_ARM64_DEB@", "@SHA256_ARM64_RPM@"]))

    def test_template_and_filled_script_are_valid_bash(self):
        for name, text in (("template", TEMPLATE.read_text()), ("filled", self.script)):
            done = subprocess.run(["bash", "-n"], input=text, capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, f"{name}: {done.stderr}")

    def test_shellcheck_finds_nothing(self):
        binary = find_shellcheck()
        if not binary:
            self.skipTest("shellcheck is not installed (set SECBLITZ_FETCH_SHELLCHECK=1 to fetch a pinned release into target/tmp)")
        for name, text in (("template", TEMPLATE.read_text()), ("filled", self.script)):
            done = subprocess.run([binary, "-s", "bash", "-"], input=text, capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, f"{name}: {done.stdout}{done.stderr}")

    def test_script_text_follows_the_rules(self):
        text = TEMPLATE.read_text()
        self.assertTrue(text.startswith("#!/usr/bin/env bash\n"))
        self.assertIn("\nset -euo pipefail\n", text)
        self.assertEqual(text.rstrip("\n").splitlines()[-1], 'main "$@"')
        self.assertEqual(text.count('main "$@"'), 1)
        self.assertNotRegex(text, r"\beval\b")
        self.assertNotIn("\u2014", text)
        self.assertNotIn("\u2013", text)
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotRegex(code, r"\|\s*(?:ba|z|da)?sh\b")

    def test_a_cut_off_download_runs_nothing(self):
        lines = self.script.splitlines(keepends=True)
        os_release = self.os_release("ubuntu-24.04")
        for keep in range(1, len(lines)):
            text = "".join(lines[:keep]).replace('OS_RELEASE_FILE="/etc/os-release"', f'OS_RELEASE_FILE="{os_release}"')
            subprocess.run(["bash"], input=text, capture_output=True, text=True, env=self.env(), timeout=60)
            self.assertEqual(self.calls(), [], f"cut after line {keep}")

    def test_debian_on_intel_downloads_checks_and_installs_with_sudo(self):
        done = self.run_script(self.script, "ubuntu-24.04", machine="x86_64")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        calls = self.calls()
        self.assertEqual(calls[:3], [
            f"curl https://secblitz.lol/downloads/secblitz-{VERSION}-linux-x64.deb",
            "sudo -v",
            f"sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y ./secblitz-{VERSION}-linux-x64.deb",
        ])
        self.assertRegex(calls[3], rf"^apt-get install -y \./secblitz-{VERSION}-linux-x64\.deb \(in \S+\)$")
        self.assertEqual(len(calls), 4)
        self.assertIn("Detecting your system... done (Ubuntu 24.04", done.stdout)
        self.assertIn("Downloading Secblitz 9.9.9... done", done.stdout)
        self.assertIn("Checking the download... done", done.stdout)
        self.assertIn("Installing Secblitz... done", done.stdout)
        self.assertIn("Open Secblitz from your app menu", done.stdout)
        self.assertIn("needs your password", done.stdout)
        self.assertNotIn("\x1b", done.stdout + done.stderr)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_fedora_on_arm_installs_as_root_without_sudo(self):
        done = self.run_script(self.script, "fedora-44", machine="aarch64", uid=0)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        calls = self.calls()
        self.assertEqual(calls[0], f"curl https://secblitz.lol/downloads/secblitz-{VERSION}-linux-arm64.rpm")
        self.assertRegex(calls[1], rf"^dnf install -y \./secblitz-{VERSION}-linux-arm64\.rpm \(in \S+\)$")
        self.assertEqual(len(calls), 2)
        self.assertNotIn("password", done.stdout)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_other_debian_family_and_arm_names_are_recognised(self):
        done = self.run_script(self.script, "mint-22.3", machine="arm64")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.calls()[0], f"curl https://secblitz.lol/downloads/secblitz-{VERSION}-linux-arm64.deb")

    def test_wrong_checksum_refuses_to_install(self):
        (self.downloads / f"secblitz-{VERSION}-linux-x64.deb").write_bytes(b"not the file we published")
        done = self.run_script(self.script, "debian-12", machine="x86_64")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("not the one we published", done.stderr)
        self.assertEqual(self.calls(), [f"curl https://secblitz.lol/downloads/secblitz-{VERSION}-linux-x64.deb"])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_failed_download_installs_nothing(self):
        (self.downloads / f"secblitz-{VERSION}-linux-x64.deb").unlink()
        done = self.run_script(self.script, "debian-12", machine="x86_64")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("internet connection", done.stderr)
        self.assertFalse([c for c in self.calls() if c.startswith(("sudo", "apt-get", "dnf"))])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_unsupported_linux_gets_a_friendly_message(self):
        done = self.run_script(self.script, 'NAME="Arch Linux"\nID=arch\nPRETTY_NAME="Arch Linux"\n', machine="x86_64")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("does not support this kind of Linux yet", done.stderr)
        self.assertEqual(self.calls(), [])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_unsupported_processor_gets_a_friendly_message(self):
        done = self.run_script(self.script, "ubuntu-24.04", machine="riscv64")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("does not support this kind of computer yet (riscv64)", done.stderr)
        self.assertEqual(self.calls(), [])

    def test_a_script_that_was_never_filled_in_refuses_to_run(self):
        done = self.run_script(TEMPLATE.read_text(), "ubuntu-24.04")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("incomplete", done.stderr)
        self.assertEqual(self.calls(), [])

    def test_not_linux_is_refused(self):
        done = self.run_script(self.script, "ubuntu-24.04", FAKE_SYSTEM="Darwin")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("for Linux", done.stderr)
        self.assertEqual(self.calls(), [])

    def run_in_terminal(self, **env):
        """Run with a real terminal on standard output and return what it showed."""
        text = self.prepared(self.script, self.os_release("ubuntu-24.04"))
        script_file = Path(self.tmp.name) / "install-run.sh"
        script_file.write_text(text)
        master, slave = pty.openpty()
        process = subprocess.Popen(["bash", str(script_file)], stdin=subprocess.DEVNULL, stdout=slave, stderr=slave,
                                   env=self.env(**env), close_fds=True)
        os.close(slave)
        output = b""
        while True:
            ready, _, _ = select.select([master], [], [], 30)
            if not ready:
                process.kill()
                self.fail("the installer did not finish in a terminal")
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
        os.close(master)
        self.assertEqual(process.wait(timeout=30), 0, output.decode(errors="replace"))
        return output.decode()

    def test_colors_and_check_marks_appear_only_in_a_terminal(self):
        shown = self.run_in_terminal()
        self.assertIn("\x1b[32m", shown)
        self.assertIn("✓", shown)
        self.assertIn("Installing Secblitz", shown)
        plain_locale = self.run_in_terminal(LANG="C", LC_ALL="C")
        self.assertIn("\x1b[32m", plain_locale)
        self.assertNotIn("✓", plain_locale)
        self.assertNotRegex(plain_locale, "[⠀-⣿]")

    def test_no_color_and_dumb_terminals_get_plain_lines(self):
        for env in ({"NO_COLOR": "1"}, {"TERM": "dumb"}):
            shown = self.run_in_terminal(**env)
            self.assertNotIn("\x1b", shown, env)
            self.assertIn("Checking the download... done", shown)


if __name__ == "__main__":
    unittest.main()
