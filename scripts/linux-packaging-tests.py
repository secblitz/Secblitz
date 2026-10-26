#!/usr/bin/env python3
"""Tests for the Linux packages, units, policy and repository tools.

    python3 scripts/linux-packaging-tests.py              # no containers: files, units, policy, package structure
    python3 scripts/linux-packaging-tests.py --containers  # also install, upgrade, remove and purge in distro containers

Uses a disposable GPG key made in a temporary GNUPGHOME and a placeholder
program in place of the real binary. Never touches a real key.
"""
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "packaging" / "linux"
LANGS = ("es", "fr", "de", "pt", "it")
XML_LANG = "{http://www.w3.org/XML/1998/namespace}lang"
EM_DASH = "\u2014"
DEB_IMAGES = ("ubuntu:24.04", "ubuntu:26.04", "debian:12", "debian:13")
RPM_IMAGES = ("fedora:43", "fedora:44")
WITH_CONTAINERS = "--containers" in sys.argv
if WITH_CONTAINERS:
    sys.argv.remove("--containers")


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load("build_linux_packages", "build-linux-packages.py")
repo = load("build_linux_repo", "build-linux-repo.py")


def ini(path):
    sections, current = {}, None
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            current = sections.setdefault(line.strip("[]"), {})
        else:
            key, _, value = line.partition("=")
            current[key.strip()] = value.strip()
    return sections


def have(program):
    return shutil.which(program) is not None


class TempKey:
    """A throwaway GPG key in its own GNUPGHOME."""

    def __init__(self):
        self.home = tempfile.mkdtemp(prefix="secblitz-test-gpg-")
        os.chmod(self.home, 0o700)
        self.env = dict(os.environ, GNUPGHOME=self.home)
        subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-gen-key", "Secblitz Test <test@example.invalid>",
                        "ed25519", "sign", "never"], env=self.env, check=True, capture_output=True)
        out = subprocess.run(["gpg", "--batch", "--list-keys", "--with-colons"], env=self.env, check=True,
                             capture_output=True, text=True).stdout
        self.fpr = next(line.split(":")[9] for line in out.splitlines() if line.startswith("fpr:"))
        self.public = subprocess.run(["gpg", "--batch", "--armor", "--export", self.fpr], env=self.env, check=True,
                                     capture_output=True).stdout
        self.private = subprocess.run(["gpg", "--batch", "--armor", "--export-secret-keys", self.fpr], env=self.env,
                                      check=True, capture_output=True).stdout

    def close(self):
        shutil.rmtree(self.home, ignore_errors=True)


class StaticFiles(unittest.TestCase):
    def test_helper_unit(self):
        unit = ini(PKG / "systemd" / "secblitz-helper.service")["Service"]
        self.assertEqual(unit["Type"], "dbus")
        self.assertEqual(unit["BusName"], "org.secblitz.Helper1")
        self.assertEqual(unit["ExecStart"], "/usr/bin/secblitz helper")
        for key, value in {"PrivateTmp": "yes", "ProtectHome": "read-only",
                           "StateDirectory": "secblitz", "StateDirectoryMode": "0700"}.items():
            self.assertEqual(unit[key], value, key)
        # Removing an old kernel writes /usr/lib/modules, which ProtectKernelModules makes read-only.
        self.assertNotIn("ProtectKernelModules", unit)
        # On Fedora, SELinux runs no rpm package script for a service with no new privileges.
        self.assertNotIn("NoNewPrivileges", unit)
        # Packages that ship setuid programs could not be installed again.
        self.assertNotIn("RestrictSUIDSGID", unit)

    def test_monitor_units(self):
        unit = ini(PKG / "systemd" / "secblitz-monitor.service")["Service"]
        self.assertEqual(unit["ExecStart"], "/usr/bin/secblitz monitor-once")
        self.assertEqual(unit["ProtectSystem"], "strict")
        self.assertEqual(unit["ReadWritePaths"], "/var/lib/secblitz")
        self.assertEqual(unit["NoNewPrivileges"], "yes")
        timer = ini(PKG / "systemd" / "secblitz-monitor.timer")
        self.assertEqual(timer["Timer"]["OnCalendar"], "daily")
        self.assertEqual(timer["Install"]["WantedBy"], "timers.target")

    def test_rpm_recommends_dconf_for_the_person_settings(self):
        spec = (PKG / "rpm" / "secblitz.spec.in").read_text(encoding="utf-8")
        self.assertRegex(spec, r"(?m)^Recommends:\s+dconf$")

    def test_dbus_activation(self):
        service = ini_like(PKG / "dbus" / "org.secblitz.Helper1.service")
        self.assertEqual(service["Name"], "org.secblitz.Helper1")
        self.assertEqual(service["SystemdService"], "secblitz-helper.service")
        self.assertEqual(service["User"], "root")

    def test_dbus_policy_only_root_owns_the_name(self):
        root = ET.parse(PKG / "dbus" / "org.secblitz.Helper1.conf").getroot()
        owners = []
        callers = []
        for policy in root.findall("policy"):
            for allow in policy.findall("allow"):
                if "own" in allow.attrib:
                    owners.append((policy.attrib, allow.attrib["own"]))
                if "send_destination" in allow.attrib:
                    callers.append(policy.attrib)
        self.assertEqual(owners, [({"user": "root"}, "org.secblitz.Helper1")])
        self.assertIn({"context": "default"}, callers)
        for policy in root.findall("policy"):
            for rule in policy:
                self.assertNotIn("own_prefix", rule.attrib)
                self.assertNotEqual(rule.tag, "deny")

    def test_polkit_actions(self):
        root = ET.parse(PKG / "polkit" / "org.secblitz.policy").getroot()
        actions = {a.attrib["id"]: a for a in root.findall("action")}
        self.assertEqual(sorted(actions), ["org.secblitz.change", "org.secblitz.check", "org.secblitz.remove"])
        wanted = {"org.secblitz.check": "yes", "org.secblitz.change": "auth_admin_keep",
                  "org.secblitz.remove": "auth_admin"}
        for action_id, action in actions.items():
            defaults = action.find("defaults")
            self.assertEqual(defaults.find("allow_active").text, wanted[action_id])
            self.assertEqual(defaults.find("allow_any").text, "no")
            self.assertEqual(defaults.find("allow_inactive").text, "no")
            for tag in ("description", "message"):
                langs = {e.attrib.get(XML_LANG, "en"): (e.text or "").strip() for e in action.findall(tag)}
                self.assertEqual(sorted(langs), sorted(("en",) + LANGS), "%s %s" % (action_id, tag))
                for lang, text in langs.items():
                    self.assertTrue(text, "%s %s %s empty" % (action_id, tag, lang))
                    self.assertNotIn(EM_DASH, text)
        self.assertNotIn(" PC", (PKG / "polkit" / "org.secblitz.policy").read_text(encoding="utf-8"))

    def test_user_facing_files_have_no_em_dash_or_jargon(self):
        for path in (PKG / "polkit" / "org.secblitz.policy", PKG / "org.secblitz.Secblitz.desktop",
                     PKG / "org.secblitz.Secblitz.metainfo.xml"):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn(EM_DASH, text, path.name)
            self.assertIsNone(re.search(r"\bPC\b", text), path.name)

    def test_desktop_file_is_translated(self):
        entries = {}
        for line in (PKG / "org.secblitz.Secblitz.desktop").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                entries[key] = value
        self.assertEqual(entries["Exec"], "secblitz")
        self.assertEqual(entries["Icon"], "org.secblitz.Secblitz")
        for base in ("GenericName", "Comment"):
            for lang in LANGS:
                self.assertIn("%s[%s]" % (base, lang), entries)

    def test_metainfo(self):
        root = ET.parse(PKG / "org.secblitz.Secblitz.metainfo.xml").getroot()
        self.assertEqual(root.find("id").text, "org.secblitz.Secblitz")
        langs = {e.attrib.get(XML_LANG, "en") for e in root.findall("summary")}
        self.assertEqual(langs, {"en", *LANGS})

    def test_repository_sources(self):
        sources = (PKG / "repo" / "secblitz.sources").read_text()
        self.assertIn("Signed-By: /usr/share/keyrings/secblitz.gpg", sources)
        self.assertIn("URIs: https://", sources)
        repo_file = ini(PKG / "repo" / "secblitz.repo")["secblitz"]
        self.assertEqual(repo_file["repo_gpgcheck"], "1")
        self.assertTrue(repo_file["baseurl"].startswith("https://"))
        self.assertTrue(repo_file["gpgkey"].startswith("file:///etc/pki/rpm-gpg/"))

    def test_maintainer_scripts_never_delete_state(self):
        for name in ("postinst", "prerm", "postrm"):
            text = (PKG / "debian" / name).read_text()
            self.assertTrue(text.startswith("#!/bin/sh\n"))
            self.assertNotRegex(text, r"rm\s+-[a-z]*r[a-z]*\s+\S*/var/lib/secblitz")
            self.assertNotIn("restart", text.replace("try-restart", ""))
        self.assertNotIn("/var/lib/secblitz", (PKG / "rpm" / "secblitz.spec.in").read_text().split("%files")[1].split("%post")[0].replace("@FILES@", ""))


def ini_like(path):
    data = {}
    for line in Path(path).read_text().splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            data[key] = value
    return data


class Glibc(unittest.TestCase):
    SAMPLE = """\
0000000000000000      DF *UND*  0000000000000000  GLIBC_2.2.5 memcpy
0000000000000000      DF *UND*  0000000000000000  GLIBC_2.34  __libc_start_main
0000000000000000      DF *UND*  0000000000000000 (GLIBC_2.14) memcpy
0000000000000000      DO *UND*  0000000000000000  GLIBC_2.38  __isoc23_strtol
"""

    def test_newest_is_numeric_not_text(self):
        self.assertEqual(build.newest_glibc(self.SAMPLE), (2, 38))
        self.assertEqual(build.newest_glibc("GLIBC_2.9 GLIBC_2.10"), (2, 10))
        self.assertIsNone(build.newest_glibc("no versions here"))

    def test_baseline(self):
        self.assertEqual(build.GLIBC_BASELINE, (2, 36))
        self.assertLess(build.newest_glibc("GLIBC_2.36"), (2, 37))


class RepoTool(unittest.TestCase):
    def test_refuses_to_run_in_ci(self):
        for var in ("CI", "GITHUB_ACTIONS"):
            with self.assertRaises(SystemExit):
                repo.main(["out", "a.deb", "--local-user", "X"], environ={var: "true"})

    def test_signing_passes_only_a_key_id(self):
        self.assertEqual(repo.gpg_sign_args("ABCD"), ["gpg", "--batch", "--yes", "--local-user", "ABCD"])

    def test_source_never_handles_key_files(self):
        text = (ROOT / "scripts" / "build-linux-repo.py").read_text()
        code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith(("#", '"""')))
        for forbidden in ("--export", "--import", "secring", "private-keys", "GNUPGHOME"):
            self.assertNotIn(forbidden, code)


@unittest.skipUnless(have("dpkg-deb") and have("gpg"), "needs dpkg-deb and gpg")
class DebStructure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="secblitz-deb-test-"))
        cls.key = TempKey()
        cls.binary = cls.tmp / "secblitz"
        cls.binary.write_text("#!/bin/sh\nexit 0\n")
        cls.binary.chmod(0o755)
        cls.deb = build.build_deb("9.9.9", cls.binary, cls.tmp, "amd64", cls.key.public, 1_700_000_000)

    @classmethod
    def tearDownClass(cls):
        cls.key.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def listing(self):
        out = subprocess.run(["dpkg-deb", "-c", str(self.deb)], check=True, capture_output=True, text=True).stdout
        files = {}
        for line in out.splitlines():
            parts = line.split()
            files[parts[5].lstrip(".")] = (parts[0], parts[1])
        return files

    def test_files_modes_and_owner(self):
        files = self.listing()
        expect = {
            "/usr/bin/secblitz": "-rwxr-xr-x",
            "/usr/lib/systemd/system/secblitz-helper.service": "-rw-r--r--",
            "/usr/lib/systemd/system/secblitz-monitor.service": "-rw-r--r--",
            "/usr/lib/systemd/system/secblitz-monitor.timer": "-rw-r--r--",
            "/usr/share/dbus-1/system-services/org.secblitz.Helper1.service": "-rw-r--r--",
            "/usr/share/dbus-1/system.d/org.secblitz.Helper1.conf": "-rw-r--r--",
            "/usr/share/polkit-1/actions/org.secblitz.policy": "-rw-r--r--",
            "/usr/share/applications/org.secblitz.Secblitz.desktop": "-rw-r--r--",
            "/usr/share/metainfo/org.secblitz.Secblitz.metainfo.xml": "-rw-r--r--",
            "/usr/share/icons/hicolor/256x256/apps/org.secblitz.Secblitz.png": "-rw-r--r--",
            "/usr/share/icons/hicolor/scalable/apps/org.secblitz.Secblitz.svg": "-rw-r--r--",
            "/usr/share/keyrings/secblitz.gpg": "-rw-r--r--",
            "/etc/apt/sources.list.d/secblitz.sources": "-rw-r--r--",
        }
        for path, mode in expect.items():
            self.assertIn(path, files)
            self.assertEqual(files[path], (mode, "root/root"), path)
        for path, (mode, owner) in files.items():
            self.assertEqual(owner, "root/root", path)
            self.assertFalse(mode.endswith("w-") or mode[8] == "w", "world writable: " + path)
        self.assertNotIn("/var/lib/secblitz", files)

    def test_control(self):
        control = subprocess.run(["dpkg-deb", "-f", str(self.deb)], check=True, capture_output=True, text=True).stdout
        self.assertIn("Package: secblitz", control)
        self.assertIn("Version: 9.9.9", control)
        self.assertIn("Architecture: amd64", control)
        self.assertIn("libc6 (>= 2.36)", control)
        self.assertIn("polkitd | policykit-1", control)
        self.assertRegex(control, r"Recommends: [^\n]*\bdconf-cli\b")

    def test_keyring_is_the_public_key_only(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run(["dpkg-deb", "-x", str(self.deb), out], check=True)
            keyring = (Path(out) / "usr/share/keyrings/secblitz.gpg").read_bytes()
        self.assertNotIn(b"PRIVATE", keyring)
        self.assertFalse(keyring.startswith(b"-----BEGIN"))
        with tempfile.TemporaryDirectory() as home:
            os.chmod(home, 0o700)
            listing = subprocess.run(["gpg", "--batch", "--homedir", home, "--show-keys", "--with-colons", "-"],
                                     input=keyring, check=True, capture_output=True).stdout.decode()
        self.assertIn(self.key.fpr, listing)
        self.assertNotIn("\nsec:", "\n" + listing)

    def test_conffile_and_scripts(self):
        with tempfile.TemporaryDirectory() as out:
            subprocess.run(["dpkg-deb", "-e", str(self.deb), out], check=True)
            self.assertEqual((Path(out) / "conffiles").read_text().split(), ["/etc/apt/sources.list.d/secblitz.sources"])
            for name in ("postinst", "prerm", "postrm", "md5sums"):
                self.assertTrue((Path(out) / name).exists(), name)

    def test_build_is_repeatable(self):
        again = self.tmp / "again"
        again.mkdir()
        other = build.build_deb("9.9.9", self.binary, again, "amd64", self.key.public, 1_700_000_000)
        self.assertEqual(self.deb.read_bytes(), other.read_bytes())

    def test_private_key_is_refused(self):
        with self.assertRaises(SystemExit):
            build.dearmor(self.key.private)

    def test_no_repository_without_a_key(self):
        out = self.tmp / "nokey"
        out.mkdir()
        deb = build.build_deb("9.9.9", self.binary, out, "amd64", None, 1_700_000_000)
        listing = subprocess.run(["dpkg-deb", "-c", str(deb)], check=True, capture_output=True, text=True).stdout
        self.assertNotIn("secblitz.gpg", listing)
        self.assertNotIn("sources.list.d", listing)


RPM_SCRIPT = r"""
set -eu
dnf -y -q install /w/old.rpm >/dev/null 2>&1
dnf -y -q install /w/new.rpm >/dev/null 2>&1
test "$(rpm -q --qf '%{VERSION}' secblitz)" = 9.9.9
check() { m=$(stat -c '%a %U:%G' "$1"); [ "$m" = "$2" ] || { echo "bad mode $1 $m"; exit 1; }; }
check /usr/bin/secblitz "755 root:root"
check /usr/lib/systemd/system/secblitz-helper.service "644 root:root"
check /usr/share/polkit-1/actions/org.secblitz.policy "644 root:root"
check /etc/yum.repos.d/secblitz.repo "644 root:root"
for u in secblitz-helper.service secblitz-monitor.service; do
  systemd-analyze verify --man=no /usr/lib/systemd/system/$u
done
if command -v pkaction >/dev/null; then
  out=$(pkaction --verbose --action-id org.secblitz.change 2>&1 || true)
  case "$out" in
    *"Error getting authority"*) echo "polkitd is not running in the container; the policy file is checked by the unit tests" ;;
    *auth_admin_keep*) ;;
    *) echo "pkaction did not show the action: $out"; exit 1 ;;
  esac
fi
rpm -ql secblitz > /tmp/files
mkdir -p /var/lib/secblitz && echo state > /var/lib/secblitz/journal
dnf -y -q remove secblitz >/dev/null 2>&1
while read -r f; do
  if [ -f "$f" ] || [ -L "$f" ]; then echo "left behind: $f"; exit 1; fi
done < /tmp/files
test -f /var/lib/secblitz/journal
echo OK
"""

DEB_SCRIPT = r"""
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends /w/old.deb >/dev/null
apt-get install -y -qq --no-install-recommends /w/new.deb >/dev/null
test "$(dpkg-query -W -f='${Version}' secblitz)" = 9.9.9
check() { m=$(stat -c '%a %U:%G' "$1"); [ "$m" = "$2" ] || { echo "bad mode $1 $m"; exit 1; }; }
check /usr/bin/secblitz "755 root:root"
check /usr/lib/systemd/system/secblitz-helper.service "644 root:root"
check /usr/share/polkit-1/actions/org.secblitz.policy "644 root:root"
check /usr/share/keyrings/secblitz.gpg "644 root:root"
check /etc/apt/sources.list.d/secblitz.sources "644 root:root"
for u in secblitz-helper.service secblitz-monitor.service; do
  systemd-analyze verify --man=no /usr/lib/systemd/system/$u
done
if command -v pkaction >/dev/null; then
  out=$(pkaction --verbose --action-id org.secblitz.change 2>&1 || true)
  case "$out" in
    *"Error getting authority"*) echo "polkitd is not running in the container; the policy file is checked by the unit tests" ;;
    *auth_admin_keep*) ;;
    *) echo "pkaction did not show the action: $out"; exit 1 ;;
  esac
fi
dpkg -L secblitz | grep -v '/$' > /tmp/files
mkdir -p /var/lib/secblitz && echo state > /var/lib/secblitz/journal
apt-get remove -y -qq secblitz >/dev/null
test ! -e /usr/share/keyrings/secblitz.gpg
test ! -e /etc/apt/sources.list.d/secblitz.sources
apt-get purge -y -qq secblitz >/dev/null
while read -r f; do
  if [ -f "$f" ] || [ -L "$f" ]; then echo "left behind: $f"; exit 1; fi
done < /tmp/files
test -f /var/lib/secblitz/journal
echo OK
"""

APT_REPO_SCRIPT = r"""
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends /w/old.deb >/dev/null
sed -i 's#https://secblitz.lol/linux/apt#file:///w/repo/apt#' /etc/apt/sources.list.d/secblitz.sources
apt-get update -qq -o APT::Sandbox::User=root 2>&1 | tee /tmp/update.log
if grep -q -i 'NO_PUBKEY\|not signed\|invalid\|^E:' /tmp/update.log; then exit 1; fi
apt-cache policy secblitz | grep -q 'file:/w/repo/apt'
echo OK
"""

DNF_REPO_SCRIPT = r"""
set -eu
dnf -y -q install /w/old.rpm >/dev/null 2>&1
sed -i 's#https://secblitz.lol/linux/rpm#file:///w/repo/rpm#' /etc/yum.repos.d/secblitz.repo
dnf -y -q makecache >/dev/null
dnf -y -q repoquery --repo secblitz secblitz | grep -q 9.9.9
echo OK
"""


def docker(image, script, mount):
    return subprocess.run(["docker", "run", "--rm", "-v", "%s:/w:ro" % mount, image, "bash", "-c", script],
                          capture_output=True, text=True)


@unittest.skipUnless(WITH_CONTAINERS and have("docker") and have("dpkg-deb"), "container tests are off (--containers)")
class Containers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="secblitz-ct-test-"))
        os.chmod(cls.tmp, 0o755)
        cls.key = TempKey()
        binary = cls.tmp / "secblitz"
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o755)
        epoch = 1_700_000_000
        cls.debs, cls.rpms = {}, {}
        for version in ("9.9.8", "9.9.9"):
            cls.debs[version] = build.build_deb(version, binary, cls.tmp, "amd64", cls.key.public, epoch)
            cls.rpms[version] = build.build_rpm(version, binary, cls.tmp, "x86_64", cls.key.public, epoch)
        shutil.copyfile(cls.debs["9.9.8"], cls.tmp / "old.deb")
        shutil.copyfile(cls.debs["9.9.9"], cls.tmp / "new.deb")
        shutil.copyfile(cls.rpms["9.9.8"], cls.tmp / "old.rpm")
        shutil.copyfile(cls.rpms["9.9.9"], cls.tmp / "new.rpm")
        for p in cls.tmp.iterdir():
            os.chmod(p, 0o755 if p.is_dir() or os.access(p, os.X_OK) else 0o644)

    @classmethod
    def tearDownClass(cls):
        cls.key.close()
        subprocess.run(["docker", "run", "--rm", "-v", "%s:/w" % cls.tmp, "debian:12", "rm", "-rf", "/w/repo"],
                       capture_output=True)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def run_script(self, image, script):
        result = docker(image, script, self.tmp)
        self.assertEqual(result.returncode, 0, "%s\n%s\n%s" % (image, result.stdout[-3000:], result.stderr[-3000:]))
        self.assertTrue(result.stdout.strip().endswith("OK"), result.stdout[-2000:])

    def test_deb_lifecycle(self):
        for image in DEB_IMAGES:
            with self.subTest(image=image):
                self.run_script(image, DEB_SCRIPT)

    def test_rpm_lifecycle(self):
        for image in RPM_IMAGES:
            with self.subTest(image=image):
                self.run_script(image, RPM_SCRIPT)

    def test_signed_repositories_verify(self):
        env = dict(os.environ, GNUPGHOME=self.key.home)
        repo_out = self.tmp / "repo"
        old_env = os.environ.get("GNUPGHOME")
        os.environ["GNUPGHOME"] = self.key.home
        try:
            repo.build_apt(repo_out, [self.debs["9.9.9"]], self.key.fpr)
            repo.build_rpm(repo_out, [self.rpms["9.9.9"]], self.key.fpr)
        finally:
            if old_env is None:
                del os.environ["GNUPGHOME"]
            else:
                os.environ["GNUPGHOME"] = old_env
        for path in ("apt/dists/stable/InRelease", "apt/dists/stable/Release.gpg",
                     "rpm/x86_64/repodata/repomd.xml.asc"):
            self.assertTrue((repo_out / path).is_file(), path)
        for path in repo_out.rglob("*"):
            os.chmod(path, 0o755 if path.is_dir() else 0o644)
        for image in ("debian:12", "ubuntu:24.04"):
            with self.subTest(image=image):
                self.run_script(image, APT_REPO_SCRIPT)
        for image in ("fedora:44",):
            with self.subTest(image=image):
                self.run_script(image, DNF_REPO_SCRIPT)
        bad = (repo_out / "apt/dists/stable/Release").read_bytes() + b"x"
        (repo_out / "apt/dists/stable/InRelease").write_bytes(bad)
        result = docker("debian:12", APT_REPO_SCRIPT, self.tmp)
        self.assertNotEqual(result.returncode, 0, "a tampered InRelease must not verify")
        self.assertIsNotNone(env)

    def test_lintian(self):
        script = ("export DEBIAN_FRONTEND=noninteractive; apt-get update -qq >/dev/null; "
                  "apt-get install -y -qq lintian >/dev/null; lintian --fail-on error,warning /w/new.deb; echo OK")
        self.run_script("debian:12", script)

    def test_rpmlint(self):
        script = ("dnf -y -q install rpmlint >/dev/null 2>&1; rpmlint --strict /w/new.rpm || true; "
                  "rpmlint /w/new.rpm 2>&1 | tail -3; echo OK")
        self.run_script("fedora:44", script)


if __name__ == "__main__":
    unittest.main()
