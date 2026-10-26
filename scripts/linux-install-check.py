#!/usr/bin/env python3
"""Install the real built Linux packages in distro containers.

    linux-install-check.py DIR VERSION {x64|arm64}

DIR holds secblitz-VERSION-linux-ARCH.deb and .rpm. Each package is installed,
checked, removed and purged in the same distro images the package tests use.
"""
import subprocess
import sys
from pathlib import Path

DEB_IMAGES = ("ubuntu:24.04", "ubuntu:26.04", "debian:12", "debian:13")
RPM_IMAGES = ("fedora:43", "fedora:44")
ARCHES = ("x64", "arm64")
FILE_ARCH = {"x64": "x86-64", "arm64": "ARM aarch64"}

CHECKS = r"""
check() { m=$(stat -c '%a %U:%G' "$1"); [ "$m" = "$2" ] || { echo "bad mode $1 $m"; exit 1; }; }
check /usr/bin/secblitz "755 root:root"
check /usr/lib/systemd/system/secblitz-helper.service "644 root:root"
check /usr/share/polkit-1/actions/org.secblitz.policy "644 root:root"
file -b /usr/bin/secblitz | grep -q "$WANT_ARCH"
secblitz --version | grep -q "$VERSION"
for u in secblitz-helper.service secblitz-monitor.service; do
  systemd-analyze verify --man=no /usr/lib/systemd/system/$u
done
"""

DEB_SCRIPT = r"""
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends file /w/PACKAGE >/dev/null
test "$(dpkg-query -W -f='${Version}' secblitz)" = "$VERSION"
""" + CHECKS + r"""
dpkg -L secblitz | grep -v '/$' > /tmp/files
apt-get purge -y -qq secblitz >/dev/null
while read -r f; do
  if [ -f "$f" ] || [ -L "$f" ]; then echo "left behind: $f"; exit 1; fi
done < /tmp/files
echo OK
"""

RPM_SCRIPT = r"""
set -eu
dnf -y -q install file /w/PACKAGE >/dev/null 2>&1
test "$(rpm -q --qf '%{VERSION}' secblitz)" = "$VERSION"
""" + CHECKS + r"""
rpm -ql secblitz > /tmp/files
dnf -y -q remove secblitz >/dev/null 2>&1
while read -r f; do
  if [ -f "$f" ] || [ -L "$f" ]; then echo "left behind: $f"; exit 1; fi
done < /tmp/files
echo OK
"""


def package_name(version, arch, kind):
    return "secblitz-%s-linux-%s.%s" % (version, arch, kind)


def run(image, script, directory, version, arch):
    return subprocess.run(
        ["docker", "run", "--rm", "-e", "VERSION=" + version, "-e", "WANT_ARCH=" + FILE_ARCH[arch],
         "-v", "%s:/w:ro" % directory, image, "bash", "-c", script],
        capture_output=True, text=True)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 3 or args[2] not in ARCHES:
        print(__doc__, file=sys.stderr)
        return 2
    directory, version, arch = Path(args[0]).resolve(), args[1], args[2]
    failed = False
    for kind, images, template in (("deb", DEB_IMAGES, DEB_SCRIPT), ("rpm", RPM_IMAGES, RPM_SCRIPT)):
        name = package_name(version, arch, kind)
        if not (directory / name).is_file():
            print("missing: " + name, file=sys.stderr)
            return 1
        script = template.replace("PACKAGE", name)
        for image in images:
            result = run(image, script, directory, version, arch)
            ok = result.returncode == 0 and result.stdout.strip().endswith("OK")
            print("%s %s: %s" % (kind, image, "ok" if ok else "FAILED"), flush=True)
            if not ok:
                print(result.stdout[-3000:] + result.stderr[-3000:], file=sys.stderr)
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
