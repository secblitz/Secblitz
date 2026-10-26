#!/usr/bin/env python3
"""Build the Secblitz .deb and .rpm from a Linux binary.

    build-linux-packages.py VERSION BINARY OUTDIR [--arch x86_64|aarch64]
        [--key PUBLIC_KEY.asc] [--without-repository] [--skip-glibc-check]
    build-linux-packages.py VERSION BINARY OUTDIR --build-binary

The .deb is made on this machine with dpkg-deb. The .rpm is made with rpmbuild
inside a fedora:44 container. --build-binary first compiles the release binary
inside debian:12 so it runs on glibc 2.36 and newer; every build then fails if
the binary needs a newer glibc symbol. --key is the owner's PUBLIC signing key
(ASCII armored); it is installed so the package manager trusts the Secblitz
repository. A private key is refused.
"""
import argparse
import datetime
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "packaging" / "linux"
GLIBC_BASELINE = (2, 36)
ARCHES = {"x86_64": ("amd64", "x86_64"), "aarch64": ("arm64", "aarch64")}
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256)
APP_ID = "org.secblitz.Secblitz"
RPM_IMAGE = "fedora:44"
BUILD_IMAGE = "debian:12"
DEB_DEPENDS = "libc6 (>= 2.36), dbus, polkitd | policykit-1, systemd"
DEB_RECOMMENDS = "dconf-cli, hicolor-icon-theme, libxkbcommon0, libwayland-client0, libvulkan1, fontconfig"
DESCRIPTION = "Check your computer's security and privacy and fix what you approve"
LONG_DESCRIPTION = [
    "Secblitz looks at your computer's security and privacy settings and tells you",
    "in plain words what it finds. Checking never changes anything. Nothing changes",
    "without your clear yes, and every change can be undone.",
]


def die(message):
    print("error: " + message, file=sys.stderr)
    sys.exit(1)


def glibc_versions(objdump_output):
    return sorted({tuple(int(p) for p in m.split(".")) for m in re.findall(r"GLIBC_(\d+(?:\.\d+)+)", objdump_output)})


def newest_glibc(objdump_output):
    found = glibc_versions(objdump_output)
    return found[-1] if found else None


def check_glibc(binary):
    result = subprocess.run(["objdump", "-T", str(binary)], capture_output=True, text=True)
    if result.returncode != 0:
        die("objdump could not read %s: %s" % (binary, result.stderr.strip()))
    newest = newest_glibc(result.stdout)
    if newest and newest > GLIBC_BASELINE:
        die("%s needs GLIBC_%s but the baseline is GLIBC_%d.%d; build it with --build-binary"
            % (binary, ".".join(map(str, newest)), *GLIBC_BASELINE))
    return newest


def build_binary(output, arch):
    if arch != "x86_64":
        die("the debian:12 build runs on this machine's architecture; build aarch64 on an aarch64 host")
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    script = (
        "set -euo pipefail\n"
        "apt-get update -qq\n"
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "
        "ca-certificates curl build-essential pkg-config cmake >/dev/null\n"
        "channel=$(sed -n 's/^channel *= *\"\\([^\"]*\\)\".*/\\1/p' /src/rust-toolchain.toml)\n"
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | "
        "sh -s -- -y --profile minimal --default-toolchain \"$channel\" >/dev/null\n"
        ". /root/.cargo/env\n"
        "cd /src\n"
        "CARGO_TARGET_DIR=/work/target cargo build --locked --release\n"
        "cp /work/target/release/secblitz /out/secblitz\n"
    )
    with tempfile.TemporaryDirectory() as work:
        out_dir = Path(work) / "out"
        out_dir.mkdir()
        subprocess.run(
            ["docker", "run", "--rm", "-v", "%s:/src:ro" % ROOT, "-v", "%s:/out" % out_dir,
             "-v", "secblitz-linux-build-cache:/work", BUILD_IMAGE, "bash", "-c", script],
            check=True)
        shutil.copyfile(out_dir / "secblitz", output)
    output.chmod(0o755)


def icon_pngs():
    try:
        from PIL import Image
    except ImportError:
        die("Pillow is needed to make the icons (pip install --require-hashes -r scripts/requirements-art.txt)")
    icons = {}
    with Image.open(ROOT / "assets" / "secblitz.ico") as ico:
        available = ico.info.get("sizes", set())
        for size in ICON_SIZES:
            if (size, size) not in available:
                die("assets/secblitz.ico has no %dx%d image" % (size, size))
            ico.size = (size, size)
            ico.load()
            buffer = io.BytesIO()
            ico.convert("RGBA").save(buffer, "PNG", optimize=True)
            icons[size] = buffer.getvalue()
    return icons


def dearmor(armored):
    if b"PRIVATE KEY" in armored:
        die("refusing a private key; give the PUBLIC key only")
    if b"BEGIN PGP PUBLIC KEY BLOCK" not in armored:
        die("the key must be an ASCII armored public key")
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        result = subprocess.run(["gpg", "--batch", "--homedir", home, "--dearmor"], input=armored, capture_output=True)
        if result.returncode != 0 or not result.stdout:
            die("gpg could not read the public key: " + result.stderr.decode(errors="replace").strip())
        return result.stdout


class Tree:
    """A staged package root. Every file is recorded with its final mode so both package formats agree."""

    def __init__(self, root, epoch):
        self.root = Path(root)
        self.epoch = epoch
        self.files = {}

    def add(self, path, data, mode=0o644, config=False):
        if isinstance(data, Path):
            data = data.read_bytes()
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        os.chmod(target, mode)
        self.files["/" + path] = {"mode": mode, "config": config, "size": len(data)}

    def finish(self):
        for dirpath, dirnames, filenames in os.walk(self.root):
            for name in dirnames + filenames:
                os.utime(Path(dirpath) / name, (self.epoch, self.epoch), follow_symlinks=False)
            os.chmod(dirpath, 0o755)


def stage(root, version, binary, key_armored, epoch, fmt):
    """Lay out the files shared by both formats; fmt is 'deb' or 'rpm' for the repository entry."""
    tree = Tree(root, epoch)
    date = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%d")
    tree.add("usr/bin/secblitz", Path(binary), 0o755)
    for unit in ("secblitz-helper.service", "secblitz-monitor.service", "secblitz-monitor.timer"):
        tree.add("usr/lib/systemd/system/" + unit, PKG / "systemd" / unit)
    tree.add("usr/share/dbus-1/system-services/org.secblitz.Helper1.service", PKG / "dbus" / "org.secblitz.Helper1.service")
    tree.add("usr/share/dbus-1/system.d/org.secblitz.Helper1.conf", PKG / "dbus" / "org.secblitz.Helper1.conf")
    tree.add("usr/share/polkit-1/actions/org.secblitz.policy", PKG / "polkit" / "org.secblitz.policy")
    tree.add("usr/share/applications/%s.desktop" % APP_ID, PKG / (APP_ID + ".desktop"))
    metainfo = (PKG / (APP_ID + ".metainfo.xml")).read_text(encoding="utf-8")
    metainfo = metainfo.replace("@VERSION@", version).replace("@DATE@", date)
    tree.add("usr/share/metainfo/%s.metainfo.xml" % APP_ID, metainfo.encode("utf-8"))
    for size, png in icon_pngs().items():
        tree.add("usr/share/icons/hicolor/%dx%d/apps/%s.png" % (size, size, APP_ID), png)
    tree.add("usr/share/icons/hicolor/scalable/apps/%s.svg" % APP_ID, ROOT / "assets" / "secblitz.svg")
    if key_armored is not None:
        if fmt == "deb":
            tree.add("usr/share/keyrings/secblitz.gpg", dearmor(key_armored))
            tree.add("etc/apt/sources.list.d/secblitz.sources", PKG / "repo" / "secblitz.sources", config=True)
        else:
            tree.add("etc/pki/rpm-gpg/RPM-GPG-KEY-secblitz", key_armored)
            tree.add("etc/yum.repos.d/secblitz.repo", PKG / "repo" / "secblitz.repo", config=True)
    return tree


def deb_control(version, arch, installed_kib):
    lines = [
        "Package: secblitz",
        "Version: " + version,
        "Architecture: " + arch,
        "Maintainer: Secblitz <support@secblitz.lol>",
        "Installed-Size: %d" % installed_kib,
        "Depends: " + DEB_DEPENDS,
        "Recommends: " + DEB_RECOMMENDS,
        "Section: admin",
        "Priority: optional",
        "Homepage: https://secblitz.lol",
        "Description: " + DESCRIPTION,
    ] + [" " + line for line in LONG_DESCRIPTION]
    return "\n".join(lines) + "\n"


def build_deb(version, binary, outdir, deb_arch, key_armored, epoch):
    outdir = Path(outdir)
    with tempfile.TemporaryDirectory() as work:
        root = Path(work) / "pkg"
        tree = stage(root, version, binary, key_armored, epoch, "deb")
        doc = "usr/share/doc/secblitz/"
        tree.add(doc + "copyright", (
            "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n"
            "Upstream-Name: secblitz\nSource: https://github.com/secblitz/Secblitz\n\n"
            "Files: *\nCopyright: Secblitz\nLicense: MIT\n"
            " Licensed under the MIT license. The full text is in /usr/share/doc/secblitz/LICENSE.\n"
        ).encode())
        tree.add(doc + "LICENSE", ROOT / "LICENSE")
        changelog = "secblitz (%s) stable; urgency=medium\n\n  * Release %s.\n\n -- Secblitz <support@secblitz.lol>  %s\n" % (
            version, version, time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime(epoch)))
        packed = io.BytesIO()
        with gzip.GzipFile(fileobj=packed, mode="wb", mtime=epoch, compresslevel=9) as gz:
            gz.write(changelog.encode())
        tree.add(doc + "changelog.Debian.gz", packed.getvalue())
        tree.finish()
        debian = root / "DEBIAN"
        debian.mkdir()
        sums = "".join("%s  %s\n" % (hashlib.md5((root / p[1:]).read_bytes()).hexdigest(), p[1:]) for p in sorted(tree.files))
        (debian / "md5sums").write_text(sums)
        conffiles = [p for p, meta in tree.files.items() if meta["config"]]
        if conffiles:
            (debian / "conffiles").write_text("\n".join(conffiles) + "\n")
        installed = sum(m["size"] for m in tree.files.values()) // 1024 + 1
        (debian / "control").write_text(deb_control(version, deb_arch, installed))
        for script in ("postinst", "prerm", "postrm"):
            shutil.copyfile(PKG / "debian" / script, debian / script)
            os.chmod(debian / script, 0o755)
        for p in debian.iterdir():
            os.utime(p, (epoch, epoch))
        os.chmod(debian, 0o755)
        out = outdir / ("secblitz_%s_%s.deb" % (version, deb_arch))
        env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch))
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", "-Zxz", str(root), str(out)], check=True, env=env,
                       stdout=subprocess.DEVNULL)
    return out


def rpm_files_section(tree):
    lines = []
    for path, meta in sorted(tree.files.items()):
        attr = "%%attr(%04o,root,root) " % meta["mode"]
        if meta["config"]:
            prefix = "%config(noreplace) "
        elif path.startswith("/usr/share/licenses/"):
            prefix = "%license "
        else:
            prefix = ""
        lines.append(prefix + attr + path)
    return "\n".join(lines)


def build_rpm(version, binary, outdir, rpm_arch, key_armored, epoch):
    outdir = Path(outdir).resolve()
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        stage_dir = work / "stage"
        tree = stage(stage_dir, version, binary, key_armored, epoch, "rpm")
        tree.add("usr/share/licenses/secblitz/LICENSE", ROOT / "LICENSE")
        tree.finish()
        spec = (PKG / "rpm" / "secblitz.spec.in").read_text(encoding="utf-8")
        rpmdate = time.strftime("%a %b %d %Y", time.gmtime(epoch))
        for key, value in {"@VERSION@": version, "@ARCH@": rpm_arch, "@STAGE@": "/stage",
                           "@FILES@": rpm_files_section(tree), "@RPMDATE@": rpmdate}.items():
            spec = spec.replace(key, value)
        (work / "secblitz.spec").write_text(spec, encoding="utf-8")
        out_dir = work / "out"
        out_dir.mkdir()
        script = (
            "set -euo pipefail\n"
            "dnf -y -q install rpm-build >/dev/null\n"
            "rpmbuild -bb --quiet --define '_topdir /tmp/rpmbuild' --define '_rpmdir /out' "
            "--define '_binary_payload w19.zstdio' --define 'use_source_date_epoch_as_buildtime 1' "
            "--define 'clamp_mtime_to_source_date_epoch 1' /spec/secblitz.spec\n"
            "chown -R %d:%d /out\n" % (os.getuid(), os.getgid())
        )
        result = subprocess.run(
            ["docker", "run", "--rm", "-e", "SOURCE_DATE_EPOCH=%d" % epoch, "-v", "%s:/stage:ro" % stage_dir,
             "-v", "%s:/spec:ro" % work, "-v", "%s:/out" % out_dir, RPM_IMAGE, "bash", "-c", script],
            capture_output=True, text=True)
        if result.returncode != 0:
            die("rpmbuild failed:\n" + result.stdout[-2000:] + result.stderr[-2000:])
        built = list(out_dir.rglob("*.rpm"))
        if len(built) != 1:
            die("rpmbuild did not produce exactly one package")
        out = outdir / built[0].name
        shutil.copyfile(built[0], out)
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version")
    parser.add_argument("binary")
    parser.add_argument("outdir")
    parser.add_argument("--arch", choices=sorted(ARCHES), default="x86_64")
    parser.add_argument("--key", help="the owner's public signing key, ASCII armored")
    parser.add_argument("--without-repository", action="store_true",
                        help="leave the repository entry and key out (test builds only)")
    parser.add_argument("--skip-glibc-check", action="store_true", help="for placeholder binaries in tests")
    parser.add_argument("--build-binary", action="store_true", help="compile BINARY inside debian:12 first")
    parser.add_argument("--formats", default="deb,rpm")
    args = parser.parse_args(argv)

    if not re.fullmatch(r"\d+\.\d+\.\d+", args.version):
        die("VERSION must look like 1.2.3")
    if args.build_binary:
        build_binary(args.binary, args.arch)
    binary = Path(args.binary)
    if not binary.is_file():
        die("binary not found: %s" % binary)
    if not args.skip_glibc_check:
        check_glibc(binary)
    key = None
    if not args.without_repository:
        if not args.key:
            die("give --key with the public signing key, or --without-repository for a test build")
        key = Path(args.key).read_bytes()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", time.time()))
    deb_arch, rpm_arch = ARCHES[args.arch]
    formats = args.formats.split(",")
    for fmt in formats:
        if fmt == "deb":
            print(build_deb(args.version, binary, outdir, deb_arch, key, epoch))
        elif fmt == "rpm":
            print(build_rpm(args.version, binary, outdir, rpm_arch, key, epoch))
        else:
            die("unknown format " + fmt)


if __name__ == "__main__":
    main()
