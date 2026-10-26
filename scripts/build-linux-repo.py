#!/usr/bin/env python3
"""Build the signed Secblitz APT and DNF repositories from finished packages. Owner's machine only.

    build-linux-repo.py OUTDIR PACKAGE... --local-user KEY_ID

OUTDIR gets apt/ and rpm/ folders ready to publish at https://secblitz.lol/linux/.
The package lists are made inside debian:12 and fedora:44 containers that never
see a key. Signing is done here by calling gpg with the key id you pass; this
script never reads, copies or exports a key file, and it refuses to run in CI
because the signing key must never leave the owner's machine.
"""
import argparse
import gzip
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

APT_IMAGE = "debian:12"
RPM_IMAGE = "fedora:44"
DEB_ARCHES = ("amd64", "arm64")
SUITE = "stable"


def die(message):
    print("error: " + message, file=sys.stderr)
    sys.exit(1)


def refuse_in_ci(environ):
    if environ.get("CI") or environ.get("GITHUB_ACTIONS"):
        die("refusing to run in CI: the signing key never leaves the owner's machine")


def gpg_sign_args(local_user):
    return ["gpg", "--batch", "--yes", "--local-user", local_user]


def sign_file(local_user, source, clearsigned=None, detached=None):
    if clearsigned:
        subprocess.run(gpg_sign_args(local_user) + ["--clearsign", "-o", str(clearsigned), str(source)], check=True)
    if detached:
        subprocess.run(gpg_sign_args(local_user) + ["--detach-sign", "--armor", "-o", str(detached), str(source)], check=True)


def run_container(image, mount, script):
    result = subprocess.run(
        ["docker", "run", "--rm", "-v", "%s:/repo" % mount, image, "bash", "-c",
         "set -euo pipefail\n" + script + "\nchown -R %d:%d /repo\n" % (os.getuid(), os.getgid())],
        capture_output=True, text=True)
    if result.returncode != 0:
        die("%s step failed:\n%s%s" % (image, result.stdout[-2000:], result.stderr[-2000:]))


def deb_arch_of(path):
    name = Path(path).name
    for arch in DEB_ARCHES:
        if name.endswith("_%s.deb" % arch):
            return arch
    die("cannot tell the architecture of " + name)


def build_apt(out, debs, local_user):
    apt = Path(out) / "apt"
    if apt.exists():
        shutil.rmtree(apt)
    pool = apt / "pool" / "main" / "s" / "secblitz"
    pool.mkdir(parents=True)
    arches = sorted({deb_arch_of(d) for d in debs})
    for deb in debs:
        shutil.copyfile(deb, pool / Path(deb).name)
    script = (
        "apt-get update -qq >/dev/null\n"
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends apt-utils >/dev/null\n"
        "cd /repo\n"
    )
    for arch in arches:
        script += "mkdir -p dists/{s}/main/binary-{a}\n".format(s=SUITE, a=arch)
        script += "apt-ftparchive --arch {a} packages pool > dists/{s}/main/binary-{a}/Packages\n".format(s=SUITE, a=arch)
        script += "gzip -9nk dists/{s}/main/binary-{a}/Packages\n".format(s=SUITE, a=arch)
    script += (
        "apt-ftparchive -o APT::FTPArchive::Release::Origin=Secblitz -o APT::FTPArchive::Release::Label=Secblitz "
        "-o APT::FTPArchive::Release::Suite={s} -o APT::FTPArchive::Release::Codename={s} "
        "-o APT::FTPArchive::Release::Architectures='{a}' -o APT::FTPArchive::Release::Components=main "
        "release dists/{s} > dists/{s}/Release\n"
    ).format(s=SUITE, a=" ".join(arches))
    run_container(APT_IMAGE, apt, script)
    release = apt / "dists" / SUITE / "Release"
    sign_file(local_user, release, clearsigned=apt / "dists" / SUITE / "InRelease",
              detached=apt / "dists" / SUITE / "Release.gpg")
    return apt


def build_rpm(out, rpms, local_user):
    rpm = Path(out) / "rpm"
    if rpm.exists():
        shutil.rmtree(rpm)
    arches = set()
    for pkg in rpms:
        arch = Path(pkg).name.rsplit(".", 2)[-2]
        if arch not in ("x86_64", "aarch64"):
            die("cannot tell the architecture of " + Path(pkg).name)
        (rpm / arch).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(pkg, rpm / arch / Path(pkg).name)
        arches.add(arch)
    script = "dnf -y -q install createrepo_c >/dev/null\n"
    for arch in sorted(arches):
        script += "createrepo_c --quiet /repo/%s\n" % arch
    run_container(RPM_IMAGE, rpm, script)
    for arch in sorted(arches):
        repomd = rpm / arch / "repodata" / "repomd.xml"
        sign_file(local_user, repomd, detached=rpm / arch / "repodata" / "repomd.xml.asc")
    return rpm


def main(argv=None, environ=None):
    refuse_in_ci(os.environ if environ is None else environ)
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("outdir")
    parser.add_argument("packages", nargs="+")
    parser.add_argument("--local-user", required=True, help="the id of the signing key in your gpg keyring")
    args = parser.parse_args(argv)
    debs = [p for p in args.packages if p.endswith(".deb")]
    rpms = [p for p in args.packages if p.endswith(".rpm")]
    if len(debs) + len(rpms) != len(args.packages):
        die("only .deb and .rpm files are accepted")
    for p in args.packages:
        if not Path(p).is_file():
            die("not found: " + p)
    out = Path(args.outdir)
    out.mkdir(parents=True, exist_ok=True)
    if debs:
        print(build_apt(out, debs, args.local_user))
    if rpms:
        print(build_rpm(out, rpms, args.local_user))


if __name__ == "__main__":
    main()
