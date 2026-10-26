#!/usr/bin/env python3
"""Build the exact website tree to deploy from a verified release. Deploys nothing.

    assemble-site.py --version 0.8.1 --assets release-assets --historical historical --output dist/pages

--assets holds the nine release files (already checked against SHA256SUMS, the
build attestations and the pinned update key by publish-website.yml):

    secblitz-X.Y.Z-windows-x64-setup.exe, secblitz-X.Y.Z-windows-x64.exe,
    secblitz-X.Y.Z-windows-arm64-setup.exe, secblitz-X.Y.Z-windows-arm64.exe,
    secblitz-X.Y.Z-windows-x64.cdx.json, secblitz-X.Y.Z-windows-arm64.cdx.json,
    SHA256SUMS, stable.json, stable-arm64.json

From 1.5.0 it also holds the four Linux packages (secblitz-X.Y.Z-linux-{x64,arm64}.{deb,rpm})
and their four signed feeds (stable-linux-{x64,arm64}-{deb,rpm}.json). They go under
downloads/ and releases/, and install.sh gets their version and checksums.

--historical holds the older downloads fetched by historical-downloads.py.
The portable exes are larger than the Pages file limit, so they stay on the GitHub
release and are not copied into the site. The parts lists (.cdx.json) stay there too.
Steps: copy website/ into a scratch tree, add the downloads and the signed
feed, write the real checksum and size into the page (finalize-site.py), run the
release gate (prepare-pages.py --require-feed) and then stage-pages.py, which
copies only allowlisted files. The result is --output, ready for wrangler.
Standard library only. Needs the Python package cryptography for the gate.
"""
import argparse
import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCHES = ("x64", "arm64")
spec = importlib.util.spec_from_file_location("prepare_pages", ROOT / "scripts/prepare-pages.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", re.ASCII)


class AssembleError(Exception):
    pass


def regular_files(directory):
    found = {}
    for path in sorted(directory.iterdir()):
        if path.is_symlink() or not path.is_file():
            raise AssembleError(f"{directory.name}/{path.name} is not a regular file.")
        found[path.name] = path
    return found


def run(*args):
    result = subprocess.run([sys.executable, *map(str, args)], cwd=ROOT, capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    if result.returncode:
        raise AssembleError(f"{Path(str(args[0])).name} failed: {(result.stderr or result.stdout).strip()}")


def assemble(version, assets, historical, output, website=None):
    if not VERSION.fullmatch(version):
        raise AssembleError("Version must be plain X.Y.Z.")
    website = website or ROOT / "website"
    setups = {arch: f"secblitz-{version}-windows-{arch}-setup.exe" for arch in ARCHES}
    portables = {arch: f"secblitz-{version}-windows-{arch}.exe" for arch in ARCHES}
    feeds = {"x64": "stable.json", "arm64": "stable-arm64.json"}
    parts_lists = {f"secblitz-{version}-windows-{arch}.cdx.json" for arch in ARCHES}
    expected = {*setups.values(), *portables.values(), *parts_lists, "SHA256SUMS", *feeds.values()}
    packages = gate.linux_package_names(version) if gate.has_linux(version) else {}
    linux_feeds = {key: Path(gate.PACKAGES[key[0]]["feeds"][key[1]]).name for key in packages}
    expected |= {*packages.values(), *linux_feeds.values()}
    release = regular_files(assets)
    if set(release) != expected:
        raise AssembleError("The release must carry exactly: " + ", ".join(sorted(expected))
                            + ". Found: " + ", ".join(sorted(release)) + ".")
    for name in packages.values():
        size = release[name].stat().st_size
        if size > gate.LIMIT:
            raise AssembleError(f"{name} is {size / 1_048_576:.1f} MiB. Cloudflare Pages cannot host a file over 25 MiB, so this release cannot be published as it is.")
    old = regular_files(historical)
    if set(old) & {*setups.values(), *portables.values(), *packages.values()}:
        raise AssembleError("The historical downloads already contain this version.")
    with tempfile.TemporaryDirectory(prefix="assemble-site-") as scratch:
        scratch = Path(scratch)
        site, reference = scratch / "site", scratch / "reference"
        shutil.copytree(website, site, symlinks=False)
        (site / "downloads").mkdir(exist_ok=True)
        for path in old.values():
            shutil.copyfile(path, site / "downloads" / path.name)
        (site / "releases").mkdir(exist_ok=True)
        reference.mkdir()
        for arch, setup in setups.items():
            shutil.copyfile(release[setup], site / "downloads" / setup)
            shutil.copyfile(release[setup], reference / setup)
            shutil.copyfile(release[feeds[arch]], site / "releases" / feeds[arch])
        for key, package in packages.items():
            shutil.copyfile(release[package], site / "downloads" / package)
            shutil.copyfile(release[package], reference / package)
            shutil.copyfile(release[linux_feeds[key]], site / "releases" / linux_feeds[key])
        run(ROOT / "scripts/finalize-site.py", "--site", site, "--version", version,
            "--setup", release[setups["x64"]], "--setup-arm64", release[setups["arm64"]],
            *(["--packages", assets] if packages else []))
        run(ROOT / "scripts/prepare-pages.py", "--site", site, "--require-feed", "--expected-version", version)
        if output.exists():
            raise AssembleError("The output directory must not exist yet.")
        run(ROOT / "scripts/stage-pages.py", "--source", site, "--output", output,
            "--reference-dir", reference, "--expected-version", version)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--historical", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        assemble(args.version, args.assets, args.historical, args.output.absolute())
    except (AssembleError, OSError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    print(f"Site for {args.version} staged in {args.output}. Nothing was deployed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
