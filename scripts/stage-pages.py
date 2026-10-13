#!/usr/bin/env python3
"""Build an allowlisted Pages directory; no credentials, signing or deployment.

Run after prepare-pages.py --require-feed. Source documentation/tests are kept.
Only a successful exit authorizes the operator to deploy the resulting snapshot.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import struct
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prepare_pages", ROOT / "scripts/prepare-pages.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

STATIC = (
    "index.html", "404.html", "privacy.html", "code-signing.html", "styles.css", "app.js", "theme.js", "_headers", "releases/stable.json", "releases/stable-arm64.json",
    "assets/favicon.svg", "assets/preview-92912b03eb97.webp",
    "assets/app-home-light.webp", "assets/app-home-dark.webp",
    "assets/app-protection-light.webp", "assets/app-protection-dark.webp", "assets/intro-ccc7b9cf66d0.mp4",
    "assets/fonts/ibm-plex-sans-400.woff2", "assets/fonts/ibm-plex-sans-500.woff2",
    "assets/fonts/ibm-plex-sans-600.woff2", "assets/fonts/IBMPlexSans-LICENSE.txt",
)
FONT_LICENSES = ("assets/fonts/OFL.txt", "assets/fonts/LICENSE.txt")
LEGACY_ASSETS = {
    "assets/poster.webp", "assets/preview-33b342ab21fb.webp", "assets/secblitz-demo.mp4", "assets/intro-6bb434a9c067.mp4",
    "assets/secblitz.svg", "assets/fonts/schibsted-grotesk-latin.woff2", "assets/fonts/OFL.txt",
    "assets/intro-a18b68fac12f.mp4", "assets/intro-a8f1e9ace5d9.webm", "assets/intro-909e4b4d6414.mp4",
    "assets/preview-541ff80cb74f.webp", "assets/home-dark-1215a72074e4.webp", "assets/preview-b081691b149a.webp",
}
HISTORICAL = (
    "secblitz-0.9.2-windows-x64-setup.exe",
    "secblitz-0.9.3-windows-x64-setup.exe",
    "secblitz-0.11.0-windows-x64-setup.exe",
    "secblitz-0.11.0-windows-arm64-setup.exe",
    "secblitz-0.11.1-windows-x64-setup.exe",
    "secblitz-0.11.1-windows-arm64-setup.exe",
    "secblitz-1.0.0-windows-x64-setup.exe",
    "secblitz-1.0.0-windows-arm64-setup.exe",
)


def plain_path(path):
    """Reject symlinks in every existing component without resolving them away."""
    path = Path(os.path.abspath(path))
    for component in (*reversed(path.parents), path):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symlink in release path (path suppressed)")
    return path


def read_file(path, limit=gate.LIMIT):
    path = plain_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise ValueError("release input must be a bounded regular single-link file (path suppressed)")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1):
            raise ValueError("release input changed during open")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if (len(data) > limit or len(data) != opened.st_size
            or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
            != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise ValueError("release input changed during read or exceeds size limit")
    return data


def check_content(relative, data):
    if gate.SECRET_MARKERS.search(data) or gate.SECRET_MARKERS.search(data.replace(b"\x00", b"")):
        raise ValueError("potential secret in release input (content and path suppressed)")
    hashed_asset = re.fullmatch(r"assets/(?:intro|preview)-([0-9a-f]{12})\.(?:mp4|webm|webp)", relative)
    if hashed_asset and not hashlib.sha256(data).hexdigest().startswith(hashed_asset[1]):
        raise ValueError("media bytes do not match the content-hashed filename")
    if relative.endswith(".exe"):
        if len(data) < 64 or data[:2] != b"MZ":
            raise ValueError("download is not a PE image")
        offset = struct.unpack_from("<I", data, 60)[0]
        if offset < 64 or offset + 26 > len(data) or data[offset:offset + 4] != b"PE\0\0":
            raise ValueError("download has an invalid PE header")
        machine = struct.unpack_from("<H", data, offset + 4)[0]
        magic = struct.unpack_from("<H", data, offset + 24)[0]
        if (machine, magic) not in ((0x14c, 0x10b), (0x8664, 0x20b), (0xaa64, 0x20b)):
            raise ValueError("download is not a supported Windows PE image")
        if not relative.endswith("-setup.exe") and machine != (0xaa64 if "-windows-arm64" in relative else 0x8664):
            raise ValueError("portable download does not match its architecture")
    elif relative.endswith(".woff2"):
        if len(data) < 48 or data[:4] != b"wOF2" or struct.unpack_from(">I", data, 8)[0] != len(data):
            raise ValueError("invalid WOFF2 font")
    elif relative.endswith(".webp"):
        if data[:4] != b"RIFF" or data[8:12] != b"WEBP":
            raise ValueError("invalid WebP asset")
    elif relative.endswith(".mp4"):
        if data[4:8] != b"ftyp":
            raise ValueError("invalid MP4 asset")
    elif relative.endswith(".webm"):
        if data[:4] != b"\x1a\x45\xdf\xa3" or b"webm" not in data[:64]:
            raise ValueError("invalid WebM asset")
    else:
        data.decode("utf-8", errors="strict")


def allowed_files(version):
    if not re.fullmatch(gate.VERSION, version):
        raise ValueError("expected version must be canonical X.Y.Z")
    downloads = (*HISTORICAL, *(f"secblitz-{version}-{info['tag']}-setup.exe" for info in gate.ARCHES.values()))
    return set(STATIC) | {"downloads/" + name for name in downloads}


def validate_snapshot(site, version, origin, references):
    payload = gate.verify_feed(site, version)
    arm_payload = gate.verify_feed(site, version, arch="arm64")
    gate.verify_site_references(site, origin, version, payload, arm_payload)
    gate.verify_not_found_page(site)
    css = (site / "styles.css").read_text(encoding="utf-8")
    if "\\" in css or re.search(r"@import\b", css, re.I):
        raise ValueError("CSS imports/escapes require explicit staging review")
    for match in re.finditer(r"url\(\s*(['\"]?)([^)'\"]+)\1\s*\)", css, re.I):
        url = gate.urlsplit(match[2].strip())
        if url.scheme or url.netloc:
            raise ValueError("CSS assets must be local")
        relative = gate.local_reference(url.path)
        if not (site / relative).is_file():
            raise ValueError("CSS references an unstaged asset")
    for filename, reference in references.items():
        expected = read_file(reference)
        check_content(filename, expected)
        actual = read_file(site / "downloads" / filename)
        if hashlib.sha256(actual).digest() != hashlib.sha256(expected).digest():
            raise ValueError("download differs from final build reference")


def check_existing_output(output, allowed):
    directories = {parent.as_posix() for name in allowed for parent in Path(name).parents if str(parent) != "."}
    for path in output.rglob("*"):
        relative = path.relative_to(output).as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode) and relative in directories:
            continue
        if relative not in allowed or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("existing staging output has unrecognized objects; choose a fresh output directory")


def stage(source, output, version, reference_dir):
    if any(".." in p.parts for p in (source, output, reference_dir)):
        raise ValueError("directory arguments must not contain traversal components")
    source, output, reference_dir = map(plain_path, (source, output, reference_dir))
    if (output.is_relative_to(source) or source.is_relative_to(output)
            or reference_dir.is_relative_to(output)):
        raise ValueError("staging output must not overlap source or contain build references")
    names = allowed_files(version)
    for name in FONT_LICENSES:
        if os.path.lexists(source / name):
            names.add(name)
    if len(names) > 64:
        raise ValueError("staging file budget exceeded")
    origin = gate.origin_value((ROOT / "assets/update-origin.txt").read_text().strip())
    if output.exists():
        if not output.is_dir():
            raise ValueError("staging output must be a directory")
        check_existing_output(output, names | set(FONT_LICENSES) | LEGACY_ASSETS)
    output.parent.mkdir(parents=True, exist_ok=True)
    references = {
        f"secblitz-{version}-{info['tag']}-setup.exe": reference_dir / f"secblitz-{version}-{info['tag']}-setup.exe"
        for info in gate.ARCHES.values()
    }
    with tempfile.TemporaryDirectory(prefix=".pages-stage-", dir=output.parent) as temporary:
        work = Path(temporary)
        snapshot = work / "site"
        snapshot.mkdir()
        for name in sorted(names):
            data = read_file(source / name, 16384 if name.startswith("releases/") else gate.LIMIT)
            check_content(name, data)
            dest = snapshot / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            dest.chmod(0o644)
        validate_snapshot(snapshot, version, origin, references)
        if output.exists():
            output.rename(work / "previous")
        try:
            snapshot.rename(output)
        except OSError:
            if (work / "previous").exists():
                (work / "previous").rename(output)
            raise
    print(f"Staged {len(names)} allowlisted files. No deployment performed.")
    return names


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=ROOT / "website")
    parser.add_argument("--output", type=Path, default=ROOT / "dist/pages")
    parser.add_argument("--reference-dir", type=Path, default=ROOT / "dist", help="final installer build directory")
    parser.add_argument("--expected-version", required=True)
    args = parser.parse_args()
    stage(args.source, args.output, args.expected_version, args.reference_dir)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        message = str(exc) if type(exc) is ValueError else "input, signature or filesystem validation failed"
        raise SystemExit(f"Staging failed: {message}")
