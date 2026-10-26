#!/usr/bin/env python3
"""After a deploy, prove the live website serves exactly the bytes that were deployed.

    verify-live-site.py --site dist/pages --version 0.8.1 [--origin https://example.org ...]
        [--feed-origin https://legacy.example ...]

Fetches, from the live origin (default: the update origin compiled into the app,
assets/update-origin.txt), the signed feeds (releases/stable.json and stable-arm64.json), the download
page (/) and both setups, and from 1.5.0 also install.sh, the four Linux feeds and
the four Linux packages, and compares the SHA-256 of each with
the staged file that was deployed. A fresh deploy can take a short while to
reach every edge, so a mismatch is retried (--attempts, --delay) and only then
fails, loudly, with exit code 1. A --feed-origin, such as a legacy update host
whose front page redirects to the main site, is checked only for the files
installed copies download from it: the Windows feeds and the setups.
Read only: no credentials, no writes.
Standard library only.
"""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 25 * 1024 * 1024
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", re.ASCII)


class LiveError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch(url):
    if not url.startswith("https://"):
        raise LiveError("Live checks use HTTPS only.")
    request = urllib.request.Request(url, headers={"Cache-Control": "no-cache", "Pragma": "no-cache",
                                                   "User-Agent": "secblitz-release-pipeline"})
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=120) as response:
            if response.status != 200:
                raise LiveError(f"{url} answered {response.status}.")
            data = response.read(LIMIT + 1)
    except (urllib.error.URLError, OSError) as err:
        raise LiveError(f"Could not fetch {url}: {err}") from err
    if len(data) > LIMIT:
        raise LiveError(f"{url} is larger than 25 MiB.")
    return data


def gate():
    spec = importlib.util.spec_from_file_location("prepare_pages", ROOT / "scripts/prepare-pages.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expected_files(site, version):
    files = {
        "/releases/stable.json": site / "releases/stable.json",
        "/releases/stable-arm64.json": site / "releases/stable-arm64.json",
        "/": site / "index.html",
    }
    for arch in ("x64", "arm64"):
        setup = f"secblitz-{version}-windows-{arch}-setup.exe"
        files[f"/downloads/{setup}"] = site / "downloads" / setup
    pages = gate()
    if pages.has_linux(version):
        files["/install.sh"] = site / "install.sh"
        for (arch, kind), package in pages.linux_package_names(version).items():
            files[f"/downloads/{package}"] = site / "downloads" / package
            files["/" + pages.PACKAGES[arch]["feeds"][kind]] = site / pages.PACKAGES[arch]["feeds"][kind]
    return files


def first_difference(deployed, served, context=80):
    """Where a served text page stops matching, so edge rewriting shows in the log."""
    at = next((i for i, (a, b) in enumerate(zip(deployed, served)) if a != b), min(len(deployed), len(served)))
    start = max(0, at - context // 4)
    return (f"first difference at byte {at}: deployed {deployed[start:at + context]!r}, "
            f"served {served[start:at + context]!r}")


def check_origin(origin, files, fetcher, attempts, delay, sleep=time.sleep):
    problems = {}
    for path, local in files.items():
        deployed = local.read_bytes()
        want = hashlib.sha256(deployed).hexdigest()
        for attempt in range(1, attempts + 1):
            try:
                served = fetcher(origin + path)
                got = hashlib.sha256(served).hexdigest()
                error = None if got == want else f"served SHA-256 {got}, deployed {want}"
                if error and not path.startswith("/downloads/"):
                    error += "; " + first_difference(deployed, served)
            except LiveError as err:
                error = str(err)
            if error is None:
                print(f"OK    {origin}{path}  {want}")
                problems.pop(path, None)
                break
            problems[path] = error
            if attempt < attempts:
                sleep(delay)
    return [f"{origin}{path}: {error}" for path, error in problems.items()]


def main(argv=None, fetcher=fetch, sleep=time.sleep):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--site", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--origin", action="append", default=[], help="live origin to check (repeatable)")
    parser.add_argument("--feed-origin", action="append", default=[], help="origin that serves only the feed and downloads (repeatable)")
    parser.add_argument("--attempts", type=int, default=30)
    parser.add_argument("--delay", type=float, default=10)
    args = parser.parse_args(argv)
    if not VERSION.fullmatch(args.version) or args.attempts < 1:
        parser.error("version must be plain X.Y.Z and attempts at least 1")
    pages = gate()
    origins = [pages.origin_value(o) for o in args.origin]
    if not origins:
        origins = [pages.origin_value((ROOT / "assets/update-origin.txt").read_text(encoding="utf-8").strip())]
    files = expected_files(args.site, args.version)
    feed_files = {path: local for path, local in files.items() if path != "/" and "linux" not in path and path != "/install.sh"}
    failures = []
    for origin in origins:
        failures += check_origin(origin, files, fetcher, args.attempts, args.delay, sleep)
    for origin in (pages.origin_value(o) for o in args.feed_origin):
        failures += check_origin(origin, feed_files, fetcher, args.attempts, args.delay, sleep)
    if failures:
        print("LIVE SITE DOES NOT MATCH THE DEPLOYED FILES:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(f"The live site serves exactly the deployed files for {args.version}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
