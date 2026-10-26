#!/usr/bin/env python3
"""Move every place that carries the Secblitz version to a new version.

    python3 scripts/bump-version.py 0.8.1 [--dry-run] [--site] [--date YYYY-MM-DD]

Updates Cargo.toml, the secblitz entry in Cargo.lock, assets/secblitz.rc (both
numeric and text versions), assets/secblitz.manifest, and moves the
"Unreleased" section of CHANGELOG.md into a new dated section. It also moves
every version string and download link on the website (website/index.html and
any other text file under website/, including structured data such as
softwareVersion) and in README.md to the new version, resets the checksum on the
page to a placeholder (the real one is written at deploy time by
finalize-site.py) and adds the version being replaced to the HISTORICAL
download list in scripts/stage-pages.py. Nothing reaches the live website until
publish-website.yml deploys the published release.
With --site-only it changes just the website files and README.md, for a version
that Cargo.toml already has. With --check-site it changes nothing and fails
when the website or README still show any other version (release.yml runs it).

The new version must be greater than the current one. One exception: when
CHANGELOG.md has "## [X] - Unreleased" for the version already in Cargo.toml
(the version being developed), `bump-version.py X` only dates that section.

Nothing is written unless every file was processed without error, and
--dry-run writes nothing at all. Standard library only.
"""
import argparse
import datetime
import os
import re
import sys
import tempfile
from pathlib import Path

VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)


class BumpError(Exception):
    pass


def parse(version):
    m = VERSION.fullmatch(version)
    if not m:
        raise BumpError(f"'{version}' is not a plain major.minor.patch version (for example 0.8.1).")
    return tuple(int(x) for x in m.groups())


def read(root, rel):
    path = root / rel
    try:
        return path.read_bytes().decode("utf-8")
    except OSError as err:
        raise BumpError(f"Cannot read {rel}: {err.strerror}") from err


def sub_once(text, pattern, repl, rel, flags=0):
    new, count = re.subn(pattern, repl, text, count=0, flags=flags)
    if count != 1:
        raise BumpError(f"{rel}: expected exactly one match for {pattern!r}, found {count}.")
    return new


def current_version(root):
    text = read(root, "Cargo.toml")
    m = re.search(r'^\[package\]\s*$(.*?)(?=^\[|\Z)', text, re.M | re.S)
    v = re.search(r'^version\s*=\s*"([^"]+)"', m.group(1), re.M) if m else None
    if not v:
        raise BumpError("Cargo.toml has no package version.")
    parse(v.group(1))
    return v.group(1)


def bump_cargo_toml(text, old, new):
    def fix(m):
        body, n = re.subn(r'^(version\s*=\s*)"' + re.escape(old) + '"', r'\g<1>"' + new + '"', m.group(2), count=1, flags=re.M)
        if n != 1:
            raise BumpError("Cargo.toml: package version line not found.")
        return m.group(1) + body
    out, n = re.subn(r'(^\[package\]\s*$)(.*?)(?=^\[|\Z)', fix, text, count=1, flags=re.M | re.S)
    if n != 1:
        raise BumpError("Cargo.toml: [package] section not found.")
    return out


def bump_cargo_lock(text, old, new):
    return sub_once(text, r'(\[\[package\]\]\r?\nname = "secblitz"\r?\nversion = ")' + re.escape(old) + '"',
                    r'\g<1>' + new + '"', "Cargo.lock")


def bump_rc(text, old, new):
    o = ",".join(old.split(".")) + ",0"
    n = ",".join(new.split(".")) + ",0"
    for key in ("FILEVERSION", "PRODUCTVERSION"):
        text = sub_once(text, r'^(' + key + r' )' + re.escape(o) + r'$', r'\g<1>' + n, "assets/secblitz.rc", re.M)
    for key in ("FileVersion", "ProductVersion"):
        text = sub_once(text, r'(VALUE "' + key + r'", ")' + re.escape(old) + '"', r'\g<1>' + new + '"', "assets/secblitz.rc")
    return text


def bump_manifest(text, old, new):
    return sub_once(text, r'(<assemblyIdentity version=")' + re.escape(old) + r'\.0"', r'\g<1>' + new + '.0"',
                    "assets/secblitz.manifest")


def site_version(readme):
    m = re.search(r"downloads/secblitz-(" + VERSION.pattern + r")-windows-x64-setup\.exe", readme)
    return m.group(1) if m else None


SITE_SUFFIXES = {".html", ".js", ".json", ".xml", ".txt", ".webmanifest", ".md"}
SHA_PLACEHOLDER = "0" * 64
SHA_ELEMENT = re.compile(r'(<code id="sha">)[0-9a-f]{64}(</code>)')
SHA_ARM_ELEMENT = re.compile(r'(<code id="sha-arm64">)[0-9a-f]{64}(</code>)')
FIRST_ARM64 = (0, 11, 0)


def site_text_files(root):
    """Text files whose version strings move with a release (README plus website/)."""
    found = ["README.md"]
    base = root / "website"
    if base.is_dir():
        for path in sorted(base.rglob("*")):
            rel = path.relative_to(root).as_posix()
            if (path.is_file() and not path.is_symlink() and path.suffix.lower() in SITE_SUFFIXES
                    and not rel.startswith(("website/releases/", "website/assets/"))):
                found.append(rel)
    return found


def site_patterns(old, new):
    return [
        (r"secblitz-" + re.escape(old) + r"-(windows|linux)-(x64|arm64)", r"secblitz-" + new + r"-\g<1>-\g<2>"),
        (r"Version " + re.escape(old) + r"\b", "Version " + new),
        (r"version-" + re.escape(old) + r"-", "version-" + new + "-"),
        (r'("softwareVersion"\s*:\s*")' + re.escape(old) + '"', r'\g<1>' + new + '"'),
    ]


def bump_site_text(text, old, new, rel, required=True):
    """Download links, 'Version X' text, the version badge and structured data, nothing else."""
    n_total = 0
    for pat, rep in site_patterns(old, new):
        text, n = re.subn(pat, rep, text)
        n_total += n
    if rel.endswith(".html"):
        text = SHA_ELEMENT.sub(lambda m: m[1] + SHA_PLACEHOLDER + m[2], text)
        text = SHA_ARM_ELEMENT.sub(lambda m: m[1] + SHA_PLACEHOLDER + m[2], text)
    if n_total == 0 and required:
        raise BumpError(f"{rel}: no mention of version {old} found.")
    return text


def check_site(root, version):
    """Return a list of problems: any version on the site or README other than `version`."""
    problems = []
    seen_download = False
    for rel in site_text_files(root):
        text = read(root, rel)
        found = []
        for pat in (r"secblitz-(" + VERSION.pattern + r")-(?:windows|linux)-(?:x64|arm64)", r"Version (" + VERSION.pattern + r")\b",
                    r"version-(" + VERSION.pattern + r")-", r'"softwareVersion"\s*:\s*"(' + VERSION.pattern + r')"'):
            found += [m.group(1) for m in re.finditer(pat, text)]
        seen_download = seen_download or bool(re.search(r"downloads/secblitz-" + VERSION.pattern + r"-windows-(?:x64|arm64)-setup\.exe", text))
        for shown in sorted(set(found) - {version}):
            problems.append(f"{rel} still shows version {shown}, the release is {version}.")
    if not seen_download:
        problems.append("No setup download link found on the website or in README.md.")
    index = read(root, "website/index.html")
    if len(SHA_ELEMENT.findall(index)) != 1:
        problems.append('website/index.html must have exactly one <code id="sha"> with a 64-digit checksum.')
    if len(SHA_ARM_ELEMENT.findall(index)) != 1:
        problems.append('website/index.html must have exactly one <code id="sha-arm64"> with a 64-digit checksum.')
    for arch in ("x64", "arm64"):
        if not re.search(r"downloads/secblitz-" + re.escape(version) + rf"-windows-{arch}-setup\.exe", index):
            problems.append(f"website/index.html does not link the {version} {arch} setup.")
    return problems


def add_historical(text, old):
    """Add the replaced version's setup to HISTORICAL in stage-pages.py. The
    portable exe is too big for Pages, so it is offered on GitHub only."""
    archs = ["x64"] + (["arm64"] if parse(old) >= FIRST_ARM64 else [])
    setups = [f"secblitz-{old}-windows-{arch}-setup.exe" for arch in archs]
    m = re.search(r"(HISTORICAL = \(\n)(.*?)(\n\)\n)", text, re.S)
    if not m:
        raise BumpError("scripts/stage-pages.py: HISTORICAL list not found.")
    added = "".join(f'\n    "{setup}",' for setup in setups if f'"{setup}"' not in text)
    return text[:m.end(2)] + added + text[m.end(2):]


HEADING = re.compile(r"^## \[([^\]]+)\](?: - (.*))?[ \t]*$", re.M)


def changelog_sections(text):
    """Return a list of (name, label, start, end) for each '## [..]' section."""
    heads = list(HEADING.finditer(text))
    out = []
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(text)
        out.append((h.group(1), (h.group(2) or "").strip(), h.start(), end))
    return out


def bump_changelog(text, old, new, today, allow_empty, warnings):
    sections = changelog_sections(text)
    by_name = {s[0]: s for s in sections}
    if new in by_name:
        name, label, start, end = by_name[new]
        if label.lower() != "unreleased" or new != old:
            raise BumpError(f"CHANGELOG.md already has a section for {new}.")
        body = text[start:end]
        if not re.search(r"^- ", body, re.M):
            raise BumpError(f"CHANGELOG.md section {new} has no entries.")
        return text[:start] + f"## [{new}] - {today}\n" + text[start:end].split("\n", 1)[1] + text[end:]
    if "Unreleased" not in by_name:
        raise BumpError("CHANGELOG.md has no '## [Unreleased]' section.")
    name, label, start, end = by_name["Unreleased"]
    body = text[start:end].split("\n", 1)[1] if "\n" in text[start:end] else ""
    if not re.search(r"^- ", body, re.M):
        if not allow_empty:
            raise BumpError("CHANGELOG.md: nothing under Unreleased. Write the release notes first (or pass --allow-empty).")
        warnings.append("CHANGELOG.md: the Unreleased section is empty; the new section has no entries.")
    pending = by_name.get(old)
    if pending and pending[1].lower() == "unreleased":
        warnings.append(f"CHANGELOG.md: version {old} is still marked Unreleased. Release it first with: bump-version.py {old}")
    body = body.strip("\n")
    section = f"## [Unreleased]\n\n## [{new}] - {today}\n" + ("\n" + body + "\n" if body else "") + "\n"
    return text[:start] + section + text[end:]


def plan(root, new, today, site=False, allow_empty=False, site_only=False):
    """Return ({relative path: new text}, [warnings], current version). Reads only."""
    new_t = parse(new)
    old = current_version(root)
    old_t = parse(old)
    changes, warnings = {}, []
    if site_only:
        if new != old:
            raise BumpError(f"--site-only needs the version already in Cargo.toml ({old}).")
        site = True
    changelog = read(root, "CHANGELOG.md")
    dating_only = new == old and any(
        s[0] == new and s[1].lower() == "unreleased" for s in changelog_sections(changelog))
    if new_t <= old_t and not dating_only and not site_only:
        raise BumpError(f"New version {new} must be greater than the current version {old}.")
    if not site_only:
        changes["CHANGELOG.md"] = bump_changelog(changelog, old, new, today, allow_empty, warnings)
    if not dating_only and not site_only:
        changes["Cargo.toml"] = bump_cargo_toml(read(root, "Cargo.toml"), old, new)
        changes["Cargo.lock"] = bump_cargo_lock(read(root, "Cargo.lock"), old, new)
        changes["assets/secblitz.rc"] = bump_rc(read(root, "assets/secblitz.rc"), old, new)
        changes["assets/secblitz.manifest"] = bump_manifest(read(root, "assets/secblitz.manifest"), old, new)
    index = read(root, "website/index.html")
    shown = site_version(index)
    if not shown:
        raise BumpError("website/index.html has no setup download link to update.")
    if parse(shown) > new_t:
        raise BumpError(f"The website already shows {shown}, which is newer than {new}.")
    core = ("README.md", "website/index.html")
    for rel in site_text_files(root):
        text = read(root, rel)
        own = site_version(text)
        if own is None and rel in core:
            raise BumpError(f"{rel} has no setup download link to update.")
        if own is not None and parse(own) > new_t:
            raise BumpError(f"{rel} already shows {own}, which is newer than {new}.")
        if own is not None and parse(own) == new_t:
            continue
        changes[rel] = bump_site_text(text, own or shown, new, rel, required=rel in core)
    if parse(shown) < new_t:
        changes["scripts/stage-pages.py"] = add_historical(read(root, "scripts/stage-pages.py"), shown)
        warnings.append("The size text in README.md (for example '8.2 MB') is not updated. Check it. "
                        "The website's size and checksum are written at deploy time.")
    return {k: v for k, v in changes.items() if v != read(root, k)}, warnings, old


def write_all(root, changes):
    """Write every file through a temp file in the same folder, then rename."""
    staged = []
    try:
        for rel, text in changes.items():
            path = root / rel
            fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".bump-", suffix=".tmp")
            with os.fdopen(fd, "wb") as handle:
                handle.write(text.encode("utf-8"))
            staged.append((tmp, path))
        for tmp, path in staged:
            os.replace(tmp, path)
        staged = []
    finally:
        for tmp, _ in staged:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def main(argv=None):
    ap = argparse.ArgumentParser(description="Bump the Secblitz version everywhere.")
    ap.add_argument("version", help="new version, for example 0.8.1")
    ap.add_argument("--dry-run", action="store_true", help="show what would change, write nothing")
    ap.add_argument("--site", action="store_true", help="kept for old habits: the website and README always move with the version now")
    ap.add_argument("--site-only", action="store_true",
                    help="only move the README and website to the version already in Cargo.toml")
    ap.add_argument("--check-site", action="store_true",
                    help="write nothing; fail when the website or README show a version other than the one given")
    ap.add_argument("--allow-empty", action="store_true", help="allow an empty Unreleased section")
    ap.add_argument("--date", help="release date YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]), help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    today = args.date or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    try:
        datetime.date.fromisoformat(today)
        root = Path(args.root)
        if args.check_site:
            parse(args.version)
            problems = check_site(root, args.version)
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            if not problems:
                print(f"The website and README match version {args.version}.")
            return 1 if problems else 0
        changes, warnings, old = plan(root, args.version, today, args.site, args.allow_empty, args.site_only)
        print(f"Secblitz {old} -> {args.version} ({today})")
        for rel in sorted(changes):
            print(f"  update {rel}")
        for w in warnings:
            print(f"  warning: {w}")
        if args.dry_run:
            print("Dry run: nothing was written.")
            return 0
        write_all(root, changes)
        print("Done. Review with git diff, then open the release pull request.")
        return 0
    except (BumpError, ValueError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
