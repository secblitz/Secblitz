#!/usr/bin/env python3
"""The files a release build produces for a version.

    release-files.py VERSION               print the file names, one per line
    release-files.py VERSION --check DIR   fail unless DIR holds exactly these files

Releases from 1.5.0 on also carry the Linux packages.
"""
import argparse
from pathlib import Path
import re
import sys

LINUX_FROM = (1, 5, 0)
WINDOWS = ("windows-x64.exe", "windows-x64-setup.exe", "windows-arm64.exe", "windows-arm64-setup.exe")
PARTS_LISTS = ("windows-x64.cdx.json", "windows-arm64.cdx.json")
LINUX = ("linux-x64.deb", "linux-x64.rpm", "linux-arm64.deb", "linux-arm64.rpm")


def parse(version):
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        raise ValueError("VERSION must look like 1.2.3")
    return tuple(int(part) for part in match.groups())


def programs(version):
    """The files listed in SHA256SUMS."""
    return ["secblitz-%s-%s" % (version, suffix) for suffix in WINDOWS]


def linux_packages(version):
    if parse(version) < LINUX_FROM:
        return []
    return ["secblitz-%s-%s" % (version, suffix) for suffix in LINUX]


def release_files(version):
    parts = ["secblitz-%s-%s" % (version, suffix) for suffix in PARTS_LISTS]
    return sorted(programs(version) + linux_packages(version) + parts + ["SHA256SUMS"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version")
    parser.add_argument("--check", metavar="DIR")
    args = parser.parse_args(argv)
    try:
        expected = release_files(args.version)
    except ValueError as error:
        parser.error(str(error))
    if args.check is None:
        print("\n".join(expected))
        return 0
    found = sorted(p.name for p in Path(args.check).iterdir())
    if found != expected:
        print("missing: %s" % ", ".join(sorted(set(expected) - set(found))), file=sys.stderr)
        print("unexpected: %s" % ", ".join(sorted(set(found) - set(expected))), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
