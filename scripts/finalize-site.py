#!/usr/bin/env python3
"""Write the released installer's checksum and size into a staged copy of the site.

    finalize-site.py --site build/site --version 0.8.1 --setup assets/secblitz-0.8.1-windows-x64-setup.exe \\
        --setup-arm64 assets/secblitz-0.8.1-windows-arm64-setup.exe

website/index.html in git cannot hold the checksum: the installer is built after
the version bump, so the page carries a placeholder. At publish time, after the
installer has passed its checksum and attestation checks, this copies the real
SHA-256 and size into the staged copy (never into git). prepare-pages.py then
proves the page, the installer and the signed feed all agree.

From 1.5.0 the release also carries the four Linux packages. With --packages DIR
(a folder holding secblitz-X.Y.Z-linux-{x64,arm64}.{deb,rpm}) the same step writes
the version and each package's SHA-256 into the staged install.sh, so the one-line
installer pins exactly the files that were verified.

Standard library only. Writes only inside --site.
"""
import argparse
import hashlib
from pathlib import Path
import re
import sys

VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", re.ASCII)
SHA_ELEMENT = re.compile(r'(<code id="sha">)[0-9a-f]{64}(</code>)')
SHA_ARM_ELEMENT = re.compile(r'(<code id="sha-arm64">)[0-9a-f]{64}(</code>)')
DETAILS = re.compile(r"(<p>Version )(\d+\.\d+\.\d+)( · )[0-9.]+( MB installer</p>)")
ARM_DETAILS = re.compile(r"(<p>ARM version · )[0-9.]+( MB installer</p>)")
LIMIT = 25 * 1024 * 1024
LINUX_PLACEHOLDERS = {
    ("x64", "deb"): "@SHA256_X64_DEB@", ("x64", "rpm"): "@SHA256_X64_RPM@",
    ("arm64", "deb"): "@SHA256_ARM64_DEB@", ("arm64", "rpm"): "@SHA256_ARM64_RPM@",
}


class FinalizeError(Exception):
    pass


def finalize_html(html, version, digest, size, arm_digest=None, arm_size=None):
    html, count = SHA_ELEMENT.subn(lambda m: m[1] + digest + m[2], html)
    if count != 1:
        raise FinalizeError(f"index.html: expected exactly one checksum element, found {count}.")
    megabytes = f"{size / 1_000_000:.1f}"

    def details(match):
        if match[2] != version:
            raise FinalizeError(f"index.html shows version {match[2]}, expected {version}.")
        return match[1] + version + match[3] + megabytes + match[4]

    html, count = DETAILS.subn(details, html)
    if count != 1:
        raise FinalizeError(f"index.html: expected exactly one 'Version X · N MB installer' line, found {count}.")
    if arm_digest is not None:
        html, count = SHA_ARM_ELEMENT.subn(lambda m: m[1] + arm_digest + m[2], html)
        if count != 1:
            raise FinalizeError(f"index.html: expected exactly one ARM checksum element, found {count}.")
        html, count = ARM_DETAILS.subn(lambda m: m[1] + f"{arm_size / 1_000_000:.1f}" + m[2], html)
        if count != 1:
            raise FinalizeError(f"index.html: expected exactly one 'ARM version · N MB installer' line, found {count}.")
    return html


def render_install(template, version, digests):
    """Fill the version and package checksums into install.sh. `digests` maps (arch, kind) to SHA-256."""
    values = {"@SECBLITZ_VERSION@": version}
    values.update({LINUX_PLACEHOLDERS[key]: digest for key, digest in digests.items()})
    if set(values) != {"@SECBLITZ_VERSION@", *LINUX_PLACEHOLDERS.values()}:
        raise FinalizeError("install.sh needs a checksum for each of the four Linux packages.")
    for placeholder, value in values.items():
        if template.count(placeholder) != 1:
            raise FinalizeError(f"install.sh: expected exactly one {placeholder}, found {template.count(placeholder)}.")
        template = template.replace(placeholder, value)
    if re.search(r"@[A-Z0-9_]+@", template):
        raise FinalizeError("install.sh still has a placeholder after filling it in.")
    return template


def linux_digests(directory, version):
    digests = {}
    for (arch, kind) in LINUX_PLACEHOLDERS:
        name = f"secblitz-{version}-linux-{arch}.{kind}"
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise FinalizeError(f"--packages must hold a regular file named {name}.")
        size = path.stat().st_size
        if size > LIMIT:
            raise FinalizeError(f"{name} is {size / 1_048_576:.1f} MiB. Cloudflare Pages cannot host a file over 25 MiB, so this release cannot be published as it is.")
        if size == 0:
            raise FinalizeError(f"{name} is empty.")
        digests[(arch, kind)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--site", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--setup", type=Path, required=True)
    parser.add_argument("--setup-arm64", type=Path)
    parser.add_argument("--packages", type=Path, help="folder with the four Linux packages; fills in install.sh")
    args = parser.parse_args(argv)
    try:
        if not VERSION.fullmatch(args.version):
            raise FinalizeError("Version must be plain X.Y.Z.")
        expected = f"secblitz-{args.version}-windows-x64-setup.exe"
        if args.setup.name != expected or args.setup.is_symlink() or not args.setup.is_file():
            raise FinalizeError(f"--setup must be a regular file named {expected}.")
        data = args.setup.read_bytes()
        if not 0 < len(data) <= LIMIT:
            raise FinalizeError("The installer is empty or larger than 25 MiB.")
        arm = None
        if args.setup_arm64:
            expected_arm = f"secblitz-{args.version}-windows-arm64-setup.exe"
            if args.setup_arm64.name != expected_arm or args.setup_arm64.is_symlink() or not args.setup_arm64.is_file():
                raise FinalizeError(f"--setup-arm64 must be a regular file named {expected_arm}.")
            arm = args.setup_arm64.read_bytes()
            if not 0 < len(arm) <= LIMIT:
                raise FinalizeError("The ARM installer is empty or larger than 25 MiB.")
        page = args.site / "index.html"
        if page.is_symlink() or not page.is_file():
            raise FinalizeError("The site has no index.html.")
        html = finalize_html(page.read_bytes().decode("utf-8"), args.version, hashlib.sha256(data).hexdigest(), len(data),
                         hashlib.sha256(arm).hexdigest() if arm is not None else None, len(arm) if arm is not None else None)
        page.write_bytes(html.encode("utf-8"))
        if args.packages:
            script = args.site / "install.sh"
            if script.is_symlink() or not script.is_file():
                raise FinalizeError("The site has no install.sh.")
            script.write_bytes(render_install(script.read_bytes().decode("utf-8"), args.version,
                                              linux_digests(args.packages, args.version)).encode("utf-8"))
            print(f"install.sh now installs {args.version} and pins the four Linux package checksums.")
        print(f"index.html now shows {args.version}, {len(data) / 1_000_000:.1f} MB, SHA-256 {hashlib.sha256(data).hexdigest()}.")
    except (FinalizeError, OSError, UnicodeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
