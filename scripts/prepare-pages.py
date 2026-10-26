#!/usr/bin/env python3
"""Validate static Pages output and optionally configure its compiled update origin.

Does not authenticate, create a project, deploy, build, copy installers or sign.
"""
import argparse
import base64
import hashlib
import json
from html.parser import HTMLParser
from pathlib import Path
import re
import stat
import time
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 25 * 1024 * 1024
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
ARCHES = {
    "x64": dict(target="windows-x86_64", tag="windows-x64", feed="releases/stable.json", sha="sha"),
    "arm64": dict(target="windows-aarch64", tag="windows-arm64", feed="releases/stable-arm64.json", sha="sha-arm64"),
}
# Linux and macOS feeds, apart from ARCHES so the Windows download checks never see them.
PACKAGES = {
    "linux-x64": dict(target="linux-x86_64", tag="linux-x64", suffixes=(".deb", ".rpm"), feed="releases/stable-linux-x64.json"),
    "linux-arm64": dict(target="linux-aarch64", tag="linux-arm64", suffixes=(".deb", ".rpm"), feed="releases/stable-linux-arm64.json"),
    "macos": dict(target="macos-universal", tag="macos-universal", suffixes=(".dmg",), feed="releases/stable-macos.json"),
}
SECRET_MARKERS = re.compile(
    rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|[\"']?(?:CLOUDFLARE_API_TOKEN|CLOUDFLARE_API_KEY|CF_API_KEY|CF_API_TOKEN|X-Auth-Key|X-Auth-Email|CLOUDFLARE_EMAIL|CF_API_EMAIL)[\"']?\s*[:=]|Authorization\s*:\s*Bearer\s+",
    re.IGNORECASE,
)


def local_reference(value):
    """Canonical site-relative URL path, never a filesystem traversal."""
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValueError("malformed asset URL escape")
    relative = unquote(value, errors="strict").removeprefix("/")
    if (not relative or any(c in relative for c in "\\\x00%:")
            or any(ord(c) < 32 for c in relative)
            or any(part in ("", ".", "..") for part in relative.split("/"))):
        raise ValueError("asset URL must be a canonical relative path")
    return relative


def origin_value(value):
    url = urlsplit(value)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.path not in ("", "/") or url.query or url.fragment
            or any(c.isspace() for c in value) or "\\" in value
            or not re.fullmatch(r"[A-Za-z0-9.-]+", url.hostname)
            or url.port not in (None, 443)):
        raise ValueError("origin must be a bare public HTTPS origin, without credentials, path, query or fragment")
    if "." not in url.hostname or url.hostname.endswith("."):
        raise ValueError("origin must have a public DNS hostname")
    return f"https://{url.hostname.lower()}"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def verify_feed(site, expected_version=None, feed_path=None, installer_directory=None, arch="x64"):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    info = ARCHES[arch] if arch in ARCHES else PACKAGES[arch]
    feed_bytes = (feed_path or site / info["feed"]).read_bytes()
    if len(feed_bytes) > 16384:
        raise ValueError("feed exceeds 16 KiB")
    envelope = json.loads(feed_bytes, object_pairs_hook=unique_object)
    if set(envelope) != {"payload", "signature"}:
        raise ValueError("unexpected signed envelope fields")
    raw = base64.b64decode(envelope["payload"], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)
    if len(raw) > 8192 or len(signature) != 64:
        raise ValueError("invalid payload or signature size")
    key = bytes.fromhex((ROOT / "assets/update-public-key.hex").read_text().strip())
    Ed25519PublicKey.from_public_bytes(key).verify(signature, raw)
    payload = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    if set(payload) != {"schema", "version", "target", "filename", "sha256", "size", "published_at", "expires_at"}:
        raise ValueError("unexpected payload fields")
    if type(payload["schema"]) is not int or payload["schema"] != 1 or payload["target"] != info["target"]:
        raise ValueError("unsupported release schema or target")
    if not isinstance(payload["version"], str) or not re.fullmatch(VERSION, payload["version"]):
        raise ValueError("invalid stable version")
    if expected_version and payload["version"] != expected_version:
        raise ValueError("signed feed version does not match expected release version")
    suffixes = info.get("suffixes", ("-setup.exe",))
    if payload["filename"] not in {f"secblitz-{payload['version']}-{info['tag']}{suffix}" for suffix in suffixes}:
        raise ValueError("invalid installer filename")
    if any(type(payload[k]) is not int for k in ("size", "published_at", "expires_at")):
        raise ValueError("size and timestamps must be integers")
    if not 0 <= payload["published_at"] <= int(time.time()) < payload["expires_at"]:
        raise ValueError("release timestamps are future-dated or expired")
    if not 0 < payload["expires_at"] - payload["published_at"] <= 90 * 86400:
        raise ValueError("release lifetime exceeds 90 days")
    if not isinstance(payload["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", payload["sha256"]):
        raise ValueError("invalid SHA-256")
    installer = (installer_directory or site / "downloads") / payload["filename"]
    if installer.is_symlink():
        raise ValueError("installer must not be a symlink")
    if not 0 < payload["size"] <= LIMIT or installer.stat().st_size != payload["size"]:
        raise ValueError("installer size mismatch")
    if hashlib.sha256(installer.read_bytes()).hexdigest() != payload["sha256"]:
        raise ValueError("installer SHA-256 mismatch")
    print(f"Signed {arch} feed and installer verified against pinned key.")
    return payload


class SiteReferences(HTMLParser):
    def __init__(self):
        super().__init__()
        self.references = []
        self.hash_parts = {}
        self.hash_tag = None
        self.hash_id = None
        self.hash_count = {}
        self.canonicals = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "base":
            raise ValueError("HTML base URL overrides are not supported by the static release gate")
        if tag == "link" and "canonical" in attrs.get("rel", "").lower().split():
            self.canonicals.append(attrs.get("href", ""))
        for name in ("href", "src", "poster"):
            if attrs.get(name):
                self.references.append(attrs[name])
        if attrs.get("id") in {info["sha"] for info in ARCHES.values()}:
            self.hash_tag = tag
            self.hash_id = attrs["id"]
            self.hash_count[self.hash_id] = self.hash_count.get(self.hash_id, 0) + 1

    def handle_endtag(self, tag):
        if tag == self.hash_tag:
            self.hash_tag = None

    def handle_data(self, data):
        if self.hash_tag:
            self.hash_parts.setdefault(self.hash_id, []).append(data)


def verify_site_references(site, origin, expected_version=None, payload=None, arm_payload=None):
    page = SiteReferences()
    page.feed((site / "index.html").read_text(encoding="utf-8"))
    if page.canonicals:
        if not origin or page.canonicals != [origin + "/"]:
            raise ValueError("HTML canonical URL must be the configured compiled origin followed by /")
    installers = {name: set() for name in ARCHES}
    for reference in page.references:
        url = urlsplit(reference)
        is_installer = unquote(url.path).lower().endswith(".exe")
        if url.netloc or url.scheme:
            if is_installer:
                if not origin or f"{url.scheme}://{url.netloc}" != origin:
                    raise ValueError("installer links must use the configured HTTPS origin")
            else:
                continue
        if not url.path:
            continue
        if url.path == "/" and not is_installer:
            continue
        relative = local_reference(url.path)
        local = (site / relative).resolve()
        if not local.is_relative_to(site.resolve()) or not local.is_file():
            raise ValueError("HTML references a missing or out-of-output local asset")
        if is_installer:
            found = None if url.query or url.fragment else re.fullmatch(
                r"downloads/secblitz-" + VERSION + r"-windows-(x64|arm64)-setup\.exe", relative)
            if not found:
                raise ValueError("HTML installer URL must use the canonical download path")
            installers[found[1]].add(relative)
    for name, signed in (("x64", payload), ("arm64", arm_payload)):
        info = ARCHES[name]
        wanted = 1 if name == "x64" or signed else 0
        if len(installers[name]) != wanted:
            raise ValueError(f"HTML must reference exactly {wanted} current {name} installer across its download links")
        if not wanted:
            if info["sha"] in page.hash_count:
                raise ValueError(f"HTML shows a {name} SHA-256 without a {name} release")
            continue
        relative = next(iter(installers[name]))
        if expected_version and relative != f"downloads/secblitz-{expected_version}-{info['tag']}-setup.exe":
            raise ValueError("HTML download version does not match expected release version")
        digest = hashlib.sha256((site / relative).read_bytes()).hexdigest()
        if page.hash_count.get(info["sha"]) != 1 or "".join(page.hash_parts[info["sha"]]).strip() != digest:
            raise ValueError("HTML displayed SHA-256 does not match its installer")
        if signed and (relative != "downloads/" + signed["filename"] or digest != signed["sha256"]):
            raise ValueError("HTML download does not match the signed stable feed")
    print("HTML assets, installer links and displayed SHA-256 verified.")


def verify_not_found_page(site):
    page = SiteReferences()
    text = (site / "404.html").read_text(encoding="utf-8")
    page.feed(text)
    if re.search(r"<script\b|\son\w+\s*=", text, re.IGNORECASE):
        raise ValueError("404 page must not contain scripts or event handlers")
    for reference in page.references:
        url = urlsplit(reference)
        if url.scheme or url.netloc or not url.path.startswith("/"):
            raise ValueError("404 page references must be root-relative")
        if url.path == "/":
            continue
        relative = local_reference(url.path)
        if not (site / relative).is_file():
            raise ValueError("404 page references a missing asset")
    print("Static 404 page and root-relative assets verified.")


def verify_policy_page(site, name):
    page = SiteReferences()
    page.feed((site / name).read_text(encoding="utf-8"))
    for reference in page.references:
        url = urlsplit(reference)
        if url.scheme or url.netloc:
            if url.scheme not in {"https", "mailto"}:
                raise ValueError(f"{name} may only link to https or mailto addresses")
            continue
        if url.path == "/":
            continue
        if not url.path.startswith("/") or not (site / local_reference(url.path)).is_file():
            raise ValueError(f"{name} references must be root-relative and exist")
    print(f"{name} references verified.")


def verify_privacy_page(site):
    verify_policy_page(site, "privacy.html")


def verify_code_signing_page(site):
    verify_policy_page(site, "code-signing.html")
    text = (site / "code-signing.html").read_text(encoding="utf-8")
    if "Free code signing provided by SignPath.io, certificate by SignPath Foundation" not in text:
        raise ValueError("code-signing.html lacks the SignPath attribution")
    if "https://secblitz.lol/privacy.html" not in text:
        raise ValueError("code-signing.html lacks the privacy policy link")


def verify_migration_redirects(site, origin):
    """Keep legacy updater requests direct while allowing the two website redirects."""
    redirects = site / "_redirects"
    if not redirects.exists():
        return
    # This project's domain migration deliberately permits only these rules.
    # Beacons update clients reject redirects, including redirects to the new host.
    allowed = {
        "https://beacons.lol/": "https://secblitz.lol/",
        "https://www.secblitz.lol/*": "https://secblitz.lol/:splat",
    }
    seen = set()
    for line in redirects.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if (len(fields) != 3 or fields[0] not in allowed
                or fields[1] != allowed[fields[0]] or fields[2] not in {"301", "308"}
                or fields[0] in seen or origin != "https://secblitz.lol"):
            raise ValueError("redirect rules must preserve direct legacy feed/download access and target the compiled primary origin")
        seen.add(fields[0])
    if seen != set(allowed):
        raise ValueError("migration redirects must include only the legacy homepage and www primary-host rules")
    print("Migration redirects preserve direct beacons.lol feed/download access.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", help="explicit operator-confirmed owned HTTPS origin to compile into future builds")
    parser.add_argument("--site", type=Path, default=ROOT / "website", help="static directory to validate (default: website; production: dist/pages)")
    parser.add_argument("--require-feed", action="store_true", help="require a verified signed stable feed")
    parser.add_argument("--expected-version", help="require this exact release version (release gate defaults to Cargo.toml)")
    parser.add_argument("--arch", choices=sorted({**ARCHES, **PACKAGES}), default="x64", help="architecture of the feed given to --verify-feed")
    parser.add_argument("--verify-feed", type=Path, help="verify a separately downloaded feed locally, without modifying files")
    parser.add_argument("--installer-directory", type=Path, help="directory containing the downloaded installer for --verify-feed")
    args = parser.parse_args()
    origin = origin_value(args.origin) if args.origin else None
    site = args.site
    expected = args.expected_version
    if not expected and (args.require_feed or args.verify_feed):
        package = re.search(r"(?ms)^\[package\]\s*\n(.*?)(?=^\[|\Z)", (ROOT / "Cargo.toml").read_text())
        version = re.search(r'^version\s*=\s*"([^"]+)"', package[1], re.MULTILINE) if package else None
        if not version:
            raise ValueError("cannot infer package version; pass --expected-version")
        expected = version[1]
    if expected and not re.fullmatch(VERSION, expected):
        raise ValueError("expected version must be canonical X.Y.Z")
    if args.verify_feed:
        if not args.installer_directory or args.origin or args.require_feed:
            parser.error("--verify-feed requires --installer-directory and cannot configure origin or use --require-feed")
        verify_feed(site, expected, args.verify_feed, args.installer_directory, args.arch)
        return
    if args.installer_directory:
        parser.error("--installer-directory requires --verify-feed")
    errors = []
    for required in ("index.html", "_headers"):
        if not (site / required).is_file():
            errors.append(f"missing {required}")
    count = 0
    for path in site.rglob("*"):
        relative = path.relative_to(site)
        if path.is_symlink():
            errors.append(f"symlink forbidden: {relative}")
            continue
        if any(p.startswith(".") for p in relative.parts) or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
            errors.append("hidden/configuration or key material found in output (path suppressed)")
        if not path.is_file():
            if not path.is_dir():
                errors.append("non-regular object found in output (path suppressed)")
            continue
        if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_nlink != 1:
            errors.append("non-regular or hardlinked file found in output (path suppressed)")
            continue
        count += 1
        if path.stat().st_size > LIMIT:
            errors.append(f"exceeds Pages 25 MiB per-file limit: {relative}")
        previous = b""
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                data = previous + chunk
                if SECRET_MARKERS.search(data) or SECRET_MARKERS.search(data.replace(b"\x00", b"")):
                    errors.append("potential secret found in output (content and path suppressed)")
                    break
                previous = data[-256:]
    if count > 20000:
        errors.append("output exceeds conservative Pages 20,000-file limit")
    if errors:
        raise ValueError("; ".join(errors))
    payload = None
    if (site / "releases/stable.json").exists():
        payload = verify_feed(site, expected)
    elif args.require_feed:
        raise ValueError("signed stable feed is missing")
    else:
        print("No stable feed yet; release publication is not ready.")
    configured = (ROOT / "assets/update-origin.txt").read_text().strip()
    effective_origin = origin or (origin_value(configured) if configured else None)
    arm_payload = verify_feed(site, expected, arch="arm64") if (site / ARCHES["arm64"]["feed"]).exists() else None
    verify_site_references(site, effective_origin, expected, payload, arm_payload)
    if (site / "404.html").exists():
        verify_not_found_page(site)
    if (site / "privacy.html").exists():
        verify_privacy_page(site)
    if (site / "code-signing.html").exists():
        verify_code_signing_page(site)
    verify_migration_redirects(site, effective_origin)
    if origin:
        (ROOT / "assets/update-origin.txt").write_text(origin + "\n", encoding="utf-8")
        print("Explicit origin saved. Rebuild the application and installer before signing.")
    print(f"Static output validated: {count} files. No deployment performed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Only our own validation messages are safe to display; parsers can echo inputs.
        message = str(exc) if type(exc) is ValueError else "input, signature or filesystem validation failed"
        raise SystemExit(f"Preparation failed: {message}")
