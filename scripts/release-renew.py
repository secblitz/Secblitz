#!/usr/bin/env python3
"""Check/renew an unchanged root-signed v1 stable feed; never publish anything.

Default is a keyless check. --sign requires --key and a NEW --output. The
operator/automation must pin --expected-origin, --expected-public-key and
--current-sha256 independently of mutable input files. The live feed must equal
the supplied snapshot before planning and again before emitting signed output.
Deploy separately with a compare-and-swap against the printed base SHA-256;
this tool cannot make a remote publish atomic. Expired feeds require a separately
reviewed recovery, not blind renewal. Candidate/delivery authorizations are not
renewed here: root approval of every exact candidate is deliberately required.
"""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import time
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidSignature

SPEC = importlib.util.spec_from_file_location("release_signing", Path(__file__).with_name("sign-release.py"))
sign = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sign)


def checked_origin(text):
    text = text.strip()
    url = urllib.parse.urlsplit(text)
    if (url.scheme != "https" or not url.hostname or url.username is not None
            or url.password is not None or url.path not in ("", "/")
            or url.query or url.fragment or "\\" in text or "?" in text or "#" in text
            or any(c.isspace() or ord(c) < 32 for c in text)):
        raise ValueError("invalid release origin")
    # Force canonical ASCII host/port spelling, matching Rust Url serialization.
    host = url.hostname
    if not host.isascii() or host != host.lower() or ":" in host:
        raise ValueError("origin must use a canonical DNS host")
    port = url.port
    canonical = "https://" + host + (f":{port}" if port not in (None, 443) else "") + "/"
    if text.rstrip("/") + "/" != canonical:
        raise ValueError("noncanonical release origin")
    return canonical


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("release redirects are forbidden")


def live_feed(origin, feed="stable.json"):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(origin + "releases/" + feed, headers={
        "User-Agent": "Secblitz-Release-Renewal/1", "Accept": "application/json",
        "Cache-Control": "no-cache",
    })
    with opener.open(request, timeout=30) as response:
        if response.status != 200 or response.url != origin + "releases/" + feed:
            raise ValueError("unexpected release response")
        data = response.read(sign.MANIFEST_LIMIT + 1)
    if len(data) > sign.MANIFEST_LIMIT:
        raise ValueError("live manifest too large")
    return data


def renewal(current, public, artifact, filename, now, lifetime_days=90, arch=None):
    payload = sign.verify_envelope(current, public)
    sign.validate_manifest(payload, now, arch)
    if (not 1 <= lifetime_days <= 90 or not payload["published_at"] < now < payload["expires_at"]
            or filename != payload["filename"] or len(artifact) != payload["size"]
            or len(artifact) > sign.ARTIFACT_LIMIT
            or hashlib.sha256(artifact).hexdigest() != payload["sha256"]):
        raise ValueError("renewal requires unchanged immutable artifact and fresh metadata")
    new = dict(payload, published_at=now, expires_at=now + lifetime_days * 86400)
    if new["expires_at"] <= payload["expires_at"]:
        raise ValueError("renewal must extend expiration")
    sign.validate_manifest(new, now, arch)
    return new


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", type=Path, required=True)
    parser.add_argument("--current-sha256", required=True)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--expected-origin", required=True)
    parser.add_argument("--expected-public-key", required=True)
    parser.add_argument("--origin-file", type=Path, default=sign.ROOT / "assets/update-origin.txt")
    parser.add_argument("--public-key", type=Path, default=sign.ROOT / "assets/update-public-key.hex")
    parser.add_argument("--renew-within-days", type=int, default=14)
    parser.add_argument("--lifetime-days", type=int, default=90)
    parser.add_argument("--arch", choices=sorted(sign.TARGETS), default="x64")
    parser.add_argument("--sign", action="store_true")
    parser.add_argument("--key", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 0 <= args.renew_within_days <= 90 or not 1 <= args.lifetime_days <= 90:
        parser.error("invalid renewal window/lifetime")
    if args.sign != (args.key is not None and args.output is not None) or (not args.sign and (args.key or args.output)):
        parser.error("--key and --output are required only with --sign")
    if not sign.HASH.fullmatch(args.current_sha256) or not sign.HASH.fullmatch(args.expected_public_key):
        parser.error("expected hashes/key must be 64 lowercase hex characters")
    inputs = {}
    for path, limit in [(args.current, sign.MANIFEST_LIMIT), (args.installer, sign.ARTIFACT_LIMIT),
                        (args.origin_file, 2048), (args.public_key, 128)]:
        inputs[path] = (limit, sign.read_input(path, limit))
    current = inputs[args.current][1]
    origin = checked_origin(inputs[args.origin_file][1].decode("ascii"))
    if origin != checked_origin(args.expected_origin):
        raise ValueError("origin changed")
    public_text = inputs[args.public_key][1].decode("ascii").strip()
    if public_text != args.expected_public_key or hashlib.sha256(current).hexdigest() != args.current_sha256:
        raise ValueError("key/current bytes changed")
    public = bytes.fromhex(public_text)
    feed = sign.feed_name(args.arch, sign.package_of(args.installer.name))
    if live_feed(origin, feed) != current:
        raise ValueError("live feed differs from renewal snapshot")
    now = int(time.time())
    planned = renewal(current, public, inputs[args.installer][1], args.installer.name, now, args.lifetime_days, args.arch)
    old = sign.verify_envelope(current, public)
    if old["expires_at"] - now > args.renew_within_days * 86400:
        print("Fresh feed outside renewal window; no output and no key loaded.")
        return
    if not args.sign:
        print(f"Renewal due; verified immutable {planned['filename']}; base_sha256={args.current_sha256}")
        return
    output = sign.plain_path(args.output)
    if output.exists() or output in {sign.plain_path(p) for p in [*inputs, args.key]}:
        raise ValueError("renewal output must be a new file, distinct from all inputs")
    key = sign.load_key(args.key, public)
    result = sign.signed_envelope(planned, key)
    # Recheck all public inputs/current bytes after signing; no private bytes are
    # logged, returned, written to the repository, or embedded in an executable.
    for path, (limit, snapshot) in inputs.items():
        if sign.read_input(path, limit) != snapshot:
            raise ValueError("renewal input changed")
    if live_feed(origin, feed) != current:
        raise ValueError("live feed changed during renewal")
    sign.validate_manifest(planned, int(time.time()), args.arch)
    # Exclusive create: unlike original release signing, renewal never replaces
    # an existing file, including a historical signed release.
    with output.open("xb") as stream:
        stream.write(result)
        stream.flush()
        import os
        os.fsync(stream.fileno())
    print(f"Renewal candidate written; publish only if base_sha256={args.current_sha256} still matches.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, InvalidSignature, TypeError, KeyError):
        raise SystemExit("Renewal failed: inputs, trust, freshness or live snapshot check rejected (details suppressed).")
