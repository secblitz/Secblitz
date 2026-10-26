#!/usr/bin/env python3
"""Sign the final installer manifest; requires Python cryptography."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", re.ASCII)
HASH = re.compile(r"[0-9a-f]{64}", re.ASCII)
MANIFEST_LIMIT = 16 * 1024
ARTIFACT_LIMIT = 25 * 1024 * 1024
# Each architecture has its own feed, target and installer name. The x64 feed
# keeps its original name and format so installed copies never see a change.
ARCHES = {
    "x64": dict(target="windows-x86_64", tag="windows-x64", feed="stable.json"),
    "arm64": dict(target="windows-aarch64", tag="windows-arm64", feed="stable-arm64.json"),
}


# Linux and macOS packages, signed into their own feeds. Kept apart from ARCHES
# so nothing that walks the Windows installers sees them.
PACKAGES = {
    "linux-x64": dict(target="linux-x86_64", tag="linux-x64", suffixes=(".deb", ".rpm"),
                      feeds=dict(deb="stable-linux-x64-deb.json", rpm="stable-linux-x64-rpm.json")),
    "linux-arm64": dict(target="linux-aarch64", tag="linux-arm64", suffixes=(".deb", ".rpm"),
                        feeds=dict(deb="stable-linux-arm64-deb.json", rpm="stable-linux-arm64-rpm.json")),
    "macos": dict(target="macos-universal", tag="macos-universal", suffixes=(".dmg",), feed="stable-macos.json"),
}
TARGETS = {**ARCHES, **PACKAGES}


def arch_of_target(target):
    for name, info in TARGETS.items():
        if info["target"] == target:
            return name
    raise ValueError("unknown target")


def feed_name(arch, package=None):
    """The feed file for one target. Linux has one feed per package kind because one binary serves both."""
    info = TARGETS[arch]
    if "feeds" in info:
        if package not in info["feeds"]:
            raise ValueError("this target needs a package kind: deb or rpm")
        return info["feeds"][package]
    if package is not None:
        raise ValueError("this target has no package kinds")
    return info["feed"]


def package_of(filename):
    for kind in ("deb", "rpm"):
        if filename.endswith("." + kind):
            return kind
    return None


def setup_names(version, arch):
    if arch in PACKAGES:
        info = PACKAGES[arch]
        return [f"secblitz-{version}-{info['tag']}{suffix}" for suffix in info["suffixes"]]
    return [f"secblitz-{version}-{ARCHES[arch]['tag']}-setup.exe"]


def setup_name(version, arch):
    return setup_names(version, arch)[0]


def strict_json(data):
    def object_pairs(pairs):
        obj = {}
        for name, value in pairs:
            if name in obj:
                raise ValueError("duplicate JSON field")
            obj[name] = value
        return obj
    def invalid_constant(value):
        raise ValueError("invalid JSON constant")
    return json.loads(data.decode("utf-8"), object_pairs_hook=object_pairs,
                      parse_constant=invalid_constant)


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def signed_envelope(payload, key):
    raw = canonical(payload)
    if len(raw) > 8192:
        raise ValueError("signed payload too large")
    signature = key.sign(raw)
    key.public_key().verify(signature, raw)
    return canonical(dict(payload=base64.b64encode(raw).decode("ascii"),
                          signature=base64.b64encode(signature).decode("ascii"))) + b"\n"


def validate_ed25519_point(encoded):
    # OpenSSL verification alone accepts identity-key/identity-R forgeries.
    # Match the client's small-order rejection before asking cryptography to
    # verify the signature. These are the five distinct y coordinates of the
    # eight torsion points; the high x-sign bit does not affect membership.
    # Also reject noncanonical field encodings (including p and p+1 aliases).
    if len(encoded) != 32:
        raise ValueError("invalid Ed25519 point size")
    y = int.from_bytes(encoded, "little") & (2**255 - 1)
    p = 2**255 - 19
    torsion_y = {0, 1, p - 1,
        int.from_bytes(bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), "little"),
        int.from_bytes(bytes.fromhex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), "little")}
    if y >= p or y in torsion_y:
        raise ValueError("weak or noncanonical Ed25519 point")


def verify_envelope(data, public):
    if len(data) > MANIFEST_LIMIT:
        raise ValueError("manifest too large")
    envelope = strict_json(data)
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise ValueError("invalid envelope fields")
    decoded = []
    for field in ("payload", "signature"):
        value = envelope[field]
        if not isinstance(value, str):
            raise ValueError("invalid base64 field")
        raw = base64.b64decode(value, validate=True)
        if base64.b64encode(raw).decode("ascii") != value:
            raise ValueError("noncanonical base64")
        decoded.append(raw)
    payload, signature = decoded
    if len(payload) > 8192 or len(signature) != 64 or len(public) != 32:
        raise ValueError("invalid signed payload/key/signature size")
    validate_ed25519_point(public)
    validate_ed25519_point(signature[:32])
    if int.from_bytes(signature[32:], "little") >= 2**252 + 27742317777372353535851937790883648493:
        raise ValueError("noncanonical Ed25519 scalar")
    Ed25519PublicKey.from_public_bytes(public).verify(signature, payload)
    return strict_json(payload)


def stable_version(version):
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError("version must be stable canonical X.Y.Z")
    parts = tuple(map(int, version.split(".")))
    if any(part > 2**64 - 1 for part in parts):
        raise ValueError("version component too large")
    return parts


def validate_manifest(payload, now, arch=None):
    fields = {"schema", "version", "filename", "sha256", "size", "published_at", "expires_at", "target"}
    if not isinstance(payload, dict) or set(payload) != fields:
        raise ValueError("invalid v1 fields")
    stable_version(payload["version"])
    for field in ("schema", "size", "published_at", "expires_at"):
        if type(payload[field]) is not int or not 0 <= payload[field] <= 2**64 - 1:
            raise ValueError("invalid integer")
    if payload["target"] not in {info["target"] for info in TARGETS.values()}:
        raise ValueError("invalid or stale v1 manifest")
    found = arch_of_target(payload["target"])
    if arch is not None and found != arch:
        raise ValueError("invalid or stale v1 manifest")
    if (payload["schema"] != 1
            or payload["filename"] not in setup_names(payload["version"], found)
            or not isinstance(payload["sha256"], str) or not HASH.fullmatch(payload["sha256"])
            or not 0 < payload["size"] <= 64 * 1024 * 1024
            or not 0 < payload["expires_at"] - payload["published_at"] <= 90 * 86400
            or payload["published_at"] > now + 600 or now > payload["expires_at"] + 600):
        raise ValueError("invalid or stale v1 manifest")


def load_key(path, public):
    if plain_path(path).is_relative_to(ROOT):
        raise ValueError("private key must be outside the repository")
    key = serialization.load_pem_private_key(read_input(path, 16384, private=True), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("key must be Ed25519")
    actual = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if actual != public:
        raise ValueError("signing key does not match pinned public key")
    return key


def plain_path(path):
    if ".." in path.parts:
        raise ValueError("signing paths must not contain traversal components")
    path = Path(os.path.abspath(path))
    for component in (*reversed(path.parents), path):
        if component.is_symlink():
            raise ValueError("symlinks are not accepted in signing paths")
    return path


def read_input(path, limit, private=False):
    path = plain_path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise ValueError("signing inputs must be bounded regular single-link files")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if ((before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)
                or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise ValueError("signing input changed during open")
        if private and os.name == "posix" and (
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.geteuid()):
            raise ValueError("private key must be owned by the operator with permissions 0600")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if (len(data) > limit or len(data) != info.st_size
            or (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
        raise ValueError("signing input changed during read or exceeds size limit")
    return data


def write_output(path, data):
    path = plain_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("output must be a regular single-link file")
    # Replace the directory entry rather than truncate its target. Even an output
    # hardlink cannot overwrite the private key or another input this way.
    fd, name = tempfile.mkstemp(prefix=".signed-feed-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lifetime-days", type=int, default=90)
    parser.add_argument("--arch", choices=sorted(TARGETS), default="x64")
    parser.add_argument("--package", choices=("deb", "rpm"), help="package kind; required with linux architectures")
    parser.add_argument("--public-key", type=Path, default=ROOT / "assets/update-public-key.hex")
    args = parser.parse_args()
    stable_version(args.version)
    if args.installer.name not in setup_names(args.version, args.arch) or args.installer.is_symlink():
        parser.error("installer must be a regular file with the exact versioned setup filename")
    if ("feeds" in TARGETS[args.arch]) != (args.package is not None):
        parser.error("--package is required with linux architectures and not allowed with the others")
    if args.package and package_of(args.installer.name) != args.package:
        parser.error("installer filename does not match --package")
    if not 1 <= args.lifetime_days <= 90:
        parser.error("lifetime must be 1 through 90 days")
    for path in (args.key, args.installer, args.public_key, args.output):
        plain_path(path)
    if args.key.resolve().is_relative_to(ROOT):
        parser.error("private key must be outside the repository")
    if args.output.resolve() in (args.key.resolve(), args.installer.resolve(), args.public_key.resolve()):
        parser.error("output must not overwrite an input")
    key = serialization.load_pem_private_key(read_input(args.key, 16384, private=True), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        parser.error("key must be Ed25519")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if public.hex() != read_input(args.public_key, 128).decode("ascii").strip():
        parser.error("signing key does not match the pinned public key")
    installer_bytes = read_input(args.installer, 25 * 1024 * 1024)
    digest = hashlib.sha256(installer_bytes)
    size = len(installer_bytes)
    if not 0 < size <= 25 * 1024 * 1024:
        parser.error("installer must be nonempty and at most 25 MiB for Pages")
    now = int(time.time())
    payload = dict(schema=1, version=args.version, target=TARGETS[args.arch]["target"], filename=args.installer.name,
                   sha256=digest.hexdigest(), size=size, published_at=now,
                   expires_at=now + args.lifetime_days * 86400)
    write_output(args.output, signed_envelope(payload, key))
    print(f"Signed {args.installer.name}: sha256={digest.hexdigest()}, size={size}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError):
        raise SystemExit("Signing failed: check input files, key format and permissions (details suppressed).")
