#!/usr/bin/env python3
"""Prepare a narrowly scoped delivery authorization; no publication or root rotation.

Default prints an UNSIGNED public payload for review. --sign with an external
--key writes a NEW envelope to --output. Publish candidate.json before
delivery.json, preserving root-signed stable.json for old clients. Do not add
fields to v1 or publish delegated signatures in stable.json. Authorization is
1-of-1 under the existing root, expires in <=7 days, and delegates ONE exact
candidate envelope to ONE key. It is not TUF. Higher sequence replaces earlier
authorization on receipt; replay before receipt is bounded only by expiry.
Use a retained --previous and --previous-candidate for every subsequent policy,
including renewals and holdback. Neither floors nor rollback are reset by 0%.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import time

from cryptography.exceptions import InvalidSignature

SPEC = importlib.util.spec_from_file_location("release_renewal", Path(__file__).with_name("release-renew.py"))
renew = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renew)
sign = renew.sign


def validate_authorization(a, origin):
    fields = {"schema", "role", "sequence", "origin", "target", "published_at", "expires_at",
              "version", "manifest_sha256", "manifest_key", "rollout", "health"}
    if not isinstance(a, dict) or set(a) != fields:
        raise ValueError("invalid authorization fields")
    for field in ("schema", "sequence", "published_at", "expires_at"):
        if type(a[field]) is not int or not 0 <= a[field] <= 2**64 - 1:
            raise ValueError("invalid integer")
    if (a["schema"] != 1 or a["role"] != "secblitz-delivery" or a["sequence"] == 0
            or a["origin"] != origin or a["target"] not in {i["target"] for i in sign.TARGETS.values()}
            or not 0 < a["expires_at"] - a["published_at"] <= 7 * 86400
            or a["health"] != "update_health_v1"):
        raise ValueError("invalid authorization scope")
    sign.stable_version(a["version"])
    r = a["rollout"]
    if (not isinstance(r, dict) or set(r) != {"salt", "basis_points"}
            or type(r["basis_points"]) is not int or not 0 <= r["basis_points"] <= 10000):
        raise ValueError("invalid rollout")
    for value in (a["manifest_sha256"], a["manifest_key"], r["salt"]):
        if not isinstance(value, str) or not sign.HASH.fullmatch(value):
            raise ValueError("invalid key/digest/salt")
    sign.validate_ed25519_point(bytes.fromhex(a["manifest_key"]))


def candidate(raw, key, now):
    m = sign.verify_envelope(raw, bytes.fromhex(key))
    sign.validate_manifest(m, now)
    return m


def prepare(raw, manifest_key, origin, sequence, basis_points, salt, now, lifetime_hours,
            previous=None, previous_raw=None):
    m = candidate(raw, manifest_key, now)
    # No post-expiry grace in automation even though the v1 verifier has skew.
    if not m["published_at"] <= now < m["expires_at"] or not 1 <= lifetime_hours <= 168:
        raise ValueError("candidate must be fresh with bounded authority")
    a = dict(schema=1, role="secblitz-delivery", sequence=sequence, origin=origin,
             target=m["target"], published_at=now, expires_at=now + lifetime_hours * 3600,
             version=m["version"], manifest_sha256=hashlib.sha256(raw).hexdigest(),
             manifest_key=manifest_key, rollout=dict(salt=salt, basis_points=basis_points),
             health="update_health_v1")
    validate_authorization(a, origin)
    if previous is not None:
        validate_authorization(previous, origin)
        if (sequence <= previous["sequence"] or now < previous["published_at"]
                or sign.stable_version(m["version"]) < sign.stable_version(previous["version"])):
            raise ValueError("authorization rollback/equivocation")
        if previous_raw is None or hashlib.sha256(previous_raw).hexdigest() != previous["manifest_sha256"]:
            raise ValueError("previous candidate snapshot required")
        old = candidate(previous_raw, previous["manifest_key"], previous["published_at"])
        if old["version"] != previous["version"]:
            raise ValueError("previous authorization version mismatch")
        if m["version"] == old["version"]:
            if salt != previous["rollout"]["salt"]:
                raise ValueError("cohort salt must remain fixed for a release")
            for field in ("version", "sha256", "size", "filename", "target"):
                if m[field] != old[field]:
                    raise ValueError("immutable release changed")
            if m["published_at"] < old["published_at"] or m["expires_at"] < old["expires_at"]:
                raise ValueError("candidate freshness rollback")
    return a


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--candidate", type=Path, required=True)
    p.add_argument("--manifest-key", required=True, help="Delegated public key, lowercase hex")
    p.add_argument("--expected-origin", required=True)
    p.add_argument("--expected-root-key", required=True)
    p.add_argument("--root-public-key", type=Path, default=sign.ROOT / "assets/update-public-key.hex")
    p.add_argument("--origin-file", type=Path, default=sign.ROOT / "assets/update-origin.txt")
    p.add_argument("--previous", type=Path)
    p.add_argument("--previous-candidate", type=Path)
    p.add_argument("--sequence", type=int, required=True)
    p.add_argument("--basis-points", type=int, required=True)
    p.add_argument("--salt", required=True, help="32-byte hex cohort salt; fixed per release")
    p.add_argument("--lifetime-hours", type=int, default=24)
    p.add_argument("--sign", action="store_true")
    p.add_argument("--key", type=Path)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    if bool(args.previous) != bool(args.previous_candidate):
        p.error("--previous requires --previous-candidate")
    if args.previous is None and args.sequence != 1:
        p.error("first authorization starts at sequence 1; retain previous snapshots thereafter")
    if args.sign != (args.key is not None and args.output is not None) or (not args.sign and (args.key or args.output)):
        p.error("--sign requires both --key and --output")
    for value in (args.expected_root_key, args.manifest_key, args.salt):
        if not sign.HASH.fullmatch(value):
            p.error("keys and salt must be 64 lowercase hex characters")
    paths = [(args.root_public_key, 128), (args.origin_file, 2048), (args.candidate, sign.MANIFEST_LIMIT)]
    if args.previous:
        paths += [(args.previous, sign.MANIFEST_LIMIT), (args.previous_candidate, sign.MANIFEST_LIMIT)]
    snapshots = {path: (limit, sign.read_input(path, limit)) for path, limit in paths}
    root = snapshots[args.root_public_key][1].decode("ascii").strip()
    origin = renew.checked_origin(snapshots[args.origin_file][1].decode("ascii"))
    if root != args.expected_root_key or origin != renew.checked_origin(args.expected_origin):
        raise ValueError("root/origin changed")
    previous = sign.verify_envelope(snapshots[args.previous][1], bytes.fromhex(root)) if args.previous else None
    payload = prepare(snapshots[args.candidate][1], args.manifest_key, origin, args.sequence,
                      args.basis_points, args.salt, int(time.time()), args.lifetime_hours, previous,
                      snapshots[args.previous_candidate][1] if args.previous else None)
    if not args.sign:
        print(sign.canonical(payload).decode("utf-8"))
        return
    output = sign.plain_path(args.output)
    if output.exists() or output in {sign.plain_path(path) for path in [*snapshots, args.key]}:
        raise ValueError("output must be new and distinct from inputs")
    key = sign.load_key(args.key, bytes.fromhex(root))
    signed = sign.signed_envelope(payload, key)
    for path, (limit, snapshot) in snapshots.items():
        if sign.read_input(path, limit) != snapshot:
            raise ValueError("input changed during authorization")
    if int(time.time()) >= payload["expires_at"]:
        raise ValueError("authorization expired before output")
    with output.open("xb") as stream:
        stream.write(signed)
        stream.flush()
        os.fsync(stream.fileno())
    print(f"Authorization candidate written: sequence={payload['sequence']}; no files published.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, InvalidSignature, TypeError, KeyError):
        raise SystemExit("Authorization failed: trust, input or policy validation rejected (details suppressed).")
