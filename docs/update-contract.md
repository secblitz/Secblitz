# Secblitz 0.5.0 update contract

Source/evidence reviewed 2026-10-03. Current gate: genuine published 0.4.3 to 0.5.0 LIVE E2E PASS. Protected highest-seen state and atomic replacement shipped in 0.4.3 and remain active. This is not full TUF or Authenticode publisher authentication. Earlier 0.4.x failures and the pre-floor/unlink-first descriptions in older reviews are historical, not the current contract.

## Architectures (0.11)

Each build reads the feed for its own processor, fixed at compile time. Nothing about the x64 feed changes, so installed copies never see a format change.

| Build | Feed | Delivery lane | `target` | Installer |
| --- | --- | --- | --- | --- |
| x64 | `releases/stable.json` | `releases/delivery.json`, `releases/candidate.json` | `windows-x86_64` | `secblitz-X.Y.Z-windows-x64-setup.exe` |
| arm64 | `releases/stable-arm64.json` | `releases/delivery-arm64.json`, `releases/candidate-arm64.json` | `windows-aarch64` | `secblitz-X.Y.Z-windows-arm64-setup.exe` |

Both feeds use the same schema, the same root key and the same rules. `scripts/sign-release.py --arch x64|arm64` signs one feed per call; the target and the installer name must agree or signing and verification refuse. An x64 build on an ARM PC keeps reading `stable.json`. Automatic switching from x64 to arm64 is not done: the app only tells the person once that a version made for their processor exists.

The protected highest-seen floor (`release-floor.json`) is shared by both builds of a PC and accepts either target, so moving to the native build keeps its history. At the same version, a change of target is not treated as changed content. A lower version is still refused. The delivery floor is kept per build (`delivery-floor.json`, `delivery-floor-arm64.json`).

## Linux and macOS targets

Builds for Linux and macOS read their own feeds with the same schema, root key and rules. Nothing about the Windows feeds changes, and a build refuses any manifest whose `target` is not its own. Each build is fixed at compile time.

| Build | Feed | `target` | Package |
| --- | --- | --- | --- |
| Linux x86_64 | `releases/stable-linux-x64.json` | `linux-x86_64` | `secblitz-X.Y.Z-linux-x64.deb` or `.rpm` |
| Linux aarch64 | `releases/stable-linux-arm64.json` | `linux-aarch64` | `secblitz-X.Y.Z-linux-arm64.deb` or `.rpm` |
| macOS | `releases/stable-macos.json` | `macos-universal` | `secblitz-X.Y.Z-macos-universal.dmg` |

The candidate and delivery lanes follow the same naming (`candidate-linux-x64.json`, `delivery-macos.json` and so on). The release floor accepts any of the five known targets, so its history carries across builds. `scripts/sign-release.py --arch linux-x64|linux-arm64|macos` signs one feed per call, and signing and verification refuse a package whose name does not match the target.

## Unreleased 0.6.0 delivery extension

Candidate clients optionally read root-signed `releases/delivery.json`, which authorizes one exact `releases/candidate.json` envelope, one delegated key, version/origin/target, bounded sequence/freshness and signed cohort policy. The authorization lasts at most seven days. A protected random local rollout identity is not uploaded; the signed basis-point policy produces deterministic holdback. Observing a held-back candidate advances the release floor, so withdrawing rollout cannot authorize downgrade. Recovery requires a higher-version fix.

Only an initial HTTP 404 allows legacy-feed fallback. Once enrolled, missing/expired/malformed/regressed delivery metadata fails closed. `stable.json` remains the existing root-signed v1 protocol: **never put a delegated signature there**. Older clients do not enforce candidate rollout. Pre-enrollment suppression and unobserved authorization replay within validity remain boundaries.

Installation intent is durably written before setup. Unknown exit or failed health checks cannot become UpToDate from a version comparison. Confirmed-zero-exit recovery only re-verifies health and publishes completion; it never repeats installation. Fixed `update health --json` reports installed version and expected task/monitor state without acquiring the locks already held by the worker. Cross-subsystem durable interlocks protect against surviving work after process loss.

`scripts/release-authorize.py` and `scripts/release-renew.py` provide explicit operator tooling; renewal checks are keyless by default. Signing requires external authorized key access and unchanged immutable artifacts. Publishing still needs a compare-and-swap against the inspected feed digest. No production delegation, rollout or renewal schedule was enabled in this development task. The pinned root was not rotated. This is not threshold signing, full TUF, independent trusted time, or completed native live-upgrade acceptance.

The remaining sections describe **published 0.5.0**.

## Trust configuration and live origins

The compile-time `SECBLITZ_UPDATE_ORIGIN` override, or compiled `assets/update-origin.txt`, supplies an HTTPS origin with no path beyond `/`, credentials, query or fragment. Empty configuration returns `NotConfigured` without networking. Runtime environment variables and CLI parameters cannot select endpoints, installers or keys.

Current 0.5.0 compiles **https://secblitz.lol**. Older 0.4.1 clients retain **https://beacons.lol**. Both origins serve feed/download routes directly without redirects. The legacy root has a fixed 301 to the primary homepage; the primary www rule preserves its path to the apex. Updater clients request their compiled HTTPS apex directly. Mail configuration was untouched. Domain migration changed neither wire schema nor pinned key.

The public trust anchor is `assets/update-public-key.hex`, 32 Ed25519 bytes encoded as 64 hex characters. Release signing credentials are external to the repository and are not distributed to users or test guests. Documentation work never needs the private key or hosting credentials. Current release artifacts/checksums are in dist/SHA256SUMS; avoid copying superseded hashes from older logs.

## Signed envelope and payload

GET `/releases/stable.json`, maximum **16 KiB**. Redirects are forbidden. The envelope has exactly `payload` and `signature`, using standard padded base64. The 64-byte Ed25519 signature authenticates the exact decoded UTF-8 payload bytes, not reserialized JSON. Payload maximum: **8 KiB**.

Required payload shape, with descriptive placeholder values rather than a usable release:

```json
{
  "schema": 1,
  "version": "0.5.0",
  "filename": "secblitz-0.5.0-windows-x64-setup.exe",
  "sha256": "<64 lowercase hexadecimal characters>",
  "size": 3850954,
  "published_at": 0,
  "expires_at": 0,
  "target": "windows-x86_64"
}
```

The timestamps above are invalid placeholders. Unknown/duplicate fields are rejected. Versions must be canonical stable `X.Y.Z`; filenames exactly match the version, never supply a path. Incoming metadata must meet both the running-build minimum and protected highest-seen floor before equality can return `UpToDate`. Only newer versions are downloaded/installed; equal-version content substitution is rejected.

Publication must be no more than ten minutes ahead of local time. Expiration follows publication, validity is at most **90 days**, and current freshness allows ten-minute clock tolerance. Operators must renew still-current metadata **before expiration**, using unchanged installer bytes/hash and nondecreasing timestamps. The persistent floor does not replace this incoming-freshness check or make the local clock independently trusted.

## Protected highest-seen release floor

`Updates/release-floor.json` is a SYSTEM/Administrators-only local record, limited to **4,096 bytes** (limit+1 read). It has schema, canonical version, signed **installer** SHA-256, fixed target, published_at and expires_at. Required types, unknown/duplicate fields and ordered validity bounds are checked. It is neither an installed-EXE hash nor a new signed-feed field.

Both check and worker first verify incoming signed metadata, then load/enforce the current floor under `update.lock`. A missing record initializes subject to the installed-build minimum; corrupt, unsafe, inaccessible or oversized state fails closed and is never reset to absent. An advancing floor is persisted **before equality handling, payload download or installer launch**. Failed payload download therefore cannot forget an observed higher release. The worker re-reads the floor, so old staging cannot bypass a later observation.

- Reject a version below either the running build or persisted highest version.
- At the same persisted version, require the exact installer hash and target, and nondecreasing publication **and** expiration timestamps.
- Identical metadata is idempotent; unchanged-content signed renewals are accepted, even after the old floor record expires. The stored record itself is not tested against present-day freshness; expiring it must not erase replay history.
- Timestamp monotonicity is per release version, not a global ordering across different versions.

This fixes the tested observe-higher/fail-payload/replay-lower case. It cannot protect releases never observed/persisted, history before initialization, privileged floor erasure, signer compromise or arbitrary time manipulation. Hosting can still withhold updates. Root rotation, threshold signing and independent trusted freshness remain operational/future design work, not implemented full TUF.

GET `/downloads/{filename}` from the same origin. Exact signed size and lowercase SHA-256 must match. Core payload maximum is **64 MiB**; the deployment scripts enforce Cloudflare Pages' stricter **25 MiB per-file** limit. Unverified network installer bytes are buffered and checked before staging. The client uses HTTPS only, no redirects and no inherited proxy configuration. Connection timeout is **15 seconds**; manifest plus payload share a **120-second download deadline**, with remaining budget applied to the second request.

**Ed25519 metadata verification is not Windows Authenticode signing.** Published PE and setup artifacts are built in CI with MSVC and are not Authenticode-signed yet. A valid release signature authorizes those exact bytes under the project's pinned key; it does not establish a Windows-trusted publisher or a complete supply-chain audit.

## Task and user preference

The installer offers automatic updates **selected by default** alongside the default desktop shortcut and Finish guide launch. Optional monitoring is independently unchecked.

Owned root task `\SecblitzUpdate` runs as **SYSTEM, highest privilege**, with exactly the installed executable's `update check` action and native Program Files/Secblitz working directory. A single time trigger starts **one hour after registration**, repeats every `PT1H`, ignores overlapping instances and has a one-hour task execution limit. It may run on battery. **StartWhenAvailable is not configured**; sleep/power-off/missed starts are not an immediate catch-up guarantee. Setup does not start the task or contact the feed. An hourly trigger is not an hourly completion deadline.

Registration applies a protected task DACL with SYSTEM/Administrators control and Users read/execute rights. Native AccessCheck with a real standard-user token granted read/run authorization but denied data/XML write, deletion, owner and DACL modification. Run authorization can request only the fixed trusted action, not select SYSTEM code. Actual alternate-user task RPC was not established by that runner. Existing same-name task identity/security mismatch fails closed; task replacement is not atomic against a hostile administrator.

Protected 64-bit `HKLM\Software\Secblitz\AutoUpdatesEnabled` stores 0/1. Interactive upgrades honor checkbox changes. Silent upgrades with saved preferences, including the fixed `/SECBLITZUPDATE=1` marker, preserve that choice even with `/TASKS=""`. On first install, an explicit empty task list opts out. Uninstall removes only the owned task and retains a disabled preference. The marker selects behavior; it does not grant authority.

## Protected namespace and locks

The 0.5.0 layout uses the protected native ProgramData known folder introduced in 0.4.2:

```text
Secblitz/
  engine.lock
  <schema-1 transaction journals>.jsonl
  Updates/
    update.lock
    update-status.json
    update-manifest.json
    update-installer.exe
    update-worker.exe
    release-floor.json
```

`Updates` requires a protected SYSTEM/Administrators-only DACL, trusted ownership and non-reparse directory semantics. Existing untrusted state is rejected, not repaired/adopted. Native ancestor/data handles pin the namespace; payload files reject hard links and are held without write/delete sharing as appropriate.

For migration, the engine accepts **exactly five legacy files** beside root journals: `update.lock`, `update-status.json`, `update-manifest.json`, `update-installer.exe`, `update-worker.exe`. It separately accepts `Updates` as a directory. Wrong types, links, unknown names, lookalike names and malformed journals are not accepted by a blanket exemption. The engine does not parse updater files as WALs. Platform ACL/owner validation still applies recursively.

Updater operations serialize on `Updates/update.lock` and contend with repairs at base `Secblitz/engine.lock`. Legacy files can coexist but are not silently migrated/deleted. The live 0.4.3 to 0.5.0 run used `Updates` throughout, advanced the authentic prior floor and preserved eight genuine journal copies. Protected temporary replacement files are updater-owned children, not engine journals or additional allowed root filenames.

## Check, worker and installer lifecycle

1. `check_and_stage` requires elevation and the trusted installed executable, validates/pins installed paths, and acquires update/base-engine locks. Busy installed sessions or an existing installer defer; no users are killed.
2. Verify feed/freshness/version, enforce and persist the highest-seen floor, then verify payload size/hash and protected staging. Copy the pinned installed image to the fixed worker path and perform sanitized-environment preflight.
3. Persist `WorkerStarted`, spawn `update-worker.exe update install-staged` with stdin/stdout/stderr detached, then let the parent exit promptly. `WorkerStarted` is not `Installed`.
4. Worker requires the exact protected worker location and an enabled administrative token. It waits up to **30 seconds** for handoff/update lock and checks busy state/base lock. The worker must byte-match the current trusted installed image, preventing a retained old worker from updating over a different installation.
5. Reverify manifest signature/freshness/version, reload/enforce/persist the current floor, and verify payload size/hash. Retain the installer handle without write/delete sharing through execution. Invoke only:

```text
/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /TASKS="" /SECBLITZUPDATE=1
```

6. **Wait for the installer to exit while retaining both locks and the payload pin. There is no 15-minute force-kill deadline.** Killing a live installer or releasing locks while it runs could leave partial/overlapping work. A hung installation can therefore retain locks and needs diagnosis; neither forced termination nor transactional rollback is promised. Scheduler limits on the check task are a separate layer, not an installer rollback contract.
7. Require installer exit 0 and validate the installed version before recording `Installed`. Failure records a short generic reason; an error does not imply the installer made no changes. Installer owns monitor stop/resume and updater preference retention, not the repair engine.

Child environments are allowlisted, including trusted Windows paths, SystemDrive, ProgramData/ALLUSERSPROFILE and protected temp/working directories. This fixes the historical known-folder failure without propagating caller CLR/profiler/path settings. Read-only preflight/version probes have their own bounds; they are not the download or installer timer.

### Atomic persistence

`replace_with` exclusively creates a protected UUID-named temporary file in the same pinned directory, writes and flushes it, validates any destination, then switches the name with **MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)**. There is no preliminary unlink or cross-volume fallback. A failed write/flush/pre-switch validation or replacement leaves the old destination intact. Pinned payload sharing still denies replacement/write/delete. Cleanup removes only this invocation's temporary file; stranded protected temps are never adopted as status/floor/payload or blindly deleted by another call.

Nine SYSTEM regression cases include partial-write failure, prior-state preservation, stranded-temp isolation, pinning and corrupt/blocked-floor behavior. These are controlled fault injections, not destructive hardware power-loss certification. Atomic file publication is not a transactional installer rollback or automatic torn-WAL repair; do not delete originals to force recovery.

## API, CLI and status

Public core APIs are `check_and_stage`, `install_staged` and `status`. Public CLI commands are `update check` and `update status`, optionally `--json`. Hidden `update install-staged` accepts no supplied path/origin/channel/force parameters and never elevates itself.

Interactive non-elevated public requests can ask UAC once. JSON/background requests require an already elevated caller and never prompt. All updater commands bypass guide/branding/animation/pauses; workers are silent. Check JSON emits the outcome directly; status JSON emits `{checked_at,result}`. Field names are stable, not translated. Technical native errors are not mixed into JSON; failures use generic structured/local reasons.

Outcomes: `not_configured`, `up_to_date`, `deferred_busy`, `worker_started`/`installed` with version, and `failed` with reason. Failed/core errors exit 1; all other updater outcomes exit 0. Missing status is `checked_at: 0` with `NotConfigured`, displayed as no update information yet. A contention status can be transient `DeferredBusy`. Neither absence nor exit 0 is proof of current installation or system health.

## Evidence and residual limits

Security release 0.4.3 passed **116 native library + 52 CLI tests** and **nine SYSTEM updater cases**, including the new floor/atomic persistence cases; the earlier seven pinning/locking cases retain their narrower scope. Current 0.5.0 acceptance passed **138 library + 66 CLI**, separate readiness smoke and the same **nine SYSTEM cases**. Ignored live/attended probes are not counted as ordinary passes. [Security summary](SECURITY-REVIEW.md) distinguishes real standard-token tests, protocol fixtures and later live evidence.

The genuine published **0.4.3 to 0.5.0** SYSTEM task returned Installed in **18.865 s**, UpToDate in **1.336 s**, and DeferredBusy in **1.005 s** while the same guide remained responsive. The prior authentic floor advanced to 0.5.0 with the signed installer hash, publication **1791022530**, expiration **1798798530**, and protected SYSTEM/Admin-only ACL; current/busy checks preserved it byte-for-byte. The resumed LocalService monitor produced a fresh **9,195-byte** typed 18/19/readiness report. All 18 baselines, original journals and eight real journal copies remained unchanged. No live rollback/corruption fixture was injected; SYSTEM regressions supply that evidence. Live results records the exact published bytes.

The shipped 0.4.0 worker still needs manual upgrade. That historical limitation does not invalidate the current live pass. Persistent observed-release rollback protection and atomic state publication are now implemented; Windows 10/Home/Pro/full standard-user broker coverage, Authenticode provenance, full TUF rotation/thresholds, staged rollout and transactional install recovery remain outside demonstrated scope. The unsigned initial browser bootstrap remains an explicit accepted preview boundary: same-site checksums are not independent publisher proof. `-RequirePublisherSignature` is ready for a future real certificate, not a self-signed trust claim.
