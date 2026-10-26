# Secblitz Windows packaging

The evidence below is historical and comes from early versions. Current release
steps are in [RELEASING.md](../docs/RELEASING.md).

**Current evidence, 2026-10-02:** v0.2.0 Windows 11 acceptance passed **70 library + 16 CLI = 86 native tests**, Inno Setup **6.7.3** compilation, Italian optional-monitor installation, actual scan and running uninstall. The coordinating host run passed **84 Linux tests**. Windows 10 is targeted but **untested**; project artifacts are **unsigned GNU-cross-built development builds**, not signed/native-MSVC provenance.

The initial installer warned that Italian `Monitor`/`Failed` fell back to English. **The corrected final repack now passed targeted verification:** warning-free ISCC compile, Italian optional-monitor install exit 0 with service Stopped, uninstall exit 0, unchanged executable/journal hashes and all 18 baseline states. The actual scan/running-uninstall evidence is from the preceding package with the identical executable and was not repeated for the two-string correction. Use `dist/SHA256SUMS` and the matching final acceptance record; the preceding package hash is historical.

## Build

Use x64 Windows, stable Rust with `rustfmt`/`clippy`, Visual Studio 2022 C++
build tools and the Windows SDK. Open **Developer PowerShell for VS 2022**:

```powershell
./scripts/build-release.ps1
# If Inno Setup is absent, from an elevated build shell:
./scripts/build-release.ps1 -DownloadInno
# Or use a compiler already installed elsewhere:
./scripts/build-release.ps1 -IsccPath 'C:\Tools\Inno Setup 6\ISCC.exe'
```

The optional download is the official Inno Setup 6.4.3 installer, checked for
a valid Jordan Russell Authenticode publisher signature before execution.
Compilation uses **six** bundled wizard resources: English, Spanish, French,
German, Portuguese and Italian, plus project custom messages for all six.
A missing resource can fail compilation, whereas missing custom messages can
warn and fall back to English: the first v0.2.0 test demonstrated that distinction.
Two setups are built. `secblitz-X.Y.Z-windows-x64-setup.exe` uses
`ArchitecturesAllowed=x64compatible`, so it still installs on ARM64 PCs, where
Windows runs it through emulation. `secblitz-X.Y.Z-windows-arm64-setup.exe`
(`./scripts/build-release.ps1 -Arch arm64`, on a Windows on ARM PC) installs the
native build with `ArchitecturesAllowed=arm64`. Both use the same AppId and
install folder, so the ARM setup upgrades an x64 install in place and keeps its
settings and history. Neither is intended for Windows Server.

The build checks formatting, tests and Clippy, then builds a locked-dependency
MSVC release with static CRT and checks PE imports with `dumpbin`. `dist/`
contains the standalone executable, actual compiled installer and SHA-256
checksums. The script requires the executable's `--version` output to match the
single `secblitz` package in Cargo metadata. For Cargo version **0.3.0**, output names are
`secblitz-0.3.0-windows-x64.exe`, `secblitz-0.3.0-windows-x64-setup.exe`
and `SHA256SUMS.txt`. The recorded GNU/guest workflow instead retains
`secblitz.exe` and `SHA256SUMS`. CI is configured to produce unsigned artifacts;
no hosted CI pass or GitHub release is implied by local native testing.
The icon is embedded through `assets/secblitz.rc`; the original manifest is
preserved. The release script forces a package rebuild because the existing
`build.rs` does not track changes to the ICO directly.

## Service integration contract

The application and monitor intentionally share the fixed known-folder path
`Program Files\Secblitz\secblitz.exe`. Setup calls **that installed executable**
with `service install`; a renamed release artifact outside Program Files is
never used to register the service. No separate copy competes for this path.

Service validation permits an optional `S-1-5-32-545` (BU) trustee with exactly
`0x1200a9` read/execute rights on the shared root and executable. It cannot gain
write, delete, owner or DACL rights. The Monitor directory/report retain their
stricter SYSTEM, Administrators and LocalService validation. Installer root
and executable ACLs are protected, owned by Administrators, with SYSTEM and
Administrators full control, and LocalService and Users read/execute. Directory
grants propagate to children. Service-created standalone layouts also support
ordinary app execution. LocalService can modify only the pre-created report;
it cannot create, replace or delete files in the Monitor directory.

## Installation lifecycle

The desktop/finish-launch behavior below is a v0.3.0 source change awaiting Windows
acceptance, not part of the recorded v0.2.0 package evidence. The current CLI has
the explicit `guide` command and no-argument guided default. The older v0.2.0
executable defaults to apply and must not be paired with this installer for release.

* The directory is fixed; `/DIR` overrides are rejected. A fixed NTFS volume,
  trusted owners and non-writable ACLs are required. Reparse points and untrusted
  existing contents fail closed instead of being recursively repaired. Files
  with multiple hard links are rejected. Validation pins ancestors and children
  against rename/delete using read-data/list-directory handles, not metadata-only
  handles (which do not enforce the same Windows sharing restrictions).
* Setup grants ordinary Users read/execute only. Start Menu and desktop shortcuts
  target only the installed executable, with no arguments. The desktop shortcut
  (`{commondesktop}\Secblitz.lnk`) is selected by default and can be unchecked.
  The app's asInvoker manifest and guided flow own elevation. Guided entry checks
  for a terminal first, then may request its initial UAC elevation to read protected
  state; this is not consent to apply fixes. Fixes require a subsequent user choice.
* The finish page offers **Open Secblitz**, checked by
  default. It invokes the fixed installed executable with no arguments, never
  `apply`, using `nowait postinstall skipifsilent runasoriginaluser`. Silent setup
  never launches this action. A `CanLaunchSecblitz` check also blocks launch when
  post-install maintenance has failed; the latched failure still returns exit 20
  and skips the success page. Guided entry must not automatically apply settings.
  Setup does not mutate the **18 hardening controls**. The optional
  service observes **18 controls/19 findings** and never heals/applies/reverts.
* Start the installer normally from an unelevated desktop and allow Setup's UAC
  prompt: Inno retains the original user context for the finish launch. If Setup
  is started already elevated (including “Run as administrator” or an elevated
  shell), `runasoriginaluser` cannot de-elevate the app. Normal unelevated installer
  invocation is required for an unelevated finish launch.
* The default-checked **Show the Secblitz shield in the taskbar corner** task writes
  the HKLM Run value `SecblitzTray` (`"{app}\secblitz.exe" tray`, removed on
  uninstall) and starts the unelevated tray for the person running Setup. Setup
  closes a running tray through Restart Manager and a `WM_CLOSE` to its window;
  the update worker instead signals `Global\SecblitzUpdateQuiesce` and relaunches
  the tray afterwards. Uninstall removes the fixed `{app}\Status` directory.
* Monitor registration is an explicit unchecked task. Task selection is not
  remembered across upgrades. Silent setup defaults to the desktop shortcut and
  no monitor. `/TASKS=monitor` opts into the monitor and out of the desktop shortcut;
  `/TASKS="desktopicon,monitor"` selects both; `/TASKS=""` selects neither optional
  task (the Start Menu shortcut remains). In PowerShell `Start-Process` argument
  arrays, use `'/TASKS=""'` to retain the literal empty-list quotes; do not pass
  literal single quotes as Windows command-line quoting. Registration does not start the monitor;
  automatic startup occurs at the next boot.
* An existing monitor is retained on upgrade even if the new-install task is
  unchecked. Setup validates its exact quoted binary command, LocalService
  account and own-process service type before stopping it. A previously running
  monitor is resumed after upgrade; a previously stopped monitor stays stopped.
  Stop failure aborts before executable replacement. Cancellation/rollback also
  attempts to resume a previously running monitor; a failed restart is logged.
* Uninstall validates the same ownership tuple before stopping anything, waits
  for stop, then delegates unregistering to `secblitz service uninstall`, which
  checks ownership again. Failure or pending deletion aborts uninstall before
  file removal. A same-named foreign service is never stopped or deleted.
* Uninstall removes installer-owned files and shortcuts, including the desktop
  shortcut when installed, then the full cleanup below. Applied settings are
  reverted only when the person chooses "Put everything back the way it was".
### Web protection (0.8.0)

* Setup always runs `InstallFilter`: `secblitz.exe filter install` registers the
  `SecblitzFilter` service (LocalService, own process, **disabled**, never started
  by Setup) and creates `ProgramData\Secblitz\Filter`; maintenance then registers
  the `SecblitzFilterReconcile` task (SYSTEM, `"{app}\secblitz.exe" filter reconcile`;
  triggers: startup, hourly, and NetworkProfile event 10000 when the PC joins a
  network). The service and task get the same ownership checks as the monitor and
  `SecblitzUpdate`: a same-named foreign service or task is refused, never changed.
* `Prepare` stops a running filter next to the monitor and reports what was running
  through its exit code (10 monitor, 11 filter, 12 both); `ResumeFilter` starts the
  filter again after the files are replaced, and cancellation/rollback resumes it.
  While it is down Windows resolves through the next server of the routing rule.
* Maintenance owns the reconcile task. `RemoveFilter` deletes the task first, then
  runs `filter uninstall` (routing rule, service, `Filter` folder).

### Removing Secblitz (0.8.0)

Two choices, wherever the person starts it. The app's sheet answers the question
itself and starts `unins000.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SECBLITZDONE`;
the Windows Settings entry asks it on a plain form (radio buttons, Cancel / Remove
Secblitz) before anything changes. Cancel stops the uninstall untouched.

* **Keep my computer as it is now**: no put-back.
* **Put everything back the way it was**: the uninstaller's status line reads
  "Putting your settings back"; `secblitz.exe uninstall-revert --user` runs as the
  original user (it refuses to run elevated; its exit code is the number of personal
  settings left), then `secblitz.exe uninstall-revert` runs elevated and prints one
  plain line per thing left (captured through a file in the uninstaller's private
  temp folder and read as UTF-8, so no newer Inno Setup function is needed). Anything
  left is shown in one message box and the removal goes on. Removed apps without a
  saved copy are not reinstalled here (no broker); the app's sheet does that.
* A **silent** uninstall without `/SECBLITZDONE` (scripts, IT tools) and one with
  `/SECBLITZDONE` never ask and never put anything back.
* Both choices then run the full cleanup, in this order: the existing monitor and
  update task removal (the only step that can refuse the uninstall), `RemoveFilter`,
  `secblitz.exe uninstall-cleanup --user` as the original user (the person's
  `%LOCALAPPDATA%\Secblitz`), the Inno file removal, then `Purge` from
  `usPostUninstall`: the `SecblitzTray` Run value (only if it starts our
  executable), `{app}\Monitor`, `%ProgramData%\Secblitz` and
  `HKLM\Software\Secblitz`. Paths are fixed. Nothing is deleted unless the whole
  tree passes the checks (no reparse point, no hard link, trusted owner, no
  untrusted write access; the filter's LocalService may hold its own write rights),
  otherwise the data stays and the failure is logged.

* Maintenance is embedded into both Setup and Uninstall and extracted into
  Inno's protected temporary directory. No installed or caller-supplied script
  is executed. PowerShell runs by absolute system path with `-NoProfile`, a
  system working directory and an allowlisted environment. The script disables
  module autoloading and imports inbox modules by absolute path. Uninstall's
  pre-elevation initialization returns without attempting privileged maintenance.
  The environment supplies fixed PATHEXT, and monitor commands use explicit
  non-shell process creation with checked child exit codes. Silent uninstall
  validation failures return nonzero without a custom modal dialog.
* Inno exclusively holds its active uninstall data file. Uninstall identifies
  that exact direct-child `.dat` path from its own executable path and validates
  its metadata, link count, owner and DACL without requesting file-data access.
  All other files/directories stay pinned normally; no `unins*.dat` wildcard
  bypass or changes to unrelated files are used.

## Signing a release

Use a real trusted code-signing certificate available to the build account
(typically backed by a hardware token or signing service). Keep credentials out
of source control and PR workflows. From a Windows SDK signing environment:

```powershell
./scripts/build-release.ps1 -CertificateThumbprint YOUR_40_HEX_CERTIFICATE_THUMBPRINT
```

The script signs and RFC3161-timestamps the app **before** embedding it, configures
Inno to sign its uninstaller and installer, verifies the app and installer with
`signtool verify /pa /all`, and hashes the final bytes. For an external signing
service, adapt the signing command to that provider and keep this ordering and
verification. SHA-256 checksums alone are not signatures. Without a certificate
the build explicitly says UNSIGNED; no trusted-signature claim is made.

## Windows VM acceptance pass

### Recorded v0.2.0 run

The actual Inno 6.7.3 package compiled with `/DAppVersion=0.2.0` and the
guest-tested binary, then passed `/LANG=it /TASKS=monitor` setup (**exit 0**).
Fresh service was Stopped; SCM start produced a new schema-1 report with
**18 observations, 19 findings, incomplete=false**. Running uninstall exited
**0**, removed the app/monitor registration and retained the report. All real
transaction-journal hashes and all **18 pre-fixture baseline states** were
unchanged by packaging. Completion is not a claim that all findings are healthy.

Before packaging, actual registry/wuauserv repair/undo, idempotence and benign
DACL-drift conflict/retry passed. Only eight controls changed. BITS's existing
flagged ACE caused an intentional skip; it was not normalized to manufacture a
passing repair. Tool undo plus manual fixture cleanup restored all 18 baseline
states. See [permissions design](../docs/permissions-design.md).

Historical v0.1.0 running-upgrade/locked-file-rejection acceptance is recorded in
the older results. Archived v0.1.0 artifacts
and matching checksums are under `dist/archive/0.1.0/`; they are not current
downloads or proof of a corrected v0.2.0 repack. The corrected repack has its own
targeted acceptance entry; exact hashes are kept there rather than duplicated here.

The website was launched locally at **http://localhost:57435**. That preview is
not public publication; an enabled download must point to verified current
bytes. Italian custom-message repack validation is recorded as passed; no public
website publication is implied.

### Further acceptance coverage

Run on disposable Windows 10 and 11 x64 VMs; items below are a checklist, not
claims that every variant has passed:

1. Build the actual installer; run `/LOG`, require no missing custom-message
   warnings, and exercise all **six languages**, including Italian failure text.
2. Default interactive install: desktop shortcut and finish launch checked,
   monitor unchecked. Finish opens `guide` without applying settings. Repeat with
   both opt-outs; verify no desktop shortcut or finish launch. Check Explorer,
   desktop and Start Menu icons at 100%, 125%, 150% and 200% scaling. Repeat silent
   setup with default tasks and `/TASKS=""`: no interactive app in either case.
   Inject each post-install failure: exit 20, no success page and no app launch.
3. As a standard user, launch the shortcut and verify the app owns UAC; verify
   standard users cannot modify the executable, maintenance script or directory.
   Start Setup normally through UAC and verify the finish-launched guide has the
   original user's unelevated token. Separately confirm the documented limitation
   when Setup starts already elevated. Neither entry may auto-apply settings.
4. Fresh opt-in install: service uses the installed quoted path and LocalService,
   remains stopped, then starts after reboot and produces read-only observations.
5. Upgrade with a running owned monitor: stop completes before replacement;
   it resumes afterward and reports/journals remain. Uninstall stops and unregisters it before removing
   the app and then deletes reports and journals (see "Removing Secblitz").
6. Test foreign same-name service, locked/stopping service, broad-writable root,
   reparse point, `/DIR` override and pending service deletion: fail closed.
7. Inspect the extracted app, setup and installed uninstaller signatures for a
   signed release. Repeat install/uninstall with `/VERYSILENT /TASKS="" /LOG`.

Automated Windows checks:

* Host-only `python installer/check-locales.py` checks all four custom-message
  keys in all six languages, desktop task/shortcut ownership, explicit `guide`,
  finish-launch flags and the failure-latch callback. Mutation regressions verify
  missing translations and unsafe launch/task edits are rejected. This is source
  coverage, not a substitute for compiled-installer or token-level acceptance.
* `installer/test-maintenance.ps1` also exercises the full-cleanup checks (junction,
  hard link, writable and foreign-owner trees are refused and left whole), the Run
  value ownership rule and the fixed filter commands.
* `installer/test-lifecycle.ps1 -OwnershipFixtures` also checks the reconcile task
  ownership validator with accepted and mutated XML.
* `installer/test-maintenance.ps1` exercises production ACL/path helpers with
  the production no-autoload module bootstrap and isolated temporary fixtures
  (requires elevation).
* `installer/test-setup-exit.ps1 -IsccPath <absolute-ISCC-path>` compiles/runs
  isolated no-install harnesses against production post-install handlers. Success
  must return 0; Secure, monitor install, monitor resume and exception failures
  must return 20. CI runs this after compiling the installer. Prepare failures
  keep Inno's native exit 7; a post-install exception alone is not reliable proof
  that Inno returns failure, hence the latched custom exit code.
* `installer/test-lifecycle.ps1 -SetupPath <absolute-built-setup-path>` checks
  default desktop creation/target/removal, fresh empty-task and monitor-only desktop opt-outs, absence of
  surviving unexpected app processes after silent setup, fresh monitor opt-in,
  running upgrade/resume, web protection registration and upgrade resume, silent
  and `/SECBLITZDONE` removal (keeps the changes; no service, task, Run value,
  settings key, `Monitor` folder or ProgramData folder left), preservation of a
  ProgramData journal sentinel across upgrades only, and a refused removal leaving
  everything in place. It also verifies that a different
  locked Inno-lookalike file causes prompt-free silent rejection, then succeeds
  after unlocking it while preserving both unrelated-file fixtures. It refuses an existing app or
   data directory, desktop shortcut or app process; use a disposable runner.
   The process snapshot cannot detect a short-lived launch; source flag checks
   complement it. The new coverage has not yet been run on a Windows guest.
* Rust service tests exercise malicious descriptors and directory pinning.

Actual rollback journals now contain schema-1 exact service descriptor snapshots
as well as registry/preferences: **128 KiB line bound, 1 MiB WAL bound**. They
contain sensitive local SID/permission history, not collected password secrets.
Keep their restricted ACLs and local retention; never publish raw descriptors,
copy them into the installer. Removing Secblitz deletes them after the person's
choice (they are only needed to put settings back). Restores can reintroduce unsafe original
grants. BITS/wuauserv are the only automatic service-DACL repair targets; no
arbitrary Windows file or third-party software permission reset is bundled.

## Icon source

`assets/secblitz.svg` is the source of truth: a white shield outline with a
lightning bolt inside, on an ink (#18181B) rounded square. It was traced by hand
from the generated artwork in `docs/brand-icon-source.webp` (fal.ai Nano Banana 2).
Frames up to 24px use `assets/secblitz-small.svg`, a solid shield with the bolt
cut out, because the outline blurs at taskbar sizes. The window icon is decoded
from the same `.ico`, and the sidebar mark (`BRAND_SVG`) is the same shape in
one colour. `build.rs` re-embeds resources when the `.ico` changes. `python assets/generate-icon.py` uses installed Pillow (reference
version 12.1.1), without CairoSVG or network access, to render nine independent
supersampled 32-bit RGBA frames from 16 through 256px. `--check` checks exact
regeneration and decodes every ICO frame.
