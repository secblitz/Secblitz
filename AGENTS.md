# Working on Secblitz

Instructions for maintainers and coding agents. Read this before changing
anything. CONTRIBUTING.md has the short version for first-time contributors.

## What Secblitz is

A Windows 10 (22H2) and Windows 11 (x64 and arm64) desktop app, written in Rust with the iced GUI toolkit, that
checks a PC's security, privacy and cleanup settings and fixes them when the
user says yes. The users are not technical. Everything follows from that:

- **Plain words.** No jargon, acronyms or fear in anything a user reads. No em
  dashes in user-facing text, docs or the website. Say what happens, not how.
- **The user decides.** Checking never changes anything. Nothing changes
  without a clear yes, and optional settings are never pre-selected.
- **Automatic, reversible fixes.** A flagged item should become a fix Secblitz
  applies itself, after the user approves, with an exact undo recorded first.
  Send the user to do something by hand only where Windows forbids an app from
  doing it. A change that cannot be undone must say so before the user agrees.
- **No disruption.** Never close the user's apps, restart the PC, or open a
  console window. Every child process the GUI starts must be created with
  `CREATE_NO_WINDOW` (see `src/operations/process.rs`).
- **Every check explains itself.** A new check needs its "what it is", "if it's
  off" and "if you turn it on" text in `src/explain/`. Tests fail without it.
- **Six languages.** Every user-facing string exists in English, Spanish,
  French, German, Portuguese and Italian (`src/i18n.rs`). If you cannot
  translate, add a TSV row to `i18n-pending/` (format in its README) and run
  `python3 scripts/merge-i18n-pending.py`.

## Layout

| Path | What lives there |
| --- | --- |
| `src/main.rs`, `src/launcher.rs` | Entry point, command line, elevation and single instance |
| `src/gui/` | The iced app: `gui.rs` (state, messages), `pages/`, `widgets/`, `theme.rs`, `icons.rs` |
| `src/app/` | App-side state that is not drawing: settings, last check, history |
| `src/engine.rs`, `src/hardening.rs`, `src/model.rs` | Checks, the report, applying and reverting changes |
| `src/explain/` | Plain-language text for every check |
| `src/platform/`, `src/platform.rs` | Windows access: registry, journal of changes, ACLs, the state folder |
| `src/broker.rs` | The admin helper's request list; every elevated action goes through it |
| `src/service/`, `src/filter/` | The background monitor service and web protection |
| `src/updater/`, `src/updater.rs` | Signed self-update (feed format: `docs/update-contract.md`) |
| `src/debloat/`, `src/uninstall.rs` | Removing and restoring apps, and the uninstall choice |
| `installer/` | Inno Setup script, maintenance script and installer test harnesses |
| `scripts/` | Release, signing, website and version tools (Python, standard library unless noted) |
| `website/` | The download page; built and checked by `scripts/assemble-site.py` |
| `docs/` | Design notes, security model, release process |

State lives in `C:\ProgramData\Secblitz` (admin-only ACL). User preferences (`gui-prefs.json`)
live in `C:\ProgramData\Secblitz\App`. Never widen an ACL or write state somewhere a standard
user could tamper with it.

## Build and test

The pinned compiler is in `rust-toolchain.toml`. Always pass `--locked`.

```sh
# Portable logic and tests, on any OS
cargo test --locked --all-targets

# The Windows app, cross-built from Linux with MinGW-w64
cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings
cargo build --locked --release --target x86_64-pc-windows-gnu

# Native Windows on ARM, cross-built from Linux (llvm-mingw, see CONTRIBUTING.md)
cargo clippy --locked --target aarch64-pc-windows-gnullvm --all-targets -- -D warnings

# Tool and website checks (Python 3, run from the repository root)
python3 installer/check-locales.py
python3 scripts/release-tests.py          # needs scripts/requirements-release.txt
python3 scripts/bump-version-tests.py
python3 scripts/make-sbom-tests.py
python3 scripts/build-site-assets.py --check
python3 scripts/historical-downloads.py check
```

The PowerShell parts of the Windows backend (`src/platform/*.ps1`) have
fixture tests next to them (`*.tests.ps1`). They load only the function
definitions and change nothing, so run them with `pwsh -NoProfile -File <test>`
(PowerShell 7, any OS) or Windows PowerShell 5.1 whenever you touch a script.
Scripts must stay compatible with Windows PowerShell 5.1.

On Windows, `scripts/build-release.ps1` runs the tests, clippy and the MSVC
build and compiles the installer. CI (`.github/workflows/ci.yml` and
`windows.yml`) runs all of the above plus the installer harnesses in
`installer/test-*.ps1` and a RustSec audit, skipping the app and installer
checks when a change touches only the website or prose. All of it must pass
before merging.

Tests are not enough. Before calling a change done, run the built app on a real
Windows 11 PC or VM and use the feature the way a user would: install, check,
fix, undo, update and uninstall where they are affected. Use a disposable VM for
anything that changes system settings. Say in the pull request what you tried.

Build output is large. Use one shared `target/` directory instead of a fresh
one per branch or worktree, and delete worktree build folders when done.

## Code style

- Match the code around you: naming, error handling, module shape.
- Keep comments rare. Write one only when the reason is not visible in the
  code: a Windows quirk, a security boundary, an ordering that matters. Never
  narrate what the next line does, and never leave notes about the change
  itself ("new", "fixed", "was X").
- Do not reformat files you are not changing, and keep diffs to what the
  change needs.
- Errors shown to users are plain sentences with a real next step. No error
  codes or stack traces in the GUI; put detail in the log.
- Windows-only code sits behind `#[cfg(windows)]` with a portable fallback, so
  `cargo test` keeps working on Linux and macOS.
- New dependencies need a reason. Each one is code that runs as admin.

## Security rules

- Never commit secrets, keys, tokens, passwords or personal data. The update
  feed signing key never leaves the owner's machine and never goes into CI.
- Never obfuscate, pack or otherwise disguise the binaries, even when an
  antivirus flags a build. False positives are reported to the vendor and fixed
  by code signing, never by hiding what the code does.
- Every elevated action is a typed request in `src/broker.rs`. Do not add a
  generic "run this command as admin" path.
- Do not weaken the update checks: signature, pinned key, version floor,
  expiry and hash all stay mandatory.
- Report vulnerabilities privately (see `SECURITY.md`).

## Versions and releases

The full process, including the GitHub settings it needs, is in
`docs/RELEASING.md`. The parts people get wrong:

- Add user-facing changes to the `Unreleased` section of `CHANGELOG.md`, in
  plain words, as you make them.
- Bump with `python3 scripts/bump-version.py X.Y.Z`. It moves the version
  everywhere (Cargo, installer resources, changelog, README, website).
- **A published version is final.** Installed copies remember the hash of
  every version they have seen, so a fix to a released build always ships as a
  new version. Never re-sign or replace the files of an existing version.
- When a release replaces the previous one, its downloads stay published:
  append their hashes to `scripts/historical-downloads.sha256` (append, do not
  re-sort) and add the version to `HISTORICAL` in `scripts/stage-pages.py`.
- Test the upgrade from the version users have now, not only a clean install,
  including the automatic update path that runs as SYSTEM.

## Commits and pull requests

- Small commits with a sentence that says what changed for the user or why.
- No generated-by, co-authored-by or tool attribution lines in commits or pull
  requests.
- Do not commit local material. `.gitignore` already covers build output,
  `video/`, `docs/superpowers/`, `.claude/`, `CLAUDE.md`, `.desloppify/`,
  `.wrangler/` and similar. Keep personal notes and agent state in those places
  or outside the repository.
- Pushing to `main`, tagging, publishing a release and deploying the website
  are owner decisions. Agents prepare them and ask.
