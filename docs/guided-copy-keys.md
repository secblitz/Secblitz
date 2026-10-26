# Guided copy and localization handoff

## Scope

Localization changes are confined to `src/i18n.rs` and this note. The catalog keeps the existing five-column `TEXT` table plus the source-keyed `ITALIAN` table. Every source key has a nonempty translation in English, Spanish, French, German, Portuguese and Italian. Duplicate entries from the interrupted work have been removed; the uniqueness and Italian key-parity tests remain strict.

## Voice and shared labels

The current CLI heading is **A safer computer. Without headaches.** The report's **Less worry. More protection.** also has complete translations. Both are presentation copy, not guarantees that every finding is fixed. The old technical heading remains a legacy catalog key; the main application now requests the new heading.

`Lang::control` uses `ui::advice::control_label`, so the selection menu, progress and friendly report use the same translated name. Examples include live virus protection, suspicious app detection, home/work/public network protection, account name privacy, sign-in secret protection and Windows Update tamper protection. Unknown control IDs remain verbatim. Technical control IDs and JSON fields/values are not renamed.

Keyboard menu copy uses full source keys, including **Choose an action**, **Choose what to fix**, **Select the fixes you want.**, **Yes, continue** and **No, go back**. Italian examples: **Scegli un'azione**, **Scegli cosa correggere**, **Seleziona le correzioni che vuoi.**, **Sì, continua**, **No, torna indietro**. Translation does not grant consent or change the menu's confirmation behavior.

The exact keyboard instructions are:

- `Use ↑/↓ to move, Enter to choose, Esc to go back.`
- `Use ↑/↓ to move, Space to select, Enter to continue, Esc to cancel.`

Italian: **Usa ↑/↓ per spostarti, Invio per scegliere, Esc per tornare indietro.** For multiple selections: **Usa ↑/↓ per spostarti, Spazio per selezionare, Invio per continuare, Esc per annullare.**

The reviewed confirmation implementation uses the selection hint: arrows move between **Yes, continue** and the default **No, go back**, and a single Enter submits the highlighted choice. Space does not approve. There is no extra Enter step or second confirmation prompt. The old `Press Enter to confirm, or Esc to cancel.` catalog key remains for compatibility but is not tested or described as active copy. Menu titles and choices have no numeric prefixes.

Menu validation and resize failures are covered in every language. The landed implementation uses `Terminal is too short to display a menu` for insufficient height and `Operation failed` when dependency interaction unwinds after a resize. Native I/O errors may retain their OS wording. Review source: `src/menu.rs`; completed implementation handoff: `docs/keyboard-review.md`.

## Input and evidence boundaries

| Language | Enter | Space | Esc |
| --- | --- | --- | --- |
| English | Enter | Space | Esc |
| Spanish | Intro | Espacio | Esc |
| French | Entrée | Espace | Échap |
| German | Eingabe | Leertaste | Esc |
| Portuguese | Enter | Espaço | Esc |
| Italian | Invio | Spazio | Esc |

Hints translate as complete sentences; individual key names are not added as generic translation fragments. Historical numbered-menu and typed-selection keys may remain in the catalog but are not keyboard-menu instructions. `all`, `none`, `complete`, `opened`, `returned` and `running` still translate only as whole values in the detail renderer, not as generic fragments in native evidence. Existing longest-key matching and identifier/path boundaries remain. Tests retain raw IDs, Settings URIs, paths, SIDs and hexadecimal codes.

## Covered sources and semantics

- Actual `main.rs`, `guided.rs`, `menu.rs`, `ui.rs`, `advice.rs`, `actions.rs`, `actions/windows.rs`, engine, service, native platform and permissions source literals are included in the diagnostic coverage check.
- Every fixed guided/menu sentence and the single-word Back/Exit choices must have exact catalog entries, not merely translatable fragments. Test-module literals are excluded. A regression check rejects numbered menu labels and typed-number instructions in the production guided/menu sources.
- Keyboard translation checks use the actual `menu::SELECT_HINT` and `menu::MULTI_HINT` constants. Retired catalog hints do not stand in for current implementation coverage. Both owned files are checked for absence of U+2014; sentence punctuation uses ordinary hyphens or other supported punctuation.
- Every key in the text blocks of `docs/report-copy-keys.md` must have an exact entry, including single-word headings and statuses.
- Fixed `throw` messages in `actions/defender.ps1` are checked independently.
- Selected-batch errors cover invalid/duplicate selection, ownership conflicts, incomplete ordering and invalid active ownership history.
- Desktop Settings handoff covers the non-elevated-window requirement, returning to the original window, renewed consent, renewed administrator permission and failure details.
- Action explanations preserve uncertainty: a returned Defender command is not independently verified scan completion or current signatures; opening Settings is not a fix; a running monitor does not establish report freshness. Extra actions are outside undo.
- Failure copy preserves partial-change and stale-check cautions. It does not turn skipped, unknown, managed, conflicted or incomplete work into confirmed protection.

The brand/version template `Secblitz · v{}` and fixed service-host command arguments are intentionally language-neutral. Native OS messages may remain in the OS language; application-authored rationale is translated.

## Verification commands

```sh
source target/build-tools/cross-env.sh
cargo test --bin secblitz i18n
cargo test --bin secblitz
cargo clippy --all-targets -- -D warnings
rustfmt --check src/i18n.rs
```

Final single-Enter/resize review checked the landed `src/menu.rs` against `docs/keyboard-review.md`. Current results with the cross-build environment sourced:

- `cargo test --locked --bin secblitz i18n`: **12 passed, 0 failed**.
- `cargo test --locked --bin secblitz`: **46 passed, 0 failed, 2 ignored**. This includes single-Enter confirmation, ignored Space/text, default No, resize-error handling, whole-key coverage, all six languages and the U+2014 exclusion check.
- `cargo clippy --locked --all-targets -- -D warnings`: **passed**.
- `cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets -- -D warnings`: **passed** (cross-target checking, not guest execution).
- `rustfmt --check --config skip_children=true src/i18n.rs`: **passed**.
- The ignored native keyboard and live-resize probes require an attended terminal or PTY driver. They were not executed by this localization pass; the menu review records its owner's separate PTY results.
- Cargo briefly waited for shared build/artifact locks, then completed normally. No unresolved build lock or missing production translation remained.

These are host checks; no guest operation is involved. The menu implementation and any attended keyboard testing remain owned by the menu agent. Any later English source-copy change must update both catalogs and rerun the checks before integration.
