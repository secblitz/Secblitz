# Report translation source keys

Each line below is an exact English `Lang::t` source key (and fallback content). Translate full sentences, not tokens. `src/advice.rs` returns these keys; `src/ui.rs` translates them at rendering time. Do not translate IDs, status input tokens, or the exact backend reason strings matched by advice. Existing keys may already be present. The i18n agent owns catalog additions; this change does not edit `src/i18n.rs`.

## Frame, status, and progress

```text
Less worry. More protection.
Your computer, checked.
Protection
Status
Why it matters / Next step
Recommended fixes
Protected
Needs your choice
Good to go
Can fix
Fixed
Couldn't check
Managed elsewhere
Restart needed
Checking
Complete
Details
Transaction
No checks were returned. Run a new check to review protection.
Your saved changes were reviewed.
Your changes are saved. Undo is available for recorded changes.
```

## Friendly control and finding labels

```text
Live virus protection
Suspicious app detection
Downloaded file checks
Compressed file checks
Work network firewall
Home network firewall
Public network firewall
Work network incoming connections
Home network incoming connections
Public network incoming connections
Permission prompts
Administrator approval
App installation permissions
Account name privacy
Remote sign-in safeguards
Sign-in secret protection
Update download protection
Windows Update protection
Additional protection checks
Protection check
Your security apps
Network protection
Virus protection
Windows support
Protection if your computer is lost
Startup protection
Windows updates
Remote access
Older file sharing
Unsafe app and website warnings
Core system protection
Who manages this computer
Automatic sign-in
Update download permissions
Windows Update permissions
Antivirus service permissions
Scheduled task service permissions
Protection monitor permissions
Saved changes
```

## Control guidance and result explanations

```text
Open Windows Security and review Virus & threat protection.
Open Windows Security and review Firewall & network protection.
Review User Account Control settings with your administrator.
Ask your administrator to review app installation permissions.
Ask your administrator to review anonymous access to account names.
Review account passwords and remote sign-in access with your administrator.
Ask your administrator to review how Windows keeps sign-in secrets.
Ask your administrator to review update service permissions.
View details and run the check again before deciding what to change.
Secblitz can fix this. Help protect against uninvited connections.
Secblitz can fix this. Help protect updates from tampering.
Secblitz can fix this. Stop keeping reusable sign-in secrets after a restart.
Secblitz can fix this. Restore permission prompts after a restart.
Secblitz can fix this. Ask for approval before administrator changes.
Secblitz can fix this. Limit elevated permissions for app installers.
Secblitz can fix this. Limit anonymous access to account names.
Secblitz can fix this. Restrict remote sign-ins with blank passwords.
Secblitz can fix this. Turn on this virus protection setting.
No action needed for this check.
This setting was updated and checked.
Your earlier setting was restored.
Review saved changes and finish undo before making more changes.
This setting changed since it was saved. Review details before undoing it.
Ask the person or organization managing this computer to review this setting.
Kept your existing setting. It may already protect you or use Windows defaults; review details if unsure.
Save your work and restart your computer to finish this change.
```

## Finding guidance

```text
Open Windows Security to check which security app is active and healthy.
Open Windows Security to review virus protection and protection updates.
Check support for your Windows version and edition, including any extended support plan.
Review device encryption and save your recovery key before changing encryption settings.
Check your computer maker's Secure Boot instructions before changing firmware settings.
Open Windows Update and check for updates. An offline check cannot confirm you are up to date.
Review Remote Desktop in Settings. Turn it off if you do not use it.
Review older device dependencies before turning off SMB1 in Windows Features.
Review reputation-based protection in Windows Security and your browser.
Review who can sign in. Use unique passwords and extra sign-in verification where supported.
Review Core isolation in Windows Security and driver compatibility before enabling memory integrity.
Review work or school connections in Settings if you are unsure who manages this computer.
Review automatic sign-in and physical access to this computer before changing your sign-in routine.
Review update service permissions with your administrator. Only a separately listed fix can be selected.
Ask your administrator to review antivirus service permissions.
Ask your administrator to review scheduled task service permissions.
Ask your administrator to review Secblitz monitor service permissions.
Review saved changes before undoing them or making more changes.
```

## Impact phrases

Each phrase is a noun phrase naming the concrete threat a check guards against, translated as a standalone key. They are used in `src/advice.rs` via `control_impact()` and `finding_impact()`, and rendered via `impact_line()` in `src/ui.rs`. Empty impact means no impact line is shown.

### Prefix keys

```text
Risk:
Protects you from:
Why it matters:
```

### Control impact phrases

```text
A full drive stopping fixes and updates from completing
Malware running as soon as it lands on your computer
Apps that behave like malware even when not yet known
Harmful files downloaded from the web or email attachments
Malware hidden inside zip and other compressed files
Other devices on your work network reaching your computer
Other devices on your home network reaching your computer
Other devices at public places like cafes or airports reaching your computer
Uninvited incoming connections on your work network
Uninvited incoming connections on your home network
Uninvited incoming connections on public networks like cafes or airports
Apps silently making system-wide changes without asking you
Apps making administrator changes without asking for approval
Any app installer quietly getting full control of your computer
Other devices on the network seeing your account names
Someone signing in over the network to an account with no password
Altered Windows updates reaching your computer
```

### Finding impact phrases

```text
Running Windows that no longer gets security fixes
Someone who finds your computer reading your files if it is lost or stolen
Hidden malware loading before Windows starts
Missing security fixes on your computer
Old file-sharing flaws used by worms like WannaCry
Scam websites and unrecognized apps you open by mistake
Malicious drivers taking over the core of Windows
Anyone who turns on your computer getting straight into your account
```

### Payoff section headings

```text
You're now protected from:
After you restart, you'll be protected from:
```

### Recap notes

```text
Needs a restart to finish
```

## Design notes

**Borders**: All CLI table and card borders use rounded corners (`╭╮╰╯`). Internal borders use `─│┬┴┼├┤`.

**Status chips**: The status cell in the wide table is prefixed with a glyph: `✓ Good to go` (green), `! Can fix` (yellow), `↻ Restart needed` (yellow), `? Couldn't check` (dim), `• For your information` (dim). Colour is derived from the glyph character.

**Group headings**: Each group heading in both the CLI report and the TUI report text carries an icon and count. CLI: `! Recommended fixes (N)`. TUI: `▸ Recommended fixes (N)`.

**Totals line**: `! Recommended fixes: N · ✓ Protected: N · ? Needs your choice: N`.

## Integration note

The catalog-coverage test validates that all impact phrases and prefix keys are in the TEXT/ITALIAN catalogs, and that they are translated in all six languages. The test `advice_impact_keys_are_translated_in_all_six_languages` in `src/i18n.rs` enumerates control and finding impact keys. Preserve qualified language such as “may”, “this check”, and “before”: absent settings, unknown health, and audit-only findings are intentionally not reported as confirmed protection or automatic repairs.
