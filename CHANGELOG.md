# Changelog

All notable changes to Secblitz. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

New work goes under **Unreleased**. `scripts/bump-version.py` moves that section into a
dated version section when a release is prepared (see `docs/RELEASING.md`).

## [Unreleased]

### Added
- Secblitz now runs on Ubuntu, Linux Mint and Fedora, with checks and fixes made for each.
- On Linux, Secblitz can look once a day for a newer version of itself and install it when you say yes.
- On Linux, Free up space shows and clears install files, old crash reports, picture previews, unused app parts, older copies of apps, old system versions and the Trash.
- On Linux, Clean up apps removes remote control and file sharing apps and can install them again.
- On Linux, more checks and fixes cover the network, printers, browsers, location, problem reports and accounts.
- On Linux, new checks cover Bluetooth at start, the weekly list of installed programs and automatic app updates, and tell you who can make changes, which programs are open to the network and whether memory saved to the drive is protected.

### Changed
- Secblitz now says computer instead of PC.

### Fixed
- Secure connections for updates and block lists use newer versions that fix recently found weaknesses.

## [1.1.0] - 2026-10-13

### Added
- A new Free up space tab in Clean up apps removes old temporary files, update leftovers, crash memory files and saved picture previews you choose.
- You can turn on Storage Sense from Free up space, so Windows removes temporary files on its own.

### Changed
- The installer and the Remove Secblitz window have a new look with a banner, and follow Windows light or dark.

## [1.0.0] - 2026-10-09

### Added
- A short welcome on first start explains what Secblitz does and asks before it checks your PC.
- A new Help tab in Settings answers common questions.
- You can save a support file to attach to a problem report; it never includes your files, your user name or the websites you visit.
- When Web protection blocks a dangerous or scam site, a warning appears over your browser so you can go back or open the site just once.
- An accessibility statement explains what already works with the keyboard and what does not yet.
- Each release now comes with a list of the code it is built from.
- The README now lists which versions of Windows are supported and which have been tested.

### Changed
- Secblitz no longer checks your PC by itself the first time it opens.
- Details and dialogs now show one short line per point, and you can open a point to read more.
- Every switch, tab and menu works with the keyboard, and Tab stays inside an open dialog.
- Background checks chosen during installation now start right away instead of after a restart.
- Blocking dangerous sites now also covers sites that spread harmful downloads or apps that secretly spy on people.
- The roadmap is now a short, plain list of what is planned.

### Removed
- The Tools page no longer offers app updates; Windows updates and repair are still there.

### Fixed
- If you remove Secblitz and keep your PC as it is, Secblitz now warns you when a removed app could not be brought back.
- Removing Secblitz while a check is running now waits for the check, so nothing is left out of what it puts back.
- On a small screen with larger text, the Secblitz window no longer opens partly behind the taskbar.
- Typing in the Protection search box no longer stops after the first letter.
- On Windows Home, the drive encryption steps no longer point you to BitLocker, which Home does not have.
- Removing Secblitz from Windows Settings no longer claims that every removed app can come back from the Microsoft Store.
- An app removed the day before now shows as removed "yesterday", not "today".

## [0.11.1] - 2026-10-09

### Changed
- Each setting has one info button that opens a small window explaining it, instead of text that opens under the row.
- The Details button is gone, and the window never repeats a setting's status or the line on its row.
- "More details" on results and errors opens in the same small window.
- Each setting on the Protection page shows at most one tag, and its sections run in one order: needs you, your choices, good to know, already protected.
- Home, Web protection, Clean up apps, Settings, History and Tools use shorter lines and say each thing once.
- Check names and explanations describe each Windows setting and what it protects, in plain words.
- The tray alert for a drop in protection is shorter.
- The installer says that web protection, if you turn it on later, downloads block lists and passes website lookups on.

### Fixed
- The History page no longer shows the same "nothing to undo" line twice.

## [0.11.0] - 2026-10-08

### Added
- Secblitz runs on PCs with an ARM processor, with its own installer.
- PCs with an ARM processor running the regular version are told when a version made for them is available.
- Web protection can block scam sites, fake shops and pop-up spam, off until you turn them on.
- Blocked scam, dangerous and pop-up sites show on the Web page, where you can let one through for 10 minutes.
- The tray tells you which scam or dangerous site was blocked.
- The Web page says when a browser, a VPN or another setting can get around Web protection, including Brave.
- Pick which Chrome and Edge add-ons to turn off, with an exact undo.
- Folder protection stops untrusted apps from changing your personal folders, after first watching which apps need them.
- See when your files were last backed up with File History, OneDrive or Windows Backup.
- A short list of what's new shows once after Secblitz is updated or reinstalled.
- Renew your PC's startup security certificates before the old ones expire, with a clear warning that it can't be undone.
- An optional fix that turns off the Run box, which fake "I'm not a robot" pages use to install password stealers.
- A check that warns when something typed into the Run box looks like a fake check page trick.
- The AI features topic shows when the Copilot app is installed, with a way to remove it.
- A way to start fresh when Secblitz's undo history is damaged, keeping a copy of the damaged files.
- Restore all brings back every removed app in one go.

### Changed
- The app uses the Lexend font, which is easier to read.
- Web protection also turns off Brave's own private lookups.
- Before you agree, every fix says if it can't be undone, needs a restart, or makes your browser say "Managed by your organization".
- Older version downloads are no longer offered on the website.
- Secblitz is now tested on Windows 10 (version 22H2).
- The window's title bar blends into the app, without the icon and name.
- The Home summary is shorter: what Secblitz can fix for you, and when it last checked.

### Fixed
- Setup no longer stops with "could not finish setting up" on some new PCs, including ARM laptops.
- Camera, microphone and location lists show the usual names of the apps that come with Windows 10.
- A start-up program or browser add-on found after a fix is no longer shown as switched back.
- Camera, microphone and location show as off when they are switched off for everyone on the PC.
- Files left over from an update are removed once the update is confirmed.
- Removing apps that came with Windows 10 now works.
- White app icons on Windows 10 show on a colored tile instead of disappearing, including Maps and People.
- An app you chose to remove is closed first if it is open, so its copy is complete.
- Bringing back an app works when Windows already has a newer version of a part it needs.
- An app is no longer reported as already back when Windows only left a folder behind, which removed its saved copy.
- Bringing back apps no longer fails after other apps have been brought back.
- The Copilot key note only shows on Windows 11, where those keyboards exist.
- The link to turn on private lookups now goes straight to its switch.
- Background checks work on Windows 10, where they could not read any settings.
- You are told when Windows switches back a virus protection setting Secblitz fixed.
- Turning the system tray icon on or off takes effect right away instead of at the next sign-in.
- A virus scan now shows that it is scanning while it runs and says when it has finished.
- Background checks start again on their own if they stop unexpectedly.
- Installing a new version or removing Secblitz while it is open now closes it first, so nothing is left behind.
- Fixes, undo and updates are no longer held back while Windows Defender or Windows Update works in the background.
- Settings no longer says automatic updates aren't set up before their first hourly check.
- Long lines in the fix result no longer run into the scroll bar.

## [0.9.3] - 2026-10-07

### Fixed
- Updates install on their own while Web protection is on.

## [0.9.2] - 2026-10-07

### Changed
- The portable version is on GitHub, linked from the download page.

## [0.9.1] - 2026-10-07

### Added
- Protection groups its settings into topic tiles that show what each topic needs.
- A notice when Windows switches back a setting Secblitz fixed, with a way to put it back.
- See which apps used your camera, microphone and location, and switch them off.
- Optional browser settings for Edge, Chrome and Firefox: fewer shopping and AI panels, less usage data, stronger protection and lookups through Web protection.
- Optional privacy switches for online speech, typing data, lock screen messages, the email on the sign-in screen and a random Wi-Fi address.
- Web protection can block adult and gambling sites and turn on safe search.
- Private lookups through Secblitz send website lookups encrypted to Quad9.
- Allow a blocked site in one click from the list of recent blocks.
- A 30-day chart of what Web protection blocked and the companies it blocked most.
- A notice when a dangerous website is blocked.
- Pause Web protection for 15 minutes, 1 hour or until restart.
- Choose which notices Secblitz shows, in Settings.

### Changed
- Tools is split into tabs.
- Web protection is split into Overview, What to block and Sites.
- The History chart shows one point per day, and your starting point until there are two days.
- Secblitz opens in the middle of the screen.
- Links to the source code and to report a problem use the new GitHub address.

### Fixed
- The notification area status stays up to date while background monitoring is on.
- Opening Secblitz while it is already open no longer asks for permission again.

## [0.8.2] - 2026-10-06

### Added
- Optional switches to turn off the AI tools in Paint and Notepad, Click to Do, Widgets and suggested device apps.
- More old Microsoft apps can be removed in Clean up apps, such as Finance, Sports, Paint 3D and Family Safety.
- An Ads and tips tab that hides ads and suggestions in the lock screen, Start, Settings, File Explorer and Game Bar.
- Undo for chosen settings: tick the ones Secblitz changed and put just those back.
- Search on the Protection and Clean up apps pages (Ctrl+F).
- Report a problem or suggest a feature from Settings.
- A privacy policy, summarized in the installer and linked from Settings.
- Credits for the web protection block lists (AdGuard, EasyList, HaGeZi).
- Tools sections open and close and remember how you left them.

### Changed
- The Microsoft 365 row uses the app's current name and notes that removing it may change the Copilot key.
- The Duolingo row now finds the app when it is installed.
- Fixes, app removal, repairs and updates check what they need before they start.
- "Run as administrator" now reopens Secblitz normally and asks for permission once.
- Fix details no longer repeat the row above them.
- The Web protection page no longer shows its on or off state twice.
- PC health tips come first on the Tools page.
- Secblitz is open source under the MIT license.
- Items to fix say what they protect you from, in calmer words.
- Clean up apps no longer ticks any app for you.
- Fixes say when Windows Update is busy and offer to try again.
- Smoother and faster screens.

### Fixed
- Secblitz no longer offers to hide the Administrator account you are signed in with.
- The list of running fixes stays centered and its scroll bar no longer covers the names.
- The score circle turns green when everything it counts is protected.
- A fix that stops partway no longer says nothing was changed.

### Removed
- The password maker, replaced by Bitwarden.
- Three notes about issues another fix already covers.

## [0.8.1] - 2026-10-06

### Fixed
- Automatic updates from 0.7.0 now finish every step.

## [0.8.0] - 2026-10-06

### Added
- Web protection blocks ads, trackers and dangerous websites on the whole PC.
- Remove Secblitz from Settings, keeping its changes or putting everything back.
- Put everything back in one step, including removed apps.
- Fixes for automatic sign-in, Remote Desktop and the old SMB1 file sharing.
- Memory integrity and kernel stack protection, on supported PCs.
- Fixes for risky start-up programs, firewall allowances, background programs and redirected websites.
- A Restart now button when Windows is waiting for a restart.
- Fixes for unused old accounts, folders shared with everyone and turned-off browser warnings.
- Remove threats Windows Security found, from the Tools page.
- Turn the Windows recovery tools back on.
- Health tips link to the matching fix.
- Name, version and copyright in the file properties of the app and Setup.
- Builds from source on GitHub, with checksums and build proof.

### Changed
- Opening Secblitz shows the last result if it is less than an hour old.
- Every error says what happened and what to do.
- "Block suggested apps" can now be undone.
- PowerShell starts with a plain command and a normal safety policy.
- The installer asks whether to keep or put back your changes when you remove Secblitz.

### Fixed
- A damaged web protection folder no longer stops the app from starting.
- Web protection counts ad networks as ads and passes on unusual but valid website names.
- The uninstaller no longer leaves an empty folder behind.

## [0.7.0] - 2026-10-05

### Added
- A full app window with Home, Protection, Tools, History and Settings.
- Clean up apps removes unused built-in apps, with a saved copy to restore them.
- More than 50 security and privacy settings, each explained.
- Tools for virus scans, Windows repair, updates, health tips and Bitwarden.
- Background monitoring from the notification area.
- Light and dark mode, and six languages.
- A new shield-and-bolt icon.

### Fixed
- Four settings that could never be read on a real PC now work.
- Windows repair and updates work when Secblitz is opened from File Explorer.
- A PowerShell injection weakness and two administrator access weaknesses.

## [0.6.1] - 2026-10-04

### Changed
- A redesigned terminal screen and report.

## [0.6.0] - 2026-10-03

### Added
- A broader assessment of Defender, accounts, remote access, updates, recovery, storage and networking.
- Windows repair (DISM and SFC) and quality updates, each approved by you.
- Profiles for everyday use, gaming, development and higher security.
- Gradual rollout of updates.

### Fixed
- The update health check recognizes the system account name Windows reports.

## [0.5.0] - 2026-10-03

### Added
- A recommended fix plan you approve in one step.
- A new scan after every fix or undo.
- Four device readiness checks.
- Updates come from secblitz.lol with a pinned signature.

### Fixed
- A firewall setting Windows already blocks is no longer offered as a fix.
- Information-only items no longer count as needing attention.

## [0.4.3] - 2026-10-03

### Fixed
- Older update files can no longer roll a PC back.

## [0.4.2] - 2026-10-03

### Fixed
- Installer and updater reliability.

## [0.4.1] - 2026-10-03

### Fixed
- Installer and updater reliability.

## [0.4.0] - 2026-10-03

### Added
- Signed automatic updates.
- A portable download next to the installer.

## [0.3.0] - 2026-10-02

### Added
- A Windows installer with an uninstall entry.
- Keyboard-only navigation.

## [0.2.0] - 2026-10-02

### Added
- 18 security settings that can be fixed and undone.
- Exact undo of every change.

## [0.1.0] - 2026-10-02

### Added
- The first release: scans Windows security settings and explains the results.
