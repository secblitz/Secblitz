<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/banner-dark.webp">
  <img src="docs/banner-light.webp" width="900" alt="Secblitz">
</picture>

Secblitz turns on the security and privacy settings your computer leaves off, in one click. It runs on Windows and Linux, removes unwanted apps and blocks ads, trackers and malware sites on your whole computer. Every change can be undone.

[**Download for Windows**](https://secblitz.lol/downloads/secblitz-1.1.0-windows-x64-setup.exe) · [**Install on Linux**](#linux) · [Website](https://secblitz.lol) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md)

![Version 1.1.0](https://img.shields.io/badge/version-1.1.0-18181B) ![Windows 10 and 11, x64 and ARM](https://img.shields.io/badge/Windows%2010%20%26%2011-x64%20%7C%20ARM-18181B) ![Ubuntu, Linux Mint, Fedora and Debian](https://img.shields.io/badge/Linux-Ubuntu%20%7C%20Mint%20%7C%20Fedora%20%7C%20Debian-18181B) ![MIT license](https://img.shields.io/badge/license-MIT-18181B)

<img src="docs/tour.webp" width="900" alt="A tour of Secblitz: checking the PC, fixing problems, blocking a dangerous site, removing apps and undoing a change.">

</div>

## How it works

1. **Check.** Secblitz looks at your computer's settings and shows which ones could be safer. It takes about a minute and changes nothing.
2. **Review.** Each setting says what it protects against and what changes for you.
3. **Fix.** One click fixes everything you approved. Secblitz then confirms each fix worked.
4. **Undo.** Every change is recorded. History puts your old settings back.

## Features

- **One-click fixes** for security and privacy settings. On Windows, more than 50: virus protection, firewall and network, sign-in, updates, startup, disk and privacy. On Linux, more than 60: firewall, updates, the system, the network, the screen lock, sharing, browsers and accounts. Anything already secure is left alone.
- **Unwanted app removal.** On Windows, removes bloatware that came with the PC and keeps a copy of each, so you can restore it later, even offline. On Linux, removes remote control and file sharing apps you don't use and can install them again.
- **Free up space.** Shows how much space old temporary files, install files, crash reports, old app and system versions and saved picture previews take, and removes the ones you choose.
- **Ad and malware blocker.** Blocks ads, trackers and malware sites in every browser and app.
- **Background monitoring.** Tells you if your protection gets worse.
- **History** of every change and every removed app.
- **Six languages:** English, Spanish, French, German, Portuguese and Italian. Light and dark mode.

Secblitz only looks at settings on this computer and changes them with your approval. It does not look at other devices, list open ports or test passwords.

Secblitz is not an antivirus. It turns on and configures the protection built into your system, and it leaves third-party antivirus and computers managed by work or school alone.

## Install

### Windows

Download the [installer](https://secblitz.lol/downloads/secblitz-1.1.0-windows-x64-setup.exe) (about 11 MB) and run it. For a PC with an ARM processor, like a Snapdragon laptop, use the [ARM installer](https://secblitz.lol/downloads/secblitz-1.1.0-windows-arm64-setup.exe) instead. Secblitz asks for administrator permission because it reads and changes system settings.

The installer is not code-signed yet, so Windows may show an unknown publisher warning. Choose **More info**, then **Run anyway**. To check the file, compare its SHA-256 with the one on the [download page](https://secblitz.lol/#download):

```powershell
Get-FileHash .\secblitz-1.1.0-windows-x64-setup.exe -Algorithm SHA256
```

Each release also has a parts list (`.cdx.json`) on its [GitHub release page](https://github.com/secblitz/Secblitz/releases) that names every piece of code Secblitz is built from.

Using Secblitz 0.9.2 or older with Web protection on? It can't update itself to a newer version. Download and run the installer once; your settings, history and undo stay.

### Linux

Open a terminal and run:

```sh
curl -fsSL https://secblitz.lol/install.sh | bash
```

It finds your kind of Linux and processor, downloads the matching package, checks it against the fingerprint published with the release and installs it. It asks for your password once, to install. Running it again updates Secblitz. Then open Secblitz from your app menu.

Prefer to install the package yourself? Download it and open it with your software app, or install it from a terminal:

| Processor | Ubuntu, Linux Mint, Debian | Fedora |
| --- | --- | --- |
| x64 | [secblitz-1.5.0-linux-x64.deb](https://secblitz.lol/downloads/secblitz-1.5.0-linux-x64.deb) | [secblitz-1.5.0-linux-x64.rpm](https://secblitz.lol/downloads/secblitz-1.5.0-linux-x64.rpm) |
| ARM | [secblitz-1.5.0-linux-arm64.deb](https://secblitz.lol/downloads/secblitz-1.5.0-linux-arm64.deb) | [secblitz-1.5.0-linux-arm64.rpm](https://secblitz.lol/downloads/secblitz-1.5.0-linux-arm64.rpm) |

```sh
sudo apt install ./secblitz-1.5.0-linux-x64.deb   # Ubuntu, Linux Mint, Debian
sudo dnf install ./secblitz-1.5.0-linux-x64.rpm   # Fedora
```

Secblitz on Linux asks for your password before it changes anything, and checks for its own updates once a day if you turn that on.

### macOS

Not available yet.

## Supported systems

### Windows

| Windows | Edition | Version | Processor | Supported | Tested |
| --- | --- | --- | --- | --- | --- |
| Windows 11 | Home | 24H2 | x64 | ✓ | ✓ 1.0.0 |
| Windows 11 | Pro | 25H2 | x64 | ✓ | ✓ 1.0.0 |
| Windows 11 | Enterprise | 25H2 | x64 | ✓ | ✓ 1.0.0 |
| Windows 11 | Pro | 24H2 | ARM | ✓ | Not yet |
| Windows 10 | Home | 22H2 | x64 | ✓ | Not yet |
| Windows 10 | Pro | 22H2 | x64 | ✓ | Not yet |
| Windows 10 | Enterprise | 22H2 | x64 | ✓ | ✓ 1.0.0 |

Secblitz supports Windows 10 version 22H2 and Windows 11, in the Home, Pro and Enterprise editions. It works from an administrator account or a standard account; on a standard account, Windows asks for an administrator's password before Secblitz changes anything. Microsoft stopped free security updates for Windows 10 on 14 October 2025 and Secblitz cannot replace them, so moving to Windows 11, or Microsoft's Extended Security Updates, keeps a Windows 10 PC safest.

### Linux

| Linux | Version | Desktop | Processor | Supported | Tested |
| --- | --- | --- | --- | --- | --- |
| Ubuntu | 26.04 | GNOME | x64 | ✓ | ✓ 1.5.0 |
| Ubuntu | 24.04 | GNOME | x64 | ✓ | Not yet |
| Linux Mint | 22.3 | Cinnamon | x64 | ✓ | ✓ 1.5.0 |
| Fedora | 44 | GNOME | x64 | ✓ | ✓ 1.5.0 |
| Fedora | 43 | GNOME | x64 | ✓ | Not yet |
| Debian | 12, 13 | GNOME | x64 | ✓ | Not yet |
| Any of the above | | | ARM | ✓ | Not yet |

Secblitz needs systemd and a desktop session. Screen lock and desktop privacy settings are made for GNOME and Cinnamon; on other desktops, Secblitz still checks and fixes the system, the network and the browsers. Web protection needs systemd-resolved, which these systems use by default.

### macOS

Not supported yet.

## Uninstall

### Windows

Open **Settings**, then **Apps**, then **Installed apps** (on Windows 10: **Apps**, then **Apps and features**). Find Secblitz and choose **Uninstall**. Secblitz asks whether to keep your PC as it is now or put everything back the way it was. Either way, it removes itself.

You can also open Secblitz, go to **Settings** and choose **Remove Secblitz from this computer**. If you use the portable version, do that to put your settings back, then delete the `secblitz.exe` file.

### Linux

Open Secblitz, go to **Settings** and choose **Remove Secblitz from this computer**, or remove it from your software app. From a terminal: `sudo apt remove secblitz` (Ubuntu, Linux Mint, Debian) or `sudo dnf remove secblitz` (Fedora). Removing the package keeps Secblitz's undo history, so a reinstall can still put your settings back.

## Build from source

On Windows 11, install:

- [Rust](https://rustup.rs) (the pinned compiler in `rust-toolchain.toml` is selected automatically)
- [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/) with "Desktop development with C++"
- [Inno Setup 6.4 or later](https://jrsoftware.org/isinfo.php), only for the installer

```powershell
git clone https://github.com/secblitz/Secblitz.git
cd Secblitz

# The app only: target\release\secblitz.exe
cargo build --locked --release

# Tests, the app and the installer: dist\
powershell -ExecutionPolicy Bypass -File scripts\build-release.ps1
```

To build the Windows app from Linux, or the Linux `.deb` and `.rpm`, see [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/RELEASING.md](docs/RELEASING.md).

## Privacy

No account, no ads, no telemetry. Secblitz goes online to update itself (if updates are on), for actions you start, and to download block lists if web protection is on. See the [privacy policy](https://secblitz.lol/privacy.html).

## Code signing policy

Free code signing provided by SignPath.io, certificate by SignPath Foundation. Releases are built from this repository by GitHub Actions, and each signing request is approved by hand. Read the full [Code signing policy](docs/CODE_SIGNING.md), also on the [website](https://secblitz.lol/code-signing.html).

## Security and contributing

For how well Secblitz works with the keyboard and other ways of using a PC, see the [accessibility statement](docs/ACCESSIBILITY.md). For what is planned, see the [roadmap](docs/ROADMAP.md). To report a security problem, see [SECURITY.md](SECURITY.md). To build Secblitz or send a change, see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). Fonts, icons, libraries and block lists from others are credited in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
