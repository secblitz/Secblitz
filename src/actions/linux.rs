//! Opening the desktop's own Privacy settings for the person who asked. The program and its one argument are fixed
//! per desktop, and nothing is started unless the program is there.
#![cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
use crate::linux::distro::Desktop;
use std::path::Path;

pub(super) const GNOME_SETTINGS: &str = "/usr/bin/gnome-control-center";
pub(super) const CINNAMON_SETTINGS: &str = "/usr/bin/cinnamon-settings";
const PANEL: &str = "privacy";

pub(super) fn privacy_command(
    desktop: Desktop,
    exists: impl Fn(&Path) -> bool,
) -> Option<(&'static str, &'static str)> {
    let program = match desktop {
        Desktop::Gnome => GNOME_SETTINGS,
        Desktop::Cinnamon => CINNAMON_SETTINGS,
        Desktop::Other => return None,
    };
    exists(Path::new(program)).then_some((program, PANEL))
}

#[cfg(target_os = "linux")]
pub(super) fn open_privacy() -> anyhow::Result<()> {
    use std::process::{Command, Stdio};

    /// What a program needs to open a window on the person's desktop, and nothing else.
    const SESSION: [&str; 10] = [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_TYPE",
        "DBUS_SESSION_BUS_ADDRESS",
        "HOME",
        "LANG",
        "LANGUAGE",
    ];

    let desktop =
        crate::linux::distro::desktop(std::env::var("XDG_CURRENT_DESKTOP").ok().as_deref());
    let Some((program, panel)) = privacy_command(desktop, Path::exists) else {
        anyhow::bail!(crate::linux::person::UNAVAILABLE);
    };
    let mut command = Command::new(program);
    command
        .arg(panel)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    for name in SESSION {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) fn open_privacy() -> anyhow::Result<()> {
    anyhow::bail!(crate::linux::person::UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_desktop_opens_its_own_privacy_panel_with_one_fixed_argument() {
        let all = |_: &Path| true;
        assert_eq!(
            privacy_command(Desktop::Gnome, all),
            Some(("/usr/bin/gnome-control-center", "privacy"))
        );
        assert_eq!(
            privacy_command(Desktop::Cinnamon, all),
            Some(("/usr/bin/cinnamon-settings", "privacy"))
        );
        assert_eq!(privacy_command(Desktop::Other, all), None);
    }

    #[test]
    fn nothing_is_started_when_the_program_is_missing() {
        assert_eq!(privacy_command(Desktop::Gnome, |_| false), None);
        let only_gnome = |p: &Path| p == Path::new(GNOME_SETTINGS);
        assert_eq!(privacy_command(Desktop::Cinnamon, only_gnome), None);
        assert!(privacy_command(Desktop::Gnome, only_gnome).is_some());
    }

    #[test]
    fn programs_are_absolute_paths() {
        assert!(GNOME_SETTINGS.starts_with('/') && CINNAMON_SETTINGS.starts_with('/'));
    }
}
