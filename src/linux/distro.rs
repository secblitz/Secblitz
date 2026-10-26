//! Which Linux distribution and desktop this is, read from `/etc/os-release` and `XDG_CURRENT_DESKTOP`.

use super::cmd::Sys;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Debian,
    Fedora,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Desktop {
    Gnome,
    Cinnamon,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distro {
    pub family: Family,
    pub id: String,
    pub version: String,
    pub desktop: Desktop,
}

/// The value of `key` in `KEY=value` lines; the last assignment wins, as when the shell reads the file. Values may be quoted with `"` or `'`; comments and blank lines are skipped.
fn field<'a>(os_release: &'a str, key: &str) -> Option<&'a str> {
    os_release.lines().rev().find_map(|line| {
        let (name, value) = line.trim().split_once('=')?;
        if name != key {
            return None;
        }
        let value = value.trim();
        let unquoted = [('"', '"'), ('\'', '\'')]
            .iter()
            .find_map(|(open, close)| value.strip_prefix(*open)?.strip_suffix(*close))
            .unwrap_or(value);
        Some(unquoted)
    })
}

fn family_of(id: &str, like: &str) -> Family {
    let named = |name: &str| match name {
        "debian" | "ubuntu" | "linuxmint" | "pop" | "raspbian" => Some(Family::Debian),
        "fedora" | "rhel" | "centos" => Some(Family::Fedora),
        _ => None,
    };
    named(id)
        .or_else(|| like.split_whitespace().find_map(named))
        .unwrap_or(Family::Other)
}

fn desktop_of(xdg_current_desktop: Option<&str>) -> Desktop {
    let names: Vec<String> = xdg_current_desktop
        .unwrap_or("")
        .split(':')
        .map(|n| n.trim().to_ascii_lowercase())
        .collect();
    let has = |wanted: &[&str]| names.iter().any(|n| wanted.contains(&n.as_str()));
    if has(&["x-cinnamon", "cinnamon"]) {
        Desktop::Cinnamon
    } else if has(&["gnome", "gnome-classic", "gnome-flashback"]) {
        Desktop::Gnome
    } else {
        Desktop::Other
    }
}

pub fn distro(os_release: &str, xdg_current_desktop: Option<&str>) -> Distro {
    let id = field(os_release, "ID").unwrap_or("").to_ascii_lowercase();
    let like = field(os_release, "ID_LIKE")
        .unwrap_or("")
        .to_ascii_lowercase();
    Distro {
        family: family_of(&id, &like),
        version: field(os_release, "VERSION_ID").unwrap_or("").to_string(),
        id,
        desktop: desktop_of(xdg_current_desktop),
    }
}

/// Reads the running system. `/etc/os-release` is usually a link to the vendor copy and a link is not read, so the
/// vendor copy is used then. A missing or unreadable file reads as an unknown distribution.
pub fn detect(sys: &dyn Sys, xdg_current_desktop: Option<&str>) -> Distro {
    let text = [
        Path::new("/etc/os-release"),
        Path::new("/usr/lib/os-release"),
    ]
    .iter()
    .find_map(|p| sys.read(p).ok().flatten())
    .map(|b| String::from_utf8_lossy(&b).into_owned())
    .unwrap_or_default();
    distro(&text, xdg_current_desktop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::cmd::fake::FakeSys;

    fn sample(name: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/os-release/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn parsed(name: &str) -> (Family, String, String) {
        let d = distro(&sample(name), None);
        (d.family, d.id, d.version)
    }

    #[test]
    fn the_tier_one_distributions_are_recognised() {
        for (file, family, id, version) in [
            ("ubuntu-24.04", Family::Debian, "ubuntu", "24.04"),
            ("ubuntu-26.04", Family::Debian, "ubuntu", "26.04"),
            ("mint-22.3", Family::Debian, "linuxmint", "22.3"),
            ("debian-12", Family::Debian, "debian", "12"),
            ("debian-13", Family::Debian, "debian", "13"),
            ("fedora-43", Family::Fedora, "fedora", "43"),
            ("fedora-44", Family::Fedora, "fedora", "44"),
        ] {
            assert_eq!(parsed(file), (family, id.into(), version.into()), "{file}");
        }
    }

    #[test]
    fn quotes_comments_and_spacing_do_not_matter() {
        let text = "# comment\n\n  ID = ignored\nID='arch'\nVERSION_ID=\"1.2\"\nID_LIKE=\"\"\n";
        let d = distro(text, None);
        assert_eq!(d.id, "arch");
        assert_eq!(d.version, "1.2");
        assert_eq!(d.family, Family::Other);
    }

    #[test]
    fn the_last_assignment_wins() {
        assert_eq!(distro("ID=a\nID=fedora\n", None).id, "fedora");
    }

    #[test]
    fn a_derivative_is_placed_by_what_it_says_it_is_like() {
        let d = distro("ID=zorin\nID_LIKE=\"ubuntu debian\"\n", None);
        assert_eq!(d.family, Family::Debian);
        let d = distro("ID=nobara\nID_LIKE=\"rhel centos fedora\"\n", None);
        assert_eq!(d.family, Family::Fedora);
    }

    #[test]
    fn an_empty_or_unknown_file_is_other() {
        for text in ["", "ID=gentoo\n", "garbage"] {
            let d = distro(text, None);
            assert_eq!(d.family, Family::Other, "{text:?}");
            assert_eq!(d.version, "");
        }
    }

    #[test]
    fn the_desktop_comes_from_the_current_desktop_list() {
        for (value, expected) in [
            (Some("ubuntu:GNOME"), Desktop::Gnome),
            (Some("GNOME"), Desktop::Gnome),
            (Some("GNOME-Classic:GNOME"), Desktop::Gnome),
            (Some("X-Cinnamon"), Desktop::Cinnamon),
            (Some("KDE"), Desktop::Other),
            (Some("XFCE"), Desktop::Other),
            (Some(""), Desktop::Other),
            (None, Desktop::Other),
        ] {
            assert_eq!(distro("", value).desktop, expected, "{value:?}");
        }
    }

    #[test]
    fn detect_reads_the_system_file_and_falls_back_to_the_vendor_copy() {
        let sys = FakeSys::default();
        assert_eq!(detect(&sys, None).family, Family::Other);
        sys.file("/usr/lib/os-release", sample("fedora-44").as_bytes());
        assert_eq!(detect(&sys, None).id, "fedora");
        sys.file("/etc/os-release", sample("debian-13").as_bytes());
        let d = detect(&sys, Some("X-Cinnamon"));
        assert_eq!((d.id.as_str(), d.desktop), ("debian", Desktop::Cinnamon));
    }
}
