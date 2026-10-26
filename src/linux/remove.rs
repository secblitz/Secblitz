//! Removing Secblitz's own package. The package tool runs as its own short-lived unit, because taking the package away
//! stops the helper that asked for it, and a tool running inside the helper would be stopped halfway.
use super::cmd::Sys;
use super::controls::plain;
use super::distro::{Distro, Family};
use super::web;
use anyhow::Result;

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const APT_GET: &str = "/usr/bin/apt-get";
const DNF: &str = "/usr/bin/dnf";

pub const CANNOT_REMOVE: &str =
    "Secblitz could not remove itself. Remove it from the software app instead.";

/// The package tool and its fixed arguments for this family of systems.
fn package_command(family: Family) -> Option<(&'static str, [&'static str; 3])> {
    match family {
        Family::Debian => Some((APT_GET, ["remove", "-y", "secblitz"])),
        Family::Fedora => Some((DNF, ["remove", "-y", "secblitz"])),
        Family::Other => None,
    }
}

/// Starts the removal and returns at once; the removal finishes on its own. Web protection is switched off first, so
/// lookups never point at a filter that is about to disappear.
pub fn start(sys: &dyn Sys, distro: &Distro) -> Result<()> {
    let Some((tool, args)) = package_command(distro.family) else {
        return Err(plain(CANNOT_REMOVE));
    };
    if let Err(error) = web::remove_everything(sys) {
        eprintln!("Web protection was not switched off before the removal: {error:#}");
    }
    let mut all = vec![
        "--quiet",
        "--no-block",
        "--collect",
        "--unit=secblitz-remove",
        "--setenv=DEBIAN_FRONTEND=noninteractive",
        tool,
    ];
    all.extend(args);
    match sys.run(SYSTEMD_RUN, &all) {
        Ok(output) if output.success() => Ok(()),
        Ok(output) => {
            eprintln!("systemd-run failed: {}", output.stderr.trim());
            Err(plain(CANNOT_REMOVE))
        }
        Err(error) => {
            eprintln!("systemd-run could not start: {error:#}");
            Err(plain(CANNOT_REMOVE))
        }
    }
}

#[cfg(target_os = "linux")]
pub fn start_installed() -> Result<()> {
    let sys = super::cmd::RealSys;
    let distro = super::distro::detect(&sys, None);
    start(&sys, &distro)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::cmd::fake::FakeSys;
    use crate::linux::distro::Desktop;

    fn distro(family: Family) -> Distro {
        Distro {
            family,
            id: "test".into(),
            version: "1".into(),
            desktop: Desktop::Other,
        }
    }

    fn launch(tool: &str) -> Vec<String> {
        [
            "--quiet",
            "--no-block",
            "--collect",
            "--unit=secblitz-remove",
            "--setenv=DEBIAN_FRONTEND=noninteractive",
            tool,
            "remove",
            "-y",
            "secblitz",
        ]
        .map(String::from)
        .to_vec()
    }

    const SHOW: &str =
        "/usr/bin/systemctl show --property=LoadState,ActiveState secblitz-filter.service";

    fn told(tool: &str, status: i32) -> FakeSys {
        let sys = FakeSys::default();
        sys.reply(
            "/usr/bin/systemctl",
            &[
                "show",
                "--property=LoadState,ActiveState",
                "secblitz-filter.service",
            ],
            0,
            "LoadState=not-found\nActiveState=inactive\n",
        );
        let args = launch(tool);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        sys.reply(SYSTEMD_RUN, &args, status, "");
        sys
    }

    #[test]
    fn the_removal_runs_in_its_own_unit_with_fixed_arguments() {
        for (family, tool) in [(Family::Debian, APT_GET), (Family::Fedora, DNF)] {
            let sys = told(tool, 0);
            start(&sys, &distro(family)).unwrap();
            let expected = format!("{SYSTEMD_RUN} {}", launch(tool).join(" "));
            assert_eq!(*sys.calls.borrow(), [SHOW.to_owned(), expected]);
        }
    }

    #[test]
    fn web_protection_is_switched_off_before_the_package_goes() {
        let sys = told(APT_GET, 0);
        sys.reply(
            "/usr/bin/systemctl",
            &[
                "show",
                "--property=LoadState,ActiveState",
                "secblitz-filter.service",
            ],
            0,
            "LoadState=loaded\nActiveState=active\n",
        );
        sys.reply(
            "/usr/bin/systemctl",
            &["disable", "--now", "secblitz-filter.service"],
            0,
            "",
        );
        sys.reply(
            "/usr/bin/systemctl",
            &["is-active", "systemd-resolved.service"],
            0,
            "active\n",
        );
        sys.reply("/usr/bin/systemctl", &["is-system-running"], 1, "running\n");
        sys.reply(
            "/usr/bin/systemctl",
            &["try-restart", "systemd-resolved.service"],
            0,
            "",
        );
        sys.reply("/usr/bin/resolvectl", &["flush-caches"], 0, "");
        sys.file(web::DROPIN, web::dropin_text().as_bytes());
        start(&sys, &distro(Family::Debian)).unwrap();
        let calls = sys.calls.borrow();
        let at = |what: &str| calls.iter().position(|c| c.contains(what)).unwrap();
        assert!(at("try-restart") < at("disable --now"));
        assert!(at("disable --now") < at("systemd-run"));
        assert!(sys.files.borrow().is_empty());
    }

    #[test]
    fn a_system_that_cannot_be_removed_keeps_web_protection() {
        let sys = FakeSys::default();
        assert!(start(&sys, &distro(Family::Other)).is_err());
        assert!(sys.calls.borrow().is_empty());
    }

    #[test]
    fn an_unknown_system_or_a_failed_start_gives_the_plain_sentence() {
        let sys = FakeSys::default();
        let error = start(&sys, &distro(Family::Other)).unwrap_err();
        assert_eq!(error.to_string(), CANNOT_REMOVE);
        assert!(sys.calls.borrow().is_empty());

        let sys = told(APT_GET, 1);
        let error = start(&sys, &distro(Family::Debian)).unwrap_err();
        assert_eq!(error.to_string(), CANNOT_REMOVE);

        let sys = FakeSys::default();
        let error = start(&sys, &distro(Family::Fedora)).unwrap_err();
        assert_eq!(error.to_string(), CANNOT_REMOVE);
    }
}
