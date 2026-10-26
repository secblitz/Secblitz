//! Removing Secblitz's own package. The package tool runs as its own short-lived unit, because taking the package away
//! stops the helper that asked for it, and a tool running inside the helper would be stopped halfway.
use super::cmd::Sys;
use super::controls::plain;
use super::distro::{Distro, Family};
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

/// Starts the removal and returns at once; the removal finishes on its own.
pub fn start(sys: &dyn Sys, distro: &Distro) -> Result<()> {
    let Some((tool, args)) = package_command(distro.family) else {
        return Err(plain(CANNOT_REMOVE));
    };
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

    fn told(tool: &str, status: i32) -> FakeSys {
        let sys = FakeSys::default();
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
            assert_eq!(*sys.calls.borrow(), [expected]);
        }
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
