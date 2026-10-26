//! The programs behind the processor update, the main administrator account and the rare network protocols, and what
//! the stand-in computer does when it starts again: the settings files are read in order and the crash reports set
//! their own value after them.

use super::{out, Sim};
use crate::linux::cmd::Output;
use anyhow::Result;
use std::collections::BTreeMap;

const SYSCTL_DIRS: [&str; 4] = [
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/lib/sysctl.d",
    "/lib/sysctl.d",
];

impl Sim {
    /// Makes a package known to the stand-in package managers, installed or not, with the packages it brings along.
    pub fn package(&self, name: &str, installed: bool, brings: &str) -> &Self {
        self.set(&format!("pkg:{name}"), if installed { "1" } else { "0" });
        self.set(&format!("brings:{name}"), brings)
    }

    pub fn installed(&self, name: &str) -> bool {
        self.get(&format!("pkg:{name}")) == "1"
    }

    /// What the computer does when it is started again: `systemd-sysctl` reads the files of the three folders in the
    /// order of their names, then the crash reports (when they are on) set what they need.
    pub fn restart_computer(&self) {
        let mut by_name: BTreeMap<String, String> = BTreeMap::new();
        for dir in SYSCTL_DIRS {
            let prefix = format!("{dir}/");
            for path in self.files.borrow().keys() {
                if let Some(name) = path.to_str().and_then(|p| p.strip_prefix(&prefix)) {
                    if name.ends_with(".conf") && !name.contains('/') {
                        by_name
                            .entry(name.to_string())
                            .or_insert_with(|| path.to_str().unwrap().to_string());
                    }
                }
            }
        }
        for path in by_name.into_values() {
            let text = self.text(&path).unwrap_or_default();
            for line in text.lines() {
                let line = line.trim().trim_start_matches('-');
                if line.starts_with('#') || line.starts_with(';') {
                    continue;
                }
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                let proc = format!("/proc/sys/{}", key.trim().replace('.', "/"));
                if self.has(&proc) {
                    self.file(&proc, &format!("{}\n", value.trim()));
                }
            }
        }
        let apport_on = self
            .units
            .borrow()
            .get("apport.service")
            .is_some_and(|u| u.0 == "enabled")
            && self
                .text("/etc/default/apport")
                .is_none_or(|t| !t.lines().any(|l| l.trim() == "enabled=0"));
        if apport_on {
            self.file("/proc/sys/fs/suid_dumpable", "2\n");
            self.file(
                "/proc/sys/kernel/core_pattern",
                "|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E\n",
            );
        }
    }

    fn lock_mark(&self) -> &'static str {
        if self
            .text("/usr/lib/os-release")
            .is_some_and(|t| t.lines().any(|l| l == "ID=fedora"))
        {
            "!!"
        } else {
            "!"
        }
    }
}

fn passwd(sim: &Sim, args: &[&str]) -> Result<Output> {
    let path = "/etc/shadow";
    let text = sim.text(path).unwrap_or_default();
    let mark = sim.lock_mark();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    let Some(at) = lines.iter().position(|l| l.starts_with("root:")) else {
        return out(1, "");
    };
    let mut fields: Vec<String> = lines[at].split(':').map(str::to_string).collect();
    let hash = fields[1].clone();
    match args {
        ["-S", "root"] => {
            let word = if hash.is_empty() {
                "NP"
            } else if hash.starts_with('!') || hash.starts_with('*') {
                "L"
            } else {
                "P"
            };
            out(0, &format!("root {word} 2026-08-26 0 99999 7 -1\n"))
        }
        ["-l", "root"] => {
            if !hash.starts_with('!') {
                fields[1] = format!("{mark}{hash}");
            }
            lines[at] = fields.join(":");
            sim.file(path, &(lines.join("\n") + "\n"));
            out(0, "")
        }
        ["-u", "root"] => {
            let rest = hash.strip_prefix(mark).unwrap_or(&hash).to_string();
            if rest.is_empty() || rest.starts_with('!') || rest.starts_with('*') {
                return Ok(Output {
                    status: 3,
                    stdout: String::new(),
                    stderr:
                        "passwd: unlocking the password would result in a passwordless account.\n"
                            .into(),
                });
            }
            fields[1] = rest;
            lines[at] = fields.join(":");
            sim.file(path, &(lines.join("\n") + "\n"));
            out(0, "")
        }
        other => anyhow::bail!("passwd {other:?}"),
    }
}

fn modinfo(sim: &Sim, args: &[&str]) -> Result<Output> {
    let ["-n", module] = args else {
        anyhow::bail!("modinfo {args:?}");
    };
    for line in sim.get("rec.modinfo").lines() {
        if let Some((name, path)) = line.split_once(' ') {
            if name == *module && path != "none" {
                return out(0, &format!("{path}\n"));
            }
        }
    }
    Ok(Output {
        status: 1,
        stdout: String::new(),
        stderr: format!("modinfo: ERROR: Module {module} not found.\n"),
    })
}

/// The packages `names` would add, in the order a package manager lists them: what they bring first, then themselves.
fn to_add(sim: &Sim, names: &[&str]) -> Vec<String> {
    let mut add: Vec<String> = Vec::new();
    for name in names {
        for dep in sim.get(&format!("brings:{name}")).split_whitespace() {
            if !sim.installed(dep) && !add.iter().any(|a| a == dep) {
                add.push(dep.to_string());
            }
        }
        if !sim.installed(name) && !add.iter().any(|a| a == name) {
            add.push((*name).to_string());
        }
    }
    add
}

/// The packages removing `names` takes away: themselves, the ones only they brought that are named in `owned:` and
/// any package that cannot live without them (`needs:<name>`).
fn to_remove(sim: &Sim, names: &[&str]) -> Vec<String> {
    let mut gone: Vec<String> = Vec::new();
    for name in names {
        if sim.installed(name) && !gone.iter().any(|g| g == name) {
            gone.push((*name).to_string());
        }
        for other in sim.get(&format!("needs:{name}")).split_whitespace() {
            if sim.installed(other) && !gone.iter().any(|g| g == other) {
                gone.push(other.to_string());
            }
        }
    }
    gone
}

fn apt_get(sim: &Sim, args: &[&str]) -> Result<Output> {
    match args {
        ["-s", "install", name] => {
            if sim.get(&format!("pkg:{name}")).is_empty() {
                return Ok(Output {
                    status: 100,
                    stdout: String::new(),
                    stderr: format!("E: Unable to locate package {name}\n"),
                });
            }
            let mut text = String::from("Reading package lists...\n");
            for gone in sim.get(&format!("replaces:{name}")).split_whitespace() {
                text.push_str(&format!("Remv {gone} [1.0]\n"));
            }
            for old in sim.get(&format!("upgrades:{name}")).split_whitespace() {
                text.push_str(&format!(
                    "Inst {old} [1.0] (2.0 Ubuntu:26.04/resolute [amd64])\n"
                ));
            }
            for add in to_add(sim, &[name]) {
                text.push_str(&format!("Inst {add} (1.0 Ubuntu:26.04/resolute [amd64])\n"));
            }
            out(0, &text)
        }
        ["install", "-y", name] => {
            if sim.get("apt.offline") == "1" {
                return Ok(Output {
                    status: 100,
                    stdout: String::new(),
                    stderr: "E: Failed to fetch\n".into(),
                });
            }
            for add in to_add(sim, &[name]) {
                sim.set(&format!("pkg:{add}"), "1");
            }
            out(0, "")
        }
        ["-s", "remove", names @ ..] => {
            let mut text = String::from("Reading package lists...\n");
            for gone in to_remove(sim, names) {
                text.push_str(&format!("Remv {gone} [1.0]\n"));
            }
            out(0, &text)
        }
        ["remove", "-y", names @ ..] => {
            for gone in to_remove(sim, names) {
                sim.set(&format!("pkg:{gone}"), "0");
            }
            out(0, "")
        }
        other => anyhow::bail!("apt-get {other:?}"),
    }
}

fn dnf(sim: &Sim, args: &[&str]) -> Result<Output> {
    const ABORTED: &str = "Operation aborted by the user.\n";
    match args {
        ["install", "--assumeno", name] => {
            let mut text = String::from("Package   Arch   Version   Repository   Size\n");
            let add = to_add(sim, &[name]);
            if !add.is_empty() {
                text.push_str("Installing:\n");
                text.push_str(&format!(" {name:<14} x86_64 1.0-1.fc44 fedora 1.0 MiB\n"));
                let deps: Vec<&String> = add.iter().filter(|a| *a != name).collect();
                if !deps.is_empty() {
                    text.push_str("Installing dependencies:\n");
                    for dep in deps {
                        text.push_str(&format!(" {dep:<14} noarch 1.0-1.fc44 fedora 1.0 MiB\n"));
                    }
                }
            }
            let upgrades = sim.get(&format!("upgrades:{name}"));
            if !upgrades.is_empty() {
                text.push_str("Upgrading:\n");
                for old in upgrades.split_whitespace() {
                    text.push_str(&format!(" {old:<14} noarch 2.0-1.fc44 fedora 1.0 MiB\n"));
                }
            }
            text.push_str("\nTransaction Summary:\n Installing:  1 package\n");
            Ok(Output {
                status: 1,
                stdout: text + ABORTED,
                stderr: String::new(),
            })
        }
        ["install", "-y", name] => {
            if sim.get("dnf.offline") == "1" {
                return Ok(Output {
                    status: 1,
                    stdout: String::new(),
                    stderr: "Failed to download metadata for repository \"fedora\"\n".into(),
                });
            }
            for add in to_add(sim, &[name]) {
                sim.set(&format!("pkg:{add}"), "1");
            }
            out(0, "")
        }
        ["remove", "--assumeno", "--no-autoremove", names @ ..] => {
            let gone = to_remove(sim, names);
            let mut text = String::from("Package   Arch   Version   Repository   Size\n");
            let (first, rest) = gone
                .split_first()
                .map_or((None, &[][..]), |(f, r)| (Some(f), r));
            if let Some(first) = first {
                text.push_str("Removing:\n");
                text.push_str(&format!(" {first:<14} x86_64 1.0-1.fc44 @fedora 1.0 MiB\n"));
                if !rest.is_empty() {
                    text.push_str("Removing dependent packages:\n");
                    for other in rest {
                        text.push_str(&format!(" {other:<14} noarch 1.0-1.fc44 @fedora 1.0 MiB\n"));
                    }
                }
            }
            text.push_str("\nTransaction Summary:\n Removing:  1 package\n");
            Ok(Output {
                status: 1,
                stdout: text + ABORTED,
                stderr: String::new(),
            })
        }
        ["remove", "-y", "--no-autoremove", names @ ..] => {
            for gone in to_remove(sim, names) {
                sim.set(&format!("pkg:{gone}"), "0");
            }
            out(0, "")
        }
        other => anyhow::bail!("dnf {other:?}"),
    }
}

pub(super) fn dispatch(sim: &Sim, program: &str, args: &[&str]) -> Option<Result<Output>> {
    let known = |name: &&str| !sim.get(&format!("pkg:{name}")).is_empty();
    Some(match program {
        "/usr/bin/passwd" => passwd(sim, args),
        "/usr/sbin/modinfo" => modinfo(sim, args),
        "/usr/bin/apt-get" => apt_get(sim, args),
        "/usr/bin/dnf" => dnf(sim, args),
        "/usr/bin/rpm" => match args {
            ["-q", name] => {
                if sim.installed(name) {
                    out(0, &format!("{name}-1.0-1.fc44.x86_64\n"))
                } else {
                    out(1, &format!("package {name} is not installed\n"))
                }
            }
            _ => return None,
        },
        "/usr/bin/dpkg-query" if args.first() == Some(&"-W") && args.last().is_some_and(known) => {
            let name = args.last().unwrap();
            if sim.installed(name) {
                out(0, "ii ")
            } else {
                out(1, "")
            }
        }
        _ => return None,
    })
}
