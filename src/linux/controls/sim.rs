//! A small stand-in for a Linux computer for the tests: files, services and the few programs the controls run. It starts
//! from files recorded on real installs (`tests/fixtures/linux/<name>/root`) and changes them the way the real programs do,
//! so a fix, a check and an undo can be followed from start to end.

use super::ini;
use crate::linux::cmd::{Output, Sys};
use anyhow::{bail, Result};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

mod services;

#[derive(Default)]
pub struct Inner {
    pub files: RefCell<BTreeMap<PathBuf, Vec<u8>>>,
    /// name -> (is-enabled word, running)
    pub units: RefCell<BTreeMap<String, (String, bool)>>,
    pub kv: RefCell<BTreeMap<String, String>>,
    pub tools: RefCell<BTreeSet<String>>,
    pub calls: RefCell<Vec<String>>,
    /// Programs started with these arguments fail.
    pub failing: RefCell<BTreeSet<String>>,
}

#[derive(Clone, Default)]
pub struct Sim(pub Rc<Inner>);

impl std::ops::Deref for Sim {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

fn out(status: i32, stdout: &str) -> Result<Output> {
    Ok(Output {
        status,
        stdout: stdout.into(),
        stderr: String::new(),
    })
}

fn read_tree(dir: &Path, root: &Path, into: &mut BTreeMap<PathBuf, Vec<u8>>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            read_tree(&path, root, into);
        } else {
            let rel = path.strip_prefix(root).unwrap();
            into.insert(Path::new("/").join(rel), std::fs::read(&path).unwrap());
        }
    }
}

impl Sim {
    /// A computer with the files recorded on a real install and the programs every Linux has.
    pub fn fixture(name: &str) -> Self {
        let sim = Sim::default();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/linux")
            .join(name)
            .join("root");
        read_tree(&root, &root, &mut sim.files.borrow_mut());
        services::load_recordings(&sim, &root.with_file_name("cmd"));
        for tool in ["/usr/bin/ls", "/usr/bin/systemctl"] {
            sim.tools.borrow_mut().insert(tool.into());
        }
        sim
    }

    pub fn tool(&self, program: &str) -> &Self {
        self.tools.borrow_mut().insert(program.into());
        self
    }

    pub fn unit(&self, name: &str, state: &str, running: bool) -> &Self {
        self.units
            .borrow_mut()
            .insert(name.into(), (state.into(), running));
        self
    }

    pub fn set(&self, key: &str, value: &str) -> &Self {
        self.kv.borrow_mut().insert(key.into(), value.into());
        self
    }

    pub fn get(&self, key: &str) -> String {
        self.kv.borrow().get(key).cloned().unwrap_or_default()
    }

    pub fn file(&self, path: &str, text: &str) -> &Self {
        self.files.borrow_mut().insert(path.into(), text.into());
        self
    }

    pub fn text(&self, path: &str) -> Option<String> {
        self.files
            .borrow()
            .get(Path::new(path))
            .map(|b| String::from_utf8(b.clone()).unwrap())
    }

    pub fn has(&self, path: &str) -> bool {
        self.files.borrow().contains_key(Path::new(path))
    }

    pub fn fail(&self, command: &str) -> &Self {
        self.failing.borrow_mut().insert(command.into());
        self
    }

    pub fn ran(&self, command: &str) -> bool {
        self.calls.borrow().iter().any(|c| c == command)
    }

    pub fn state(&self, name: &str) -> (String, bool) {
        self.units.borrow().get(name).cloned().unwrap()
    }

    fn edit(&self, path: &str, f: impl FnOnce(&str) -> String) {
        let old = self.text(path).unwrap_or_default();
        self.file(path, &f(&old));
    }

    fn ls(&self, dir: &str) -> Result<Output> {
        let prefix = format!("{}/", dir.trim_end_matches('/'));
        let mut names = BTreeSet::new();
        for path in self.files.borrow().keys() {
            if let Some(rest) = path.to_str().and_then(|p| p.strip_prefix(&prefix)) {
                names.insert(rest.split('/').next().unwrap().to_string());
            }
        }
        if names.is_empty() {
            return out(2, "");
        }
        out(
            0,
            &(names.into_iter().collect::<Vec<_>>().join("\n") + "\n"),
        )
    }

    fn systemctl(&self, args: &[&str]) -> Result<Output> {
        let mut units = self.units.borrow_mut();
        let now = args.contains(&"--now");
        let names: Vec<&&str> = args
            .iter()
            .skip(1)
            .filter(|a| !a.starts_with("--"))
            .collect();
        let Some(name) = names.first().map(|n| n.to_string()) else {
            bail!("no unit");
        };
        match args[0] {
            "is-enabled" => match units.get(&name) {
                None => out(4, "not-found\n"),
                Some((state, _)) => {
                    let ok = matches!(
                        state.as_str(),
                        "enabled" | "enabled-runtime" | "static" | "alias" | "indirect"
                    );
                    out(i32::from(!ok), &format!("{state}\n"))
                }
            },
            "is-active" => match units.get(&name) {
                Some((_, true)) => out(0, "active\n"),
                _ => out(3, "inactive\n"),
            },
            "try-restart" => out(i32::from(!units.contains_key(&name)) * 5, ""),
            "enable" | "disable" | "start" | "stop" | "reload" => {
                let Some(unit) = units.get_mut(&name) else {
                    return out(5, "");
                };
                match args[0] {
                    "enable" => {
                        if unit.0.starts_with("masked") {
                            return out(1, "");
                        }
                        unit.0 = "enabled".into();
                        unit.1 |= now;
                    }
                    "disable" => {
                        unit.0 = "disabled".into();
                        if now {
                            unit.1 = false;
                        }
                    }
                    "start" => unit.1 = true,
                    "stop" => unit.1 = false,
                    _ => {
                        if !unit.1 {
                            return out(1, "");
                        }
                    }
                }
                out(0, "")
            }
            other => bail!("systemctl {other}"),
        }
    }

    fn ufw(&self, args: &[&str]) -> Result<Output> {
        match args {
            ["version"] => out(0, "ufw 0.36.2\n"),
            ["status"] => {
                if self.get("ufw.active") == "1" {
                    out(0, "Status: active\n")
                } else {
                    out(0, "Status: inactive\n")
                }
            }
            ["--force", "enable"] => {
                self.set("ufw.active", "1");
                self.edit("/etc/ufw/ufw.conf", |t| ini::set(t, "", "ENABLED", "yes"));
                out(0, "")
            }
            ["disable"] => {
                self.set("ufw.active", "0");
                self.edit("/etc/ufw/ufw.conf", |t| ini::set(t, "", "ENABLED", "no"));
                out(0, "")
            }
            ["default", policy, "incoming"] => {
                let word = match *policy {
                    "deny" => "DROP",
                    "reject" => "REJECT",
                    "allow" => "ACCEPT",
                    _ => return out(1, ""),
                };
                self.edit("/etc/default/ufw", |t| {
                    ini::set(t, "", "DEFAULT_INPUT_POLICY", &format!("\"{word}\""))
                });
                out(0, "")
            }
            other => bail!("ufw {other:?}"),
        }
    }

    /// firewalld: `permanent` is `--permanent` (or the offline tool). The zone data lives in the key-value store.
    fn firewalld(&self, program: &str, args: &[&str]) -> Result<Output> {
        let running = self
            .units
            .borrow()
            .get("firewalld.service")
            .is_some_and(|u| u.1);
        let offline = program.ends_with("offline-cmd");
        if offline == running {
            return out(252, "");
        }
        let args: Vec<&str> = args
            .iter()
            .copied()
            .filter(|a| *a != "--permanent")
            .collect();
        let zone_of = |a: &[&str]| {
            a.iter()
                .find_map(|x| x.strip_prefix("--zone="))
                .map(str::to_string)
                .unwrap_or_else(|| self.get("fw.zone"))
        };
        let zone = zone_of(&args);
        if args.contains(&"--get-default-zone") {
            return out(0, &format!("{}\n", self.get("fw.zone")));
        }
        if args.contains(&"--get-target") {
            return out(0, &format!("{}\n", self.get(&format!("fw.target.{zone}"))));
        }
        if args.contains(&"--list-ports") {
            return out(0, &format!("{}\n", self.get(&format!("fw.ports.{zone}"))));
        }
        if let Some(t) = args.iter().find_map(|a| a.strip_prefix("--set-target=")) {
            self.set(&format!("fw.target.{zone}"), t);
            return out(0, "");
        }
        if let Some(p) = args.iter().find_map(|a| a.strip_prefix("--add-port=")) {
            let key = format!("fw.ports.{zone}");
            let now = self.get(&key);
            self.set(&key, format!("{now} {p}").trim());
            return out(0, "");
        }
        if let Some(p) = args.iter().find_map(|a| a.strip_prefix("--remove-port=")) {
            let key = format!("fw.ports.{zone}");
            let now: Vec<String> = self
                .get(&key)
                .split_whitespace()
                .filter(|x| *x != p)
                .map(str::to_string)
                .collect();
            self.set(&key, &now.join(" "));
            return out(0, "");
        }
        if args.contains(&"--reload") {
            return out(0, "");
        }
        bail!("firewalld {args:?}")
    }

    /// Linux Mint's switch: a marker file and the timer, as `mintupdate-automation upgrade` leaves them.
    fn mint_automation(&self, args: &[&str]) -> Result<Output> {
        const TOUCH: &str = "/var/lib/linuxmint/mintupdate-automatic-upgrades-enabled";
        const TIMER: &str = "mintupdate-automation-upgrade.timer";
        match args {
            ["upgrade", "enable"] => {
                self.file(TOUCH, "");
                self.unit(TIMER, "enabled", true);
                out(0, "")
            }
            ["upgrade", "disable"] => {
                self.files.borrow_mut().remove(Path::new(TOUCH));
                self.unit(TIMER, "disabled", false);
                out(0, "")
            }
            _ => out(1, "Bad arguments\n"),
        }
    }

    fn apt_config(&self) -> String {
        let mut values: BTreeMap<String, String> = BTreeMap::new();
        for name in self
            .ls("/etc/apt/apt.conf.d")
            .map(|o| o.stdout)
            .unwrap_or_default()
            .lines()
        {
            let text = self
                .text(&format!("/etc/apt/apt.conf.d/{name}"))
                .unwrap_or_default();
            for line in text.lines().filter(|l| l.starts_with("APT::Periodic::")) {
                if let Some((k, v)) = line.split_once(' ') {
                    values.insert(k.to_string(), v.trim_end_matches(';').to_string());
                }
            }
        }
        values.iter().map(|(k, v)| format!("{k} {v};\n")).collect()
    }

    /// `sshd -T`: the first value of a word wins, and `Include` is read where it stands.
    fn sshd_config(&self) -> String {
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        let main = self.text("/etc/ssh/sshd_config").unwrap_or_default();
        let mut lines: Vec<String> = Vec::new();
        for line in main.lines() {
            if line.trim_start().starts_with("Include") {
                let names = self
                    .ls("/etc/ssh/sshd_config.d")
                    .map(|o| o.stdout)
                    .unwrap_or_default();
                for name in names.lines().filter(|n| n.ends_with(".conf")) {
                    let text = self
                        .text(&format!("/etc/ssh/sshd_config.d/{name}"))
                        .unwrap();
                    lines.extend(text.lines().map(str::to_string));
                }
            } else {
                lines.push(line.to_string());
            }
        }
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once(char::is_whitespace) {
                seen.entry(k.to_ascii_lowercase())
                    .or_insert_with(|| v.trim().to_string());
            }
        }
        let value = |k: &str, default: &str| seen.get(k).cloned().unwrap_or_else(|| default.into());
        format!(
            "port 22\npermitrootlogin {}\npasswordauthentication {}\n",
            value("permitrootlogin", "without-password"),
            value("passwordauthentication", "yes")
        )
    }

    fn dispatch(&self, program: &str, args: &[&str]) -> Result<Output> {
        if let Some(done) = services::dispatch(self, program, args) {
            return done;
        }
        match program {
            "/usr/bin/ls" => self.ls(args[1]),
            "/usr/bin/systemctl" => self.systemctl(args),
            "/usr/sbin/ufw" => self.ufw(args),
            "/usr/bin/firewall-cmd" | "/usr/bin/firewall-offline-cmd" => {
                self.firewalld(program, args)
            }
            "/usr/bin/dpkg-query" => match args {
                ["--version"] => out(0, "1.22\n"),
                _ => {
                    if self.get("dpkg.unattended") == "1" {
                        out(0, "install ok installed")
                    } else {
                        out(1, "")
                    }
                }
            },
            "/usr/bin/mintupdate-automation" => self.mint_automation(args),
            "/usr/bin/apt-config" => out(0, &self.apt_config()),
            "/usr/sbin/sshd" => match args {
                ["-V"] => out(1, ""),
                ["-T"] => out(0, &self.sshd_config()),
                ["-t"] => out(0, ""),
                other => bail!("sshd {other:?}"),
            },
            "/usr/sbin/sysctl" => {
                let (key, value) = args[1].split_once('=').unwrap();
                let key = if key.contains('/') {
                    key.to_string()
                } else {
                    key.replace('.', "/")
                };
                self.file(
                    &format!("/proc/sys/{key}"),
                    &format!("{value}\n"),
                );
                out(0, "")
            }
            "/usr/bin/dnf5" => match (args, self.get("dnf.cache").as_str()) {
                (_, "") => Ok(Output {
                    status: 1,
                    stdout: "Updating and loading repositories:\n".into(),
                    stderr: "Cache-only enabled but no cache for repository \"fedora\"\n".into(),
                }),
                (["-C", "check-upgrade"], _) => {
                    out(if self.get("dnf.waiting") == "1" { 100 } else { 0 }, "")
                }
                (["-C", "needs-restarting", "-r"], _) if self.get("dnf.restart") == "1" => out(
                    1,
                    "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\n",
                ),
                (["-C", "needs-restarting", "-r"], _) => out(
                    0,
                    "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n",
                ),
                (other, _) => bail!("dnf5 {other:?}"),
            },
            "/usr/bin/mokutil" => match self.get("sb.support").as_str() {
                "none" => out(255, "This system doesn't support Secure Boot\n"),
                _ => out(1, "EFI variables are not supported on this system\n"),
            },
            "/usr/bin/findmnt" => out(0, &format!("{}\n", self.get("root.source"))),
            "/usr/bin/lsblk" => out(
                0,
                &if self.get("root.crypt") == "1" {
                    "part\ncrypt\n".to_string()
                } else {
                    "part\n".to_string()
                },
            ),
            "/usr/lib/update-notifier/apt-check" => Ok(Output {
                status: 0,
                stdout: String::new(),
                stderr: format!("{};0\n", self.get("apt.waiting")),
            }),
            other => bail!("unexpected program {other}"),
        }
    }
}

impl Sys for Sim {
    fn run(&self, program: &'static str, args: &[&str]) -> Result<Output> {
        let command = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.calls.borrow_mut().push(command.clone());
        if !self.tools.borrow().contains(program) {
            bail!("no such program: {program}");
        }
        if self
            .failing
            .borrow()
            .iter()
            .any(|f| command.starts_with(f.as_str()))
        {
            return out(1, "");
        }
        self.dispatch(program, args)
    }

    fn read(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        Ok(self.files.borrow().get(path).cloned())
    }

    fn write_atomic(&self, path: &Path, bytes: &[u8], _mode: u32) -> Result<()> {
        self.files.borrow_mut().insert(path.into(), bytes.to_vec());
        Ok(())
    }

    fn remove(&self, path: &Path) -> Result<()> {
        self.files.borrow_mut().remove(path);
        Ok(())
    }
}
