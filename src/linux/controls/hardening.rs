//! Hardening of how the system treats memory, crashes, rare network protocols, processor fixes and the main administrator
//! account.
//!
//! Most of these are running kernel settings read from `/proc/sys`; a fix sets the running value and keeps it after a
//! restart in the control's own file in `/etc/sysctl.d`, which is named so that it is read after the files a system ships.
//! An undo puts the recorded value back and takes the file away.

use super::kernel::{self, Def, NOTE};
use super::network::{MKDIR, RMDIR, TEST};
use super::{
    flag, ini, num_of, observation, plain, Cx, Items, CHANGE_FAILED, NO_RECORD, UNRECOGNISED,
};
use crate::debloat::linux::is_valid_package;
use crate::hardening::{item_is_safe, Item};
use crate::linux::catalog::spec;
use crate::linux::distro::Family;
use crate::model::Observation;
use anyhow::Result;
use std::collections::BTreeMap;

pub const CRASH_REPORTS_NEED_IT: &str =
    "Crash reports are on and they need this setting. Turn off crash reports first if you want to change it.";
pub const OVERRIDDEN: &str =
    "Another file on this computer sets this again every time it starts, so Secblitz left it alone.";
pub const NO_OTHER_ADMIN: &str = "No other account on this computer can act as an administrator, so Secblitz left the main administrator account alone. You could be locked out.";
pub const PACKAGE_REFUSED: &str =
    "Installing this would also change other software, so Secblitz left it alone.";
pub const PACKAGE_UNDO_REFUSED: &str =
    "Taking this back would also remove other software, so Secblitz left it alone.";
pub const PACKAGE_FAILED: &str =
    "The processor update could not be installed. Check that this computer is online, then try again.";
pub const PACKAGE_REMOVE_FAILED: &str =
    "The processor update could not be removed. Wait for any software installation to finish, then try again.";

pub const SENTENCES: [&str; 7] = [
    CRASH_REPORTS_NEED_IT,
    OVERRIDDEN,
    NO_OTHER_ADMIN,
    PACKAGE_REFUSED,
    PACKAGE_UNDO_REFUSED,
    PACKAGE_FAILED,
    PACKAGE_REMOVE_FAILED,
];

const MEMORY: Def = Def {
    id: "linux.memory_shuffle",
    dropin: "/etc/sysctl.d/90-secblitz-memory-shuffle.conf",
    keys: &[("randomize_va_space", "kernel.randomize_va_space")],
};

const BPF: Def = Def {
    id: "linux.bpf_hardening",
    dropin: "/etc/sysctl.d/90-secblitz-bpf.conf",
    keys: &[
        (
            "unprivileged_bpf_disabled",
            "kernel.unprivileged_bpf_disabled",
        ),
        ("jit_harden", "net.core.bpf_jit_harden"),
    ],
};

const TERMINAL: Def = Def {
    id: "linux.terminal_drivers",
    dropin: "/etc/sysctl.d/90-secblitz-terminal-drivers.conf",
    keys: &[("ldisc_autoload", "dev.tty.ldisc_autoload")],
};

const CRASH_MEMORY: Def = Def {
    id: "linux.crash_memory",
    dropin: "/etc/sysctl.d/90-secblitz-crash-memory.conf",
    keys: &[("suid_dumpable", "fs.suid_dumpable")],
};

const SANDBOX: Def = Def {
    id: "linux.app_sandbox_limits",
    dropin: "/etc/sysctl.d/90-secblitz-app-sandbox.conf",
    keys: &[("restricted", "kernel.apparmor_restrict_unprivileged_userns")],
};

const SYSCTL_DIRS: [&str; 4] = [
    "/etc/sysctl.d",
    "/run/sysctl.d",
    "/usr/lib/sysctl.d",
    "/lib/sysctl.d",
];
const SYSCTL_CONF: &str = "/etc/sysctl.conf";
const CORE_PATTERN: &str = "/proc/sys/kernel/core_pattern";

/// `name=value` of a settings line, with the folder spelling of the name turned into the dotted one.
fn assignment(line: &str) -> Option<(String, String)> {
    let line = line.trim().trim_start_matches('-');
    if line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    let (name, value) = line.split_once('=')?;
    Some((name.trim().replace('/', "."), value.trim().to_string()))
}

/// The settings files that are read after `dropin`, in the order they are read.
fn later_texts(cx: &Cx, dropin: &str) -> Vec<String> {
    let ours = dropin.rsplit('/').next().unwrap_or(dropin);
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    for dir in SYSCTL_DIRS {
        for name in cx.list(dir) {
            if name.ends_with(".conf") && name.as_str() > ours {
                files
                    .entry(name.clone())
                    .or_insert_with(|| format!("{dir}/{name}"));
            }
        }
    }
    let mut texts = Vec::new();
    for (name, path) in files {
        let text = match cx.text(&path) {
            Ok(text) => text,
            // Some systems keep the old main file behind a link in this folder, which is not read as a file.
            Err(_) if name == "99-sysctl.conf" => cx.text(SYSCTL_CONF).ok().flatten(),
            Err(_) => None,
        };
        texts.extend(text);
    }
    texts.extend(cx.text(SYSCTL_CONF).ok().flatten());
    texts
}

/// Whether the value this system will have after its next start is not `wanted` because a file read after `dropin` says so.
fn overridden(cx: &Cx, dropin: &str, sysctl: &str, wanted: u32) -> bool {
    let mut last = None;
    for text in later_texts(cx, dropin) {
        for line in text.lines() {
            if let Some((name, value)) = assignment(line) {
                if name == sysctl {
                    last = Some(value);
                }
            }
        }
    }
    last.is_some_and(|v| v.parse::<u32>().ok() != Some(wanted))
}

fn write_sysctl(cx: &Cx, want: &Items, def: &Def) -> Result<()> {
    let catalog = spec(def.id).ok_or_else(|| plain(UNRECOGNISED))?;
    for (key, sysctl) in def.keys {
        let Some(Item::Num(value)) = want.get(*key) else {
            continue;
        };
        let rule = catalog
            .keys
            .iter()
            .find(|k| k.name == *key)
            .map(|k| k.rule)
            .ok_or_else(|| plain(UNRECOGNISED))?;
        if item_is_safe(rule, &Item::Num(*value))
            && kernel::running(cx, sysctl)? != Item::Num(*value)
            && overridden(cx, def.dropin, sysctl, *value)
        {
            return Err(plain(OVERRIDDEN));
        }
    }
    kernel::write_def(cx, want, def)
}

pub fn observe_memory_shuffle(cx: &Cx) -> Result<Observation> {
    kernel::observe_def(cx, &MEMORY)
}

pub fn write_memory_shuffle(cx: &Cx, want: &Items) -> Result<()> {
    write_sysctl(cx, want, &MEMORY)
}

pub fn observe_bpf(cx: &Cx) -> Result<Observation> {
    kernel::observe_def(cx, &BPF)
}

/// Shutting unprivileged programs out for good (1) cannot be taken back until a restart, so only 2 is ever written.
pub fn write_bpf(cx: &Cx, want: &Items) -> Result<()> {
    if want.get("unprivileged_bpf_disabled") == Some(&Item::Num(1))
        && kernel::running(cx, "kernel.unprivileged_bpf_disabled")? != Item::Num(1)
    {
        return Err(plain(UNRECOGNISED));
    }
    write_sysctl(cx, want, &BPF)
}

pub fn observe_terminal_drivers(cx: &Cx) -> Result<Observation> {
    kernel::observe_def(cx, &TERMINAL)
}

pub fn write_terminal_drivers(cx: &Cx, want: &Items) -> Result<()> {
    write_sysctl(cx, want, &TERMINAL)
}

pub fn observe_app_sandbox(cx: &Cx) -> Result<Observation> {
    kernel::observe_def(cx, &SANDBOX)
}

pub fn write_app_sandbox(cx: &Cx, want: &Items) -> Result<()> {
    write_sysctl(cx, want, &SANDBOX)
}

/// The program the system sends a crashed program to, as the last part of its path, when the pattern pipes to one.
fn crash_handler(cx: &Cx) -> Result<Option<String>> {
    let Some(text) = cx.text(CORE_PATTERN)? else {
        return Ok(None);
    };
    Ok(text
        .trim()
        .strip_prefix('|')
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|path| path.rsplit('/').next())
        .map(str::to_string))
}

/// Ubuntu's crash reports set this to 2 each time they start, after the settings files are read, so a file cannot keep it.
pub fn observe_crash_memory(cx: &Cx) -> Result<Observation> {
    let item = kernel::running(cx, "fs.suid_dumpable")?;
    if matches!(item, Item::Num(n) if n != 0) && crash_handler(cx)?.as_deref() == Some("apport") {
        return Ok(observation(
            vec![("suid_dumpable", item)],
            false,
            CRASH_REPORTS_NEED_IT,
        ));
    }
    Ok(observation(vec![("suid_dumpable", item)], true, ""))
}

pub fn write_crash_memory(cx: &Cx, want: &Items) -> Result<()> {
    write_sysctl(cx, want, &CRASH_MEMORY)
}

const COREDUMP_MAIN: [&str; 2] = [
    "/usr/lib/systemd/coredump.conf",
    "/etc/systemd/coredump.conf",
];
const COREDUMP_DIRS: [&str; 3] = [
    "/usr/lib/systemd/coredump.conf.d",
    "/run/systemd/coredump.conf.d",
    "/etc/systemd/coredump.conf.d",
];
const COREDUMP_FOLDER: &str = "/etc/systemd/coredump.conf.d";
const COREDUMP_DROPIN: &str = "/etc/systemd/coredump.conf.d/90-secblitz.conf";
/// Written when Secblitz made the folder for its file, so the undo takes the folder away too.
const COREDUMP_FOLDER_MEMO: &str = "coredump-folder";

/// Whether the crash catcher keeps a crashed program's memory on disk, from the files it reads each time a program
/// crashes. `None` when a file holds a word it does not know.
fn coredump_keeps(cx: &Cx) -> Result<Option<bool>> {
    let mut by_name = BTreeMap::new();
    for dir in COREDUMP_DIRS {
        for name in cx.list(dir) {
            if name.ends_with(".conf") {
                by_name.insert(name.clone(), format!("{dir}/{name}"));
            }
        }
    }
    let mut texts = Vec::new();
    for path in COREDUMP_MAIN {
        texts.extend(cx.text(path)?);
    }
    for path in by_name.into_values() {
        texts.extend(cx.text(&path)?);
    }
    let mut word = String::new();
    for text in &texts {
        if let Some(value) = ini::get(text, &["Coredump"], "Storage") {
            word = value;
        }
    }
    Ok(match word.to_ascii_lowercase().as_str() {
        "" | "external" | "journal" | "both" => Some(true),
        "none" => Some(false),
        _ => None,
    })
}

pub fn observe_crash_files(cx: &Cx) -> Result<Observation> {
    if crash_handler(cx)?.as_deref() != Some("systemd-coredump") {
        return Ok(observation(vec![("stored", Item::Absent)], true, ""));
    }
    match coredump_keeps(cx)? {
        Some(keeps) => Ok(observation(vec![("stored", flag(keeps))], true, "")),
        None => Ok(super::unavailable("linux.crash_files", UNRECOGNISED)),
    }
}

/// Takes away the drop-in folder when Secblitz made it and nothing else was put in it since.
fn remove_coredump_folder(cx: &Cx) -> Result<()> {
    if cx.memo_read(COREDUMP_FOLDER_MEMO)?.is_some() {
        let _ = cx.run(RMDIR, &[COREDUMP_FOLDER]);
        cx.memo_clear(COREDUMP_FOLDER_MEMO)?;
    }
    Ok(())
}

fn write_coredump_file(cx: &Cx) -> Result<()> {
    if !cx
        .run(TEST, &["-d", COREDUMP_FOLDER])
        .is_ok_and(|o| o.success())
    {
        cx.memo_write(COREDUMP_FOLDER_MEMO, &[COREDUMP_FOLDER.to_string()])?;
        cx.run_ok(MKDIR, &["-m", "0755", COREDUMP_FOLDER])?;
    }
    cx.write_text(
        COREDUMP_DROPIN,
        &format!("{NOTE}[Coredump]\nStorage=none\n"),
        0o644,
    )
}

/// The crash catcher is started again by the system for each crash and reads its files then, so nothing is restarted.
pub fn write_crash_files(cx: &Cx, want: &Items) -> Result<()> {
    match num_of(want, "stored")? {
        Some(0) => {
            cx.remove(COREDUMP_DROPIN)?;
            remove_coredump_folder(cx)?;
            if coredump_keeps(cx)? == Some(false) {
                return Ok(());
            }
            if let Err(e) = write_coredump_file(cx) {
                cx.remove(COREDUMP_DROPIN)?;
                remove_coredump_folder(cx)?;
                return Err(e);
            }
            if coredump_keeps(cx)? != Some(false) {
                cx.remove(COREDUMP_DROPIN)?;
                remove_coredump_folder(cx)?;
                return Err(plain(CHANGE_FAILED));
            }
            Ok(())
        }
        Some(1) => {
            cx.remove(COREDUMP_DROPIN)?;
            remove_coredump_folder(cx)
        }
        Some(_) => Err(plain(UNRECOGNISED)),
        None => Ok(()),
    }
}

/// Each rarely used protocol and the names the system asks for when a program opens a connection of that kind.
const RARE: [(&str, &[&str]); 4] = [
    ("dccp", &[]),
    ("sctp", &[]),
    ("rds", &["net-pf-21"]),
    ("tipc", &["net-pf-30"]),
];
const MODPROBE_DIRS: [&str; 4] = [
    "/etc/modprobe.d",
    "/run/modprobe.d",
    "/usr/lib/modprobe.d",
    "/lib/modprobe.d",
];
const RARE_DROPIN: &str = "/etc/modprobe.d/90-secblitz-rare-network.conf";
const MODINFO: &str = "/usr/sbin/modinfo";
const NO_PROGRAM: [&str; 4] = ["/bin/true", "/bin/false", "/usr/bin/true", "/usr/bin/false"];

/// The loading rules of every file, one line per rule, without the control's own file when `skip_ours` is set.
fn modprobe_rules(cx: &Cx, skip_ours: bool) -> Result<Vec<Vec<String>>> {
    let ours = RARE_DROPIN.rsplit('/').next().unwrap_or(RARE_DROPIN);
    let mut by_name = BTreeMap::new();
    for dir in MODPROBE_DIRS {
        for name in cx.list(dir) {
            if name.ends_with(".conf") && !(skip_ours && name == ours) {
                by_name
                    .entry(name.clone())
                    .or_insert_with(|| format!("{dir}/{name}"));
            }
        }
    }
    let mut rules = Vec::new();
    for path in by_name.into_values() {
        for line in cx.text(&path)?.unwrap_or_default().lines() {
            let line = line.trim();
            if !line.starts_with('#') && !line.is_empty() {
                rules.push(line.split_whitespace().map(str::to_string).collect());
            }
        }
    }
    Ok(rules)
}

fn same_module(a: &str, b: &str) -> bool {
    a.replace('-', "_") == b.replace('-', "_")
}

fn blocked(rules: &[Vec<String>], module: &str, aliases: &[&str]) -> bool {
    rules.iter().any(|rule| match rule.as_slice() {
        [word, name, program, ..] if word == "install" => {
            same_module(name, module) && NO_PROGRAM.contains(&program.as_str())
        }
        [word, alias, off] if word == "alias" => off == "off" && aliases.contains(&alias.as_str()),
        _ => false,
    })
}

/// Whether a module of the running system can be loaded: it exists as a file and is not part of the system itself.
fn loadable(cx: &Cx, module: &str) -> Option<bool> {
    let out = cx.run(MODINFO, &["-n", module]).ok()?;
    let path = out.stdout.trim();
    Some(out.success() && !path.is_empty() && !path.contains("(builtin)"))
}

fn in_use(cx: &Cx, module: &str) -> Result<bool> {
    Ok(cx
        .text("/proc/modules")?
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .any(|name| same_module(name, module)))
}

/// The modules that exist here, are not in use and that no file stops from loading on demand. `None` when the system's
/// module tool is missing.
fn open_modules(cx: &Cx, skip_ours: bool) -> Result<Option<Vec<&'static str>>> {
    let rules = modprobe_rules(cx, skip_ours)?;
    let mut open = Vec::new();
    for (module, aliases) in RARE {
        match loadable(cx, module) {
            None => return Ok(None),
            Some(false) => {}
            Some(true) => {
                if !in_use(cx, module)? && !blocked(&rules, module, aliases) {
                    open.push(module);
                }
            }
        }
    }
    Ok(Some(open))
}

pub fn observe_rare_protocols(cx: &Cx) -> Result<Observation> {
    let item = match open_modules(cx, false)? {
        Some(open) => flag(!open.is_empty()),
        None => Item::Absent,
    };
    Ok(observation(vec![("open", item)], true, ""))
}

/// A module that is loaded now is left as it is. Only future loading is stopped, so nothing running is unloaded.
pub fn write_rare_protocols(cx: &Cx, want: &Items) -> Result<()> {
    match num_of(want, "open")? {
        Some(0) => {
            let Some(open) = open_modules(cx, true)? else {
                return Err(plain(CHANGE_FAILED));
            };
            if open.is_empty() {
                return cx.remove(RARE_DROPIN);
            }
            let mut text = String::from(NOTE);
            for module in open {
                text.push_str(&format!("install {module} /bin/false\n"));
            }
            cx.write_text(RARE_DROPIN, &text, 0o644)?;
            if open_modules(cx, false)?.is_some_and(|left| !left.is_empty()) {
                cx.remove(RARE_DROPIN)?;
                return Err(plain(CHANGE_FAILED));
            }
            Ok(())
        }
        Some(1) => cx.remove(RARE_DROPIN),
        Some(_) => Err(plain(UNRECOGNISED)),
        None => Ok(()),
    }
}

const DPKG_QUERY: &str = "/usr/bin/dpkg-query";
const RPM: &str = "/usr/bin/rpm";
const APT_GET: &str = "/usr/bin/apt-get";
const DNF: &str = "/usr/bin/dnf";
const PROCESSOR_MEMO: &str = "processor-updates";

/// The package that carries the fixes for this computer's processor, and the packages that count as having them.
fn processor_package(cx: &Cx) -> Result<Option<(&'static str, &'static [&'static str])>> {
    let cpu = cx.text("/proc/cpuinfo")?.unwrap_or_default();
    let vendor = cpu.lines().find_map(|l| {
        let (key, value) = l.split_once(':')?;
        (key.trim() == "vendor_id").then(|| value.trim().to_string())
    });
    Ok(match (cx.distro.family, vendor.as_deref()) {
        (Family::Debian, Some("GenuineIntel")) => {
            Some(("intel-microcode", &["intel-microcode"][..]))
        }
        (Family::Debian, Some("AuthenticAMD")) => {
            Some(("amd64-microcode", &["amd64-microcode"][..]))
        }
        (Family::Fedora, Some("GenuineIntel")) => {
            Some(("microcode_ctl", &["microcode_ctl", "linux-firmware"][..]))
        }
        (Family::Fedora, Some("AuthenticAMD")) => {
            Some(("linux-firmware", &["microcode_ctl", "linux-firmware"][..]))
        }
        _ => None,
    })
}

/// Whether the package is installed; `None` when the package tool cannot be run.
fn installed(cx: &Cx, package: &str) -> Option<bool> {
    Some(match cx.distro.family {
        Family::Debian => {
            let out = cx
                .run(DPKG_QUERY, &["-W", "-f=${db:Status-Abbrev}", package])
                .ok()?;
            out.success() && out.stdout.trim_start().starts_with('i')
        }
        Family::Fedora => cx.run(RPM, &["-q", package]).ok()?.success(),
        Family::Other => return None,
    })
}

fn any_installed(cx: &Cx, names: &[&str]) -> Option<bool> {
    let mut any = false;
    for name in names {
        any |= installed(cx, name)?;
    }
    Some(any)
}

pub fn observe_processor_updates(cx: &Cx) -> Result<Observation> {
    let item = match processor_package(cx)? {
        Some((_, names)) => any_installed(cx, names).map_or(Item::Absent, flag),
        None => Item::Absent,
    };
    Ok(observation(vec![("installed", item)], true, ""))
}

/// The package names listed under the headings of dnf's pretend run that start with one of `headings`; the flag is
/// true when a heading of one of the `other` kinds of change shows up.
fn dnf_names(text: &str, headings: &[&str], other: &[&str]) -> (Vec<String>, bool) {
    let mut names = Vec::new();
    let mut bad = false;
    let mut inside = false;
    for line in text.lines() {
        if line.starts_with("Transaction Summary") {
            break;
        }
        if !line.starts_with(' ') && !line.trim().is_empty() {
            let head = line.trim();
            inside = headings.iter().any(|h| head.starts_with(h));
            bad |= other.iter().any(|o| head.starts_with(o));
        } else if inside && !line.trim_start().starts_with("replacing") {
            if let Some(name) = line.split_whitespace().next() {
                names.push(name.to_string());
            }
        }
    }
    (names, bad)
}

/// What installing `package` would add, or `None` when it would change anything that is already installed.
fn install_plan(cx: &Cx, package: &str) -> Result<Option<Vec<String>>> {
    match cx.distro.family {
        Family::Debian => {
            let out = cx.run(APT_GET, &["-s", "install", package])?;
            if !out.success() {
                return Err(plain(PACKAGE_FAILED));
            }
            let mut names = Vec::new();
            for line in out.stdout.lines() {
                if line.starts_with("Remv ") {
                    return Ok(None);
                }
                if let Some(rest) = line.strip_prefix("Inst ") {
                    let mut parts = rest.split_whitespace();
                    let name = parts.next().unwrap_or("");
                    if parts.next().is_some_and(|w| w.starts_with('[')) {
                        return Ok(None);
                    }
                    names.push(name.split(':').next().unwrap_or(name).to_string());
                }
            }
            Ok(Some(names))
        }
        Family::Fedora => {
            let out = cx.run(DNF, &["install", "--assumeno", package])?;
            if !out.success() && !out.stdout.contains("Transaction Summary") {
                return Err(plain(PACKAGE_FAILED));
            }
            let (names, bad) = dnf_names(
                &out.stdout,
                &["Installing"],
                &[
                    "Upgrading",
                    "Removing",
                    "Downgrading",
                    "Replacing",
                    "Reinstalling",
                ],
            );
            Ok((!bad).then_some(names))
        }
        Family::Other => Err(plain(PACKAGE_FAILED)),
    }
}

/// What removing `names` would take away along with them.
fn removal_plan(cx: &Cx, names: &[String]) -> Result<Vec<String>> {
    let args = |head: &[&'static str]| -> Vec<String> {
        head.iter()
            .map(|s| s.to_string())
            .chain(names.iter().cloned())
            .collect()
    };
    match cx.distro.family {
        Family::Debian => {
            let owned = args(&["-s", "remove"]);
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            let out = cx.run(APT_GET, &refs)?;
            if !out.success() {
                return Err(plain(PACKAGE_REMOVE_FAILED));
            }
            Ok(out
                .stdout
                .lines()
                .filter_map(|l| l.strip_prefix("Remv "))
                .filter_map(|rest| rest.split_whitespace().next())
                .map(|n| n.split(':').next().unwrap_or(n).to_string())
                .collect())
        }
        Family::Fedora => {
            let owned = args(&["remove", "--assumeno", "--no-autoremove"]);
            let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
            let out = cx.run(DNF, &refs)?;
            if !out.success() && !out.stdout.contains("Transaction Summary") {
                return Err(plain(PACKAGE_REMOVE_FAILED));
            }
            Ok(dnf_names(&out.stdout, &["Removing"], &[]).0)
        }
        Family::Other => Err(plain(PACKAGE_REMOVE_FAILED)),
    }
}

fn install(cx: &Cx, package: &str) -> Result<()> {
    let wait = match cx.distro.family {
        Family::Debian => cx.sys.run_long(APT_GET, &["install", "-y", package])?,
        _ => cx.sys.run_long(DNF, &["install", "-y", package])?,
    };
    if !wait.success() {
        return Err(plain(PACKAGE_FAILED));
    }
    Ok(())
}

fn remove(cx: &Cx, names: &[String]) -> Result<()> {
    let mut owned: Vec<String> = match cx.distro.family {
        Family::Debian => vec!["remove".into(), "-y".into()],
        _ => vec!["remove".into(), "-y".into(), "--no-autoremove".into()],
    };
    owned.extend(names.iter().cloned());
    let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let program = if cx.distro.family == Family::Debian {
        APT_GET
    } else {
        DNF
    };
    if !cx.sys.run_long(program, &refs)?.success() {
        return Err(plain(PACKAGE_REMOVE_FAILED));
    }
    Ok(())
}

/// The packages are simulated first and the plan is refused if it would touch anything but what is being added or
/// taken away. What an install added is written down first, so the undo takes away exactly that.
pub fn write_processor_updates(cx: &Cx, want: &Items) -> Result<()> {
    let Some((package, names)) = processor_package(cx)? else {
        return Err(plain(CHANGE_FAILED));
    };
    match num_of(want, "installed")? {
        Some(1) => {
            if any_installed(cx, names) == Some(true) {
                return Ok(());
            }
            let plan = install_plan(cx, package)?.ok_or_else(|| plain(PACKAGE_REFUSED))?;
            if !plan.iter().any(|n| n == package) || !plan.iter().all(|n| is_valid_package(n)) {
                return Err(plain(PACKAGE_REFUSED));
            }
            cx.memo_write(PROCESSOR_MEMO, &plan)?;
            let done = install(cx, package).and_then(|()| {
                if installed(cx, package) == Some(true) {
                    Ok(())
                } else {
                    Err(plain(PACKAGE_FAILED))
                }
            });
            if done.is_err() {
                let left: Vec<String> = plan
                    .into_iter()
                    .filter(|n| installed(cx, n) == Some(true))
                    .collect();
                if left.is_empty() {
                    cx.memo_clear(PROCESSOR_MEMO)?;
                } else {
                    cx.memo_write(PROCESSOR_MEMO, &left)?;
                }
            }
            done
        }
        Some(0) => {
            let recorded = cx
                .memo_read(PROCESSOR_MEMO)?
                .ok_or_else(|| plain(NO_RECORD))?;
            if !recorded.iter().all(|n| is_valid_package(n)) {
                return Err(plain(NO_RECORD));
            }
            let present: Vec<String> = recorded
                .into_iter()
                .filter(|n| installed(cx, n) == Some(true))
                .collect();
            if !present.is_empty() {
                let plan = removal_plan(cx, &present)?;
                if !plan.iter().all(|n| present.contains(n)) {
                    return Err(plain(PACKAGE_UNDO_REFUSED));
                }
                remove(cx, &present)?;
                if present.iter().any(|n| installed(cx, n) != Some(false)) {
                    return Err(plain(PACKAGE_REMOVE_FAILED));
                }
            }
            cx.memo_clear(PROCESSOR_MEMO)
        }
        Some(_) => Err(plain(UNRECOGNISED)),
        None => Ok(()),
    }
}

const PASSWD: &str = "/usr/bin/passwd";
const ADMIN_GROUPS: [&str; 2] = ["sudo", "wheel"];

/// The state of the main administrator account's password: 1 usable, 0 locked, `None` for anything else.
fn root_password(cx: &Cx) -> Option<u32> {
    let out = cx.run(PASSWD, &["-S", "root"]).ok()?;
    if !out.success() {
        return None;
    }
    match out.stdout.split_whitespace().nth(1)? {
        "P" => Some(1),
        "L" | "LK" => Some(0),
        _ => None,
    }
}

/// Whether some other account that can sign in with a password belongs to the group of administrators.
fn other_admin(cx: &Cx) -> bool {
    let (Some(passwd), Some(group)) = (
        cx.text("/etc/passwd").ok().flatten(),
        cx.text("/etc/group").ok().flatten(),
    ) else {
        return false;
    };
    let shadow = cx.text("/etc/shadow").ok().flatten();
    let accounts: Vec<Vec<&str>> = passwd
        .lines()
        .map(|l| l.split(':').collect::<Vec<_>>())
        .filter(|f| f.len() >= 4)
        .collect();
    let mut candidates: Vec<&str> = Vec::new();
    for line in group.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 4 || !ADMIN_GROUPS.contains(&fields[0]) {
            continue;
        }
        candidates.extend(fields[3].split(',').filter(|n| !n.is_empty()));
        candidates.extend(accounts.iter().filter(|a| a[3] == fields[2]).map(|a| a[0]));
    }
    let can_sign_in = |name: &str| {
        shadow.as_ref().is_none_or(|text| {
            text.lines().any(|l| {
                let mut f = l.split(':');
                f.next() == Some(name)
                    && f.next()
                        .is_some_and(|hash| !hash.is_empty() && !hash.starts_with(['!', '*']))
            })
        })
    };
    candidates.into_iter().any(|name| {
        name != "root" && accounts.iter().any(|a| a[0] == name && a[2] != "0") && can_sign_in(name)
    })
}

pub fn observe_root_account(cx: &Cx) -> Result<Observation> {
    let Some(state) = root_password(cx) else {
        return Ok(observation(vec![("usable", Item::Absent)], true, ""));
    };
    if state == 1 && !other_admin(cx) {
        return Ok(observation(
            vec![("usable", flag(true))],
            false,
            NO_OTHER_ADMIN,
        ));
    }
    Ok(observation(vec![("usable", Item::Num(state))], true, ""))
}

/// Locking keeps the password in the file behind a mark, so unlocking brings back exactly what was there.
pub fn write_root_account(cx: &Cx, want: &Items) -> Result<()> {
    match (num_of(want, "usable")?, root_password(cx)) {
        (Some(0), Some(1)) => {
            if !other_admin(cx) {
                return Err(plain(NO_OTHER_ADMIN));
            }
            cx.run_ok(PASSWD, &["-l", "root"])?;
            Ok(())
        }
        (Some(1), Some(0)) => {
            cx.run_ok(PASSWD, &["-u", "root"])?;
            Ok(())
        }
        (Some(0 | 1), _) | (None, _) => Ok(()),
        (Some(_), _) => Err(plain(UNRECOGNISED)),
    }
}
