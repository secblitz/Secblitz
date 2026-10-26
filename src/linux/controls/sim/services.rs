//! The programs behind the clock, printing, Ubuntu news and snap update controls. Each starts from the output recorded on a
//! real install (`tests/fixtures/linux/<name>/cmd/<program>.txt`, kept under `rec.<program>`) and changes that text the way
//! the real program does.

use super::{out, Sim};
use crate::linux::cmd::Output;
use anyhow::Result;
use std::path::Path;

pub(super) fn load_recordings(sim: &Sim, dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_string_lossy().into_owned();
        sim.set(
            &format!("rec.{name}"),
            &std::fs::read_to_string(&path).unwrap(),
        );
    }
}

/// `text` with the line that starts with `prefix` swapped for `line`.
fn replace_line(text: &str, prefix: &str, line: &str) -> String {
    text.lines()
        .map(|l| if l.starts_with(prefix) { line } else { l })
        .map(|l| format!("{l}\n"))
        .collect()
}

fn word(on: bool) -> &'static str {
    if on {
        "yes"
    } else {
        "no"
    }
}

fn timedatectl(sim: &Sim, args: &[&str]) -> Result<Output> {
    match args {
        ["show"] => out(0, &sim.get("rec.timedatectl")),
        ["set-ntp", on] => {
            let line = format!("NTP={}", word(*on == "true"));
            sim.set(
                "rec.timedatectl",
                &replace_line(&sim.get("rec.timedatectl"), "NTP=", &line),
            );
            out(0, "")
        }
        other => anyhow::bail!("timedatectl {other:?}"),
    }
}

fn cupsctl(sim: &Sim, args: &[&str]) -> Result<Output> {
    let mut text = sim.get("rec.cupsctl");
    for arg in args {
        let (key, on) = match *arg {
            "--share-printers" => ("_share_printers", 1),
            "--no-share-printers" => ("_share_printers", 0),
            "--remote-admin" => ("_remote_admin", 1),
            "--no-remote-admin" => ("_remote_admin", 0),
            "--remote-any" => ("_remote_any", 1),
            "--no-remote-any" => ("_remote_any", 0),
            _ => return out(1, ""),
        };
        text = replace_line(&text, &format!("{key}="), &format!("{key}={on}"));
    }
    sim.set("rec.cupsctl", &text);
    if args.is_empty() {
        return out(0, &text);
    }
    out(0, "")
}

fn pro(sim: &Sim, args: &[&str]) -> Result<Output> {
    match args {
        ["config", "show"] => out(0, &sim.get("rec.pro")),
        ["config", "set", setting] => {
            let Some(("apt_news", value)) = setting.split_once('=') else {
                return out(1, "");
            };
            let shown = if value == "true" { "True" } else { "False" };
            let line = format!("apt_news                       {shown}");
            let text = sim.get("rec.pro");
            let updated: String = text
                .lines()
                .map(|l| {
                    if l.starts_with("apt_news ") && !l.starts_with("apt_news_url") {
                        line.as_str()
                    } else {
                        l
                    }
                })
                .map(|l| format!("{l}\n"))
                .collect();
            sim.set("rec.pro", &updated);
            out(0, "")
        }
        other => anyhow::bail!("pro {other:?}"),
    }
}

fn snap(sim: &Sim, args: &[&str]) -> Result<Output> {
    const NONE: &str = "error: snap \"system\" has no \"refresh.hold\" configuration option\n";
    match args {
        ["get", "system", "refresh.hold"] => {
            let held = sim.get("rec.snap-hold");
            if held.is_empty() {
                Ok(Output {
                    status: 1,
                    stdout: String::new(),
                    stderr: NONE.into(),
                })
            } else {
                out(0, &held)
            }
        }
        ["unset", "system", "refresh.hold"] => {
            sim.set("rec.snap-hold", "");
            out(0, "")
        }
        ["set", "system", setting] => {
            let Some(value) = setting.strip_prefix("refresh.hold=") else {
                return out(1, "");
            };
            sim.set("rec.snap-hold", &format!("{value}\n"));
            out(0, "")
        }
        other => anyhow::bail!("snap {other:?}"),
    }
}

pub(super) fn dispatch(sim: &Sim, program: &str, args: &[&str]) -> Option<Result<Output>> {
    Some(match program {
        "/usr/bin/timedatectl" => timedatectl(sim, args),
        "/usr/sbin/cupsctl" => cupsctl(sim, args),
        "/usr/bin/pro" => pro(sim, args),
        "/usr/bin/snap" => snap(sim, args),
        "/usr/bin/date" if args.last() == Some(&"+%s") => out(0, &format!("{}\n", sim.now())),
        "/usr/bin/systemctl" if args.first() == Some(&"try-restart") => out(0, ""),
        _ => return None,
    })
}

impl Sim {
    /// The clock of the stand-in computer in seconds, when the recordings were made (26 October 2026, 11:04:48).
    fn now(&self) -> String {
        let set = self.get("clock");
        if set.is_empty() {
            "1793012688".into()
        } else {
            set
        }
    }
}
