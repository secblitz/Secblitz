//! Ways in from other computers: the remote sign-in (SSH) server, how it lets people in, and Windows file sharing (Samba).
//!
//! `enabled` and `samba` are 1 when a unit of that service is switched on or running, 0 when it is installed but off, and
//! absent when it is not installed. `password` is 1 when a password may be used to sign in over SSH; `root_login` is the
//! server's `PermitRootLogin` word.

use super::units::{self, Unit};
use super::{
    flag, num_of, observation, plain, text_item, text_of, unavailable, Cx, Items,
    NO_REMOTE_SIGN_IN, NO_SIGN_IN_KEY, REMOTE_SIGN_IN_OFF, REMOTE_SIGN_IN_UNREADABLE, UNRECOGNISED,
};
use crate::hardening::Item;
use crate::model::Observation;
use anyhow::Result;
use std::path::Path;

/// Sockets come first so switching them off does not start the service again.
const SSH_UNITS: [&str; 4] = ["ssh.socket", "sshd.socket", "ssh.service", "sshd.service"];
const SSH_FALLBACK: [&str; 2] = ["ssh.service", "sshd.service"];
const SSH_RELOAD: [&str; 2] = ["ssh.service", "sshd.service"];
const SSH_MEMO: &str = "ssh-units";
const SAMBA_UNITS: [&str; 4] = ["smbd.service", "nmbd.service", "smb.service", "nmb.service"];
const SAMBA_FALLBACK: [&str; 2] = ["smbd.service", "smb.service"];
const SAMBA_MEMO: &str = "samba-units";
const SSHD: &str = "/usr/sbin/sshd";
const SSH_DROPIN: &str = "/etc/ssh/sshd_config.d/00-secblitz.conf";
const SSH_NOTE: &str = "# Written by Secblitz. Delete this file to go back to how it was.\n";

fn on_state(units: &[Unit]) -> Item {
    if units.is_empty() {
        Item::Absent
    } else {
        flag(units.iter().any(Unit::on))
    }
}

fn write_units(
    cx: &Cx,
    names: &[&'static str],
    fallback: &[&'static str],
    memo: &str,
    wanted: Option<u32>,
) -> Result<()> {
    match wanted {
        Some(0) => units::switch_off(cx, memo, &units::probe_all(cx, names)),
        Some(1) => {
            if units::probe_all(cx, names).iter().any(Unit::on) {
                return Ok(());
            }
            units::switch_on(cx, memo, names, fallback)
        }
        _ => Ok(()),
    }
}

pub fn observe_ssh_server(cx: &Cx) -> Result<Observation> {
    let units = units::probe_all(cx, &SSH_UNITS);
    Ok(observation(vec![("enabled", on_state(&units))], true, ""))
}

pub fn write_ssh_server(cx: &Cx, want: &Items) -> Result<()> {
    write_units(
        cx,
        &SSH_UNITS,
        &SSH_FALLBACK,
        SSH_MEMO,
        num_of(want, "enabled")?,
    )
}

pub fn observe_file_sharing(cx: &Cx) -> Result<Observation> {
    let units = units::probe_all(cx, &SAMBA_UNITS);
    Ok(observation(vec![("samba", on_state(&units))], true, ""))
}

pub fn write_file_sharing(cx: &Cx, want: &Items) -> Result<()> {
    write_units(
        cx,
        &SAMBA_UNITS,
        &SAMBA_FALLBACK,
        SAMBA_MEMO,
        num_of(want, "samba")?,
    )
}

/// What the server would do right now, from `sshd -T`: whether passwords work and the root login word.
fn sshd_settings(cx: &Cx) -> Result<(u32, String)> {
    let out = cx.run_ok(SSHD, &["-T"])?;
    let mut password = None;
    let mut root = None;
    for line in out.stdout.lines() {
        match line.split_once(' ') {
            Some(("passwordauthentication", v)) => password = Some(v.trim().to_ascii_lowercase()),
            Some(("permitrootlogin", v)) => root = Some(v.trim().to_ascii_lowercase()),
            _ => {}
        }
    }
    let password = match password.as_deref() {
        Some("yes") => 1,
        Some("no") => 0,
        _ => anyhow::bail!("unusual PasswordAuthentication"),
    };
    let root = match root.as_deref() {
        Some("without-password") => "prohibit-password".to_string(),
        Some(v @ ("yes" | "no" | "prohibit-password" | "forced-commands-only")) => v.to_string(),
        other => anyhow::bail!("unusual PermitRootLogin {other:?}"),
    };
    Ok((password, root))
}

pub fn observe_ssh_password(cx: &Cx) -> Result<Observation> {
    let units = units::probe_all(cx, &SSH_UNITS);
    if units.is_empty() || cx.run(SSHD, &["-V"]).is_err() {
        return Ok(unavailable("linux.ssh_password", NO_REMOTE_SIGN_IN));
    }
    match sshd_settings(cx) {
        Ok((password, root)) => {
            let reason = if units.iter().any(Unit::on) {
                ""
            } else {
                REMOTE_SIGN_IN_OFF
            };
            Ok(observation(
                vec![
                    ("password", Item::Num(password)),
                    ("root_login", text_item(root)),
                ],
                reason.is_empty(),
                reason,
            ))
        }
        Err(e) => {
            eprintln!("secblitz: sshd: {e:#}");
            Ok(unavailable("linux.ssh_password", REMOTE_SIGN_IN_UNREADABLE))
        }
    }
}

/// Whether anyone can sign in over SSH with a key, in the places the server looks by default.
fn sign_in_key_exists(cx: &Cx) -> bool {
    let mut homes = vec!["/root".to_string()];
    homes.extend(cx.list("/home").into_iter().map(|n| format!("/home/{n}")));
    homes.iter().any(|home| {
        let file = format!("{home}/.ssh/authorized_keys");
        cx.sys
            .read(Path::new(&file))
            .ok()
            .flatten()
            .is_some_and(|bytes| {
                String::from_utf8_lossy(&bytes).lines().any(|l| {
                    let l = l.trim();
                    !l.is_empty() && !l.starts_with('#')
                })
            })
    })
}

/// The server's own drop-in is taken away first, so an undo returns to what the other files say; lines are added only for
/// what they do not already give. The result is read back and the drop-in removed again if it did not take effect.
pub fn write_ssh_password(cx: &Cx, want: &Items) -> Result<()> {
    let password = num_of(want, "password")?;
    let root = text_of(want, "root_login")?;
    if password.is_some_and(|p| p > 1)
        || root.is_some_and(|r| {
            !matches!(
                r,
                "yes" | "no" | "prohibit-password" | "forced-commands-only"
            )
        })
    {
        return Err(plain(UNRECOGNISED));
    }
    let previous = cx.text(SSH_DROPIN)?;
    cx.remove(SSH_DROPIN)?;
    let (now_password, now_root) = sshd_settings(cx)?;
    if password == Some(0) && now_password == 1 && !sign_in_key_exists(cx) {
        if let Some(text) = previous {
            cx.write_text(SSH_DROPIN, &text, 0o644)?;
        }
        return Err(plain(NO_SIGN_IN_KEY));
    }
    let mut text = String::from(SSH_NOTE);
    let mut changed = false;
    if let Some(p) = password.filter(|p| *p != now_password) {
        text.push_str(&format!(
            "PasswordAuthentication {}\n",
            if p == 1 { "yes" } else { "no" }
        ));
        changed = true;
    }
    if let Some(r) = root.filter(|r| *r != now_root) {
        text.push_str(&format!("PermitRootLogin {r}\n"));
        changed = true;
    }
    if changed {
        cx.write_text(SSH_DROPIN, &text, 0o644)?;
        let took_effect = cx.run_ok(SSHD, &["-t"]).is_ok()
            && sshd_settings(cx)
                .is_ok_and(|(p, r)| password.is_none_or(|w| w == p) && root.is_none_or(|w| w == r));
        if !took_effect {
            cx.remove(SSH_DROPIN)?;
            return Err(plain(super::CHANGE_FAILED));
        }
    }
    for unit in units::probe_all(cx, &SSH_RELOAD) {
        if unit.active && !unit.alias() {
            units::reload(cx, unit.name)?;
        }
    }
    Ok(())
}
