//! Things that reach outside the computer by themselves: Bluetooth adapters that switch on at every start and the weekly
//! list of installed programs that Debian and Ubuntu can send.
//!
//! `auto_enable` is 1 when Bluetooth adapters switch themselves on every time the computer starts, which is also what
//! happens when nothing says otherwise. `participate` is 1 when the program that reports installed programs is set to take
//! part.

use super::services::{put_back_file, remember_file, remembered_file, two_state};
use super::units;
use super::{flag, ini, observation, plain, unavailable, Cx, Items, NO_RECORD, UNRECOGNISED};
use crate::model::Observation;
use anyhow::Result;
use std::path::Path;

const BLUETOOTH_CONF: &str = "/etc/bluetooth/main.conf";
const BLUETOOTH_UNIT: &str = "bluetooth.service";
const BLUETOOTH_MEMO: &str = "bluetooth-file";
const SURVEY_CONF: &str = "/etc/popularity-contest.conf";
const SURVEY_TOOL: &str = "/usr/sbin/popularity-contest";
const SURVEY_MEMO: &str = "usage-survey-file";

pub const NO_BLUETOOTH: &str =
    "Bluetooth is not set up on this computer, so Secblitz leaves this alone.";
pub const NO_USAGE_SURVEY: &str = "The program that reports installed programs is not on this computer, so Secblitz leaves this alone.";

/// Every sentence a person can be shown by these controls, for the translation tests.
pub const SENTENCES: [&str; 2] = [NO_BLUETOOTH, NO_USAGE_SURVEY];

/// The Bluetooth settings file when Bluetooth is installed, or `None` when it is not or has no such file.
fn bluetooth_file(cx: &Cx) -> Result<Option<String>> {
    if units::probe(cx, BLUETOOTH_UNIT).is_none() {
        return Ok(None);
    }
    cx.text(BLUETOOTH_CONF)
}

/// Whether the adapters switch on at start. `None` when the file says something Secblitz does not know.
fn auto_enable(text: &str) -> Option<bool> {
    match ini::get(text, &["Policy"], "AutoEnable").as_deref() {
        None | Some("true" | "1") => Some(true),
        Some("false" | "0") => Some(false),
        Some(_) => None,
    }
}

/// Whether Bluetooth is installed and its settings can be read, for the list of checks to show.
pub fn bluetooth_present(cx: &Cx) -> bool {
    bluetooth_file(cx).is_ok_and(|t| t.is_some_and(|t| auto_enable(&t).is_some()))
}

pub fn observe_bluetooth(cx: &Cx) -> Result<Observation> {
    let Some(text) = bluetooth_file(cx)? else {
        return Ok(unavailable("linux.bluetooth_autostart", NO_BLUETOOTH));
    };
    match auto_enable(&text) {
        Some(on) => Ok(observation(vec![("auto_enable", flag(on))], true, "")),
        None => Ok(unavailable("linux.bluetooth_autostart", UNRECOGNISED)),
    }
}

/// Turning it off changes only the one key and takes effect at the next start. Bluetooth is not restarted, so nobody loses
/// a keyboard or mouse that is connected right now.
pub fn write_bluetooth(cx: &Cx, want: &Items) -> Result<()> {
    let Some(on) = two_state(want, "auto_enable")? else {
        return Ok(());
    };
    let text = bluetooth_file(cx)?.ok_or_else(|| plain(NO_BLUETOOTH))?;
    let now = auto_enable(&text).ok_or_else(|| plain(UNRECOGNISED))?;
    if now == (on == 1) {
        return Ok(());
    }
    if on == 0 {
        remember_file(cx, BLUETOOTH_MEMO, text.as_bytes())?;
        cx.write_text(
            BLUETOOTH_CONF,
            &ini::set(&text, "Policy", "AutoEnable", "false"),
            0o644,
        )
    } else {
        let bytes = remembered_file(cx, BLUETOOTH_MEMO)?.ok_or_else(|| plain(NO_RECORD))?;
        put_back_file(cx, BLUETOOTH_CONF, &bytes)?;
        cx.memo_clear(BLUETOOTH_MEMO)
    }
}

/// The survey program's settings when the program is installed, or `None` when it is not.
fn survey_file(cx: &Cx) -> Result<Option<String>> {
    if cx.sys.read(Path::new(SURVEY_TOOL)).ok().flatten().is_none() {
        return Ok(None);
    }
    cx.text(SURVEY_CONF)
}

fn participates(text: &str) -> Option<bool> {
    match ini::get(text, &[""], "PARTICIPATE").as_deref() {
        Some("yes") => Some(true),
        Some("no") => Some(false),
        _ => None,
    }
}

/// Whether the program is installed and its settings can be read, for the list of checks to show.
pub fn survey_present(cx: &Cx) -> bool {
    survey_file(cx).is_ok_and(|t| t.is_some_and(|t| participates(&t).is_some()))
}

pub fn observe_usage_survey(cx: &Cx) -> Result<Observation> {
    let Some(text) = survey_file(cx)? else {
        return Ok(unavailable("linux.usage_survey", NO_USAGE_SURVEY));
    };
    match participates(&text) {
        Some(on) => Ok(observation(vec![("participate", flag(on))], true, "")),
        None => Ok(unavailable("linux.usage_survey", UNRECOGNISED)),
    }
}

pub fn write_usage_survey(cx: &Cx, want: &Items) -> Result<()> {
    let Some(on) = two_state(want, "participate")? else {
        return Ok(());
    };
    let text = survey_file(cx)?.ok_or_else(|| plain(NO_USAGE_SURVEY))?;
    let now = participates(&text).ok_or_else(|| plain(UNRECOGNISED))?;
    if now == (on == 1) {
        return Ok(());
    }
    if on == 0 {
        remember_file(cx, SURVEY_MEMO, text.as_bytes())?;
        cx.write_text(
            SURVEY_CONF,
            &ini::set(&text, "", "PARTICIPATE", "\"no\""),
            0o644,
        )
    } else {
        let bytes = remembered_file(cx, SURVEY_MEMO)?.ok_or_else(|| plain(NO_RECORD))?;
        put_back_file(cx, SURVEY_CONF, &bytes)?;
        cx.memo_clear(SURVEY_MEMO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_real_assignment_in_the_policy_section_counts() {
        assert_eq!(auto_enable("[Policy]\n#AutoEnable=true\n"), Some(true));
        assert_eq!(auto_enable("[Policy]\nAutoEnable=false\n"), Some(false));
        assert_eq!(auto_enable("[General]\nAutoEnable=false\n"), Some(true));
        assert_eq!(auto_enable("[Policy]\nAutoEnable=0\n"), Some(false));
        assert_eq!(auto_enable("[Policy]\nAutoEnable=maybe\n"), None);
    }

    #[test]
    fn the_survey_setting_is_read_with_or_without_quotes() {
        assert_eq!(participates("PARTICIPATE=\"yes\"\n"), Some(true));
        assert_eq!(
            participates("# PARTICIPATE=\"yes\"\nPARTICIPATE=no\n"),
            Some(false)
        );
        assert_eq!(participates("PARTICIPATE=\"Yes\"\n"), None);
        assert_eq!(participates("MY_HOSTID=\"abc\"\n"), None);
    }
}
