//! Explanations for the sign-in and remote access fixes: automatic sign-in,
//! Remote Desktop and the old file-sharing version.
use super::Explainer;

const fn e(what: &'static str, risk: &'static str, change: &'static str) -> Explainer {
    Explainer { what, risk, change }
}

#[cfg(test)]
const IDS: &[&str] = &[
    "accounts.autologon",
    "remote_desktop.disabled",
    "smb1.disabled",
];

pub(super) fn get(id: &str) -> Option<Explainer> {
    Some(match id {
        "accounts.autologon" => e(
            "Your computer is set to sign in to your account by itself when it starts, without asking for a password.",
            "Anyone who can switch on your computer, or who finds it lost, gets straight into your files and accounts.",
            "Your computer asks for your password or PIN when it starts. Make sure you know it before you turn this on.",
        ),
        "remote_desktop.disabled" => e(
            "Remote Desktop lets someone sign in to this computer and use it from another device, anywhere on the internet or your network.",
            "Anyone who knows one password could sign in from another device and use this computer.",
            "Other devices can no longer connect this way. Everything on this computer works as before, and you can turn it back on.",
        ),
        "smb1.disabled" => e(
            "A very old way of sharing files and printers between computers is still switched on in Windows.",
            "Malware has used flaws in it to spread from one computer to the next without anyone clicking anything.",
            "Very old network drives or printers that only use it may stop working. Needs a restart, and you can turn it back on.",
        ),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_access_control_has_a_short_calm_explanation() {
        for id in IDS {
            assert!(crate::hardening::is_hardening_check_id(id), "{id}");
            let x = get(id).unwrap_or_else(|| panic!("no explanation for {id}"));
            for (label, line) in [("what", x.what), ("risk", x.risk), ("change", x.change)] {
                crate::explain::tests::assert_short_sentence(id, label, line);
                assert!(
                    !line.contains('!') && !line.contains('\u{2014}'),
                    "{id} {label}"
                );
                assert!(
                    !line.contains("SMB") && !line.contains("RDP"),
                    "{id} {label}"
                );
            }
            assert!(crate::explain::for_check(id).is_some(), "{id}");
        }
        assert!(get("not.a.check").is_none());
    }
}
