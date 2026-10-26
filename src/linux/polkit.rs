//! Which polkit action each request needs, and the one polkit call the helper makes.
use crate::app::remote::Request;

pub const CHECK: &str = "org.secblitz.check";
pub const CHANGE: &str = "org.secblitz.change";
pub const REMOVE: &str = "org.secblitz.remove";

pub const NOT_ALLOWED: &str = "Secblitz needs your password to change this.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Check,
    Change,
    Remove,
}

impl Action {
    pub const fn id(self) -> &'static str {
        match self {
            Action::Check => CHECK,
            Action::Change => CHANGE,
            Action::Remove => REMOVE,
        }
    }
}

/// Reading needs only a signed-in person at the keyboard; anything that can change the computer asks for a password.
pub fn action_for(request: &Request) -> Action {
    match request {
        Request::Available
        | Request::RestartIds
        | Request::Audit
        | Request::History
        | Request::CanStart { .. }
        | Request::UpdateStatus => Action::Check,
        Request::Apply { .. }
        | Request::Undo
        | Request::UndoSelected { .. }
        | Request::ChooseItems { .. }
        | Request::StartFresh
        | Request::MonitorTimer { .. }
        | Request::InstallUpdate => Action::Change,
        Request::RemoveSelf => Action::Remove,
    }
}

#[cfg(target_os = "linux")]
pub use bus::*;

#[cfg(target_os = "linux")]
mod bus {
    use super::Action;
    use std::collections::HashMap;
    use zbus::zvariant::Variant;
    use zbus::{Connection, Message};

    pub const DESTINATION: &str = "org.freedesktop.PolicyKit1";
    pub const PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
    pub const INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
    pub const METHOD: &str = "CheckAuthorization";

    /// Lets the password prompt appear.
    const ALLOW_INTERACTION: u32 = 1;

    type Subject<'a> = (&'a str, HashMap<&'a str, Variant<'a>>);
    /// subject, action id, details, flags, cancellation id
    pub type CheckArgs<'a> = (
        Subject<'a>,
        &'a str,
        HashMap<&'a str, &'a str>,
        u32,
        &'a str,
    );

    /// The caller is named by its bus name, so polkit looks up the process behind that name itself.
    pub fn check_args<'a>(sender: &'a str, action: &'a str) -> CheckArgs<'a> {
        let mut subject = HashMap::new();
        subject.insert("name", Variant::from(sender));
        (
            ("system-bus-name", subject),
            action,
            HashMap::new(),
            ALLOW_INTERACTION,
            "",
        )
    }

    #[cfg(test)]
    pub fn check_message(sender: &str, action: &str) -> zbus::Result<Message> {
        Message::method_call(PATH, METHOD)
            .interface(INTERFACE)
            .destination(DESTINATION)
            .build(&check_args(sender, action))
    }

    /// The reply is `(bba{ss})`: authorized, challenge, details. Only a plain yes counts; a dismissed prompt or an unanswered challenge is a no.
    pub fn decode_reply(reply: &Message) -> zbus::Result<bool> {
        let (authorized, _challenge, _details): (bool, bool, HashMap<String, String>) =
            reply.body().deserialize()?;
        Ok(authorized)
    }

    pub async fn is_authorized(
        connection: &Connection,
        sender: &str,
        action: Action,
    ) -> zbus::Result<bool> {
        let reply = connection
            .call_method(
                Some(DESTINATION),
                PATH,
                Some(INTERFACE),
                METHOD,
                &check_args(sender, action.id()),
            )
            .await?;
        decode_reply(&reply)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        type Decoded = (
            (String, HashMap<String, zbus::zvariant::OwnedVariant>),
            String,
            HashMap<String, String>,
            u32,
            String,
        );

        /// The signature field as it sits in the header bytes. The typed accessors wrap a multi-argument body in one more struct.
        fn wire_signature(message: &Message) -> String {
            let bytes = message.data().to_vec();
            let at = bytes
                .windows(4)
                .position(|w| w == [8, 1, b'g', 0])
                .expect("the header has a signature field");
            let len = usize::from(bytes[at + 4]);
            String::from_utf8(bytes[at + 5..at + 5 + len].to_vec()).unwrap()
        }

        #[test]
        fn the_call_is_encoded_the_way_polkit_expects() {
            let message = check_message(":1.42", "org.secblitz.change").unwrap();
            assert_eq!(wire_signature(&message), "(sa{sv})sa{ss}us");
            let header = message.header();
            assert_eq!(header.member().unwrap().as_str(), "CheckAuthorization");
            assert_eq!(
                header.interface().unwrap().as_str(),
                "org.freedesktop.PolicyKit1.Authority"
            );
            assert_eq!(
                header.destination().unwrap().to_string(),
                "org.freedesktop.PolicyKit1"
            );
        }

        #[test]
        fn the_body_names_the_caller_the_action_and_allows_the_prompt() {
            let message = check_message(":1.42", "org.secblitz.check").unwrap();
            let body = message.body();
            let ((kind, fields), action, details, flags, cancel): Decoded =
                body.deserialize().unwrap();
            assert_eq!(kind, "system-bus-name");
            assert_eq!(fields.len(), 1);
            let name: String = fields["name"].try_clone().unwrap().try_into().unwrap();
            assert_eq!(name, ":1.42");
            assert_eq!(action, "org.secblitz.check");
            assert!(details.is_empty());
            assert_eq!(flags, 1);
            assert_eq!(cancel, "");
        }

        fn reply(authorized: bool, challenge: bool) -> Message {
            Message::method_call(PATH, METHOD)
                .build(&(authorized, challenge, HashMap::<String, String>::new()))
                .unwrap()
        }

        #[test]
        fn only_a_plain_yes_is_a_yes() {
            assert!(decode_reply(&reply(true, false)).unwrap());
            assert!(!decode_reply(&reply(false, false)).unwrap());
            assert!(!decode_reply(&reply(false, true)).unwrap());
        }

        #[test]
        fn a_reply_of_the_wrong_shape_is_an_error() {
            let odd = Message::method_call(PATH, METHOD).build(&"yes").unwrap();
            assert!(decode_reply(&odd).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reading_asks_for_the_light_action_and_changing_for_the_password_one() {
        for request in [
            Request::Available,
            Request::RestartIds,
            Request::Audit,
            Request::History,
            Request::CanStart { undo: true },
            Request::UpdateStatus,
        ] {
            assert_eq!(action_for(&request), Action::Check, "{request:?}");
        }
        for request in [
            Request::Apply { ids: vec![] },
            Request::Undo,
            Request::UndoSelected { ids: vec![] },
            Request::ChooseItems {
                picked: Default::default(),
            },
            Request::StartFresh,
            Request::MonitorTimer { on: true },
            Request::MonitorTimer { on: false },
            Request::InstallUpdate,
        ] {
            assert_eq!(action_for(&request), Action::Change, "{request:?}");
        }
        assert_eq!(action_for(&Request::RemoveSelf), Action::Remove);
        assert_eq!(Action::Remove.id(), "org.secblitz.remove");
        assert_eq!(Action::Check.id(), "org.secblitz.check");
        assert_eq!(Action::Change.id(), "org.secblitz.change");
    }
}
