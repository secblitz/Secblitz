//! What a page that this system does not have yet says, instead of an error or Windows-only controls.
use crate::gui::theme;
use crate::gui::widgets::{self, ButtonKind};
use crate::gui::{Ctx, Message, Page};
use iced::widget::{column, space};
use iced::Element;
use secblitz::os::Os;

const TITLE: &str = "Not available on {system} yet";
const HELP: &str = "This part of Secblitz is not ready for {system} yet. Your checks and fixes are on the Protection page.";
const GO: &str = "Go to Protection";

/// The pages with nothing to show on this system.
pub fn applies(os: Os, page: Page) -> bool {
    match os {
        Os::Windows => false,
        Os::Linux => matches!(page, Page::Web | Page::Tools),
        Os::Macos => matches!(page, Page::Web | Page::Tools | Page::Debloat),
    }
}

pub fn view<'a>(ctx: &'a Ctx, page: Page) -> Element<'a, Message> {
    let p = ctx.palette;
    let system = Os::CURRENT.name();
    let title = ctx.t(TITLE).replace("{system}", system);
    column![
        widgets::page_header(p, ctx.t(page.label()), Some(title.clone())),
        space::vertical().height(theme::S6),
        widgets::region(
            p,
            column![
                widgets::h2(p, title),
                widgets::muted(p, ctx.t(HELP).replace("{system}", system)),
                space::vertical().height(theme::S2),
                widgets::action(
                    p,
                    ButtonKind::Secondary,
                    ctx.t(GO),
                    None,
                    Some(Message::Navigate(Page::Fixes)),
                ),
            ]
            .spacing(theme::S1),
        ),
    ]
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    #[test]
    fn linux_has_no_web_protection_or_tools_yet_and_windows_keeps_all() {
        for page in Page::ALL {
            assert!(!applies(Os::Windows, page), "{page:?}");
        }
        for page in [Page::Web, Page::Tools] {
            assert!(applies(Os::Linux, page), "{page:?}");
        }
        for page in [
            Page::Home,
            Page::Fixes,
            Page::Debloat,
            Page::History,
            Page::Settings,
        ] {
            assert!(!applies(Os::Linux, page), "{page:?}");
        }
    }

    #[test]
    fn the_words_are_plain_and_exist_in_every_language() {
        for lang in [Lang::Es, Lang::Fr, Lang::De, Lang::Pt, Lang::It] {
            for key in [TITLE, HELP, GO] {
                let text = lang.t(key);
                assert_ne!(text, key, "{}: {key}", lang.code());
            }
            assert!(lang.t(TITLE).contains("{system}"), "{}", lang.code());
        }
        for key in [TITLE, HELP, GO] {
            assert!(!key.contains('\u{2014}'));
        }
    }
}
