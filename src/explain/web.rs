use super::Explainer;

pub(super) fn get(id: &str) -> Option<Explainer> {
    Some(match id {
        "web.ads" => Explainer {
            what: "Most ads come from a known list of advertising websites. This stops your computer from loading anything from that list.",
            risk: "Ads slow pages down, follow you from site to site, and sometimes lead to scam or virus websites.",
            change: "Many ads disappear from websites and apps. Some pages look a little different, and a few sites may ask you to turn this off.",
        },
        "web.tracking" => Explainer {
            what: "Many websites, apps and Windows itself quietly send data about what you do to companies that collect it.",
            risk: "Your habits can be collected, sold and used to show you ads built around you.",
            change: "Those requests are stopped. Everything should work as before, but a few pages that rely on them may load oddly.",
        },
        "web.dangerous" => Explainer {
            what: "Secblitz keeps a list of known scam and virus websites and updates it often.",
            risk: "A link in an email or message could take you to a look-alike bank page or a site that infects your computer.",
            change: "Your computer can't open websites on that list. If a safe site is blocked by mistake, pause web protection for an hour.",
        },
        "web.scam" => Explainer {
            what: "Secblitz keeps a list of fake online shops, fake streaming sites and subscription traps, and updates it every day.",
            risk: "A fake shop takes your money and card details and sends nothing. A fake streaming site can sign you up to payments you never meant to make.",
            change: "Your computer can't open websites on that list. If a real site is blocked by mistake, open it for 10 minutes from Recent blocks on the Overview tab, or allow it on the Sites tab.",
        },
        "web.popups" => Explainer {
            what: "Secblitz keeps a list of websites known for flooding people with pop-ups and fake alerts, and updates it every day.",
            risk: "These sites show fake messages such as 'your computer is infected' to scare you into calling a scam number or paying for software you don't need.",
            change: "Your computer can't open websites on that list. This list sometimes blocks a real site by mistake, so you can open one for 10 minutes from Recent blocks on the Overview tab, or allow it on the Sites tab.",
        },
        "web.adult" => Explainer {
            what: "Secblitz keeps a list of websites meant for adults and updates it often.",
            risk: "Children, and anyone else using this computer, can open those websites by accident or on purpose.",
            change: "Your computer can't open websites on that list. If a safe site is blocked by mistake, allow it on the Sites tab.",
        },
        "web.gambling" => Explainer {
            what: "Secblitz keeps a list of online betting and casino websites and updates it often.",
            risk: "Gambling websites are easy to open and can lead to losing money quickly, especially for children.",
            change: "Your computer can't open websites on that list. If a safe site is blocked by mistake, allow it on the Sites tab.",
        },
        "web.safe_search" => Explainer {
            what: "Search websites can hide results meant for adults. This asks Google, Bing, YouTube and DuckDuckGo to show only family-friendly results.",
            risk: "Searches and videos can show adult content, even when nobody was looking for it.",
            change: "Searches on those four websites show only family-friendly results in every browser on this computer. Other search websites are not changed.",
        },
        "web.private_lookups" => Explainer {
            what: "Every time you open a website, your computer first asks where it is. Normally that question can be read by your internet provider and by anyone on the same public Wi-Fi.",
            risk: "They can see every website you visit, even when the website itself is protected.",
            change: "The question is sent privately to Quad9, a non-profit service. If your network doesn't allow that, Secblitz goes back to the normal way so the internet keeps working.",
        },
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_switch_is_explained() {
        for id in [
            "web.ads",
            "web.tracking",
            "web.dangerous",
            "web.scam",
            "web.popups",
            "web.adult",
            "web.gambling",
            "web.safe_search",
            "web.private_lookups",
        ] {
            assert!(get(id).is_some(), "{id}");
            assert!(crate::explain::for_check(id).is_some(), "{id}");
        }
        assert!(get("web.other").is_none());
    }
}
