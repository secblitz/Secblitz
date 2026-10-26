//! Reading and changing single assignments in the plain `key=value` files Linux programs use, leaving every other byte as it was.

struct Line<'a> {
    text: &'a str,
    section: String,
    key: Option<&'a str>,
}

fn strip_quotes(value: &str) -> &str {
    ['"', '\'']
        .iter()
        .find_map(|q| value.strip_prefix(*q)?.strip_suffix(*q))
        .unwrap_or(value)
}

fn lines(text: &str) -> Vec<Line<'_>> {
    let mut section = String::new();
    text.split_inclusive('\n')
        .map(|raw| {
            let t = raw.trim();
            let mut key = None;
            if t.starts_with('[') && t.ends_with(']') && t.len() >= 2 {
                section = t[1..t.len() - 1].to_string();
            } else if !t.is_empty() && !t.starts_with('#') && !t.starts_with(';') {
                if let Some((k, _)) = t.split_once('=') {
                    key = Some(k.trim());
                }
            }
            Line {
                text: raw,
                section: section.clone(),
                key,
            }
        })
        .collect()
}

fn value_of(line: &str) -> &str {
    strip_quotes(line.split_once('=').map_or("", |(_, v)| v.trim()))
}

/// The names of the `[sections]`, in file order.
pub fn sections(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in lines(text) {
        if line.key.is_none() && line.text.trim().starts_with('[') && !found.contains(&line.section)
        {
            found.push(line.section);
        }
    }
    found
}

/// The value of the last assignment of `key` inside any of `sections` (`""` is the part before the first section).
pub fn get(text: &str, sections: &[&str], key: &str) -> Option<String> {
    lines(text)
        .into_iter()
        .rev()
        .find(|l| l.key == Some(key) && sections.contains(&l.section.as_str()))
        .map(|l| value_of(l.text).to_string())
}

fn ending(raw: &str) -> &str {
    if raw.ends_with("\r\n") {
        "\r\n"
    } else if raw.ends_with('\n') {
        "\n"
    } else {
        ""
    }
}

/// Sets `key` in `section`: the last assignment is changed in place, otherwise a line is added to that section (which is added when missing).
pub fn set(text: &str, section: &str, key: &str, value: &str) -> String {
    let parsed = lines(text);
    if let Some(i) = parsed
        .iter()
        .rposition(|l| l.key == Some(key) && l.section == section)
    {
        let raw = parsed[i].text;
        let eq = raw.find('=').unwrap_or(0);
        let after = &raw[eq + 1..];
        let spaces = after.len() - after.trim_start_matches([' ', '\t']).len();
        let kept = &raw[..eq + 1 + spaces];
        let mut out = String::with_capacity(text.len() + value.len());
        for (n, l) in parsed.iter().enumerate() {
            if n == i {
                out.push_str(kept);
                out.push_str(value);
                out.push_str(ending(raw));
            } else {
                out.push_str(l.text);
            }
        }
        return out;
    }
    let new_line = |nl: &str| format!("{key}={value}{nl}");
    let in_section: Vec<usize> = parsed
        .iter()
        .enumerate()
        .filter(|(_, l)| l.section == section && l.key.is_some())
        .map(|(i, _)| i)
        .collect();
    let header = parsed.iter().position(|l| {
        l.key.is_none()
            && l.text.trim().starts_with('[')
            && l.section == section
            && !section.is_empty()
    });
    let at = match (in_section.last(), header) {
        (Some(last), _) => Some(*last),
        (None, Some(h)) => Some(h),
        (None, None) if section.is_empty() => None,
        (None, None) => {
            let mut out = text.to_string();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(&format!("[{section}]\n"));
            out.push_str(&new_line("\n"));
            return out;
        }
    };
    match at {
        Some(at) => {
            let mut out = String::with_capacity(text.len() + key.len() + value.len() + 2);
            for (n, l) in parsed.iter().enumerate() {
                out.push_str(l.text);
                if n == at {
                    if !l.text.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str(&new_line("\n"));
                }
            }
            out
        }
        None => {
            let mut out = text.to_string();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&new_line("\n"));
            out
        }
    }
}

/// Removes every assignment of `key` inside any of `sections`.
pub fn unset(text: &str, sections: &[&str], key: &str) -> String {
    lines(text)
        .into_iter()
        .filter(|l| !(l.key == Some(key) && sections.contains(&l.section.as_str())))
        .map(|l| l.text)
        .collect()
}

/// Whether anything but blank lines, comments and section headers is left.
pub fn has_assignments(text: &str) -> bool {
    lines(text).iter().any(|l| l.key.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GDM: &str = "# GDM\n\n[daemon]\n\n# Enabling automatic login\n#  AutomaticLoginEnable = true\n\n[security]\n\n[debug]\n#Enable=true\n";

    #[test]
    fn comments_are_not_assignments_and_the_last_assignment_wins() {
        assert_eq!(get(GDM, &["daemon"], "AutomaticLoginEnable"), None);
        let text = "[daemon]\nAutomaticLoginEnable = True\nAutomaticLoginEnable=\"false\"\n";
        assert_eq!(
            get(text, &["daemon"], "AutomaticLoginEnable").as_deref(),
            Some("false")
        );
        assert_eq!(get(text, &["security"], "AutomaticLoginEnable"), None);
        assert_eq!(get("enabled=1\n", &[""], "enabled").as_deref(), Some("1"));
    }

    #[test]
    fn a_new_key_goes_into_its_section_and_nothing_else_moves() {
        let out = set(GDM, "daemon", "AutomaticLoginEnable", "false");
        assert_eq!(
            out,
            "# GDM\n\n[daemon]\nAutomaticLoginEnable=false\n\n# Enabling automatic login\n#  AutomaticLoginEnable = true\n\n[security]\n\n[debug]\n#Enable=true\n"
        );
        assert_eq!(unset(&out, &["daemon"], "AutomaticLoginEnable"), GDM);
    }

    #[test]
    fn an_existing_key_is_changed_in_place_with_its_spacing() {
        let text = "[daemon]\nAutomaticLoginEnable = true\r\nAutomaticLogin = sam\n";
        let out = set(text, "daemon", "AutomaticLoginEnable", "false");
        assert_eq!(
            out,
            "[daemon]\nAutomaticLoginEnable = false\r\nAutomaticLogin = sam\n"
        );
        assert_eq!(set("enabled=1", "", "enabled", "0"), "enabled=0");
        assert_eq!(set("a=\nb=2\n", "", "a", "x"), "a=x\nb=2\n");
    }

    #[test]
    fn a_missing_section_is_added_at_the_end() {
        assert_eq!(set("[a]\nx=1\n", "b", "y", "2"), "[a]\nx=1\n\n[b]\ny=2\n");
        assert_eq!(set("", "b", "y", "2"), "[b]\ny=2\n");
        assert_eq!(set("# top\n", "", "k", "v"), "# top\nk=v\n");
        assert_eq!(set("k=v", "", "j", "w"), "k=v\nj=w\n");
    }

    #[test]
    fn sections_and_leftovers_are_reported() {
        assert_eq!(sections("[a]\nx=1\n[b]\n"), ["a", "b"]);
        assert!(has_assignments("[a]\nx=1\n"));
        assert!(!has_assignments("# c\n[a]\n\n"));
    }
}
