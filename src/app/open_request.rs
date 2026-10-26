//! A page asked for by a second start while Secblitz is already open.
//!
//! The second start may run without administrator rights, so the request sits in
//! the user's own folder. The open app only reads it: a page name it knows and
//! a time. It never deletes it, since a delete with administrator rights in a
//! folder the user controls could be pointed at another file.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const FILE: &str = "open-request.json";
const LIMIT: u64 = 256;
const FRESH_SECONDS: u64 = 30;

#[derive(Serialize, Deserialize)]
struct Request {
    page: String,
    at: u64,
}

fn path() -> Option<PathBuf> {
    if cfg!(test) {
        return None;
    }
    let base = std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty())?;
    Some(PathBuf::from(base).join("Secblitz").join(FILE))
}

#[cfg(windows)]
pub fn write(page: &str, now: u64) {
    let Some(path) = path() else {
        return;
    };
    let Ok(bytes) = serde_json::to_vec(&Request {
        page: page.to_owned(),
        at: now,
    }) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, bytes);
}

/// The page asked for since `after`, if the request is still fresh.
pub fn read(now: u64, after: u64) -> Option<(String, u64)> {
    use std::io::Read;
    let file = std::fs::File::open(path()?).ok()?;
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes).ok()?;
    parse(&bytes, now, after)
}

fn parse(bytes: &[u8], now: u64, after: u64) -> Option<(String, u64)> {
    if bytes.len() as u64 > LIMIT {
        return None;
    }
    let request: Request = serde_json::from_slice(bytes).ok()?;
    let fresh = request.at > after && request.at <= now && now - request.at <= FRESH_SECONDS;
    fresh.then_some((request.page, request.at))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(page: &str, at: u64) -> Vec<u8> {
        serde_json::to_vec(&Request {
            page: page.into(),
            at,
        })
        .unwrap()
    }

    #[test]
    fn a_request_counts_once_and_only_while_fresh() {
        let req = bytes("protection", 1000);
        assert_eq!(parse(&req, 1005, 0), Some(("protection".into(), 1000)));
        assert_eq!(parse(&req, 1005, 1000), None, "already handled");
        assert_eq!(parse(&req, 1000 + FRESH_SECONDS + 1, 0), None, "too old");
        assert_eq!(parse(&req, 990, 0), None, "from the future");
    }

    #[test]
    fn damaged_or_oversized_requests_are_ignored() {
        assert_eq!(parse(b"{broken", 1000, 0), None);
        let long = bytes(&"p".repeat(LIMIT as usize), 1000);
        assert_eq!(parse(&long, 1000, 0), None);
    }
}
