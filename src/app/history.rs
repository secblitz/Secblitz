//! Score log (`checks.jsonl`) and the merged History timeline.
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

pub const FILE: &str = "checks.jsonl";
pub const MAX_LINES: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Check,
    Fix,
    Undo,
    UndoSome,
    Debloat,
    Restore,
    Recovery,
    SecureBootRenewal,
    FreedSpace,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub t: u64,
    pub kind: Kind,
    pub protected: usize,
    pub total: usize,
    #[serde(default)]
    pub n: usize,
}

/// Append one line and keep only the newest `MAX_LINES`. The file is replaced
/// atomically (temp file in the same folder, then rename), so a crash never
/// leaves a half-written log.
pub fn record(dir: &Path, entry: &Entry) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(FILE);
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_owned)
        .collect();
    lines.push(serde_json::to_string(entry)?);
    if lines.len() > MAX_LINES {
        let excess = lines.len() - MAX_LINES;
        lines.drain(..excess);
    }
    let tmp = dir.join(format!("{FILE}.tmp"));
    {
        let mut file = std::fs::File::create(&tmp)?;
        for line in &lines {
            file.write_all(line.as_bytes())?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

pub fn load(dir: &Path) -> Vec<Entry> {
    let Ok(text) = std::fs::read_to_string(dir.join(FILE)) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| serde_json::from_str::<Entry>(l.trim()).ok())
        .collect()
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub use secblitz::clock::{local_day, local_seconds};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub t: u64,
    pub kind: Kind,
    pub n: usize,
    pub protected: usize,
    pub total: usize,
    pub repeats: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Day {
    pub day: u64,
    pub items: Vec<Item>,
}

pub fn timeline(entries: &[Entry]) -> Vec<Day> {
    let mut sorted: Vec<&Entry> = entries.iter().collect();
    sorted.sort_by(|a, b| b.t.cmp(&a.t));
    let mut days: Vec<Day> = Vec::new();
    for e in sorted {
        let day = local_day(e.t);
        if days.last().is_none_or(|d| d.day != day) {
            days.push(Day {
                day,
                items: Vec::new(),
            });
        }
        let items = &mut days.last_mut().expect("day pushed").items;
        if let Some(prev) = items.last_mut() {
            if prev.kind == Kind::Check
                && e.kind == Kind::Check
                && prev.protected == e.protected
                && prev.total == e.total
            {
                prev.repeats += 1;
                continue;
            }
        }
        items.push(Item {
            t: e.t,
            kind: e.kind,
            n: e.n,
            protected: e.protected,
            total: e.total,
            repeats: 1,
        });
    }
    days
}

pub fn label(kind: Kind, n: usize) -> &'static str {
    match (kind, n) {
        (Kind::Check, _) => "Checked your computer",
        (Kind::Fix, 0) => "Fixed problems",
        (Kind::Fix, 1) => "Fixed 1 problem",
        (Kind::Fix, _) => "Fixed {n} problems",
        (Kind::Undo, _) => "Undid your last fixes",
        (Kind::UndoSome, 0 | 1) => "Put back 1 setting",
        (Kind::UndoSome, _) => "Put back {n} settings",
        (Kind::Debloat, 0 | 1) => "Removed 1 app",
        (Kind::Debloat, _) => "Removed {n} apps",
        (Kind::Restore, 0 | 1) => "Restored an app",
        (Kind::Restore, _) => "Restored {n} apps",
        (Kind::Recovery, _) => "Undo history started fresh",
        (Kind::FreedSpace, _) => "Freed {size}",
        (Kind::SecureBootRenewal, _) => {
            "Started the startup security renewal. This can't be undone."
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DayScore {
    pub day: u64,
    pub protected: usize,
    pub total: usize,
}

impl DayScore {
    pub fn ratio(&self) -> f32 {
        self.protected.min(self.total) as f32 / self.total.max(1) as f32
    }
}

pub fn daily_scores(entries: &[Entry], max_days: usize) -> Vec<DayScore> {
    let mut scored: Vec<&Entry> = entries.iter().filter(|e| e.total > 0).collect();
    scored.sort_by_key(|e| e.t);
    let mut days: Vec<DayScore> = Vec::new();
    for e in scored {
        let score = DayScore {
            day: local_day(e.t),
            protected: e.protected,
            total: e.total,
        };
        match days.last_mut() {
            Some(last) if last.day == score.day => *last = score,
            _ => days.push(score),
        }
    }
    let skip = days.len().saturating_sub(max_days);
    days.drain(..skip);
    days
}

pub fn civil(days: u64) -> (i64, u32, u32) {
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(t: u64, kind: Kind, protected: usize, total: usize, n: usize) -> Entry {
        Entry {
            t,
            kind,
            protected,
            total,
            n,
        }
    }

    #[test]
    fn record_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), &e(10, Kind::Check, 3, 5, 0)).unwrap();
        record(dir.path(), &e(20, Kind::Fix, 5, 5, 2)).unwrap();
        let all = load(dir.path());
        assert_eq!(
            all,
            vec![e(10, Kind::Check, 3, 5, 0), e(20, Kind::Fix, 5, 5, 2)]
        );
        assert!(!dir.path().join("checks.jsonl.tmp").exists());
    }

    #[test]
    fn record_trims_to_max_lines_dropping_oldest() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..(MAX_LINES as u64 + 7) {
            record(dir.path(), &e(i, Kind::Check, 1, 2, 0)).unwrap();
        }
        let all = load(dir.path());
        assert_eq!(all.len(), MAX_LINES);
        assert_eq!(all[0].t, 7);
        assert_eq!(all.last().unwrap().t, MAX_LINES as u64 + 6);
    }

    #[test]
    fn load_skips_malformed_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).is_empty());
        let good = serde_json::to_string(&e(5, Kind::Undo, 1, 2, 0)).unwrap();
        std::fs::write(
            dir.path().join(FILE),
            format!("not json\n{good}\n\n{{\"t\":1}}\n{{\"t\":1,\"kind\":\"nope\",\"protected\":0,\"total\":0}}\n"),
        )
        .unwrap();
        assert_eq!(load(dir.path()), vec![e(5, Kind::Undo, 1, 2, 0)]);
        record(dir.path(), &e(6, Kind::Check, 2, 2, 0)).unwrap();
        assert_eq!(load(dir.path()).len(), 2);
    }

    #[test]
    fn the_renewal_is_logged_with_a_plain_cannot_be_undone_label() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), &e(9, Kind::SecureBootRenewal, 4, 6, 0)).unwrap();
        assert_eq!(
            load(dir.path()),
            vec![e(9, Kind::SecureBootRenewal, 4, 6, 0)]
        );
        let text = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert!(text.contains("\"secure_boot_renewal\""));
        assert!(label(Kind::SecureBootRenewal, 0).contains("can't be undone"));
    }

    #[test]
    fn freed_space_entries_round_trip_and_stay_out_of_the_score_chart() {
        let entry = e(7, Kind::FreedSpace, 0, 0, 3600);
        let text = serde_json::to_string(&entry).unwrap();
        assert!(text.contains("\"freed_space\""));
        assert_eq!(serde_json::from_str::<Entry>(&text).unwrap(), entry);
        assert!(daily_scores(&[entry], 30).is_empty());
    }

    #[test]
    fn put_back_entries_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), &e(9, Kind::UndoSome, 4, 6, 2)).unwrap();
        assert_eq!(load(dir.path()), vec![e(9, Kind::UndoSome, 4, 6, 2)]);
        let text = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert!(text.contains("\"undo_some\""));
    }

    #[test]
    fn n_defaults_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(FILE),
            "{\"t\":1,\"kind\":\"check\",\"protected\":1,\"total\":2}\n",
        )
        .unwrap();
        assert_eq!(load(dir.path())[0].n, 0);
    }

    #[test]
    fn timeline_is_newest_first_grouped_by_day() {
        let d = 86_400;
        let noon = 10 * d + d / 2;
        let entries = vec![
            e(noon, Kind::Check, 1, 3, 0),
            e(noon + d + 50, Kind::Fix, 3, 3, 2),
            e(noon + d + 10, Kind::Check, 1, 3, 0),
        ];
        let days = timeline(&entries);
        assert_eq!(days.len(), 2);
        assert_eq!(days[0].day, local_day(noon) + 1);
        assert_eq!(days[0].items[0].kind, Kind::Fix);
        assert_eq!(days[0].items[1].kind, Kind::Check);
        assert_eq!(days[1].day, local_day(noon));
        assert!(timeline(&[]).is_empty());
    }

    #[test]
    fn identical_back_to_back_checks_collapse() {
        let entries = vec![
            e(10, Kind::Check, 2, 4, 0),
            e(20, Kind::Check, 2, 4, 0),
            e(30, Kind::Check, 2, 4, 0),
            e(40, Kind::Check, 3, 4, 0),
        ];
        let days = timeline(&entries);
        let items = &days[0].items;
        assert_eq!(items.len(), 2);
        assert_eq!((items[0].protected, items[0].repeats), (3, 1));
        assert_eq!((items[1].t, items[1].repeats), (30, 3));
    }

    #[test]
    fn labels_are_plain() {
        assert_eq!(label(Kind::Check, 0), "Checked your computer");
        assert_eq!(label(Kind::Fix, 1), "Fixed 1 problem");
        assert_eq!(label(Kind::Fix, 3), "Fixed {n} problems");
        assert_eq!(label(Kind::Undo, 0), "Undid your last fixes");
        assert_eq!(label(Kind::FreedSpace, 3600), "Freed {size}");
        assert_eq!(label(Kind::UndoSome, 1), "Put back 1 setting");
        assert_eq!(label(Kind::UndoSome, 4), "Put back {n} settings");
        assert_eq!(label(Kind::Debloat, 12), "Removed {n} apps");
        assert_eq!(label(Kind::Debloat, 1), "Removed 1 app");
        assert_eq!(label(Kind::Restore, 1), "Restored an app");
        assert_eq!(label(Kind::Restore, 4), "Restored {n} apps");
        assert_eq!(label(Kind::Recovery, 0), "Undo history started fresh");
    }

    const DAY: u64 = 86_400;

    #[test]
    fn many_checks_on_one_day_make_one_point_the_last_of_that_day() {
        let entries = vec![
            e(DAY + 300, Kind::Check, 4, 5, 0),
            e(DAY + 100, Kind::Check, 2, 5, 0),
            e(DAY + 200, Kind::Fix, 3, 5, 1),
        ];
        let scores = daily_scores(&entries, 30);
        assert_eq!(scores.len(), 1);
        assert_eq!(
            (scores[0].day, scores[0].protected),
            (local_day(DAY + 300), 4)
        );
    }

    #[test]
    fn days_come_oldest_first_and_far_apart_days_stay_two_points() {
        let entries = vec![
            e(200 * DAY + 5, Kind::Check, 5, 5, 0),
            e(DAY + 5, Kind::Check, 1, 5, 0),
        ];
        let scores = daily_scores(&entries, 30);
        assert_eq!(
            scores.iter().map(|s| s.day).collect::<Vec<_>>(),
            vec![local_day(DAY + 5), local_day(200 * DAY + 5)]
        );
    }

    #[test]
    fn only_the_newest_thirty_days_are_kept() {
        let entries: Vec<Entry> = (0..45u64)
            .map(|d| e(d * DAY + 10, Kind::Check, (d % 5) as usize, 5, 0))
            .collect();
        let scores = daily_scores(&entries, 30);
        assert_eq!(scores.len(), 30);
        assert_eq!(scores[0].day, local_day(15 * DAY + 10));
        assert_eq!(scores[29].day, local_day(44 * DAY + 10));
    }

    #[test]
    fn entries_without_a_score_and_empty_logs_make_no_points() {
        assert!(daily_scores(&[], 30).is_empty());
        assert!(daily_scores(&[e(1, Kind::Debloat, 0, 0, 2)], 30).is_empty());
        let mixed = vec![
            e(DAY, Kind::Check, 3, 4, 0),
            e(DAY + 9, Kind::Debloat, 0, 0, 1),
        ];
        let scores = daily_scores(&mixed, 30);
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].protected, 3);
    }

    #[test]
    fn a_score_is_a_share_between_zero_and_one() {
        let score = |protected, total| DayScore {
            day: 0,
            protected,
            total,
        };
        assert_eq!(score(5, 5).ratio(), 1.0);
        assert_eq!(score(0, 5).ratio(), 0.0);
        assert_eq!(score(7, 5).ratio(), 1.0);
        assert_eq!(score(1, 4).ratio(), 0.25);
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(19_723), (2024, 1, 1));
        assert_eq!(civil(20_366), (2025, 10, 5));
        assert_eq!(civil(11_016), (2000, 2, 29));
    }
}
