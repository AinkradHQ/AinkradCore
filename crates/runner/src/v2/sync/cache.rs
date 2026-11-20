//! Where the warm per-project caches live and which to drop (E15-4, spec §4.5): one folder per
//! project under `<work_root>/cache/<core_id>/`, an index file beside it, and a persistent job home
//! (the Cargo, npm and Go caches of the project's jobs). Least recently used caches go when free
//! disk drops under [`MIN_FREE_PCT`] or the total passes [`MAX_TOTAL_BYTES`].

use std::path::{Path, PathBuf};

pub const MIN_FREE_PCT: u8 = 10;
pub const MAX_TOTAL_BYTES: u64 = 20 * 1024 * 1024 * 1024;

/// The caches of one Core on this runner.
#[derive(Clone, Debug)]
pub struct Layout {
    base: PathBuf,
}

/// The Core part of the cache path: the Core's fingerprint, kept to path-safe characters.
pub fn safe_core_id(id: &str) -> Option<String> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    ok.then(|| id.to_owned())
}

impl Layout {
    pub fn new(work_root: &Path, core_id: &str) -> Self {
        Self {
            base: work_root.join("cache").join(core_id),
        }
    }

    pub fn base(&self) -> &Path {
        &self.base
    }

    /// The project's working copy.
    pub fn root(&self, project: i64) -> PathBuf {
        self.base.join(project.to_string())
    }

    pub fn index(&self, project: i64) -> PathBuf {
        self.base.join(format!("{project}.index.json"))
    }

    /// The writable home of the project's jobs (package caches), outside the synced tree.
    pub fn home(&self, project: i64) -> PathBuf {
        self.base.join(".home").join(project.to_string())
    }

    /// The projects that have an index here.
    pub fn projects(&self) -> Vec<i64> {
        let Ok(rd) = std::fs::read_dir(&self.base) else {
            return Vec::new();
        };
        rd.flatten()
            .filter_map(|e| {
                e.file_name()
                    .to_str()?
                    .strip_suffix(".index.json")?
                    .parse()
                    .ok()
            })
            .collect()
    }
}

/// The bytes under `path`, links not followed.
pub fn dir_size(path: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(path) else {
        return 0;
    };
    rd.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_size(&e.path()),
            Ok(_) => e.metadata().map_or(0, |m| m.len()),
            Err(_) => 0,
        })
        .sum()
}

/// Free space on the disk holding `path`, as a percentage (`df -Pk`: used percentage in column 5).
pub fn free_pct(path: &Path) -> Option<u8> {
    let out = std::process::Command::new("df")
        .arg("-Pk")
        .arg(path)
        .output()
        .ok()?;
    parse_df(&String::from_utf8_lossy(&out.stdout))
}

pub fn parse_df(out: &str) -> Option<u8> {
    let used: u8 = out
        .lines()
        .nth(1)?
        .split_whitespace()
        .nth(4)?
        .trim_end_matches('%')
        .parse()
        .ok()?;
    Some(100u8.saturating_sub(used))
}

/// One cache as eviction sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    pub project: i64,
    /// Unix seconds of its last use.
    pub last_used: u64,
    pub bytes: u64,
}

/// Which caches to drop, oldest first, never `keep`: all of what passes the total cap, or the one
/// oldest when the disk is low (the next sync drops another if it is still low).
/// ponytail: a low disk drops one cache per sync, not enough at once for a very full disk.
pub fn to_evict(held: &[Held], free: Option<u8>, keep: i64) -> Vec<i64> {
    let mut order: Vec<&Held> = held.iter().filter(|h| h.project != keep).collect();
    order.sort_by_key(|h| h.last_used);
    let mut total: u64 = held.iter().map(|h| h.bytes).sum();
    let mut out = Vec::new();
    for h in &order {
        if total <= MAX_TOTAL_BYTES {
            break;
        }
        total -= h.bytes;
        out.push(h.project);
    }
    if out.is_empty()
        && free.is_some_and(|f| f < MIN_FREE_PCT)
        && let Some(h) = order.first()
    {
        out.push(h.project);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(project: i64, last_used: u64, gb: u64) -> Held {
        Held {
            project,
            last_used,
            bytes: gb << 30,
        }
    }

    #[test]
    fn the_oldest_caches_go_past_the_total_cap_but_never_the_one_in_use() {
        let held = [h(1, 10, 8), h(2, 20, 8), h(3, 30, 8)];
        // 24 GB over a 20 GB cap: the oldest goes, and that is enough.
        assert_eq!(to_evict(&held, Some(50), 9), vec![1]);
        assert_eq!(to_evict(&held, Some(50), 1), vec![2], "project 1 is in use");
        let more = [h(1, 10, 15), h(2, 20, 15), h(3, 30, 15)];
        assert_eq!(to_evict(&more, Some(50), 9), vec![1, 2]);
        assert!(to_evict(&[h(1, 1, 1)], Some(50), 9).is_empty());
    }

    #[test]
    fn a_low_disk_drops_the_oldest_one() {
        let held = [h(1, 10, 1), h(2, 20, 1)];
        assert_eq!(
            to_evict(&held[1..], Some(5), 2),
            Vec::<i64>::new(),
            "only the kept one is left"
        );
        assert_eq!(to_evict(&held, Some(5), 2), vec![1], "never the kept one");
        assert_eq!(to_evict(&held, Some(5), 9), vec![1]);
        assert!(to_evict(&held, Some(50), 9).is_empty());
        assert!(to_evict(&held, None, 9).is_empty());
    }

    #[test]
    fn df_gives_free_percent_and_layout_paths_are_per_project() {
        let out = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk1 1000 900 100 90% /\n";
        assert_eq!(parse_df(out), Some(10));
        assert_eq!(parse_df("nothing"), None);
        let l = Layout::new(Path::new("/w"), "core");
        assert_eq!(l.root(7), Path::new("/w/cache/core/7"));
        assert_eq!(l.index(7), Path::new("/w/cache/core/7.index.json"));
        assert_eq!(safe_core_id("a-B_9").as_deref(), Some("a-B_9"));
        assert_eq!(safe_core_id("a/b"), None);
    }
}
