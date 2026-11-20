//! Tier 2 of the heavy-job decision (spec §5.2): how long a command takes in a project.
//! `core_cmd_history` keeps, per project and `cmd_key`, the run count and a running median.
//! Jobs report their duration when they end; the shim reports the ones that ran locally.

use sqlx::SqlitePool;

/// A command whose median is above this is heavy ...
pub const HEAVY_MS: i64 = 20_000;
/// ... once it has run at least this many times.
pub const MIN_RUNS: i64 = 2;

/// What history says about a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hist {
    Heavy,
    /// Seen enough times, and quick.
    Light,
    /// Too few runs to say.
    Unknown,
}

/// The program plus its first two non-flag arguments: `cargo test`, `npm run build`.
pub fn cmd_key(argv: &[String]) -> String {
    let prog = argv.first().map_or("", |p| p.rsplit('/').next().unwrap_or(p));
    let words = argv
        .iter()
        .skip(1)
        .filter(|a| !a.starts_with('-') && !a.starts_with('+'))
        .take(2);
    let mut key = prog.to_owned();
    for w in words {
        key.push(' ');
        key.push_str(w);
    }
    key.chars().take(256).collect()
}

pub fn judge(runs: i64, p50_ms: i64) -> Hist {
    match (runs >= MIN_RUNS, p50_ms > HEAVY_MS) {
        (false, _) => Hist::Unknown,
        (true, true) => Hist::Heavy,
        (true, false) => Hist::Light,
    }
}

/// The median after one more run of `ms`.
// ponytail: a running estimate that moves 1/n (at most 1/5) of the way to each new run: exact for
// two runs, then it follows the recent runs. Keep samples if a project needs a true median.
pub fn next_p50(p50_ms: i64, runs: i64, ms: i64) -> i64 {
    if runs <= 0 {
        return ms;
    }
    p50_ms + (ms - p50_ms) / (runs + 1).min(5)
}

pub async fn lookup(pool: &SqlitePool, project: i64, key: &str) -> sqlx::Result<Hist> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT runs, p50_ms FROM core_cmd_history WHERE project_id = ? AND cmd_key = ?",
    )
    .bind(project)
    .bind(key)
    .fetch_optional(pool)
    .await?;
    Ok(row.map_or(Hist::Unknown, |(runs, p50)| judge(runs, p50)))
}

/// Adds one run of `ms` milliseconds. `now` is the ISO time stored as `updated_at`.
pub async fn record(
    pool: &SqlitePool,
    project: i64,
    key: &str,
    ms: i64,
    now: &str,
) -> sqlx::Result<()> {
    let ms = ms.max(0);
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT runs, p50_ms FROM core_cmd_history WHERE project_id = ? AND cmd_key = ?",
    )
    .bind(project)
    .bind(key)
    .fetch_optional(pool)
    .await?;
    let (runs, p50) = row.unwrap_or((0, 0));
    sqlx::query(
        "INSERT INTO core_cmd_history (project_id, cmd_key, runs, p50_ms, last_ms, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT (project_id, cmd_key) DO UPDATE SET runs = excluded.runs, \
         p50_ms = excluded.p50_ms, last_ms = excluded.last_ms, updated_at = excluded.updated_at",
    )
    .bind(project)
    .bind(key)
    .bind(runs.saturating_add(1))
    .bind(next_p50(p50, runs, ms))
    .bind(ms)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn the_key_is_the_program_and_two_words() {
        assert_eq!(cmd_key(&a("/usr/bin/cargo +nightly test -p x --release foo bar")), "cargo test x");
        assert_eq!(cmd_key(&a("make")), "make");
        assert_eq!(cmd_key(&a("npm run build")), "npm run build");
        assert_eq!(cmd_key(&[]), "");
    }

    #[test]
    fn heavy_needs_two_runs_and_a_slow_median() {
        assert_eq!(judge(1, 90_000), Hist::Unknown);
        assert_eq!(judge(2, 20_001), Hist::Heavy);
        assert_eq!(judge(2, 20_000), Hist::Light);
        assert_eq!(judge(0, 0), Hist::Unknown);
    }

    #[test]
    fn the_median_follows_the_runs() {
        assert_eq!(next_p50(0, 0, 30_000), 30_000);
        // Two runs: the middle, as a median of two is.
        assert_eq!(next_p50(30_000, 1, 10_000), 20_000);
        // One slow outlier does not tip a quick command over the line.
        let mut p = 5_000;
        for (runs, ms) in [(5, 5_000), (6, 90_000), (7, 5_000)] {
            p = next_p50(p, runs, ms);
        }
        assert!(p < HEAVY_MS, "{p}");
    }
}
