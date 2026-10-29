//! The scheduler loop (E2.9): ticks every `every` until shut down. The platform's jobs are
//! expiring pairings past their 5 minutes and trimming events past retention (E1-04.4);
//! modules' jobs come with E2-11. The time comes from a
//! `Clock`, so nothing reads the system clock itself and tests drive it with a fake one.

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::SqlitePool;

use crate::store::gov::expire_pairings;

/// The most events one tick trims: the write stays short, and at the default 10 s tick that is
/// 30 000 a minute, three times the 10k/min the bus is sized for (E1-04.5).
const TRIM_BATCH: u32 = 5_000;

/// Trims events older than the `events.retention_secs` setting (E1-04.4).
///
/// Time-based, not count-based: what a client can rely on is "offline for less than the
/// retention, I resume; longer, I re-sync", which a count cannot promise (a busy hour would
/// shorten it). Disk stays bounded by the write rate times the retention.
async fn trim_events(pool: &SqlitePool, now: &str) -> Result<(), sqlx::Error> {
    use ainkrad_core::settings::{Key, Scope};
    let keep = crate::store::settings::value(pool, Key::EventsRetentionSecs, Scope::Server).await?;
    if let Some(t) = crate::store::events::trim(pool, now, keep, TRIM_BATCH).await? {
        tracing::info!(floor = t.floor, removed = t.removed, "events trimmed");
    }
    Ok(())
}

/// Where the scheduler gets "now", as ISO-8601 UTC text (`2026-10-21T10:00:00.000Z`).
pub trait Clock {
    fn now(&self) -> String;

    /// The same instant in whole unix seconds (signed requests, sessions, lockouts).
    fn unix(&self) -> i64 {
        unix_secs(&self.now()).expect("a clock gives `YYYY-MM-DDTHH:MM:SS…Z`")
    }
}

/// The real clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> String {
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        iso8601(since.as_millis() as i64)
    }
}

/// Whole unix seconds of a stored `YYYY-MM-DDTHH:MM:SS[.fff]Z` time; `None` for anything else.
pub fn unix_secs(iso: &str) -> Option<i64> {
    let b = iso.as_bytes();
    let shape = b.len() >= 20
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && iso.ends_with('Z');
    let num = |r: std::ops::Range<usize>| iso.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !shape || !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm), the inverse of `iso8601`.
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

/// Unix seconds as the stored format.
pub fn iso_of_unix(secs: i64) -> String {
    iso8601(secs * 1000)
}

/// `ms` since the Unix epoch as ISO-8601 UTC with milliseconds, the stored format.
fn iso8601(ms: i64) -> String {
    let (days, ms) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let (h, m, s) = (ms / 3_600_000, ms / 60_000 % 60, ms / 1000 % 60);
    format!(
        "{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{:03}Z",
        ms % 1000
    )
}

/// How often the scheduler ticks and the pusher pushes: the `scheduler.tick_secs` and
/// `push.interval_secs` settings (E15.17), read once when `serve` starts.
pub async fn loop_intervals(pool: &SqlitePool) -> Result<[Duration; 2], sqlx::Error> {
    use ainkrad_core::settings::{Key, Scope};
    let mut out = [Duration::ZERO; 2];
    let keys = [Key::SchedulerTickSecs, Key::PushIntervalSecs];
    for (d, key) in out.iter_mut().zip(keys) {
        let secs = crate::store::settings::value(pool, key, Scope::Server).await?;
        *d = Duration::from_secs(secs as u64);
    }
    Ok(out)
}

pub struct Scheduler<C> {
    pub pool: SqlitePool,
    pub clock: C,
    /// Time between ticks.
    pub every: Duration,
}

impl<C: Clock> Scheduler<C> {
    /// Ticks at once, then every `every`, until `shutdown` completes; returns how many
    /// ticks ran. A failed tick is reported on stderr and the loop goes on: the next tick
    /// retries the same work, since it is idempotent.
    pub async fn run(&self, shutdown: impl Future<Output = ()>) -> u64 {
        tokio::pin!(shutdown);
        let mut every = tokio::time::interval(self.every);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut ticks = 0;
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => return ticks,
                _ = every.tick() => {
                    let now = self.clock.now();
                    if let Err(e) = expire_pairings(&self.pool, &now).await {
                        eprintln!("ainkrad-core-server: scheduler tick failed: {e}");
                    }
                    if let Err(e) = trim_events(&self.pool, &now).await {
                        eprintln!("ainkrad-core-server: trimming events failed: {e}");
                    }
                    let unix = unix_secs(&now).unwrap_or_default();
                    if let Err(e) = crate::store::gov::prune_limits(&self.pool, unix).await {
                        eprintln!("ainkrad-core-server: pruning lockouts failed: {e}");
                    }
                    ticks += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use ainkrad_core::audit::AuditActor;
    use tokio::sync::oneshot;

    use super::*;
    use crate::store::connect;

    #[test]
    fn formats_epoch_millis_as_stored_timestamps() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_792_576_800_123), "2026-10-21T10:00:00.123Z");
        assert_eq!(iso8601(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(iso8601(-1), "1969-12-31T23:59:59.999Z");
        assert_eq!(SystemClock.now().len(), 24);
        for ms in [
            0,
            1_792_576_800_000,
            951_782_400_000,
            -86_400_000,
            4_102_444_799_000,
        ] {
            assert_eq!(unix_secs(&iso8601(ms)), Some(ms / 1000), "{ms}");
        }
        assert_eq!(unix_secs("2026-10-21T10:00:00Z"), Some(1_792_576_800));
        for bad in [
            "",
            "2026-10-21 10:00:00.000Z",
            "2026-13-21T10:00:00.000Z",
            "x026-10-21T10:00:00.000Z",
        ] {
            assert_eq!(unix_secs(bad), None, "{bad}");
        }
    }

    /// Hands out `times` in order, then signals `done` and keeps repeating the last one.
    struct Fake {
        times: Mutex<Vec<&'static str>>,
        done: Mutex<Option<oneshot::Sender<()>>>,
    }

    impl Clock for Fake {
        fn now(&self) -> String {
            let mut times = self.times.lock().unwrap();
            if times.len() == 1 {
                if let Some(done) = self.done.lock().unwrap().take() {
                    let _ = done.send(());
                }
                return times[0].to_owned();
            }
            times.remove(0).to_owned()
        }
    }

    #[tokio::test]
    async fn the_loop_intervals_are_settings() {
        use ainkrad_core::settings::{Key, Scope};
        let dir = std::env::temp_dir().join(format!("core-loops-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = connect(&dir.join("core.db")).await.unwrap();
        let secs = |s: u64| Duration::from_secs(s);
        assert_eq!(loop_intervals(&pool).await.unwrap(), [secs(10), secs(5)]);
        let now = "2026-10-22T10:00:00.000Z";
        for (key, v) in [(Key::SchedulerTickSecs, "2"), (Key::PushIntervalSecs, "3")] {
            let by = AuditActor::System;
            crate::store::settings::set(&pool, key, Scope::Server, v, by, now)
                .await
                .unwrap();
        }
        assert_eq!(loop_intervals(&pool).await.unwrap(), [secs(2), secs(3)]);
        pool.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn the_loop_ticks_on_the_clock_until_shut_down() {
        let dir = std::env::temp_dir().join(format!("core-sched-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = connect(&dir.join("core.db")).await.unwrap();
        // A code started at 10:00 lives five minutes; one started at 10:58 outlives the run.
        for (n, expires) in ["2026-10-21T10:05:00.000Z", "2026-10-21T11:03:00.000Z"]
            .into_iter()
            .enumerate()
        {
            sqlx::query(
                "INSERT INTO core_pairings (id, code_hash, secret_hash, kind, name, scopes, \
                 created_at, expires_at) VALUES (?, ?, ?, 'device', 'x', '[]', ?, ?)",
            )
            .bind(crate::auth::crypto::random_id("p_"))
            .bind(vec![n as u8; 32])
            .bind(vec![n as u8 + 10; 32])
            .bind("2026-10-21T10:00:00.000Z")
            .bind(expires)
            .execute(&pool)
            .await
            .unwrap();
        }

        let (tx, rx) = oneshot::channel();
        let scheduler = Scheduler {
            pool: pool.clone(),
            clock: Fake {
                times: Mutex::new(vec![
                    "2026-10-21T10:00:00.000Z",
                    "2026-10-21T10:30:00.000Z",
                    "2026-10-21T11:00:00.000Z",
                ]),
                done: Mutex::new(Some(tx)),
            },
            every: Duration::from_millis(5),
        };
        // Shut down once the clock runs out, or after 5 s if the loop stops asking it.
        let shutdown = async {
            let _ = tokio::time::timeout(Duration::from_secs(5), rx).await;
        };
        let ticks = scheduler.run(shutdown).await;
        assert!(ticks >= 3, "{ticks}");
        let left: i64 =
            sqlx::query_scalar("SELECT count(*) FROM core_pairings WHERE status = 'live'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            left, 1,
            "the expired pairing is expired, the live one stays"
        );
        pool.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn the_loop_trims_events_past_retention() {
        let dir = std::env::temp_dir().join(format!("core-sched-trim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = connect(&dir.join("core.db")).await.unwrap();
        crate::store::kinds::allow(&pool, &["ops.line"], &[]).await;
        for at in ["2026-09-01T00:00:00.000Z", "2026-10-21T09:00:00.000Z"] {
            sqlx::query("INSERT INTO events (at, kind, payload) VALUES (?, 'ops.line', '{}')")
                .bind(at)
                .execute(&pool)
                .await
                .unwrap();
        }
        let (tx, rx) = oneshot::channel();
        let scheduler = Scheduler {
            pool: pool.clone(),
            clock: Fake {
                times: Mutex::new(vec!["2026-10-21T10:00:00.000Z"]),
                done: Mutex::new(Some(tx)),
            },
            every: Duration::from_millis(5),
        };
        let shutdown = async {
            let _ = tokio::time::timeout(Duration::from_secs(5), rx).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        scheduler.run(shutdown).await;
        // The default retention is 30 days: the September event goes, this morning's stays.
        assert_eq!(crate::store::events::floor(&pool).await.unwrap(), 1);
        pool.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
