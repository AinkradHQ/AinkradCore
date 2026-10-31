//! Health (E1-13.4, E1-19.3): what the Core knows about itself, for an operator who is not
//! watching.
//!
//! - **Metrics** (`metrics`): `GET /api/v1/metrics`, Prometheus text, for a device holding
//!   `admin`. Gauges and counters only, with a handful of fixed label values: never an id, a
//!   name, a path or any content.
//! - **Alarms** (this file): three conditions, each against a setting (`alarm.*`): the newest
//!   backup is too old, the public certificate is too close to its end, the data disk is too
//!   full. The scheduler calls [`Health::tick`]; it reads the host (at most once a minute),
//!   and a condition that holds (or stops holding) for [`DEBOUNCE_SECS`] is a transition: one
//!   audit row and one `alarm.raised`/`alarm.cleared` event, written together. A flapping
//!   reading therefore writes nothing, and a steady one writes nothing after the first. The
//!   notifications service pushes the event to devices holding `admin` (`push::Platform`); its
//!   payload names the alarm and two integers, never a path or a secret.
//!
//! Which alarms are active is not stored: the newest `alarm.*` audit row of each says, read once
//! per process, so a restart neither re-raises a standing alarm nor loses one.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use ainkrad_core::settings::{Key, Scope};
use serde_json::json;
use sqlx::SqlitePool;

use crate::store::{self, audit, events, settings};

pub mod metrics;

/// A condition must hold, or stop holding, this long before it is a transition.
pub const DEBOUNCE_SECS: i64 = 120;
/// The host is read at most this often, whatever the scheduler's tick.
pub const EVERY_SECS: i64 = 60;
/// An alarm changes state at most this often: a reading that flaps around its threshold writes
/// one audit row and one push per gap, not per debounce (about 2 000 rows a day otherwise).
pub const MIN_GAP_SECS: i64 = 3_600;
/// `/api/v1/metrics` shows a host reading at most this old, so a scrape loop cannot make the
/// Core run `df` and `ps` and parse the certificate on every request.
pub const HOST_CACHE_SECS: u64 = 5;

/// What the host showed to a scrape: the process and the alarm readings.
#[derive(Debug, Default)]
pub struct HostSnapshot {
    pub rss_bytes: Option<u64>,
    pub open_fds: Option<u64>,
    pub readings: Readings,
}

/// The three conditions, named as in `alarm.raised` payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alarm {
    BackupAge,
    CertExpiry,
    DiskFree,
}

impl Alarm {
    pub const ALL: [Self; 3] = [Self::BackupAge, Self::CertExpiry, Self::DiskFree];

    pub fn name(self) -> &'static str {
        match self {
            Self::BackupAge => "backup_age",
            Self::CertExpiry => "cert_expiry",
            Self::DiskFree => "disk_free",
        }
    }
}

/// The settings the conditions are judged by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    pub backup_max_age_secs: i64,
    pub cert_min_days: i64,
    pub disk_min_free_pct: i64,
}

impl Thresholds {
    pub async fn load(pool: &SqlitePool) -> Result<Self, sqlx::Error> {
        let get = |k| settings::value(pool, k, Scope::Server);
        Ok(Self {
            backup_max_age_secs: get(Key::AlarmBackupMaxAgeSecs).await?,
            cert_min_days: get(Key::AlarmCertMinDays).await?,
            disk_min_free_pct: get(Key::AlarmDiskMinFreePct).await?,
        })
    }
}

/// What the host showed at one moment. `None`: not known (no certificate on a loopback Core, a
/// `df` that failed); an unknown reading never raises or clears an alarm.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Readings {
    /// Unix seconds of the newest `*.age` file in `<home>/backups/`.
    pub backup_at: Option<i64>,
    /// When the database file was created: the clock of "never backed up".
    pub db_created: Option<i64>,
    /// Unix seconds of the public certificate's end.
    pub cert_not_after: Option<i64>,
    pub disk_free_bytes: Option<u64>,
    pub disk_total_bytes: Option<u64>,
}

impl Readings {
    pub fn backup_age(&self, now: i64) -> Option<i64> {
        self.backup_at.or(self.db_created).map(|t| (now - t).max(0))
    }

    pub fn cert_days_left(&self, now: i64) -> Option<i64> {
        self.cert_not_after.map(|t| (t - now).div_euclid(86_400))
    }

    pub fn disk_free_pct(&self) -> Option<i64> {
        let (free, total) = (self.disk_free_bytes?, self.disk_total_bytes?);
        (total > 0).then(|| i64::try_from(free.saturating_mul(100) / total).unwrap_or(100))
    }

    /// Whether `alarm` is breached, with the reading and the threshold.
    pub fn check(&self, alarm: Alarm, now: i64, th: &Thresholds) -> Option<(bool, i64, i64)> {
        Some(match alarm {
            Alarm::BackupAge => {
                let age = self.backup_age(now)?;
                (age > th.backup_max_age_secs, age, th.backup_max_age_secs)
            }
            Alarm::CertExpiry => {
                let days = self.cert_days_left(now)?;
                (days < th.cert_min_days, days, th.cert_min_days)
            }
            Alarm::DiskFree => {
                let pct = self.disk_free_pct()?;
                (pct < th.disk_min_free_pct, pct, th.disk_min_free_pct)
            }
        })
    }

    /// Reads the host: the home of `db`, and the certificate under `<home>/tls`. The file reads
    /// and the certificate parse run off the async threads.
    pub async fn gather(db: &Path) -> Self {
        let owned = db.to_path_buf();
        let mut r = tokio::task::spawn_blocking(move || Self::read_files(&owned))
            .await
            .unwrap_or_default();
        let home = db.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some((free, total)) = metrics::disk(home.unwrap_or(Path::new("."))).await {
            r.disk_free_bytes = Some(free);
            r.disk_total_bytes = Some(total);
        }
        r
    }

    fn read_files(db: &Path) -> Self {
        let home = db.parent().filter(|p| !p.as_os_str().is_empty());
        let home = home.unwrap_or(Path::new("."));
        let unix = |t: SystemTime| {
            t.duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|d| i64::try_from(d.as_secs()).ok())
        };
        let mut r = Self {
            db_created: std::fs::metadata(db)
                .ok()
                .and_then(|m| m.created().ok())
                .and_then(unix),
            ..Self::default()
        };
        r.backup_at = std::fs::read_dir(home.join("backups"))
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "age"))
            .filter_map(|e| e.metadata().ok()?.modified().ok().and_then(unix))
            .max();
        let tls = home.join("tls");
        r.cert_not_after = std::fs::read_to_string(tls.join("cert.pem"))
            .ok()
            .zip(std::fs::read_to_string(tls.join("key.pem")).ok())
            .and_then(|(chain, key)| crate::gateway::tls::Cert::from_pem(&chain, &key).ok())
            .and_then(|c| unix(c.not_after));
        r
    }
}

#[derive(Debug, Default)]
struct Slot {
    active: bool,
    /// When `active` last changed (unix seconds), for [`MIN_GAP_SECS`].
    changed_at: Option<i64>,
    /// Since when the reading has disagreed with `active`.
    pending_since: Option<i64>,
}

#[derive(Default)]
struct State {
    restored: bool,
    last_eval: Option<i64>,
    slots: HashMap<&'static str, Slot>,
}

/// A change of one alarm's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub alarm: Alarm,
    pub raised: bool,
    pub value: i64,
    pub threshold: i64,
}

/// The Core's health: its alarms' state and the counters the metrics show.
#[derive(Default)]
pub struct Health {
    /// The database file (`serve <db>`); without it the host readings are unknown.
    db: Option<PathBuf>,
    started: Option<Instant>,
    /// Responses by class: 2xx, 3xx, 4xx, 5xx, other.
    requests: [AtomicU64; 5],
    state: Mutex<State>,
    host: tokio::sync::Mutex<Option<(Instant, std::sync::Arc<HostSnapshot>)>>,
}

impl Health {
    pub fn new(db: &Path) -> Self {
        Self {
            db: Some(db.to_path_buf()),
            started: Some(Instant::now()),
            ..Self::default()
        }
    }

    pub fn count_response(&self, status: u16) {
        let class = match status {
            200..=299 => 0,
            300..=399 => 1,
            400..=499 => 2,
            500..=599 => 3,
            _ => 4,
        };
        self.requests[class].fetch_add(1, Ordering::Relaxed);
    }

    pub fn request_counts(&self) -> [u64; 5] {
        std::array::from_fn(|i| self.requests[i].load(Ordering::Relaxed))
    }

    pub fn db_path(&self) -> Option<&Path> {
        self.db.as_deref()
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.map_or(0, |s| s.elapsed().as_secs())
    }

    /// The host as of at most [`HOST_CACHE_SECS`] ago; one scrape at a time computes it.
    pub async fn host(&self) -> std::sync::Arc<HostSnapshot> {
        let mut cache = self.host.lock().await;
        if let Some((at, snap)) = &*cache
            && at.elapsed().as_secs() < HOST_CACHE_SECS
        {
            return std::sync::Arc::clone(snap);
        }
        let (rss_bytes, open_fds) = metrics::process().await;
        let readings = match &self.db {
            Some(db) => Readings::gather(db).await,
            None => Readings::default(),
        };
        let snap = std::sync::Arc::new(HostSnapshot {
            rss_bytes,
            open_fds,
            readings,
        });
        *cache = Some((Instant::now(), std::sync::Arc::clone(&snap)));
        snap
    }

    /// Whether `alarm` is raised, as of the last pass.
    pub fn active(&self, alarm: Alarm) -> bool {
        let state = self.state.lock().unwrap();
        state.slots.get(alarm.name()).is_some_and(|s| s.active)
    }

    /// The scheduler's call: one pass if a minute has gone by since the last.
    pub async fn tick(&self, pool: &SqlitePool, now: i64) -> Result<Vec<Transition>, sqlx::Error> {
        let Some(db) = &self.db else {
            return Ok(vec![]);
        };
        let due = {
            let state = self.state.lock().unwrap();
            state.last_eval.is_none_or(|t| now - t >= EVERY_SECS)
        };
        if !due {
            return Ok(vec![]);
        }
        self.tick_with(pool, now, &Readings::gather(db).await).await
    }

    /// A pass over `readings` at `now`: the transitions it made, each already written.
    pub async fn tick_with(
        &self,
        pool: &SqlitePool,
        now: i64,
        readings: &Readings,
    ) -> Result<Vec<Transition>, sqlx::Error> {
        let th = Thresholds::load(pool).await?;
        if !self.state.lock().unwrap().restored {
            let mut standing = vec![];
            for alarm in Alarm::ALL {
                standing.push((alarm, standing_from_audit(pool, alarm).await?));
            }
            let mut state = self.state.lock().unwrap();
            for (alarm, (active, at)) in standing {
                let slot = state.slots.entry(alarm.name()).or_default();
                (slot.active, slot.changed_at) = (active, at);
            }
            state.restored = true;
        }
        let mut out = vec![];
        for alarm in Alarm::ALL {
            let Some((breached, value, threshold)) = readings.check(alarm, now, &th) else {
                continue;
            };
            let raised = {
                let mut state = self.state.lock().unwrap();
                let slot = state.slots.entry(alarm.name()).or_default();
                if breached == slot.active {
                    slot.pending_since = None;
                    continue;
                }
                let since = *slot.pending_since.get_or_insert(now);
                // Held back: not long enough yet, or the alarm changed too recently. The
                // reading stays pending, so the change lands once the gap is over.
                if now - since < DEBOUNCE_SECS
                    || slot.changed_at.is_some_and(|t| now - t < MIN_GAP_SECS)
                {
                    continue;
                }
                breached
            };
            let t = Transition {
                alarm,
                raised,
                value,
                threshold,
            };
            write(pool, &t).await?;
            let mut state = self.state.lock().unwrap();
            let slot = state.slots.entry(alarm.name()).or_default();
            (slot.active, slot.pending_since, slot.changed_at) = (raised, None, Some(now));
            out.push(t);
        }
        self.state.lock().unwrap().last_eval = Some(now);
        Ok(out)
    }
}

/// The audit row and the event of a transition, in one write.
async fn write(pool: &SqlitePool, t: &Transition) -> Result<(), sqlx::Error> {
    let action = if t.raised {
        "alarm.raised"
    } else {
        "alarm.cleared"
    };
    let payload = json!({"alarm": t.alarm.name(), "value": t.value, "threshold": t.threshold});
    let mut tx = store::begin_write(pool).await?;
    let row = NewAuditEvent {
        actor: AuditActor::System,
        action: action.to_owned(),
        entity: None,
        details: payload.to_string(),
    };
    audit::append(&mut tx, &row).await?;
    events::append(&mut tx, action, &payload).await?;
    tx.commit().await?;
    tracing::warn!(alarm = t.alarm.name(), raised = t.raised, "alarm");
    Ok(())
}

/// Whether the newest `alarm.*` audit row of `alarm` says raised, and when it was written.
// ponytail: the first pass scans the audit table once per alarm when there is no such row yet;
// an index on action if the chain ever gets large enough for that to matter.
async fn standing_from_audit(
    pool: &SqlitePool,
    alarm: Alarm,
) -> Result<(bool, Option<i64>), sqlx::Error> {
    let last: Option<(String, String)> = sqlx::query_as(
        "SELECT action, at FROM audit_events WHERE action IN ('alarm.raised', 'alarm.cleared') \
         AND json_extract(details, '$.alarm') = ? ORDER BY seq DESC LIMIT 1",
    )
    .bind(alarm.name())
    .fetch_optional(pool)
    .await?;
    Ok(match last {
        Some((action, at)) => (action == "alarm.raised", crate::scheduler::unix_secs(&at)),
        None => (false, None),
    })
}

#[cfg(test)]
mod tests;
