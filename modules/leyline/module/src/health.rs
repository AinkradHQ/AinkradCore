//! Agentless health (Y5-01, plan T8): once a minute every host that may be probed gets ONE fixed,
//! read-only `ssh.exec`; what comes back becomes a sample (up/down, latency, load, memory, disk,
//! failed units). Nothing is installed on a host.
//!
//! Security model.
//! - The prober is the principal `system:health` (`Principal::health`, built only here). Its whole
//!   power is `Action::Probe`, decided by the gate's one table; every probe holds an `Authorized`
//!   from `gate::authorize_many` and is sent only through `exec::probe`, the same path a pre-set
//!   command takes (lease per hop, pinned keys, `gate::checked` right before dispatch). Health can
//!   never trust or replace a host key, and runs no text but the constant `PROBE`.
//! - A host whose key (or any jump hop's) has no TRUSTED host key is not probed at all, and a runner
//!   that answers `host_key_unknown` / `host_key_changed` records nothing: "we could not verify the
//!   host" is never "the host is down" (a changed key raises the `host_key_changed` alert, `hostkeys::saw`).
//! - Only a failed connect (or a probe that timed out) is DOWN. A runner that is away, busy or too
//!   old, or a refused run, records nothing either.
//! - At most `PER_RUNNER` probes are in flight per runner (the Core's small box is the relay).
//! - What is stored is numbers and the `os` fact (`linux`/`darwin`/`other`): no remote text.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiResult;
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Missed, Run, Schedule};
use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_core_server::store::begin_write;
use ainkrad_proto::v2::{Body, ErrorCode, Reply};
use axum::Json;
use axum::extract::{Path, State};
use sqlx::{Row, SqlitePool};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::alerts;
use crate::exec;
use crate::gate::{Action, Authorized, Principal, authorize_many, checked, finish};
use crate::hostkeys;

/// Probes in flight on one runner.
const PER_RUNNER: usize = 4;
/// A host that does not answer a probe in this long is down.
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// The gate takes at most this many hosts per call.
const BATCH: usize = 100;
/// Raw samples are kept this long, then averaged into `ROLL`-second buckets.
const RAW_SECS: i64 = 86_400;
const ROLL: i64 = 300;
/// Averaged samples are kept this long.
const KEEP_SECS: i64 = 30 * 86_400;

/// The one command a probe sends. `sh -c` so a fish or csh login shell parses nothing of it; no
/// single quote inside; every section is marked so the parser never guesses. `df` has no `-x`
/// (busybox); `systemctl` is asked only where systemd runs.
const PROBE: &str = r#"sh -c 'echo "@uname"; uname -s; echo "@load"; cat /proc/loadavg 2>/dev/null; echo "@cpus"; nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo 2>/dev/null; echo "@mem"; grep -E "^(MemTotal|MemAvailable):" /proc/meminfo 2>/dev/null; echo "@disk"; df -P 2>/dev/null; if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then echo "@units"; systemctl --failed --no-legend --plain 2>/dev/null; fi; true'"#;

/// What one probe's output says. `None` = not reported (not Linux, or that part missing).
#[derive(Debug, Default, PartialEq)]
pub(crate) struct Facts {
    pub(crate) os: Option<&'static str>,
    pub(crate) load1: Option<f64>,
    pub(crate) cpus: Option<i64>,
    pub(crate) mem_pct: Option<f64>,
    pub(crate) disk_pct: Option<f64>,
    pub(crate) failed_units: Option<i64>,
}

fn r1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// Reads a probe's stdout. Never fails: what it cannot read stays `None`. Lines before the first
/// marker (a login banner, a locale warning) are ignored; only Linux reports numbers.
pub(crate) fn parse(out: &str) -> Facts {
    const NAMES: [&str; 6] = ["uname", "load", "cpus", "mem", "disk", "units"];
    let mut sec: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut cur: Option<&str> = None;
    for line in out.lines() {
        let line = line.trim_end();
        match line.strip_prefix('@').filter(|n| NAMES.contains(n)) {
            Some(n) => {
                cur = Some(n);
                sec.entry(n).or_default();
            }
            None => {
                if let Some(c) = cur {
                    sec.entry(c).or_default().push(line);
                }
            }
        }
    }
    let first = |n: &str| {
        sec.get(n)
            .and_then(|l| l.iter().find(|x| !x.trim().is_empty()))
            .map(|x| x.trim())
    };
    let os = first("uname").map(|u| match u {
        "Linux" => "linux",
        "Darwin" => "darwin",
        _ => "other",
    });
    let mut f = Facts {
        os,
        ..Facts::default()
    };
    if os != Some("linux") {
        return f;
    }
    f.load1 = first("load")
        .and_then(|l| l.split_whitespace().next())
        .and_then(|t| t.parse::<f64>().ok())
        .filter(|x| x.is_finite() && *x >= 0.0);
    f.cpus = first("cpus")
        .and_then(|c| c.parse::<i64>().ok())
        .filter(|c| *c >= 1);
    let kb = |key: &str| {
        sec.get("mem")?.iter().find_map(|l| {
            let rest = l.strip_prefix(key)?.strip_prefix(':')?;
            rest.split_whitespace().next()?.parse::<f64>().ok()
        })
    };
    if let (Some(total), Some(avail)) = (kb("MemTotal"), kb("MemAvailable"))
        && total > 0.0
    {
        f.mem_pct = Some(r1((100.0 * (1.0 - avail / total)).clamp(0.0, 100.0)));
    }
    // The fullest real disk: devices only (not tmpfs/overlay/shm), no snap loop images.
    f.disk_pct = sec
        .get("disk")
        .into_iter()
        .flatten()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            let real = t.len() >= 6
                && t[0].starts_with('/')
                && !t[0].starts_with("/dev/loop")
                && !t[5].starts_with("/snap");
            if !real {
                return None;
            }
            t[4].strip_suffix('%')?.parse::<f64>().ok()
        })
        .reduce(f64::max);
    f.failed_units = sec.get("units").map(|l| {
        i64::try_from(l.iter().filter(|x| !x.trim().is_empty()).count()).unwrap_or(i64::MAX)
    });
    f
}

/// A host row as far as "may it be probed" needs.
pub(crate) struct Row0 {
    pub(crate) id: String,
    pub(crate) on: bool,
    pub(crate) has_key: bool,
    pub(crate) chain: Vec<String>,
}

/// The hosts to probe now: health on, a key, and a TRUSTED host key for the host and every hop
/// (and every hop has a key). An unknown key is "not probed", never "down".
pub(crate) fn due(rows: &[Row0], trusted: &HashSet<String>) -> Vec<String> {
    let ready = |id: &str| trusted.contains(id) && rows.iter().any(|r| r.id == id && r.has_key);
    rows.iter()
        .filter(|r| r.on && ready(&r.id) && r.chain.iter().all(|h| ready(h)))
        .map(|r| r.id.clone())
        .collect()
}

async fn due_now(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    let mut rows = Vec::new();
    for r in sqlx::query("SELECT id, health, key_id, jump_chain FROM leyline_hosts")
        .fetch_all(pool)
        .await?
    {
        rows.push(Row0 {
            id: r.try_get("id")?,
            on: r.try_get::<i64, _>("health")? == 1,
            has_key: r.try_get::<Option<String>, _>("key_id")?.is_some(),
            chain: serde_json::from_str(&r.try_get::<String, _>("jump_chain")?).unwrap_or_default(),
        });
    }
    let trusted: HashSet<String> = sqlx::query_scalar(
        "SELECT DISTINCT host_id FROM leyline_host_keys WHERE state = 'trusted'",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();
    Ok(due(&rows, &trusted))
}

/// One semaphore per runner: the cap on probes in flight there.
#[derive(Clone, Default)]
pub(crate) struct Limits(Arc<Mutex<HashMap<String, Arc<Semaphore>>>>);

impl Limits {
    fn of(&self, runner: &str) -> Arc<Semaphore> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(runner.to_owned())
            .or_insert_with(|| Arc::new(Semaphore::new(PER_RUNNER)))
            .clone()
    }
}

/// What one probe found out.
enum Seen {
    Up(Facts, i64),
    Down,
    /// Nothing can be said (host not verified, runner away, refused): record nothing.
    Unknown,
}

async fn measure(app: &App, limits: &Limits, auth: &Authorized) -> Seen {
    // The runner is read from the gate's check, to queue behind it; the probe itself is built from a
    // second `checked` taken after the wait, and dispatched from that very read (nothing re-read).
    let Ok(first) = checked(app, auth).await else {
        return Seen::Unknown;
    };
    let Ok(_permit) = limits.of(&first.runner).acquire_owned().await else {
        return Seen::Unknown;
    };
    let Ok(link) = checked(app, auth).await else {
        return Seen::Unknown;
    };
    // The host ids along the path, in dialling order (jump hosts, then the target): a runner names a
    // hop by its position, never by an id.
    let path: Vec<String> = link
        .hops
        .iter()
        .chain([&link.target])
        .map(|s| s.id.clone())
        .collect();
    let Ok(sent) = exec::probe(app, auth, PROBE, PROBE_TIMEOUT, link).await else {
        return Seen::Unknown;
    };
    let t = Instant::now();
    let answer = sent.outcome().await;
    let ms = i64::try_from(t.elapsed().as_millis()).unwrap_or(i64::MAX);
    match answer {
        Ok(Body::Result(Reply::SshExec(r))) if r.timed_out => Seen::Down,
        Ok(Body::Result(Reply::SshExec(r))) => Seen::Up(parse(&r.stdout.text), ms),
        // The host answered the connection but refused the key: it is up.
        Err(e) if e.code == ErrorCode::SshAuthFailed => Seen::Up(Facts::default(), ms),
        Err(e) if e.code == ErrorCode::SshFailed => Seen::Down,
        // Not down, not a sample: the host (or a jump hop) presented another key. The hop's own
        // host id is alerted, and `saw` stores the fingerprint for a person to compare.
        Err(e) if e.code == ErrorCode::HostKeyChanged => {
            if let Some(k) = e
                .host_key
                .filter(|k| hostkeys::fingerprint_ok(&k.fingerprint))
                && let Some(id) = path.get(usize::from(k.hop))
                && let Err(err) = hostkeys::saw(app, id, &k.fingerprint, true).await
            {
                tracing::error!(error = %err.message, "recording a changed host key failed");
            }
            Seen::Unknown
        }
        _ => Seen::Unknown,
    }
}

async fn store(app: &App, host: &str, seen: &Seen) -> Result<(), sqlx::Error> {
    let at = app.clock.unix();
    let (up, ms, f) = match seen {
        Seen::Up(f, ms) => (1_i64, Some(*ms), Some(f)),
        Seen::Down => (0, None, None),
        Seen::Unknown => return Ok(()),
    };
    let none = Facts::default();
    let f = f.unwrap_or(&none);
    sqlx::query(
        "INSERT OR REPLACE INTO leyline_health_samples \
         (host_id, at, up, latency_ms, load1, cpus, mem_pct, disk_pct, failed_units) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(host)
    .bind(at)
    .bind(up)
    .bind(ms)
    .bind(f.load1)
    .bind(f.cpus)
    .bind(f.mem_pct)
    .bind(f.disk_pct)
    .bind(f.failed_units)
    .execute(&app.pool)
    .await?;
    if let Some(os) = f.os {
        sqlx::query("UPDATE leyline_hosts SET os = ? WHERE id = ? AND os IS NOT ?")
            .bind(os)
            .bind(host)
            .bind(os)
            .execute(&app.pool)
            .await?;
    }
    Ok(())
}

async fn probe(app: App, limits: Limits, auth: Authorized) {
    let seen = measure(&app, &limits, &auth).await;
    if let Err(e) = store(&app, auth.host_id(), &seen).await {
        tracing::error!(error = %e, "storing a leyline health sample failed");
    } else if !matches!(seen, Seen::Unknown)
        && let Err(e) = alerts::evaluate(&app, auth.host_id()).await
    {
        tracing::error!(error = %e, "evaluating leyline health alerts failed");
    }
    let ok = matches!(seen, Seen::Up(..));
    if let Err(e) = finish(&app, auth, ok).await {
        tracing::error!(error = %e.message, "closing a leyline probe run failed");
    }
}

/// One round: every due host, `BATCH` per gated run, all probes of a batch at once (each waits for
/// its runner's slot).
async fn tick(app: &App, limits: &Limits) -> Result<(), String> {
    let ids = due_now(&app.pool)
        .await
        .map_err(|_| "the hosts cannot be read".to_owned())?;
    for batch in ids.chunks(BATCH) {
        let hosts: Vec<&str> = batch.iter().map(String::as_str).collect();
        let gated = authorize_many(app, &Principal::health(), &hosts, &Action::Probe)
            .await
            .map_err(|e| e.message)?;
        let mut set = JoinSet::new();
        for auth in gated.authorized {
            set.spawn(probe(app.clone(), limits.clone(), auth));
        }
        while set.join_next().await.is_some() {}
    }
    Ok(())
}

/// Moves raw samples older than a day into 5-minute averages, drops averages older than 30 days and
/// the samples of hosts that no longer exist. Buckets are cut at a `ROLL` boundary, so one is never
/// averaged half-way.
pub(crate) async fn rollup(pool: &SqlitePool, now: i64) -> Result<(), sqlx::Error> {
    let cutoff = (now - RAW_SECS) / ROLL * ROLL;
    type Avg = (
        String,
        i64,
        i64,
        Option<i64>,
        Option<f64>,
        Option<i64>,
        Option<f64>,
        Option<f64>,
        Option<i64>,
    );
    let mut tx = begin_write(pool).await?;
    let avgs: Vec<Avg> = sqlx::query_as(
        "SELECT host_id, at - at % ?1, CAST(AVG(up) + 0.5 AS INTEGER), CAST(AVG(latency_ms) AS INTEGER), \
         AVG(load1), MAX(cpus), AVG(mem_pct), AVG(disk_pct), MAX(failed_units) \
         FROM leyline_health_samples WHERE rolled = 0 AND at < ?2 GROUP BY host_id, at - at % ?1",
    )
    .bind(ROLL)
    .bind(cutoff)
    .fetch_all(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM leyline_health_samples WHERE rolled = 0 AND at < ?")
        .bind(cutoff)
        .execute(&mut *tx)
        .await?;
    for a in avgs {
        sqlx::query(
            "INSERT OR REPLACE INTO leyline_health_samples \
             (host_id, at, up, latency_ms, load1, cpus, mem_pct, disk_pct, failed_units, rolled) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
        )
        .bind(a.0)
        .bind(a.1)
        .bind(a.2)
        .bind(a.3)
        .bind(a.4)
        .bind(a.5)
        .bind(a.6.map(r1))
        .bind(a.7.map(r1))
        .bind(a.8)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM leyline_health_samples WHERE rolled = 1 AND at < ?")
        .bind(now - KEEP_SECS)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM leyline_health_samples WHERE host_id NOT IN (SELECT id FROM leyline_hosts)",
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

/// The gate writes one run per round for the prober; a day of them is plenty.
async fn sweep_runs(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM leyline_runs WHERE principal = 'system:health' \
         AND created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')",
    )
    .execute(pool)
    .await?;
    // Alerts of a host that is gone have nothing left to resolve them.
    sqlx::query("DELETE FROM leyline_alerts WHERE host_id NOT IN (SELECT id FROM leyline_hosts)")
        .execute(pool)
        .await?;
    Ok(())
}

// ponytail: the module is a unit struct (the tests and the binary build `Leyline` bare), so the
// app the jobs run on is a process-wide cell, set once by `attach`. One app per process in practice;
// make `Leyline` carry an `Arc<OnceLock<App>>` like Lore if a test ever needs two servers' jobs.
static APP: OnceLock<App> = OnceLock::new();

/// The app the jobs run on, once attached.
pub(crate) fn app() -> Option<&'static App> {
    APP.get()
}

pub(crate) fn attach(app: &App) {
    let _ = APP.set(app.clone());
}

struct Probes(Limits);
struct Rollup;

impl JobHandler for Probes {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let app = APP.get().ok_or("the leyline module is not attached")?;
            tick(app, &self.0).await?;
            // A round every minute: not worth an audit row each (a failure always is).
            run.idle();
            Ok(())
        })
    }
}

impl JobHandler for Rollup {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let app = APP.get().ok_or("the leyline module is not attached")?;
            let err = |_| "the health samples cannot be rolled up".to_owned();
            rollup(&app.pool, app.clock.unix()).await.map_err(err)?;
            sweep_runs(&app.pool).await.map_err(err)?;
            run.idle();
            Ok(())
        })
    }
}

/// The module's jobs: a probe round every 60 s and an hourly rollup. A missed round is skipped,
/// never caught up (a late probe says nothing about now).
// ponytail: the cadence is fixed at 60 s; the plan's 30-600 s setting arrives with the settings UI.
pub(crate) fn jobs() -> Vec<Job> {
    let skip = |job: Job| Job {
        missed: Missed::Skip,
        ..job
    };
    vec![
        skip(Job::new(
            "probe",
            Schedule::Every(60),
            Arc::new(Probes(Limits::default())),
        )),
        skip(Job::new("rollup", Schedule::Every(3600), Arc::new(Rollup))),
    ]
}

/// The newest sample is "now" for this long; after it the host's state is unknown.
const FRESH_SECS: i64 = 300;
/// Samples the host page draws as its sparklines.
const SERIES: i64 = 30;

/// One point of the host page's sparklines.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct HealthPoint {
    pub load1: Option<f64>,
    pub cpus: Option<i64>,
    pub mem_pct: Option<f64>,
    pub disk_pct: Option<f64>,
}

/// A host's latest health and its last samples (numbers only: no remote text).
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct HealthView {
    /// `up`, `down`, or `unknown` (never probed, not verifiable, or the newest sample is old).
    pub state: String,
    pub checked_at: Option<String>,
    pub load1: Option<f64>,
    pub cpus: Option<i64>,
    pub mem_pct: Option<f64>,
    pub disk_pct: Option<f64>,
    pub failed_units: Option<i64>,
    /// Oldest first.
    pub history: Vec<HealthPoint>,
}

#[utoipa::path(get, path = "/hosts/{host}/health", operation_id = "leylineHostHealth", tag = "leyline",
    params(("host" = String, Path, description = "Host id, else its unique label")),
    responses((status = 200, description = "The stored samples of the host's last probes; reads the table, probes nothing", body = HealthView)))]
pub(crate) async fn read(
    State(app): State<App>,
    Path(host): Path<String>,
) -> ApiResult<HealthView> {
    let id = {
        let mut conn = app.pool.acquire().await?;
        crate::hosts::find(&mut conn, &host).await?
    };
    let rows = sqlx::query(
        "SELECT at, up, load1, cpus, mem_pct, disk_pct, failed_units FROM leyline_health_samples \
         WHERE host_id = ? ORDER BY at DESC LIMIT ?",
    )
    .bind(&id)
    .bind(SERIES)
    .fetch_all(&app.pool)
    .await?;
    let point = |r: &sqlx::sqlite::SqliteRow| HealthPoint {
        load1: r.get("load1"),
        cpus: r.get("cpus"),
        mem_pct: r.get("mem_pct"),
        disk_pct: r.get("disk_pct"),
    };
    let mut out = HealthView {
        state: "unknown".to_owned(),
        checked_at: None,
        load1: None,
        cpus: None,
        mem_pct: None,
        disk_pct: None,
        failed_units: None,
        history: rows.iter().rev().map(point).collect(),
    };
    if let Some(r) = rows.first() {
        let at: i64 = r.get("at");
        out.checked_at = Some(iso_of_unix(at));
        if app.clock.unix() - at <= FRESH_SECS {
            out.state = if r.get::<i64, _>("up") == 1 {
                "up"
            } else {
                "down"
            }
            .to_owned();
        }
        out.load1 = r.get("load1");
        out.cpus = r.get("cpus");
        out.mem_pct = r.get("mem_pct");
        out.disk_pct = r.get("disk_pct");
        out.failed_units = r.get("failed_units");
    }
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    const DEBIAN: &str = include_str!("../tests/health/debian.txt");
    const ALPINE: &str = include_str!("../tests/health/alpine.txt");
    const NO_SYSTEMD: &str = include_str!("../tests/health/nosystemd.txt");
    const MACOS: &str = include_str!("../tests/health/macos.txt");
    const GARBAGE: &str = include_str!("../tests/health/garbage.txt");

    #[test]
    fn debian() {
        // The snap loop image (100 %) and tmpfs are not disks; the fullest real one counts.
        assert_eq!(
            parse(DEBIAN),
            Facts {
                os: Some("linux"),
                load1: Some(0.52),
                cpus: Some(4),
                mem_pct: Some(75.0),
                disk_pct: Some(92.0),
                failed_units: Some(2),
            }
        );
    }

    #[test]
    fn alpine_busybox() {
        // No systemd: the failed-units count is "not reported", not zero. Overlay is not a disk.
        assert_eq!(
            parse(ALPINE),
            Facts {
                os: Some("linux"),
                load1: Some(1.2),
                cpus: Some(2),
                mem_pct: Some(50.0),
                disk_pct: Some(26.0),
                failed_units: None,
            }
        );
    }

    #[test]
    fn linux_without_systemd() {
        assert_eq!(
            parse(NO_SYSTEMD),
            Facts {
                os: Some("linux"),
                load1: Some(0.0),
                cpus: Some(1),
                mem_pct: Some(80.0),
                disk_pct: Some(43.0),
                failed_units: None,
            }
        );
    }

    #[test]
    fn macos_is_up_down_only() {
        assert_eq!(
            parse(MACOS),
            Facts {
                os: Some("darwin"),
                ..Facts::default()
            }
        );
    }

    #[test]
    fn unreadable_output_reports_nothing() {
        assert_eq!(parse(GARBAGE), Facts::default());
        assert_eq!(parse(""), Facts::default());
        // A banner before the markers and a marker with nothing under it do not break the rest.
        let f = parse("Welcome\n@uname\nLinux\n@load\n@cpus\nlots\n");
        assert_eq!(f.os, Some("linux"));
        assert_eq!(
            (f.load1, f.cpus, f.mem_pct, f.disk_pct),
            (None, None, None, None)
        );
    }

    #[test]
    fn the_probe_is_one_quote_balanced_read_only_line() {
        assert!(!PROBE.contains('\n'));
        assert_eq!(PROBE.matches('\'').count(), 2);
        for bad in ["rm ", "sudo", ">>", "kill", "tee "] {
            assert!(!PROBE.contains(bad), "{bad}");
        }
    }

    fn row(id: &str, on: bool, key: bool, chain: &[&str]) -> Row0 {
        Row0 {
            id: id.into(),
            on,
            has_key: key,
            chain: chain.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    #[test]
    fn only_verified_hosts_are_probed() {
        let rows = [
            row("h_ok", true, true, &[]),
            row("h_unknown", true, true, &[]),
            row("h_off", false, true, &[]),
            row("h_nokey", true, false, &[]),
            row("h_hop", true, true, &["h_ok"]),
            row("h_badhop", true, true, &["h_unknown"]),
            row("h_ghost", true, true, &["h_gone"]),
        ];
        let trusted: HashSet<String> = ["h_ok", "h_off", "h_nokey", "h_hop", "h_badhop", "h_ghost"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(due(&rows, &trusted), ["h_ok", "h_hop"]);
    }

    #[tokio::test]
    async fn at_most_four_in_flight_per_runner() {
        let l = Limits::default();
        let a = l.of("d_a");
        let held: Vec<_> = (0..PER_RUNNER)
            .map(|_| a.clone().try_acquire_owned().unwrap())
            .collect();
        assert!(
            a.clone().try_acquire_owned().is_err(),
            "a fifth probe waits"
        );
        // Another runner has its own slots; the same runner shares one set.
        assert!(l.of("d_b").try_acquire_owned().is_ok());
        assert!(l.of("d_a").try_acquire_owned().is_err());
        drop(held);
        assert!(l.of("d_a").try_acquire_owned().is_ok());
    }

    async fn pool() -> SqlitePool {
        let p = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        for sql in [
            "CREATE TABLE leyline_hosts (id TEXT)",
            include_str!("../migrations/0005_health.up.sql"),
            "INSERT INTO leyline_hosts (id) VALUES ('h_1')",
        ] {
            sqlx::query(sql).execute(&p).await.unwrap();
        }
        p
    }

    async fn put(p: &SqlitePool, host: &str, at: i64, up: i64, load: f64, rolled: i64) {
        sqlx::query(
            "INSERT INTO leyline_health_samples (host_id, at, up, load1, rolled) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(host)
        .bind(at)
        .bind(up)
        .bind(load)
        .bind(rolled)
        .execute(p)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn rollup_averages_old_samples_and_prunes() {
        let p = pool().await;
        let now = 100 * 86_400;
        let old = now - 2 * 86_400;
        let b = old / ROLL * ROLL;
        // Five old minutes of one bucket (one down), one fresh sample, one very old average,
        // and one sample of a host that is gone.
        for (i, up) in [1, 1, 1, 1, 0].into_iter().enumerate() {
            put(&p, "h_1", b + 60 * i as i64, up, 1.0 + i as f64, 0).await;
        }
        put(&p, "h_1", now - 60, 1, 9.0, 0).await;
        put(&p, "h_1", now - 40 * 86_400, 1, 1.0, 1).await;
        put(&p, "h_gone", old, 1, 1.0, 0).await;
        rollup(&p, now).await.unwrap();
        let rows: Vec<(i64, i64, f64, i64)> =
            sqlx::query_as("SELECT at, up, load1, rolled FROM leyline_health_samples ORDER BY at")
                .fetch_all(&p)
                .await
                .unwrap();
        // The old average and the gone host are pruned; the bucket is one row (4 of 5 up = up,
        // load 3.0); the fresh raw sample is untouched.
        assert_eq!(rows, [(b, 1, 3.0, 1), (now - 60, 1, 9.0, 0)]);
        // A second pass changes nothing.
        rollup(&p, now).await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM leyline_health_samples")
            .fetch_one(&p)
            .await
            .unwrap();
        assert_eq!(n, 2);
    }
}
