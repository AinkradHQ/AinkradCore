//! `GET /api/v1/metrics` (E1-13.4): the Core's gauges in Prometheus text format, behind the
//! signed-request gate with scope `admin` (deny by default: `api/v1/scopes.rs`). It is not on the
//! pre-auth listener, and no scrape without a device signature gets an answer.
//!
//! What is allowed in: counts, sizes, ages and sequence numbers. What is not: a device or runner
//! id or name, a path, a terminal's or an agent's content, a key or a secret. Labels carry one
//! of a few fixed words (a state, a status class), so the series count is constant however many
//! devices, runners, terminals or sessions there are.

use std::fmt::Write;
use std::path::Path;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;

use super::{Alarm, Readings};
use crate::api::App;
use crate::store::{events, gov};

/// The Prometheus text exposition content type.
const TEXT: &str = "text/plain; version=0.0.4; charset=utf-8";

/// A text body under construction.
struct Out(String);

impl Out {
    fn head(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.0, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    fn gauge(&mut self, name: &str, help: &str, value: impl std::fmt::Display) {
        self.head(name, "gauge", help);
        let _ = writeln!(self.0, "{name} {value}");
    }

    /// One series per fixed label value.
    fn labelled<V: std::fmt::Display>(
        &mut self,
        name: &str,
        kind: &str,
        help: &str,
        label: &str,
        rows: &[(&str, V)],
    ) {
        self.head(name, kind, help);
        for (value, n) in rows {
            let _ = writeln!(self.0, "{name}{{{label}=\"{value}\"}} {n}");
        }
    }

    fn opt(&mut self, name: &str, help: &str, value: Option<impl std::fmt::Display>) {
        if let Some(v) = value {
            self.gauge(name, help, v);
        }
    }
}

#[utoipa::path(get, path = "/api/v1/metrics", operation_id = "getMetrics", tag = "ops",
    responses((status = 200, description = "Prometheus text format: process, event bus, audit \
        chain, store, backup, certificate, disk, scheduler, runner, terminal, agent and alarm \
        gauges and request counts by status class. No identifiers, names or content.",
        content_type = "text/plain", body = String)))]
pub async fn get(State(app): State<App>) -> impl IntoResponse {
    let body = render(&app).await;
    (
        [
            (header::CONTENT_TYPE, TEXT),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
}

/// The free and total bytes of the filesystem holding `dir`, from `df -Pk` (no `unsafe` and no
/// libc here); `None` where it cannot be read.
pub async fn disk(dir: &Path) -> Option<(u64, u64)> {
    let out = tokio::process::Command::new("df")
        .args(["-Pk"])
        .arg(dir)
        .output()
        .await
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let f: Vec<&str> = text.lines().nth(1)?.split_whitespace().collect();
    let kib = |i: usize| f.get(i)?.parse::<u64>().ok()?.checked_mul(1024);
    Some((kib(3)?, kib(1)?))
}

/// This process's resident memory (bytes) and open file descriptors, where the host says.
async fn process() -> (Option<u64>, Option<u64>) {
    let pid = std::process::id().to_string();
    let rss = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s.lines().find_map(|l| {
            let kb = l.strip_prefix("VmRSS:")?.trim().strip_suffix("kB")?.trim();
            kb.parse::<u64>().ok()
        }),
        Err(_) => {
            let ps = tokio::process::Command::new("ps")
                .args(["-o", "rss=", "-p", &pid])
                .output()
                .await
                .ok();
            ps.and_then(|o| String::from_utf8(o.stdout).ok()?.trim().parse().ok())
        }
    };
    let fds = ["/proc/self/fd", "/dev/fd"]
        .iter()
        .find_map(|d| std::fs::read_dir(d).ok())
        .map(|d| d.count() as u64);
    (rss.map(|kb| kb * 1024), fds)
}

async fn count_by(app: &App, sql: &str) -> Vec<(String, i64)> {
    sqlx::query_as(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_all(&app.pool)
        .await
        .unwrap_or_default()
}

fn tally<'a>(rows: &'a [(String, i64)], states: &[&'a str]) -> Vec<(&'a str, i64)> {
    states
        .iter()
        .map(|s| (*s, rows.iter().find(|r| r.0 == *s).map_or(0, |r| r.1)))
        .collect()
}

/// The whole page.
pub async fn render(app: &App) -> String {
    let now = app.clock.unix();
    let mut o = Out(String::new());
    let h = &app.health;
    o.gauge(
        "ainkrad_uptime_seconds",
        "Seconds since this process started.",
        h.uptime_secs(),
    );
    let (rss, fds) = process().await;
    o.opt(
        "ainkrad_process_resident_memory_bytes",
        "Resident memory of the Core process.",
        rss,
    );
    o.opt(
        "ainkrad_process_open_fds",
        "Open file descriptors of the Core process.",
        fds,
    );

    // Event bus.
    let head = events::last_event_seq(&app.pool).await.unwrap_or(0);
    o.gauge(
        "ainkrad_events_head_seq",
        "Newest event sequence number.",
        head,
    );
    let pushed = gov::push_cursor(&app.pool).await.ok().flatten();
    o.opt(
        "ainkrad_push_cursor_lag_events",
        "Events the notifications service has not read yet (its consumer lag).",
        pushed.map(|c| (head - c).max(0)),
    );

    // Audit chain.
    let audit: Option<(i64, String)> =
        sqlx::query_as("SELECT seq, at FROM audit_events ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&app.pool)
            .await
            .ok()
            .flatten();
    if let Some((seq, at)) = audit {
        o.gauge(
            "ainkrad_audit_head_seq",
            "Newest audit row's sequence number.",
            seq,
        );
        let age = crate::scheduler::unix_secs(&at).map(|t| (now - t).max(0));
        o.opt(
            "ainkrad_audit_head_age_seconds",
            "Seconds since the newest audit row.",
            age,
        );
    }

    // Devices and runners.
    let devices = gov::list_devices(&app.pool).await.unwrap_or_default();
    let active = |kind: &str| {
        devices
            .iter()
            .filter(|d| d.usable() && d.kind == kind)
            .count()
    };
    o.labelled(
        "ainkrad_devices_active",
        "gauge",
        "Paired, unrevoked devices by kind.",
        "kind",
        &[("app", active("device")), ("runner", active("runner"))],
    );
    let runners = app.hub.runners();
    let online = runners.values().filter(|r| r.online).count();
    let degraded = runners.values().filter(|r| r.online && r.degraded).count();
    o.labelled(
        "ainkrad_runners",
        "gauge",
        "Runners the hub knows, by state.",
        "state",
        &[("connected", online), ("degraded", degraded)],
    );
    let loads: Vec<_> = runners.values().filter_map(|r| r.host_load).collect();
    let max_load = loads.iter().map(|l| l.avg1).fold(0.0, f64::max);
    o.gauge(
        "ainkrad_runner_host_load1_max",
        "Highest one-minute load average a runner host reported (0 when none did).",
        max_load,
    );
    o.gauge(
        "ainkrad_runner_host_cores",
        "CPUs the reporting runner hosts have in all.",
        loads.iter().map(|l| u64::from(l.cores)).sum::<u64>(),
    );
    o.gauge(
        "ainkrad_runner_commands_inflight",
        "Commands in flight across all runners.",
        runners.values().map(|r| r.load).sum::<usize>(),
    );

    // Terminals and agent sessions.
    let t = count_by(
        app,
        "SELECT status, count(*) FROM core_terminals GROUP BY status",
    )
    .await;
    let attached = app.terminals.attached_total();
    let running = tally(&t, &["running"])[0].1;
    o.labelled(
        "ainkrad_terminals",
        "gauge",
        "Terminals by state; orphaned is running with no client attached.",
        "state",
        &[
            ("running", running),
            ("exited", tally(&t, &["exited"])[0].1),
            ("orphaned", (running - i64::from(attached.0)).max(0)),
        ],
    );
    o.gauge(
        "ainkrad_terminal_clients_attached",
        "Client attachments to terminals right now.",
        attached.1,
    );
    let per_runner = count_by(
        app,
        "SELECT runner, count(*) FROM core_terminals WHERE status IN ('created', 'running') \
         GROUP BY runner",
    )
    .await;
    o.gauge(
        "ainkrad_terminal_hosting_runners",
        "Runners hosting at least one live terminal.",
        per_runner.len(),
    );
    o.gauge(
        "ainkrad_terminals_per_runner_max",
        "Most live terminals on one runner.",
        per_runner.iter().map(|r| r.1).max().unwrap_or(0),
    );
    let a = count_by(
        app,
        "SELECT state, count(*) FROM core_agent_sessions GROUP BY state",
    )
    .await;
    let states = ["starting", "running", "interrupted", "ended", "lost"];
    o.labelled(
        "ainkrad_agent_sessions",
        "gauge",
        "Agent sessions by state.",
        "state",
        &tally(&a, &states),
    );

    // Store.
    if let Some(db) = app.health.db_path() {
        let size = |p: &Path| std::fs::metadata(p).ok().map(|m| m.len());
        o.opt(
            "ainkrad_db_size_bytes",
            "Size of the database file.",
            size(db),
        );
        let wal = format!("{}-wal", db.display());
        o.opt(
            "ainkrad_db_wal_size_bytes",
            "Size of the write-ahead log.",
            size(Path::new(&wal)).or(Some(0)),
        );
        let r = Readings::gather(db).await;
        o.opt(
            "ainkrad_backup_last_timestamp_seconds",
            "Unix time of the newest local backup.",
            r.backup_at,
        );
        o.opt(
            "ainkrad_backup_age_seconds",
            "Seconds since the newest local backup (since the database was created when none).",
            r.backup_age(now),
        );
        o.gauge(
            "ainkrad_backup_present",
            "1 when a local backup exists, else 0 (a failed backup leaves none).",
            u8::from(r.backup_at.is_some()),
        );
        o.opt(
            "ainkrad_certificate_not_after_seconds",
            "Unix time the public certificate ends.",
            r.cert_not_after,
        );
        o.opt(
            "ainkrad_certificate_days_left",
            "Whole days until the public certificate ends.",
            r.cert_days_left(now),
        );
        o.opt(
            "ainkrad_disk_free_bytes",
            "Free bytes on the data directory's filesystem.",
            r.disk_free_bytes,
        );
        o.opt(
            "ainkrad_disk_free_percent",
            "Free share of the data directory's filesystem.",
            r.disk_free_pct(),
        );
    }

    // Scheduler.
    let lag: Option<i64> = sqlx::query_scalar(
        "SELECT max(strftime('%s', ?1) - strftime('%s', run_at)) FROM core_job_runs \
         WHERE status = 'queued' AND run_at <= ?1",
    )
    .bind(app.clock.now())
    .fetch_one(&app.pool)
    .await
    .ok()
    .flatten();
    o.gauge(
        "ainkrad_jobs_lag_seconds",
        "How long the oldest due job run has waited (0 when none waits).",
        lag.unwrap_or(0).max(0),
    );
    let j = count_by(
        app,
        "SELECT status, count(*) FROM core_job_runs GROUP BY status",
    )
    .await;
    o.labelled(
        "ainkrad_job_runs",
        "gauge",
        "Job runs by status.",
        "status",
        &tally(&j, &["queued", "running", "dead"]),
    );

    // Requests.
    let classes = ["2xx", "3xx", "4xx", "5xx", "other"];
    let counts: Vec<(&str, u64)> = classes
        .iter()
        .zip(&h.request_counts())
        .map(|(c, n)| (*c, *n))
        .collect();
    o.labelled(
        "ainkrad_http_responses_total",
        "counter",
        "Responses by status class.",
        "class",
        &counts,
    );

    // Alarms.
    let rows: Vec<(&str, u8)> = Alarm::ALL
        .iter()
        .map(|a| (a.name(), u8::from(h.active(*a))))
        .collect();
    o.labelled(
        "ainkrad_alarm_active",
        "gauge",
        "1 while the alarm is raised.",
        "alarm",
        &rows,
    );
    o.0
}
