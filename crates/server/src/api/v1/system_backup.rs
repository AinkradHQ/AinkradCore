//! Backups through the root host helper (E2-6): `POST /system/backup` starts one now and
//! `GET /system/backups` reads the schedule, the last run and the backups on disk. The helper
//! classes both like a restart (class A: a fixed argv or a read, rate limited, logged), not like
//! a restore or an update (class B): starting the unit the timer starts anyway changes no data and
//! no access. Nothing the caller sends reaches the helper. The start is audited before the helper
//! is asked (`host.backup_requested`) and after (`host.action_result`), as a restart is.

use axum::Json;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use serde::Serialize;
use serde_json::{Value, json};
use utoipa::ToSchema;

use super::system::{ACTION_RESULT, Fail, audit, fail, internal, outcome, refused};
use super::types::{Timestamp, ts};
use super::{Caller, system};
use crate::api::App;
use crate::host::{Actor, Failure, request_id};
use crate::scheduler::iso_of_unix;

pub const BACKUP_REQUESTED: &str = "host.backup_requested";

#[derive(Debug, Serialize, ToSchema)]
pub struct BackupStarted {
    /// The id the start is audited under (`host.backup_requested`, `host.action_result`).
    pub request_id: String,
}

/// One backup on the host's disk.
#[derive(Debug, Serialize, ToSchema)]
pub struct BackupFile {
    pub at: Timestamp,
    pub bytes: u64,
}

/// The newest run of the backup unit, as systemd says.
#[derive(Debug, Serialize, ToSchema)]
pub struct BackupRun {
    /// `success`, or what systemd calls the failure (`exit-code`, `timeout`…).
    pub result: Option<String>,
    /// Whether a backup is running now.
    pub running: Option<bool>,
    pub started_at: Option<Timestamp>,
    pub finished_at: Option<Timestamp>,
}

/// The backup schedule and history of the Core machine.
#[derive(Debug, Serialize, ToSchema)]
pub struct BackupStatus {
    /// `present` (the host helper answered), `absent` (not installed here) or `error`.
    pub helper: String,
    /// The backup unit is installed.
    pub installed: Option<bool>,
    /// The timer's `OnCalendar` expression (`daily`, `*-*-* 22:00:00`).
    pub schedule: Option<String>,
    /// Whether the timer is armed.
    pub timer_active: Option<bool>,
    /// When the timer fires next; absent when the host's clock zone is not UTC.
    pub next_at: Option<Timestamp>,
    pub last_run: Option<BackupRun>,
    /// The backups on disk, newest first, at most 60.
    pub history: Option<Vec<BackupFile>>,
}

/// A time as systemd prints it (`Fri 2026-11-20 00:12:00 UTC`), in unix seconds. Only UTC is read:
/// any other zone is `None` rather than a wrong time. `n/a` and empty are `None`.
// ponytail: UTC hosts only; ask the helper for `--timestamp=unix` if a Core runs in another zone.
pub fn parse_systemd_utc(text: &str) -> Option<i64> {
    let mut it = text.split_whitespace();
    let (_day, date, time, zone) = (it.next()?, it.next()?, it.next()?, it.next()?);
    if zone != "UTC" || it.next().is_some() {
        return None;
    }
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let mut t = time.split(':').map(|p| p.parse::<i64>().ok());
    let (h, mi, s) = (t.next()??, t.next()??, t.next()??);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3_600 + mi * 60 + s)
}

fn at(secs: i64) -> Timestamp {
    ts(&iso_of_unix(secs))
}

fn word(v: &Value) -> Option<String> {
    v.as_str()
        .filter(|s| !s.is_empty())
        .map(|s| system::plain(s, 64))
}

/// The helper's `backup_info` result as the API's, every string bounded and plain.
pub fn status_of(r: &Value) -> BackupStatus {
    let when = |v: &Value| v.as_str().and_then(parse_systemd_utc).map(at);
    let history = r["history"].as_array().map(|a| {
        a.iter()
            .take(60)
            .filter_map(|e| {
                Some(BackupFile {
                    at: at(i64::try_from(e["at"].as_u64()?).ok()?),
                    bytes: e["bytes"].as_u64()?,
                })
            })
            .collect()
    });
    BackupStatus {
        helper: "present".to_owned(),
        installed: r["installed"].as_bool(),
        schedule: word(&r["timer"]["calendar"]),
        timer_active: r["timer"]["active"].as_str().map(|a| a == "active"),
        next_at: when(&r["timer"]["next"]),
        last_run: r["run"].is_object().then(|| BackupRun {
            result: word(&r["run"]["result"]),
            running: r["run"]["active"]
                .as_str()
                .map(|a| matches!(a, "active" | "activating")),
            started_at: when(&r["run"]["started"]),
            finished_at: when(&r["run"]["finished"]),
        }),
        history,
    }
}

fn empty(helper: &str) -> BackupStatus {
    BackupStatus {
        helper: helper.to_owned(),
        installed: None,
        schedule: None,
        timer_active: None,
        next_at: None,
        last_run: None,
        history: None,
    }
}

#[utoipa::path(get, path = "/api/v1/system/backups", operation_id = "getBackups", tag = "system",
    responses((status = 200, description = "The backup schedule, the last run and the backups on \
        disk, from the host helper. `helper` says whether it answered (`absent`: not installed \
        here; `error`: stopped, busy or failing); the rest is then missing. Needs `admin`",
        body = BackupStatus)))]
pub async fn backups(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> Result<Json<BackupStatus>, Fail> {
    let actor = Actor {
        device: me.device.id.clone(),
        audit_seq: 0,
    };
    match app
        .host_helper
        .call(&request_id(), "backup_info", json!({}), &actor)
        .await
    {
        Ok(r) => Ok(Json(status_of(&r))),
        Err(Failure::Absent) => Ok(Json(empty("absent"))),
        Err(f) => {
            refused(&app, &me, "backup_info", &f).await;
            Ok(Json(empty("error")))
        }
    }
}

#[utoipa::path(post, path = "/api/v1/system/backup", operation_id = "startBackup",
    tag = "system",
    responses((status = 202, description = "A backup is started now (audited first as \
        `host.backup_requested`, then `host.action_result`). It runs on its own; read \
        `getBackups` for its end. Needs `admin`. 409 `not_installed` (no backup unit); 429 with \
        `Retry-After` (the helper's limits: a minute between two, four an hour); 503 \
        `host_helper_unavailable`, `host_helper_busy` or `host_state_unavailable`; 504 \
        `host_helper_timeout`; 502 `host_helper_failed`", body = BackupStarted)))]
pub async fn start(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> Result<(StatusCode, Json<BackupStarted>), Fail> {
    let action = "backup_now";
    let now = u64::try_from(app.clock.unix()).unwrap_or(0);
    if let Some(f) = app.host_helper.blocked(action, now) {
        refused(&app, &me, action, &f).await;
        return Err(fail(f));
    }
    let id = request_id();
    let row = audit(
        &app,
        &me,
        BACKUP_REQUESTED,
        json!({"request_id": id, "by_device": me.device.id}),
    )
    .await
    .map_err(internal)?;
    let actor = Actor {
        device: me.device.id.clone(),
        audit_seq: u64::try_from(row.seq.0).unwrap_or(0),
    };
    let result = app.host_helper.call(&id, action, json!({}), &actor).await;
    let code = match &result {
        Ok(_) => "accepted".to_owned(),
        Err(f) => outcome(f),
    };
    match &result {
        Ok(_) => {
            let why = Failure::Refused {
                code: "rate_limited".into(),
                retry_after: Some(60),
            };
            app.host_helper.block(action, now, 60, why);
        }
        Err(f) => {
            let secs = match f {
                Failure::Refused { code, retry_after } if code == "rate_limited" => {
                    retry_after.unwrap_or(60).clamp(1, 3600)
                }
                _ => 10,
            };
            app.host_helper.block(action, now, secs, f.clone());
        }
    }
    let details = json!({"request_id": id, "action": action, "code": code});
    if let Err(e) = audit(&app, &me, ACTION_RESULT, details).await {
        tracing::error!(error = %e, request_id = id, "auditing a host action result failed");
    }
    match result {
        Ok(_) => Ok((StatusCode::ACCEPTED, Json(BackupStarted { request_id: id }))),
        Err(f) => Err(fail(f)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_utc_times_are_read_and_other_zones_are_not() {
        assert_eq!(
            parse_systemd_utc("Fri 2026-11-20 00:12:00 UTC"),
            Some(1_795_133_520)
        );
        assert_eq!(parse_systemd_utc("Thu 1970-01-01 00:00:01 UTC"), Some(1));
        assert_eq!(parse_systemd_utc("Fri 2026-11-20 00:12:00 EET"), None);
        assert_eq!(parse_systemd_utc("n/a"), None);
        assert_eq!(parse_systemd_utc(""), None);
        assert_eq!(parse_systemd_utc("Fri 2026-13-20 00:12:00 UTC"), None);
    }

    #[test]
    fn the_helpers_answer_becomes_the_status() {
        let s = status_of(&json!({
            "installed": true,
            "timer": {"active": "active", "calendar": "*-*-* 22:00:00",
                      "next": "Fri 2026-11-20 22:00:00 UTC", "last": ""},
            "run": {"active": "inactive", "result": "success",
                    "started": "Thu 2026-11-19 22:00:01 UTC",
                    "finished": "Thu 2026-11-19 22:03:10 UTC", "exit_status": 0},
            "history": [{"at": 1_795_100_000u64, "bytes": 5}, {"at": "bad"}],
        }));
        assert_eq!(s.schedule.as_deref(), Some("*-*-* 22:00:00"));
        assert_eq!(s.timer_active, Some(true));
        assert!(s.next_at.is_some());
        let run = s.last_run.unwrap();
        assert_eq!(
            (run.result.as_deref(), run.running),
            (Some("success"), Some(false))
        );
        assert_eq!(s.history.map(|h| h.len()), Some(1), "a bad row is dropped");
    }
}
