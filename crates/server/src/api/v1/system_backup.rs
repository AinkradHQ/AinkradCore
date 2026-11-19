//! Backups through the root host helper (E2-6): `POST /system/backup` starts one now and
//! `GET /system/backups` reads the schedule, the last run and the backups on disk. The helper
//! classes both like a restart (class A: a fixed argv or a read, rate limited, logged), not like
//! a restore or an update (class B): starting the unit the timer starts anyway changes no data and
//! no access. The retention is not the helper's: the Core writes its own config. The start is audited before the helper
//! is asked (`host.backup_requested`) and after (`host.action_result`), as a restart is.

use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;

use super::ApiError;
use super::system::{ACTION_RESULT, Fail, audit, fail, internal, outcome, refused};
use super::types::{Timestamp, ts};
use super::{Caller, system};
use crate::api::App;
use crate::host::{Actor, Failure, request_id};
use crate::scheduler::iso_of_unix;

pub const BACKUP_REQUESTED: &str = "host.backup_requested";
pub const RETENTION_REQUESTED: &str = "host.backup_retention_requested";
/// The fewest and most local backups the Core may be set to keep.
const KEEP_MIN: u32 = 1;
const KEEP_MAX: u32 = 60;

const KEY: &str = "backup_keep_local";
const CONFIG_MAX: u64 = 64 * 1024;

/// The value of `backup_keep_local = N` on a line (a trailing `# comment` is ignored).
fn keep_of(line: &str) -> Option<Option<u32>> {
    let rest = line.trim_start().strip_prefix(KEY)?;
    let value = rest.trim_start().strip_prefix('=')?;
    Some(value.split('#').next()?.trim().parse().ok())
}

/// `text` with the `backup_keep_local` line set to `keep` (added at the end when there is none);
/// every other line is kept.
fn with_keep(text: &str, keep: u32) -> String {
    let line = format!("{KEY} = {keep}");
    let mut done = false;
    let mut out: Vec<String> = text
        .lines()
        .map(|l| {
            if !done && keep_of(l).is_some() {
                done = true;
                line.clone()
            } else {
                l.to_owned()
            }
        })
        .collect();
    if !done {
        out.push(line);
    }
    out.join("\n") + "\n"
}

/// Sets `backup_keep_local` in the config at `path`: a regular file only (a link is refused), a
/// fresh temp file made exclusively next to it (so a link planted at its name is never followed)
/// with the old file's mode, synced, then renamed over it.
fn write_keep(path: &Path, keep: u32) -> io::Result<()> {
    let old = std::fs::symlink_metadata(path)?;
    if !old.is_file() || old.len() > CONFIG_MAX {
        return Err(io::Error::other("the config is not a regular file"));
    }
    let text = std::fs::read_to_string(path)?;
    let tmp = path.with_file_name("config.toml.keep.tmp");
    let _ = std::fs::remove_file(&tmp);
    let written = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(old.mode() & 0o777)
            .open(&tmp)?;
        f.write_all(with_keep(&text, keep).as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        // The rename is durable only once its folder is: sync it too.
        match path.parent() {
            Some(dir) => std::fs::File::open(dir)?.sync_all(),
            None => Ok(()),
        }
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

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
    /// When the timer fires next, in any clock zone of the host (the helper asks systemd for unix
    /// time); absent when the timer is not armed.
    pub next_at: Option<Timestamp>,
    pub last_run: Option<BackupRun>,
    /// The backups on disk, newest first, at most 60.
    pub history: Option<Vec<BackupFile>>,
    /// How many local backups the Core keeps (`PUT /system/backups/retention` changes it).
    pub keep: Option<u32>,
}

/// How many local backups the Core keeps.
#[derive(Debug, Serialize, ToSchema)]
pub struct BackupRetention {
    /// `present` (the host helper answered), `absent` (not installed here) or `error`.
    pub helper: String,
    /// The backups kept in the Core's backups folder; older ones are removed after each backup.
    pub keep: Option<u32>,
    /// The fewest `PUT` accepts.
    pub min: u32,
    /// The most `PUT` accepts.
    pub max: u32,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetRetention {
    /// 1 to 60.
    pub keep: i64,
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

/// A systemd time: `@<unix seconds>` (what the helper asks for, right in any zone), or the
/// printed UTC form of an older helper.
pub fn parse_systemd_time(text: &str) -> Option<i64> {
    match text.strip_prefix('@') {
        Some(n) => n.parse::<i64>().ok().filter(|n| *n > 0),
        None => parse_systemd_utc(text),
    }
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
    let when = |v: &Value| v.as_str().and_then(parse_systemd_time).map(at);
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
        keep: r["retention"]
            .as_u64()
            .and_then(|k| u32::try_from(k).ok())
            .filter(|k| (KEEP_MIN..=KEEP_MAX).contains(k)),
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
        keep: None,
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

#[utoipa::path(get, path = "/api/v1/system/backups/retention", operation_id = "getBackupRetention",
    tag = "system",
    responses((status = 200, description = "How many local backups the Core keeps, from the host \
        helper (`helper` is `absent` or `error` when it did not answer; `keep` is then missing). \
        Needs `admin`", body = BackupRetention)))]
pub async fn retention(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
) -> Result<Json<BackupRetention>, Fail> {
    let s = backups(State(app), Extension(me)).await?.0;
    Ok(Json(BackupRetention {
        helper: s.helper,
        keep: s.keep,
        min: KEEP_MIN,
        max: KEEP_MAX,
    }))
}

#[utoipa::path(put, path = "/api/v1/system/backups/retention", operation_id = "setBackupRetention",
    tag = "system", request_body = SetRetention,
    responses((status = 200, description = "The Core now keeps this many local backups (audited \
        first as `host.backup_retention_requested`, then `host.action_result`); the Core writes \
        it into its own config and the next backup applies it. Needs `admin` and a step-up. \
        400 for a body other than `{\"keep\": 1..60}`; 409 `not_installed` (no config)",
        body = BackupRetention)))]
pub async fn set_retention(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    body: Bytes,
) -> Result<Json<BackupRetention>, Fail> {
    let keep = serde_json::from_slice::<SetRetention>(&body)
        .ok()
        .and_then(|b| u32::try_from(b.keep).ok())
        .filter(|k| (KEEP_MIN..=KEEP_MAX).contains(k))
        .ok_or_else(|| {
            Fail::from(
                ApiError::bad_request("the body is {\"keep\": a count from 1 to 60}")
                    .into_response(),
            )
        })?;
    let path = app
        .health
        .db_path()
        .and_then(Path::parent)
        .map(|home| home.join("config.toml"));
    let id = request_id();
    audit(
        &app,
        &me,
        RETENTION_REQUESTED,
        json!({"request_id": id, "keep": keep, "by_device": me.device.id}),
    )
    .await
    .map_err(internal)?;
    let result = match &path {
        Some(p) => {
            // Blocking file work (read, write, fsync) stays off the async workers.
            let p = p.clone();
            tokio::task::spawn_blocking(move || write_keep(&p, keep))
                .await
                .unwrap_or_else(|e| Err(io::Error::other(e)))
        }
        None => Err(io::Error::from(io::ErrorKind::NotFound)),
    };
    let code = match &result {
        Ok(()) => "accepted",
        Err(e) if e.kind() == io::ErrorKind::NotFound => "not_installed",
        Err(_) => "failed",
    };
    let details = json!({"request_id": id, "action": "backup_retention", "code": code});
    if let Err(e) = audit(&app, &me, ACTION_RESULT, details).await {
        tracing::error!(error = %e, request_id = id, "auditing a host action result failed");
    }
    match result {
        Ok(()) => Ok(Json(BackupRetention {
            helper: "present".to_owned(),
            keep: Some(keep),
            min: KEEP_MIN,
            max: KEEP_MAX,
        })),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Fail::from(
            ApiError::new(
                StatusCode::CONFLICT,
                "not_installed",
                "the Core has no config file to change",
            )
            .into_response(),
        )),
        Err(e) => {
            tracing::error!(error = %e, "writing the backup retention failed");
            Err(Fail::from(
                ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "the Core could not write its config",
                )
                .into_response(),
            ))
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
    fn every_audit_action_the_backup_and_export_routes_emit_is_declared() {
        use crate::store::kinds::PLATFORM_AUDIT_ACTIONS as A;
        for a in [
            BACKUP_REQUESTED,
            RETENTION_REQUESTED,
            ACTION_RESULT,
            "host.restart_requested",
            "secret.exported",
            "project.defaults_changed",
            "project.unarchived",
            "core.prefs_changed",
        ] {
            assert!(A.contains(&a), "{a} is not in PLATFORM_AUDIT_ACTIONS");
        }
    }

    #[test]
    fn the_keep_line_is_set_and_the_rest_of_the_config_is_kept() {
        let t = "home = \"/x\"\n# keep\nbackup_keep_local = 7 # days\nmodules = []\n";
        assert_eq!(
            with_keep(t, 30),
            "home = \"/x\"\n# keep\nbackup_keep_local = 30\nmodules = []\n"
        );
        assert_eq!(
            with_keep("home = 1", 3),
            "home = 1\nbackup_keep_local = 3\n"
        );
    }

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
    fn unix_times_read_in_any_host_zone() {
        assert_eq!(parse_systemd_time("@1795133520"), Some(1_795_133_520));
        assert_eq!(
            parse_systemd_time("Fri 2026-11-20 00:12:00 UTC"),
            Some(1_795_133_520),
            "an older helper's UTC form still reads"
        );
        for bad in ["@", "@0", "@-5", "@abc", "", "n/a"] {
            assert_eq!(parse_systemd_time(bad), None, "{bad}");
        }
        let s = status_of(&json!({"timer": {"next": "@1795133520"}, "retention": 14}));
        assert!(s.next_at.is_some());
        assert_eq!(s.keep, Some(14));
        assert_eq!(status_of(&json!({"retention": 0})).keep, None);
        assert_eq!(status_of(&json!({"retention": 61})).keep, None);
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
