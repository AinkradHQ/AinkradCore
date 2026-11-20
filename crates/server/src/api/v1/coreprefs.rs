//! The Core's own preferences, storage and update status for the App's Settings, Core page
//! (Core 0.10, E2-3): its name, whether it may send crash reports, the automatic-update choice
//! and the hour an update installs, how much disk each kind of data uses, and a "check now" for
//! updates. Preferences live in the settings table under `core.pref.*` (strings, so outside the
//! integer registry that `/api/v1/settings` lists).
//!
//! The update choice and hour are only stored here: installing an update is E12's, and there is
//! no release feed yet, so `check` records that it looked and says the feed is unavailable.
//! ponytail: backup schedule, retention and "back up now" are the host's backup timer and the
//! root-owned helper (`system::host`); the Core cannot start or change them, so they are not here.

use std::path::Path;

use ainkrad_core::audit::NewAuditEvent;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqliteConnection;
use utoipa::ToSchema;

use super::types::{Timestamp, ts};
use super::{ApiError, ApiResult, BY};
use crate::api::App;
use crate::store::{self, audit};

const NAME: &str = "core.pref.name";
const CRASH: &str = "core.pref.crash_reports";
const AUTO: &str = "core.pref.auto_update";
const HOUR: &str = "core.pref.update_hour";
const CHECKED: &str = "core.pref.update_checked_at";
/// The hour (Core's local time) an update installs when none is set.
const DEFAULT_HOUR: i64 = 3;
const NAME_MAX: usize = 64;

/// What this Core is called and how it treats crash reports and updates.
#[derive(Debug, Serialize, ToSchema)]
pub struct CorePrefs {
    /// How this Core shows up on devices; absent until one is set.
    #[schema(required = false)]
    pub name: Option<String>,
    /// Whether anonymous crash reports may be sent. Off until turned on.
    #[schema(required = false)]
    pub crash_reports: Option<bool>,
    /// Whether the Core, runners and app update by themselves. On until turned off.
    #[schema(required = false)]
    pub auto_update: Option<bool>,
    /// The hour, 0 to 23, an automatic update installs at.
    #[schema(required = false)]
    pub update_hour: Option<i64>,
    /// When "check now" last ran.
    #[schema(required = false)]
    pub update_checked_at: Option<Timestamp>,
}

/// The preferences to change; a field left out stays as it is.
#[derive(Debug, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetCorePrefs {
    pub name: Option<String>,
    pub crash_reports: Option<bool>,
    pub auto_update: Option<bool>,
    pub update_hour: Option<i64>,
}

/// The settings column holds JSON (`json_valid`), so a preference is stored as a JSON string and read back as the text.
async fn read(conn: &mut SqliteConnection, key: &str) -> Result<Option<String>, sqlx::Error> {
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT value FROM settings WHERE key = ? AND scope_kind = 'server' AND scope_id = 0",
    )
    .bind(key)
    .fetch_optional(conn)
    .await?;
    Ok(raw.map(|v| serde_json::from_str::<String>(&v).unwrap_or(v)))
}

async fn write(
    conn: &mut SqliteConnection,
    key: &str,
    value: &str,
    now: &str,
) -> Result<(), sqlx::Error> {
    let (by_kind, by_id) = BY.parts();
    sqlx::query(
        "INSERT INTO settings (key, scope_kind, scope_id, value, updated_by_kind, updated_by_id, \
         updated_at) VALUES (?, 'server', 0, ?, ?, ?, ?) \
         ON CONFLICT (key, scope_kind, scope_id) DO UPDATE SET value = excluded.value, \
         updated_by_kind = excluded.updated_by_kind, updated_by_id = excluded.updated_by_id, \
         updated_at = excluded.updated_at",
    )
    .bind(key)
    .bind(serde_json::to_string(value).expect("a string is JSON"))
    .bind(by_kind)
    .bind(by_id)
    .bind(now)
    .execute(conn)
    .await?;
    Ok(())
}

async fn prefs(conn: &mut SqliteConnection) -> Result<CorePrefs, sqlx::Error> {
    let flag = |v: Option<String>, default: bool| Some(v.map_or(default, |v| v == "1"));
    Ok(CorePrefs {
        name: read(conn, NAME).await?.filter(|n| !n.is_empty()),
        crash_reports: flag(read(conn, CRASH).await?, false),
        auto_update: flag(read(conn, AUTO).await?, true),
        update_hour: Some(
            read(conn, HOUR)
                .await?
                .and_then(|h| h.parse().ok())
                .filter(|h| (0..24).contains(h))
                .unwrap_or(DEFAULT_HOUR),
        ),
        update_checked_at: read(conn, CHECKED).await?.map(|t| ts(&t)),
    })
}

/// A name that fits on a device list: trimmed, 1 to 64 characters, no control characters.
fn clean_name(raw: &str) -> Result<String, ApiError> {
    let name = raw.trim();
    if name.is_empty() || name.chars().count() > NAME_MAX || name.chars().any(char::is_control) {
        return Err(ApiError::bad_request(format!(
            "the name is 1 to {NAME_MAX} characters, with no control characters"
        )));
    }
    Ok(name.to_owned())
}

#[utoipa::path(get, path = "/api/v1/core/prefs", operation_id = "getCorePrefs", tag = "system",
    responses((status = 200, description = "The Core's name, crash-report choice and update \
        choice. Needs `read`", body = CorePrefs)))]
pub async fn get(State(app): State<App>) -> ApiResult<CorePrefs> {
    let mut conn = app.pool.acquire().await?;
    Ok(Json(prefs(&mut conn).await?))
}

#[utoipa::path(put, path = "/api/v1/core/prefs", operation_id = "setCorePrefs", tag = "system",
    request_body = SetCorePrefs,
    responses((status = 200, description = "Changed (audited as `core.prefs_changed`); the \
        preferences now. 400 for a name that is empty, over 64 characters or has control \
        characters, or an hour outside 0 to 23. Needs `admin`", body = CorePrefs)))]
pub async fn put(State(app): State<App>, Json(body): Json<SetCorePrefs>) -> ApiResult<CorePrefs> {
    let name = body.name.as_deref().map(clean_name).transpose()?;
    if body.update_hour.is_some_and(|h| !(0..24).contains(&h)) {
        return Err(ApiError::bad_request("the update hour is 0 to 23"));
    }
    let now = app.clock.now();
    let mut tx = store::begin_write(&app.pool).await?;
    let before = prefs(&mut tx).await?;
    let mut changed = Vec::new();
    if let Some(n) = &name {
        write(&mut tx, NAME, n, &now).await?;
        changed.push("name");
    }
    let flag = |b: bool| if b { "1" } else { "0" };
    if let Some(b) = body.crash_reports {
        write(&mut tx, CRASH, flag(b), &now).await?;
        changed.push("crash_reports");
    }
    if let Some(b) = body.auto_update {
        write(&mut tx, AUTO, flag(b), &now).await?;
        changed.push("auto_update");
    }
    if let Some(h) = body.update_hour {
        write(&mut tx, HOUR, &h.to_string(), &now).await?;
        changed.push("update_hour");
    }
    if !changed.is_empty() {
        let event = NewAuditEvent {
            actor: BY,
            action: "core.prefs_changed".to_owned(),
            entity: None,
            details: json!({"changed": changed, "old_name": before.name, "at": now}).to_string(),
        };
        audit::append(&mut tx, &event).await?;
    }
    let after = prefs(&mut tx).await?;
    tx.commit().await?;
    Ok(Json(after))
}

/// What the update check found.
#[derive(Debug, Serialize, ToSchema)]
pub struct UpdateCheck {
    /// When the check ran.
    pub checked_at: Timestamp,
    /// The version this Core runs.
    pub current_version: String,
    /// A newer version, when a feed says so.
    #[schema(required = false)]
    pub latest_version: Option<String>,
    /// `feed_unavailable`: no release feed is set up on this Core yet, so nothing was compared.
    pub status: String,
}

#[utoipa::path(post, path = "/api/v1/core/update/check", operation_id = "checkCoreUpdate",
    tag = "system",
    responses((status = 200, description = "Records that a check ran. Until a release feed \
        exists (E12) the status is `feed_unavailable` and no version is compared. Needs `admin`",
        body = UpdateCheck)))]
pub async fn check_update(State(app): State<App>) -> ApiResult<UpdateCheck> {
    let now = app.clock.now();
    let mut tx = store::begin_write(&app.pool).await?;
    write(&mut tx, CHECKED, &now, &now).await?;
    tx.commit().await?;
    Ok(Json(UpdateCheck {
        checked_at: ts(&now),
        current_version: env!("CARGO_PKG_VERSION").to_owned(),
        latest_version: None,
        status: "feed_unavailable".to_owned(),
    }))
}

/// How much disk each kind of data uses, in bytes. A part the Core cannot measure is absent.
#[derive(Debug, Serialize, ToSchema)]
pub struct CoreStorage {
    /// The database and its journal; it holds notes, Brain memory, projects' records and the audit log.
    #[schema(required = false)]
    pub database_bytes: Option<u64>,
    /// The Core's copies of project repositories (`mirrors/`).
    #[schema(required = false)]
    pub projects_bytes: Option<u64>,
    /// Backup archives (`backups/`).
    #[schema(required = false)]
    pub backups_bytes: Option<u64>,
    /// How many backup files there are.
    #[schema(required = false)]
    pub backups_count: Option<u64>,
    /// Everything else under the Core's home.
    #[schema(required = false)]
    pub other_bytes: Option<u64>,
    /// Share of the data disk in use, 0 to 100.
    #[schema(required = false)]
    pub disk_used_pct: Option<i64>,
    /// Size of the data disk in bytes.
    #[schema(required = false)]
    pub disk_total_bytes: Option<u64>,
}

/// Bytes and file count under `dir` (symlinks are counted, not followed); 0 when it is not there.
fn tree(dir: &Path) -> (u64, u64) {
    let (mut bytes, mut files) = (0, 0);
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        let Ok(read) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in read.flatten() {
            let Ok(m) = e.metadata() else { continue };
            if m.is_dir() {
                todo.push(e.path());
            } else {
                bytes += m.len();
                files += 1;
            }
        }
    }
    (bytes, files)
}

fn measure(db: &Path) -> CoreStorage {
    let home = db
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let len = |p: &Path| std::fs::metadata(p).map_or(0, |m| m.len());
    let mut sidecar = db.as_os_str().to_owned();
    sidecar.push("-wal");
    let wal = len(Path::new(&sidecar));
    let mut shm = db.as_os_str().to_owned();
    shm.push("-shm");
    let database = len(db) + wal + len(Path::new(&shm));
    let (projects, _) = tree(&home.join("mirrors"));
    let (backups, count) = tree(&home.join("backups"));
    let (all, _) = tree(home);
    CoreStorage {
        database_bytes: Some(database),
        projects_bytes: Some(projects),
        backups_bytes: Some(backups),
        backups_count: Some(count),
        other_bytes: Some(all.saturating_sub(database + projects + backups)),
        disk_used_pct: None,
        disk_total_bytes: None,
    }
}

#[utoipa::path(get, path = "/api/v1/core/storage", operation_id = "getCoreStorage",
    tag = "system",
    responses((status = 200, description = "Disk use by kind of data under the Core's home, \
        and the data disk's size and fill. Walks the home's files, so it is for a person \
        opening the page, not for polling. Needs `admin`", body = CoreStorage)))]
pub async fn storage(State(app): State<App>) -> ApiResult<CoreStorage> {
    let host = app.health.host().await;
    let r = &host.readings;
    let mut out = match app.health.db_path().map(Path::to_path_buf) {
        Some(db) => tokio::task::spawn_blocking(move || measure(&db))
            .await
            .map_err(|e| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", e.to_string())
            })?,
        None => CoreStorage {
            database_bytes: None,
            projects_bytes: None,
            backups_bytes: None,
            backups_count: None,
            other_bytes: None,
            disk_used_pct: None,
            disk_total_bytes: None,
        },
    };
    out.disk_used_pct = r.disk_free_pct().map(|f| 100 - f);
    out.disk_total_bytes = r.disk_total_bytes;
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_trimmed_and_bounded() {
        assert_eq!(clean_name("  Studio server ").unwrap(), "Studio server");
        assert!(clean_name("   ").is_err());
        assert!(clean_name(&"x".repeat(65)).is_err());
        assert!(clean_name("a\nb").is_err());
        assert!(clean_name(&"é".repeat(64)).is_ok());
    }

    #[test]
    fn storage_counts_each_folder_and_leaves_the_rest_to_other() {
        let dir = std::env::temp_dir().join(format!("core-storage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("backups")).unwrap();
        std::fs::create_dir_all(dir.join("mirrors/a.git")).unwrap();
        std::fs::write(dir.join("core.db"), [0u8; 100]).unwrap();
        std::fs::write(dir.join("backups/a.age"), [0u8; 40]).unwrap();
        std::fs::write(dir.join("backups/b.age"), [0u8; 10]).unwrap();
        std::fs::write(dir.join("mirrors/a.git/HEAD"), [0u8; 7]).unwrap();
        std::fs::write(dir.join("note.txt"), [0u8; 3]).unwrap();
        let s = measure(&dir.join("core.db"));
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(s.database_bytes, Some(100));
        assert_eq!((s.backups_bytes, s.backups_count), (Some(50), Some(2)));
        assert_eq!(s.projects_bytes, Some(7));
        assert_eq!(s.other_bytes, Some(3));
    }
}
