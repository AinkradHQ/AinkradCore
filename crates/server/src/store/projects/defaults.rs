//! The limits a run gets unless a project says otherwise, as the Settings page's Projects >
//! Options tab edits them (Core 0.10, E2-4). They live in the settings table as one JSON value.
//! Saving them also sets every project, so "for all projects" is literal; a project's own
//! change afterwards (`PATCH /projects/{id}`) still wins until the next save here.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::SqliteConnection;

use ainkrad_core::audit::NewAuditEvent;

use super::{Who, limits_ok};
use crate::store::secrets::Error;

const KEY: &str = "core.pref.project_limits";

/// CPUs, memory and the idle stop a new project starts with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Defaults {
    pub cpu_limit: f64,
    pub mem_limit_mb: i64,
    pub idle_minutes: i64,
    pub idle_never: bool,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            cpu_limit: 2.0,
            mem_limit_mb: 4096,
            idle_minutes: 30,
            idle_never: false,
        }
    }
}

/// What [`set`] changes; `None` keeps the value.
#[derive(Default)]
pub struct DefaultsChange {
    pub cpu_limit: Option<f64>,
    pub mem_limit_mb: Option<i64>,
    pub idle_minutes: Option<i64>,
    pub idle_never: Option<bool>,
}

/// The saved defaults, else the built-in ones (a value that no longer parses counts as unset).
pub async fn get(conn: &mut SqliteConnection) -> Result<Defaults, sqlx::Error> {
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT value FROM settings WHERE key = ? AND scope_kind = 'server' AND scope_id = 0",
    )
    .bind(KEY)
    .fetch_optional(conn)
    .await?;
    Ok(raw
        .and_then(|v| serde_json::from_str(&v).ok())
        .unwrap_or_default())
}

/// Saves the defaults and sets every project to them (audited as `project.defaults_changed`).
pub async fn set(
    pool: &sqlx::SqlitePool,
    c: &DefaultsChange,
    who: Who<'_>,
) -> Result<Defaults, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let old = get(&mut tx).await?;
    let new = Defaults {
        cpu_limit: c.cpu_limit.unwrap_or(old.cpu_limit),
        mem_limit_mb: c.mem_limit_mb.unwrap_or(old.mem_limit_mb),
        idle_minutes: c.idle_minutes.unwrap_or(old.idle_minutes),
        idle_never: c.idle_never.unwrap_or(old.idle_never),
    };
    limits_ok(new.idle_minutes, new.cpu_limit, new.mem_limit_mb)?;
    let (kind, id) = who.actor.parts();
    sqlx::query(
        "INSERT INTO settings (key, scope_kind, scope_id, value, updated_by_kind, updated_by_id, \
         updated_at) VALUES (?, 'server', 0, ?, ?, ?, ?) \
         ON CONFLICT (key, scope_kind, scope_id) DO UPDATE SET value = excluded.value, \
         updated_by_kind = excluded.updated_by_kind, updated_by_id = excluded.updated_by_id, \
         updated_at = excluded.updated_at",
    )
    .bind(KEY)
    .bind(serde_json::to_string(&new).unwrap_or_default())
    .bind(kind)
    .bind(id)
    .bind(who.now)
    .execute(&mut *tx)
    .await?;
    let n = sqlx::query(
        "UPDATE core_projects SET cpu_limit = ?, mem_limit_mb = ?, idle_minutes = ?, \
         idle_never = ?, updated_at = ?",
    )
    .bind(new.cpu_limit)
    .bind(new.mem_limit_mb)
    .bind(new.idle_minutes)
    .bind(new.idle_never)
    .bind(who.now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let details = json!({"cpu_limit": new.cpu_limit, "mem_limit_mb": new.mem_limit_mb,
        "idle_minutes": new.idle_minutes, "idle_never": new.idle_never, "projects": n,
        "by_device": who.by_device});
    let event = NewAuditEvent {
        actor: who.actor,
        action: "project.defaults_changed".to_owned(),
        entity: None,
        details: details.to_string(),
    };
    crate::store::audit::append(&mut tx, &event).await?;
    tx.commit().await?;
    Ok(new)
}
