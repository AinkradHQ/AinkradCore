//! "Always for this project" rules (Core 0.10, E14): `core_approval_rules`. A rule is a tool and a
//! normalised pattern; what may be stored, and what a stored rule covers, is decided by
//! `agents::rules`, never here. Adding and removing is audited.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::json;
use sqlx::Row;
use sqlx::sqlite::{SqlitePool, SqliteRow};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: i64,
    pub project_id: i64,
    pub tool: String,
    pub pattern: String,
    pub created_at: String,
}

fn rule(r: &SqliteRow) -> Result<Rule, sqlx::Error> {
    Ok(Rule {
        id: r.try_get("id")?,
        project_id: r.try_get("project_id")?,
        tool: r.try_get("tool")?,
        pattern: r.try_get("pattern")?,
        created_at: r.try_get("created_at")?,
    })
}

const COLS: &str = "id, project_id, tool, pattern, created_at";

/// The project's rules, oldest first.
pub async fn list(pool: &SqlitePool, project: i64) -> Result<Vec<Rule>, sqlx::Error> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} FROM core_approval_rules WHERE project_id = ? ORDER BY id"
    )))
    .bind(project)
    .fetch_all(pool)
    .await?;
    rows.iter().map(rule).collect()
}

/// Stores the rule (the same one again is the row it already is) and audits it, once.
pub async fn add(
    pool: &SqlitePool,
    project: i64,
    tool: &str,
    pattern: &str,
    by_device: &str,
    now: &str,
) -> Result<Rule, sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let made = sqlx::query(
        "INSERT OR IGNORE INTO core_approval_rules (project_id, tool, pattern, created_by, created_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(project)
    .bind(tool)
    .bind(pattern)
    .bind(by_device)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLS} FROM core_approval_rules WHERE project_id = ? AND tool = ? AND pattern = ?"
    )))
    .bind(project)
    .bind(tool)
    .bind(pattern)
    .fetch_one(&mut *tx)
    .await?;
    let kept = rule(&row)?;
    if made > 0 {
        let details = json!({"rule": kept.id, "tool": tool, "pattern": pattern,
                             "by_device": by_device});
        record(&mut tx, "agent.approval_rule_added", project, details).await?;
    }
    tx.commit().await?;
    Ok(kept)
}

/// Removes rule `id` of the project; `false` when there is none.
pub async fn delete(
    pool: &SqlitePool,
    project: i64,
    id: i64,
    by_device: &str,
) -> Result<bool, sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let gone = sqlx::query("DELETE FROM core_approval_rules WHERE id = ? AND project_id = ?")
        .bind(id)
        .bind(project)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        > 0;
    if gone {
        let details = json!({"rule": id, "by_device": by_device});
        record(&mut tx, "agent.approval_rule_removed", project, details).await?;
    }
    tx.commit().await?;
    Ok(gone)
}

async fn record(
    conn: &mut sqlx::SqliteConnection,
    action: &str,
    project: i64,
    details: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let entry = NewAuditEvent {
        actor: AuditActor::System,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "project".to_owned(),
            id: project,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &entry)
        .await
        .map(drop)
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))
}
