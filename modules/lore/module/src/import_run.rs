//! Import run records (R4-01): the run row, its counts as the API shows them, the state checks and the audit/event
//! line. Security model is that of `import.rs`: refusals are fixed sentences, audit and events carry ids only.

use std::collections::BTreeMap;

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::v1::{ApiError, BY};
use ainkrad_core_server::store::{audit, events};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

pub(crate) fn run_ok(s: &str) -> bool {
    crate::notes::id_has("li_", s)
}

pub(crate) fn none() -> ApiError {
    ApiError::not_found("no such import")
}

pub(crate) fn sha_hex(s: &str) -> String {
    Sha256::digest(s.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Audit row (`lore.import.<op>`) and event, ids and counts only.
pub(crate) async fn record(
    conn: &mut SqliteConnection,
    op: &str,
    run: &str,
    state: &str,
) -> Result<(), sqlx::Error> {
    let row = NewAuditEvent {
        actor: BY,
        action: format!("lore.import.{op}"),
        entity: None,
        details: json!({"import": run}).to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(conn, "lore.import", &json!({"id": run, "state": state})).await?;
    Ok(())
}

#[derive(Serialize, ToSchema)]
pub struct RunView {
    /// `li_` and 12 base32 characters.
    pub id: String,
    /// `mirror` or `upload`.
    pub source: String,
    pub project: Option<String>,
    pub repo: Option<String>,
    /// `staging`, `review`, `committing`, `committed`, `undoing`, `undone` or `abandoned`.
    pub state: String,
    /// Staged items.
    pub items: i64,
    /// Items that a commit would act on (marked include, not too large or skipped).
    pub include: i64,
    /// Entries refused as unsafe and entries ignored as unwanted; counted, never kept.
    pub refused: i64,
    pub ignored: i64,
    /// Why the run could not be read, a fixed sentence.
    pub error: Option<String>,
    /// Items by flag (`duplicate`, `changed`, `conflict`, `too_large`, `skipped`).
    pub flags: BTreeMap<String, i64>,
    /// Items by what commit did (`created`, `updated`, `conflict`, `unchanged`, `skipped`).
    pub results: BTreeMap<String, i64>,
    /// Items undo put back (`undone`) and ones it left because the note changed after the import (`kept`).
    pub undone: i64,
    pub kept: i64,
    pub created_by: String,
    pub created_at: String,
    pub updated_at: String,
    pub committed_at: Option<String>,
}

async fn tally(
    conn: &mut SqliteConnection,
    sql_col: bool,
    run: &str,
) -> Result<BTreeMap<String, i64>, sqlx::Error> {
    let sql: &'static str = if sql_col {
        "SELECT flag AS k, count(*) AS n FROM lore_import_items WHERE run = ? AND flag IS NOT NULL GROUP BY flag"
    } else {
        "SELECT result AS k, count(*) AS n FROM lore_import_items WHERE run = ? AND result IS NOT NULL GROUP BY result"
    };
    let rows = sqlx::query(sql).bind(run).fetch_all(conn).await?;
    rows.iter()
        .map(|r| Ok((r.try_get("k")?, r.try_get("n")?)))
        .collect()
}

pub(crate) async fn run_view(conn: &mut SqliteConnection, run: &str) -> Result<RunView, ApiError> {
    let r = sqlx::query("SELECT * FROM lore_imports WHERE id = ?")
        .bind(run)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(none)?;
    let n = |sql: &'static str| sqlx::query_scalar::<_, i64>(sql);
    let items = n("SELECT count(*) FROM lore_import_items WHERE run = ?")
        .bind(run)
        .fetch_one(&mut *conn)
        .await?;
    let include = n(
        "SELECT count(*) FROM lore_import_items WHERE run = ? AND mark = 'include' \
         AND (flag IS NULL OR flag NOT IN ('too_large', 'skipped'))",
    )
    .bind(run)
    .fetch_one(&mut *conn)
    .await?;
    let undone = n("SELECT count(*) FROM lore_import_items WHERE run = ? AND undone = 1")
        .bind(run)
        .fetch_one(&mut *conn)
        .await?;
    let kept = n("SELECT count(*) FROM lore_import_items WHERE run = ? AND undone = 2")
        .bind(run)
        .fetch_one(&mut *conn)
        .await?;
    let text = |c: &str| r.try_get::<String, _>(c);
    Ok(RunView {
        id: text("id")?,
        source: text("source")?,
        project: r.try_get("project")?,
        repo: r.try_get("repo")?,
        state: text("state")?,
        items,
        include,
        refused: r.try_get("refused")?,
        ignored: r.try_get("ignored")?,
        error: r.try_get("error")?,
        flags: tally(conn, true, run).await?,
        results: tally(conn, false, run).await?,
        undone,
        kept,
        created_by: text("created_by")?,
        created_at: text("created_at")?,
        updated_at: text("updated_at")?,
        committed_at: r.try_get("committed_at")?,
    })
}

/// The run's state, or the fixed refusal when it is not one of `allowed`.
pub(crate) async fn state_of(
    conn: &mut SqliteConnection,
    run: &str,
    allowed: &[&str],
) -> Result<String, ApiError> {
    if !run_ok(run) {
        return Err(none());
    }
    let st: String = sqlx::query_scalar("SELECT state FROM lore_imports WHERE id = ?")
        .bind(run)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(none)?;
    if allowed.contains(&st.as_str()) {
        Ok(st)
    } else {
        Err(ApiError::conflict(
            "the import is not in a state that allows this",
        ))
    }
}

pub(crate) async fn set_state(
    conn: &mut SqliteConnection,
    run: &str,
    state: &str,
    error: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE lore_imports SET state = ?, error = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), \
         committed_at = IIF(? = 'committed', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), committed_at) WHERE id = ?",
    )
    .bind(state)
    .bind(error)
    .bind(state)
    .bind(run)
    .execute(conn)
    .await
    .map(|_| ())
}
