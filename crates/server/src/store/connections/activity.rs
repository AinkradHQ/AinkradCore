//! What agents and features did with a connection (C5, CN6): its `connection.used` audit rows,
//! newest first. Only the fields the broker wrote as plain identifiers (kind, operation, result,
//! code, session, agent); the audit row holds no payload, so neither does this.

use sqlx::sqlite::SqlitePool;

use crate::store::secrets::Error;

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Use {
    pub seq: i64,
    pub at: String,
    pub kind: Option<String>,
    pub action: Option<String>,
    pub result: Option<String>,
    pub code: Option<String>,
    pub session: Option<String>,
    pub agent: Option<String>,
}

/// Uses of connection `id` of workspace `ws` with `seq` below `before`, newest first, at most
/// `limit`. Another workspace's id is `not_found`.
pub async fn list(
    pool: &SqlitePool,
    ws: i64,
    id: i64,
    before: Option<i64>,
    limit: u32,
) -> Result<Vec<Use>, Error> {
    super::get(pool, ws, id).await?;
    Ok(sqlx::query_as(
        "SELECT seq, at, json_extract(details, '$.kind') AS kind, \
         json_extract(details, '$.action') AS action, \
         json_extract(details, '$.result') AS result, json_extract(details, '$.code') AS code, \
         json_extract(details, '$.session') AS session, json_extract(details, '$.agent') AS agent \
         FROM audit_events WHERE entity_kind = 'connection' AND entity_id = ?1 \
         AND action = 'connection.used' AND (?2 IS NULL OR seq < ?2) ORDER BY seq DESC LIMIT ?3",
    )
    .bind(id)
    .bind(before)
    .bind(i64::from(limit))
    .fetch_all(pool)
    .await?)
}
