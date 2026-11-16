//! Attachments of AI sessions (E4, migration `0037`): files kept with their session, in the
//! database, until the session row goes (`ON DELETE CASCADE`) or the session has been over for
//! [`RETENTION_SECS`] (`sweep`, from the scheduler).

use sqlx::sqlite::SqlitePool;

/// The most bytes one session's attachments hold together.
pub const MAX_PER_SESSION: i64 = 100 * 1024 * 1024;

/// How long an ended or lost session keeps its attachments: a week, so a conversation woken
/// within it can still name them.
pub const RETENTION_SECS: i64 = 7 * 24 * 3600;

/// A new attachment, as the API checked it.
pub struct NewAttachment<'a> {
    pub id: &'a str,
    pub session: &'a str,
    pub name: &'a str,
    pub content_type: Option<&'a str>,
    pub sha256: &'a str,
    pub data: &'a [u8],
    pub created_by: &'a str,
}

/// Stores `a` unless the session's attachments would pass [`MAX_PER_SESSION`]: `false` then.
pub async fn add(pool: &SqlitePool, a: &NewAttachment<'_>, now: &str) -> Result<bool, sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let held: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(size), 0) FROM core_agent_attachments WHERE session = ?",
    )
    .bind(a.session)
    .fetch_one(&mut *tx)
    .await?;
    let size = i64::try_from(a.data.len()).unwrap_or(i64::MAX);
    if held.saturating_add(size) > MAX_PER_SESSION {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO core_agent_attachments \
         (id, session, name, content_type, size, sha256, data, created_by, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(a.id)
    .bind(a.session)
    .bind(a.name)
    .bind(a.content_type)
    .bind(size)
    .bind(a.sha256)
    .bind(a.data)
    .bind(a.created_by)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Of `ids`, the ones session `session` does not hold.
pub async fn missing(
    pool: &SqlitePool,
    session: &str,
    ids: &[String],
) -> Result<Vec<String>, sqlx::Error> {
    let mut gone = Vec::new();
    for id in ids {
        let held: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM core_agent_attachments WHERE id = ? AND session = ?")
                .bind(id)
                .bind(session)
                .fetch_optional(pool)
                .await?;
        if held.is_none() {
            gone.push(id.clone());
        }
    }
    Ok(gone)
}

/// One attachment of `session`, `(name, data)`; `None` for another session's or a swept one.
pub async fn load(
    pool: &SqlitePool,
    session: &str,
    id: &str,
) -> Result<Option<(String, Vec<u8>)>, sqlx::Error> {
    sqlx::query_as("SELECT name, data FROM core_agent_attachments WHERE id = ? AND session = ?")
        .bind(id)
        .bind(session)
        .fetch_optional(pool)
        .await
}

/// The attachments of the session's pending message, oldest first.
pub async fn pending(pool: &SqlitePool, session: &str) -> Result<Vec<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT id FROM core_agent_attachments WHERE session = ? AND pending = 1 \
         ORDER BY created_at, id",
    )
    .bind(session)
    .fetch_all(pool)
    .await
}

/// Deletes the attachments of every session over since before `cutoff` (ISO-8601 UTC); how many.
pub async fn sweep(pool: &SqlitePool, cutoff: &str) -> Result<u64, sqlx::Error> {
    let mut tx = super::begin_write(pool).await?;
    let gone = sqlx::query(
        "DELETE FROM core_agent_attachments WHERE session IN (SELECT id FROM core_agent_sessions \
         WHERE state IN ('ended', 'lost') AND coalesce(ended_at, updated_at) < ?)",
    )
    .bind(cutoff)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok(gone)
}
