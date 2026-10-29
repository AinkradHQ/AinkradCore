//! Audit repository: append and read the append-only log. There is no update or delete;
//! the schema's triggers reject both.
//!
//! `append` runs inside the caller's write transaction, so the row commits or rolls back with
//! the change it records. Rows are hash-chained (`chain`, E1-10.1).

use ainkrad_core::audit::{
    AuditActor, AuditEntity, AuditEvent, AuditFilter, AuditSeq, NewAuditEvent,
};
use sqlx::sqlite::{SqliteConnection, SqlitePool, SqliteRow};
use sqlx::{Error, Row};

macro_rules! audit_columns {
    () => {
        "seq, at, actor_kind, actor_id, action, entity_kind, entity_id, details"
    };
}

fn event(row: SqliteRow) -> Result<AuditEvent, Error> {
    let kind: String = row.try_get("actor_kind")?;
    let actor = AuditActor::from_parts(&kind, row.try_get("actor_id")?).ok_or_else(|| {
        Error::ColumnDecode {
            index: "actor_kind".to_owned(),
            source: format!("bad actor `{kind}`").into(),
        }
    })?;
    let entity_kind: Option<String> = row.try_get("entity_kind")?;
    let entity_id: Option<i64> = row.try_get("entity_id")?;
    Ok(AuditEvent {
        seq: AuditSeq(row.try_get("seq")?),
        at: row.try_get("at")?,
        actor,
        action: row.try_get("action")?,
        entity: entity_kind
            .zip(entity_id)
            .map(|(kind, id)| AuditEntity { kind, id }),
        details: row.try_get("details")?,
    })
}

/// The user every row belongs to until there are more (#18); part of the hashed row.
const USER: i64 = 1;

/// Appends one row inside the caller's write transaction (`store::begin_write`), so it commits
/// or rolls back with the change it records. Its `details` are redacted first (`redact`), then
/// it is chained (`chain`): it reads the newest row's hash and takes the next seq, so it must run
/// under the write gate; a racing writer outside the gate is refused by the chain trigger rather
/// than forking the chain. The `audit` event comes with it, written by trigger.
pub async fn append(conn: &mut SqliteConnection, e: &NewAuditEvent) -> Result<AuditEvent, Error> {
    let (actor_kind, actor_id) = e.actor.parts();
    let (at, seq, prev): (String, i64, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), \
         coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'), 0) + 1, \
         (SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1)",
    )
    .fetch_one(&mut *conn)
    .await?;
    let prev = prev.unwrap_or_else(|| vec![0; 32]);
    let row = chain::ChainRow {
        seq,
        at,
        user_id: USER,
        actor_kind: actor_kind.to_owned(),
        actor_id,
        action: e.action.clone(),
        entity_kind: e.entity.as_ref().map(|x| x.kind.clone()),
        entity_id: e.entity.as_ref().map(|x| x.id),
        details: crate::store::redact::text(&e.details),
        prev_hash: None,
        hash: None,
    };
    let hash = chain::digest(&row, &chain::hex(&prev));
    sqlx::query(concat!(
        "INSERT INTO audit_events (seq, at, user_id, actor_kind, actor_id, action, entity_kind, \
         entity_id, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING ",
        audit_columns!()
    ))
    .bind(row.seq)
    .bind(&row.at)
    .bind(row.user_id)
    .bind(&row.actor_kind)
    .bind(row.actor_id)
    .bind(&row.action)
    .bind(&row.entity_kind)
    .bind(row.entity_id)
    .bind(&row.details)
    .bind(prev)
    .bind(&hash[..])
    .fetch_one(&mut *conn)
    .await
    .map_err(|err| match &err {
        Error::Database(d) if d.message() == "unknown audit action" => {
            Error::InvalidArgument(format!("unknown audit action {:?}", e.action))
        }
        _ => err,
    })
    .and_then(event)
}

/// Appends one row in a write transaction of its own.
pub async fn append_one(pool: &SqlitePool, e: &NewAuditEvent) -> Result<AuditEvent, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let row = append(&mut tx, e).await?;
    tx.commit().await?;
    Ok(row)
}

/// Up to `limit` events matching `filter` with `seq` above `after` (all when `None`),
/// oldest first. Page by passing the last `seq` seen.
pub async fn list(
    pool: &SqlitePool,
    filter: &AuditFilter,
    after: Option<AuditSeq>,
    limit: u32,
) -> Result<Vec<AuditEvent>, Error> {
    let actor = filter.actor.map(AuditActor::parts);
    sqlx::query(concat!(
        "SELECT ",
        audit_columns!(),
        " FROM audit_events WHERE seq > ?1 \
         AND (?2 IS NULL OR (entity_kind = ?2 AND entity_id = ?3)) \
         AND (?4 IS NULL OR (actor_kind = ?4 AND actor_id IS ?5)) \
         ORDER BY seq LIMIT ?6"
    ))
    .bind(after.map_or(0, |s| s.0))
    .bind(filter.entity.as_ref().map(|x| &x.kind))
    .bind(filter.entity.as_ref().map(|x| x.id))
    .bind(actor.map(|(kind, _)| kind))
    .bind(actor.and_then(|(_, id)| id))
    .bind(limit)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(event)
    .collect()
}

/// Up to `limit` events below `before` (all when `None`), newest first: whose action starts
/// with `action_prefix`, about `entity` (a kind, and an id when given), done by an `actor`
/// kind (`user`, `system`) when given. Page by passing the last `seq` seen as `before`.
pub async fn page(
    pool: &SqlitePool,
    before: Option<AuditSeq>,
    action_prefix: Option<&str>,
    entity: Option<(&str, Option<i64>)>,
    actor: Option<&str>,
    limit: u32,
) -> Result<Vec<AuditEvent>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        audit_columns!(),
        " FROM audit_events WHERE (?1 IS NULL OR seq < ?1) \
         AND (?2 IS NULL OR substr(action, 1, length(?2)) = ?2) \
         AND (?3 IS NULL OR entity_kind = ?3) \
         AND (?4 IS NULL OR entity_id = ?4) \
         AND (?5 IS NULL OR actor_kind = ?5) \
         ORDER BY seq DESC LIMIT ?6"
    ))
    .bind(before.map(|s| s.0))
    .bind(action_prefix)
    .bind(entity.map(|(kind, _)| kind))
    .bind(entity.and_then(|(_, id)| id))
    .bind(actor)
    .bind(limit)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(event)
    .collect()
}

pub mod chain;

#[cfg(test)]
mod tests;
