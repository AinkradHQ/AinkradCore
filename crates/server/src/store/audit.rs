//! Audit repository: append and read the append-only log. There is no update or delete;
//! the schema's triggers reject both.
//!
//! `append` takes any executor, so a write path appends inside its own transaction and the
//! event commits or rolls back with the change it records.

use ainkrad_core::audit::{
    AuditActor, AuditEntity, AuditEvent, AuditFilter, AuditSeq, NewAuditEvent,
};
use sqlx::sqlite::{SqliteExecutor, SqlitePool, SqliteRow};
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

/// Appends one event. Pass `&mut *tx` to append inside a write's transaction.
pub async fn append<'e>(
    executor: impl SqliteExecutor<'e>,
    e: &NewAuditEvent,
) -> Result<AuditEvent, Error> {
    let (actor_kind, actor_id) = e.actor.parts();
    sqlx::query(concat!(
        "INSERT INTO audit_events (actor_kind, actor_id, action, entity_kind, entity_id, \
         details) VALUES (?, ?, ?, ?, ?, ?) RETURNING ",
        audit_columns!()
    ))
    .bind(actor_kind)
    .bind(actor_id)
    .bind(&e.action)
    .bind(e.entity.as_ref().map(|x| &x.kind))
    .bind(e.entity.as_ref().map(|x| x.id))
    .bind(&e.details)
    .fetch_one(executor)
    .await
    .and_then(event)
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

#[cfg(test)]
mod tests;
