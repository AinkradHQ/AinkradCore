//! The event log (E10.2, E1-04): what the client stream and its HTTP replay read. One strictly
//! increasing `seq` over every row; each row is a registered `kind` (`store::kinds`) and a JSON
//! `payload`.
//!
//! **The transaction rule.** An event is written in the same write transaction as the change it
//! describes, so both commit or neither does, and a reader never sees one without the other:
//! a write path takes `store::begin_write`, makes its change, calls [`append`] (or
//! `audit::append`) on the same transaction, and commits. There is no other way to emit an event.
//! SQLite has one writer at a time, so seq order is commit order.
//!
//! **One definition of an event.** Two paths write rows, and the database holds both to the same
//! rules (migrations `0001`, `0002`): [`append`] for a module's kinds, and the
//! `events_from_audit` trigger, which writes an `audit` event for every audit row. Either way the
//! kind must be registered, the payload is JSON, and the payload is redacted: [`append`] redacts
//! it here, and an audit row's details are redacted by `audit::append` before the trigger copies
//! them.
//!
//! **Retention** (E1-04.4): [`trim`] removes the oldest events, those older than the
//! `events.retention_secs` setting, and raises the floor; a client resuming below it is told so
//! ([`replay`] returns [`PastRetention`]) and re-syncs from a snapshot.

use serde_json::Value;
use sqlx::sqlite::{SqliteConnection, SqlitePool};
use sqlx::types::Json;

use ainkrad_core::audit::{AuditActor, NewAuditEvent};

/// One event as stored.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct StoredEvent {
    pub seq: i64,
    pub at: String,
    pub kind: String,
    pub payload: Json<Value>,
}

/// The most events a read returns.
pub const MAX_EVENTS: u32 = 1000;

/// Appends one event of a registered `kind` inside the caller's write transaction (see the
/// transaction rule above); returns its seq. The payload is redacted first. An unregistered kind
/// is an `InvalidArgument` naming it, and nothing is written.
pub async fn append(
    conn: &mut SqliteConnection,
    kind: &str,
    payload: &Value,
) -> Result<i64, sqlx::Error> {
    let mut payload = payload.clone();
    crate::store::redact::json(&mut payload);
    sqlx::query_scalar("INSERT INTO events (kind, payload) VALUES (?, ?) RETURNING seq")
        .bind(kind)
        .bind(payload.to_string())
        .fetch_one(conn)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(d) if d.message() == "unknown event kind" => {
                sqlx::Error::InvalidArgument(format!("unknown event kind {kind:?}"))
            }
            _ => e,
        })
}

/// Up to `limit` (at most [`MAX_EVENTS`]) events with seq above `after`, oldest first, whatever
/// the floor (the pusher's read: it only needs what is there).
pub async fn list_events(
    pool: &SqlitePool,
    after: i64,
    limit: u32,
) -> Result<Vec<StoredEvent>, sqlx::Error> {
    sqlx::query_as("SELECT seq, at, kind, payload FROM events WHERE seq > ? ORDER BY seq LIMIT ?")
        .bind(after)
        .bind(limit.min(MAX_EVENTS))
        .fetch_all(pool)
        .await
}

/// A resume point below the retention floor: events after it are gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PastRetention {
    /// The newest trimmed seq; events above it are all there.
    pub floor: i64,
}

/// A client's read: the events after `after`, as [`list_events`], or [`PastRetention`] when
/// some of them were trimmed. Floor and events are read in one snapshot, so a trim in between
/// cannot leave a silent gap.
pub async fn replay(
    pool: &SqlitePool,
    after: i64,
    limit: u32,
) -> Result<Result<Vec<StoredEvent>, PastRetention>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let floor = floor_in(&mut tx).await?;
    if after < floor {
        return Ok(Err(PastRetention { floor }));
    }
    let events = sqlx::query_as(
        "SELECT seq, at, kind, payload FROM events WHERE seq > ? ORDER BY seq LIMIT ?",
    )
    .bind(after)
    .bind(limit.min(MAX_EVENTS))
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Ok(events))
}

async fn floor_in(conn: &mut SqliteConnection) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT seq FROM events_floor")
        .fetch_one(conn)
        .await
}

/// The retention floor: the newest trimmed seq, 0 before any trim.
pub async fn floor(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    floor_in(&mut *pool.acquire().await?).await
}

/// The newest event's seq (the floor when every event is trimmed); 0 when there is none.
pub async fn last_event_seq(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT max(coalesce((SELECT max(seq) FROM events), 0), (SELECT seq FROM events_floor))",
    )
    .fetch_one(pool)
    .await
}

/// What one [`trim`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Trimmed {
    pub floor: i64,
    pub removed: u64,
}

/// Trims events older than `keep_secs` before `now`, at most `batch` of them, oldest first, and
/// audits it (`events.trimmed`). Only the unbroken run of old events from the floor up is
/// trimmed, so the floor is a seq below which everything is gone and above which nothing is.
/// `None` when there is nothing to trim.
///
/// The floor is raised first; the delete trigger lets only rows at or below it go.
pub async fn trim(
    pool: &SqlitePool,
    now: &str,
    keep_secs: i64,
    batch: u32,
) -> Result<Option<Trimmed>, sqlx::Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let floor = floor_in(&mut tx).await?;
    let old: Vec<(i64, bool)> = sqlx::query_as(
        "SELECT seq, at < strftime('%Y-%m-%dT%H:%M:%fZ', ?1, '-' || ?2 || ' seconds') \
         FROM events WHERE seq > ?3 ORDER BY seq LIMIT ?4",
    )
    .bind(now)
    .bind(keep_secs)
    .bind(floor)
    .bind(batch)
    .fetch_all(&mut *tx)
    .await?;
    let Some(new) = old.iter().take_while(|(_, old)| *old).last().map(|r| r.0) else {
        return Ok(None);
    };
    sqlx::query("UPDATE events_floor SET seq = ?")
        .bind(new)
        .execute(&mut *tx)
        .await?;
    let removed = sqlx::query("DELETE FROM events WHERE seq <= ?")
        .bind(new)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    let audit = NewAuditEvent {
        actor: AuditActor::System,
        action: "events.trimmed".to_owned(),
        entity: None,
        details: serde_json::json!({"floor": new, "removed": removed, "retention_secs": keep_secs})
            .to_string(),
    };
    crate::store::audit::append(&mut tx, &audit).await?;
    tx.commit().await?;
    Ok(Some(Trimmed {
        floor: new,
        removed,
    }))
}

#[cfg(test)]
mod tests;
