//! The event log (E10.2): what the client stream and its HTTP replay read. Each row is a
//! `kind` and a JSON `payload`, written in the transaction of the change it describes; the
//! platform's own kind, `audit`, is written by a trigger on `audit_events` (see the baseline
//! migration), with the audit row as its payload.

use serde_json::Value;
use sqlx::sqlite::SqlitePool;
use sqlx::types::Json;

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

/// Up to `limit` (at most [`MAX_EVENTS`]) events with seq above `after`, oldest first.
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

/// The newest event's seq; 0 when there is none.
pub async fn last_event_seq(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT coalesce(max(seq), 0) FROM events")
        .fetch_one(pool)
        .await
}

#[cfg(test)]
mod tests {
    use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
    use serde_json::json;

    use super::*;
    use crate::store::{audit, connect};

    #[tokio::test]
    async fn every_audit_is_an_event_in_commit_order_and_rollbacks_leave_none() {
        let dir = std::env::temp_dir().join(format!("core-events-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = connect(&dir.join("core.db")).await.unwrap();
        let event = |n: i64| NewAuditEvent {
            actor: AuditActor::System,
            action: "test.happened".to_owned(),
            entity: Some(AuditEntity {
                kind: "thing".to_owned(),
                id: n,
            }),
            details: json!({"n": n}).to_string(),
        };
        assert_eq!(last_event_seq(&pool).await.unwrap(), 0);
        audit::append(&pool, &event(1)).await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        audit::append(&mut *tx, &event(2)).await.unwrap();
        tx.rollback().await.unwrap();
        audit::append(&pool, &event(3)).await.unwrap();

        let all = list_events(&pool, 0, 10).await.unwrap();
        assert!(all.iter().all(|e| e.kind == "audit"));
        let ns: Vec<&Value> = all.iter().map(|e| &e.payload.0["details"]["n"]).collect();
        assert_eq!(
            ns,
            [&json!(1), &json!(3)],
            "the rolled back one is not there"
        );
        assert_eq!(all[0].payload.0["action"], "test.happened");
        assert_eq!(all[0].payload.0["entity_kind"], "thing");
        assert!(all[0].seq < all[1].seq);
        assert_eq!(list_events(&pool, all[0].seq, 10).await.unwrap(), all[1..]);
        assert_eq!(last_event_seq(&pool).await.unwrap(), all[1].seq);
        let edit = sqlx::query("UPDATE events SET kind = 'other'")
            .execute(&pool)
            .await;
        assert!(edit.is_err(), "append-only");
        assert!(
            sqlx::query("DELETE FROM events")
                .execute(&pool)
                .await
                .is_err()
        );
        let empty_kind = sqlx::query("INSERT INTO events (kind, payload) VALUES ('', '{}')")
            .execute(&pool)
            .await;
        assert!(empty_kind.is_err(), "a kind is never empty");
        sqlx::query("INSERT INTO events (kind, payload) VALUES ('ops.ran', '{\"ok\":true}')")
            .execute(&pool)
            .await
            .expect("any non-empty kind with a JSON payload");

        pool.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
