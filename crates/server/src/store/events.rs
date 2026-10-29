//! The event log (E10.2): what the client stream and its HTTP replay read. The `events`
//! table is written only by triggers (see its migration); this reads it with what each row
//! points at. A row whose target is gone (a test deleted a run) is skipped: its seq is a
//! gap, never a different event.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::WakeSource;
use serde_json::Value;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::types::Json;
use sqlx::{Error, Row};

use super::org::text;

/// One event as stored, with its target's fields.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredEvent {
    pub seq: i64,
    pub at: String,
    pub what: What,
}

#[derive(Debug, Clone, PartialEq)]
pub enum What {
    Audit {
        audit_seq: i64,
        action: String,
        actor: AuditActor,
        entity: Option<(String, i64)>,
        company_id: Option<i64>,
        run_id: Option<i64>,
        details: Value,
    },
    Transcript {
        run_id: i64,
        seq: i64,
        at: String,
        kind: String,
        payload: Value,
    },
    Wake {
        wake_id: i64,
        agent_id: i64,
        issue_id: Option<i64>,
        source: WakeSource,
        reason: String,
    },
}

/// The most events a read returns.
pub const MAX_EVENTS: u32 = 1000;

fn stored(row: &SqliteRow) -> Result<Option<StoredEvent>, Error> {
    let kind: String = row.try_get("kind")?;
    let ref_id: i64 = row.try_get("ref_id")?;
    let what =
        match kind.as_str() {
            "audit" => {
                let Some(actor_kind) = row.try_get::<Option<String>, _>("actor_kind")? else {
                    return Ok(None);
                };
                let actor = AuditActor::from_parts(&actor_kind, row.try_get("actor_id")?)
                    .ok_or_else(|| Error::ColumnDecode {
                        index: "actor_kind".to_owned(),
                        source: format!("bad actor `{actor_kind}`").into(),
                    })?;
                let entity_kind: Option<String> = row.try_get("entity_kind")?;
                let details: String = row.try_get("details")?;
                What::Audit {
                    audit_seq: ref_id,
                    action: row.try_get("action")?,
                    actor,
                    entity: entity_kind.zip(row.try_get::<Option<i64>, _>("entity_id")?),
                    company_id: row.try_get("company_id")?,
                    run_id: row.try_get("a_run")?,
                    details: serde_json::from_str(&details).unwrap_or(Value::String(details)),
                }
            }
            "transcript" => {
                let Some(run_id) = row.try_get::<Option<i64>, _>("t_run")? else {
                    return Ok(None);
                };
                What::Transcript {
                    run_id,
                    seq: row.try_get("t_seq")?,
                    at: row.try_get("t_at")?,
                    kind: row.try_get("t_kind")?,
                    payload: row.try_get::<Json<Value>, _>("t_payload")?.0,
                }
            }
            _ => {
                let Some(agent_id) = row.try_get::<Option<i64>, _>("w_agent")? else {
                    return Ok(None);
                };
                What::Wake {
                    wake_id: ref_id,
                    agent_id,
                    issue_id: row.try_get("w_issue")?,
                    source: text(row, "w_source")?,
                    reason: row.try_get("w_reason")?,
                }
            }
        };
    Ok(Some(StoredEvent {
        seq: row.try_get("seq")?,
        at: row.try_get("at")?,
        what,
    }))
}

/// Up to `limit` (at most [`MAX_EVENTS`]) events with seq above `after`, oldest first.
pub async fn list_events(
    pool: &SqlitePool,
    after: i64,
    limit: u32,
) -> Result<Vec<StoredEvent>, Error> {
    let rows = sqlx::query(
        "SELECT e.seq, e.at, e.kind, e.ref_id, \
         a.action, a.actor_kind, a.actor_id, a.entity_kind, a.entity_id, a.company_id, \
         a.run_id AS a_run, a.details, \
         r.run_id AS t_run, r.seq AS t_seq, r.at AS t_at, r.kind AS t_kind, \
         r.payload AS t_payload, \
         w.agent_id AS w_agent, w.issue_id AS w_issue, w.source AS w_source, \
         w.reason AS w_reason \
         FROM events e \
         LEFT JOIN audit_events a ON e.kind = 'audit' AND a.seq = e.ref_id \
         LEFT JOIN run_events r ON e.kind = 'transcript' AND r.id = e.ref_id \
         LEFT JOIN wake_requests w ON e.kind = 'wake' AND w.id = e.ref_id \
         WHERE e.seq > ? ORDER BY e.seq LIMIT ?",
    )
    .bind(after)
    .bind(limit.min(MAX_EVENTS))
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        out.extend(stored(row)?);
    }
    Ok(out)
}

/// The newest event's seq; 0 when there is none.
pub async fn last_event_seq(pool: &SqlitePool) -> Result<i64, Error> {
    sqlx::query_scalar("SELECT coalesce(max(seq), 0) FROM events")
        .fetch_one(pool)
        .await
}

/// The newest seq of an event of `company` (an audited change of it, a transcript chunk of
/// its run, a wake of its agent), as the scoped stream shows them; 0 when there is none.
/// Read from the newest down, so it stops at the company's latest event.
pub async fn last_company_event_seq(pool: &SqlitePool, company: i64) -> Result<i64, Error> {
    sqlx::query_scalar(
        "SELECT coalesce((SELECT e.seq FROM events e \
         LEFT JOIN audit_events a ON e.kind = 'audit' AND a.seq = e.ref_id \
         LEFT JOIN run_events r ON e.kind = 'transcript' AND r.id = e.ref_id \
         LEFT JOIN runs ru ON ru.id = r.run_id \
         LEFT JOIN agents ra ON ra.id = ru.agent_id \
         LEFT JOIN wake_requests w ON e.kind = 'wake' AND w.id = e.ref_id \
         LEFT JOIN agents wa ON wa.id = w.agent_id \
         WHERE coalesce(a.company_id, ra.company_id, wa.company_id) = ? \
         ORDER BY e.seq DESC LIMIT 1), 0)",
    )
    .bind(company)
    .fetch_one(pool)
    .await
}

#[cfg(test)]
mod tests {
    use ainkrad_core::audit::{AuditEntity, NewAuditEvent};
    use serde_json::json;

    use super::*;
    use crate::store::{audit, connect};

    #[tokio::test]
    async fn every_audit_is_an_event_in_commit_order_and_rollbacks_leave_none() {
        let dir = std::env::temp_dir().join(format!("citadel-events-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pool = connect(&dir.join("citadel.db")).await.unwrap();
        let event = |n: i64| NewAuditEvent {
            actor: AuditActor::System,
            action: "test.happened".to_owned(),
            entity: Some(AuditEntity {
                kind: "issue".to_owned(),
                id: n,
            }),
            company_id: None,
            run_id: None,
            details: json!({"n": n}).to_string(),
        };
        assert_eq!(last_event_seq(&pool).await.unwrap(), 0);
        audit::append(&pool, &event(1)).await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        audit::append(&mut *tx, &event(2)).await.unwrap();
        tx.rollback().await.unwrap();
        audit::append(&pool, &event(3)).await.unwrap();

        let all = list_events(&pool, 0, 10).await.unwrap();
        let ns: Vec<Value> = all
            .iter()
            .map(|e| match &e.what {
                What::Audit { details, .. } => details["n"].clone(),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(ns, [json!(1), json!(3)], "the rolled back one is not there");
        assert!(all[0].seq < all[1].seq);
        assert_eq!(list_events(&pool, all[0].seq, 10).await.unwrap(), all[1..]);
        assert_eq!(last_event_seq(&pool).await.unwrap(), all[1].seq);
        let edit = sqlx::query("UPDATE events SET kind = 'wake'")
            .execute(&pool)
            .await;
        assert!(edit.is_err(), "append-only");
        assert!(
            sqlx::query("DELETE FROM events")
                .execute(&pool)
                .await
                .is_err()
        );

        pool.close().await;
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
