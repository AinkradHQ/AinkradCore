use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_proto::redact::PLANTED;
use serde_json::json;

use super::*;
use crate::store::kinds::allow;
use crate::store::{audit, begin_write, connect};

/// A migrated database in its own temp dir, removed on drop.
struct Db {
    pool: SqlitePool,
    dir: std::path::PathBuf,
}

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn db() -> Db {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-events-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    allow(&pool, &["ops.ran", "ops.line"], &["test.happened"]).await;
    Db { pool, dir }
}

fn audited(n: i64) -> NewAuditEvent {
    NewAuditEvent {
        actor: AuditActor::System,
        action: "test.happened".to_owned(),
        entity: Some(AuditEntity {
            kind: "thing".to_owned(),
            id: n,
        }),
        details: json!({"n": n}).to_string(),
    }
}

async fn emit(pool: &SqlitePool, kind: &str, payload: Value) -> Result<i64, sqlx::Error> {
    let mut tx = begin_write(pool).await?;
    let seq = append(&mut tx, kind, &payload).await?;
    tx.commit().await?;
    Ok(seq)
}

#[tokio::test]
async fn every_audit_is_an_event_in_commit_order_and_rollbacks_leave_none() {
    let db = db().await;
    let pool = &db.pool;
    assert_eq!(last_event_seq(pool).await.unwrap(), 0);
    audit::append_one(pool, &audited(1)).await.unwrap();
    let mut tx = begin_write(pool).await.unwrap();
    audit::append(&mut tx, &audited(2)).await.unwrap();
    append(&mut tx, "ops.ran", &json!({"n": 2})).await.unwrap();
    tx.rollback().await.unwrap();
    audit::append_one(pool, &audited(3)).await.unwrap();

    let all = list_events(pool, 0, 10).await.unwrap();
    assert!(
        all.iter().all(|e| e.kind == "audit"),
        "the rolled back event too"
    );
    let ns: Vec<&Value> = all.iter().map(|e| &e.payload.0["details"]["n"]).collect();
    assert_eq!(
        ns,
        [&json!(1), &json!(3)],
        "the rolled back one is not there"
    );
    assert_eq!(all[0].payload.0["action"], "test.happened");
    assert_eq!(all[0].payload.0["entity_kind"], "thing");
    assert!(all[0].seq < all[1].seq);
    assert_eq!(list_events(pool, all[0].seq, 10).await.unwrap(), all[1..]);
    assert_eq!(last_event_seq(pool).await.unwrap(), all[1].seq);
    for sql in ["UPDATE events SET kind = 'other'", "DELETE FROM events"] {
        assert!(sqlx::query(sql).execute(pool).await.is_err(), "append-only");
    }
}

#[tokio::test]
async fn an_unknown_kind_is_refused_on_every_path() {
    let db = db().await;
    let pool = &db.pool;
    let seq = emit(pool, "ops.ran", json!({"ok": true})).await.unwrap();
    assert_eq!(list_events(pool, 0, 10).await.unwrap()[0].seq, seq);
    let err = emit(pool, "ops.unheard_of", json!({})).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("unknown event kind \"ops.unheard_of\""),
        "{err}"
    );
    for sql in [
        "INSERT INTO events (kind, payload) VALUES ('ops.unheard_of', '{}')",
        "INSERT INTO events (kind, payload) VALUES ('', '{}')",
    ] {
        let err = sqlx::query(sql).execute(pool).await.unwrap_err();
        assert!(err.to_string().contains("unknown event kind"), "{err}");
    }
    let unknown = NewAuditEvent {
        action: "test.unheard_of".to_owned(),
        ..audited(1)
    };
    let err = audit::append_one(pool, &unknown).await.unwrap_err();
    assert!(err.to_string().contains("unknown audit action"), "{err}");
    assert_eq!(list_events(pool, 0, 10).await.unwrap().len(), 1);

    // Registration: another owner cannot take a name; a module only its own prefix.
    let mut tx = begin_write(pool).await.unwrap();
    let taken = crate::store::kinds::register(&mut tx, "ops", &["audit"], &[]).await;
    assert!(taken.is_err());
    let theirs = crate::store::kinds::register(&mut tx, "mail", &["ops.ran"], &[]).await;
    assert!(theirs.is_err());
    crate::store::kinds::register(&mut tx, "ops", &["ops.ran"], &[])
        .await
        .expect("idempotent");
}

/// A planted secret never reaches the audit log or the event stream.
#[tokio::test]
async fn planted_secrets_are_masked_in_audit_and_events() {
    let db = db().await;
    let pool = &db.pool;
    for (_, secret) in PLANTED {
        let payload = json!({"api_token": "plain-looking-value", "note": format!("x {secret} y"),
                            "list": [secret], "key": "scheduler.tick_secs"});
        let e = NewAuditEvent {
            details: payload.to_string(),
            ..audited(1)
        };
        let row = audit::append_one(pool, &e).await.unwrap();
        emit(pool, "ops.line", payload).await.unwrap();
        let stored: Vec<String> =
            sqlx::query_scalar("SELECT details FROM audit_events WHERE seq = ?")
                .bind(row.seq.0)
                .fetch_all(pool)
                .await
                .unwrap();
        let events = list_events(pool, 0, MAX_EVENTS).await.unwrap();
        let texts = stored
            .into_iter()
            .chain(events.iter().rev().take(2).map(|e| e.payload.0.to_string()));
        let mut seen = 0;
        for text in texts {
            seen += 1;
            assert!(!text.contains("plain-looking-value"), "{text}");
            // A PEM block is stored JSON-escaped: check its body, which is what matters.
            let body = secret.lines().nth(1).unwrap_or(secret);
            assert!(!text.contains(body), "{secret} leaked: {text}");
            assert!(text.contains("[redacted:"), "{text}");
            assert!(
                text.contains("scheduler.tick_secs"),
                "a setting name is kept: {text}"
            );
        }
        assert_eq!(seen, 3, "the audit row, its event and the module's event");
    }
}

#[tokio::test]
async fn trimming_raises_the_floor_and_a_resume_below_it_is_past_retention() {
    let db = db().await;
    let pool = &db.pool;
    let at = |s: &str| format!("2026-10-{s}T00:00:00.000Z");
    for (day, n) in [("01", 1), ("02", 2), ("10", 3), ("03", 4)] {
        sqlx::query("INSERT INTO events (at, kind, payload) VALUES (?, 'ops.line', ?)")
            .bind(at(day))
            .bind(json!({"n": n}).to_string())
            .execute(pool)
            .await
            .unwrap();
    }
    assert_eq!(replay(pool, 0, 10).await.unwrap().unwrap().len(), 4);
    let day = 86_400;
    // Keep 5 days before the 10th: the 1st and 2nd go; the 3rd stays behind the newer 10th.
    let trimmed = trim(pool, &at("10"), 5 * day, 100).await.unwrap().unwrap();
    assert_eq!(
        trimmed,
        Trimmed {
            floor: 2,
            removed: 2
        }
    );
    assert_eq!(floor(pool).await.unwrap(), 2);
    assert_eq!(trim(pool, &at("10"), 5 * day, 100).await.unwrap(), None);
    assert_eq!(
        replay(pool, 1, 10).await.unwrap(),
        Err(PastRetention { floor: 2 })
    );
    assert_eq!(
        replay(pool, 0, 10).await.unwrap(),
        Err(PastRetention { floor: 2 })
    );
    let rest = replay(pool, 2, 10).await.unwrap().unwrap();
    assert_eq!(rest[0].seq, 3, "nothing above the floor is gone");
    assert_eq!(rest.last().unwrap().kind, "audit", "the trim is audited");
    assert_eq!(rest.last().unwrap().payload.0["action"], "events.trimmed");

    // A batch limit trims the oldest first.
    let trimmed = trim(pool, &at("30"), day, 1).await.unwrap().unwrap();
    assert_eq!(trimmed.floor, 3);

    // Rows above the floor stay append-only; the floor never falls.
    let err = sqlx::query("DELETE FROM events")
        .execute(pool)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("append-only"), "{err}");
    let err = sqlx::query("UPDATE events_floor SET seq = 0")
        .execute(pool)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("only rises"), "{err}");

    // Everything trimmed: the head is still the floor, never back to 0.
    let head = last_event_seq(pool).await.unwrap();
    trim(pool, "2030-01-01T00:00:00.000Z", 3600, 100)
        .await
        .unwrap();
    trim(pool, "2030-01-01T00:00:00.000Z", 3600, 100)
        .await
        .unwrap();
    assert!(last_event_seq(pool).await.unwrap() >= head);
}
