//! The pushes a connection's health calls for (C5): only a suspected or a confirmed auth failure,
//! only to the admins of the connection's user, the connection's id and a fixed title only; a
//! cooldown or a recovery is in-app only.

use super::stub::Fake;
use super::tests_apns::fx;
use super::*;
use crate::store::gov::set_kinds;

const TOKEN: &str = "c5push-token-7f3a9d41e0b2c8a6";

async fn emit(pool: &SqlitePool, payload: Value) {
    let mut tx = begin_write(pool).await.unwrap();
    append(&mut tx, "connection.health", &payload)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn health(state: &str, reason: &str) -> Value {
    json!({"connection": 5, "user": 1, "kind": "github", "state": state, "reason": reason})
}

#[tokio::test]
async fn only_an_auth_failure_is_pushed_to_that_users_admins_with_ids_alone() {
    let fx = fx("connection-push").await;
    let fake = Arc::new(Fake::new("apns"));
    let (admin, _) = fx.device("admin", &["admin"], 1).await;
    let (reader, _) = fx.device("reader", &["read"], 2).await;
    let (muted, _) = fx.device("muted", &["admin"], 3).await;
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(&fx.pool)
        .await
        .unwrap();
    let (other, _) = fx.device("other", &["admin"], 4).await;
    sqlx::query("UPDATE core_devices SET user_id = 2 WHERE id = ?")
        .bind(&other)
        .execute(&fx.pool)
        .await
        .unwrap();
    assert!(
        set_kinds(&fx.pool, &muted, Some(&["approval_needed".to_owned()]))
            .await
            .unwrap()
    );
    let pusher = Pusher::new(
        fx.pool.clone(),
        vec![fake.clone()],
        Arc::new(Platform),
        Duration::from_secs(1),
        Arc::new(crate::scheduler::SystemClock),
    );
    assert_eq!(pusher.tick().await.unwrap(), 0);
    // In-app only: a cooldown, a limit, a recovery.
    for (state, reason) in [
        ("cooling", "rate_limited"),
        ("limited", "quota"),
        ("active", "recovered"),
    ] {
        emit(&fx.pool, health(state, reason)).await;
    }
    assert_eq!(pusher.tick().await.unwrap(), 0, "in-app only");
    assert!(fake.take().is_empty());
    // A suspected failure, with words around it that must not travel.
    let mut e = health("unhealthy", "auth_suspected");
    e["name"] = json!("work-github");
    e["note"] = json!(format!("401 {TOKEN}"));
    emit(&fx.pool, e).await;
    assert_eq!(pusher.tick().await.unwrap(), 1);
    let sent = fake.take();
    let to: Vec<&str> = sent.iter().map(|(d, _)| d.as_str()).collect();
    assert_eq!(to, [admin.as_str()], "not {reader}, {muted} nor {other}");
    let n = &sent[0].1;
    assert_eq!((n.kind, n.scope), ("connection_health", "admin"));
    assert_eq!(n.data, json!({"connection": 5}));
    // A confirmed one says so, under its own kind.
    emit(&fx.pool, health("disabled", "auth_failed")).await;
    assert_eq!(pusher.tick().await.unwrap(), 1);
    let sent = fake.take();
    assert_eq!(sent[0].1.kind, "connection_failed");
    for (_, n) in &sent {
        let all = format!("{n:?}");
        for leaked in [TOKEN, "work-github", "401"] {
            assert!(!all.contains(leaked), "the push leaked {leaked}: {all}");
        }
    }
}

#[test]
fn a_malformed_health_event_is_no_push() {
    use crate::push::Classifier;
    for payload in [
        json!({"reason": "auth_suspected"}),
        json!({"connection": 5, "reason": "auth_suspected"}),
        json!({"connection": "5", "user": 1, "reason": "auth_suspected"}),
        json!({"connection": 5, "user": 1, "reason": "auth_confirmed"}),
    ] {
        let e = StoredEvent {
            seq: 1,
            at: String::new(),
            kind: "connection.health".to_owned(),
            payload: sqlx::types::Json(payload.clone()),
        };
        assert!(Platform.notification(&e).is_none(), "{payload}");
    }
}
