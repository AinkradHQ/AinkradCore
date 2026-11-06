//! The pushes an account's state calls for (S7): only an `auth_suspected` health event, only to
//! admins that did not opt out, ids and a fixed title only; a cooldown is in-app only.

use super::stub::Fake;
use super::tests_apns::fx;
use super::*;
use crate::store::gov::set_kinds;

const TOKEN: &str = "sk-ant-oat01-TESTONLYnotarealtoken0123456789";

async fn emit(pool: &SqlitePool, kind: &str, payload: Value) {
    let mut tx = begin_write(pool).await.unwrap();
    append(&mut tx, kind, &payload).await.unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn only_a_suspected_sign_in_is_pushed_and_it_carries_the_account_id_alone() {
    let fx = fx("account-push").await;
    let fake = Arc::new(Fake::new("apns"));
    let (admin, _) = fx.device("admin", &["admin"], 1).await;
    let (reader, _) = fx.device("reader", &["read"], 2).await;
    let (muted, _) = fx.device("muted", &["admin"], 3).await;
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
    // History is not pushed: the first tick only finds the newest event.
    assert_eq!(pusher.tick().await.unwrap(), 0);

    // In-app only: a cooldown, a quota limit, an upstream-errors window, a plan limit.
    emit(
        &fx.pool,
        "account.limited",
        json!({"account": 7, "class": "rate_limited", "until": "2026-11-06T10:00:00.000Z",
               "source": "gateway"}),
    )
    .await;
    emit(
        &fx.pool,
        "account.health",
        json!({"account": 7, "state": "unhealthy", "reason": "upstream_errors"}),
    )
    .await;
    assert_eq!(pusher.tick().await.unwrap(), 0, "in-app only");
    assert!(fake.take().is_empty());

    // The one that is pushed. The payload's extra fields (a label, a token, an upstream's words)
    // never reach the notification.
    emit(
        &fx.pool,
        "account.health",
        json!({"account": 7, "state": "unhealthy", "reason": "auth_suspected",
               "label": "claude-main", "note": format!("401 {TOKEN}")}),
    )
    .await;
    assert_eq!(pusher.tick().await.unwrap(), 1);
    let sent = fake.take();
    let to: Vec<&str> = sent.iter().map(|(d, _)| d.as_str()).collect();
    assert_eq!(
        to,
        [admin.as_str()],
        "admins that did not opt out, not {reader} nor {muted}"
    );
    let n = &sent[0].1;
    assert_eq!((n.kind, n.scope), ("account_health", "admin"));
    assert_eq!(n.data, json!({"account": 7}));
    let all = format!("{n:?}");
    for leaked in [TOKEN, "claude-main", "401"] {
        assert!(!all.contains(leaked), "the push leaked {leaked}: {all}");
    }
    // The event log's own copy is redacted too.
    let stored: Vec<String> =
        sqlx::query_scalar("SELECT payload FROM events WHERE kind LIKE 'account.%'")
            .fetch_all(&fx.pool)
            .await
            .unwrap();
    assert!(stored.iter().all(|p| !p.contains(TOKEN)), "{stored:?}");
}

#[test]
fn a_malformed_health_event_is_no_push() {
    use crate::push::Classifier;
    for payload in [
        json!({"reason": "auth_suspected"}),
        json!({"account": "7", "reason": "auth_suspected"}),
        json!({"account": 7, "reason": "auth_confirmed"}),
    ] {
        let e = StoredEvent {
            seq: 1,
            at: String::new(),
            kind: "account.health".to_owned(),
            payload: sqlx::types::Json(payload.clone()),
        };
        assert!(Platform.notification(&e).is_none(), "{payload}");
    }
}
