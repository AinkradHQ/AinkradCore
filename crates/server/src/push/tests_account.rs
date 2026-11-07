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
    // An admin of another user is not told about this user's account.
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
        json!({"account": 7, "user": 1, "state": "unhealthy", "reason": "upstream_errors"}),
    )
    .await;
    assert_eq!(pusher.tick().await.unwrap(), 0, "in-app only");
    assert!(fake.take().is_empty());

    // The one that is pushed. The payload's extra fields (a label, a token, an upstream's words)
    // never reach the notification.
    emit(
        &fx.pool,
        "account.health",
        json!({"account": 7, "user": 1, "state": "unhealthy", "reason": "auth_suspected",
               "label": "claude-main", "note": format!("401 {TOKEN}")}),
    )
    .await;
    assert_eq!(pusher.tick().await.unwrap(), 1);
    let sent = fake.take();
    let to: Vec<&str> = sent.iter().map(|(d, _)| d.as_str()).collect();
    assert_eq!(
        to,
        [admin.as_str()],
        "this user's admins that did not opt out, not {reader}, {muted} nor {other}"
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
        json!({"account": 7, "reason": "auth_suspected"}),
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

#[test]
fn a_failover_and_an_expiry_are_pushed_to_their_user_with_ids_only_and_a_budget_is_not() {
    use crate::push::Classifier;
    let ev = |kind: &str, payload: Value| StoredEvent {
        seq: 1,
        at: String::new(),
        kind: kind.to_owned(),
        payload: sqlx::types::Json(payload),
    };
    let moved = json!({"run": "as_r", "user": 3, "from_session": "as_r", "to_session": "as_n",
        "from_account": 1, "to_account": 2, "from_pool": 1, "to_pool": 1, "class": "quota",
        "hop": 1, "label": "claude-main", "note": TOKEN});
    let n = Platform
        .notification(&ev("account.failover", moved.clone()))
        .unwrap();
    assert_eq!(
        (n.kind, n.scope, n.user),
        ("account_failover", "admin", Some(3))
    );
    assert_eq!(n.data, json!({"run": "as_r", "hop": 1}));
    assert!(!format!("{n:?}").contains(TOKEN));
    // A run that ended says so, in the title.
    let mut ended = moved;
    ended["to_session"] = Value::Null;
    let e = Platform
        .notification(&ev("account.failover", ended))
        .unwrap();
    assert_ne!(e.title, n.title);
    let expired = ev(
        "account.expired",
        json!({"account": 9, "user": 3, "reason": "auth_confirmed"}),
    );
    let x = Platform.notification(&expired).unwrap();
    assert_eq!(
        (x.kind, x.user, x.data),
        ("account_expired", Some(3), json!({"account": 9}))
    );
    // No user, no push; a budget or a cooldown is in-app only.
    assert!(
        Platform
            .notification(&ev("account.expired", json!({"account": 9})))
            .is_none()
    );
    let budget = json!({"subject_kind": "pool", "subject": "3", "state": "exhausted", "user": 3});
    assert!(
        Platform
            .notification(&ev("account.budget", budget))
            .is_none()
    );
}

#[tokio::test]
async fn a_storm_alarm_is_pushed_to_its_users_admins_and_a_core_alarm_to_all() {
    let fx = fx("storm-push").await;
    let fake = Arc::new(Fake::new("apns"));
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(&fx.pool)
        .await
        .unwrap();
    let (first, _) = fx.device("first", &["admin"], 1).await;
    let (second, _) = fx.device("second", &["admin"], 2).await;
    sqlx::query("UPDATE core_devices SET user_id = 2 WHERE id = ?")
        .bind(&second)
        .execute(&fx.pool)
        .await
        .unwrap();
    let pusher = Pusher::new(
        fx.pool.clone(),
        vec![fake.clone()],
        Arc::new(Platform),
        Duration::from_secs(1),
        Arc::new(crate::scheduler::SystemClock),
    );
    assert_eq!(pusher.tick().await.unwrap(), 0);
    let storm =
        |user: i64| json!({"alarm": "failover_storm", "value": 1, "threshold": 1, "user": user});
    emit(&fx.pool, "alarm.raised", storm(1)).await;
    emit(&fx.pool, "alarm.raised", storm(2)).await;
    assert_eq!(pusher.tick().await.unwrap(), 2, "one each, not merged");
    let mut got: Vec<(String, &str)> = fake.take().into_iter().map(|(d, n)| (d, n.kind)).collect();
    got.sort();
    let mut want = vec![
        (first.clone(), "alarm_raised"),
        (second.clone(), "alarm_raised"),
    ];
    want.sort();
    assert_eq!(got, want, "each admin got exactly its own user's alarm");
    // An alarm of the Core's own (no user) reaches every admin.
    emit(
        &fx.pool,
        "alarm.raised",
        json!({"alarm": "disk_free", "value": 4, "threshold": 10}),
    )
    .await;
    assert_eq!(pusher.tick().await.unwrap(), 1);
    assert_eq!(fake.take().len(), 2);
}
