//! The failover surface of the scheduler API (S7 on S6): the attempts of a run on a session, the
//! `?run=` filter, the wake of a replaced attempt, an account's plan snapshot, `account.failover`
//! and the storm alarm, `account.expired`, and the `scheduler.*` settings the failover reads.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::allocator::w;
use super::failover::{limited, mv, over, to};
use super::gateway_store::gw;
use super::health::at;
use super::*;
use crate::store::agents as store;
use crate::store::alloc;
use crate::store::failover::Moved;
use crate::store::settings;
use ainkrad_core::settings::{Key, Scope};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str) -> (StatusCode, Value) {
    send(&fx.app, req(m, uri, Some(dev), None)).await
}

async fn payloads(fx: &Fx, kind: &str) -> Vec<Value> {
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT payload FROM events WHERE kind = ? ORDER BY seq")
            .bind(kind)
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    rows.iter()
        .map(|p| serde_json::from_str(p).unwrap())
        .collect()
}

async fn set(fx: &Fx, key: Key, value: &str) {
    settings::set(&fx.app.pool, key, Scope::Server, value, BY, NOW)
        .await
        .unwrap();
}

/// Ends the live attempt `id` as rate limited at `t`.
async fn end_limited(fx: &Fx, id: &str, t: i64) {
    let pool = &fx.app.pool;
    alloc::mark_start_sent(pool, id).await.unwrap();
    store::set_state(pool, id, "running", "test", false, &at(t))
        .await
        .unwrap();
    store::end(pool, id, "ended", &limited(), &at(t + 1))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_run_shows_its_attempts_and_a_non_admin_and_another_user_see_less() {
    let w = w().await;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    let (old, _) = over(&w, &chain, limited(), 0).await;
    let (new, _) = to(mv(&w, &old.id, "rate_limited", &at(5), true).await);
    let fx = &w.fx;
    let one = |id: &str| format!("/api/v1/agent-sessions/{id}");
    let (st, first) = call(fx, &fx.dev, Method::GET, &one(&old.id)).await;
    assert_eq!(st, StatusCode::OK, "{first}");
    assert_eq!(
        (&first["run"], &first["attempt"]),
        (&json!(old.id), &json!(0))
    );
    assert_eq!(first["failed_over_to"], json!(new));
    assert_eq!(first["failover_class"], "rate_limited");
    assert_eq!(first["skip_pools"], json!([]));
    assert!(first["failover_of"].is_null());
    let second = fx.ok(&one(&new)).await;
    assert_eq!(
        (&second["run"], &second["attempt"]),
        (&json!(old.id), &json!(1))
    );
    assert_eq!(second["failover_of"], json!(old.id));
    assert!(second["failed_over_to"].is_null());
    // The attempts of a run, newest first.
    let list = fx
        .ok(&format!("/api/v1/agent-sessions?run={}", old.id))
        .await;
    let ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [new.as_str(), old.id.as_str()]);
    assert_eq!(
        fx.ok("/api/v1/agent-sessions?run=as_nothere").await,
        json!([])
    );
    // A device of the same user without admin sees the run, but not why it moved nor the pools.
    let agent = super::stepup::plain(fx, "agent-dev", &["agent", "read"], true).await;
    let (st, seen) = call(fx, &agent, Method::GET, &one(&old.id)).await;
    assert_eq!(st, StatusCode::OK, "{seen}");
    assert_eq!(seen["failed_over_to"], json!(new));
    assert!(
        seen["failover_class"].is_null() && seen["skip_pools"].is_null(),
        "{seen}"
    );
    // Another user's device sees none of it.
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let other = fx.enroll("second", &["read", "admin", "agent"]).await;
    sqlx::query("UPDATE core_devices SET user_id = 2 WHERE id = ?")
        .bind(&other.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(
        call(fx, &other, Method::GET, &one(&old.id)).await.0,
        StatusCode::NOT_FOUND
    );
    let l = call(
        fx,
        &other,
        Method::GET,
        &format!("/api/v1/agent-sessions?run={}", old.id),
    )
    .await;
    assert_eq!(l.1, json!([]));
    // Nor can it act on it: every write route and the transcript answer as for a missing session,
    // and the newest attempt's id never reaches it.
    for dev in [&other, &fx.enroll("second-agent", &["read", "agent"]).await] {
        sqlx::query("UPDATE core_devices SET user_id = 2 WHERE id = ?")
            .bind(&dev.id)
            .execute(&fx.app.pool)
            .await
            .unwrap();
        for (m, tail, body) in [
            (Method::POST, "wake", Some(json!({}))),
            (Method::POST, "cancel", None),
            (Method::POST, "kill", None),
            (Method::POST, "resume", None),
            (Method::POST, "messages", Some(json!({"text": "hi"}))),
            (Method::GET, "transcript", None),
        ] {
            for id in [&old.id, &new] {
                let uri = format!("{}/{tail}", one(id));
                let (st, b) = send(&fx.app, req(m.clone(), &uri, Some(dev), body.clone())).await;
                assert_eq!(
                    (st, b["code"].as_str()),
                    (StatusCode::NOT_FOUND, Some("not_found")),
                    "{m} {uri}: {b}"
                );
                assert!(!b.to_string().contains(&new) || id == &new, "{b}");
            }
        }
    }
    let untouched: String =
        sqlx::query_scalar("SELECT state FROM core_agent_sessions WHERE id = ?")
            .bind(&new)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(untouched, "starting", "user B's writes changed nothing");
    // A wake of the replaced attempt names the one to wake.
    let wake = format!("{}/wake", one(&old.id));
    let (st, b) = send(
        &fx.app,
        req(Method::POST, &wake, Some(&fx.dev), Some(json!({}))),
    )
    .await;
    assert_eq!(
        (st, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("failed_over")),
        "{b}"
    );
    assert!(b["message"].as_str().unwrap().contains(&new), "{b}");
}

#[tokio::test]
async fn an_accounts_plan_snapshot_is_for_admins_only() {
    let g = gw().await;
    let resets = crate::scheduler::unix_secs(NOW).unwrap() + 3600;
    let snapshot = json!({"at": crate::scheduler::unix_secs(NOW).unwrap(),
        "plan": {"status": "rejected", "windows": [{"name": "five_hour", "utilization": 1.0,
                                                   "resets_at": resets}]}});
    sqlx::query("UPDATE core_accounts SET plan_limit = ? WHERE id = ?")
        .bind(snapshot.to_string())
        .bind(g.account.id)
        .execute(&g.fx.app.pool)
        .await
        .unwrap();
    let uri = format!("/api/v1/accounts/{}", g.account.id);
    let admin = g.fx.ok(&uri).await;
    let plan = &admin["health"]["plan_limit"];
    assert_eq!(plan["status"], "rejected");
    assert_eq!(plan["at"], "2026-10-22T10:00:00.000Z");
    assert_eq!(
        plan["windows"],
        json!([{"name": "five_hour", "utilization": 1.0, "resets_at": "2026-10-22T11:00:00.000Z"}])
    );
    let reader = g.fx.enroll("reader", &["read"]).await;
    let (_, theirs) = call(&g.fx, &reader, Method::GET, &uri).await;
    assert!(theirs["health"].is_null(), "{theirs}");
    // An account with no snapshot says none.
    sqlx::query("UPDATE core_accounts SET plan_limit = NULL")
        .execute(&g.fx.app.pool)
        .await
        .unwrap();
    assert!(g.fx.ok(&uri).await["health"]["plan_limit"].is_null());
}

#[tokio::test]
async fn a_move_and_an_end_raise_account_failover_with_ids_only() {
    let w = w().await;
    let (a1, a2) = (w.acct("a1").await, w.acct("a2").await);
    let chain = [w.keys("main", &[a1.id, a2.id]).await];
    let pool = chain[0].pool;
    let (old, first) = over(&w, &chain, limited(), 0).await;
    let (new, _) = to(mv(&w, &old.id, "rate_limited", &at(5), true).await);
    let moved = payloads(&w.fx, "account.failover").await;
    assert_eq!(
        moved,
        [
            json!({"run": old.id, "user": 1, "from_session": old.id, "to_session": new,
                "from_account": first, "to_account": a2.id, "from_pool": pool, "to_pool": pool,
                "class": "rate_limited", "hop": 1})
        ]
    );
    // Nothing is left for the successor: the run ends, and the event says so.
    end_limited(&w.fx, &new, 10).await;
    let ended = mv(&w, &new, "rate_limited", &at(20), true).await;
    assert!(matches!(ended, Moved::Ended { .. }), "{ended:?}");
    let all = payloads(&w.fx, "account.failover").await;
    assert_eq!(all.len(), 2);
    assert_eq!(
        all[1],
        json!({"run": old.id, "user": 1, "from_session": new, "to_session": null,
               "from_account": a2.id, "to_account": null, "from_pool": pool, "to_pool": null,
               "class": "rate_limited", "hop": 2})
    );
    for p in &all {
        assert!(!p.to_string().contains("sk-ant"), "{p}");
    }
}

#[tokio::test]
async fn max_hops_and_the_storm_rate_are_settings_and_the_storm_raises_one_alarm_a_window() {
    let w = w().await;
    let accounts = [w.acct("a1").await, w.acct("a2").await, w.acct("a3").await];
    let ids: Vec<i64> = accounts.iter().map(|a| a.id).collect();
    let chain = [w.keys("main", &ids).await];
    // max_hops 1: the first move is allowed, the second is the hop cap.
    set(&w.fx, Key::SchedulerMaxHops, "1").await;
    let (r1, _) = over(&w, &chain, limited(), 0).await;
    let (s1, _) = to(mv(&w, &r1.id, "rate_limited", &at(5), true).await);
    end_limited(&w.fx, &s1, 10).await;
    match mv(&w, &s1, "rate_limited", &at(20), true).await {
        Moved::Ended { why, .. } => assert!(why.starts_with("hop cap"), "{why}"),
        other => panic!("{other:?}"),
    }
    // max_hops 0: failover is off, for a new run too.
    set(&w.fx, Key::SchedulerMaxHops, "0").await;
    let (r2, _) = over(&w, &chain, limited(), 100).await;
    match mv(&w, &r2.id, "rate_limited", &at(105), true).await {
        Moved::Ended { why, .. } => assert!(why.contains("failover is off"), "{why}"),
        other => panic!("{other:?}"),
    }
    // The storm rate is per user and read from the setting: with 1 in a window, the next run ends.
    set(&w.fx, Key::SchedulerMaxHops, "4").await;
    set(&w.fx, Key::SchedulerFailoversPer10Min, "1").await;
    assert!(payloads(&w.fx, "alarm.raised").await.is_empty());
    let (r3, _) = over(&w, &chain, limited(), 200).await;
    match mv(&w, &r3.id, "rate_limited", &at(205), true).await {
        Moved::Ended { why, .. } => assert_eq!(why, "failover storm guard"),
        other => panic!("{other:?}"),
    }
    let (r4, _) = over(&w, &chain, limited(), 300).await;
    assert!(matches!(
        mv(&w, &r4.id, "rate_limited", &at(305), true).await,
        Moved::Ended { .. }
    ));
    let alarms = payloads(&w.fx, "alarm.raised").await;
    assert_eq!(alarms.len(), 1, "once per window: {alarms:?}");
    assert_eq!(
        (
            &alarms[0]["alarm"],
            &alarms[0]["value"],
            &alarms[0]["threshold"]
        ),
        (&json!("failover_storm"), &json!(1), &json!(1))
    );
}

#[tokio::test]
async fn a_confirmed_auth_failure_raises_account_expired_and_a_cleared_one_does_not() {
    let g = gw().await;
    let pool = &g.fx.app.pool;
    let id = g.account.id;
    for (key, verdict) in [("k1", "cleared"), ("k2", "confirmed")] {
        sqlx::query(
            "INSERT INTO core_account_auth_signals (account_id, session, gw_key, seen_at) \
             VALUES (?, 's', ?, ?)",
        )
        .bind(id)
        .bind(key)
        .bind(NOW)
        .execute(pool)
        .await
        .unwrap();
        crate::store::gateway::decide(pool, id, verdict, "", NOW)
            .await
            .unwrap();
    }
    assert_eq!(
        payloads(&g.fx, "account.expired").await,
        [json!({"account": id, "user": 1, "reason": "auth_confirmed"})]
    );
}

#[tokio::test]
async fn the_storm_guard_and_its_alarm_are_per_user() {
    let w = w().await;
    let pool = &w.fx.app.pool;
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(pool)
        .await
        .unwrap();
    let other = super::secrets::runner(&w.fx, "second").await.id;
    sqlx::query("UPDATE core_devices SET user_id = 2 WHERE id = ?")
        .bind(&other)
        .execute(pool)
        .await
        .unwrap();
    let (a, b, c) = (w.acct("a").await, w.acct("b").await, w.acct("c").await);
    for id in [b.id, c.id] {
        sqlx::query("UPDATE core_accounts SET user_id = 2 WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }
    let mine = [w.keys("mine", &[a.id]).await];
    let theirs = [w.keys("theirs", &[b.id, c.id]).await];
    set(&w.fx, Key::SchedulerFailoversPer10Min, "1").await;
    // Each user has one failover in the window already (the bucket), so each one's next run ends.
    for (user, chain) in [(1, &mine), (2, &theirs)] {
        let s = match user {
            1 => w.session(chain, &[]).await,
            _ => w.session_by(chain, &[], &other).await,
        };
        sqlx::query(
            "UPDATE core_agent_sessions SET failover_of = 'as_fake' || n, created_at = ? WHERE id = ?",
        )
        .bind(at(100))
        .bind(&s.id)
        .execute(pool)
        .await
        .unwrap();
    }
    let (r1, _) = over(&w, &mine, limited(), 200).await;
    assert!(matches!(
        mv(&w, &r1.id, "rate_limited", &at(300), true).await,
        Moved::Ended { .. }
    ));
    let r2 = w.session_by(&theirs, &[], &other).await;
    let got = super::allocator::took(
        w.pick_p(
            &r2.id,
            &theirs,
            &at(200),
            super::allocator::P {
                user: 2,
                ..super::allocator::p()
            },
        )
        .await,
    );
    assert!(got.account == b.id || got.account == c.id);
    alloc::mark_start_sent(pool, &r2.id).await.unwrap();
    store::end(pool, &r2.id, "ended", &limited(), &at(201))
        .await
        .unwrap();
    assert!(matches!(
        mv(&w, &r2.id, "rate_limited", &at(300), true).await,
        Moved::Ended { .. }
    ));
    // A second storm of the first user in the window raises no second alarm for them.
    let (r3, _) = over(&w, &mine, limited(), 400).await;
    assert!(matches!(
        mv(&w, &r3.id, "rate_limited", &at(405), true).await,
        Moved::Ended { .. }
    ));
    let mut users: Vec<i64> = payloads(&w.fx, "alarm.raised")
        .await
        .iter()
        .map(|p| p["user"].as_i64().unwrap())
        .collect();
    users.sort_unstable();
    assert_eq!(users, [1, 2], "one alarm per user and window");
}
