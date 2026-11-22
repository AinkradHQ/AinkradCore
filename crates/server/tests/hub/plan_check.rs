//! `POST /accounts/{id}/check` for a Claude plan (N36), with a runner played by hand: the token is
//! leased to a runner that lists `plan-check`, the one fixed op carries only the lease, the answer
//! is recorded as the account's last test and audited, an old runner and a second check within a
//! minute are told apart, and an API-key account is left to its key test.

use std::time::Duration;

use ainkrad_core_server::agents::plan_check::{self, Failed};
use ainkrad_core_server::api::v1::Caller;
use ainkrad_core_server::store::{accounts, gov};
use ainkrad_proto::v2::*;

use super::gateway::command;
use super::subscription::{S, up, up_with};

async fn caller(s: &S) -> Caller {
    let device = gov::get_device(&s.core.app.pool, &s.runner)
        .await
        .unwrap()
        .expect("the runner device");
    Caller {
        device,
        session: String::new(),
    }
}

fn checked(result: &str) -> Body {
    with_windows(result, None)
}

fn with_windows(result: &str, plan_limit: Option<PlanLimit>) -> Body {
    Body::Result(Reply::PlanCheck(PlanChecked {
        result: result.to_owned(),
        latency_ms: 9,
        plan_limit,
    }))
}

fn windows() -> PlanLimit {
    PlanLimit {
        status: "allowed".to_owned(),
        windows: vec![
            PlanWindow {
                name: "five_hour".to_owned(),
                utilization: 0.3,
                resets_at: Some(1_900_000_000),
            },
            PlanWindow {
                name: "seven_day".to_owned(),
                utilization: 0.1,
                resets_at: Some(1_900_400_000),
            },
        ],
    }
}

/// The account's stored snapshot (`{"at": unix, "plan": ...}`), as the accounts API reads it.
async fn stored(s: &S) -> Option<serde_json::Value> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT plan_limit FROM core_accounts WHERE id = ?")
            .bind(s.account.id)
            .fetch_one(&s.core.app.pool)
            .await
            .unwrap();
    raw.map(|r| serde_json::from_str(&r).unwrap())
}

#[tokio::test]
async fn a_plan_check_leases_the_token_to_a_runner_and_records_the_answer() {
    let mut s = up("pc-ok").await;
    let who = caller(&s).await;
    let (app, id) = (s.core.app.clone(), s.account.id);
    let task = tokio::spawn(async move { plan_check::run(&app, &who, id).await });
    let (stream, cmd) = command(&mut s.fake).await;
    let Command::PlanCheck(c) = cmd else {
        panic!("{cmd:?}")
    };
    assert!(c.lease.starts_with("l_"));
    s.fake.send(stream, checked("ok")).await;
    let Ok(done) = task.await.unwrap() else {
        panic!("the check failed")
    };
    assert_eq!(
        (done.result.as_str(), done.runner.as_str()),
        ("ok", s.runner.as_str())
    );
    let (result, at): (Option<String>, Option<String>) =
        sqlx::query_as("SELECT last_test_result, last_test_at FROM core_accounts WHERE id = ?")
            .bind(s.account.id)
            .fetch_one(&s.core.app.pool)
            .await
            .unwrap();
    assert!(at.is_some());
    assert_eq!(result.as_deref(), Some("ok"));
    let trail: Vec<String> =
        sqlx::query_scalar("SELECT action || ' ' || details FROM audit_events")
            .fetch_all(&s.core.app.pool)
            .await
            .unwrap();
    let trail = trail.join("\n");
    assert!(trail.contains("account.tested"), "{trail}");
    assert!(trail.contains("\"to\":\"plan-check\""), "{trail}");
    assert!(!trail.contains(super::login::TOKEN), "no token in any row");

    // A second check within a minute is refused, and sends nothing.
    let again = plan_check::run(&s.core.app, &caller(&s).await, s.account.id).await;
    assert!(matches!(again, Err(Failed::Soon(_))));
}

#[tokio::test]
async fn the_runners_reason_comes_back_as_it_is() {
    let mut s = up("pc-expired").await;
    let who = caller(&s).await;
    let (app, id) = (s.core.app.clone(), s.account.id);
    let task = tokio::spawn(async move { plan_check::run(&app, &who, id).await });
    let (stream, _) = command(&mut s.fake).await;
    s.fake.send(stream, checked("token_expired")).await;
    let Ok(done) = task.await.unwrap() else {
        panic!("the check failed")
    };
    assert_eq!(done.result, "token_expired");
}

#[tokio::test]
async fn a_runner_without_plan_check_is_outdated_and_is_never_leased_the_token() {
    let s = up_with("pc-old", false).await;
    let done = plan_check::run(&s.core.app, &caller(&s).await, s.account.id).await;
    let Ok(done) = done else { panic!("no answer") };
    assert_eq!(done.result, "runner_outdated");
    let leased: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'secret.leased'")
            .fetch_one(&s.core.app.pool)
            .await
            .unwrap();
    assert_eq!(leased, 0);
}

/// The windows Claude reported on the check's answer are kept like a session's: same row, same
/// shape, stamped with the check's time; an answer without them leaves the last ones.
#[tokio::test]
async fn a_check_answer_with_windows_keeps_them_like_a_sessions() {
    let mut s = up("pc-windows").await;
    assert_eq!(stored(&s).await, None);
    let who = caller(&s).await;
    let (app, id) = (s.core.app.clone(), s.account.id);
    let task = tokio::spawn(async move { plan_check::run(&app, &who, id).await });
    let (stream, _) = command(&mut s.fake).await;
    s.fake
        .send(stream, with_windows("ok", Some(windows())))
        .await;
    assert!(task.await.unwrap().is_ok());
    let got = stored(&s).await.expect("the check's windows");
    let (at, now) = (got["at"].as_i64().unwrap(), s.core.app.clock.unix());
    assert!(
        (now - 5..=now).contains(&at),
        "stamped at the check: {at} vs {now}"
    );
    assert_eq!(got["plan"], serde_json::to_value(windows()).unwrap());
}

/// A plan account nothing runs on: the refresh checks it on an idle runner and keeps its windows;
/// fresh windows, a recent check, a turned-off account or an expired sign-in are left alone.
#[tokio::test]
async fn the_refresh_checks_an_unused_plan_and_skips_the_rest() {
    let mut s = up("pc-refresh").await;
    let a = s.account.clone();
    let now = s.core.app.clock.unix();
    let old = now - plan_check::REFRESH_AFTER_SECS;
    assert!(plan_check::wants_refresh(&a, None, now), "never said");
    assert!(plan_check::wants_refresh(&a, Some(old), now), "hours old");
    assert!(!plan_check::wants_refresh(&a, Some(old + 1), now), "fresh");
    let iso = |t: i64| ainkrad_core_server::scheduler::iso_of_unix(t);
    let tested = |at: i64, r: &str| accounts::Account {
        last_test_at: Some(iso(at)),
        last_test_result: Some(r.to_owned()),
        ..a.clone()
    };
    assert!(
        !plan_check::wants_refresh(&tested(now - 60, "failed"), None, now),
        "checked just now"
    );
    assert!(plan_check::wants_refresh(&tested(old, "failed"), None, now));
    assert!(
        !plan_check::wants_refresh(&tested(old, "token_expired"), None, now),
        "signed out"
    );
    for state in ["disabled", "cooling", "limited", "unhealthy"] {
        let off = accounts::Account {
            state: state.to_owned(),
            ..a.clone()
        };
        assert!(!plan_check::wants_refresh(&off, None, now), "{state}");
    }
    let key = accounts::Account {
        provider: "anthropic".to_owned(),
        ..a.clone()
    };
    assert!(
        !plan_check::wants_refresh(&key, None, now),
        "an API key has no plan"
    );

    // Due: one check goes to the idle runner and its windows are kept.
    let app = s.core.app.clone();
    let task = tokio::spawn(async move { plan_check::refresh(&app).await });
    let (stream, cmd) = command(&mut s.fake).await;
    assert!(matches!(cmd, Command::PlanCheck(_)), "{cmd:?}");
    s.fake
        .send(stream, with_windows("ok", Some(windows())))
        .await;
    task.await.unwrap();
    assert!(stored(&s).await.is_some());
    // Fresh now: the next pass sends nothing (a sent check would wait for an answer).
    let pass = plan_check::refresh(&s.core.app);
    tokio::time::timeout(Duration::from_secs(5), pass)
        .await
        .expect("nothing sent");

    // Turned off, never checked and never said: still nothing.
    sqlx::query(
        "UPDATE core_accounts SET state = 'disabled', plan_limit = NULL, last_test_at = NULL \
         WHERE id = ?",
    )
    .bind(s.account.id)
    .execute(&s.core.app.pool)
    .await
    .unwrap();
    let pass = plan_check::refresh(&s.core.app);
    tokio::time::timeout(Duration::from_secs(5), pass)
        .await
        .expect("a turned-off account is never checked");
    let leased: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'secret.leased'")
            .fetch_one(&s.core.app.pool)
            .await
            .unwrap();
    assert_eq!(leased, 1, "only the one due check");
}
