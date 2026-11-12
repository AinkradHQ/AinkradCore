//! `POST /accounts/{id}/check` for a Claude plan (N36), with a runner played by hand: the token is
//! leased to a runner that lists `plan-check`, the one fixed op carries only the lease, the answer
//! is recorded as the account's last test and audited, an old runner and a second check within a
//! minute are told apart, and an API-key account is left to its key test.

use ainkrad_core_server::agents::plan_check::{self, Failed};
use ainkrad_core_server::api::v1::Caller;
use ainkrad_core_server::store::gov;
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
    Body::Result(Reply::PlanCheck(PlanChecked {
        result: result.to_owned(),
        latency_ms: 9,
    }))
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
