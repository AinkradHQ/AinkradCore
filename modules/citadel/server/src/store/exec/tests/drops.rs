//! Provider drops per account (E15.4): counted against the run's account with the resume's
//! prompt, three in ten minutes make it unhealthy (skipped at dispatch), and it comes back
//! once the window has passed.

use citadel_core::audit::AuditActor;
use citadel_core::gov::{AccountId, AccountStatus};

use super::wake::{runner, wake};
use super::*;
use crate::store::gov::{
    account_usage, assign_account, create_account, get_account, new_account, record_drop,
};

/// The `account.drop_window_secs` default (also `account.unhealthy_secs`).
const DROP_WINDOW_SECS: i64 = 600;

const BY: AuditActor = AuditActor::User(UserId(1));

fn at(secs: i64) -> String {
    let t = 10 * 3600 + secs;
    format!(
        "2026-10-22T{:02}:{:02}:{:02}.000Z",
        t / 3600,
        t / 60 % 60,
        t % 60
    )
}

#[tokio::test]
async fn three_drops_in_the_window_make_an_account_unhealthy_until_it_passes() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, i) = fixture(pool, "A").await;
    let company = crate::store::org::get_agent(pool, dev)
        .await
        .unwrap()
        .unwrap()
        .company_id;
    let new = new_account(pool, Harness::Claude, "flaky", None, None, None, None);
    let flaky = create_account(pool, &new.await.unwrap(), BY)
        .await
        .unwrap()
        .id;
    assign_account(pool, flaky, company, true, BY)
        .await
        .unwrap();
    let r = runner(pool, "box").await;
    enqueue_wake(pool, &wake(dev, Some(i), "w")).await.unwrap();
    let run = dispatch_next(pool, r, &[], &Harness::ALL, &at(0))
        .await
        .unwrap()
        .unwrap();
    let by = AuditActor::Runner(r);
    let status = |a: AccountId| async move { get_account(pool, a).await.unwrap().unwrap() };
    // Two drops 9 minutes apart, then one at +11 min: the first has left the window.
    for secs in [60, 600, 660] {
        record_drop(pool, run.id, "API Error: Connection error.", by, &at(secs))
            .await
            .unwrap();
    }
    assert_eq!(
        status(flaky).await.status,
        AccountStatus::Active,
        "2 in the window"
    );
    record_drop(pool, run.id, "API Error: Connection error.", by, &at(700))
        .await
        .unwrap();
    let sick = status(flaky).await;
    assert_eq!(sick.status, AccountStatus::Unhealthy);
    assert_eq!(
        sick.status_reason.as_deref(),
        Some("the provider dropped 3 turns in 10m")
    );
    assert_eq!(sick.status_until, Some(at(700 + DROP_WINDOW_SECS)));
    let usage = account_usage(pool, &at(700)).await.unwrap();
    assert_eq!(usage[0].drops, 3);
    // Every drop is audited on the run, and each resume is a message: 1 dispatch + 4.
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'run.provider_dropped' AND run_id = ?",
    )
    .bind(run.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(audited, 4);
    assert_eq!(usage[0].companies[0].messages, 5);

    // Skipped while unhealthy; back once the window has passed.
    start_run(pool, run.id, by, None, &at(710)).await.unwrap();
    transition_run(
        pool,
        run.id,
        by,
        &citadel_core::exec::RunEvent::Succeed,
        &at(710),
    )
    .await
    .unwrap();
    enqueue_wake(pool, &wake(dev, Some(i), "w2")).await.unwrap();
    let skipped = dispatch_next(pool, r, &[], &Harness::ALL, &at(720)).await;
    assert!(skipped.unwrap().is_none());
    let back = dispatch_next(pool, r, &[], &Harness::ALL, &at(700 + DROP_WINDOW_SECS)).await;
    assert!(back.unwrap().is_some());
    assert_eq!(status(flaky).await.status, AccountStatus::Active);
}
