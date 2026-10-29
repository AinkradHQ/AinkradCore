//! How a run's account is picked and what happens when none is free are settings
//! (`account.pick_strategy`, `account.at_limit`); transcripts are pruned after
//! `transcript.retention_secs`.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::RunEvent;
use ainkrad_core::gov::AccountStatus;
use ainkrad_core::org::ModelRoute;
use ainkrad_core::settings::{Key, Scope};
use serde_json::json;

use super::accounts::{account, at, fresh_issue, next_account};
use super::lease::{assigned, working};
use super::settings::set;
use super::wake::{dispatch, runner, wake};
use super::*;
use crate::store::gov::set_account_status;
use crate::store::org::set_fallbacks;

const BY: AuditActor = AuditActor::User(UserId(1));

#[tokio::test]
async fn fill_first_keeps_to_the_first_account_until_it_is_limited() {
    let db = db().await;
    let pool = &db.pool;
    let a = create_company(pool, "A").await.unwrap().id;
    let dev = agent(pool, a).await;
    let one = account(pool, "claude-1", a).await;
    let two = account(pool, "claude-2", a).await;
    let r = runner(pool, "box").await;
    set(pool, Key::AccountPickStrategy, Scope::Company(a), 2).await;
    for minute in 1..=3 {
        assert_eq!(next_account(pool, dev, a, r, minute).await, Some(one));
    }
    set_account_status(pool, one, AccountStatus::Disabled, None, BY)
        .await
        .unwrap();
    assert_eq!(next_account(pool, dev, a, r, 4).await, Some(two));
}

#[tokio::test]
async fn at_limit_a_run_falls_to_the_next_entry_or_waits() {
    let db = db().await;
    let pool = &db.pool;
    let a = create_company(pool, "A").await.unwrap().id;
    let dev = agent(pool, a).await;
    let only = account(pool, "claude-1", a).await;
    // The chain's next entry is a harness with no account in the pool: the runner's login.
    let next = ModelRoute {
        harness: Harness::Opencode,
        model: "opencode/big-pickle".to_owned(),
    };
    set_fallbacks(pool, dev, std::slice::from_ref(&next), BY)
        .await
        .unwrap();
    set_account_status(pool, only, AccountStatus::Disabled, None, BY)
        .await
        .unwrap();
    let r = runner(pool, "box").await;
    let i = fresh_issue(pool, a).await;
    enqueue_wake(pool, &wake(dev, Some(i), "w1")).await.unwrap();
    let run = dispatch(pool, r, &at(1)).await.expect("the next entry");
    assert_eq!(run.harness, Harness::Opencode);
    let by = AuditActor::Runner(r);
    start_run(pool, run.id, by, None, &at(1)).await.unwrap();
    transition_run(pool, run.id, by, &RunEvent::Succeed, &at(1))
        .await
        .unwrap();

    set(pool, Key::AccountAtLimit, Scope::Company(a), 1).await;
    let i = fresh_issue(pool, a).await;
    enqueue_wake(pool, &wake(dev, Some(i), "w2")).await.unwrap();
    assert!(
        dispatch(pool, r, &at(2)).await.is_none(),
        "waits for its first entry's account"
    );
}

#[tokio::test]
async fn transcripts_are_pruned_after_their_retention_and_the_run_says_so() {
    let db = db().await;
    let pool = &db.pool;
    let (dev, _) = assigned(pool, "A").await;
    let mac = runner(pool, "mac").await;
    let now = "2026-10-21T10:00:00.000Z";
    let run = working(pool, mac, now).await;
    let chunk = json!({"type": "assistant_text", "text": "hi"});
    append_run_event(pool, run.id, mac, 1, &chunk, now)
        .await
        .unwrap();
    transition_run(
        pool,
        run.id,
        AuditActor::Runner(mac),
        &RunEvent::Succeed,
        now,
    )
    .await
    .unwrap();
    // The engine stamps the end with the wall clock; pin it to the test's.
    sqlx::query("UPDATE runs SET ended_at = ? WHERE id = ?")
        .bind(now)
        .bind(run.id.0)
        .execute(pool)
        .await
        .unwrap();
    let later = "2026-10-21T12:00:00.000Z";
    assert!(
        prune_transcripts(pool, later).await.unwrap().is_empty(),
        "kept by default"
    );

    let company = crate::store::org::get_agent(pool, dev)
        .await
        .unwrap()
        .unwrap()
        .company_id;
    set(
        pool,
        Key::TranscriptRetentionSecs,
        Scope::Company(company),
        3 * 3600,
    )
    .await;
    assert!(
        prune_transcripts(pool, later).await.unwrap().is_empty(),
        "not yet"
    );
    let much_later = "2026-10-21T14:00:00.000Z";
    assert_eq!(prune_transcripts(pool, much_later).await.unwrap(), [run.id]);
    assert!(list_run_events(pool, run.id).await.unwrap().is_empty());
    let run = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(run.transcript_pruned_at.as_deref(), Some(much_later));
    assert!(
        prune_transcripts(pool, much_later)
            .await
            .unwrap()
            .is_empty(),
        "once"
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'run.transcripts_pruned'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(audited, 1);
}
