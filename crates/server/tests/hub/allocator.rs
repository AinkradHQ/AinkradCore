//! The allocator through the hub (KAN-437 S4), with a runner played by hand: a chain session with
//! no account yet never reaches `agent.start` (the runner would use its own login), waits while
//! every account cools and starts on the account that comes back (its grant passes), ends when
//! nothing will be available soon, and is picked again when a launch refuses the account the pick
//! chose.

use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::scheduler::iso_of_unix;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_core_server::store::alloc::Entry;
use ainkrad_core_server::store::{accounts, pools};
use serde_json::json;

use super::Core;
use super::gateway::{W, command, policy, started, until, up};

fn entry(pool: i64) -> Entry {
    Entry {
        pool,
        provider: "anthropic".to_owned(),
        harness: "claude".to_owned(),
        model: Some("claude-x".to_owned()),
    }
}

async fn pool_of(core: &Core, runner: &str, accounts: &[i64]) -> Entry {
    let (p, now) = (&core.app.pool, core.app.clock.now());
    let made = pools::create(p, "main", "anthropic", runner, AuditActor::System, &now)
        .await
        .unwrap();
    for id in accounts {
        pools::add_member(p, made.id, *id, runner, AuditActor::System, &now)
            .await
            .unwrap();
    }
    entry(made.id)
}

/// A `starting` chain session with no account, supervised in the background.
async fn chain_session(core: &Core, runner: &str, chain: &[Entry]) -> String {
    let policy = policy();
    let new = NewSession {
        runner,
        harness: "claude",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: runner,
    };
    let now = core.app.clock.now();
    let s = sessions::create(&core.app.pool, &new, AuditActor::System, &now)
        .await
        .unwrap();
    sqlx::query("UPDATE core_agent_sessions SET chain = ? WHERE id = ?")
        .bind(json!(chain).to_string())
        .bind(&s.id)
        .execute(&core.app.pool)
        .await
        .unwrap();
    service::authorize_for_tests(&core.app, &s.id);
    let (app, row) = (core.app.clone(), s.clone());
    tokio::spawn(async move {
        let _ = service::start(&app, &row).await;
    });
    s.id
}

async fn cool(core: &Core, account: i64, secs: i64) {
    let until = iso_of_unix(core.app.clock.unix() + secs);
    sqlx::query(
        "UPDATE core_accounts SET state = 'cooling', state_reason = 'rate_limited', \
         state_until = ? WHERE id = ?",
    )
    .bind(until)
    .bind(account)
    .execute(&core.app.pool)
    .await
    .unwrap();
}

async fn no_start(fake: &mut super::Fake) {
    let got = tokio::time::timeout(Duration::from_millis(600), command(fake)).await;
    assert!(got.is_err(), "nothing is started: {:?}", got.map(|c| c.1));
}

#[tokio::test]
async fn a_waiting_session_never_starts_and_starts_on_the_account_that_comes_back() {
    let (core, mut fake, runner, account) = up("alloc-wait", true, None).await;
    let chain = [pool_of(&core, &runner, &[account.id]).await];
    cool(&core, account.id, 600).await;
    let session = chain_session(&core, &runner, &chain).await;
    no_start(&mut fake).await;
    let (state, waiting, held): (String, Option<String>, Option<i64>) =
        sqlx::query_as("SELECT state, waiting, account_id FROM core_agent_sessions WHERE id = ?")
            .bind(&session)
            .fetch_one(&core.app.pool)
            .await
            .unwrap();
    assert_eq!((state.as_str(), held), ("starting", None));
    assert!(
        waiting.unwrap().contains("cooling"),
        "the row says why it waits"
    );
    // The cooldown is lifted (the admin's "it's fine"): the next pick takes the account.
    sqlx::query(
        "UPDATE core_accounts SET state = 'active', state_reason = NULL, state_until = NULL",
    )
    .execute(&core.app.pool)
    .await
    .unwrap();
    let mut w = W {
        core,
        fake,
        runner,
        account,
        session,
    };
    started(&mut w, u64::MAX).await;
    until("the start", &w.core, &w.session, |s| s.state == "running").await;
    let row = sessions::get(&w.core.app.pool, &w.session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.gateway_account_id, Some(w.account.id));
    assert_eq!(
        row.secrets.len(),
        1,
        "the account's own secret, nothing else"
    );
    let waiting: Option<String> =
        sqlx::query_scalar("SELECT waiting FROM core_agent_sessions WHERE id = ?")
            .bind(&w.session)
            .fetch_one(&w.core.app.pool)
            .await
            .unwrap();
    assert_eq!(waiting, None);
}

#[tokio::test]
async fn a_session_with_nothing_available_soon_ends_and_never_starts() {
    let (core, mut fake, runner, account) = up("alloc-exhausted", true, None).await;
    let chain = [pool_of(&core, &runner, &[account.id]).await];
    cool(&core, account.id, 7200).await;
    let session = chain_session(&core, &runner, &chain).await;
    until("the end", &core, &session, |s| !s.live()).await;
    let s = sessions::get(&core.app.pool, &session)
        .await
        .unwrap()
        .unwrap();
    assert!(
        s.outcome
            .unwrap()
            .to_string()
            .contains("no account is available")
    );
    no_start(&mut fake).await;
}

#[tokio::test]
async fn a_launch_that_refuses_the_picked_account_picks_another() {
    let (core, fake, runner, a) = up("alloc-repick", true, None).await;
    let now = core.app.clock.now();
    let sealer = core.app.secrets.as_deref().unwrap();
    let new = accounts::NewAccount {
        provider: "anthropic",
        label: "second",
        value: "throwaway-account-value-two-77d0be",
        runners: std::slice::from_ref(&runner),
        cap: None,
    };
    let b = accounts::create(
        &core.app.pool,
        sealer,
        &new,
        &runner,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    let chain = [pool_of(&core, &runner, &[a.id, b.id]).await];
    // The row as a pick left it: on the first account, which is then disabled before the launch.
    let policy = policy();
    let secret = json!([{"name": a.secret_name, "var": "ANTHROPIC_API_KEY"}]);
    let new = NewSession {
        runner: &runner,
        harness: "claude",
        model: Some("claude-x"),
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &runner,
    };
    let s = sessions::create(&core.app.pool, &new, AuditActor::System, &now)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE core_agent_sessions SET chain = ?, chain_pos = 0, account_id = ?, \
         gateway_account_id = ?, secrets = ? WHERE id = ?",
    )
    .bind(json!(chain).to_string())
    .bind(a.id)
    .bind(a.id)
    .bind(secret.to_string())
    .bind(&s.id)
    .execute(&core.app.pool)
    .await
    .unwrap();
    accounts::set_state(
        &core.app.pool,
        a.id,
        "disabled",
        None,
        None,
        &runner,
        AuditActor::System,
        &now,
    )
    .await
    .unwrap();
    service::authorize_for_tests(&core.app, &s.id);
    let (app, row) = (
        core.app.clone(),
        sessions::get(&core.app.pool, &s.id).await.unwrap().unwrap(),
    );
    tokio::spawn(async move {
        let _ = service::start(&app, &row).await;
    });
    let mut w = W {
        core,
        fake,
        runner,
        account: b.clone(),
        session: s.id.clone(),
    };
    started(&mut w, u64::MAX).await;
    until("the start", &w.core, &s.id, |s| s.state == "running").await;
    let (account, tried): (i64, String) =
        sqlx::query_as("SELECT account_id, tried_accounts FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(&w.core.app.pool)
            .await
            .unwrap();
    assert_eq!((account, tried), (b.id, json!([a.id]).to_string()));
}
