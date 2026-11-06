//! A chain session made by `chains::create_session` (S5), the path S7's create route takes, is
//! picked by S4's allocator and launched by the supervisor: nothing but the store call, no SQL
//! to stage the row. It waits for its account (never starts on the runner's own login) and starts
//! on the chain's entry, with the entry's harness and model.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents as service;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_core_server::store::alloc::Entry;
use ainkrad_core_server::store::chains::{self, EntrySpec, Request};
use ainkrad_core_server::store::pools;

use super::gateway::{W, policy, started, until, up};

#[tokio::test]
async fn a_chain_session_from_create_session_is_picked_and_launched() {
    let (core, fake, runner, account) = up("chain-create", true, None).await;
    let (p, now) = (&core.app.pool, core.app.clock.now());
    let pool = pools::create(p, "main", "anthropic", &runner, AuditActor::System, &now)
        .await
        .unwrap();
    pools::add_member(p, pool.id, account.id, &runner, AuditActor::System, &now)
        .await
        .unwrap();
    let spec = [EntrySpec {
        pool: pool.id,
        model: Some("claude-x"),
        harness: None,
    }];
    let chain = chains::create(p, 1, "main", &spec, &runner, AuditActor::System, &now)
        .await
        .unwrap();
    let policy = policy();
    let new = NewSession {
        runner: &runner,
        harness: "",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &runner,
    };
    let req = Request {
        user_id: 1,
        chain: Some(chain.id),
        agent: Some("agent-1"),
    };
    let s = chains::create_session(p, &new, None, None, req, AuditActor::System, &now)
        .await
        .unwrap();
    // As stored: a chain snapshot S4 reads, and no account yet.
    let (snap, account_id, pos): (String, Option<i64>, Option<i64>) =
        sqlx::query_as("SELECT chain, account_id, chain_pos FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(p)
            .await
            .unwrap();
    let entries: Vec<Entry> = serde_json::from_str(&snap).unwrap();
    assert_eq!(entries, chain.entries);
    assert_eq!((account_id, pos), (None, None));
    // The supervisor holds it until the pick has given it an account, then starts it.
    service::authorize_for_tests(&core.app, &s.id);
    let (app, row) = (core.app.clone(), s.clone());
    tokio::spawn(async move {
        let _ = service::start(&app, &row).await;
    });
    let mut w = W {
        core,
        fake,
        runner,
        account,
        session: s.id.clone(),
    };
    started(&mut w, u64::MAX).await;
    until("the start", &w.core, &w.session, |s| s.state == "running").await;
    let row = sessions::get(&w.core.app.pool, &w.session)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.gateway_account_id, Some(w.account.id));
    assert_eq!(
        (row.harness.as_str(), row.model.as_deref()),
        ("claude", Some("claude-x"))
    );
    let held: Option<i64> =
        sqlx::query_scalar("SELECT account_id FROM core_agent_sessions WHERE id = ?")
            .bind(&w.session)
            .fetch_one(&w.core.app.pool)
            .await
            .unwrap();
    assert_eq!(held, Some(w.account.id));
}
