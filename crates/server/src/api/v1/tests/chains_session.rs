//! Chains on sessions (S5; design 2026-11-06 §4.2, §4.5): the snapshot, the resolution order, the
//! sessions that are refused without leaving a row, and the deletion of a chain a run walks.

use serde_json::json;

use super::chains::{BY, code, make, order_of, pool, setup, spec};
use super::*;
use crate::store::agents::{self as store, NewSession, SessionSecret};
use crate::store::chains::{self as ch, EntrySpec, Request};
use crate::store::secrets::Error;

pub(super) async fn session(
    fx: &Fx,
    secrets: &[SessionSecret],
    owner: Option<&str>,
    req: Request<'_>,
) -> Result<store::Session, Error> {
    let policy = json!({"mode": "ask", "min_isolation": "process"});
    let new = NewSession {
        runner: &fx.dev.id,
        harness: "claude",
        model: Some("placeholder"),
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets,
        created_by: &fx.dev.id,
    };
    ch::create_session(&fx.app.pool, &new, owner, None, req, BY, NOW).await
}

fn ask(chain: Option<i64>, agent: Option<&str>) -> Request<'_> {
    Request {
        user_id: 1,
        chain,
        agent,
    }
}

async fn sessions(fx: &Fx) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM core_agent_sessions")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_chain_a_live_session_walks_is_not_deleted() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    ch::bind(p, "agent-1", c.id, "d_x", BY, NOW).await.unwrap();
    let s = session(&fx, &[], None, ask(Some(c.id), None))
        .await
        .unwrap();
    assert_eq!(code(ch::delete(p, c.id, "d_x", BY).await), "conflict");
    for state in ["running", "interrupted"] {
        sqlx::query("UPDATE core_agent_sessions SET state = ? WHERE id = ?")
            .bind(state)
            .bind(&s.id)
            .execute(p)
            .await
            .unwrap();
        assert_eq!(
            code(ch::delete(p, c.id, "d_x", BY).await),
            "conflict",
            "{state}"
        );
    }
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended' WHERE id = ?")
        .bind(&s.id)
        .execute(p)
        .await
        .unwrap();
    ch::delete(p, c.id, "d_x", BY).await.unwrap();
    assert!(
        ch::list_bindings(p).await.unwrap().is_empty(),
        "bindings went with it"
    );
    // The ended run keeps its snapshot after the chain is gone.
    let mut conn = p.acquire().await.unwrap();
    assert_eq!(
        order_of(&ch::session_chain(&mut conn, &s.id).await.unwrap().unwrap()),
        [a]
    );
    assert_eq!(code(ch::delete(p, c.id, "d_x", BY).await), "not_found");
}

#[tokio::test]
async fn a_session_snapshots_its_chain_and_an_edit_does_not_move_it() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let (a, o) = (
        pool(&fx, "a", "anthropic").await,
        pool(&fx, "o", "openai").await,
    );
    let s1 = pool(&fx, "s", "claude-sub").await;
    let model = EntrySpec {
        model: Some("gpt-test"),
        ..spec(o)
    };
    let c = ch::create(p, 1, "main", &[spec(s1), spec(a), model], "d_x", BY, NOW)
        .await
        .unwrap();
    let s = session(&fx, &[], None, ask(Some(c.id), Some("agent-7")))
        .await
        .unwrap();
    // The row is a placeholder (the first entry's harness and model) until the allocator picks.
    assert_eq!(
        (s.harness.as_str(), s.model.as_deref(), s.state.as_str()),
        ("claude", None, "starting")
    );
    let (cid, agent): (Option<i64>, Option<String>) =
        sqlx::query_as("SELECT chain_id, agent FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(p)
            .await
            .unwrap();
    assert_eq!((cid, agent.as_deref()), (Some(c.id), Some("agent-7")));
    ch::update(p, c.id, "main", &[spec(o)], "d_x", BY, NOW)
        .await
        .unwrap();
    let mut conn = p.acquire().await.unwrap();
    let snap = ch::session_chain(&mut conn, &s.id).await.unwrap().unwrap();
    assert_eq!(snap, c.entries, "a snapshot, not a reference");
    assert_eq!(snap[2].model.as_deref(), Some("gpt-test"));
}

#[tokio::test]
async fn a_new_session_gets_the_named_chain_then_the_agents_then_the_default_then_none() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let (a, o, g) = (
        pool(&fx, "a", "anthropic").await,
        pool(&fx, "o", "openai").await,
        pool(&fx, "g", "google").await,
    );
    let (named, bound, default) = (
        make(&fx, "named", &[a]).await,
        make(&fx, "bound", &[o]).await,
        make(&fx, "dflt", &[g]).await,
    );
    let chain_of = |s: &store::Session| {
        let id = s.id.clone();
        let p = p.clone();
        async move {
            sqlx::query_scalar::<_, Option<i64>>(
                "SELECT chain_id FROM core_agent_sessions WHERE id = ?",
            )
            .bind(id)
            .fetch_one(&p)
            .await
            .unwrap()
        }
    };
    // Nothing configured: a plain session, as before, with the agent recorded.
    let none = session(&fx, &[], None, ask(None, Some("agent-1")))
        .await
        .unwrap();
    assert_eq!(chain_of(&none).await, None);
    assert_eq!(
        none.model.as_deref(),
        Some("placeholder"),
        "a plain session is untouched"
    );
    ch::bind(p, "agent-1", bound.id, "d_x", BY, NOW)
        .await
        .unwrap();
    ch::set_default(p, default.id, "d_x", BY, NOW)
        .await
        .unwrap();
    let s = session(&fx, &[], None, ask(Some(named.id), Some("agent-1")))
        .await
        .unwrap();
    assert_eq!(
        chain_of(&s).await,
        Some(named.id),
        "the request's chain wins"
    );
    let s = session(&fx, &[], None, ask(None, Some("agent-1")))
        .await
        .unwrap();
    assert_eq!(
        chain_of(&s).await,
        Some(bound.id),
        "then the agent's binding"
    );
    let s = session(&fx, &[], None, ask(None, Some("agent-2")))
        .await
        .unwrap();
    assert_eq!(chain_of(&s).await, Some(default.id), "then the default");
    let s = session(&fx, &[], None, ask(None, None)).await.unwrap();
    assert_eq!(chain_of(&s).await, Some(default.id));
    ch::unbind(p, "agent-1", "d_x", BY).await.unwrap();
    let s = session(&fx, &[], None, ask(None, Some("agent-1")))
        .await
        .unwrap();
    assert_eq!(
        chain_of(&s).await,
        Some(default.id),
        "an unbound agent falls back"
    );
    assert_eq!(code(ch::unbind(p, "agent-1", "d_x", BY).await), "not_found");
    // Setting another default moves it.
    ch::set_default(p, named.id, "d_x", BY, NOW).await.unwrap();
    let defaults: Vec<i64> = sqlx::query_scalar("SELECT id FROM core_chains WHERE is_default = 1")
        .fetch_all(p)
        .await
        .unwrap();
    assert_eq!(defaults, [named.id]);
}

#[tokio::test]
async fn a_chain_session_that_cannot_have_its_chain_is_never_stored() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    let before = sessions(&fx).await;
    // A pinned account never fails over: a chain and an `acct.*` secret do not mix.
    let pinned = [SessionSecret {
        name: "acct.anthropic.1".to_owned(),
        var: "ANTHROPIC_API_KEY".to_owned(),
    }];
    let r = session(&fx, &pinned, None, ask(Some(c.id), None)).await;
    assert_eq!(code(r), "bad_request");
    // A module's session takes no chain.
    let r = session(&fx, &[], Some("citadel"), ask(Some(c.id), None)).await;
    assert_eq!(code(r), "bad_request");
    // A chain that is missing, or another user's.
    assert_eq!(
        code(session(&fx, &[], None, ask(Some(9999), None)).await),
        "not_found"
    );
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(p)
        .await
        .unwrap();
    sqlx::query("UPDATE core_pools SET user_id = 2 WHERE id = ?")
        .bind(a)
        .execute(p)
        .await
        .unwrap();
    let theirs = ch::create(p, 2, "theirs", &[spec(a)], "d_x", BY, NOW)
        .await
        .unwrap();
    assert_eq!(
        code(session(&fx, &[], None, ask(Some(theirs.id), None)).await),
        "not_found"
    );
    // A bad agent id.
    assert_eq!(
        code(session(&fx, &[], None, ask(None, Some("bad agent!"))).await),
        "bad_request"
    );
    assert_eq!(
        sessions(&fx).await,
        before,
        "no refused request left a row behind"
    );
    // A running session, or one with a chain already, takes none.
    let ok = session(&fx, &[], None, ask(Some(c.id), None))
        .await
        .unwrap();
    let mut conn = p.acquire().await.unwrap();
    assert_eq!(
        code(ch::assign_in(&mut conn, &ok.id, c.id, None).await),
        "conflict"
    );
}

#[tokio::test]
async fn bindings_need_a_chain_and_a_valid_agent() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    assert_eq!(
        code(ch::bind(p, "bad agent!", c.id, "d_x", BY, NOW).await),
        "bad_request"
    );
    assert_eq!(
        code(ch::bind(p, "ag", 9999, "d_x", BY, NOW).await),
        "not_found"
    );
    let d = make(&fx, "other", &[a]).await;
    ch::bind(p, "ag", c.id, "d_x", BY, NOW).await.unwrap();
    ch::bind(p, "ag", d.id, "d_x", BY, NOW).await.unwrap();
    let all = ch::list_bindings(p).await.unwrap();
    assert_eq!(
        (all.len(), all[0].chain_id),
        (1, d.id),
        "rebinding replaces"
    );
}
