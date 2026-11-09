//! Chains on sessions (S5; design 2026-11-06 §4.2, §4.5): the snapshot, the resolution order, the
//! sessions that are refused without leaving a row, and the deletion of a chain a run walks.

use serde_json::json;

use super::chains::{BY, code, make, order_of, pool, setup, spec};
use super::*;
use crate::store::agents::{self as store, NewSession, SessionSecret};
use crate::store::chains::{self as ch, EntrySpec, Request};
use crate::store::secrets::Error;

/// A session as a request that names a chain makes it: no harness, no model.
pub(super) async fn session(
    fx: &Fx,
    secrets: &[SessionSecret],
    owner: Option<&str>,
    req: Request<'_>,
) -> Result<store::Session, Error> {
    session_as(fx, secrets, owner, req, "", None).await
}

/// A session as a request that names no chain makes it: its own harness and model.
async fn plain(fx: &Fx, owner: Option<&str>, req: Request<'_>) -> Result<store::Session, Error> {
    session_as(fx, &[], owner, req, "claude", Some("placeholder")).await
}

async fn session_as(
    fx: &Fx,
    secrets: &[SessionSecret],
    owner: Option<&str>,
    req: Request<'_>,
    harness: &str,
    model: Option<&str>,
) -> Result<store::Session, Error> {
    let policy = json!({"mode": "ask", "min_isolation": "process"});
    let new = NewSession {
        runner: &fx.dev.id,
        harness,
        model,
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
async fn a_new_session_gets_the_named_chain_then_the_agents_then_the_default_for_an_agent_and_else_none()
 {
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
    let none = plain(&fx, None, ask(None, Some("agent-1"))).await.unwrap();
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
    // A request that names no chain and no agent gets NO chain, whatever the default (§4.5 item 3):
    // plain, and a module's session alike, with the harness and model they asked for.
    for owner in [None, Some("citadel")] {
        let s = plain(&fx, owner, ask(None, None)).await.unwrap();
        assert_eq!(chain_of(&s).await, None, "{owner:?}");
        assert_eq!(
            (s.harness.as_str(), s.model.as_deref()),
            ("claude", Some("placeholder"))
        );
        let chain: Option<String> =
            sqlx::query_scalar("SELECT chain FROM core_agent_sessions WHERE id = ?")
                .bind(&s.id)
                .fetch_one(p)
                .await
                .unwrap();
        assert_eq!(chain, None);
    }
    ch::unbind(p, 1, "agent-1", "d_x", BY).await.unwrap();
    let s = session(&fx, &[], None, ask(None, Some("agent-1")))
        .await
        .unwrap();
    assert_eq!(
        chain_of(&s).await,
        Some(default.id),
        "an unbound agent falls back"
    );
    assert_eq!(
        code(ch::unbind(p, 1, "agent-1", "d_x", BY).await),
        "not_found"
    );
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

#[tokio::test]
async fn a_chain_session_names_no_harness_or_model_and_a_plain_one_names_its_harness() {
    let fx = setup().await;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    let before = sessions(&fx).await;
    for (harness, model) in [
        ("claude", None),
        ("", Some("claude-sonnet")),
        ("codex", Some("x")),
    ] {
        let r = session_as(&fx, &[], None, ask(Some(c.id), None), harness, model).await;
        assert_eq!(code(r), "bad_request", "{harness} {model:?}");
    }
    // The same through the agent's binding and the default.
    ch::bind(&fx.app.pool, "ag", c.id, "d_x", BY, NOW)
        .await
        .unwrap();
    let r = session_as(&fx, &[], None, ask(None, Some("ag")), "claude", None).await;
    assert_eq!(code(r), "bad_request");
    assert_eq!(
        code(session_as(&fx, &[], None, ask(None, None), "", None).await),
        "bad_request"
    );
    assert_eq!(sessions(&fx).await, before, "nothing was stored");
}

/// Two users may bind the same agent id, each to their own chain; neither replaces, resolves or
/// drops the other's, and the limits count per user.
#[tokio::test]
async fn bindings_are_per_user() {
    let fx = setup().await;
    let p = &fx.app.pool;
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(p)
        .await
        .unwrap();
    let (a, b) = (
        pool(&fx, "a", "anthropic").await,
        pool(&fx, "b", "openai").await,
    );
    sqlx::query("UPDATE core_pools SET user_id = 2 WHERE id = ?")
        .bind(b)
        .execute(p)
        .await
        .unwrap();
    let mine = make(&fx, "mine", &[a]).await;
    let theirs = ch::create(p, 2, "theirs", &[spec(b)], "d_x", BY, NOW)
        .await
        .unwrap();
    ch::bind(p, "shared-agent", mine.id, "d_x", BY, NOW)
        .await
        .unwrap();
    ch::bind(p, "shared-agent", theirs.id, "d_x", BY, NOW)
        .await
        .unwrap();
    let all = ch::list_bindings(p).await.unwrap();
    assert_eq!(
        all.iter()
            .map(|b| (b.user_id, b.chain_id))
            .collect::<Vec<_>>(),
        [(1, mine.id), (2, theirs.id)]
    );
    let mut conn = p.acquire().await.unwrap();
    for (user, want) in [(1, mine.id), (2, theirs.id)] {
        let got = ch::resolve_for(&mut conn, user, None, Some("shared-agent"))
            .await
            .unwrap();
        assert_eq!(got, Some(want), "user {user}");
    }
    drop(conn);
    // User 1 unbinding leaves user 2's binding; a user with none gets not_found.
    ch::unbind(p, 1, "shared-agent", "d_x", BY).await.unwrap();
    assert_eq!(
        code(ch::unbind(p, 1, "shared-agent", "d_x", BY).await),
        "not_found"
    );
    let left = ch::list_bindings(p).await.unwrap();
    assert_eq!((left.len(), left[0].user_id), (1, 2));
}

#[tokio::test]
async fn a_session_whose_secrets_cannot_be_read_takes_no_chain() {
    let fx = setup().await;
    let p = &fx.app.pool;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    let s = plain(&fx, None, ask(None, None)).await.unwrap();
    // The column's own CHECK keeps the JSON valid, so corrupt it to valid JSON of the wrong shape.
    sqlx::query("UPDATE core_agent_sessions SET secrets = '[{\"name\": 5}]' WHERE id = ?")
        .bind(&s.id)
        .execute(p)
        .await
        .unwrap();
    let mut conn = p.acquire().await.unwrap();
    assert_eq!(
        code(ch::assign_in(&mut conn, &s.id, c.id, None).await),
        "bad_request"
    );
    let chain: Option<String> =
        sqlx::query_scalar("SELECT chain FROM core_agent_sessions WHERE id = ?")
            .bind(&s.id)
            .fetch_one(p)
            .await
            .unwrap();
    assert_eq!(chain, None);
}

#[tokio::test]
async fn the_limits_count_per_user() {
    let fx = setup().await;
    let p = &fx.app.pool;
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(p)
        .await
        .unwrap();
    let a = pool(&fx, "a", "anthropic").await;
    let b = pool(&fx, "b", "anthropic").await;
    sqlx::query("UPDATE core_pools SET user_id = 2 WHERE id = ?")
        .bind(b)
        .execute(p)
        .await
        .unwrap();
    for i in 0..ch::MAX_CHAINS {
        ch::create(p, 1, &format!("n{i}"), &[spec(a)], "d_x", BY, NOW)
            .await
            .unwrap();
    }
    assert_eq!(
        code(ch::create(p, 1, "one-more", &[spec(a)], "d_x", BY, NOW).await),
        "limit_reached"
    );
    ch::create(p, 2, "second-users", &[spec(b)], "d_x", BY, NOW)
        .await
        .expect("another user's count is their own");
}
