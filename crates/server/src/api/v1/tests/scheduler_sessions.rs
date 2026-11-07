//! Chain sessions over the API (S7): what a session shows of its chain, account and wait; the
//! create that names a chain or an agent (admin only, no harness, model or account secret, nothing
//! left behind by a refusal); and the stop of a chain session that never reached its runner, over
//! HTTP and by a module (S4 left both untested).

use ainkrad_proto::v2::{AgentStop, Command};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::chains::{make, pool, setup};
use super::chains_session::session;
use super::*;
use crate::agents::{ModuleAgents, Refusal};
use crate::scheduler::unix_secs;
use crate::store::agents::{self as store, NewSession};
use crate::store::chains::{self as ch, Request};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

async fn call(fx: &Fx, dev: &TestDevice, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(dev), body)).await
}

async fn post(fx: &Fx, dev: &TestDevice, body: Value) -> (StatusCode, Value) {
    call(fx, dev, Method::POST, "/api/v1/agent-sessions", body).await
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

async fn audited(fx: &Fx, action: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_session_shows_its_chain_its_account_and_why_it_waits() {
    let fx = setup().await;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    let s = session(&fx, &[], None, ask(Some(c.id), Some("agent-1")))
        .await
        .unwrap();
    let uri = format!("/api/v1/agent-sessions/{}", s.id);
    let fresh = fx.ok(&uri).await;
    assert_eq!(fresh["agent"], "agent-1");
    assert_eq!(fresh["chain_id"], c.id);
    assert_eq!(
        fresh["chain"],
        json!([{"pool": a, "provider": "anthropic", "harness": "claude", "model": null}])
    );
    for none in [
        "chain_pos",
        "account",
        "waiting",
        "repicked",
        "upstream_class",
    ] {
        assert!(fresh[none].is_null(), "{none}: {fresh}");
    }
    // Waiting, then picked after two launches refused an account, then a gateway class.
    let since = unix_secs(NOW).unwrap();
    let waiting =
        json!({"until": "2026-10-22T10:15:00.000Z", "why": "every account cools", "since": since});
    sqlx::query("UPDATE core_agent_sessions SET waiting = ? WHERE id = ?")
        .bind(waiting.to_string())
        .bind(&s.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let waits = fx.ok(&uri).await;
    assert_eq!(
        waits["waiting"],
        json!({"since": "2026-10-22T10:00:00.000Z", "until": "2026-10-22T10:15:00.000Z",
               "why": "every account cools"})
    );
    sqlx::query(
        "UPDATE core_agent_sessions SET waiting = NULL, account_id = 7, chain_pos = 0, \
         tried_accounts = '[3,4]', upstream_class = 'rate_limited' WHERE id = ?",
    )
    .bind(&s.id)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let held = fx.ok(&uri).await;
    assert_eq!(
        (
            &held["account"],
            &held["chain_pos"],
            &held["repicked"],
            &held["upstream_class"]
        ),
        (&json!(7), &json!(0), &json!(2), &json!("rate_limited"))
    );
    assert!(held["waiting"].is_null());
    // The list says the same, and a plain session has none of it.
    let plain = {
        let policy = json!({});
        let new = NewSession {
            runner: &fx.dev.id,
            harness: "claude",
            model: None,
            prompt: None,
            workspace: None,
            policy: &policy,
            secrets: &[],
            created_by: &fx.dev.id,
        };
        store::create(&fx.app.pool, &new, BY, NOW).await.unwrap()
    };
    let list = fx.ok("/api/v1/agent-sessions").await;
    let row = |id: &str| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(row(&s.id), held);
    let p = row(&plain.id);
    for none in [
        "agent",
        "chain_id",
        "chain",
        "chain_pos",
        "account",
        "waiting",
        "repicked",
    ] {
        assert!(p[none].is_null(), "{none}: {p}");
    }
}

#[tokio::test]
async fn a_create_naming_a_chain_or_an_agent_is_admin_only_and_refused_cleanly() {
    let fx = setup().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    let policy = json!({"mode": "ask", "min_isolation": "process"});
    let base = |extra: Value| {
        let mut b = json!({"runner": vm.id, "policy": policy});
        b.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        b
    };
    let code = |r: &(StatusCode, Value)| {
        (
            r.0.as_u16(),
            r.1["code"].as_str().unwrap_or_default().to_owned(),
        )
    };

    // A device that is not an admin: 403 for a chain and for an agent, KAN-433.
    let agent = super::stepup::plain(&fx, "agent-dev", &["agent", "read"], true).await;
    assert_eq!(super::stepup::step_up(&fx, &agent).await.0, StatusCode::OK);
    for body in [
        base(json!({"chain": c.id})),
        base(json!({"agent": "agent-1"})),
    ] {
        let r = post(&fx, &agent, body).await;
        assert_eq!(code(&r), (403, "forbidden_scope".to_owned()), "{}", r.1);
    }
    // The wrong user's chain does not exist for the caller.
    let r = {
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
        post(&fx, &other, base(json!({"chain": c.id}))).await
    };
    assert_eq!(code(&r), (404, "not_found".to_owned()), "{}", r.1);
    // A chain that is not there.
    let r = post(&fx, &fx.dev, base(json!({"chain": 9999}))).await;
    assert_eq!(code(&r), (404, "not_found".to_owned()), "{}", r.1);
    // The harness, the model and an account secret beside a chain: 400, before the runner is asked.
    let acct = json!([{"name": "acct.anthropic.1", "var": "ANTHROPIC_API_KEY"}]);
    for (why, extra) in [
        ("a harness", json!({"chain": c.id, "harness": "claude"})),
        ("a model", json!({"chain": c.id, "model": "claude-sonnet"})),
        (
            "a redirecting variable a plain create refuses",
            json!({"chain": c.id, "secrets": [{"name": "proxy", "var": "HTTPS_PROXY"}]}),
        ),
        ("an account secret", json!({"chain": c.id, "secrets": acct})),
        (
            "an agent that resolves to a chain",
            json!({"agent": "x", "harness": "claude"}),
        ),
    ] {
        let extra = if why.starts_with("an agent") {
            ch::set_default(&fx.app.pool, c.id, "d_x", BY, NOW)
                .await
                .unwrap();
            extra
        } else {
            extra
        };
        let r = post(&fx, &fx.dev, base(extra)).await;
        assert_eq!(r.0, StatusCode::BAD_REQUEST, "{why}: {}", r.1);
    }
    // A bad agent id.
    let r = post(&fx, &fx.dev, base(json!({"agent": "bad agent!"}))).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
    // Past every refusal it reaches the runner, which is not connected here: 409, and no row.
    for extra in [json!({"chain": c.id}), json!({"agent": "agent-1"})] {
        let r = post(&fx, &fx.dev, base(extra)).await;
        assert_eq!(code(&r), (409, "runner_offline".to_owned()), "{}", r.1);
    }
    assert_eq!(sessions(&fx).await, 0, "a refusal leaves no session behind");
    // An agent with no binding and no default chain is a plain request: it names its harness.
    sqlx::query("UPDATE core_chains SET is_default = 0")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let r = post(&fx, &fx.dev, base(json!({"agent": "agent-1"}))).await;
    assert_eq!(r.0, StatusCode::BAD_REQUEST, "{}", r.1);
    // And one that names neither is the plain create it always was.
    let r = post(&fx, &agent, base(json!({"harness": "claude"}))).await;
    assert_eq!(code(&r), (409, "runner_offline".to_owned()), "{}", r.1);
    assert_eq!(sessions(&fx).await, 0);
}

#[tokio::test]
async fn cancel_and_kill_end_a_waiting_chain_session_in_the_core() {
    let fx = setup().await;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    let waiting = json!({"until": "2026-10-22T10:15:00.000Z", "why": "every account cools",
                         "since": unix_secs(NOW).unwrap()});
    for (route, action) in [("cancel", "agent.cancelled"), ("kill", "agent.killed")] {
        let s = session(&fx, &[], None, ask(Some(c.id), None))
            .await
            .unwrap();
        sqlx::query("UPDATE core_agent_sessions SET waiting = ? WHERE id = ?")
            .bind(waiting.to_string())
            .bind(&s.id)
            .execute(&fx.app.pool)
            .await
            .unwrap();
        let uri = format!("/api/v1/agent-sessions/{}/{route}", s.id);
        // No runner is connected: the Core ends it itself, and nothing is asked of one.
        let (st, b) = call(&fx, &fx.dev, Method::POST, &uri, Value::Null).await;
        assert_eq!(st, StatusCode::OK, "{route}: {b}");
        assert_eq!(
            (b["state"].as_str(), b["outcome"]["kind"].as_str()),
            (Some("ended"), Some("cancelled"))
        );
        assert!(b["waiting"].is_null(), "no longer waiting: {b}");
        assert_eq!(audited(&fx, action).await, 1, "{action}");
        // Once over, the cancel stands (nothing is left to stop).
        let (st, b) = call(&fx, &fx.dev, Method::POST, &uri, Value::Null).await;
        assert_eq!(st, StatusCode::OK, "{b}");
        // It never starts: the supervisor finds it over.
        let ended: String =
            sqlx::query_scalar("SELECT state FROM core_agent_sessions WHERE id = ?")
                .bind(&s.id)
                .fetch_one(&fx.app.pool)
                .await
                .unwrap();
        assert_eq!(ended, "ended");
    }
    // A session whose start was sent is the runner's to stop: with none connected it is refused,
    // stays as it was and is not audited as cancelled.
    let sent = session(&fx, &[], None, ask(Some(c.id), None))
        .await
        .unwrap();
    sqlx::query("UPDATE core_agent_sessions SET start_sent = 1 WHERE id = ?")
        .bind(&sent.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let uri = format!("/api/v1/agent-sessions/{}/cancel", sent.id);
    let (st, b) = call(&fx, &fx.dev, Method::POST, &uri, Value::Null).await;
    assert_eq!(
        (st, b["code"].as_str()),
        (StatusCode::CONFLICT, Some("runner_offline")),
        "{b}"
    );
    assert_eq!(
        audited(&fx, "agent.cancelled").await,
        2,
        "the refused one is not audited"
    );
    let state: String = sqlx::query_scalar("SELECT state FROM core_agent_sessions WHERE id = ?")
        .bind(&sent.id)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(state, "starting");
}

#[tokio::test]
async fn a_module_stops_its_own_unstarted_session_and_never_owns_a_chain_one() {
    let fx = setup().await;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    let citadel = ModuleAgents::named("citadel");
    let stop = |id: &str| {
        Command::AgentStop(AgentStop {
            session: id.to_owned(),
            kill: false,
        })
    };
    let state = |id: String| {
        let pool = fx.app.pool.clone();
        async move {
            sqlx::query_scalar::<_, String>("SELECT state FROM core_agent_sessions WHERE id = ?")
                .bind(id)
                .fetch_one(&pool)
                .await
                .unwrap()
        }
    };
    // The store never gives a module's session a chain: the only way to one is the row itself.
    let policy = json!({"mode": "ask", "min_isolation": "process"});
    let new = NewSession {
        runner: &fx.dev.id,
        harness: "",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: &fx.dev.id,
    };
    let refused = ch::create_session(
        &fx.app.pool,
        &new,
        Some("citadel"),
        None,
        ask(Some(c.id), None),
        BY,
        NOW,
    )
    .await;
    assert!(matches!(
        refused,
        Err(crate::store::secrets::Error::Refused {
            code: "bad_request",
            ..
        })
    ));
    assert_eq!(sessions(&fx).await, 0, "and nothing is left behind");
    // So the row is crafted (it cannot exist through the store): a module's session that sits on a
    // chain and never started is ended by the module's own stop, in the Core.
    let plain = NewSession {
        harness: "claude",
        ..new
    };
    let mine = store::create_owned(&fx.app.pool, &plain, Some("citadel"), BY, NOW)
        .await
        .unwrap();
    let snapshot = serde_json::to_string(&c.entries).unwrap();
    sqlx::query("UPDATE core_agent_sessions SET chain = ?, chain_id = ? WHERE id = ?")
        .bind(&snapshot)
        .bind(c.id)
        .bind(&mine.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    citadel
        .instruct(&fx.app, &mine.id, stop(&mine.id))
        .await
        .unwrap();
    assert_eq!(state(mine.id.clone()).await, "ended");
    let outcome: String =
        sqlx::query_scalar("SELECT outcome FROM core_agent_sessions WHERE id = ?")
            .bind(&mine.id)
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(outcome.contains("cancelled"), "{outcome}");
    // One whose start was sent is the runner's: with none connected the stop is refused, and the
    // row stays.
    let sent = store::create_owned(&fx.app.pool, &plain, Some("citadel"), BY, NOW)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE core_agent_sessions SET chain = ?, chain_id = ?, start_sent = 1 WHERE id = ?",
    )
    .bind(&snapshot)
    .bind(c.id)
    .bind(&sent.id)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let r = citadel.instruct(&fx.app, &sent.id, stop(&sent.id)).await;
    assert!(matches!(r, Err(Refusal::Runner(_))), "{r:?}");
    assert_eq!(state(sent.id.clone()).await, "starting");
    // A client's chain session is not a module's to stop, and stays as it was.
    let theirs = session(&fx, &[], None, ask(Some(c.id), None))
        .await
        .unwrap();
    let r = citadel
        .instruct(&fx.app, &theirs.id, stop(&theirs.id))
        .await;
    assert!(
        matches!(&r, Err(Refusal::Runner(e)) if e.message.contains("not this module's")),
        "{r:?}"
    );
    assert_eq!(state(theirs.id.clone()).await, "starting");
}

#[tokio::test]
async fn a_session_answers_to_its_user_and_its_chain_and_account_to_admins_only() {
    let fx = setup().await;
    let a = pool(&fx, "a", "anthropic").await;
    let c = make(&fx, "main", &[a]).await;
    let s = session(&fx, &[], None, ask(Some(c.id), Some("agent-1")))
        .await
        .unwrap();
    sqlx::query("UPDATE core_agent_sessions SET account_id = 7, chain_pos = 0 WHERE id = ?")
        .bind(&s.id)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let uri = format!("/api/v1/agent-sessions/{}", s.id);
    // An admin of the same user sees all of it.
    let admin = fx.ok(&uri).await;
    assert_eq!(
        (&admin["account"], &admin["chain_id"], &admin["agent"]),
        (&json!(7), &json!(c.id), &json!("agent-1"))
    );
    assert!(admin["chain"].is_array());
    // A device of the same user without admin sees the session, but no chain, agent or account.
    let agent = super::stepup::plain(&fx, "agent-dev", &["agent", "read"], true).await;
    let seen = call(&fx, &agent, Method::GET, &uri, Value::Null).await;
    assert_eq!(seen.0, StatusCode::OK, "{}", seen.1);
    for hidden in ["chain", "account", "chain_id", "agent"] {
        assert!(seen.1[hidden].is_null(), "{hidden}: {}", seen.1);
    }
    assert_eq!(seen.1["chain_pos"], 0);
    let list = call(
        &fx,
        &agent,
        Method::GET,
        "/api/v1/agent-sessions",
        Value::Null,
    )
    .await;
    assert!(
        list.1[0]["chain"].is_null() && list.1[0]["account"].is_null(),
        "{}",
        list.1
    );
    // Another user's devices, admin or not, do not see it at all.
    sqlx::query("INSERT INTO users (id, name) VALUES (2, 'second')")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let other_admin = fx.enroll("second", &["read", "admin", "agent"]).await;
    let other_agent = fx.enroll("second-agent", &["read", "agent"]).await;
    for dev in [&other_admin, &other_agent] {
        sqlx::query("UPDATE core_devices SET user_id = 2 WHERE id = ?")
            .bind(&dev.id)
            .execute(&fx.app.pool)
            .await
            .unwrap();
        let r = call(&fx, dev, Method::GET, &uri, Value::Null).await;
        assert_eq!(r.0, StatusCode::NOT_FOUND, "{}", r.1);
        let l = call(&fx, dev, Method::GET, "/api/v1/agent-sessions", Value::Null).await;
        assert_eq!(l.1, json!([]), "{}", l.1);
        assert!(!l.1.to_string().contains(&s.id));
    }
}
