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

/// A signed request as the app sends it, to the Core under test.
async fn http(
    core: &super::Core,
    dev: &ainkrad_core_server::auth::testing::TestDevice,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (u16, serde_json::Value) {
    let bytes = body.map(|b| b.to_string()).unwrap_or_default();
    let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
    let mut req = reqwest::Client::new().request(m, format!("http://{}{path}", core.host));
    for (n, v) in dev.headers(method, path, bytes.as_bytes()) {
        req = req.header(n, v);
    }
    if !bytes.is_empty() {
        req = req.header("content-type", "application/json").body(bytes);
    }
    let res = req.send().await.unwrap();
    let status = res.status().as_u16();
    (status, res.json().await.unwrap_or(serde_json::Value::Null))
}

/// An admin device with a live step-up.
async fn admin(core: &super::Core) -> ainkrad_core_server::auth::testing::TestDevice {
    let dev = core.device("device", &["read", "agent", "admin"]).await;
    let sid = dev.session.lock().unwrap().clone().unwrap();
    let until = ainkrad_core_server::scheduler::Clock::unix(&*core.app.clock) + 300;
    assert!(core.app.auth.elevate(&sid, &dev.id, until));
    dev
}

/// The same path through the HTTP route (S7): `POST /agent-sessions` with a chain and no harness
/// makes the session, the allocator picks the account, the supervisor starts it on the entry's
/// harness and model, and the reads show the chain, the account and the account's load.
#[tokio::test]
async fn a_create_over_http_with_a_chain_is_picked_started_and_shown() {
    let (core, fake, runner, account) = up("chain-http", true, None).await;
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
    let dev = admin(&core).await;
    let body = serde_json::json!({"runner": runner, "chain": chain.id, "agent": "agent-1",
        "prompt": "go", "policy": policy()});
    let (status, made) = http(&core, &dev, "POST", "/api/v1/agent-sessions", Some(body)).await;
    assert_eq!(status, 200, "{made}");
    let id = made["id"].as_str().unwrap().to_owned();
    assert_eq!(
        (made["chain_id"].as_i64(), made["agent"].as_str()),
        (Some(chain.id), Some("agent-1"))
    );
    let mut w = W {
        core,
        fake,
        runner,
        account,
        session: id.clone(),
    };
    started(&mut w, u64::MAX).await;
    until("the start", &w.core, &id, |s| s.state == "running").await;
    let path = format!("/api/v1/agent-sessions/{id}");
    let (status, got) = http(&w.core, &dev, "GET", &path, None).await;
    assert_eq!(status, 200, "{got}");
    assert_eq!(
        (
            got["state"].as_str(),
            got["harness"].as_str(),
            got["model"].as_str()
        ),
        (Some("running"), Some("claude"), Some("claude-x"))
    );
    assert_eq!(
        (got["account"].as_i64(), got["chain_pos"].as_i64()),
        (Some(w.account.id), Some(0))
    );
    assert!(got["waiting"].is_null(), "{got}");
    let (_, accounts) = http(&w.core, &dev, "GET", "/api/v1/accounts", None).await;
    let mine = accounts
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"].as_i64() == Some(w.account.id))
        .unwrap();
    assert_eq!(mine["live"], 1, "{mine}");
    assert_eq!(mine["health"]["fail_streak"], 0, "{mine}");
}

/// `scheduler.wait_max_secs` is read at each pick: an account that cools for ten minutes is a
/// wait under the default (15 minutes) and the end of the run once the setting says five seconds.
#[tokio::test]
async fn the_wait_max_setting_decides_between_waiting_and_ending() {
    let (core, _fake, runner, account) = up("chain-wait-max", true, None).await;
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
    let until_iso = ainkrad_core_server::scheduler::iso_of_unix(core.app.clock.unix() + 600);
    sqlx::query(
        "UPDATE core_accounts SET state = 'cooling', state_reason = 'rate_limited', state_until = ?",
    )
    .bind(until_iso)
    .execute(p)
    .await
    .unwrap();
    let dev = admin(&core).await;
    let body = |name: &str| serde_json::json!({"runner": runner, "chain": chain.id, "agent": name, "policy": policy()});
    // The default: it waits, and the row says until when.
    let (status, waits) = http(
        &core,
        &dev,
        "POST",
        "/api/v1/agent-sessions",
        Some(body("a")),
    )
    .await;
    assert_eq!(status, 200, "{waits}");
    let id = waits["id"].as_str().unwrap().to_owned();
    let path = format!("/api/v1/agent-sessions/{id}");
    for _ in 0..250 {
        let (_, got) = http(&core, &dev, "GET", &path, None).await;
        if !got["waiting"].is_null() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    }
    let (_, got) = http(&core, &dev, "GET", &path, None).await;
    assert_eq!(got["state"], "starting", "{got}");
    assert!(
        got["waiting"]["until"].is_string() && got["waiting"]["since"].is_string(),
        "it waits under the default: {got}"
    );
    // Five seconds: the next one has nothing to wait for, and ends.
    let setting = "/api/v1/settings/server/scheduler.wait_max_secs";
    let (st, set) = http(
        &core,
        &dev,
        "PUT",
        setting,
        Some(serde_json::json!({"value": 5})),
    )
    .await;
    assert_eq!(st, 200, "{set}");
    let (_, short) = http(
        &core,
        &dev,
        "POST",
        "/api/v1/agent-sessions",
        Some(body("b")),
    )
    .await;
    let short = short["id"].as_str().unwrap().to_owned();
    until("the end", &core, &short, |s| s.state == "ended").await;
    let row = sessions::get(&core.app.pool, &short)
        .await
        .unwrap()
        .unwrap();
    let why = row.outcome.unwrap()["reason"].as_str().unwrap().to_owned();
    assert!(why.contains("no account is available"), "{why}");
}

/// A chain create counts against the runner's capacity like a plain one (here 2): the third is
/// refused before it makes a row.
#[tokio::test]
async fn a_chain_create_on_a_full_runner_is_refused_503() {
    let (core, _fake, runner, account) = up("chain-busy", true, None).await;
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
    // The only account cools, so the first two wait and hold their runner slot.
    let until_iso = ainkrad_core_server::scheduler::iso_of_unix(core.app.clock.unix() + 600);
    sqlx::query(
        "UPDATE core_accounts SET state = 'cooling', state_reason = 'rate_limited', state_until = ?",
    )
    .bind(until_iso)
    .execute(p)
    .await
    .unwrap();
    let dev = admin(&core).await;
    let body = serde_json::json!({"runner": runner, "chain": chain.id, "policy": policy()});
    for n in 0..2 {
        let (status, made) = http(
            &core,
            &dev,
            "POST",
            "/api/v1/agent-sessions",
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, 200, "{n}: {made}");
    }
    let (status, busy) = http(&core, &dev, "POST", "/api/v1/agent-sessions", Some(body)).await;
    assert_eq!(
        (status, busy["code"].as_str()),
        (503, Some("runner_busy")),
        "{busy}"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM core_agent_sessions")
        .fetch_one(p)
        .await
        .unwrap();
    assert_eq!(rows, 2, "the refused create left no row");
}
