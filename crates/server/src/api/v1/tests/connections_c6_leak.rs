//! C6: the whole-system credential leak property. Secrets of every kind (access and refresh
//! tokens, an app client secret, a PEM key, a device code, a PKCE verifier, a Jira API token and
//! the Basic form of its pair) go in; then every route, flow, broker call, health transition,
//! audit write, event, error path and Debug print runs; and every output is scanned for each
//! secret in the forms a careless Core might repeat (plain, base64, URL-safe base64, Basic,
//! Bearer): response bodies, events, audit rows, the TRACE log, the poll stream the runner is
//! sent, tool results, Debug text and the database file with its log.

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use super::connections_apps::{mark, pem};
use super::connections_fx::*;
use crate::auth::testing::TestDevice;
use crate::connections::broker::Env;
use crate::connections::jira::tests as jt;
use ainkrad_proto::v2::{ToolCall, ToolResult, ToolsPoll};

const URI: &str = "/api/v1/connections";
const NEWTOK: &str = "c6new-token-4e8d2a6f0b13";
const RUNNER: &str = "d_cccccccccccccccccccccccccc";

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn logging(logs: &Logs) -> tracing::subscriber::DefaultGuard {
    let writer = logs.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_default(sub)
}

/// A request with a body that is not valid JSON (or not what the route wants), signed as `dev`.
async fn raw(cx: &Cx, dev: &TestDevice, m: Method, uri: &str, bytes: &str) -> (StatusCode, Value) {
    let mut b = axum::http::Request::builder()
        .method(m.clone())
        .uri(uri)
        .header(axum::http::header::HOST, super::HOST);
    for (n, v) in dev.headers(m.as_str(), uri, bytes.as_bytes()) {
        b = b.header(n, v);
    }
    b = b.header(axum::http::header::CONTENT_TYPE, "application/json");
    let body = axum::body::Body::from(bytes.to_owned());
    super::send(&cx.fx.app, b.body(body).unwrap()).await
}

fn needles(secrets: &[&str], more: &[String]) -> Vec<String> {
    let mut out: Vec<String> = more.to_vec();
    for s in secrets {
        out.push((*s).to_owned());
        out.push(STANDARD.encode(s));
        out.push(URL_SAFE_NO_PAD.encode(s));
        out.push(format!("Bearer {s}"));
    }
    out.push(STANDARD.encode(format!("{EMAIL}:{API_TOKEN}")));
    out
}

fn absent(what: &str, hay: &str, needles: &[String]) {
    for n in needles {
        assert!(!hay.contains(n.as_str()), "{n} is in {what}");
    }
}

#[tokio::test]
async fn no_credential_of_any_kind_is_in_any_output_of_the_whole_system() {
    let logs = Logs::default();
    let _log = logging(&logs);
    tracing::debug!("c6 log capture is live");
    let cx = cx().await;
    let key = pem();
    let mut out = String::new(); // every response, result and Debug text, in one haystack
    cx.configure().await;
    cx.ok(
        Method::PUT,
        "/api/v1/connection-apps/github",
        json!({"fields": {"app_id": "123456", "app_key": key, "app_slug": "ainkrad-test"}}),
    )
    .await;

    // Connections: a token one, a refused one whose error echoes its token, a Jira one.
    let gh = cx.github("main").await;
    let jira = cx.jira("acme").await;
    cx.gh.push(
        401,
        &[],
        &format!(r#"{{"message":"Bad credentials {GH_TOKEN2}","token":"{GH_TOKEN2}"}}"#),
    );
    let r = cx
        .admin(
            Method::POST,
            URI,
            json!({"kind": "github", "name": "x", "auth_method": "token", "token": GH_TOKEN2}),
        )
        .await;
    assert_eq!(r.0.as_u16(), 400);
    out.push_str(&r.1.to_string());

    // Atlassian sign-in: the code is echoed in a failure, then the exchange succeeds.
    cx.jf.reply(
        "POST /oauth/token",
        400,
        json!({"error": "invalid_grant", "echo": CODE, "token": REFRESH}),
    );
    let v = start(&cx, "jira", json!({})).await.1;
    let (flow, state) = (v["id"].as_str().unwrap(), v["state"].clone());
    let r = cx
        .admin(
            Method::POST,
            &format!("{URI}/flows/{flow}/callback"),
            json!({"code": CODE, "state": state}),
        )
        .await;
    out.push_str(&r.1.to_string());
    cx.jf.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": ACCESS, "refresh_token": REFRESH, "expires_in": 3600,
            "scope": crate::connections::jira::SCOPES, "echo": CODE}),
    );
    let v = start(&cx, "jira", json!({})).await.1;
    let (flow, state) = (v["id"].as_str().unwrap(), v["state"].clone());
    let r = cx
        .admin(
            Method::POST,
            &format!("{URI}/flows/{flow}/callback"),
            json!({"code": CODE, "state": state}),
        )
        .await;
    out.push_str(&r.1.to_string());
    let verifier = cx.jf.last("POST /oauth/token").unwrap().body["code_verifier"]
        .as_str()
        .unwrap()
        .to_owned();

    // GitHub device flow ending in a stored credential.
    cx.gh.push(200, &[], START);
    cx.gh.push(
        200,
        &[],
        &format!(r#"{{"access_token":"{GH_TOKEN2}","token_type":"bearer","scope":"repo"}}"#),
    );
    cx.gh.push(200, &[], r#"{"login":"octocat","id":1}"#);
    let d = start(&cx, "github", json!({})).await.1;
    out.push_str(&d.to_string());
    out.push_str(
        &until(&cx, d["id"].as_str().unwrap(), "connected")
            .await
            .to_string(),
    );

    // Grants, a default, the apps, and every read route as three kinds of device.
    for (id, kind) in [(gh, "github"), (jira, "jira")] {
        for g in [
            json!({"grantee_kind": "role", "grantee": "member"}),
            json!({"grantee_kind": "agent", "grantee": "bot"}),
        ] {
            cx.ok(Method::PUT, &format!("{URI}/{id}/grants"), g).await;
        }
        cx.ok(
            Method::PUT,
            &format!("/api/v1/connection-defaults/{kind}"),
            json!({"connection": id}),
        )
        .await;
    }
    let reader = cx.fx.enroll("reader", &["read"]).await;
    let other = other_admin(&cx).await;
    for dev in [&cx.fx.dev, &reader, &other] {
        for u in [
            URI.to_owned(),
            "/api/v1/connection-kinds".to_owned(),
            format!("{URI}/{gh}"),
            format!("{URI}/{jira}"),
            format!("{URI}/{gh}/activity"),
            format!("{URI}/{gh}/grants"),
            "/api/v1/connection-defaults".to_owned(),
            "/api/v1/connection-apps/jira".to_owned(),
            "/api/v1/connection-apps/github".to_owned(),
        ] {
            let r = cx.call(dev, Method::GET, &u, Value::Null).await;
            out.push_str(&r.1.to_string());
        }
    }

    // Error paths: bodies that are not JSON or not the route's shape, with secrets inside them.
    for (m, u) in [
        (Method::POST, URI.to_owned()),
        (Method::POST, format!("{URI}/start")),
        (Method::PUT, format!("{URI}/{gh}/credential")),
        (Method::PUT, "/api/v1/connection-apps/jira".to_owned()),
        (Method::PUT, format!("{URI}/{gh}/grants")),
        (
            Method::POST,
            format!("{URI}/flows/cf_00000000000000000000000000/callback"),
        ),
    ] {
        for body in [
            format!(r#"{{"token":"{GH_TOKEN}","kind":"#),
            format!(r#"{{"toke":"{GH_TOKEN}","bogus":"{CLIENT_SECRET}"}}"#),
            format!(
                r#"{{"kind":"{API_TOKEN}","tokens":["{ACCESS}"],"fields":{{"client_secret":1}}}}"#
            ),
            format!(r#"["{REFRESH}"]"#),
            format!("\"{CODE}\""),
            format!(r#"{{"state":"{DEVICE_CODE}","code":{{"x":"{PEM_MARK}"}}}}"#),
        ] {
            let r = raw(&cx, &cx.fx.dev, m.clone(), &u, &body).await;
            assert!(r.0.as_u16() < 500, "{m} {u}: {} {}", r.0, r.1);
            out.push_str(&r.1.to_string());
        }
    }

    // The broker: a session of agent `bot`, echoing upstreams, every health transition.
    sqlx::query(
        "INSERT INTO core_devices (id, kind, name, routine_spki, fingerprint, status) \
         VALUES (?, 'runner', 'r1', randomblob(91), substr(hex(randomblob(22)), 1, 43), 'active')",
    )
    .bind(RUNNER)
    .execute(&cx.fx.app.pool)
    .await
    .unwrap();
    let policy = json!({});
    let new = crate::store::agents::NewSession {
        runner: RUNNER,
        harness: "claude",
        model: None,
        prompt: None,
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: RUNNER,
    };
    let now = cx.fx.app.clock.now();
    let session = crate::store::agents::create(
        &cx.fx.app.pool,
        &new,
        ainkrad_core::audit::AuditActor::System,
        &now,
    )
    .await
    .unwrap()
    .id;
    sqlx::query("UPDATE core_agent_sessions SET agent = 'bot' WHERE id = ?")
        .bind(&session)
        .execute(&cx.fx.app.pool)
        .await
        .unwrap();
    let allow = ["read_repo".to_owned(), "read_issues".to_owned()];
    crate::store::connections::access::set(&cx.fx.app.pool, &session, &allow)
        .await
        .unwrap();
    let mut results: Vec<ToolResult> = Vec::new();
    let mut seq = 0;
    let mut call = |tool: &str, args: Value| {
        seq += 1;
        ToolCall {
            tc_seq: seq,
            id: format!("c-{seq}"),
            tool: tool.to_owned(),
            args,
        }
    };
    let issue = || json!({"repo": "octocat/hello", "number": 1});
    // The service echoes the token it was sent: the first two calls carry GH_TOKEN, the rest
    // (after the credential is replaced at step 2) carry NEWTOK.
    let echo = format!(r#"{{"title":"{GH_TOKEN}","{GH_TOKEN}":1,"n":[{{"t":"x {GH_TOKEN} y"}}]}}"#);
    let steps: [(u16, String); 6] = [
        (200, echo),
        (
            401,
            format!(r#"{{"message":"Bad credentials {GH_TOKEN}"}}"#),
        ),
        (
            403,
            format!(r#"{{"message":"API rate limit exceeded {NEWTOK}"}}"#),
        ),
        (500, format!("boom {NEWTOK}")),
        (500, format!(r#"{{"message":"{NEWTOK}","{NEWTOK}":[1]}}"#)),
        (200, format!(r#"{{"title":"{NEWTOK}","{NEWTOK}":1}}"#)),
    ];
    for (n, (status, body)) in steps.iter().enumerate() {
        if n == 2 {
            // The 401 left the connection pending: a test decides, and the service refuses it.
            cx.gh
                .push(401, &[], &format!(r#"{{"message":"{GH_TOKEN}"}}"#));
            let r = cx
                .admin(Method::POST, &format!("{URI}/{gh}/test"), Value::Null)
                .await;
            out.push_str(&r.1.to_string());
            // A new credential brings it back.
            cx.gh.push(200, &[], r#"{"login":"octocat","id":583231}"#);
            let r = cx
                .admin(
                    Method::PUT,
                    &format!("{URI}/{gh}/credential"),
                    json!({"token": NEWTOK}),
                )
                .await;
            out.push_str(&r.1.to_string());
        }
        cx.gh.push(*status, &[("retry-after", "30")], body);
        let c = call("github.get_issue", issue());
        let env = Env {
            pool: &cx.fx.app.pool,
            sealer: cx.fx.app.secrets.as_ref(),
            now: &cx.fx.app.clock.now(),
        };
        results.push(
            cx.fx
                .app
                .connections
                .handle(&env, RUNNER, &session, &c)
                .await,
        );
        cx.fx.clock.advance(400);
    }
    // Forged and echoing arguments, an unknown tool, a Jira read, a wrong runner.
    let env_now = cx.fx.app.clock.now();
    let env = Env {
        pool: &cx.fx.app.pool,
        sealer: cx.fx.app.secrets.as_ref(),
        now: &env_now,
    };
    let broker = &cx.fx.app.connections;
    let extra = [
        call("github.get_issue", json!({"repo": GH_TOKEN, "number": 1})),
        call(
            "github.get_issue",
            json!({"repo": "a/b", "number": 1, "token": NEWTOK}),
        ),
        call(&format!("github.{GH_TOKEN}"), json!({})),
        call("jira.get_issue", json!({"key": "ABC-1"})),
    ];
    cx.jf.reply(
        &format!("GET {}", jt::site_path("/issue/ABC-1")),
        200,
        json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}, "summary": format!("{API_TOKEN} Basic {}", STANDARD.encode(format!("{EMAIL}:{API_TOKEN}")))}}),
    );
    for c in &extra {
        results.push(broker.handle(&env, RUNNER, &session, c).await);
    }
    results.push(
        broker
            .handle(
                &env,
                "d_wrongrunner",
                &session,
                &call("github.get_issue", issue()),
            )
            .await,
    );
    let tools = broker.tools(&env, &session).await.unwrap();
    // What the runner is sent: the poll with the results and the list, serialized and printed.
    let poll = ToolsPoll {
        session: session.clone(),
        after: u64::try_from(results.len()).unwrap(),
        wait_ms: None,
        results: results.clone(),
        tools: Some(tools.clone()),
    };
    let stream = format!(
        "{}\n{poll:?}\n{results:?}\n{tools:?}",
        serde_json::to_string(&poll).unwrap()
    );

    // Debug prints of what the store holds and of what it opens.
    let mut printed = String::new();
    for c in crate::store::connections::list(&cx.fx.app.pool, 1, None)
        .await
        .unwrap()
    {
        printed.push_str(&format!("{c:?}\n"));
        let opened = crate::store::connections::secret::open(
            &cx.fx.app.pool,
            cx.fx.app.secrets.as_deref().unwrap(),
            1,
            c.id,
        )
        .await;
        printed.push_str(&format!("{opened:?}\n"));
        let g = crate::store::connections::grants::list(&cx.fx.app.pool, 1, c.id)
            .await
            .unwrap();
        printed.push_str(&format!("{g:?}\n"));
    }

    let secrets = [
        GH_TOKEN,
        GH_TOKEN2,
        API_TOKEN,
        CLIENT_SECRET,
        CODE,
        ACCESS,
        REFRESH,
        DEVICE_CODE,
        PEM_MARK,
        NEWTOK,
    ];
    let more = vec![mark(&key), verifier];
    let n = needles(&secrets, &more);
    absent("a response or a Debug text", &out, &n);
    absent("a tool result or the poll stream", &stream, &n);
    absent("a Debug print", &printed, &n);
    let extra_strings: Vec<&str> = n.iter().map(String::as_str).collect();
    cx.assert_clean_also(&extra_strings).await;
    let logged = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
    // Whether the Core's own events reach a thread-local subscriber depends on the callsite
    // interest other tests left behind, so liveness is proven by an event of this test's own.
    assert!(logged.contains("c6 log capture is live"), "the capture is dead");
    absent("the TRACE log", &logged, &n);
    assert!(
        cx.health_events().await.len() >= 2,
        "the health transitions were not exercised"
    );
    // The database file, after its log is folded in, holds only sealed bytes.
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&cx.fx.app.pool)
        .await
        .unwrap();
    let path = cx
        .fx
        .app
        .pool
        .connect_options()
        .get_filename()
        .to_path_buf();
    let bytes = std::fs::read(path).unwrap();
    for needle in n
        .iter()
        .filter(|s| !s.contains(DEVICE_CODE) && !s.contains(PEM_MARK) && s.len() > 8)
    {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} is in the database file"
        );
    }
}
