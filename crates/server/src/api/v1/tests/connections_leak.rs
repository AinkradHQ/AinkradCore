//! No credential is in any response, event, audit row or the database file (C5): a scan over a
//! full session of use, with upstream answers that echo the very secrets Core holds, error
//! bodies and flow polls included.

use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::http::Method;
use serde_json::{Value, json};

use super::connections_apps::{mark, pem};
use super::connections_fx::*;

const URI: &str = "/api/v1/connections";
const APPS: &str = "/api/v1/connection-apps";

/// What the Core logged, at TRACE.
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

impl Logs {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
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

#[tokio::test]
async fn no_secret_is_in_any_body_event_audit_row_or_the_database_file() {
    let logs = Logs::default();
    let _log = logging(&logs);
    let cx = cx().await;
    // The upstream echoes what Core sent it, in the places a careless Core would repeat.
    cx.jf.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": ACCESS, "refresh_token": REFRESH,
        "expires_in": 3600, "echo": CODE}),
    );
    cx.configure().await;
    cx.ok(
        Method::PUT,
        "/api/v1/connection-apps/jira",
        json!({"fields": {"loopback_port": "50124"}}),
    )
    .await;
    // A token connection, a refused one whose error echoes the token, and a jira one.
    let gh = cx.github("main").await;
    cx.gh.push(
        401,
        &[],
        &format!(r#"{{"message":"Bad credentials {GH_TOKEN2}","token":"{GH_TOKEN2}"}}"#),
    );
    let refused = cx
        .admin(
            Method::POST,
            URI,
            json!({"kind": "github", "name": "x", "auth_method": "token", "token": GH_TOKEN2}),
        )
        .await;
    assert_eq!(refused.0.as_u16(), 400, "{}", refused.1);
    let jira = cx.jira("acme").await;
    // An Atlassian sign-in whose code the service echoes back in its failure.
    cx.jf.reply(
        "POST /oauth/token",
        400,
        json!({"error": "invalid_grant", "echo": CODE, "token": REFRESH}),
    );
    let v = start(&cx, "jira", json!({})).await.1;
    let flow = v["id"].as_str().unwrap().to_owned();
    let failed = cx
        .admin(
            Method::POST,
            &format!("{URI}/flows/{flow}/callback"),
            json!({"code": CODE, "state": v["state"]}),
        )
        .await;
    assert_eq!(failed.1["step"], "failed", "{}", failed.1);
    cx.admin(Method::GET, &format!("{URI}/flows/{flow}"), Value::Null)
        .await;
    // A GitHub device flow that ends in a stored credential.
    cx.gh.push(200, &[], START);
    cx.gh.push(
        200,
        &[],
        &format!(r#"{{"access_token":"{GH_TOKEN2}","token_type":"bearer","scope":"repo"}}"#),
    );
    cx.gh.push(200, &[], r#"{"login":"octocat","id":1}"#);
    let d = start(&cx, "github", json!({})).await.1;
    until(&cx, d["id"].as_str().unwrap(), "connected").await;
    // Every read and write route, as the admin, as a reader and as a stranger.
    let reader = cx.fx.enroll("reader", &["read"]).await;
    cx.ok(
        Method::PUT,
        &format!("{URI}/{gh}/grants"),
        json!({"grantee_kind": "role", "grantee": "member"}),
    )
    .await;
    cx.ok(
        Method::PUT,
        "/api/v1/connection-defaults/github",
        json!({"connection": gh}),
    )
    .await;
    cx.gh.push(200, &[], r#"{"login":"octocat","id":1}"#);
    let all = [
        (Method::GET, "/api/v1/connection-kinds".to_owned()),
        (Method::GET, URI.to_owned()),
        (Method::GET, format!("{URI}/{gh}")),
        (Method::GET, format!("{URI}/{jira}")),
        (Method::GET, format!("{URI}/{gh}/grants")),
        (Method::GET, format!("{URI}/{gh}/activity")),
        (Method::GET, "/api/v1/connection-defaults".to_owned()),
        (Method::GET, "/api/v1/connection-apps/jira".to_owned()),
        (Method::GET, "/api/v1/connection-apps/github".to_owned()),
        (Method::POST, format!("{URI}/{gh}/test")),
        (Method::GET, "/api/v1/events?after=0&limit=1000".to_owned()),
        (Method::GET, "/api/v1/audit?limit=200".to_owned()),
    ];
    for (m, uri) in &all {
        cx.admin(m.clone(), uri, Value::Null).await;
        cx.call(&reader, m.clone(), uri, Value::Null).await;
    }
    let stranger = cx.fx.stranger();
    cx.call(&stranger, Method::GET, URI, Value::Null).await;
    // Error bodies: junk that carries a secret, a missing row, a wrong method.
    let junk = Value::String(format!("{{{GH_TOKEN} {CLIENT_SECRET}"));
    for (m, uri) in [
        (Method::POST, URI.to_owned()),
        (Method::PUT, format!("{URI}/{gh}/credential")),
        (Method::PUT, "/api/v1/connection-apps/jira".to_owned()),
        (Method::PUT, format!("{URI}/{gh}/grants")),
        (Method::POST, format!("{URI}/start")),
        (Method::PATCH, format!("{URI}/{gh}")),
    ] {
        let r = cx.admin(m, &uri, junk.clone()).await;
        assert_eq!(r.0.as_u16(), 400, "{}", r.1);
    }
    cx.admin(Method::GET, &format!("{URI}/999999"), Value::Null)
        .await;
    cx.assert_clean().await;
    let logged = logs.text();
    assert!(logged.len() > 1000, "the capture saw the Core's own logs");
    for secret in SECRETS {
        assert!(!logged.contains(secret), "{secret} is in the logs");
    }
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
    for s in SECRETS
        .iter()
        .filter(|s| **s != DEVICE_CODE && **s != PEM_MARK)
    {
        assert!(
            !bytes.windows(s.len()).any(|w| w == s.as_bytes()),
            "{s} is in the database file"
        );
    }
}

#[tokio::test]
async fn the_installation_renewal_and_site_choice_paths_leak_nothing_against_an_echoing_upstream() {
    let logs = Logs::default();
    let _log = logging(&logs);
    let cx = cx().await;
    cx.configure().await;
    let key = pem();
    let line = mark(&key);
    cx.ok(
        Method::PUT,
        &format!("{APPS}/github"),
        json!({"fields": {"app_id": "123456", "app_key": key, "app_slug": "ainkrad-test"}}),
    )
    .await;
    let (t1, t2) = ("c5inst-leak-1111aaaa2222", "c5inst-leak-3333bbbb4444");
    // Every upstream answer carries the secrets Core holds or has just been given.
    let echo = format!(r#""echo":"{GH_TOKEN} {GH_TOKEN2} {line} {DEVICE_CODE} {t1} {t2}""#);
    cx.gh.push(
        200,
        &[],
        &format!(r#"{{"id":77,"account":{{"login":"octo-org"}},{echo}}}"#),
    );
    cx.gh.push(
        201,
        &[],
        &format!(r#"{{"token":"{t1}","expires_at":"2026-10-22T11:00:00Z",{echo}}}"#),
    );
    cx.gh
        .push(403, &[], &format!(r#"{{"message":"no {t1}",{echo}}}"#));
    cx.gh.push(
        200,
        &[],
        &format!(r#"{{"repositories":[{{"owner":{{"login":"octo-org","id":9}}}}],{echo}}}"#),
    );
    let body = json!({"kind": "github", "name": "app", "auth_method": "app_install", "installation_id": 77});
    let id = cx.ok(Method::POST, URI, body).await["id"].as_i64().unwrap();
    // A renewal whose mint is refused with a body that echoes them: the answer is a plain test.
    sqlx::query("UPDATE core_connection_secrets SET expires_at = '2026-10-22T10:02:00.000Z' WHERE connection_id = ?")
        .bind(id)
        .execute(&cx.fx.app.pool)
        .await
        .unwrap();
    cx.fx.clock.advance(11);
    cx.gh
        .push(500, &[], &format!(r#"{{"message":"{t2}",{echo}}}"#));
    cx.gh
        .push(403, &[], &format!(r#"{{"message":"{t1}",{echo}}}"#));
    cx.gh.push(
        200,
        &[],
        &format!(r#"{{"repositories":[{{"owner":{{"login":"octo-org","id":9}}}}],{echo}}}"#),
    );
    cx.ok(Method::POST, &format!("{URI}/{id}/test"), Value::Null)
        .await;
    // A sign-in with several sites, one named with control characters and past the label limit,
    // one at an address Core cannot use: the sign-in is not failed by them.
    let long = format!("{}\u{7}{}", "A".repeat(100), "B".repeat(100));
    let sites = json!([
        {"id": jt_cloud(), "url": jt_site(), "name": long, "scopes": ["read:jira-work"]},
        {"id": "7d0c4b1e-0000-4000-8000-000000000001", "url": "https://beta.atlassian.net",
         "name": "Beta", "scopes": ["read:jira-work"]},
        {"id": "7d0c4b1e-0000-4000-8000-000000000002", "url": "http://insecure.example",
         "name": "Bad", "scopes": ["read:jira-work"]},
    ]);
    cx.jf
        .reply("GET /oauth/token/accessible-resources", 200, sites);
    let v = start(&cx, "jira", json!({})).await.1;
    let f = v["id"].as_str().unwrap();
    let cb = cx
        .admin(
            Method::POST,
            &format!("{URI}/flows/{f}/callback"),
            json!({"code": CODE, "state": v["state"]}),
        )
        .await;
    assert_eq!(cb.1["step"], "choose_site", "{}", cb.1);
    let listed: Vec<&str> = cb.1["sites"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    assert_eq!(listed.len(), 2, "the unusable site is left out: {listed:?}");
    assert!(
        listed
            .iter()
            .all(|n| n.chars().count() <= 80 && !n.chars().any(char::is_control))
    );
    let done = cx
        .admin(
            Method::POST,
            &format!("{URI}/flows/{f}/choose"),
            json!({"site": jt_cloud()}),
        )
        .await;
    assert_eq!(done.1["step"], "connected", "{}", done.1);
    let label = cx
        .ok(
            Method::GET,
            &format!("{URI}/{}", done.1["connection"]),
            Value::Null,
        )
        .await;
    assert_eq!(label["label"].as_str().unwrap(), "A".repeat(80));
    cx.assert_clean_also(&[t1, t2, line.as_str()]).await;
    let logged = logs.text();
    for s in SECRETS.iter().chain(&[t1, t2, line.as_str()]) {
        assert!(!logged.contains(s), "{s} is in the logs");
    }
}

fn jt_cloud() -> &'static str {
    crate::connections::jira::tests::CLOUD
}

fn jt_site() -> &'static str {
    crate::connections::jira::tests::SITE
}
