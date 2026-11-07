//! The fixture of the connection route tests (C5): the app on a migrated database with the broker
//! on, its GitHub and Jira adapters pointed at loopback fakes (no network, no real token), and a
//! recorder of every response body so a test can prove no credential was ever in one.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::chains_api::{call, refusal, second_user};
use super::*;
use crate::connections::adapter::Registry;
use crate::connections::broker::{Broker, Limits};
use crate::connections::github::Github;
use crate::connections::github::tests::fake::Fake as GhFake;
use crate::connections::jira::tests as jt;
use crate::connections::jira::{Jira, SCOPES};
use crate::ops::secretbox::SecretBox;

/// Shapeless on purpose: the redactor must not be what hides a leak.
pub(super) const GH_TOKEN: &str = "c5gh-7f3a9d41e0b2c8a6";
pub(super) const GH_TOKEN2: &str = "c5gh2-1b8e5c3a9d7f2640";
pub(super) const API_TOKEN: &str = "c5jira-91c4d2b7a6e1f035";
pub(super) const CLIENT_SECRET: &str = "c5secret-3b9f6e2d1a70c4";
pub(super) const CODE: &str = "c5code-5d2e8b0c7a41f9";
pub(super) const ACCESS: &str = "c5acc-2e9d41f7a3b0c8";
pub(super) const REFRESH: &str = "c5ref-8a1f3c5d7e92b4";
pub(super) const DEVICE_CODE: &str = "c5dev-code-xyz-31337";
pub(super) const PEM_MARK: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC";
pub(super) const EMAIL: &str = "ann@example.com";
pub(super) const SITE: &str = "acme.atlassian.net";
pub(super) const START: &str = r#"{"device_code":"c5dev-code-xyz-31337","user_code":"WDJB-MJHT","verification_uri":"https://github.com/login/device","expires_in":900,"interval":1}"#;

/// Every string that must never appear in a response body, an event or an audit row.
pub(super) const SECRETS: [&str; 9] = [
    GH_TOKEN,
    GH_TOKEN2,
    API_TOKEN,
    CLIENT_SECRET,
    CODE,
    ACCESS,
    REFRESH,
    DEVICE_CODE,
    PEM_MARK,
];

pub(super) struct Cx {
    pub fx: Fx,
    pub gh: GhFake,
    pub jf: jt::Fake,
    seen: Mutex<Vec<String>>,
}

pub(super) async fn cx() -> Cx {
    let mut fx = fx().await;
    crate::store::settings::set(
        &fx.app.pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    fx.app.secrets = Some(Arc::new(SecretBox::new(&[7; 32])));
    let gh = GhFake::start().await;
    let jf = jt::Fake::default();
    let addr = jf.serve().await;
    jf.reply(
        "GET /oauth/token/accessible-resources",
        200,
        json!([{"id": jt::CLOUD, "url": jt::SITE, "name": "Acme", "scopes": ["read:jira-work"]}]),
    );
    jf.reply(
        "POST /oauth/token",
        200,
        json!({"access_token": ACCESS, "refresh_token": REFRESH, "expires_in": 3600,
            "scope": SCOPES}),
    );
    jf.reply(
        "GET /me",
        200,
        json!({"account_id": "5b10ac8d", "name": "Ann Lee"}),
    );
    jf.reply(
        "GET /rest/api/3/myself",
        200,
        json!({"accountId": "5b10ac8d", "displayName": "Ann Lee"}),
    );
    let jira = Arc::new(Jira::loopback(None, addr));
    let github = Github::new(Arc::new(gh.transport()));
    let mut reg = Registry::new();
    reg.register(Arc::new(github.clone())).unwrap();
    reg.register(jira.clone()).unwrap();
    fx.app.connections = Arc::new(Broker::with(reg, github, jira, Limits::default()));
    Cx {
        fx,
        gh,
        jf,
        seen: Mutex::default(),
    }
}

impl Cx {
    /// A request as `dev`; the body is recorded for the leak scan. The path is copied at once
    /// and kept out of what the future captures, so a temporary path is fine.
    pub fn call<'a>(
        &'a self,
        dev: &'a TestDevice,
        m: Method,
        uri: &str,
        body: Value,
    ) -> impl Future<Output = (StatusCode, Value)> + use<'a> {
        let uri = uri.to_owned();
        async move {
            let r = call(&self.fx, dev, m, &uri, body).await;
            self.seen.lock().unwrap().push(format!("{} {}", r.0, r.1));
            r
        }
    }

    /// As the admin device (every scope, stepped up).
    pub fn admin<'a>(
        &'a self,
        m: Method,
        uri: &str,
        body: Value,
    ) -> impl Future<Output = (StatusCode, Value)> + use<'a> {
        self.call(&self.fx.dev, m, uri, body)
    }

    /// As the admin device; must answer 200.
    pub fn ok<'a>(
        &'a self,
        m: Method,
        uri: &str,
        body: Value,
    ) -> impl Future<Output = Value> + use<'a> {
        let uri = uri.to_owned();
        let r = self.admin(m.clone(), &uri, body);
        async move {
            let r = r.await;
            assert_eq!(r.0, StatusCode::OK, "{m} {uri}: {}", r.1);
            r.1
        }
    }

    /// Configures both apps through the API.
    pub async fn configure(&self) {
        self.ok(
            Method::PUT,
            "/api/v1/connection-apps/jira",
            json!({"fields": {"client_id": "client-id-8c41", "client_secret": CLIENT_SECRET}}),
        )
        .await;
        self.ok(
            Method::PUT,
            "/api/v1/connection-apps/github",
            json!({"fields": {"client_id": "Iv1.abc123"}}),
        )
        .await;
    }

    /// A GitHub token connection named `name` (the fake says whose it is).
    pub async fn github(&self, name: &str) -> i64 {
        self.gh.push(200, &[], r#"{"login":"octocat","id":583231}"#);
        let body =
            json!({"kind": "github", "name": name, "auth_method": "token", "token": GH_TOKEN});
        self.ok(Method::POST, "/api/v1/connections", body).await["id"]
            .as_i64()
            .unwrap()
    }

    /// A token-auth Jira connection to `acme.atlassian.net`.
    pub async fn jira(&self, name: &str) -> i64 {
        let body = json!({"kind": "jira", "name": name, "auth_method": "token",
            "token": API_TOKEN, "email": EMAIL, "site": SITE});
        self.ok(Method::POST, "/api/v1/connections", body).await["id"]
            .as_i64()
            .unwrap()
    }

    /// Every event payload and audit row, as text.
    pub async fn stored(&self) -> String {
        let p = &self.fx.app.pool;
        let events: Vec<String> = sqlx::query_scalar("SELECT payload FROM events")
            .fetch_all(p)
            .await
            .unwrap();
        let audit: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events")
            .fetch_all(p)
            .await
            .unwrap();
        format!("{}\n{}", events.join("\n"), audit.join("\n"))
    }

    /// The `connection.health` events written so far, oldest first.
    pub async fn health_events(&self) -> Vec<Value> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT payload FROM events WHERE kind = 'connection.health' ORDER BY seq",
        )
        .fetch_all(&self.fx.app.pool)
        .await
        .unwrap();
        rows.iter()
            .map(|r| serde_json::from_str(r).unwrap())
            .collect()
    }

    /// Fails when a credential is in any response body seen, any event or any audit row.
    pub async fn assert_clean(&self) {
        self.assert_clean_also(&[]).await;
    }

    /// [`Cx::assert_clean`] with more strings that must be absent.
    pub async fn assert_clean_also(&self, more: &[&str]) {
        let seen = self.seen.lock().unwrap().join("\n");
        let stored = self.stored().await;
        for s in SECRETS.iter().chain(more) {
            assert!(!seen.contains(s), "{s} is in a response body");
            assert!(!stored.contains(s), "{s} is in an event or an audit row");
        }
    }
}

/// `k` of a URL's query.
pub(super) fn param(url: &str, k: &str) -> String {
    let u = reqwest::Url::parse(url).unwrap();
    let found = u.query_pairs().find(|(n, _)| n == k);
    found.map(|(_, v)| v.into_owned()).unwrap()
}

pub(super) fn code(r: &(StatusCode, Value)) -> (u16, String) {
    let (s, c) = refusal(r);
    (s, c.to_owned())
}

/// A second user's admin device.
pub(super) async fn other_admin(cx: &Cx) -> TestDevice {
    second_user(&cx.fx).await
}

/// Starts a sign-in as the admin device.
pub(super) async fn start(cx: &Cx, kind: &str, extra: Value) -> (StatusCode, Value) {
    let mut b = json!({"kind": kind});
    for (k, v) in extra.as_object().unwrap() {
        b[k] = v.clone();
    }
    cx.admin(Method::POST, "/api/v1/connections/start", b).await
}

/// Polls flow `id` until it reaches `step`; a flow that ended some other way fails the test.
pub(super) async fn until(cx: &Cx, id: &str, step: &str) -> Value {
    for _ in 0..150 {
        let v = cx
            .ok(
                Method::GET,
                &format!("/api/v1/connections/flows/{id}"),
                Value::Null,
            )
            .await;
        let now = v["step"].as_str().unwrap().to_owned();
        if now == step {
            return v;
        }
        let over = ["connected", "failed", "denied", "expired"].contains(&now.as_str());
        assert!(!over, "the flow ended as {now}, not {step}: {v}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the flow never reached {step}");
}

/// Every connection of the admin's workspace.
pub(super) async fn connections(cx: &Cx) -> Vec<Value> {
    let all = cx.ok(Method::GET, "/api/v1/connections", Value::Null).await;
    all.as_array().unwrap().clone()
}
