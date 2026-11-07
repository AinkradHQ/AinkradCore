//! Tests of the Jira adapter. A fake Atlassian on loopback answers every request (the adapter
//! is pointed at it by `Jira::loopback`); no real network, no real token. The tokens are
//! shapeless on purpose: the broker's secret gate must not be what hides a leak.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::response::Response;
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePool;

use super::{Ctx, Jira, OAuthApp, cred, oauth_material, token_material};
use crate::connections::adapter::{KindAdapter, Registry};
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::connections::{Connection, NewConnection, Who, create};

mod errors;
mod limits;
mod oauth;
mod ops;
mod renew;
mod safety;

pub const NOW: &str = "2026-11-06T10:00:00.000Z";
pub const CLOUD: &str = "1324a887-451d-4b3e-b3a5-0bfbb4c7d8f1";
pub const SITE: &str = "https://acme.atlassian.net";
pub const ACCESS: &str = "acc1-7f3a9d41e0b2";
pub const REFRESH: &str = "ref1-91c4d2b7a6e1";
pub const API_TOKEN: &str = "apitok-5d2e8b0c7a41";
pub const CLIENT_SECRET: &str = "clsec-3b9f6e2d1a70";
pub const REDIRECT: &str = "http://127.0.0.1:53682/callback";
pub const EMAIL: &str = "ann@example.com";

#[derive(Clone)]
pub struct Reply {
    pub status: u16,
    pub body: Value,
    pub headers: Vec<(String, String)>,
    pub delay_ms: u64,
    pub raw: Option<Vec<u8>>,
}

impl Reply {
    pub fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            body,
            headers: Vec::new(),
            delay_ms: 0,
            raw: None,
        }
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_owned(), v.to_owned()));
        self
    }

    pub fn delayed(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }
}

#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub query: String,
    pub auth: Option<String>,
    pub body: Value,
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

#[derive(Default)]
struct Inner {
    handlers: HashMap<String, Handler>,
    seen: Vec<Seen>,
    /// The scopes the (fake) grant holds; `None` is what `SCOPES` asks for.
    scopes: Option<Vec<String>>,
}

/// The classic scope an OAuth-routed endpoint needs (token-auth paths are not scoped).
fn needs(method: &str, path: &str) -> Option<&'static str> {
    if path == "/me" {
        return Some("read:me");
    }
    if !path.starts_with("/ex/jira/") {
        return None;
    }
    Some(if path.ends_with("/rest/api/3/myself") {
        "read:jira-user"
    } else if method == "GET" || path.ends_with("/search/jql") {
        "read:jira-work"
    } else {
        "write:jira-work"
    })
}

/// The fake service: handlers by `"METHOD /path"`, and a log of everything it was asked.
#[derive(Clone, Default)]
pub struct Fake {
    inner: Arc<Mutex<Inner>>,
}

async fn handle(State(f): State<Fake>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body, 1 << 20).await.unwrap_or_default();
    let seen = Seen {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().unwrap_or("").to_owned(),
        auth: parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    };
    let key = format!("{} {}", seen.method, seen.path);
    let (handler, scoped) = {
        let mut i = f.inner.lock().unwrap();
        i.seen.push(seen.clone());
        let held = i
            .scopes
            .clone()
            .unwrap_or_else(|| super::SCOPES.split(' ').map(str::to_owned).collect());
        let missing = needs(&seen.method, &seen.path).is_some_and(|n| !held.iter().any(|h| h == n));
        (i.handlers.get(&key).cloned(), missing)
    };
    // The real service answers 401 when the token's scopes do not cover the endpoint.
    let r = match handler {
        _ if scoped => Reply::json(
            401,
            json!({"message": "Unauthorized; scope does not match"}),
        ),
        Some(h) => h(&seen),
        None => Reply::json(404, json!({})),
    };
    if r.delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(r.delay_ms)).await;
    }
    let mut b = Response::builder()
        .status(r.status)
        .header("content-type", "application/json");
    for (k, v) in &r.headers {
        b = b.header(k.as_str(), v.as_str());
    }
    let bytes = r
        .raw
        .unwrap_or_else(|| serde_json::to_vec(&r.body).unwrap());
    b.body(Body::from(bytes)).unwrap()
}

impl Fake {
    pub fn on(&self, key: &str, f: impl Fn(&Seen) -> Reply + Send + Sync + 'static) {
        let mut i = self.inner.lock().unwrap();
        i.handlers.insert(key.to_owned(), Arc::new(f));
    }

    pub fn reply(&self, key: &str, status: u16, body: Value) {
        self.on(key, move |_| Reply::json(status, body.clone()));
    }

    /// Grants only these scopes from now on.
    pub fn grant_scopes(&self, scopes: &[&str]) {
        let list = scopes.iter().map(|s| (*s).to_owned()).collect();
        self.inner.lock().unwrap().scopes = Some(list);
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.inner.lock().unwrap().seen.clone()
    }

    /// Requests seen for `"METHOD /path"`.
    pub fn count(&self, key: &str) -> usize {
        let hit = |s: &&Seen| format!("{} {}", s.method, s.path) == key;
        self.seen().iter().filter(hit).count()
    }

    pub fn last(&self, key: &str) -> Option<Seen> {
        let hit = |s: &&Seen| format!("{} {}", s.method, s.path) == key;
        self.seen().iter().rev().find(hit).cloned()
    }

    pub async fn serve(&self) -> SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let app = Router::new().fallback(handle).with_state(self.clone());
        tokio::spawn(async move {
            let _ = axum::serve(l, app).await;
        });
        addr
    }

    /// A token endpoint that rotates: each refresh token works once and issues `acc<n>-...` and
    /// `ref<n>-...`; the spent one is `invalid_grant`. Returns the number of refreshes served.
    pub fn rotating(&self) -> Arc<AtomicUsize> {
        let served = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(Mutex::new(REFRESH.to_owned()));
        let n = served.clone();
        self.on("POST /oauth/token", move |s| {
            let mut current = state.lock().unwrap();
            if s.body["refresh_token"].as_str() != Some(current.as_str()) {
                return Reply::json(400, json!({"error": "invalid_grant"}));
            }
            let k = n.fetch_add(1, Ordering::SeqCst) + 2;
            *current = format!("ref{k}-91c4d2b7a6e1");
            let body = json!({"access_token": format!("acc{k}-7f3a9d41e0b2"),
                "refresh_token": *current, "expires_in": 3600});
            Reply::json(200, body).delayed(150)
        });
        served
    }
}

pub struct Fx {
    pub fake: Fake,
    pub jira: Arc<Jira>,
    pub reg: Registry,
    pub pool: SqlitePool,
    pub sealer: Arc<SecretBox>,
    pub addr: SocketAddr,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A database, a fake Atlassian and a Jira adapter pointed at it; with an OAuth app when `app`.
pub async fn fx(app: bool) -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-jira-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = crate::store::connect(&dir.join("core.db")).await.unwrap();
    let set = crate::store::settings::set;
    set(
        &pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    let fake = Fake::default();
    let addr = fake.serve().await;
    // The sites the account can reach: the one these tests connect to.
    fake.reply(
        "GET /oauth/token/accessible-resources",
        200,
        json!([{"id": CLOUD, "url": SITE, "name": "Acme", "scopes": ["read:jira-work"]}]),
    );
    let app = app.then(|| OAuthApp::new("client-id-8c41", CLIENT_SECRET, &[REDIRECT]).unwrap());
    let jira = Arc::new(Jira::loopback(app, addr));
    let mut reg = Registry::new();
    reg.register(jira.clone()).unwrap();
    Fx {
        fake,
        jira,
        reg,
        pool,
        sealer: Arc::new(SecretBox::new(&[7; 32])),
        addr,
        dir,
    }
}

impl Fx {
    pub fn cx<'a>(&'a self, now: &'a str) -> Ctx<'a> {
        let who = Who {
            workspace: 1,
            by_device: "d_test",
            actor: AuditActor::System,
            now,
        };
        Ctx {
            pool: &self.pool,
            sealer: &self.sealer,
            who,
        }
    }

    pub async fn connect(&self, name: &str, auth: &str, m: &Material) -> Connection {
        let new = NewConnection {
            kind: "jira",
            name,
            label: "A Jira site",
            auth_method: auth,
        };
        let who = Who {
            workspace: 1,
            by_device: "d_test",
            actor: AuditActor::System,
            now: NOW,
        };
        create(&self.pool, &self.sealer, &self.reg, &new, m, who)
            .await
            .unwrap()
    }

    /// A token-auth connection to `acme.atlassian.net`.
    pub async fn basic(&self) -> Connection {
        self.connect("acme", "token", &basic()).await
    }

    pub async fn basic_named(&self, name: &str) -> Connection {
        self.connect(name, "token", &basic()).await
    }

    /// Every audit row's details, to look for a leak.
    pub async fn audit_text(&self) -> String {
        let rows: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events")
            .fetch_all(&self.pool)
            .await
            .unwrap();
        rows.join("\n")
    }
}

/// `secs` after [`NOW`].
pub fn at(secs: i64) -> String {
    iso_of_unix(unix_secs(NOW).unwrap() + secs)
}

pub fn oauth(access: &str, refresh: &str, expires_in: i64) -> Material {
    oauth_material(CLOUD, SITE, access, Some(refresh), Some(&at(expires_in))).unwrap()
}

pub fn basic() -> Material {
    token_material("acme.atlassian.net", EMAIL, API_TOKEN).unwrap()
}

/// The path the fake sees for a Jira API path of an OAuth connection.
pub fn oauth_path(rest: &str) -> String {
    format!("/ex/jira/{CLOUD}/rest/api/3{rest}")
}

/// The path of a token-auth connection.
pub fn site_path(rest: &str) -> String {
    format!("/rest/api/3{rest}")
}

#[test]
fn the_descriptor_is_valid_and_every_operation_has_one_capability() {
    use super::DESCRIPTOR;
    assert_eq!(DESCRIPTOR.problem(), None);
    assert_eq!(DESCRIPTOR.read_only(), ["read_issues"]);
    assert_eq!(DESCRIPTOR.auth_methods[0].id, "oauth");
    assert!(DESCRIPTOR.auth_methods[1].advanced);
    let op = |o| DESCRIPTOR.capability_of(o).map(|c| c.name);
    assert_eq!(op("jira.transition_issue"), Some("transition"));
    assert_eq!(op("jira.create_issue"), Some("write_issues"));
    assert_eq!(op("jira.search_issues"), Some("read_issues"));
    assert!(DESCRIPTOR.is_self_limited("jira.search_issues"));
    let bad = super::Descriptor {
        self_limited: &["jira.nope"],
        ..DESCRIPTOR
    };
    assert!(
        bad.problem().is_some(),
        "a self-limited name must be an operation"
    );
    assert!(DESCRIPTOR.allows_host("api.atlassian.com"));
    assert!(!DESCRIPTOR.allows_host("api.atlassian.com.evil.test"));
    assert!(!DESCRIPTOR.allows_host("acme.atlassian.net"));
    let _ = (cred::site_host, Jira::new(None).descriptor().kind);
}
