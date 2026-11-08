//! Tests of the Linear adapter. A fake Linear on loopback answers every request (the adapter is
//! pointed at it by `Linear::loopback`); no real network, no real token. The tokens are shapeless
//! on purpose: the broker's secret gate must not be what hides a leak.
//!
//! The fake holds every GraphQL request to the adapter's own documents: a request whose `query`
//! is not exactly one of [`docs::ALL`] (or whose `operationName` does not match) is answered with
//! a validation error and counted, and the tests assert the count stays 0. That is the proof that
//! no caller text ever reaches a document.

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

use super::{Ctx, Linear, OAuthApp, docs, key_material, oauth_material};
use crate::connections::adapter::{KindAdapter, Registry};
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::connections::{Connection, NewConnection, Who, create};

mod descriptor;
mod errors;
mod limits;
mod oauth;
mod ops;
mod pages;
mod renew;
mod safety;

pub const NOW: &str = "2026-11-06T10:00:00.000Z";
pub const ACCESS: &str = "acc1-7f3a9d41e0b2";
pub const REFRESH: &str = "ref1-91c4d2b7a6e1";
pub const API_KEY: &str = "key1-5d2e8b0c7a41";
pub const CLIENT_SECRET: &str = "clsec-3b9f6e2d1a70";
pub const REDIRECT: &str = "http://127.0.0.1:53682/callback";
pub const ORG: &str = "acme";
pub const ORG_ID: &str = "0b1a2c3d-0000-4000-8000-000000000001";
pub const ME: &str = "5f1c2a90-7b3d-4e8a-9c61-0d4b2e7a1f33";
pub const TEAM_ENG: &str = "9cfb482a-81e3-4154-b5b9-2c805e70a02d";
pub const ISSUE_ID: &str = "2a7c1e04-5b9d-4c3f-8e21-7d6f0a9b4c58";
pub const STATE_ID: &str = "c3d4e5f6-1a2b-4c3d-8e4f-5a6b7c8d9e0f";

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

    /// A 200 with `data`.
    pub fn data(data: Value) -> Self {
        Self::json(200, json!({"data": data}))
    }

    /// A GraphQL error with `code`, at `status`.
    pub fn error(status: u16, code: &str) -> Self {
        let e = json!({"message": "scope and token text must not matter",
            "extensions": {"code": code}});
        Self::json(status, json!({"errors": [e]}))
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
    pub auth: Option<String>,
    pub content_type: Option<String>,
    /// The GraphQL `variables`, or the token endpoint's form as an object.
    pub body: Value,
    /// The GraphQL `operationName` ("" for anything else).
    pub op: String,
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

#[derive(Default)]
struct Inner {
    handlers: HashMap<String, Handler>,
    seen: Vec<Seen>,
    /// The scopes the (fake) grant holds; `None` is what `SCOPES` asks for.
    scopes: Option<Vec<String>>,
    /// Requests that were not one of the adapter's documents, or a token request that was not a form.
    bad: usize,
}

/// The scopes that allow an operation, per Linear's OAuth docs (linear.app/developers/oauth-2-0-
/// authentication): `issues:create` "allows creating and updating issues", `comments:create`
/// "allows creating new issue comments", `write` is broad write access, `admin` is more. `read`
/// is always included by Linear, but a token can still be refused: that is what the
/// scope-enforcing `viewer` stands for.
fn needs(op: &str) -> &'static [&'static str] {
    match op {
        "IssueCreate" | "IssueUpdate" => &["issues:create", "write", "admin"],
        "CommentCreate" => &["comments:create", "write", "admin"],
        _ => &["read", "write", "admin"],
    }
}

/// The fake service: handlers by `"GQL <OperationName>"` or `"POST /oauth/token"`, and a log of
/// everything it was asked.
#[derive(Clone, Default)]
pub struct Fake {
    inner: Arc<Mutex<Inner>>,
}

fn form(bytes: &[u8]) -> Value {
    let text = String::from_utf8_lossy(bytes);
    let url = reqwest::Url::parse(&format!("http://x/?{text}")).unwrap();
    let pairs: serde_json::Map<String, Value> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), json!(v.into_owned())))
        .collect();
    Value::Object(pairs)
}

async fn handle(State(f): State<Fake>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body, 1 << 20).await.unwrap_or_default();
    let header = |n: &str| {
        let v = parts.headers.get(n).and_then(|v| v.to_str().ok());
        v.map(str::to_owned)
    };
    let content_type = header("content-type");
    let path = parts.uri.path().to_owned();
    let is_form = content_type
        .as_deref()
        .is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"));
    let (op, vars, doc_ok) = if path == "/graphql" {
        let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let name = v.get("operationName").and_then(Value::as_str).unwrap_or("");
        let query = v.get("query").and_then(Value::as_str).unwrap_or("");
        let known = docs::ALL.iter().find(|d| d.name == name);
        let ok = known.is_some_and(|d| d.query == query);
        let vars = v.get("variables").cloned().unwrap_or(Value::Null);
        (name.to_owned(), vars, ok)
    } else if path == "/oauth/token" {
        (String::new(), form(&bytes), is_form)
    } else {
        (String::new(), Value::Null, true)
    };
    let seen = Seen {
        method: parts.method.to_string(),
        path: path.clone(),
        auth: header("authorization"),
        content_type,
        body: vars,
        op: op.clone(),
    };
    let key = if path == "/graphql" {
        format!("GQL {op}")
    } else {
        format!("{} {path}", seen.method)
    };
    let (handler, short) = {
        let mut i = f.inner.lock().unwrap();
        i.seen.push(seen.clone());
        if !doc_ok {
            i.bad += 1;
        }
        let held = i
            .scopes
            .clone()
            .unwrap_or_else(|| super::SCOPES.split(',').map(str::to_owned).collect());
        let short = path == "/graphql" && !held.iter().any(|h| needs(&op).contains(&h.as_str()));
        (i.handlers.get(&key).cloned(), short)
    };
    let r = match handler {
        _ if !doc_ok && path == "/graphql" => Reply::error(400, "GRAPHQL_VALIDATION_FAILED"),
        _ if !doc_ok => Reply::json(400, json!({"error": "invalid_request"})),
        // A token that lacks the scope is refused, as Linear refuses a call it did not allow.
        _ if short && op == "Viewer" => Reply::error(400, "AUTHENTICATION_ERROR"),
        _ if short => Reply::error(200, "FORBIDDEN"),
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

    /// Answers GraphQL operation `name` with `data`.
    pub fn data(&self, name: &str, data: Value) {
        self.on(&format!("GQL {name}"), move |_| Reply::data(data.clone()));
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

    /// Requests that were not the adapter's own documents (or not a form at the token endpoint).
    pub fn bad(&self) -> usize {
        self.inner.lock().unwrap().bad
    }

    /// Requests seen for `"GQL <Name>"` or `"METHOD /path"`.
    pub fn count(&self, key: &str) -> usize {
        self.seen().iter().filter(|s| key_of(s) == key).count()
    }

    pub fn last(&self, key: &str) -> Option<Seen> {
        self.seen().iter().rev().find(|s| key_of(s) == key).cloned()
    }

    /// Every GraphQL operation seen, in order.
    pub fn ops(&self) -> Vec<String> {
        let gql = |s: &&Seen| s.path == "/graphql";
        self.seen()
            .iter()
            .filter(gql)
            .map(|s| s.op.clone())
            .collect()
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
                "token_type": "Bearer", "refresh_token": *current, "expires_in": 3600});
            Reply::json(200, body).delayed(150)
        });
        served
    }
}

fn key_of(s: &Seen) -> String {
    if s.path == "/graphql" {
        format!("GQL {}", s.op)
    } else {
        format!("{} {}", s.method, s.path)
    }
}

pub struct Fx {
    pub fake: Fake,
    pub linear: Arc<Linear>,
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

/// A database, a fake Linear and a Linear adapter pointed at it; with an OAuth app when `app`.
/// The fake answers `viewer` as `ME` in workspace `acme`.
pub async fn fx(app: bool) -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-linear-{}-{n}", std::process::id()));
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
    fake.data("Viewer", viewer(ORG));
    let app = app.then(|| OAuthApp::new("client-id-8c41", CLIENT_SECRET, &[REDIRECT]).unwrap());
    let linear = Arc::new(Linear::loopback(app, addr));
    let mut reg = Registry::new();
    reg.register(linear.clone()).unwrap();
    Fx {
        fake,
        linear,
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
            kind: "linear",
            name,
            label: "A Linear workspace",
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

    /// A personal-API-key connection.
    pub async fn key(&self) -> Connection {
        self.connect("acme", "token", &key()).await
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

/// The `data` of a `viewer` answer for workspace `org` (another url key is another workspace,
/// with another id).
pub fn viewer(org: &str) -> Value {
    let id = match org == ORG {
        true => ORG_ID.to_owned(),
        false => format!("0b1a2c3d-0000-4000-8000-{:012}", org.len()),
    };
    json!({"viewer": {"id": ME, "name": "Ann", "email": "ann@example.com",
        "organization": {"id": id, "urlKey": org, "name": "Acme"}}})
}

/// The identity line the fake's `viewer` makes: the user, the workspace and its id.
pub fn identity() -> String {
    format!("{ME} at {ORG} ({ORG_ID})")
}

/// `secs` after [`NOW`].
pub fn at(secs: i64) -> String {
    iso_of_unix(unix_secs(NOW).unwrap() + secs)
}

pub fn oauth(access: &str, refresh: &str, expires_in: i64) -> Material {
    oauth_material(access, refresh, Some(&at(expires_in))).unwrap()
}

pub fn key() -> Material {
    key_material(API_KEY).unwrap()
}

/// An issue as Linear answers it, in `team` with `identifier`.
pub fn issue(identifier: &str, team: &str) -> Value {
    json!({"id": ISSUE_ID, "identifier": identifier, "title": "A title",
        "description": "Some text", "priority": 2, "priorityLabel": "High",
        "url": format!("https://linear.app/acme/issue/{identifier}"),
        "createdAt": "2026-11-01T10:00:00.000Z", "updatedAt": "2026-11-02T10:00:00.000Z",
        "dueDate": null, "state": {"name": "Todo", "type": "unstarted"},
        "assignee": {"name": "ann", "displayName": "Ann"},
        "team": {"key": team, "name": "Team"}, "project": null,
        "labels": {"nodes": [{"name": "bug"}]}})
}

/// The answer of an `IssueRef` pre-read.
pub fn issue_ref(identifier: &str, team: &str) -> Value {
    json!({"issue": {"id": ISSUE_ID, "identifier": identifier, "team": {"key": team}}})
}
