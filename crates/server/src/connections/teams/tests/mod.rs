//! Tests of the Teams adapter. A fake Microsoft on loopback answers every request (the adapter is
//! pointed at it by `Teams::loopback`); no real network, no real token. The tokens are shapeless
//! on purpose: the broker's secret gate must not be what hides a leak.
//!
//! The fake holds every request to the adapter's own contract and counts any that breaks it as
//! `bad`; the tests assert the count stays 0. That is the proof that no caller text becomes a
//! parameter, a header or a path:
//!
//! - Entra (`/<tenant>/oauth2/v2.0/devicecode|token`): a form POST, tenant `organizations` or a
//!   GUID, only the documented parameters, NEVER a client secret, NEVER an `Authorization`.
//! - Graph (`/v1.0/...`): one of the typed routes with validated ids, a bearer of a token the fake
//!   issued, a query of `$top` (1 to 50) and `$skiptoken` on the two list routes and nothing else
//!   (no `$filter`, `$expand`, `$select`, `$orderby`, `$search`), a POST body of exactly
//!   `{"body": {"contentType": "text", "content": <text>}}`.
//!
//! It enforces the delegated scope of each route like Microsoft does: `403 Forbidden`.

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
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePool;

use super::cred::{channel_id, guid, message_id};
use super::{Ctx, SCOPES, Teams, TeamsApp};
use crate::connections::adapter::Registry;
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::connections::{Connection, NewConnection, Who, create};

mod descriptor;
mod device;
mod errors;
mod limits;
mod ops;
mod renew;
mod safety;

pub const NOW: &str = "2026-11-06T10:00:00.000Z";
pub const CLIENT: &str = "00001111-aaaa-2222-bbbb-3333cccc4444";
pub const TENANT: &str = "2432b57b-0abd-43db-aa7b-16eadd115d34";
pub const OTHER_TENANT: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
pub const USER: &str = "8ea0e38b-efb3-4757-924a-5f94061cf8c2";
pub const TEAM_A: &str = "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b";
pub const TEAM_B: &str = "57fb72d0-d811-46f4-8947-305e6072eaa5";
pub const CH_A1: &str = "19:4a95f7d8db4c4e7fae857bcebe0623e6@thread.tacv2";
pub const CH_A2: &str = "19:ZmNjZDMxYmQtYzA3Zi00MGQ5LTk4MTAtMzg0NTA4NTg4YjQ2@thread.tacv2";
pub const CH_B1: &str = "19:b6bed8d24574f6a9e436813cb2617d8a@thread.tacv2";
pub const KEY_A1: &str = "fbe2bf47-16c8-47cf-b4a5-4b9b187c508b/4a95f7d8db4c4e7fae857bcebe0623e6";
pub const KEY_B1: &str = "57fb72d0-d811-46f4-8947-305e6072eaa5/b6bed8d24574f6a9e436813cb2617d8a";
pub const MSG: &str = "1616990032035";
pub const ACCESS: &str = "acc1-graphtok-0001-aaaaaaaa";
pub const REFRESH: &str = "ref1-refreshtok-0001-bbbbbbbb";
pub const ACC2: &str = "acc2-graphtok-0002-aaaaaaaa";
pub const REF2: &str = "ref2-refreshtok-0002-bbbbbbbb";

#[derive(Clone)]
pub struct Reply {
    pub status: u16,
    pub body: Value,
    pub headers: Vec<(String, String)>,
    pub delay_ms: u64,
    pub raw: Option<Vec<u8>>,
}

impl Reply {
    pub fn http(status: u16, body: Value) -> Self {
        Self {
            status,
            body,
            headers: Vec::new(),
            delay_ms: 0,
            raw: None,
        }
    }

    pub fn ok(body: Value) -> Self {
        Self::http(200, body)
    }

    /// A Graph error: `{"error": {"code": ..., "message": ...}}`.
    pub fn graph(status: u16, code: &str) -> Self {
        Self::http(
            status,
            json!({"error": {"code": code, "message": "a message Core never shows"}}),
        )
    }

    /// An Entra error: `{"error": ..., "error_description": ...}`.
    pub fn entra(status: u16, code: &str) -> Self {
        Self::http(
            status,
            json!({"error": code, "error_description": "AADSTS0: never shown", "error_codes": [0]}),
        )
    }

    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_owned(), v.to_owned()));
        self
    }

    pub fn delayed(mut self, ms: u64) -> Self {
        self.delay_ms = ms;
        self
    }

    pub fn raw(mut self, bytes: Vec<u8>) -> Self {
        self.raw = Some(bytes);
        self
    }
}

#[derive(Clone, Debug)]
pub struct Seen {
    /// The route name (`messages`, `post`, `token`, ...), "" for a path outside the contract.
    pub name: String,
    pub path: String,
    pub auth: Option<String>,
    /// The query (Graph) or the form (Entra), as an object of strings.
    pub params: Value,
    /// The JSON body of a Graph POST.
    pub body: Value,
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

#[derive(Default)]
struct Inner {
    handlers: HashMap<String, Handler>,
    seen: Vec<Seen>,
    /// The delegated scopes the (fake) sign-in holds; `None` is what `SCOPES` asks for.
    scopes: Option<Vec<String>>,
    /// Requests that broke the adapter's contract.
    bad: usize,
}

fn name_of(method: &str, path: &str) -> String {
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    let n = match (method, segs.as_slice()) {
        ("POST", [t, "oauth2", "v2.0", "devicecode"]) if tenant_seg(t) => "devicecode",
        ("POST", [t, "oauth2", "v2.0", "token"]) if tenant_seg(t) => "token",
        ("GET", ["v1.0", "me"]) => "me",
        ("GET", ["v1.0", "me", "joinedTeams"]) => "teams",
        ("GET", ["v1.0", "teams", t, "channels"]) if guid(t) => "channels",
        ("GET", ["v1.0", "teams", t, "channels", c, "messages"]) if guid(t) && channel_id(c) => {
            "messages"
        }
        ("POST", ["v1.0", "teams", t, "channels", c, "messages"]) if guid(t) && channel_id(c) => {
            "post"
        }
        ("GET", ["v1.0", "teams", t, "channels", c, "messages", m])
            if guid(t) && channel_id(c) && message_id(m) =>
        {
            "message"
        }
        ("GET", ["v1.0", "teams", t, "channels", c, "messages", m, "replies"])
            if guid(t) && channel_id(c) && message_id(m) =>
        {
            "replies"
        }
        ("POST", ["v1.0", "teams", t, "channels", c, "messages", m, "replies"])
            if guid(t) && channel_id(c) && message_id(m) =>
        {
            "reply"
        }
        _ => "",
    };
    n.to_owned()
}

fn tenant_seg(t: &str) -> bool {
    t == "organizations" || guid(t)
}

/// The delegated scope a route needs.
fn needs(name: &str) -> Option<&'static str> {
    Some(match name {
        "me" => "User.Read",
        "teams" => "Team.ReadBasic.All",
        "channels" => "Channel.ReadBasic.All",
        "messages" | "message" | "replies" => "ChannelMessage.Read.All",
        "post" | "reply" => "ChannelMessage.Send",
        _ => return None,
    })
}

/// The form parameters an Entra call may carry.
fn form_ok(name: &str, p: &Value) -> bool {
    let Some(o) = p.as_object() else { return false };
    let has = |k: &str| o.contains_key(k);
    let only = |allowed: &[&str]| o.keys().all(|k| allowed.contains(&k.as_str()));
    match name {
        "devicecode" => only(&["client_id", "scope"]) && has("client_id") && has("scope"),
        "token" => match o.get("grant_type").and_then(Value::as_str) {
            Some("refresh_token") => {
                only(&["grant_type", "client_id", "refresh_token", "scope"])
                    && has("client_id")
                    && has("refresh_token")
            }
            Some("urn:ietf:params:oauth:grant-type:device_code") => {
                only(&["grant_type", "client_id", "device_code"])
                    && has("client_id")
                    && has("device_code")
            }
            _ => false,
        },
        _ => false,
    }
}

fn query_ok(name: &str, p: &Value) -> bool {
    let Some(o) = p.as_object() else { return false };
    if o.is_empty() {
        return true;
    }
    let top_ok = o.get("$top").is_none_or(|t| {
        t.as_str()
            .and_then(|t| t.parse::<u64>().ok())
            .is_some_and(|n| (1..=50).contains(&n))
    });
    matches!(name, "messages" | "replies")
        && o.keys().all(|k| k == "$top" || k == "$skiptoken")
        && top_ok
}

fn body_ok(name: &str, b: &Value) -> bool {
    match name {
        "post" | "reply" => {
            let Some(o) = b.as_object() else { return false };
            let inner = o.get("body").and_then(Value::as_object);
            o.len() == 1
                && inner.is_some_and(|i| {
                    i.len() == 2
                        && i.get("contentType") == Some(&json!("text"))
                        && i.get("content").is_some_and(Value::is_string)
                })
        }
        _ => b.is_null(),
    }
}

/// The fake service: handlers by route name, and a log of everything it was asked.
#[derive(Clone, Default)]
pub struct Fake {
    inner: Arc<Mutex<Inner>>,
}

fn pairs(text: &str) -> Value {
    let url = reqwest::Url::parse(&format!("http://x/?{text}")).unwrap();
    let m: serde_json::Map<String, Value> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), json!(v.into_owned())))
        .collect();
    Value::Object(m)
}

async fn handle(State(f): State<Fake>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = to_bytes(body, 1 << 20).await.unwrap_or_default();
    let header = |n: &str| {
        let v = parts.headers.get(n).and_then(|v| v.to_str().ok());
        v.map(str::to_owned)
    };
    let method = parts.method.to_string();
    let path = parts.uri.path().to_owned();
    let name = name_of(&method, &path);
    let auth = header("authorization");
    let content_type = header("content-type").unwrap_or_default();
    let entra = matches!(name.as_str(), "devicecode" | "token");
    let (params, json_body) = if entra {
        (pairs(&String::from_utf8_lossy(&bytes)), Value::Null)
    } else {
        let q = parts.uri.query().unwrap_or_default();
        let b = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(json!("not json"))
        };
        (pairs(q), b)
    };
    let well_formed = if entra {
        // A public client: a form, no client secret, no Authorization, nothing in the query.
        content_type.starts_with("application/x-www-form-urlencoded")
            && auth.is_none()
            && parts.uri.query().is_none()
            && form_ok(&name, &params)
    } else {
        !name.is_empty()
            && auth.as_deref().is_some_and(|a| a.starts_with("Bearer "))
            && query_ok(&name, &params)
            && body_ok(&name, &json_body)
            && (json_body.is_null() || content_type.starts_with("application/json"))
    };
    let seen = Seen {
        name: name.clone(),
        path,
        auth,
        params,
        body: json_body,
    };
    let (handler, short) = {
        let mut i = f.inner.lock().unwrap();
        i.seen.push(seen.clone());
        if !well_formed {
            i.bad += 1;
        }
        let held = i
            .scopes
            .clone()
            .unwrap_or_else(|| SCOPES.split(' ').map(str::to_owned).collect());
        let short = needs(&name).filter(|n| !held.iter().any(|h| h == n));
        (i.handlers.get(&name).cloned(), short.is_some())
    };
    let r = match handler {
        _ if !well_formed => Reply::graph(400, "BadRequest"),
        _ if short => Reply::graph(403, "Forbidden"),
        Some(h) => h(&seen),
        None => Reply::http(404, json!({})),
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
    pub fn on(&self, name: &str, f: impl Fn(&Seen) -> Reply + Send + Sync + 'static) {
        let mut i = self.inner.lock().unwrap();
        i.handlers.insert(name.to_owned(), Arc::new(f));
    }

    pub fn reply(&self, name: &str, r: Reply) {
        self.on(name, move |_| r.clone());
    }

    /// Grants only these delegated scopes from now on.
    pub fn grant_scopes(&self, scopes: &[&str]) {
        let list = scopes.iter().map(|s| (*s).to_owned()).collect();
        self.inner.lock().unwrap().scopes = Some(list);
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.inner.lock().unwrap().seen.clone()
    }

    /// Requests that broke the adapter's contract.
    pub fn bad(&self) -> usize {
        self.inner.lock().unwrap().bad
    }

    pub fn count(&self, name: &str) -> usize {
        self.seen().iter().filter(|s| s.name == name).count()
    }

    pub fn last(&self, name: &str) -> Option<Seen> {
        self.seen().iter().rev().find(|s| s.name == name).cloned()
    }

    /// Requests that reached Graph (not Entra), whatever they were.
    pub fn graph_count(&self) -> usize {
        let graph = |s: &&Seen| !matches!(s.name.as_str(), "devicecode" | "token");
        self.seen().iter().filter(graph).count()
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

    /// A token endpoint that rotates: each refresh token works once and issues `acc<n>` and
    /// `ref<n>`; the spent one is `invalid_grant`. Returns the number of refreshes served.
    pub fn rotating(&self) -> Arc<AtomicUsize> {
        let served = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(Mutex::new(REFRESH.to_owned()));
        let n = served.clone();
        self.on("token", move |s| {
            let mut current = state.lock().unwrap();
            if s.params["refresh_token"].as_str() != Some(current.as_str()) {
                return Reply::entra(400, "invalid_grant");
            }
            let k = n.fetch_add(1, Ordering::SeqCst) + 2;
            *current = format!("ref{k}-refreshtok-000{k}-bbbbbbbb");
            Reply::ok(json!({"token_type": "Bearer", "scope": SCOPES,
                "access_token": format!("acc{k}-graphtok-000{k}-aaaaaaaa"),
                "refresh_token": *current, "expires_in": 3599}))
            .delayed(150)
        });
        served
    }
}

/// An id token Microsoft would issue to `aud` for tenant `tid` (unsigned: Core reads the payload).
pub fn id_token(aud: &str, tid: &str) -> String {
    let payload = json!({"aud": aud, "tid": tid, "oid": USER}).to_string();
    format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(payload))
}

pub struct Fx {
    pub fake: Fake,
    pub teams: Arc<Teams>,
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

/// A chat message of `channel`, as Graph shows one.
pub fn message(team: &str, channel: &str, id: &str, content: &str) -> Value {
    json!({"id": id, "replyToId": null, "etag": id, "messageType": "message",
        "createdDateTime": "2021-03-29T03:53:52.035Z", "lastModifiedDateTime": "2021-03-29T03:53:52.035Z",
        "deletedDateTime": null, "subject": null, "importance": "normal",
        "webUrl": "https://teams.microsoft.com/l/message/x", "chatId": null,
        "from": {"application": null, "device": null,
            "user": {"id": USER, "displayName": "Robin Kline", "userIdentityType": "aadUser"}},
        "body": {"contentType": "text", "content": content},
        "channelIdentity": {"teamId": team, "channelId": channel},
        "attachments": [], "mentions": [], "reactions": []})
}

/// The channel and team a route's path names (the fake's own parse of an adapter-built path).
fn ids(path: &str) -> (String, String) {
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    let team = segs.get(2).copied().unwrap_or_default().to_owned();
    let channel = segs.get(4).copied().unwrap_or_default().to_owned();
    (team, channel)
}

/// A database, a fake Microsoft and an adapter pointed at it; with an app when `app`. The fake
/// answers like a small tenant: two teams, three channels, `/me` as [`USER`].
pub async fn fx(app: bool) -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-teams-{}-{n}", std::process::id()));
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
    fake.reply(
        "me",
        Reply::ok(json!({"id": USER, "displayName": "Robin Kline"})),
    );
    fake.reply(
        "teams",
        Reply::ok(json!({"value": [
            {"id": TEAM_A, "displayName": "Alpha", "description": "first"},
            {"id": TEAM_B, "displayName": "Beta", "description": null}]})),
    );
    fake.on("channels", |s| {
        let (team, _) = ids(&s.path);
        let list = if team == TEAM_A {
            json!([{"id": CH_A1, "displayName": "General", "membershipType": "standard"},
                {"id": CH_A2, "displayName": "Secret", "membershipType": "private"}])
        } else {
            json!([{"id": CH_B1, "displayName": "General", "membershipType": "standard"}])
        };
        Reply::ok(json!({"value": list}))
    });
    fake.on("messages", |s| {
        let (team, channel) = ids(&s.path);
        Reply::ok(json!({"value": [message(&team, &channel, MSG, "hello")]}))
    });
    fake.on("message", |s| {
        let (team, channel) = ids(&s.path);
        Reply::ok(message(&team, &channel, MSG, "hello"))
    });
    fake.on("replies", |s| {
        let (team, channel) = ids(&s.path);
        Reply::ok(json!({"value": [message(&team, &channel, "1616990032999", "re")]}))
    });
    for route in ["post", "reply"] {
        fake.on(route, |s| {
            let (team, channel) = ids(&s.path);
            let text = s.body["body"]["content"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            Reply::http(201, message(&team, &channel, "1616990099999", &text))
        });
    }
    let app = app.then(|| TeamsApp::new(CLIENT, "organizations").unwrap());
    let teams = Arc::new(Teams::loopback(app, addr));
    let mut reg = Registry::new();
    reg.register(teams.clone()).unwrap();
    Fx {
        fake,
        teams,
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

    pub async fn connect(&self, name: &str, m: &Material) -> Connection {
        let new = NewConnection {
            kind: "teams",
            name,
            label: "A Microsoft tenant",
            auth_method: "oauth",
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

    /// A connection signed in at [`TENANT`], good for an hour.
    pub async fn signed_in(&self) -> Connection {
        self.connect("acme", &material(ACCESS, REFRESH, 3600)).await
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

/// A credential of [`TENANT`] that ends `expires_in` seconds after [`NOW`].
pub fn material(access: &str, refresh: &str, expires_in: i64) -> Material {
    super::cred::oauth_material(TENANT, access, refresh, &at(expires_in)).unwrap()
}

/// Runs `op` with `args` for connection `c` under `limit`, as the broker would.
pub async fn run(
    f: &Fx,
    c: &Connection,
    limit: &super::Limit,
    op: &str,
    args: Value,
) -> Result<Value, super::CallError> {
    f.teams.call(&f.cx(NOW), c, limit, op, &args).await
}

/// A credential of [`TENANT`] built from arbitrary token text (good for an hour).
pub fn oauth_wrapped(access: &str, refresh: &str) -> Material {
    super::cred::oauth_material(TENANT, access, refresh, &at(3600)).unwrap()
}
