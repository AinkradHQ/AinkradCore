//! The fake Microsoft: a loopback Graph and Entra that hold every request to the adapter's contract
//! and count any that breaks it (see the module docs of `tests`).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Request, State};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use super::super::SCOPES;
use super::super::cred::{channel_id, guid, message_id};
use super::*;

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

    /// Entra's `invalid_grant` for a refresh token that is dead for good (AADSTS700082).
    pub fn dead_grant() -> Self {
        Self::grant_error(&[700_082], None)
    }

    /// An `invalid_grant` with these `error_codes` (and a `suberror`, as a step-up carries one).
    pub fn grant_error(codes: &[u64], suberror: Option<&str>) -> Self {
        let mut body = json!({"error": "invalid_grant", "error_description": "AADSTS: never shown",
            "error_codes": codes});
        if let Some(s) = suberror {
            body["suberror"] = json!(s);
        }
        Self::http(400, body)
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
        ("GET", ["v1.0", "teams", t, "channels", c]) if guid(t) && channel_id(c) => "channel",
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
        "channels" | "channel" => "Channel.ReadBasic.All",
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
                return Reply::dead_grant();
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
    id_token_as(aud, tid, USER)
}

/// [`id_token`] for the user `oid`.
pub fn id_token_as(aud: &str, tid: &str, oid: &str) -> String {
    let payload = json!({"aud": aud, "tid": tid, "oid": oid}).to_string();
    format!("e30.{}.sig", URL_SAFE_NO_PAD.encode(payload))
}
