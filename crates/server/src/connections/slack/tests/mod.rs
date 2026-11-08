//! Tests of the Slack adapter. A fake Slack on loopback answers every request (the adapter is
//! pointed at it by `Slack::loopback`); no real network, no real token. The tokens are shapeless
//! on purpose (short, so the redactor names none): the broker's secret gate must not be what
//! hides a leak.
//!
//! The fake holds every request to the adapter's own contract: a POST of a form to
//! `/api/<one of Method::ALL>` with exactly that method's parameters, the token only in an
//! `Authorization` header (and no header at `oauth.v2.access`), never in the form or the query. A
//! request that breaks any of it is counted as `bad`, and the tests assert the count stays 0.
//! That is the proof that no caller text becomes a parameter, a header or a path.
//!
//! It enforces the scope of each method like Slack does: `200 {ok:false, error:missing_scope}`.

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

use super::http::Method;
use super::{Ctx, OAuthApp, Slack, oauth_material, token_material};
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
mod pace;
mod renew;
mod rotation;
mod safety;

pub const NOW: &str = "2026-11-06T10:00:00.000Z";
pub const ACCESS: &str = "xoxb-test-111-222-acc1";
pub const ROT_ACCESS: &str = "xoxe.xoxb-test-111-222-acc1";
pub const REFRESH: &str = "xoxe-1-test-ref1-91c4d2";
pub const CLIENT_SECRET: &str = "clsec-3b9f6e2d1a70";
pub const REDIRECT: &str = "https://core.example.test/connections/slack/callback";
pub const TEAM: &str = "T012AB3CD";
pub const BOT_USER: &str = "U012AB3CD";
pub const CH: &str = "C012AB3CD";
pub const CH2: &str = "C0123456789";
pub const PRIV: &str = "G012AB3CD";
pub const TS: &str = "1700000000.000100";

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

    /// A 200 `ok:true` with `fields` beside it.
    pub fn ok(fields: Value) -> Self {
        let mut body = json!({"ok": true});
        if let (Some(b), Some(f)) = (body.as_object_mut(), fields.as_object()) {
            b.extend(f.clone());
        }
        Self::http(200, body)
    }

    /// A 200 `ok:false` with `error`, the way Slack answers nearly everything.
    pub fn err(code: &str) -> Self {
        Self::http(200, json!({"ok": false, "error": code}))
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
    /// The Web API method name (`chat.postMessage`), "" for an unknown path.
    pub name: String,
    pub auth: Option<String>,
    /// The form, as an object of strings.
    pub form: Value,
}

type Handler = Arc<dyn Fn(&Seen) -> Reply + Send + Sync>;

#[derive(Default)]
struct Inner {
    handlers: HashMap<String, Handler>,
    seen: Vec<Seen>,
    /// The scopes the (fake) install holds; `None` is what `SCOPES` asks for.
    scopes: Option<Vec<String>>,
    /// Requests that broke the adapter's contract (see the module docs).
    bad: usize,
}

/// The scope a method needs.
fn needs(name: &str) -> Option<&'static str> {
    Some(match name {
        "conversations.history" | "conversations.replies" => "channels:history",
        "conversations.list" | "conversations.info" => "channels:read",
        "users.info" => "users:read",
        "chat.postMessage" => "chat:write",
        "reactions.add" => "reactions:write",
        _ => return None,
    })
}

/// The only parameters a method is ever sent. `blocks`, `attachments`, `metadata`, `username`,
/// `icon_*`, `as_user`, `reply_broadcast`, `link_names`, `markdown_text` and `token` are in none.
fn allowed(name: &str) -> &'static [&'static str] {
    match name {
        "auth.test" => &[],
        "conversations.info" => &["channel"],
        "conversations.history" => &["channel", "limit", "cursor", "oldest", "latest"],
        "conversations.replies" => &["channel", "ts", "limit", "cursor"],
        "conversations.list" => &["types", "exclude_archived", "limit", "cursor"],
        "users.info" => &["user"],
        "chat.postMessage" => &[
            "channel",
            "text",
            "parse",
            "unfurl_links",
            "unfurl_media",
            "thread_ts",
        ],
        "reactions.add" => &["channel", "timestamp", "name"],
        "oauth.v2.access" => &[
            "client_id",
            "client_secret",
            "code",
            "redirect_uri",
            "grant_type",
            "refresh_token",
        ],
        _ => &[],
    }
}

/// The fake service: handlers by Web API method name, and a log of everything it was asked.
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
    let name = path
        .strip_prefix("/api/")
        .and_then(|n| Method::ALL.iter().find(|m| m.name() == n))
        .map_or("", |m| m.name());
    let fields = form(&bytes);
    let is_form = content_type
        .as_deref()
        .is_some_and(|c| c.starts_with("application/x-www-form-urlencoded"));
    let auth = header("authorization");
    let names_ok = fields
        .as_object()
        .is_some_and(|o| o.keys().all(|k| allowed(name).contains(&k.as_str())));
    let auth_ok = match name {
        "oauth.v2.access" => auth.is_none(),
        _ => auth.as_deref().is_some_and(|a| a.starts_with("Bearer xox")),
    };
    let well_formed = !name.is_empty()
        && parts.method == "POST"
        && is_form
        && parts.uri.query().is_none()
        && names_ok
        && auth_ok;
    let seen = Seen {
        name: name.to_owned(),
        auth,
        form: fields,
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
            .unwrap_or_else(|| super::SCOPES.split(',').map(str::to_owned).collect());
        let short = needs(name).filter(|n| !held.iter().any(|h| h == n));
        (i.handlers.get(name).cloned(), short.map(|n| (n, held)))
    };
    let r = match handler {
        _ if !well_formed => Reply::http(400, json!({"ok": false, "error": "invalid_arguments"})),
        // A token that lacks the scope is refused, as Slack refuses a method it did not allow.
        _ if short.is_some() => {
            let (needed, held) = short.unwrap();
            Reply::http(
                200,
                json!({"ok": false, "error": "missing_scope", "needed": needed,
                    "provided": held.join(",")}),
            )
        }
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

    /// Answers method `name` with `r`.
    pub fn reply(&self, name: &str, r: Reply) {
        self.on(name, move |_| r.clone());
    }

    /// Grants only these scopes from now on.
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

    /// Every method seen, in order.
    pub fn names(&self) -> Vec<String> {
        self.seen().iter().map(|s| s.name.clone()).collect()
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

    /// Answers `conversations.info` the way Slack does for a channel: the id asked for, private
    /// when it is a `G…` id, and neither a direct message nor a group DM.
    pub fn default_info(&self) {
        self.on("conversations.info", |s| {
            let id = s.form["channel"].as_str().unwrap_or_default().to_owned();
            let private = id.starts_with('G');
            let channel = json!({"id": id, "is_private": private, "is_mpim": false,
                "is_im": false});
            Reply::ok(json!({"channel": channel}))
        });
    }

    /// A token endpoint that rotates: each refresh token works once and issues
    /// `xoxe.xoxb-test-111-222-acc<n>` and `xoxe-1-test-ref<n>-91c4d2`; the spent one is
    /// `invalid_refresh_token`. Returns the number of refreshes served.
    pub fn rotating(&self) -> Arc<AtomicUsize> {
        let served = Arc::new(AtomicUsize::new(0));
        let state = Arc::new(Mutex::new(REFRESH.to_owned()));
        let n = served.clone();
        self.on("oauth.v2.access", move |s| {
            let mut current = state.lock().unwrap();
            if s.form["refresh_token"].as_str() != Some(current.as_str()) {
                return Reply::err("invalid_refresh_token");
            }
            let k = n.fetch_add(1, Ordering::SeqCst) + 2;
            *current = format!("xoxe-1-test-ref{k}-91c4d2");
            Reply::ok(
                json!({"access_token": format!("xoxe.xoxb-test-111-222-acc{k}"),
                "token_type": "bot", "refresh_token": *current, "expires_in": 43200}),
            )
            .delayed(150)
        });
        served
    }
}

pub struct Fx {
    pub fake: Fake,
    pub slack: Arc<Slack>,
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

/// A database, a fake Slack and a Slack adapter pointed at it; with an OAuth app when `app`. The
/// fake answers `auth.test` as the bot [`BOT_USER`] of workspace [`TEAM`].
pub async fn fx(app: bool) -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-slack-{}-{n}", std::process::id()));
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
    fake.reply("auth.test", Reply::ok(auth_test(TEAM)));
    fake.default_info();
    let app = app.then(|| OAuthApp::new("1234.5678", CLIENT_SECRET, REDIRECT).unwrap());
    let slack = Arc::new(Slack::loopback(app, addr));
    let mut reg = Registry::new();
    reg.register(slack.clone()).unwrap();
    Fx {
        fake,
        slack,
        reg,
        pool,
        sealer: Arc::new(SecretBox::new(&[7; 32])),
        addr,
        dir,
    }
}

/// [`fx`] at `secrets.mode` 2, where a rotated token can be stored: the renewal tests.
pub async fn fx_rotating(app: bool) -> Fx {
    let f = fx(app).await;
    let set = crate::store::settings::set;
    let mode = set(
        &f.pool,
        Key::SecretsMode,
        Scope::Server,
        "2",
        AuditActor::System,
        NOW,
    );
    mode.await.unwrap();
    f
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
            kind: "slack",
            name,
            label: "A Slack workspace",
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

    /// A pasted-bot-token connection.
    pub async fn bot(&self) -> Connection {
        self.connect("acme", "token", &bot()).await
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

/// The body of an `auth.test` answer for a bot of workspace `team`.
pub fn auth_test(team: &str) -> Value {
    json!({"url": "https://acme.slack.com/", "team": "Acme", "user": "ainkrad",
        "team_id": team, "user_id": BOT_USER, "bot_id": "B012AB3CD"})
}

/// `secs` after [`NOW`].
pub fn at(secs: i64) -> String {
    iso_of_unix(unix_secs(NOW).unwrap() + secs)
}

/// A rotating install: `ROT_ACCESS`-shaped access token, a refresh token, `expires_in` from NOW.
pub fn rotating(access: &str, refresh: &str, expires_in: i64) -> Material {
    oauth_material(access, Some(refresh), Some(&at(expires_in))).unwrap()
}

pub fn bot() -> Material {
    token_material(ACCESS).unwrap()
}

/// What `conversations.history` answers: the given messages.
pub fn history(messages: Vec<Value>) -> Reply {
    Reply::ok(json!({"messages": messages, "has_more": false}))
}

pub fn msg(ts: &str, text: &str) -> Value {
    json!({"type": "message", "user": BOT_USER, "text": text, "ts": ts})
}
