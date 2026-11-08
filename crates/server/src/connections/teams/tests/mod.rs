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

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePool;

use super::{Ctx, SCOPES, Teams, TeamsApp};
use crate::connections::adapter::Registry;
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::connections::{Connection, NewConnection, Who, create};

mod confirm;
mod descriptor;
mod device;
mod errors;
mod fake;
mod limits;
mod ops;
mod pace;
mod renew;
mod renew_race;
mod safety;

pub use fake::{Fake, Reply, id_token, id_token_as};

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

/// The team a channel really belongs to in the fake tenant, and its kind.
fn home(channel: &str) -> (&'static str, &'static str) {
    match channel {
        CH_A1 => (TEAM_A, "standard"),
        CH_A2 => (TEAM_A, "private"),
        _ => (TEAM_B, "standard"),
    }
}

/// `GET /teams/{t}/channels/{c}` as Graph answers it. It does NOT refuse a channel asked under
/// another team: it shows the channel as it is (its `webUrl` names the team it really is in), the
/// way an id is looked up by itself.
pub fn channel_info(_asked: &str, channel: &str) -> Value {
    let (team, kind) = home(channel);
    json!({"id": channel, "displayName": "General", "membershipType": kind,
        "tenantId": TENANT,
        "webUrl": format!("https://teams.microsoft.com/l/channel/x/General?groupId={team}&tenantId={TENANT}")})
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
    fake.on("channel", |s| {
        let (team, channel) = ids(&s.path);
        Reply::ok(channel_info(&team, &channel))
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
