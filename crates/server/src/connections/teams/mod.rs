//! The Microsoft Teams kind adapter (C10; design `2026-11-06-core-connections-design` §3, §6, §9).
//!
//! - **Sign in**: the OAuth 2.0 DEVICE CODE flow ([`device`]): no redirect address, no client
//!   secret, nothing to paste. The person types a short code at Microsoft's page; Core polls,
//!   pins the tenant from the grant's id token, seals both tokens and renews them single flight
//!   ([`renew`]: Microsoft rotates the refresh token).
//! - **Calls** go through [`Teams::call`]: typed Graph operations ([`ops`]) whose URLs [`calls`]
//!   builds from validated ids, a channel limit enforced on the request AND the answer
//!   ([`answer`]), and a client that only reaches exactly `graph.microsoft.com` and
//!   `login.microsoftonline.com`, never follows a redirect and keeps no credential in an error
//!   ([`http`]).
//!
//! Delegated: a message is sent AS the person who signed in. Channels only: no chats or direct
//! messages, no mail, files or calendar, no deletion, no HTML, cards or mentions.
//!
//! No token paste: a Graph access token lasts about an hour and a pasted one has no refresh
//! token, so the only auth method is the sign-in, and a credential is replaced only by signing in
//! again (which must land in the same tenant).

mod answer;
mod calls;
mod cred;
mod device;
mod http;
mod oauth;
mod ops;
mod renew;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_util::future::{BoxFuture, FutureExt};
use serde_json::Value;
use sqlx::sqlite::SqlitePool;

pub use cred::{Cred, TenantCheck, check_tenant, secrets_of, tenant_id, tenant_of, unpack};
pub use device::{DeviceError, Granted, Pending, Step};
pub use http::CallError;
pub use oauth::{SCOPES, TeamsApp};
pub use ops::{Limit, Plan, resource_of};

use super::adapter::{
    AuthMethodSpec, Capability, Descriptor, Identity, KindAdapter, LimitKey, TestError,
};
use super::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::unix_secs;
use crate::store::connections::verdict::{self, TestOutcome};
use crate::store::connections::{Connection, Who};

/// The most Graph requests ONE call makes (the operation and a renewal's retry): the budget below
/// is in calls, Microsoft counts requests.
pub const MAX_REQUESTS_PER_CALL: u32 = calls::MAX_REQUESTS;
/// Microsoft's limit on one channel: 1 request a second per app per tenant (Graph throttling
/// limits, "channel messages"), the lowest figure this adapter can hit hard from one connection.
/// (Every connection of one tenant also shares the app's 20 requests a second per tenant; a 429
/// cools the connection and the broker's `connection_busy` keeps the wait.)
pub const CHANNEL_REQUESTS_PER_HOUR: u32 = 3_600;
/// Calls an hour through ONE connection: 60% of that limit, spread over the worst call.
const HOURLY_CALLS: u32 = CHANNEL_REQUESTS_PER_HOUR * 6 / 10 / MAX_REQUESTS_PER_CALL;

pub const DESCRIPTOR: Descriptor = Descriptor {
    kind: "teams",
    title: "Microsoft Teams",
    summary: "Read channels and threads and post messages in Microsoft Teams, as you, in chosen channels.",
    auth_methods: &[AuthMethodSpec {
        id: "oauth",
        title: "Sign in with Microsoft",
        help: "Type a short code at Microsoft's sign-in page, with your work or school account. \
               Nothing to copy or paste. A tenant admin may have to approve Core's app first; \
               messages are sent as you.",
        steps: &[
            "Choose Sign in with Microsoft",
            "Open the address shown and type the code",
            "Approve access with your work or school account",
        ],
        advanced: false,
    }],
    capabilities: &[
        Capability {
            name: "read_messages",
            title: "Read teams, channels, messages and replies",
            write: false,
            operations: &[
                "teams.list_teams",
                "teams.list_channels",
                "teams.list_messages",
                "teams.get_message",
                "teams.list_replies",
            ],
        },
        Capability {
            name: "post_messages",
            title: "Post messages and replies in channels, as you",
            write: true,
            operations: &["teams.post_message", "teams.reply_message"],
        },
    ],
    // Exactly two: Graph, and Entra's device code and token endpoints (never sent a bearer).
    hosts: &[http::API_HOST, http::AUTH_HOST],
    limits: &[LimitKey {
        key: "channels",
        title: "Channels",
        help: "Only these channels, as <team id>/<channel id without the 19: and @thread.tacv2 \
               around it> (list_channels shows each one's key), or <team id>/* for every \
               channel of one team. Team ids are lower-case GUIDs. No limit means every channel \
               you can see.",
    }],
    // No shape: Microsoft's tokens are JWTs or opaque strings with no documented prefix a
    // redactor could name without redacting every JWT (and refusing any other service's at the
    // secret gate). The credential is sealed base32 so the gate cannot misread it (`cred`), and
    // the broker scrubs the raw tokens from every answer.
    token_shapes: &[],
    refresh_prefixes: &[],
    own_shape_refresh: false,
    // A team or channel list is cut to the limit by the adapter.
    self_limited: &["teams.list_teams", "teams.list_channels"],
    hourly_calls: HOURLY_CALLS,
};

/// What a call needs from the store: the pool and sealer for the credential, and who and when.
pub struct Ctx<'a> {
    pub pool: &'a SqlitePool,
    /// An `Arc`: a renewal runs in a task of its own and keeps its own handle.
    pub sealer: &'a Arc<SecretBox>,
    pub who: Who<'a>,
}

/// `GET /me`: who the credential is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Viewer {
    /// The user's object id (a GUID): stable, never the display name.
    pub user_id: String,
    /// The tenant the credential is pinned to.
    pub tenant: String,
}

pub struct Teams {
    http: http::Http,
    /// Ainkrad's Microsoft app. Swapped in place by [`Teams::set_app`] (the API's config change):
    /// the server has ONE `Teams`, shared by the registry, the broker and the API.
    app: std::sync::RwLock<Option<TeamsApp>>,
    locks: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
    /// When each connection's token was last renewed (see `renew::Job::run`).
    recent: renew::Recent,
}

impl Teams {
    /// `app`: Ainkrad's Microsoft app; `None` leaves Sign in with Microsoft off.
    pub fn new(app: Option<TeamsApp>) -> Self {
        Self::with(http::Http::production(), app)
    }

    #[cfg(test)]
    pub(crate) fn loopback(app: Option<TeamsApp>, addr: std::net::SocketAddr) -> Self {
        Self::with(http::Http::loopback(addr), app)
    }

    fn with(http: http::Http, app: Option<TeamsApp>) -> Self {
        Self {
            http,
            app: std::sync::RwLock::new(app),
            locks: Mutex::default(),
            recent: Arc::default(),
        }
    }

    /// A copy of the app in force (it holds no secret).
    pub(super) fn app(&self) -> Option<TeamsApp> {
        self.app.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether Sign in with Microsoft is set up.
    pub fn app_configured(&self) -> bool {
        self.app().is_some()
    }

    /// Replaces Ainkrad's Microsoft app in place (a config change; whether it changed), keeping
    /// this one instance: its locks and the registry's and broker's handles to it stay valid.
    /// Sign-ins waiting under the old app are ended by the caller (`apps::reload`). Tokens already
    /// stored are renewed with the NEW app; a changed client id makes them fail to renew
    /// ([`CallError::AppConfig`], which is no verdict on the connection).
    pub fn set_app(&self, app: Option<TeamsApp>) -> bool {
        let mut cur = self.app.write().unwrap_or_else(|e| e.into_inner());
        let unchanged = match (&*cur, &app) {
            (None, None) => true,
            (Some(a), Some(b)) => a.same(b),
            _ => false,
        };
        if unchanged {
            return false;
        }
        *cur = app;
        true
    }

    /// `GET /me`: who the credential is, by object id, and the tenant it is pinned to.
    pub async fn viewer(&self, cred: &Cred) -> Result<Viewer, CallError> {
        let auth = cred
            .authorization()
            .ok_or(CallError::Internal("the stored credential is unusable"))?;
        let req = http::Req {
            method: reqwest::Method::GET,
            path: vec!["me".to_owned()],
            query: None,
            body: None,
        };
        let body = self.http.graph(auth, &req).await?.into_ok()?;
        let id = body
            .get("id")
            .and_then(Value::as_str)
            .filter(|i| cred::guid(i))
            .ok_or(CallError::Upstream(200))?;
        Ok(Viewer {
            user_id: id.to_owned(),
            tenant: cred.tenant().to_owned(),
        })
    }

    /// Tests connection `id` and records the outcome, the way `verdict::run_test` does but with
    /// the token renewed first. A renewal Microsoft REFUSES with `invalid_grant` (the refresh
    /// token is revoked, expired or spent) is a conclusive verdict: the credential is dead, so the
    /// connection becomes "sign in again". A renewal that merely failed (network, 5xx, rate limit,
    /// a bad app registration, a policy step-up) is inconclusive.
    pub async fn test_connection(
        &self,
        cx: &Ctx<'_>,
        id: i64,
    ) -> Result<Connection, crate::store::secrets::Error> {
        let c = crate::store::connections::get(cx.pool, cx.who.workspace, id).await?;
        if c.kind != "teams" {
            return crate::store::connections::refused("bad_request", "not a Teams connection");
        }
        // The verdict is recorded against the version the renewal judged (and the credential it
        // tested is that version's): a refusal of an old refresh token cannot condemn a credential
        // a person stored while the renewal ran.
        let (version, renewed) = self.renew_versioned(cx, id, None).await;
        if version == 0 {
            return crate::store::connections::refused(
                "secrets_unavailable",
                "the connection's credential did not open",
            );
        }
        let outcome = match renewed {
            Err(CallError::AuthFailed) => TestOutcome::Rejected,
            Err(_) => TestOutcome::Inconclusive,
            Ok(m) => match self.test(&m).await {
                Ok(identity) => TestOutcome::Passed(identity),
                Err(TestError::Rejected) => TestOutcome::Rejected,
                Err(TestError::Inconclusive) => TestOutcome::Inconclusive,
            },
        };
        match verdict::record_test(cx.pool, id, version, outcome, cx.who).await {
            // The credential changed while this was judged: the verdict was dropped, and the
            // connection as it now stands is the answer.
            Err(crate::store::secrets::Error::Refused {
                code: "conflict", ..
            }) => crate::store::connections::get(cx.pool, cx.who.workspace, id).await,
            other => other,
        }
    }
}

impl KindAdapter for Teams {
    fn descriptor(&self) -> &Descriptor {
        &DESCRIPTOR
    }

    /// `GET /me`; the identity is `<user object id> in <tenant id>`: both are stable ids, never a
    /// renameable name. Only a 401 on a token that is not past its expiry is a rejection (it
    /// disables the connection): an expired token, a 403, a rate limit, a 5xx or an unreadable
    /// answer say nothing about the credential, so they are inconclusive. Call [`Teams::fresh`]
    /// first so the token is not expired.
    fn test<'a>(&'a self, m: &'a Material) -> BoxFuture<'a, Result<Identity, TestError>> {
        async move {
            let cred = cred::unpack(m).ok_or(TestError::Inconclusive)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
            let expired = m
                .expires_at
                .as_deref()
                .and_then(unix_secs)
                .is_some_and(|e| e <= now + oauth::SKEW_SECS);
            match self.viewer(&cred).await {
                Ok(me) => Ok(Identity {
                    subject: cred::subject(&me.user_id, &me.tenant),
                }),
                Err(CallError::AuthFailed) if !expired => Err(TestError::Rejected),
                Err(_) => Err(TestError::Inconclusive),
            }
        }
        .boxed()
    }
}
