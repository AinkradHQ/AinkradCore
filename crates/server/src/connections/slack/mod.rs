//! The Slack kind adapter (C9; design `2026-11-06-core-connections-design` §3, §6, §9).
//!
//! - **Sign in** (preferred, needs an `https` catcher: Slack refuses a loopback `http` redirect):
//!   OAuth v2 "Add to Slack" ([`oauth`]); Core builds the authorize URL, whatever catches the
//!   redirect hands back `code` and `state`, Core exchanges and seals the bot token (and, for an
//!   app with token rotation, its refresh token, renewed single flight).
//! - **Token** (Advanced): a bot token (`xoxb-…`) pasted by an admin ([`cred`]).
//! - **Calls** go through [`Slack::call`]: fixed Web API methods ([`http::Method`]) whose forms
//!   [`ops`] rebuilds from validated arguments, a channel limit enforced on the request AND the
//!   answer ([`answer`], [`calls`]), and a client that only reaches exactly `slack.com`, never
//!   follows a redirect and keeps no credential in an error ([`http`]).
//!
//! Bots only: a user token would send as a person and reach their DMs. No DMs, no file transfer,
//! no admin or user-list methods, no `blocks`, no impersonation, no `@channel`-style pings.

mod answer;
mod calls;
mod cred;
mod http;
mod oauth;
mod ops;
mod pace;
mod renew;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_util::future::{BoxFuture, FutureExt};
use serde_json::Value;
use sqlx::sqlite::SqlitePool;

pub use cred::{
    Cred, TeamCheck, channel_id, check_team, oauth_material, token_material, unpack, workspace_of,
};
pub use http::CallError;
pub use oauth::{
    Finished, FlowError, OAuthApp, OAuthApp as SlackApp, SCOPES, Started, redirect_ok,
};
pub use ops::{Limit, Plan, resource_of};

use super::adapter::{
    AuthMethodSpec, Capability, Descriptor, Identity, KindAdapter, LimitKey, TestError,
};
use super::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::unix_secs;
use crate::store::connections::verdict::{self, TestOutcome};
use crate::store::connections::{Connection, Who};

/// The most requests ONE call makes (5 list pages and a renewal's retry): the budget below is in
/// calls, Slack counts requests.
pub const MAX_REQUESTS_PER_CALL: u32 = calls::MAX_REQUESTS;
/// `conversations.list` is Tier 2 (20 a minute, 1,200 an hour), the lowest tier this adapter
/// touches that a limited connection can hit hard. (History and replies are 1 a minute for
/// distributed apps outside Slack's Marketplace: a 429 cools the connection, bounded.)
pub const LIST_REQUESTS_PER_HOUR: u32 = 1_200;
/// Calls an hour through ONE connection: 60% of the lowest tier, spread over the worst call.
const HOURLY_CALLS: u32 = LIST_REQUESTS_PER_HOUR * 6 / 10 / MAX_REQUESTS_PER_CALL;

pub const DESCRIPTOR: Descriptor = Descriptor {
    kind: "slack",
    title: "Slack",
    summary: "Read channels and threads and post messages in Slack, as a bot, in chosen channels.",
    auth_methods: &[
        AuthMethodSpec {
            id: "oauth",
            title: "Add to Slack",
            help: "Approve Core's Slack app for one workspace in your browser. Needs an https \
                   redirect page on this Core's side, which an admin sets up; until then use the \
                   bot token. A workspace admin may have to approve the app first. The bot reads \
                   and posts only where it was invited.",
            steps: &[
                "Choose Add to Slack",
                "Pick the workspace and approve access in the browser window that opens",
                "Invite the bot to the channels it should use",
            ],
            advanced: false,
        },
        AuthMethodSpec {
            id: "token",
            title: "Bot token",
            help: "Use the bot token (xoxb-) of a Slack app installed in your workspace. Give the \
                   app only the scopes it needs, and never im:*, mpim:* or user scopes.",
            steps: &[
                "Open api.slack.com/apps, create an app and add the bot scopes channels:read, \
                 groups:read, channels:history, groups:history, chat:write, reactions:write and \
                 users:read",
                "Install the app to your workspace and copy the Bot User OAuth Token (xoxb-)",
                "Paste the token, and invite the bot to the channels it should use",
            ],
            advanced: true,
        },
    ],
    capabilities: &[
        Capability {
            name: "read_messages",
            title: "Read channels, threads and user names",
            write: false,
            operations: &[
                "slack.list_channels",
                "slack.read_channel",
                "slack.read_thread",
                "slack.get_user",
            ],
        },
        Capability {
            name: "post_messages",
            title: "Post messages and reactions",
            write: true,
            operations: &["slack.post_message", "slack.add_reaction"],
        },
    ],
    // Exactly one: the Web API, `oauth.v2.access` and the authorize address Core builds (never
    // fetched, never sent a token) are all on `slack.com`.
    hosts: &[http::HOST],
    limits: &[LimitKey {
        key: "channels",
        title: "Channels",
        help: "Only these Slack channels, by channel ID (C0123456789). No limit means every \
               channel the bot is in.",
    }],
    // The redactor's name for `xoxb-`, `xoxp-`, the rotating `xoxe.xoxb-` / `xoxe.xoxp-` access
    // tokens and the `xoxe-` refresh token (Slack documents that prefix). A refresh token is never
    // the access token, and its own shape is admitted in the refresh slot. A rotating ACCESS token
    // holds a second Slack shape, so the gate admits one only at `secrets.mode` 2.
    token_shapes: &["slack_token"],
    refresh_prefixes: &["xoxe-"],
    own_shape_refresh: true,
    // A channel list is cut to the limit by the adapter; a user lookup names no channel and
    // returns a tiny typed set of a workspace member's public names.
    self_limited: &["slack.list_channels", "slack.get_user"],
    hourly_calls: HOURLY_CALLS,
};

/// What a call needs from the store: the pool and sealer for the credential, and who and when.
pub struct Ctx<'a> {
    pub pool: &'a SqlitePool,
    /// An `Arc`: a renewal runs in a task of its own and keeps its own handle.
    pub sealer: &'a Arc<SecretBox>,
    pub who: Who<'a>,
}

/// `auth.test`: who the credential is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Viewer {
    /// The bot's user id (`U…`).
    pub user_id: String,
    /// The workspace's stable id (`T…`): what identity and re-sign-in compare. Never the name.
    pub team_id: String,
}

pub struct Slack {
    http: http::Http,
    /// Ainkrad's Slack app. Swapped in place by [`Slack::set_app`] (the API's config change):
    /// the server has ONE `Slack`, shared by the registry, the broker and the API.
    app: std::sync::RwLock<Option<OAuthApp>>,
    flows: Mutex<oauth::Flows>,
    locks: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
    /// When each connection's token was last renewed (see `renew::Job::run`).
    recent: renew::Recent,
    /// Local cooling by method family and the channels confirmed ([`pace`]).
    pace: pace::Pace,
}

impl Slack {
    /// `app`: Ainkrad's Slack app; `None` leaves Add to Slack off (token auth works).
    pub fn new(app: Option<OAuthApp>) -> Self {
        Self::with(http::Http::production(), app)
    }

    #[cfg(test)]
    pub(crate) fn loopback(app: Option<OAuthApp>, addr: std::net::SocketAddr) -> Self {
        Self::with(http::Http::loopback(addr), app)
    }

    fn with(http: http::Http, app: Option<OAuthApp>) -> Self {
        Self {
            http,
            app: std::sync::RwLock::new(app),
            flows: Mutex::default(),
            locks: Mutex::default(),
            recent: Arc::default(),
            pace: pace::Pace::default(),
        }
    }

    /// Tests: this adapter with its own pacing (a short confirmation lifetime).
    #[cfg(test)]
    pub(crate) fn with_pace(mut self, pace: pace::Pace) -> Self {
        self.pace = pace;
        self
    }

    /// A copy of the OAuth app in force (it holds no token).
    pub(super) fn app(&self) -> Option<OAuthApp> {
        self.app.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether Add to Slack is set up.
    pub fn app_configured(&self) -> bool {
        self.app().is_some_and(|a| a.signs_in())
    }

    /// Whether the Slack app is set up with token rotation on (its tokens expire in 12 hours and
    /// come with a single-use refresh token).
    pub fn rotation(&self) -> bool {
        self.app().is_some_and(|a| a.rotation())
    }

    /// The redirect addresses registered with Slack (none when no app is set; one otherwise).
    pub fn redirects(&self) -> Vec<String> {
        let redirect = self.app().and_then(|a| a.redirect().map(str::to_owned));
        redirect.into_iter().collect()
    }

    /// Replaces Ainkrad's Slack app in place (a config change; whether it changed), keeping this
    /// one instance: its locks and the registry's and broker's handles to it stay valid. When the
    /// app really changed, sign-ins started under the old one are dropped. Rotating tokens already
    /// stored are renewed with the NEW app; a changed client id makes them fail to renew
    /// ([`CallError::AppConfig`], which is no verdict on the connection).
    pub fn set_app(&self, app: Option<OAuthApp>) -> bool {
        let mut cur = self.app.write().unwrap_or_else(|e| e.into_inner());
        let unchanged = match (&*cur, &app) {
            (None, None) => true,
            (Some(a), Some(b)) => a.same(b),
            _ => false,
        };
        // A write that left the Slack app as it was ends nobody's sign-in.
        if unchanged {
            return false;
        }
        self.flows.lock().unwrap_or_else(|e| e.into_inner()).clear();
        *cur = app;
        true
    }

    /// `auth.test`: who the credential is, and the workspace it is in. A token with no bot (a
    /// user token) or an enterprise-wide one is [`CallError::Refused`]: Core holds bots of one
    /// workspace only.
    pub async fn viewer(&self, cred: &Cred) -> Result<Viewer, CallError> {
        let auth = cred
            .authorization()
            .ok_or(CallError::Internal("the stored credential is unusable"))?;
        let res = self
            .http
            .call(Some(auth), http::Method::AuthTest, &[])
            .await?;
        let body = res.into_ok()?;
        let text = |k: &str| {
            body.get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        };
        let not_bot = || CallError::Refused("that token is not a bot of one workspace".into());
        if body.get("is_enterprise_install").and_then(Value::as_bool) == Some(true) {
            return Err(not_bot());
        }
        match (text("user_id"), text("team_id"), text("bot_id")) {
            (Some(u), Some(t), Some(_)) if cred::user_id(u) && cred::team_id(t) => Ok(Viewer {
                user_id: u.to_owned(),
                team_id: t.to_owned(),
            }),
            (_, _, None) => Err(not_bot()),
            _ => Err(CallError::Upstream(200)),
        }
    }

    /// Tests connection `id` and records the outcome, the way `verdict::run_test` does but with the
    /// token renewed first. A renewal Slack REFUSES with `invalid_refresh_token` (the refresh token
    /// is revoked or spent) is a conclusive verdict: the credential is dead, so the connection
    /// becomes "sign in again". A renewal that merely failed (network, 5xx, rate limit, a bad app
    /// registration) is inconclusive.
    pub async fn test_connection(
        &self,
        cx: &Ctx<'_>,
        id: i64,
    ) -> Result<Connection, crate::store::secrets::Error> {
        let c = crate::store::connections::get(cx.pool, cx.who.workspace, id).await?;
        if c.kind != "slack" {
            return crate::store::connections::refused("bad_request", "not a Slack connection");
        }
        // Suspended for a rotation it could not store: the refresh token is spent, so asking
        // Slack again can only fail. It stays as it is until a credential is stored.
        if c.state_reason.as_deref() == Some(crate::store::connections::suspend::NEEDS_MODE_2) {
            return Ok(c);
        }
        // The verdict is recorded against the version the renewal judged (and the credential it
        // tested is that version's): a refusal of an old refresh token cannot condemn a credential
        // a person stored while the renewal ran.
        let (version, renewed) = self.renew_versioned(cx, id, None).await;
        // The refresh token could not be spent safely (`secrets.mode` below 2): the connection is
        // suspended as it stands, and a test says nothing more.
        if matches!(renewed, Err(CallError::NeedsMode2)) {
            return crate::store::connections::get(cx.pool, cx.who.workspace, id).await;
        }
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

impl KindAdapter for Slack {
    fn descriptor(&self) -> &Descriptor {
        &DESCRIPTOR
    }

    /// `auth.test`; the identity is `<bot user id> in <workspace id>`: both are stable ids, never
    /// a renameable name. Only a refusal of a token that is not past its expiry (or one that is
    /// no bot) is a rejection (it disables the connection): an expired rotating token, a rate
    /// limit, a 5xx or an unreadable answer say nothing about the credential, so they are
    /// inconclusive. Call [`Slack::fresh`] first so the token is not expired.
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
                    subject: format!("{} in {}", me.user_id, me.team_id),
                }),
                Err(CallError::AuthFailed) if !expired => Err(TestError::Rejected),
                Err(CallError::Refused(_)) => Err(TestError::Rejected),
                Err(_) => Err(TestError::Inconclusive),
            }
        }
        .boxed()
    }
}
