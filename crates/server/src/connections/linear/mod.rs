//! The Linear kind adapter (C8; design `2026-11-06-core-connections-design` §3, §6).
//!
//! - **Sign in** (preferred): OAuth 2.0 authorization code with PKCE ([`oauth`]); Core builds the
//!   authorize URL, the Mac app catches the loopback redirect and hands back `code` and `state`,
//!   Core exchanges, seals access and refresh tokens, renews with single-flight rotation.
//! - **Token** (Advanced): a personal API key, sent as `Authorization: <key>` ([`cred`]).
//! - **Calls** go through [`Linear::call`]: fixed typed GraphQL documents ([`docs`]) whose
//!   variables [`ops`] rebuilds from validated arguments, a team limit enforced on the request AND
//!   the answer ([`answer`]), and a client that only reaches exactly `api.linear.app`, never
//!   follows a redirect and keeps no credential in an error ([`http`]).
//!
//! The sealed `Material` holds the bare credential (see [`cred`]).

mod answer;
mod calls;
mod cred;
mod docs;
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

pub use cred::{Cred, issue_identifier, key_material, oauth_material, team_key, unpack};
pub use http::{CallError, Quota};
pub use oauth::{Finished, FlowError, OAuthApp, SCOPES, Started};
pub use ops::{Limit, Plan, resource_of};

use super::adapter::{
    AuthMethodSpec, Capability, Descriptor, Identity, KindAdapter, LimitKey, TestError,
};
use super::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::unix_secs;
use crate::store::connections::verdict::{self, TestOutcome};
use crate::store::connections::{Connection, Who};

/// The most Linear requests one tool call makes: `list_teams` reads up to 5 pages; the dearest
/// change is a pre-read, a state check and the write (3). A 401 adds a retry only once, after which
/// the connection is out of use.
pub const MAX_REQUESTS_PER_CALL: u32 = 5;
/// Linear's budget for a personal API key, per user and hour, shared by all of that user's keys
/// (an OAuth app gets 5,000). Calls times requests per call stays under 60% of it.
pub const KEY_REQUESTS_PER_HOUR: u32 = 2500;

pub const DESCRIPTOR: Descriptor = Descriptor {
    kind: "linear",
    title: "Linear",
    summary: "Read and change Linear issues: search, comment, create, move through the workflow.",
    auth_methods: &[
        AuthMethodSpec {
            id: "oauth",
            title: "Sign in with Linear",
            help: "Approve Core in your browser. Nothing to copy or paste.",
            steps: &[
                "Choose Sign in with Linear",
                "Approve access in the browser window that opens",
            ],
            advanced: false,
        },
        AuthMethodSpec {
            id: "token",
            title: "Personal API key",
            help: "Use a personal API key from your Linear account. It can do what you can.",
            steps: &[
                "Open Linear, Settings, Account, Security and access, and create a personal API key",
                "Paste the key",
            ],
            advanced: true,
        },
    ],
    capabilities: &[
        Capability {
            name: "read_issues",
            title: "Read issues, teams and projects",
            write: false,
            operations: &[
                "linear.get_issue",
                "linear.search_issues",
                "linear.list_teams",
                "linear.list_workflow_states",
                "linear.list_projects",
            ],
        },
        Capability {
            name: "write_issues",
            title: "Create and edit issues, add comments",
            write: true,
            operations: &[
                "linear.create_issue",
                "linear.update_issue",
                "linear.add_comment",
            ],
        },
    ],
    // Exactly these two: `api.linear.app` for every call and the token endpoint, `linear.app` for
    // the authorize address only (built by Core, never fetched, never sent a bearer).
    hosts: &[http::API_HOST, http::AUTH_HOST],
    limits: &[LimitKey {
        key: "teams",
        title: "Teams",
        help: "Only these Linear teams, by key (ENG). No limit means every team.",
    }],
    // Linear's own changelog (linear.app/changelog/2021-08-19-github-secret-scanning) documents the
    // prefixes `lin_api_` (API keys) and `lin_oauth_` (OAuth access tokens): both are the redactor's
    // `linear_token`. No refresh token prefix is documented, so none is declared.
    token_shapes: &["linear_token"],
    refresh_prefixes: &[],
    // Whether Linear's refresh tokens share the access token's `lin_oauth_` prefix is not
    // documented: if they do, a sign-in must not be refused for it.
    own_shape_refresh: true,
    self_limited: &[
        "linear.search_issues",
        "linear.list_teams",
        "linear.list_projects",
    ],
    // Calls, not requests: one call is up to MAX_REQUESTS_PER_CALL requests, and the budget is Linear's
    // smaller one (the key's), so this is 60% of it spread over the worst call.
    hourly_calls: KEY_REQUESTS_PER_HOUR * 6 / 10 / MAX_REQUESTS_PER_CALL,
};

/// What a call needs from the store: the pool and sealer for the credential, and who and when.
pub struct Ctx<'a> {
    pub pool: &'a SqlitePool,
    /// An `Arc`: a renewal runs in a task of its own and keeps its own handle.
    pub sealer: &'a Arc<SecretBox>,
    pub who: Who<'a>,
}

/// `viewer`: who the credential is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Viewer {
    pub id: String,
    /// The workspace's url key (`acme` in `linear.app/acme`): a label, it can be renamed.
    pub workspace: String,
    /// The workspace's own id: what identifies it.
    pub org: String,
}

/// The identity line of a credential: `<user id> at <url key> (<organization id>)`. The
/// organization id is the stable part; it is what a re-sign-in or a replaced key is compared by.
pub fn identity_of(me: &Viewer) -> String {
    format!("{} at {} ({})", me.id, me.workspace, me.org)
}

/// The organization id of an identity line [`identity_of`] made.
pub fn org_of(identity: &str) -> Option<&str> {
    let (_, tail) = identity.rsplit_once(" (")?;
    tail.strip_suffix(')').filter(|o| org_id(o))
}

fn org_id(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Whether a credential for organization `org` may stand in for the connection whose stored
/// identity is `old`. Team keys (`ENG`) exist in every workspace, so a credential from another
/// one would silently re-aim the team limit at someone else's teams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgCheck {
    Same,
    Different,
    /// The connection has no stored organization id (never tested, or tested before ids were kept).
    Unknown,
}

pub fn check_org(old: Option<&str>, org: &str) -> OrgCheck {
    match old.and_then(org_of) {
        Some(o) if o == org => OrgCheck::Same,
        Some(_) => OrgCheck::Different,
        None => OrgCheck::Unknown,
    }
}

pub struct Linear {
    http: http::Http,
    /// Ainkrad's Linear app. Swapped in place by [`Linear::set_app`] (the API's config change):
    /// the server has ONE `Linear`, shared by the registry, the broker and the API.
    app: std::sync::RwLock<Option<OAuthApp>>,
    flows: Mutex<oauth::Flows>,
    locks: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
    /// When each connection's token was last renewed (see `renew::Job::run`).
    recent: renew::Recent,
    /// The budget Linear last reported per connection, taken by the broker after a call.
    quotas: Mutex<HashMap<i64, Quota>>,
}

fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

impl Linear {
    /// `app`: Ainkrad's Linear app; `None` leaves Sign in with Linear off (token auth works).
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
            quotas: Mutex::default(),
        }
    }

    pub(super) fn note_quota(&self, id: i64, q: Quota) {
        if q == (None, None, None) {
            return;
        }
        let mut map = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= 256 && !map.contains_key(&id) {
            map.clear();
        }
        map.insert(id, q);
    }

    /// What Linear last said about connection `id`'s budget, once: the broker feeds it to its
    /// local `connection_busy` refusal, as for GitHub.
    pub fn quota(&self, id: i64) -> Option<Quota> {
        let mut map = self.quotas.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(&id)
    }

    /// A copy of the OAuth app in force (it holds no token).
    pub(super) fn app(&self) -> Option<OAuthApp> {
        self.app.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether Sign in with Linear is set up.
    pub fn app_configured(&self) -> bool {
        self.app().is_some()
    }

    /// The redirect addresses registered with Linear (none when no app is set).
    pub fn redirects(&self) -> Vec<String> {
        self.app()
            .map(|a| a.redirects().to_vec())
            .unwrap_or_default()
    }

    /// Replaces Ainkrad's Linear app in place (a config change; whether it changed), keeping this
    /// one instance: its locks and the registry's and broker's handles to it stay valid. When the
    /// app really changed, sign-ins started under the old one are dropped: a code issued for one
    /// client id cannot be exchanged by another. Tokens already stored are renewed with the NEW
    /// app; a changed client id makes them fail to renew (`invalid_client`: [`CallError::AppConfig`],
    /// which is no verdict on the connection), and those connections sign in again.
    pub fn set_app(&self, app: Option<OAuthApp>) -> bool {
        let mut cur = self.app.write().unwrap_or_else(|e| e.into_inner());
        let unchanged = match (&*cur, &app) {
            (None, None) => true,
            (Some(a), Some(b)) => a.same(b),
            _ => false,
        };
        // A write that left the Linear app as it was ends nobody's sign-in.
        if unchanged {
            return false;
        }
        self.flows.lock().unwrap_or_else(|e| e.into_inner()).clear();
        *cur = app;
        true
    }

    /// `viewer`: who the credential is, and the workspace it is in.
    pub async fn viewer(&self, cred: &Cred) -> Result<Viewer, CallError> {
        let auth = cred
            .authorization()
            .ok_or(CallError::Internal("the stored credential is unusable"))?;
        let none = serde_json::json!({});
        let res = self
            .http
            .graphql(auth, docs::VIEWER.query, docs::VIEWER.name, &none)
            .await?;
        let data = res.into_data()?;
        let v = data.get("viewer").ok_or(CallError::Upstream(200))?;
        let text = |o: &Value, k: &str| {
            o.get(k)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(|s| clean(s, 128))
        };
        let org = v.get("organization").ok_or(CallError::Upstream(200))?;
        let org_id = text(org, "id").filter(|o| self::org_id(o));
        match (text(v, "id"), text(org, "urlKey"), org_id) {
            (Some(id), Some(workspace), Some(org)) => Ok(Viewer { id, workspace, org }),
            _ => Err(CallError::Upstream(200)),
        }
    }

    /// Tests connection `id` and records the outcome, the way `verdict::run_test` does but with the
    /// token renewed first. A renewal the service REFUSES with `invalid_grant` (the refresh token
    /// is revoked or spent) is a conclusive verdict: the credential is dead, so the connection
    /// becomes "sign in again". A renewal that merely failed (network, 5xx, rate limit, a bad
    /// app registration) is inconclusive.
    pub async fn test_connection(
        &self,
        cx: &Ctx<'_>,
        id: i64,
    ) -> Result<Connection, crate::store::secrets::Error> {
        let c = crate::store::connections::get(cx.pool, cx.who.workspace, id).await?;
        if c.kind != "linear" {
            return crate::store::connections::refused("bad_request", "not a Linear connection");
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

impl KindAdapter for Linear {
    fn descriptor(&self) -> &Descriptor {
        &DESCRIPTOR
    }

    /// `viewer`; the identity is `<user id> at <url key> (<organization id>)` (see [`identity_of`]). Only a refusal of a token that is not past its expiry is a rejection (it
    /// disables the connection): an expired OAuth token, a rate limit, a 5xx or an unreadable
    /// answer say nothing about the credential, so they are inconclusive. Call [`Linear::fresh`]
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
                    subject: identity_of(&me),
                }),
                Err(CallError::AuthFailed) if !expired => Err(TestError::Rejected),
                Err(_) => Err(TestError::Inconclusive),
            }
        }
        .boxed()
    }
}
