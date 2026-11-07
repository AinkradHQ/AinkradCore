//! The Jira (Atlassian) kind adapter (C3; design `2026-11-06-core-connections-design` §3, §6).
//!
//! - **Sign in** (preferred): OAuth 2.0 3LO with PKCE ([`oauth`]); Core builds the authorize URL,
//!   the Mac app catches the loopback redirect and hands back `code` and `state`, Core exchanges,
//!   seals access and refresh tokens, renews with single-flight rotation.
//! - **Token** (Advanced): email and API token, Basic auth against `<site>.atlassian.net`,
//!   validated strictly ([`cred::site_host`]).
//! - **Calls** go through [`Jira::call`]: the typed operations of [`ops`], a project limit
//!   enforced on the request and the answer, a client that only reaches exactly `api.atlassian.com`
//!   (or the validated site host), never follows a redirect and keeps no credential in an error.
//!
//! The sealed `Material` holds a Jira envelope ([`cred`]), because the generic adapter test sees
//! only the material: the site and cloud id ride inside it.

mod answer;
mod cred;
mod http;
mod jql;
mod oauth;
mod ops;
mod renew;
#[cfg(test)]
pub(crate) mod tests;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_util::future::{BoxFuture, FutureExt};
use reqwest::Method;
use serde_json::Value;
use sqlx::sqlite::SqlitePool;

pub use cred::{
    Cred, issue_key, oauth_material, project_key, site_host, site_host_of, token_material, unpack,
};
pub use http::CallError;
pub use oauth::{Finished, FlowError, OAuthApp, SCOPES, Site, Started};
pub use ops::{Limit, Plan, resource_of};

use super::adapter::{
    AuthMethodSpec, Capability, Descriptor, Identity, KindAdapter, LimitKey, TestError,
};
use super::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::unix_secs;
use crate::store::connections::verdict::{self, TestOutcome};
use crate::store::connections::{Connection, Who};

pub const DESCRIPTOR: Descriptor = Descriptor {
    kind: "jira",
    title: "Jira",
    summary: "Read and change Jira issues: search, comment, create, move through the workflow.",
    auth_methods: &[
        AuthMethodSpec {
            id: "oauth",
            title: "Sign in with Atlassian",
            help: "Approve Core in your browser. Nothing to copy or paste.",
            steps: &[
                "Choose Sign in with Atlassian",
                "Approve access in the browser window that opens",
                "Pick the Jira site to connect",
            ],
            advanced: false,
        },
        AuthMethodSpec {
            id: "token",
            title: "Email and API token",
            help: "Use an Atlassian API token for your account on one Jira site.",
            steps: &[
                "Open id.atlassian.com, Security, API tokens, and create a token",
                "Enter your Atlassian email and your site, like acme.atlassian.net",
                "Paste the token",
            ],
            advanced: true,
        },
    ],
    capabilities: &[
        Capability {
            name: "read_issues",
            title: "Read issues and projects",
            write: false,
            operations: &[
                "jira.search_issues",
                "jira.get_issue",
                "jira.list_transitions",
                "jira.list_projects",
            ],
        },
        Capability {
            name: "write_issues",
            title: "Create and edit issues, add comments",
            write: true,
            operations: &["jira.create_issue", "jira.update_issue", "jira.add_comment"],
        },
        Capability {
            name: "transition",
            title: "Move issues through the workflow",
            write: true,
            operations: &["jira.transition_issue"],
        },
    ],
    // Exactly these two. A token-auth connection's own `<site>.atlassian.net` is validated per
    // connection (`cred::site_host`), never by suffix.
    hosts: &[http::API_HOST, http::AUTH_HOST],
    limits: &[LimitKey {
        key: "projects",
        title: "Projects",
        help: "Only these Jira projects, by key (ABC). No limit means every project.",
    }],
    // Atlassian's own tokens are not a shape the redactor names (C2 reads this for GitHub).
    token_shapes: &[],
    refresh_prefixes: &[],
    self_limited: &["jira.search_issues", "jira.list_projects"],
    // Jira Cloud limits by cost and says so with 429 and Retry-After; this is a conservative ceiling.
    hourly_calls: 2000,
};

/// What a call needs from the store: the pool and sealer for the credential, and who and when.
pub struct Ctx<'a> {
    pub pool: &'a SqlitePool,
    /// An `Arc`: a renewal runs in a task of its own and keeps its own handle.
    pub sealer: &'a Arc<SecretBox>,
    pub who: Who<'a>,
}

/// `GET /myself`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Myself {
    pub account_id: String,
    pub display_name: String,
    pub site: String,
}

pub struct Jira {
    http: http::Http,
    app: Option<OAuthApp>,
    flows: Mutex<oauth::Flows>,
    locks: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
    /// When each connection's token was last renewed (see `oauth::Job::run`).
    recent: renew::Recent,
}

fn clean(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

impl Jira {
    /// `app`: Ainkrad's Atlassian app; `None` leaves Sign in with Atlassian off (token auth works).
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
            app,
            flows: Mutex::default(),
            locks: Mutex::default(),
            recent: Arc::default(),
        }
    }

    fn url(&self, cred: &Cred, path: &str) -> String {
        match cred {
            Cred::Oauth { cloud_id, .. } => {
                format!("{}/ex/jira/{cloud_id}/rest/api/3{path}", self.http.api)
            }
            Cred::Basic { host, .. } => {
                format!("{}/rest/api/3{path}", self.http.site_base(host))
            }
        }
    }

    async fn send(&self, cred: &Cred, req: &ops::Req) -> Result<Value, CallError> {
        let url = self.url(cred, &req.path);
        self.send_url(cred, req.method.clone(), &url, req.body.as_ref())
            .await
    }

    async fn send_url(
        &self,
        cred: &Cred,
        method: Method,
        url: &str,
        body: Option<&Value>,
    ) -> Result<Value, CallError> {
        let site = match cred {
            Cred::Basic { host, .. } => Some(host.as_str()),
            Cred::Oauth { .. } => None,
        };
        let auth = cred
            .authorization()
            .ok_or(CallError::Internal("the stored credential is unusable"))?;
        let res = self.http.send(site, method, url, Some(auth), body).await?;
        res.into_ok()
    }

    /// One authenticated request with a stored credential: an OAuth 401 renews the token once
    /// (single-flight) and retries once. A second 401 is [`CallError::AuthFailed`].
    async fn authed(&self, cx: &Ctx<'_>, id: i64, req: &ops::Req) -> Result<Value, CallError> {
        let not_jira = CallError::Internal("the credential is not a Jira one");
        let m = self.fresh(cx, id).await?;
        let cred = cred::unpack(&m).ok_or(not_jira.clone())?;
        match self.send(&cred, req).await {
            Err(CallError::AuthFailed) if cred.is_oauth() => {
                let rejected = zeroize::Zeroizing::new(m.access().to_owned());
                let m = self.renew(cx, id, Some(rejected.as_str())).await?;
                let cred = cred::unpack(&m).ok_or(not_jira)?;
                self.send(&cred, req).await
            }
            other => other,
        }
    }

    /// Runs operation `op` (`jira.get_issue`) of connection `c` for `limit` (from the grant that
    /// let the call through, see [`Limit::from_grant`]). The caller (the broker) has already
    /// resolved the connection and its grant; this enforces the project limit on top, on the
    /// request and on the answer. Errors are [`CallError`]; none carries a credential.
    pub async fn call(
        &self,
        cx: &Ctx<'_>,
        c: &Connection,
        limit: &Limit,
        op: &str,
        args: &Value,
    ) -> Result<Value, CallError> {
        if c.kind != "jira" {
            return Err(CallError::Internal("not a Jira connection"));
        }
        let plan = ops::plan(op, args, limit).map_err(CallError::Refused)?;
        if let (ops::Guard::Preread, Some(key)) = (plan.guard, &plan.key) {
            let pre = ops::Req {
                method: Method::GET,
                path: format!("/issue/{key}?fields=project"),
                body: None,
            };
            let v = self.authed(cx, c.id, &pre).await?;
            answer::check_preread(&v, limit).map_err(CallError::Refused)?;
        }
        let v = self.authed(cx, c.id, &plan.req).await?;
        answer::check_result(plan.guard, v, limit).map_err(CallError::Refused)
    }

    /// Who the credential is. OAuth asks `https://api.atlassian.com/me` (covered by `read:me`);
    /// `/rest/api/3/myself` would need `read:jira-user`, which is not requested. A token
    /// connection asks the site's `/myself`.
    pub async fn myself(&self, cred: &Cred) -> Result<Myself, CallError> {
        let (url, id_key, name_key) = match cred {
            Cred::Oauth { .. } => (format!("{}/me", self.http.api), "account_id", "name"),
            Cred::Basic { .. } => (self.url(cred, "/myself"), "accountId", "displayName"),
        };
        let v = self.send_url(cred, Method::GET, &url, None).await?;
        let id = v
            .get(id_key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        Ok(Myself {
            account_id: clean(id.ok_or(CallError::Upstream(200))?, 128),
            display_name: clean(
                v.get(name_key)
                    .and_then(Value::as_str)
                    .unwrap_or("Jira user"),
                80,
            ),
            site: cred.site(),
        })
    }

    /// Whether the account still reaches an OAuth connection's site (`accessible-resources`, no
    /// scope needed); `None` when that could not be read. A token connection has no cloud id.
    async fn site_listed(&self, cred: &Cred) -> Option<bool> {
        let Cred::Oauth { cloud_id, .. } = cred else {
            return Some(true);
        };
        let url = format!("{}/oauth/token/accessible-resources", self.http.api);
        let v = self.send_url(cred, Method::GET, &url, None).await.ok()?;
        let sites = v.as_array()?;
        let listed = |s: &Value| s.get("id").and_then(Value::as_str) == Some(cloud_id.as_str());
        Some(sites.iter().any(listed))
    }

    /// Tests connection `id` and records the outcome, the way `verdict::run_test` does but with the
    /// token renewed first. A renewal the service REFUSES (the refresh token is revoked or spent)
    /// is a conclusive verdict: the credential is dead, so the connection becomes "sign in again".
    /// A renewal that merely failed (network, 5xx, rate limit) is inconclusive.
    pub async fn test_connection(
        &self,
        cx: &Ctx<'_>,
        id: i64,
    ) -> Result<Connection, crate::store::secrets::Error> {
        let c = crate::store::connections::get(cx.pool, cx.who.workspace, id).await?;
        if c.kind != "jira" {
            return crate::store::connections::refused("bad_request", "not a Jira connection");
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

impl KindAdapter for Jira {
    fn descriptor(&self) -> &Descriptor {
        &DESCRIPTOR
    }

    /// `GET /me` (OAuth) or `/myself` (token); the identity is `<account id> at <site>`: the
    /// account id is stable, the display name is only a label (see [`Myself`]). Only a 401 on a token that is
    /// not past its expiry is a rejection (it disables the connection): an expired OAuth token,
    /// a 403, a rate limit, a 5xx or an unreadable envelope say nothing about the credential,
    /// so they are inconclusive. Call [`Jira::fresh`] first so the token is not expired.
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
            match self.myself(&cred).await {
                // A working token for an account that no longer reaches the site is a connection
                // to nothing: conclusive when the site list was read and lacks it (C1 has one
                // conclusive verdict, a rejection: the connection needs signing in again),
                // no verdict when the list could not be read.
                Ok(me) => match self.site_listed(&cred).await {
                    Some(true) => Ok(Identity {
                        subject: format!("{} at {}", me.account_id, me.site),
                    }),
                    Some(false) => Err(TestError::Rejected),
                    None => Err(TestError::Inconclusive),
                },
                Err(CallError::AuthFailed) if !expired => Err(TestError::Rejected),
                Err(_) => Err(TestError::Inconclusive),
            }
        }
        .boxed()
    }
}
