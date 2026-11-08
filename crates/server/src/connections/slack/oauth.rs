//! Sign in with Slack (OAuth v2, "Add to Slack"), Core's side.
//!
//! **Slack requires `https` redirect URLs** (the authorize `redirect_uri` and the ones registered
//! in the app), so the Mac app's `http://127.0.0.1` catcher cannot be used. Core takes ONE
//! configured `https` redirect (an address of Ainkrad's or of this Core: whatever catches
//! `code` and `state` there hands them to the flow's callback, like the loopback catcher does for
//! Atlassian). Slack documents no PKCE for `oauth.v2.access`, so none is sent: the `state` (one
//! use, bound to the user and the flow) is the protection, and the code is useless without the
//! client secret Core holds.
//!
//! **Bot installs only.** Only `scope` (bot scopes) is asked for, never `user_scope`; the answer
//! must be a bot token of one workspace (`team.id`), not an enterprise-wide install. The tokens
//! of whoever approved (`authed_user`) are never read. What Core stores is checked once more with
//! `auth.test`: the workspace must be the one the exchange named.
//!
//! **Rotation is optional.** Without it the token is long lived and has no refresh token; with it
//! (`xoxe.xoxb-`, 12 hours) the refresh token is single use and rotates (see `renew`).

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use serde_json::Value;
use zeroize::Zeroizing;

use super::Slack;
use super::cred::{Cred, oauth_material, team_id, unpack, user_id};
use super::http::{CallError, Http, Method, classify};
use crate::connections::material::Material;
use crate::scheduler::{iso_of_unix, unix_secs};

/// Bot scopes: public and private channels (read, history), posting, reactions, user names. Never
/// `im:*`, `mpim:*`, `chat:write.public`, `chat:write.customize`, `users:read.email`, `files:*`,
/// `channels:manage` or `admin`.
pub const SCOPES: &str = "channels:read,groups:read,channels:history,groups:history,chat:write,\
                          reactions:write,users:read";
/// A started sign-in is good this long.
const FLOW_TTL: Duration = Duration::from_secs(600);
const MAX_FLOWS: usize = 64;
/// Waiting sign-ins one user may have.
const MAX_FLOWS_PER_USER: usize = 8;
/// A token is renewed when it has less than this left.
pub(super) const SKEW_SECS: i64 = 120;

/// Ainkrad's registered Slack app. Ahmed registers it; Core takes the values at start.
#[derive(Clone)]
pub struct OAuthApp {
    pub(super) client_id: String,
    pub(super) client_secret: Zeroizing<String>,
    /// The `https` redirect URL registered with Slack, exactly. A sign-in may use only this one.
    /// `None`: the app only renews tokens already issued (no sign-in: the https page that catches
    /// the redirect is not ready, or no redirect is set).
    redirect: Option<String>,
    /// The Slack app has token rotation on: tokens expire in 12 hours with a single-use refresh
    /// token, which Core can only store at `secrets.mode` 2.
    rotation: bool,
}

impl OAuthApp {
    /// `None` when the id or the secret is empty or has a control character, or the redirect is
    /// not a fixed `https` address of a host NAME (no IP, no userinfo, no query, no fragment, no
    /// port but 443).
    pub fn new(client_id: &str, client_secret: &str, redirect: &str) -> Option<Self> {
        if !redirect_ok(redirect) {
            return None;
        }
        let (id, secret) = (client_id.trim(), client_secret.trim());
        let ok = |s: &str| (1..=512).contains(&s.len()) && !s.chars().any(char::is_control);
        (ok(id) && ok(secret)).then(|| Self {
            client_id: id.to_owned(),
            client_secret: Zeroizing::new(secret.to_owned()),
            redirect: Some(redirect.to_owned()),
            rotation: false,
        })
    }

    /// The app without a sign-in: the client id and secret, which is all RENEWING a token needs.
    /// Turning sign-in off (no catcher page yet, a cleared redirect) must not turn the renewal of
    /// the connections already made off with it.
    pub fn renewal_only(client_id: &str, client_secret: &str) -> Option<Self> {
        let (id, secret) = (client_id.trim(), client_secret.trim());
        let ok = |s: &str| (1..=512).contains(&s.len()) && !s.chars().any(char::is_control);
        (ok(id) && ok(secret)).then(|| Self {
            client_id: id.to_owned(),
            client_secret: Zeroizing::new(secret.to_owned()),
            redirect: None,
            rotation: false,
        })
    }

    /// This app, with token rotation said to be on (or off).
    #[must_use]
    pub fn rotating(mut self, on: bool) -> Self {
        self.rotation = on;
        self
    }

    pub fn rotation(&self) -> bool {
        self.rotation
    }

    /// Whether `other` is the same registration (client id, secret and redirect).
    pub(super) fn same(&self, other: &Self) -> bool {
        self.client_id == other.client_id
            && self.client_secret.as_str() == other.client_secret.as_str()
            && self.redirect == other.redirect
            && self.rotation == other.rotation
    }

    /// The registered redirect; `None` when this app does not sign anyone in.
    pub fn redirect(&self) -> Option<&str> {
        self.redirect.as_deref()
    }

    /// Whether Add to Slack can start and finish with this app.
    pub fn signs_in(&self) -> bool {
        self.redirect.is_some()
    }
}

impl fmt::Debug for OAuthApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OAuthApp(<redacted>)")
    }
}

/// Why a sign-in did not start or finish. Fixed text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// No client id, secret and redirect are configured: Ainkrad's Slack app is not set up here.
    NotConfigured,
    BadRedirect,
    TooManyFlows,
    /// The state is wrong, expired, already used or another user's.
    UnknownState,
    BadCode,
    /// Slack's answer is not a bot install of one workspace (a user token, an enterprise-wide
    /// install, a missing workspace, or another workspace than `auth.test` names).
    NotABotInstall,
    /// The Slack app has token rotation on and `secrets.mode` is below 2, where its rotating
    /// tokens cannot be stored: nothing is started, so no sign-in code is spent.
    NeedsMode2,
    /// The token exchange or the read of who was installed failed.
    Exchange(CallError),
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotConfigured => {
                "Sign in with Slack is not set up on this Core: no Slack app id, secret and \
                 redirect address are configured"
            }
            Self::BadRedirect => "that redirect address is not the one registered for Slack",
            Self::TooManyFlows => "too many sign-ins are waiting; try again in a few minutes",
            Self::UnknownState => "that sign-in is unknown, expired or already used; start again",
            Self::BadCode => "the authorization code is not valid text",
            Self::NotABotInstall => {
                "Slack did not install a bot into one workspace; Core only connects a bot of a \
                 single workspace"
            }
            Self::NeedsMode2 => {
                "this Slack app rotates its tokens, which needs secrets.mode 2 to store: raise it, \
                 or turn token rotation off in the Slack app"
            }
            Self::Exchange(_) => "Slack did not complete the sign-in",
        })
    }
}

impl std::error::Error for FlowError {}

/// Where a started sign-in stands, in memory only (a restart ends it; the user starts again).
pub(super) struct Pending {
    user: i64,
    pub(super) expires: Instant,
}

pub(super) type Flows = HashMap<String, Pending>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    /// What the person opens in the browser.
    pub authorize_url: String,
    /// Returned unchanged by the redirect; the key of this sign-in.
    pub state: String,
    pub expires_in_secs: u64,
}

/// A completed sign-in: tokens (never printed) and which workspace they belong to.
pub struct Finished {
    access: Zeroizing<String>,
    refresh: Option<Zeroizing<String>>,
    expires_at: Option<String>,
    /// The workspace's stable id (`T…`), as the identity line names it.
    pub workspace: String,
}

impl fmt::Debug for Finished {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Finished")
            .field("workspace", &self.workspace)
            .finish_non_exhaustive()
    }
}

impl Finished {
    /// The material of the connection, for `store::connections::create`. Use it for ONE
    /// connection: a refresh token must not back two.
    pub fn material(&self) -> Option<Material> {
        let refresh = self.refresh.as_ref().map(|r| r.as_str());
        oauth_material(&self.access, refresh, self.expires_at.as_deref())
    }
}

fn random_b64(n: usize) -> Option<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).ok()?;
    Some(URL_SAFE_NO_PAD.encode(b))
}

/// A fixed `https` address of a host NAME: no userinfo, query or fragment, port 443 or none.
pub fn redirect_ok(uri: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(uri) else {
        return false;
    };
    uri.len() <= 300
        && u.scheme() == "https"
        && u.domain().is_some()
        && u.username().is_empty()
        && u.password().is_none()
        && u.fragment().is_none()
        && u.query().is_none()
        && u.port().is_none()
        && !uri.contains('#')
}

/// Whether the access token is due for renewal at `now`: a rotating credential with a known
/// expiry closer than the skew (relative for a short-lived token: when `lifetime` is known, due
/// when less than a quarter of its life is left, at most the skew).
pub(super) fn due(m: &Material, now: &str, lifetime: Option<i64>) -> bool {
    let threshold = lifetime.map_or(SKEW_SECS, |l| SKEW_SECS.min(l / 4));
    let exp = m.expires_at.as_deref().and_then(unix_secs);
    match (unpack(m), exp, unix_secs(now)) {
        (Some(Cred::Rotating(_)), Some(exp), Some(now)) => exp - now < threshold,
        _ => false,
    }
}

/// What `oauth.v2.access` said, as the tokens in it: (access, refresh if issued, expiry, lifetime).
pub(super) type Issued = (
    Zeroizing<String>,
    Option<Zeroizing<String>>,
    Option<String>,
    Option<i64>,
);

/// POSTs `oauth.v2.access` (a form). It answers 200 with `ok:false`; only `invalid_refresh_token`
/// says THIS refresh token is dead ([`CallError::AuthFailed`]). A refusal of Core's own app
/// (`invalid_client_id`, `bad_client_secret`, ...) is [`CallError::AppConfig`]. Any other 401 or
/// 403 (an edge, a proxy) is [`CallError::Forbidden`] and any other status is classified as for
/// an API call: none of them condemns a credential. Returns the whole `ok:true` body.
pub(super) async fn token_call(http: &Http, pairs: &[(&str, &str)]) -> Result<Value, CallError> {
    let res = http.call(None, Method::OauthV2Access, pairs).await?;
    let (status, retry_after) = (res.status, res.retry_after);
    let said = res.body.get("error").and_then(Value::as_str);
    if res.body.get("ok").and_then(Value::as_bool) == Some(false) {
        return Err(match said {
            Some("invalid_refresh_token") => CallError::AuthFailed,
            Some(
                "invalid_client_id"
                | "bad_client_secret"
                | "invalid_client"
                | "unauthorized_client"
                | "invalid_grant_type",
            ) => CallError::AppConfig,
            Some("ratelimited") => CallError::RateLimited { retry_after },
            _ if (200..300).contains(&status) => CallError::BadRequest(status),
            _ => classify_token(status, retry_after),
        });
    }
    if !(200..300).contains(&status) {
        return Err(classify_token(status, retry_after));
    }
    match res.body.get("ok").and_then(Value::as_bool) {
        Some(true) => Ok(res.body),
        _ => Err(CallError::Upstream(status)),
    }
}

fn classify_token(status: u16, retry_after: Option<u64>) -> CallError {
    match status {
        401 | 403 => CallError::Forbidden,
        s => classify(s, retry_after),
    }
}

/// The tokens of an `ok:true` answer. `now` is the clock for the expiry. A refresh token with no
/// expiry (or the other way round) is not a rotating install this adapter can keep alive.
pub(super) fn issued(body: &Value, now: &str) -> Result<Issued, CallError> {
    let text = |k: &str| {
        body.get(k)
            .and_then(Value::as_str)
            .map(|s| Zeroizing::new(s.to_owned()))
    };
    let access = text("access_token").ok_or(CallError::Upstream(200))?;
    let refresh = text("refresh_token");
    let secs = body.get("expires_in").and_then(Value::as_i64);
    let expiry = match secs {
        Some(s) => {
            let s = s.clamp(60, 2_592_000);
            let now = unix_secs(now).ok_or(CallError::Internal("the clock is unreadable"))?;
            Some((iso_of_unix(now + s), s))
        }
        None => None,
    };
    let (expires_at, lifetime) = expiry.unzip();
    Ok((access, refresh, expires_at, lifetime))
}

impl Slack {
    /// Drops the pending sign-in `state` of `user` (a cancelled or ended flow); nothing when it
    /// is spent, expired or another user's.
    pub fn cancel(&self, user: i64, state: &str) {
        let mut flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        if flows.get(state).is_some_and(|p| p.user == user) {
            flows.remove(state);
        }
    }

    /// How many sign-ins are waiting.
    #[cfg(test)]
    pub(crate) fn pending(&self) -> usize {
        self.flows.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Starts a sign-in for `user`. `redirect_uri` must be the registered one exactly. `team` is
    /// a hint (the workspace a re-sign-in must land in; Slack may ignore it, so the finish checks
    /// again); anything that is not a workspace id is not sent.
    pub fn start(
        &self,
        user: i64,
        redirect_uri: &str,
        team: Option<&str>,
    ) -> Result<Started, FlowError> {
        // Held to the end: `set_app` cannot swap the app between the check and the flow's insert.
        let guard = self.app.read().unwrap_or_else(|e| e.into_inner());
        let app = guard.as_ref().ok_or(FlowError::NotConfigured)?;
        match app.redirect.as_deref() {
            None => return Err(FlowError::NotConfigured),
            Some(r) if r != redirect_uri => return Err(FlowError::BadRedirect),
            Some(_) => {}
        }
        let Some(state) = random_b64(32) else {
            return Err(FlowError::TooManyFlows);
        };
        let mut params = vec![
            ("client_id", app.client_id.as_str()),
            ("scope", SCOPES),
            ("redirect_uri", redirect_uri),
            ("state", state.as_str()),
        ];
        if let Some(t) = team.filter(|t| team_id(t)) {
            params.push(("team", t));
        }
        let url = reqwest::Url::parse_with_params(
            &format!("{}/oauth/v2/authorize", self.http.api),
            params,
        )
        .map_err(|_| FlowError::BadRedirect)?;
        let mut flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        flows.retain(|_, p| p.expires > now);
        if flows.len() >= MAX_FLOWS
            || flows.values().filter(|p| p.user == user).count() >= MAX_FLOWS_PER_USER
        {
            return Err(FlowError::TooManyFlows);
        }
        flows.insert(
            state.clone(),
            Pending {
                user,
                expires: now + FLOW_TTL,
            },
        );
        Ok(Started {
            authorize_url: url.into(),
            state,
            expires_in_secs: FLOW_TTL.as_secs(),
        })
    }

    /// Completes the sign-in the redirect's `state` names: exchanges `code`, checks that a bot of
    /// one workspace was installed and reads who it is. The state is spent by the first call by
    /// its user, success or not. `now` is the clock for the expiry.
    pub async fn finish(
        &self,
        user: i64,
        state: &str,
        code: &str,
        now: &str,
    ) -> Result<Finished, FlowError> {
        let app = self.app().ok_or(FlowError::NotConfigured)?;
        let redirect = app.redirect.clone().ok_or(FlowError::NotConfigured)?;
        let _flow = {
            let mut flows = self.flows.lock().unwrap_or_else(|e| e.into_inner());
            match flows.get(state) {
                Some(p) if p.user == user => flows.remove(state),
                _ => None,
            }
        }
        .filter(|p| p.expires > Instant::now())
        .ok_or(FlowError::UnknownState)?;
        if code.is_empty() || code.len() > 2048 || code.chars().any(char::is_control) {
            return Err(FlowError::BadCode);
        }
        let pairs = [
            ("client_id", app.client_id.as_str()),
            ("client_secret", app.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", redirect.as_str()),
        ];
        let body = token_call(&self.http, &pairs)
            .await
            .map_err(FlowError::Exchange)?;
        let team = bot_install(&body).ok_or(FlowError::NotABotInstall)?;
        let (access, refresh, expires_at, _) = issued(&body, now).map_err(FlowError::Exchange)?;
        let material = oauth_material(
            &access,
            refresh.as_ref().map(|r| r.as_str()),
            expires_at.as_deref(),
        )
        .ok_or(FlowError::NotABotInstall)?;
        let cred = unpack(&material).ok_or(FlowError::NotABotInstall)?;
        // Who the token is: the workspace must be the one the exchange named.
        let me = self.viewer(&cred).await.map_err(FlowError::Exchange)?;
        if me.team_id != team {
            return Err(FlowError::NotABotInstall);
        }
        Ok(Finished {
            access,
            refresh,
            expires_at,
            workspace: me.team_id,
        })
    }
}

/// The workspace id of a bot install answer; `None` for a user token, an enterprise-wide install
/// or an answer that names no workspace.
fn bot_install(body: &Value) -> Option<String> {
    if body.get("is_enterprise_install").and_then(Value::as_bool) == Some(true) {
        return None;
    }
    if body.get("token_type").and_then(Value::as_str) != Some("bot") {
        return None;
    }
    body.get("bot_user_id")
        .and_then(Value::as_str)
        .filter(|u| user_id(u))?;
    body.get("team")?
        .get("id")?
        .as_str()
        .filter(|t| team_id(t))
        .map(str::to_owned)
}
