//! Sign in with Linear (OAuth 2.0 authorization code with PKCE), Core's side. The Mac app opens the
//! authorize URL, catches the redirect on its loopback address and hands Core the `code` and
//! `state`; Core keeps the PKCE verifier (it never leaves Core unless the app chose to make its
//! own, see [`Linear::start`]), exchanges the code and later keeps the access token fresh.
//!
//! **Rotation.** Linear's refresh tokens rotate: each refresh returns a new refresh token. So a
//! refresh is single-flight per connection (a lock, then a second look at the stored material), and
//! the new refresh token is sealed before anyone else can need it. One grant must back ONE
//! connection. A sign-in is one workspace: there is no site to choose.
//!
//! **Scopes** are comma-separated: `read` (always included), `issues:create` (create and update
//! issues) and `comments:create`. `write` and `admin` are never asked for.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::Linear;
use super::cred::{Cred, oauth_material, unpack};
use super::http::CallError;
use super::renew::token_call;
use crate::connections::material::Material;
use crate::scheduler::unix_secs;

pub const SCOPES: &str = "read,issues:create,comments:create";
/// A started sign-in is good this long.
const FLOW_TTL: Duration = Duration::from_secs(600);
const MAX_FLOWS: usize = 64;
/// Waiting sign-ins one user may have.
const MAX_FLOWS_PER_USER: usize = 8;
/// A token is renewed when it has less than this left.
pub(super) const SKEW_SECS: i64 = 120;

/// Ainkrad's registered Linear app. Ahmed registers it; Core takes the values at start.
#[derive(Clone)]
pub struct OAuthApp {
    pub(super) client_id: String,
    pub(super) client_secret: Zeroizing<String>,
    /// The redirect URIs registered with Linear, exactly. A sign-in may use only these.
    redirects: Vec<String>,
}

impl OAuthApp {
    /// `None` when either is empty, there is no redirect, or one is not a fixed loopback address
    /// (`http://127.0.0.1:<port>/...` or `http://[::1]:<port>/...`, the Mac app's catcher).
    /// `redirects` are exactly what is registered with Linear; no `localhost`, no `https`, no
    /// pattern.
    pub fn new(client_id: &str, client_secret: &str, redirects: &[&str]) -> Option<Self> {
        if redirects.is_empty() || redirects.len() > 8 || !redirects.iter().all(|r| redirect_ok(r))
        {
            return None;
        }
        let (id, secret) = (client_id.trim(), client_secret.trim());
        let ok = |s: &str| (1..=512).contains(&s.len()) && !s.chars().any(char::is_control);
        (ok(id) && ok(secret)).then(|| Self {
            client_id: id.to_owned(),
            client_secret: Zeroizing::new(secret.to_owned()),
            redirects: redirects.iter().map(|r| (*r).to_owned()).collect(),
        })
    }

    /// Whether `other` is the same registration (client id, secret and redirects).
    pub(super) fn same(&self, other: &Self) -> bool {
        self.client_id == other.client_id
            && self.client_secret.as_str() == other.client_secret.as_str()
            && self.redirects == other.redirects
    }

    /// The redirect addresses registered with Linear, exactly.
    pub fn redirects(&self) -> &[String] {
        &self.redirects
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
    /// No client id and secret are configured: Ainkrad's Linear app is not registered here.
    NotConfigured,
    BadRedirect,
    BadChallenge,
    TooManyFlows,
    /// The state is wrong, expired, already used or another user's.
    UnknownState,
    BadCode,
    /// The verifier the app sent does not match the challenge it started with.
    BadVerifier,
    /// Linear issued no refresh token.
    NoRefreshToken,
    /// The token exchange or the read of who signed in failed.
    Exchange(CallError),
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotConfigured => {
                "Sign in with Linear is not set up on this Core: no Linear app id and secret \
                 are configured"
            }
            Self::BadRedirect => {
                "that redirect address is not one registered for Sign in with Linear"
            }
            Self::BadChallenge => "the PKCE challenge is not a SHA-256 challenge",
            Self::TooManyFlows => "too many sign-ins are waiting; try again in a few minutes",
            Self::UnknownState => "that sign-in is unknown, expired or already used; start again",
            Self::BadCode => "the authorization code is not valid text",
            Self::BadVerifier => "the PKCE verifier does not match",
            Self::NoRefreshToken => "Linear issued no refresh token; sign in again",
            Self::Exchange(_) => "Linear did not complete the sign-in",
        })
    }
}

impl std::error::Error for FlowError {}

/// Where a started sign-in stands, in memory only (a restart ends it; the user starts again).
pub(super) struct Pending {
    user: i64,
    redirect: String,
    /// Core's own verifier; `None` when the app made its own and sent the challenge.
    verifier: Option<Zeroizing<String>>,
    challenge: String,
    pub(super) expires: Instant,
}

pub(super) type Flows = HashMap<String, Pending>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Started {
    /// What the app opens in the browser.
    pub authorize_url: String,
    /// Returned unchanged by the redirect; the key of this sign-in.
    pub state: String,
    pub expires_in_secs: u64,
}

/// A completed sign-in: tokens (never printed) and who signed in.
pub struct Finished {
    access: Zeroizing<String>,
    refresh: Zeroizing<String>,
    expires_at: String,
    /// The workspace's url key, as the identity line names it (`<user id> at <url key>`).
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
    /// connection: the refresh token must not back two (see the module docs).
    pub fn material(&self) -> Option<Material> {
        oauth_material(&self.access, &self.refresh, Some(self.expires_at.as_str()))
    }
}

fn random_b64(n: usize) -> Option<String> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).ok()?;
    Some(URL_SAFE_NO_PAD.encode(b))
}

pub(super) fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A fixed loopback address: `http` on `127.0.0.1` or `[::1]` with a port, no userinfo, query
/// or fragment.
fn redirect_ok(uri: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(uri) else {
        return false;
    };
    let plain = u.username().is_empty()
        && u.password().is_none()
        && u.fragment().is_none()
        && u.query().is_none();
    let loopback = matches!(u.host_str(), Some("127.0.0.1" | "[::1]"));
    uri.len() <= 300 && plain && u.scheme() == "http" && loopback && u.port().is_some()
}

/// Whether the access token is due for renewal at `now`: an OAuth credential with a known expiry
/// that is closer than the skew (relative for a short-lived token: with `lifetime` known, due when
/// less than a quarter of its life is left, at most the skew).
pub(super) fn due(m: &Material, now: &str, lifetime: Option<i64>) -> bool {
    let threshold = lifetime.map_or(SKEW_SECS, |l| SKEW_SECS.min(l / 4));
    let exp = m.expires_at.as_deref().and_then(unix_secs);
    match (unpack(m), exp, unix_secs(now)) {
        (Some(Cred::Oauth(_)), Some(exp), Some(now)) => exp - now < threshold,
        _ => false,
    }
}

impl Linear {
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

    /// Starts a sign-in for `user`. `challenge` is the app's own PKCE challenge when it made the
    /// verifier itself (then [`Linear::finish`] needs the verifier); otherwise Core makes both and
    /// keeps the verifier.
    pub fn start(
        &self,
        user: i64,
        redirect_uri: &str,
        challenge: Option<&str>,
    ) -> Result<Started, FlowError> {
        // Held to the end: `set_app` cannot swap the app between the check and the flow's insert.
        let guard = self.app.read().unwrap_or_else(|e| e.into_inner());
        let app = guard.as_ref().ok_or(FlowError::NotConfigured)?;
        if !app.redirects.iter().any(|r| r == redirect_uri) {
            return Err(FlowError::BadRedirect);
        }
        if challenge.is_some_and(|c| c.len() != 43 || URL_SAFE_NO_PAD.decode(c).is_err()) {
            return Err(FlowError::BadChallenge);
        }
        let (Some(state), Some(own)) = (random_b64(32), random_b64(48)) else {
            return Err(FlowError::TooManyFlows);
        };
        let own = Zeroizing::new(own);
        let mine = challenge.is_none();
        let challenge = challenge.map_or_else(|| s256(&own), str::to_owned);
        let url = reqwest::Url::parse_with_params(
            &format!("{}/oauth/authorize", self.http.auth),
            [
                ("client_id", app.client_id.as_str()),
                ("redirect_uri", redirect_uri),
                ("response_type", "code"),
                ("scope", SCOPES),
                ("state", state.as_str()),
                ("prompt", "consent"),
                ("code_challenge", challenge.as_str()),
                ("code_challenge_method", "S256"),
            ],
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
                redirect: redirect_uri.to_owned(),
                verifier: mine.then_some(own),
                challenge,
                expires: now + FLOW_TTL,
            },
        );
        Ok(Started {
            authorize_url: url.into(),
            state,
            expires_in_secs: FLOW_TTL.as_secs(),
        })
    }

    /// Completes the sign-in the redirect's `state` names: exchanges `code` (with the verifier:
    /// Core's, or `verifier` when the app made its own) and reads who signed in. The state is
    /// spent by the first call by its user, success or not. `now` is the clock for the expiry.
    pub async fn finish(
        &self,
        user: i64,
        state: &str,
        code: &str,
        verifier: Option<&str>,
        now: &str,
    ) -> Result<Finished, FlowError> {
        let app = self.app().ok_or(FlowError::NotConfigured)?;
        let flow = {
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
        let verifier = match (&flow.verifier, verifier) {
            (Some(own), _) => own.clone(),
            (None, Some(v)) if s256(v) == flow.challenge => Zeroizing::new(v.to_owned()),
            (None, _) => return Err(FlowError::BadVerifier),
        };
        let pairs = [
            ("grant_type", "authorization_code"),
            ("client_id", app.client_id.as_str()),
            ("client_secret", app.client_secret.as_str()),
            ("code", code),
            ("redirect_uri", flow.redirect.as_str()),
            ("code_verifier", verifier.as_str()),
        ];
        let tokens = token_call(&self.http, &pairs, now)
            .await
            .map_err(FlowError::Exchange)?;
        let (access, Some(refresh), expires_at, _) = tokens else {
            return Err(FlowError::NoRefreshToken);
        };
        // Who signed in: the workspace the connection will be tied to (a re-sign-in must be the
        // same one, or the team limits would be re-aimed at another workspace's teams).
        let cred = oauth_material(&access, &refresh, None)
            .and_then(|m| unpack(&m))
            .ok_or(FlowError::Exchange(CallError::Internal(
                "the service sent an unusable token",
            )))?;
        let me = self.viewer(&cred).await.map_err(FlowError::Exchange)?;
        Ok(Finished {
            access,
            refresh,
            expires_at,
            workspace: me.workspace,
        })
    }
}
