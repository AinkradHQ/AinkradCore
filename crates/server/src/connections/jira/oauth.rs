//! Sign in with Atlassian (OAuth 2.0 3LO, authorization code with PKCE), Core's side. The Mac app
//! opens the authorize URL, catches the redirect on its loopback address and hands Core the
//! `code` and `state`; Core keeps the PKCE verifier (it never leaves Core unless the app chose to
//! make its own, see [`Jira::start`]), exchanges the code, discovers the sites, and later keeps
//! the access token fresh.
//!
//! **Rotation.** Atlassian's refresh tokens rotate: each refresh invalidates the one it used. So a
//! refresh is single-flight per connection (a lock, then a second look at the stored material:
//! whoever waited finds it already renewed and spends nothing), and the new refresh token is
//! sealed (`secret::replace`) before anyone else can need it. One grant must back ONE connection:
//! two connections that share a refresh token would invalidate each other.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Method;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqlitePool;
use zeroize::Zeroizing;

use ainkrad_core::audit::AuditActor;

use super::cred::{Cred, oauth_material, unpack};
use super::http::{CallError, Http, classify};
use super::{Ctx, Jira};
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::connections::{Who, secret};

/// Classic scopes; `offline_access` is what makes Atlassian issue a refresh token.
pub const SCOPES: &str = "read:jira-work write:jira-work read:me offline_access";
/// A started sign-in is good this long.
const FLOW_TTL: Duration = Duration::from_secs(600);
const MAX_FLOWS: usize = 64;
/// Waiting sign-ins one user may have.
const MAX_FLOWS_PER_USER: usize = 8;
/// A token is renewed when it has less than this left.
pub(super) const SKEW_SECS: i64 = 120;
const MAX_SITES: usize = 50;

/// Ainkrad's registered Atlassian app. Ahmed registers it; Core takes the values at start.
#[derive(Clone)]
pub struct OAuthApp {
    client_id: String,
    client_secret: Zeroizing<String>,
    /// The redirect URIs registered with Atlassian, exactly. A sign-in may use only these.
    redirects: Vec<String>,
}

impl OAuthApp {
    /// `None` when either is empty (the default: sign-in is then refused with a plain error) or
    /// there is no redirect, or one is not a fixed loopback address (`http://127.0.0.1:<port>/...`
    /// or `http://[::1]:<port>/...`, the Mac app's catcher). `redirects` are exactly what is
    /// registered with Atlassian; no `localhost`, no `https`, no pattern.
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
}

impl fmt::Debug for OAuthApp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OAuthApp(<redacted>)")
    }
}

/// Why a sign-in did not start or finish. Fixed text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// No client id and secret are configured: Ainkrad's Atlassian app is not registered here.
    NotConfigured,
    BadRedirect,
    BadChallenge,
    TooManyFlows,
    /// The state is wrong, expired, already used or another user's.
    UnknownState,
    BadCode,
    /// The verifier the app sent does not match the challenge it started with.
    BadVerifier,
    /// Atlassian issued no refresh token (the `offline_access` scope was not granted).
    NoRefreshToken,
    /// The token exchange or the site discovery failed.
    Exchange(CallError),
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotConfigured => {
                "Sign in with Atlassian is not set up on this Core: no Atlassian app id and secret \
                 are configured"
            }
            Self::BadRedirect => {
                "that redirect address is not one registered for Sign in with Atlassian"
            }
            Self::BadChallenge => "the PKCE challenge is not a SHA-256 challenge",
            Self::TooManyFlows => "too many sign-ins are waiting; try again in a few minutes",
            Self::UnknownState => "that sign-in is unknown, expired or already used; start again",
            Self::BadCode => "the authorization code is not valid text",
            Self::BadVerifier => "the PKCE verifier does not match",
            Self::NoRefreshToken => "Atlassian issued no refresh token; sign in again and allow it",
            Self::Exchange(_) => "Atlassian did not complete the sign-in",
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

/// A Jira site the account can reach (from `accessible-resources`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pub cloud_id: String,
    pub url: String,
    pub name: String,
}

/// A completed sign-in: tokens (never printed) and the sites to pick from.
pub struct Finished {
    access: Zeroizing<String>,
    refresh: Zeroizing<String>,
    expires_at: String,
    pub sites: Vec<Site>,
}

impl fmt::Debug for Finished {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Finished")
            .field("sites", &self.sites)
            .finish_non_exhaustive()
    }
}

impl Finished {
    /// The material of a connection to `site`, for `store::connections::create`. Use it for ONE
    /// connection: the refresh token must not back two (see the module docs).
    pub fn material_for(&self, site: &Site) -> Option<Material> {
        oauth_material(
            &site.cloud_id,
            &site.url,
            &self.access,
            Some(self.refresh.as_str()),
            Some(self.expires_at.as_str()),
        )
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
/// that is closer than the skew.
fn due(m: &Material, now: &str) -> bool {
    let exp = m.expires_at.as_deref().and_then(unix_secs);
    match (unpack(m), exp, unix_secs(now)) {
        (Some(Cred::Oauth { .. }), Some(exp), Some(now)) => exp - now < SKEW_SECS,
        _ => false,
    }
}

impl Jira {
    /// Starts a sign-in for `user`. `challenge` is the app's own PKCE challenge when it made the
    /// verifier itself (then [`Jira::finish`] needs the verifier); otherwise Core makes both and
    /// keeps the verifier.
    pub fn start(
        &self,
        user: i64,
        redirect_uri: &str,
        challenge: Option<&str>,
    ) -> Result<Started, FlowError> {
        let app = self.app.as_ref().ok_or(FlowError::NotConfigured)?;
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
            &format!("{}/authorize", self.http.auth),
            [
                ("audience", "api.atlassian.com"),
                ("client_id", app.client_id.as_str()),
                ("scope", SCOPES),
                ("redirect_uri", redirect_uri),
                ("state", state.as_str()),
                ("response_type", "code"),
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
    /// Core's, or `verifier` when the app made its own), reads the sites. The state is spent by
    /// the first call by its user, success or not. `now` is the clock for the expiry.
    pub async fn finish(
        &self,
        user: i64,
        state: &str,
        code: &str,
        verifier: Option<&str>,
        now: &str,
    ) -> Result<Finished, FlowError> {
        let app = self.app.as_ref().ok_or(FlowError::NotConfigured)?;
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
        let body = json!({"grant_type": "authorization_code", "client_id": app.client_id,
            "client_secret": app.client_secret.as_str(), "code": code,
            "redirect_uri": flow.redirect, "code_verifier": verifier.as_str()});
        let tokens = token_call(&self.http, &body, now)
            .await
            .map_err(FlowError::Exchange)?;
        let (access, Some(refresh), expires_at) = tokens else {
            return Err(FlowError::NoRefreshToken);
        };
        let sites = self.sites(&access).await.map_err(FlowError::Exchange)?;
        Ok(Finished {
            access,
            refresh,
            expires_at,
            sites,
        })
    }

    /// The Jira sites of the account (`accessible-resources`), at most [`MAX_SITES`].
    async fn sites(&self, access: &str) -> Result<Vec<Site>, CallError> {
        let url = format!("{}/oauth/token/accessible-resources", self.http.api);
        let mut auth = reqwest::header::HeaderValue::from_str(&format!("Bearer {access}"))
            .map_err(|_| CallError::Internal("the access token is unusable"))?;
        auth.set_sensitive(true);
        let v = self
            .http
            .send(None, Method::GET, &url, Some(auth), None)
            .await?
            .into_ok()?;
        let list = v.as_array().ok_or(CallError::Upstream(200))?;
        let sites = list.iter().filter_map(|s| {
            let jira = s["scopes"].as_array().is_none_or(|sc| {
                sc.iter()
                    .any(|x| x.as_str().is_some_and(|x| x.contains("jira")))
            });
            let (id, url) = (s["id"].as_str()?, s["url"].as_str()?);
            let name: String = s["name"]
                .as_str()
                .unwrap_or(url)
                .chars()
                .filter(|c| !c.is_control())
                .take(80)
                .collect();
            let valid = oauth_material(id, url, "x", None, None).is_some();
            (jira && valid).then(|| Site {
                cloud_id: id.to_owned(),
                url: url.to_owned(),
                name,
            })
        });
        Ok(sites.take(MAX_SITES).collect())
    }

    fn lock_of(&self, id: i64) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
        // A lock nobody holds or waits on (only the map has it) is dropped, so the map does not
        // grow with every connection ever renewed.
        locks.retain(|k, l| *k == id || Arc::strong_count(l) > 1);
        locks.entry(id).or_default().clone()
    }

    async fn open(cx: &Ctx<'_>, id: i64) -> Result<Material, CallError> {
        let gone = |_| CallError::Internal("the connection's credential did not open");
        secret::open(cx.pool, cx.sealer, cx.who.workspace, id)
            .await
            .map(|(m, _)| m)
            .map_err(gone)
    }

    /// The credential of connection `id`, its access token renewed first if it is within two
    /// minutes of expiry. [`Jira::test_connection`] does this before it tests.
    pub async fn fresh(&self, cx: &Ctx<'_>, id: i64) -> Result<Material, CallError> {
        self.renew(cx, id, None).await
    }

    /// Single-flight renewal. `rejected` is the packed access the service just refused (a 401):
    /// then the material is renewed unless it already differs (someone else renewed it), and not
    /// at all when it was renewed less than the skew ago (a fresh token that is refused is a real
    /// refusal, not a reason to spend another refresh token).
    ///
    /// The renewal (the exchange and the sealing of the rotated refresh token) runs in a task of
    /// its own, holding the lock: a caller that is dropped mid-way (a timeout, a cancelled
    /// request) cannot lose a refresh token the service has already rotated.
    pub(super) async fn renew(
        &self,
        cx: &Ctx<'_>,
        id: i64,
        rejected: Option<&str>,
    ) -> Result<Material, CallError> {
        let m = Self::open(cx, id).await?;
        if rejected.is_none() && !due(&m, cx.who.now) {
            return Ok(m);
        }
        let app = self.app.clone().ok_or(CallError::Internal(
            "Sign in with Atlassian is not set up on this Core",
        ))?;
        let lock = self.lock_of(id);
        let job = Job {
            http: self.http.clone(),
            app,
            pool: cx.pool.clone(),
            sealer: cx.sealer.clone(),
            workspace: cx.who.workspace,
            by_device: cx.who.by_device.to_owned(),
            actor: cx.who.actor,
            now: cx.who.now.to_owned(),
            id,
            rejected: rejected.map(|r| Zeroizing::new(r.to_owned())),
            recent: self.recent.clone(),
        };
        let task = tokio::spawn(async move {
            let _held = lock.lock_owned().await;
            job.run().await
        });
        task.await
            .map_err(|_| CallError::Internal("the renewal was interrupted"))?
    }
}

/// One renewal, with everything it needs owned so it can outlive its caller.
struct Job {
    http: Http,
    app: OAuthApp,
    pool: SqlitePool,
    sealer: Arc<SecretBox>,
    workspace: i64,
    by_device: String,
    actor: AuditActor,
    now: String,
    id: i64,
    rejected: Option<Zeroizing<String>>,
    recent: Arc<Mutex<HashMap<i64, Instant>>>,
}

impl Job {
    fn who(&self) -> Who<'_> {
        Who {
            workspace: self.workspace,
            by_device: &self.by_device,
            actor: self.actor,
            now: &self.now,
        }
    }

    async fn run(self) -> Result<Material, CallError> {
        let gone = |_| CallError::Internal("the connection's credential did not open");
        let (m, _) = secret::open(&self.pool, &self.sealer, self.workspace, self.id)
            .await
            .map_err(gone)?;
        let stale = match &self.rejected {
            Some(r) => m.access() == r.as_str(),
            None => due(&m, &self.now),
        };
        let Some(Cred::Oauth { cloud_id, site, .. }) = unpack(&m).filter(|_| stale) else {
            return Ok(m);
        };
        let renewed_lately = self
            .recent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&self.id)
            .is_some_and(|t| t.elapsed() < Duration::from_secs(SKEW_SECS as u64));
        if self.rejected.is_some() && renewed_lately {
            return Err(CallError::AuthFailed);
        }
        let Some(old) = m.refresh() else {
            return Err(CallError::AuthFailed);
        };
        let body = json!({"grant_type": "refresh_token", "client_id": self.app.client_id,
            "client_secret": self.app.client_secret.as_str(), "refresh_token": old});
        let (access, refresh, expires_at) = token_call(&self.http, &body, &self.now).await?;
        let refresh = refresh.as_ref().map_or(old, |r| r.as_str());
        let sealed = oauth_material(
            &cloud_id,
            &site,
            &access,
            Some(refresh),
            Some(expires_at.as_str()),
        )
        .ok_or(CallError::Internal("the service sent an unusable token"))?;
        // The old refresh token is spent: losing the new one now would strand the connection, so
        // a failed write is tried again, with a short wait.
        for wait_ms in [0u64, 100, 300] {
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
            if secret::renew(&self.pool, &self.sealer, self.id, &sealed, self.who())
                .await
                .is_ok()
            {
                self.recent
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(self.id, Instant::now());
                return Ok(sealed);
            }
        }
        Err(CallError::Internal(
            "the renewed credential could not be stored",
        ))
    }
}

/// POSTs the token endpoint: (access, refresh if issued, expiry). Every status but 2xx is an
/// error; a refusal of a refresh or a code (400, 401, 403) is [`CallError::AuthFailed`].
async fn token_call(
    http: &Http,
    body: &Value,
    now: &str,
) -> Result<(Zeroizing<String>, Option<Zeroizing<String>>, String), CallError> {
    let url = format!("{}/oauth/token", http.auth);
    let res = http
        .send(None, Method::POST, &url, None, Some(body))
        .await?;
    let status = res.status;
    if !(200..300).contains(&status) {
        return Err(match status {
            400 | 401 | 403 => CallError::AuthFailed,
            s => classify(s, res.retry_after),
        });
    }
    let v = res.body;
    let text = |k: &str| v[k].as_str().map(|s| Zeroizing::new(s.to_owned()));
    let access = text("access_token").ok_or(CallError::Upstream(status))?;
    let secs = v["expires_in"]
        .as_i64()
        .filter(|n| (60..=86_400).contains(n));
    let now = unix_secs(now).ok_or(CallError::Internal("the clock is unreadable"))?;
    Ok((
        access,
        text("refresh_token"),
        iso_of_unix(now + secs.unwrap_or(3600)),
    ))
}
