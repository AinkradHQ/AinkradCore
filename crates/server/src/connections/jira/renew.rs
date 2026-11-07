//! Keeping an OAuth access token fresh: single-flight renewal of a rotating refresh token.
//! See the module docs of `oauth` for the rotation rules.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ainkrad_core::audit::AuditActor;
use reqwest::Method;
use serde_json::{Value, json};
use sqlx::sqlite::SqlitePool;
use zeroize::Zeroizing;

use super::cred::{Cred, oauth_material, unpack};
use super::http::{CallError, Http, classify};
use super::oauth::{OAuthApp, SKEW_SECS, due};
use super::{Ctx, Jira};
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::connections::{Who, secret};
use crate::store::secrets::Error;

/// What a renewal knows about a token's life, per connection: when it was renewed and how long the
/// service said it would last.
pub(super) type Recent = Arc<Mutex<HashMap<i64, (Instant, i64)>>>;

fn lifetime_of(recent: &Recent, id: i64) -> Option<i64> {
    let map = recent.lock().unwrap_or_else(|e| e.into_inner());
    map.get(&id).map(|(_, life)| *life)
}

impl Jira {
    fn lock_of(&self, id: i64) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
        // A lock nobody holds or waits on (only the map has it) is dropped, so the map does not
        // grow with every connection ever renewed.
        locks.retain(|k, l| *k == id || Arc::strong_count(l) > 1);
        locks.entry(id).or_default().clone()
    }

    /// The credential of connection `id`, its access token renewed first if it is nearly
    /// expired. [`Jira::test_connection`] does this before it tests.
    pub async fn fresh(&self, cx: &Ctx<'_>, id: i64) -> Result<Material, CallError> {
        self.renew(cx, id, None).await
    }

    pub(super) async fn renew(
        &self,
        cx: &Ctx<'_>,
        id: i64,
        rejected: Option<&str>,
    ) -> Result<Material, CallError> {
        self.renew_versioned(cx, id, rejected).await.1
    }

    /// Single-flight renewal, and the credential VERSION it judged (0 when none could be read):
    /// a verdict on a credential must be recorded against that version, so one about an old
    /// credential cannot settle a newer one a person stored meanwhile.
    ///
    /// `rejected` is the packed access the service just refused (a 401): then the material is
    /// renewed unless it already differs (someone else renewed it), and not at all when it was
    /// renewed less than the skew ago (a fresh token that is refused is a real refusal, not a
    /// reason to spend another refresh token).
    ///
    /// The renewal (the exchange and the sealing of the rotated refresh token) runs in a task of
    /// its own, holding the lock: a caller that is dropped mid-way (a timeout, a cancelled
    /// request) cannot lose a refresh token the service has already rotated. Its write is
    /// conditional on the version it started from, so a credential a person stored meanwhile wins.
    pub(super) async fn renew_versioned(
        &self,
        cx: &Ctx<'_>,
        id: i64,
        rejected: Option<&str>,
    ) -> (i64, Result<Material, CallError>) {
        let opened = secret::open(cx.pool, cx.sealer, cx.who.workspace, id).await;
        let Ok((m, version)) = opened else {
            let gone = CallError::Internal("the connection's credential did not open");
            return (0, Err(gone));
        };
        let lifetime = lifetime_of(&self.recent, id);
        if rejected.is_none() && !due(&m, cx.who.now, lifetime) {
            return (version, Ok(m));
        }
        let Some(app) = self.app.clone() else {
            return (version, Err(CallError::OAuthNotConfigured));
        };
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
        match task.await {
            Ok(done) => done,
            Err(_) => (
                version,
                Err(CallError::Internal("the renewal was interrupted")),
            ),
        }
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
    recent: Recent,
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

    async fn open(&self) -> Result<(Material, i64), CallError> {
        let gone = |_| CallError::Internal("the connection's credential did not open");
        secret::open(&self.pool, &self.sealer, self.workspace, self.id)
            .await
            .map_err(gone)
    }

    async fn run(self) -> (i64, Result<Material, CallError>) {
        let (m, version) = match self.open().await {
            Ok(v) => v,
            Err(e) => return (0, Err(e)),
        };
        let lifetime = lifetime_of(&self.recent, self.id);
        let stale = match &self.rejected {
            Some(r) => m.access() == r.as_str(),
            None => due(&m, &self.now, lifetime),
        };
        let Some(Cred::Oauth { cloud_id, site, .. }) = unpack(&m).filter(|_| stale) else {
            return (version, Ok(m));
        };
        let renewed_lately = self
            .recent
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&self.id)
            .is_some_and(|(t, _)| t.elapsed() < Duration::from_secs(SKEW_SECS as u64));
        if self.rejected.is_some() && renewed_lately {
            return (version, Err(CallError::AuthFailed));
        }
        let Some(old) = m.refresh() else {
            return (version, Err(CallError::AuthFailed));
        };
        let body = json!({"grant_type": "refresh_token", "client_id": self.app.client_id,
            "client_secret": self.app.client_secret.as_str(), "refresh_token": old});
        let issued = match token_call(&self.http, &body, &self.now).await {
            Ok(t) => t,
            Err(e) => return (version, Err(e)),
        };
        let (access, refresh, expires_at, lifetime) = issued;
        let refresh = refresh.as_ref().map_or(old, |r| r.as_str());
        let sealed = oauth_material(
            &cloud_id,
            &site,
            &access,
            Some(refresh),
            Some(expires_at.as_str()),
        );
        let Some(sealed) = sealed else {
            let unusable = CallError::Internal("the service sent an unusable token");
            return (version, Err(unusable));
        };
        // The old refresh token is spent: losing the new one now would strand the connection, so
        // a failed write is tried again, with a short wait. A `conflict` is not retried: a person
        // stored a credential meanwhile, it is the newer one, and this result is dropped.
        for wait_ms in [0u64, 100, 300] {
            tokio::time::sleep(Duration::from_millis(wait_ms)).await;
            let wrote = secret::renew(
                &self.pool,
                &self.sealer,
                self.id,
                &sealed,
                self.who(),
                version,
            );
            match wrote.await {
                Ok(_) => {
                    let mut recent = self.recent.lock().unwrap_or_else(|e| e.into_inner());
                    recent.insert(self.id, (Instant::now(), lifetime));
                    return (version + 1, Ok(sealed));
                }
                Err(Error::Refused {
                    code: "conflict", ..
                }) => {
                    return match self.open().await {
                        Ok((current, v)) => (v, Ok(current)),
                        Err(e) => (0, Err(e)),
                    };
                }
                Err(_) => {}
            }
        }
        let unstored = CallError::Internal("the renewed credential could not be stored");
        (version, Err(unstored))
    }
}

/// What the token endpoint said: (access, refresh if issued, expiry, lifetime in seconds).
type Issued = (Zeroizing<String>, Option<Zeroizing<String>>, String, i64);

/// POSTs the token endpoint. Only a JSON body `error` of `invalid_grant` says THIS credential
/// (a refresh token or a code) is dead ([`CallError::AuthFailed`], whatever the status: Atlassian
/// answers 400 or 403). `invalid_client` and `unauthorized_client` are Core's own app registration
/// ([`CallError::AppConfig`]). Any other 401 or 403 (an edge, a proxy) is [`CallError::Forbidden`]
/// and any other status is classified as for an API call: none of them condemns a credential.
pub(super) async fn token_call(http: &Http, body: &Value, now: &str) -> Result<Issued, CallError> {
    let url = format!("{}/oauth/token", http.auth);
    let res = http
        .send(None, Method::POST, &url, None, Some(body))
        .await?;
    let status = res.status;
    if !(200..300).contains(&status) {
        let said = res.body.get("error").and_then(Value::as_str);
        return Err(match (status, said) {
            (400 | 401 | 403, Some("invalid_grant")) => CallError::AuthFailed,
            (_, Some("invalid_client" | "unauthorized_client")) => CallError::AppConfig,
            (401 | 403, _) => CallError::Forbidden,
            (s, _) => classify(s, res.retry_after),
        });
    }
    let v = res.body;
    let text = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(|s| Zeroizing::new(s.to_owned()))
    };
    let access = text("access_token").ok_or(CallError::Upstream(status))?;
    let secs = v
        .get("expires_in")
        .and_then(Value::as_i64)
        .map_or(3600, |n| n.clamp(60, 86_400));
    let now = unix_secs(now).ok_or(CallError::Internal("the clock is unreadable"))?;
    Ok((access, text("refresh_token"), iso_of_unix(now + secs), secs))
}
