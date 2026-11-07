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

impl Jira {
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
pub(super) async fn token_call(
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
