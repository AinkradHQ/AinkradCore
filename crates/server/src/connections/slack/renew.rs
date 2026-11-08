//! Keeping a rotating bot token fresh: single-flight renewal of a single-use refresh token.
//! A token that does not rotate has no refresh token and is never renewed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use sqlx::sqlite::SqlitePool;
use zeroize::Zeroizing;

use super::cred::{Cred, oauth_material, unpack};
use super::http::{CallError, Http};
use super::oauth::{OAuthApp, SKEW_SECS, due, issued, token_call};
use super::{Ctx, Slack};
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::store::connections::{Who, secret, suspend};
use crate::store::secrets::Error;
use crate::store::settings::value_in;

/// What a renewal knows about a token's life, per connection: when it was renewed and how long the
/// service said it would last.
pub(super) type Recent = Arc<Mutex<HashMap<i64, (Instant, i64)>>>;

fn lifetime_of(recent: &Recent, id: i64) -> Option<i64> {
    let map = recent.lock().unwrap_or_else(|e| e.into_inner());
    map.get(&id).map(|(_, life)| *life)
}

impl Slack {
    fn lock_of(&self, id: i64) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
        // A lock nobody holds or waits on (only the map has it) is dropped, so the map does not
        // grow with every connection ever renewed.
        locks.retain(|k, l| *k == id || Arc::strong_count(l) > 1);
        locks.entry(id).or_default().clone()
    }

    /// The credential of connection `id`, its access token renewed first if it is nearly
    /// expired. [`Slack::test_connection`] does this before it tests.
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
    /// `rejected` is the access token the service just refused (a 401): then the material is
    /// renewed unless it already differs (someone else renewed it), and not at all when it was
    /// renewed less than the skew ago (a fresh token that is refused is a real refusal, not a
    /// reason to spend another refresh token).
    ///
    /// The renewal (the exchange and the sealing of the rotated refresh token) runs in a task of
    /// its own, holding the lock: a caller that is dropped mid-way cannot lose a refresh token the
    /// service has already rotated. Its write is conditional on the version it started from, so a
    /// credential a person stored meanwhile wins.
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
        let Some(app) = self.app() else {
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

    /// Whether a rotated token could be stored: below `secrets.mode` 2 the gate refuses the shape
    /// of every real Slack token a rotation hands out.
    async fn can_store_rotated(&self) -> Result<bool, sqlx::Error> {
        let mut conn = self.pool.acquire().await?;
        Ok(value_in(&mut conn, Key::SecretsMode, Scope::Server).await? >= 2)
    }

    /// Suspends the connection as `needs_mode_2` (from any state but disabled) and says so. A
    /// suspension that could not be written is an error of its own, logged without a secret.
    async fn suspend(&self, version: i64) -> (i64, Result<Material, CallError>) {
        match suspend::needs_mode_2(&self.pool, self.workspace, self.id, &self.now).await {
            Ok(_) => (version, Err(CallError::NeedsMode2)),
            Err(e) => {
                tracing::error!(
                    connection = self.id,
                    "could not suspend a Slack connection: {e:?}"
                );
                let why = CallError::Internal("the connection could not be suspended");
                (version, Err(why))
            }
        }
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
        // A token that does not rotate is never renewed: only a rotating install has a refresh token.
        if !stale || !matches!(unpack(&m), Some(Cred::Rotating(_))) {
            return (version, Ok(m));
        }
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
        // The refresh token is single use: spending it for a token that cannot be stored would
        // strand the connection. Below `secrets.mode` 2 nothing is asked of Slack.
        match self.can_store_rotated().await {
            Ok(true) => {}
            Ok(false) => return self.suspend(version).await,
            Err(_) => {
                let why = CallError::Internal("secrets.mode could not be read");
                return (version, Err(why));
            }
        }
        let pairs = [
            ("grant_type", "refresh_token"),
            ("client_id", self.app.client_id.as_str()),
            ("client_secret", self.app.client_secret.as_str()),
            ("refresh_token", old),
        ];
        let body = match token_call(&self.http, &pairs).await {
            Ok(b) => b,
            Err(e) => return (version, Err(e)),
        };
        let (access, refresh, expires_at, lifetime) = match issued(&body, &self.now) {
            Ok(t) => t,
            Err(e) => return (version, Err(e)),
        };
        // A rotating renewal always carries its expiry: without one the token cannot be kept alive.
        let (Some(expires_at), Some(lifetime)) = (expires_at, lifetime) else {
            let unusable = CallError::Internal("the service sent an unusable token");
            return (version, Err(unusable));
        };
        let refresh = refresh.as_ref().map_or(old, |r| r.as_str());
        let sealed = oauth_material(&access, Some(refresh), Some(expires_at.as_str()));
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
                // The mode was lowered after the check above: the gate refuses the rotated token's
                // shape, and Slack has already spent the old refresh token. Retrying cannot help, so
                // the connection is suspended with a plain reason (no health signal, no test loop).
                Err(Error::Refused {
                    code: "real_secret_refused",
                    ..
                }) => {
                    return self.suspend(version).await;
                }
                Err(_) => {}
            }
        }
        let unstored = CallError::Internal("the renewed credential could not be stored");
        (version, Err(unstored))
    }
}
