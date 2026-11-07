//! GitHub App installation tokens, kept fresh (C5; design §6). An `app_install` connection holds
//! an installation token that lasts an hour; its installation id is stored with the connection
//! (`store::connections::apps::installation_of`) and the App's id and key live in the
//! [`Installer`] (the API sets them from the sealed config). [`Github::renew_installation`] mints
//! a new token before the old one ends, single flight per connection, and seals it with
//! `secret::renew`, conditional on the version it started from, so a credential a person stored
//! meanwhile is never overwritten.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use super::Github;
use super::app::{self, AppKey};
use super::outcome::Outcome;
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::unix_secs;
use crate::store::connections::{self, Who, apps, secret};
use crate::store::secrets::Error;

/// A token with less than this left is minted again.
pub const RENEW_SKEW_SECS: i64 = 300;

/// The GitHub App's signing key, and the single-flight locks of renewals.
#[derive(Default)]
pub struct Installer {
    key: RwLock<Option<Arc<AppKey>>>,
    locks: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
}

impl Installer {
    /// Sets (or clears) the App key: a config change.
    pub fn set_key(&self, key: Option<AppKey>) {
        *self.key.write().unwrap_or_else(|e| e.into_inner()) = key.map(Arc::new);
    }

    /// Whether the App's key is set.
    pub fn configured(&self) -> bool {
        self.key().is_some()
    }

    fn key(&self) -> Option<Arc<AppKey>> {
        self.key.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn lock_of(&self, id: i64) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(|e| e.into_inner());
        locks.retain(|k, l| *k == id || Arc::strong_count(l) > 1);
        locks.entry(id).or_default().clone()
    }
}

/// Why a mint or a renewal did not happen. Fixed codes.
#[derive(Debug)]
pub enum InstallError {
    /// No GitHub App id and key are configured on this Core.
    NotConfigured,
    Mint(Outcome),
    Store(Error),
}

impl InstallError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Mint(o) => o.code(),
            Self::Store(_) => "store",
        }
    }
}

impl From<Error> for InstallError {
    fn from(e: Error) -> Self {
        Self::Store(e)
    }
}

impl From<sqlx::Error> for InstallError {
    fn from(e: sqlx::Error) -> Self {
        Self::Store(e.into())
    }
}

impl Github {
    /// The App key holder (the API sets it).
    pub fn installer(&self) -> &Installer {
        &self.installer
    }

    /// Mints an installation token for `installation`.
    pub async fn mint(&self, installation: i64) -> Result<Material, InstallError> {
        let key = self.installer.key().ok_or(InstallError::NotConfigured)?;
        let id = u64::try_from(installation).map_err(|_| InstallError::Mint(Outcome::Invalid))?;
        app::mint(&self.transport, &key, id)
            .await
            .map_err(InstallError::Mint)
    }

    /// Mints a new token for connection `id` when it is an installation connection whose token is
    /// near its end; whether it did. Anything else is `Ok(false)` and no request.
    pub async fn renew_installation(
        &self,
        pool: &sqlx::sqlite::SqlitePool,
        sealer: &SecretBox,
        who: Who<'_>,
        id: i64,
    ) -> Result<bool, InstallError> {
        let c = connections::get(pool, who.workspace, id).await?;
        if c.kind != "github" || c.auth_method != "app_install" {
            return Ok(false);
        }
        let Some(installation) = apps::installation_of(pool, who.workspace, id).await? else {
            return Ok(false);
        };
        let lock = self.installer.lock_of(id);
        let _held = lock.lock().await;
        let (m, version) = secret::open(pool, sealer, who.workspace, id).await?;
        let now = unix_secs(who.now).unwrap_or(0);
        let due = m
            .expires_at
            .as_deref()
            .and_then(unix_secs)
            .is_none_or(|e| e <= now + RENEW_SKEW_SECS);
        if !due {
            return Ok(false);
        }
        let fresh = self.mint(installation).await?;
        match secret::renew(pool, sealer, id, &fresh, who, version).await {
            Ok(_) => Ok(true),
            // A person stored a newer credential meanwhile: it wins.
            Err(Error::Refused {
                code: "conflict", ..
            }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}
