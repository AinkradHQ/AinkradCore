//! GitHub App installation tokens, kept fresh (C5; design §6). An `app_install` connection holds
//! an installation token that lasts an hour; its installation id is stored with the connection
//! (`store::connections::apps::installation_of`) and the App's id and key live in the
//! [`Installer`] (the API sets them from the sealed config). [`Github::renew_installation`] mints
//! a new token before the old one ends, single flight per connection, and seals it with
//! `secret::renew`, conditional on the version it started from, so a credential a person stored
//! meanwhile is never overwritten.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use serde_json::json;
use zeroize::Zeroizing;

use super::Github;
use super::app::{self, AppKey};
use super::http::{Host, Req};
use super::outcome::{Outcome, classify};
use crate::auth::Identity;
use crate::connections::jira::http::{CallError, Http};
use crate::connections::jira::service;
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::{iso_of_unix, unix_secs};
use crate::store::connections::{self, Who, apps, secret};
use crate::store::secrets::Error;

/// A token with less than this left is minted again.
pub const RENEW_SKEW_SECS: i64 = 300;

/// The GitHub App's signing key (an admin's own App, self-hosted), and the single-flight locks of
/// renewals. With no key, tokens are minted by Ainkrad's sign-in service, which holds the
/// built-in App's key so no Core does (S1): `signer` signs those calls.
pub struct Installer {
    key: RwLock<Option<Arc<AppKey>>>,
    signer: RwLock<Option<Arc<Identity>>>,
    service: Http,
    locks: Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
}

impl Default for Installer {
    fn default() -> Self {
        Self {
            key: RwLock::default(),
            signer: RwLock::default(),
            service: Http::production(),
            locks: Mutex::default(),
        }
    }
}

impl Installer {
    /// Gives the installer the Core's identity key, for the sign-in service.
    pub fn set_signer(&self, identity: Arc<Identity>) {
        *self.signer.write().unwrap_or_else(|e| e.into_inner()) = Some(identity);
    }

    fn signer(&self) -> Option<Arc<Identity>> {
        self.signer
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Whether an admin's own App key is set (else the service mints).
    pub fn has_own_key(&self) -> bool {
        self.key().is_some()
    }

    #[cfg(test)]
    pub(crate) fn set_service(&mut self, http: Http) {
        self.service = http;
    }

    /// Sets (or clears) the App key: a config change.
    pub fn set_key(&self, key: Option<AppKey>) {
        *self.key.write().unwrap_or_else(|e| e.into_inner()) = key.map(Arc::new);
    }

    /// Whether `app_install` can work: an own key, or the identity that signs for the service.
    pub fn configured(&self) -> bool {
        self.key().is_some() || self.signer().is_some()
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
    /// The sign-in service refused or could not be reached; fixed, user-readable text.
    Service(&'static str),
    /// The installation is not the signed-in user's.
    NotYours,
    /// The person has no GitHub sign-in to prove an installation with.
    NoUserToken,
}

impl InstallError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Mint(o) => o.code(),
            Self::Store(_) => "store",
            Self::Service(_) => "signin_service",
            Self::NotYours => "installation_not_yours",
            Self::NoUserToken => "no_github_sign_in",
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

    /// The GitHub account App installation `installation` is on, as the App API says (a signed
    /// App JWT; the installation must exist). The account names the installation in the claim
    /// the first workspace to use it records.
    pub async fn installation_account(&self, installation: i64) -> Result<String, InstallError> {
        let key = self.installer.key().ok_or(InstallError::NotConfigured)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let jwt = key
            .jwt(i64::try_from(now.as_secs()).unwrap_or(0))
            .ok_or(InstallError::Mint(Outcome::Unexpected))?;
        let req = Req::get(Host::Api, format!("/app/installations/{installation}"));
        let resp = self
            .transport
            .send(&req, Some(jwt.as_str()))
            .await
            .map_err(|e| InstallError::Mint(e.into()))?;
        classify(&resp).map_err(InstallError::Mint)?;
        let v: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|_| InstallError::Mint(Outcome::Unexpected))?;
        let login = v["account"]["login"]
            .as_str()
            .filter(|l| !l.is_empty())
            .ok_or(InstallError::Mint(Outcome::Unexpected))?;
        Ok(login.chars().take(100).collect())
    }

    /// Mints an installation token for `installation`.
    pub async fn mint(&self, installation: i64) -> Result<Material, InstallError> {
        let key = self.installer.key().ok_or(InstallError::NotConfigured)?;
        let id = u64::try_from(installation).map_err(|_| InstallError::Mint(Outcome::Invalid))?;
        app::mint(&self.transport, &key, id)
            .await
            .map_err(InstallError::Mint)
    }

    /// The GitHub user token of `workspace`'s first live GitHub sign-in (device flow): what proves
    /// to the service that an installation belongs to this person.
    async fn user_token(
        pool: &sqlx::sqlite::SqlitePool,
        sealer: &SecretBox,
        workspace: i64,
        now: &str,
    ) -> Result<Zeroizing<String>, InstallError> {
        for c in connections::list(pool, workspace, Some("github")).await? {
            if c.auth_method == "oauth" && c.status != "disabled" {
                let (m, _) = secret::open(pool, sealer, workspace, c.id).await?;
                // An expiring token cannot be renewed without a client secret: sign in again.
                let now = unix_secs(now).unwrap_or(0);
                if m.expires_at
                    .as_deref()
                    .and_then(unix_secs)
                    .is_some_and(|e| e <= now)
                {
                    continue;
                }
                return Ok(Zeroizing::new(m.access().to_owned()));
            }
        }
        Err(InstallError::NoUserToken)
    }

    /// Asks the sign-in service for an installation token (the Core holds no App key). Also the
    /// account name when the service sent it. `now` is the Core's clock (ISO).
    pub async fn mint_hosted(
        &self,
        pool: &sqlx::sqlite::SqlitePool,
        sealer: &SecretBox,
        workspace: i64,
        installation: i64,
        now: &str,
    ) -> Result<(Material, Option<String>), InstallError> {
        let user = Self::user_token(pool, sealer, workspace, now).await?;
        let body = json!({"installation_id": installation, "user_token": user.as_str()});
        let path = "/v1/github/installation-token";
        let signer = self.installer.signer();
        let res = service::post(&self.installer.service, signer.as_deref(), path, &body, now)
            .await
            .map_err(|e| match e {
                CallError::SignIn(why) => InstallError::Service(why),
                _ => InstallError::Service("Ainkrad's sign-in service could not be asked"),
            })?;
        if !(200..300).contains(&res.status) {
            let code = res.body["error"]["code"].as_str().unwrap_or("");
            return Err(match (res.status, code) {
                (403, "not_your_installation") | (404, "installation_not_found") => {
                    InstallError::NotYours
                }
                // The user token is dead (or expired): signing in to GitHub again is the cure.
                (401, "bad_user_token") => InstallError::NoUserToken,
                (502, "app_auth_failed") | (503, "not_configured") => InstallError::Service(
                    "Ainkrad's sign-in service has no working GitHub App right now. Try again later",
                ),
                _ => match service::fault(res.status, &res.body) {
                    CallError::SignIn(why) => InstallError::Service(why),
                    _ => InstallError::Service("Ainkrad's sign-in service refused the request"),
                },
            });
        }
        let bad = InstallError::Mint(Outcome::Unexpected);
        let token = res.body["token"].as_str().ok_or(bad)?;
        let expires_at = match res.body["expires_at"].as_str() {
            None => None,
            Some(at) => Some(iso_of_unix(
                unix_secs(at).ok_or(InstallError::Mint(Outcome::Unexpected))?,
            )),
        };
        let m = Material::new(token, None, expires_at.as_deref())
            .ok_or(InstallError::Mint(Outcome::Unexpected))?;
        let account = res.body["account"].as_str().filter(|a| !a.is_empty());
        Ok((m, account.map(|a| a.chars().take(100).collect())))
    }

    /// A fresh installation token: from the admin's own App key when there is one, else from the
    /// sign-in service.
    pub async fn mint_for(
        &self,
        pool: &sqlx::sqlite::SqlitePool,
        sealer: &SecretBox,
        workspace: i64,
        installation: i64,
        now: &str,
    ) -> Result<Material, InstallError> {
        if self.installer.has_own_key() {
            return self.mint(installation).await;
        }
        Ok(self
            .mint_hosted(pool, sealer, workspace, installation, now)
            .await?
            .0)
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
        let fresh = self
            .mint_for(pool, sealer, who.workspace, installation, who.now)
            .await?;
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
