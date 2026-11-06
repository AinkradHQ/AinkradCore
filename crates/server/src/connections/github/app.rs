//! GitHub App sign-in, Core side (C2; design §6: "a GitHub App install to choose which repos
//! Core may reach"). The person installs the Ainkrad GitHub App on their account, picks the
//! repositories there, and GitHub gives the install an id. Core then mints a short-lived
//! **installation token** from the App's private key: a signed JWT (RS256, 9 minutes) exchanged at
//! `POST /app/installations/{id}/access_tokens`. The token lasts an hour and reaches only the
//! repositories the person picked.
//!
//! The App's id and private key are the Ainkrad App's, held by Core as [`AppKey`] (a secret: no
//! `Debug` text). Not here: learning the installation id (C5 takes it from the
//! App's setup redirect, `?installation_id=`) and calling this again when the token's
//! `expires_at` is near (C4).

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::http::{Host, Method, Req, Transport};
use super::outcome::{Outcome, classify};
use crate::connections::material::Material;

/// The App's id and signing key.
pub struct AppKey {
    app_id: String,
    key: RsaKeyPair,
}

impl fmt::Debug for AppKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppKey(<redacted>)")
    }
}

impl AppKey {
    /// `app_id` is the App's numeric id (or client id); `pem` the private key GitHub gave
    /// (`RSA PRIVATE KEY`, PKCS#1, or `PRIVATE KEY`, PKCS#8). `None` when either is not usable.
    pub fn new(app_id: &str, pem: &str) -> Option<Self> {
        let app_id = app_id.trim();
        let id_ok = (1..=40).contains(&app_id.len())
            && app_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        let pkcs1 = pem.contains("BEGIN RSA PRIVATE KEY");
        let b64: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .flat_map(|l| l.trim().chars())
            .collect();
        let der = Zeroizing::new(STANDARD.decode(b64).ok()?);
        let key = if pkcs1 {
            RsaKeyPair::from_der(&der)
        } else {
            RsaKeyPair::from_pkcs8(&der)
        }
        .ok()?;
        id_ok.then(|| Self {
            app_id: app_id.to_owned(),
            key,
        })
    }

    #[cfg(test)]
    pub(super) fn public_der(&self) -> &[u8] {
        self.key.public().as_ref()
    }

    /// The App JWT for `now` (unix seconds): issued a minute ago, good for nine.
    pub fn jwt(&self, now: i64) -> Option<Zeroizing<String>> {
        let head = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = format!(
            r#"{{"iat":{},"exp":{},"iss":"{}"}}"#,
            now - 60,
            now + 540,
            self.app_id
        );
        let signing = Zeroizing::new(format!("{head}.{}", URL_SAFE_NO_PAD.encode(claims)));
        let mut sig = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing.as_bytes(),
                &mut sig,
            )
            .ok()?;
        Some(Zeroizing::new(format!(
            "{}.{}",
            signing.as_str(),
            URL_SAFE_NO_PAD.encode(sig)
        )))
    }
}

#[derive(Deserialize)]
struct Minted {
    token: String,
    expires_at: Option<String>,
}

/// Exchanges the App's JWT for an installation token. The token is returned as [`Material`]
/// (no refresh token: mint another); its expiry is GitHub's `expires_at`.
pub async fn mint(t: &Transport, app: &AppKey, installation_id: u64) -> Result<Material, Outcome> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let jwt = app
        .jwt(i64::try_from(now.as_secs()).unwrap_or(0))
        .ok_or(Outcome::Unexpected)?;
    let req = Req {
        host: Host::Api,
        method: Method::Post,
        path: format!("/app/installations/{installation_id}/access_tokens"),
        body: None,
    };
    let resp = t.send(&req, Some(jwt.as_str())).await?;
    classify(&resp)?;
    let m: Minted = serde_json::from_slice(&resp.body).map_err(|_| Outcome::Unexpected)?;
    Material::new(&m.token, None, m.expires_at.as_deref()).ok_or(Outcome::Unexpected)
}
