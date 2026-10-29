//! Web sign-in with a passkey (handshake spec §9, E1-08.1/.3). The browser holds no long-lived
//! secret and no cookie: it makes a **non-extractable WebCrypto P-256 key** `k`, sends its SPKI to
//! `POST /handshake/passkey/options`, answers the options with a passkey assertion (user
//! verification required) at `POST /handshake/passkey/session`, and gets a session whose every
//! request it then signs with `k` exactly as §5 says (WebCrypto emits raw `r‖s`). The session
//! is memory-only like every other, lives `auth.web_session_secs` (8 h by default, 1 to 24 h,
//! absolute), carries the passkey device's scopes and dies with a revocation or a restart.
//!
//! No cookie means no ambient credential, so there is nothing for a cross-site request to ride
//! on (the CSRF stance): a request is authenticated only by a signature from a key the page's
//! own origin holds and cannot export, over custom `Ainkrad-*` headers that a cross-origin page
//! could only send after a CORS preflight the Core never grants; and any foreign `Origin` is
//! refused before routing anyway.
//!
//! Every failure of the session call is the one `auth_failed`, no sooner than `gate::FAIL_FLOOR`,
//! counted against the address (and the address and device, once the credential names one):
//! an unknown, used or expired ceremony, an unknown or revoked credential, a device that is not
//! an active passkey, a wrong origin, RP or signature, no user verification. A sign count that
//! did not grow on a verified assertion locks the credential and its device (`passkey.locked`)
//! and closes its sockets. Options are 30 a minute per address, three live per address.

use ainkrad_core::settings::{Key, Scope};
use axum::Json;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use webauthn_rs::prelude::{DiscoverableKey, Passkey, PublicKeyCredential, WebauthnError};

use super::passkey::{body, disabled};
use super::types::{Timestamp, ts};
use super::{ApiError, gate, too_many};
use crate::api::App;
use crate::auth::crypto::{spki_point, unb64};
use crate::auth::web::{CEREMONY_SECS, Passkeys};
use crate::scheduler::iso_of_unix;
use crate::store::gov::{self, Device};

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WebOptionsRequest {
    /// The browser's session key: a non-extractable WebCrypto ECDSA P-256 key's SPKI
    /// (`exportKey("spki")` of its public half), base64url.
    pub session_spki: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebOptions {
    /// `{"publicKey": PublicKeyCredentialRequestOptions}` (WebAuthn, binary fields base64url),
    /// user verification required, no credential list (the passkey is discoverable): decode
    /// it and pass it to `navigator.credentials.get`.
    #[schema(value_type = Object)]
    pub options: Option<Value>,
    pub expires_in: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct WebSessionRequest {
    /// The assertion as a WebAuthn `PublicKeyCredential` (`id`, `rawId`, `type`,
    /// `response.authenticatorData`, `response.clientDataJSON`, `response.signature`,
    /// `response.userHandle`), binary fields base64url.
    #[schema(value_type = Object)]
    pub credential: Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebSessionGrant {
    /// The passkey device, `d_…`: sent as `Ainkrad-Device`.
    pub device_id: Option<String>,
    /// `s_…`: sent as `Ainkrad-Session`; every request is signed with the session key.
    pub session_id: Option<String>,
    pub expires_at: Option<Timestamp>,
    pub scopes: Option<Vec<String>>,
    pub elevated_until: Option<Timestamp>,
}

#[utoipa::path(post, path = "/handshake/passkey/options", operation_id = "webSignInOptions",
    tag = "handshake", request_body = WebOptionsRequest, security(()),
    responses((status = 200, description = "Sign-in options bound to the session key, live 60 s, \
        single use. 429 past 30 a minute from one address; three live per address (a new one \
        replaces the oldest); 400 `passkeys_disabled` when the Core has no passkeys",
        body = WebOptions)))]
pub async fn options(State(app): State<App>, req: Request) -> Response {
    let Some(pk) = app.passkeys.clone() else {
        return disabled();
    };
    let (parts, raw) = req.into_parts();
    let addr = gate::address(&app, &parts);
    let now = app.clock.unix();
    match gov::locked_until(&app.pool, &[&addr], now).await {
        Ok(Some(until)) => {
            return too_many(std::time::Duration::from_secs((until - now).max(1) as u64));
        }
        Ok(None) => {}
        Err(e) => return ApiError::from(e).into_response(),
    }
    if let Err(wait) = app
        .auth
        .challenge_limit
        .take(&addr, std::time::Instant::now())
    {
        return too_many(wait);
    }
    let b: WebOptionsRequest = match body(raw).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let Some(key) = unb64(&b.session_spki, 122).filter(|k| spki_point(k).is_some()) else {
        return ApiError::bad_request("session_spki is a P-256 SubjectPublicKeyInfo, base64url")
            .into_response();
    };
    match pk.start_signin(key, &addr, now) {
        Some(options) => Json(WebOptions {
            options: Some(options),
            expires_in: Some(CEREMONY_SECS),
        })
        .into_response(),
        None => too_many(std::time::Duration::from_secs(CEREMONY_SECS as u64)),
    }
}

#[utoipa::path(post, path = "/handshake/passkey/session", operation_id = "webSignIn",
    tag = "handshake", request_body = WebSessionRequest, security(()),
    responses((status = 200, description = "A web session for the passkey device, signed with \
        the session key from the options, live `auth.web_session_secs` (absolute). Every failure \
        is 401 `auth_failed`; a sign count that did not grow locks the passkey",
        body = WebSessionGrant)))]
pub async fn session(State(app): State<App>, req: Request) -> Response {
    let Some(pk) = app.passkeys.clone() else {
        return disabled();
    };
    let (parts, raw) = req.into_parts();
    let addr = gate::address(&app, &parts);
    let now = app.clock.unix();
    match gov::locked_until(&app.pool, &[&addr], now).await {
        Ok(Some(until)) => {
            return too_many(std::time::Duration::from_secs((until - now).max(1) as u64));
        }
        Ok(None) => {}
        Err(e) => return ApiError::from(e).into_response(),
    }
    let b: WebSessionRequest = match body(raw).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let Ok(cred) = serde_json::from_value::<PublicKeyCredential>(b.credential) else {
        return ApiError::bad_request("credential is a PublicKeyCredential").into_response();
    };
    let started = tokio::time::Instant::now();
    match sign_in(&app, &pk, &cred, now).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => e.into_response(),
        Err((why, device)) => {
            let device = device.unwrap_or_else(|| "-".to_owned());
            let ipdev = format!("ipdev:{addr}:{device}");
            let r = gate::fail(&app, &addr, &ipdev, &device, why, now).await;
            tokio::time::sleep_until(started + gate::FAIL_FLOOR).await;
            r
        }
    }
}

/// Why a sign-in failed, and the device its credential names, once known.
type Failed = (&'static str, Option<String>);

async fn sign_in(
    app: &App,
    pk: &Passkeys,
    cred: &PublicKeyCredential,
    now: i64,
) -> Result<Result<Response, ApiError>, Failed> {
    let Some((state, key)) = pk.take_signin(cred, now) else {
        return Err(("no live sign-in ceremony", None));
    };
    let stored = match gov::get_credential(&app.pool, &cred.raw_id).await {
        Ok(Some(c)) if !c.revoked => c,
        Ok(_) => return Err(("unknown or revoked credential", None)),
        Err(e) => return Ok(Err(e.into())),
    };
    let named = Some(stored.device_id.clone());
    let device = match gov::get_device(&app.pool, &stored.device_id).await {
        Ok(Some(d)) if d.kind == "passkey" && d.usable() => d,
        Ok(_) => return Err(("device not usable", named)),
        Err(e) => return Ok(Err(e.into())),
    };
    let Ok(mut passkey) = serde_json::from_str::<Passkey>(&stored.passkey) else {
        tracing::error!(device = device.id, "a stored passkey does not parse");
        return Err(("stored passkey unreadable", named));
    };
    let keys = [DiscoverableKey::from(&passkey)];
    let result = match pk
        .webauthn
        .finish_discoverable_authentication(cred, state, &keys)
    {
        Ok(r) => r,
        Err(WebauthnError::CredentialPossibleCompromise) => {
            let counter = counter_of(cred);
            if let Err(e) = lock(app, &device, &stored.credential_id, counter).await {
                return Ok(Err(e.into()));
            }
            return Err(("sign count did not grow: locked", named));
        }
        Err(e) => {
            tracing::debug!(error = %e, "assertion refused");
            return Err(("assertion does not verify", named));
        }
    };
    passkey.update_credential(&result);
    let record = serde_json::to_string(&passkey).expect("a passkey serialises");
    let at = app.clock.now();
    let used = gov::credential_used(
        &app.pool,
        &stored.credential_id,
        &record,
        result.counter(),
        &at,
    );
    if let Err(e) = used.await {
        return Ok(Err(e.into()));
    }
    let secs = match crate::store::settings::value(
        &app.pool,
        Key::AuthWebSessionSecs,
        Scope::Server,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => return Ok(Err(e.into())),
    };
    let s = app.auth.issue_web_session(&device.id, key, now, now + secs);
    tracing::info!(device = device.id, "web session issued");
    Ok(Ok(Json(WebSessionGrant {
        device_id: Some(device.id),
        session_id: Some(s.id),
        expires_at: Some(ts(&iso_of_unix(s.expires))),
        scopes: Some(device.scopes),
        elevated_until: s.elevated_until.map(|t| ts(&iso_of_unix(t))),
    })
    .into_response()))
}

/// The sign count an assertion reports (bytes 33..37 of its authenticator data).
pub(super) fn counter_of(cred: &PublicKeyCredential) -> u32 {
    cred.response
        .authenticator_data
        .get(33..37)
        .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Locks a cloned credential and its device, then closes the device's sessions and sockets.
pub(super) async fn lock(
    app: &App,
    device: &Device,
    credential: &[u8],
    reported: u32,
) -> Result<(), sqlx::Error> {
    if gov::lock_credential(&app.pool, credential, reported, &app.clock.now()).await? {
        tracing::warn!(
            device = device.id,
            "passkey locked: sign count did not grow"
        );
    }
    app.auth.revoked(&device.id);
    Ok(())
}
