//! Calls to Ainkrad's sign-in service (`signin.ainkrad.io`), which holds the Atlassian client
//! secret so no Core does (N23). Contract: `Docs/Specs/2026-11-12-signin-service-contract.md`.
//! Each request is signed `AINKRAD-SVC-V1` with the Core identity key.

use serde_json::Value;

use super::http::{CallError, Http, Resp};
use super::renew::{Issued, issued};
use crate::auth::Identity;
use crate::auth::crypto::{b64, random, sha256};
use crate::scheduler::unix_secs;

/// The service's origin.
pub const DEFAULT_BASE: &str = "https://signin.ainkrad.io";
/// Overrides [`DEFAULT_BASE`] (tests, a staging service).
pub const BASE_ENV: &str = "AINKRAD_SIGNIN_URL";

pub(crate) fn base() -> String {
    std::env::var(BASE_ENV)
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_BASE.to_owned())
}

/// The string the signature covers: 8 fields, `\n`-joined, no trailing newline.
pub fn signed_string(fp: &str, path: &str, ts: &str, nonce: &str, body: &[u8]) -> String {
    let hash = b64(&sha256(body));
    [
        "AINKRAD-SVC-V1",
        fp,
        "ES256",
        "POST",
        path,
        ts,
        nonce,
        &hash,
    ]
    .join("\n")
}

/// The signing headers of a request (`Content-Type` is set by the transport).
pub fn headers(id: &Identity, path: &str, ts: &str, body: &[u8]) -> Vec<(&'static str, String)> {
    let nonce = b64(&random::<16>());
    let sig = id.sign(signed_string(&id.fp, path, ts, &nonce, body).as_bytes());
    vec![
        ("ainkrad-core", id.fp.clone()),
        ("ainkrad-key", b64(&id.spki)),
        ("ainkrad-alg", "ES256".to_owned()),
        ("ainkrad-timestamp", ts.to_owned()),
        ("ainkrad-nonce", nonce),
        ("ainkrad-signature", b64(&sig)),
    ]
}

const DOWN: CallError = CallError::SignIn(
    "Ainkrad's sign-in service could not be reached. Check this Core's internet access and try again",
);

/// POSTs `body` to `path` on the service, signed; `now` is the Core's clock (ISO). Any answer is
/// `Ok`; only a service that cannot be reached is an error.
pub(crate) async fn post(
    http: &Http,
    signer: Option<&Identity>,
    path: &str,
    body: &Value,
    now: &str,
) -> Result<Resp, CallError> {
    let id = signer.ok_or(CallError::Internal(
        "this Core has no identity to sign with",
    ))?;
    let secs = unix_secs(now).ok_or(CallError::Internal("the clock is unreadable"))?;
    let bytes = serde_json::to_vec(body).map_err(|_| CallError::Internal("unserializable body"))?;
    let hdrs = headers(id, path, &secs.to_string(), &bytes);
    let url = format!("{}{path}", http.signin);
    match http.post_bytes(&url, bytes, &hdrs).await {
        Err(CallError::Network | CallError::TimedOut | CallError::Broken) => Err(DOWN),
        other => other,
    }
}

/// [`post`] for a token endpoint: the tokens, or what the failure means.
pub(super) async fn call(
    http: &Http,
    signer: Option<&Identity>,
    path: &str,
    body: &Value,
    now: &str,
) -> Result<Issued, CallError> {
    let res = post(http, signer, path, body, now).await?;
    if (200..300).contains(&res.status) {
        return issued(res.body, res.status, now);
    }
    Err(fault(res.status, &res.body))
}

/// What a failed answer means. `invalid_grant` alone condemns the user's credential.
pub(crate) fn fault(status: u16, body: &Value) -> CallError {
    let code = body["error"]["code"].as_str().unwrap_or("");
    CallError::SignIn(match (status, code) {
        (_, "invalid_grant") => return CallError::AuthFailed,
        (401, "stale_timestamp") => {
            "This Core's clock is too far off for Ainkrad's sign-in service. Fix the clock and try again"
        }
        (429, _) => "Ainkrad's sign-in service is busy. Try again in a minute",
        (500 | 502, "service_misconfigured") => {
            "Ainkrad's sign-in service has no working Atlassian app right now. Try again later"
        }
        (502, _) => "Ainkrad's sign-in service could not reach Atlassian. Try again in a minute",
        (s, _) if s >= 500 => "Ainkrad's sign-in service had an error. Try again in a minute",
        _ => "Ainkrad's sign-in service refused this Core's request",
    })
}
