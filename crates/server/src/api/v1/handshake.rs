//! `GET /handshake` (E1-05.5): what a client asks before it has a key, or before it trusts
//! the server it reached: the server's version and build, the contract minor it speaks and
//! the minors it serves. A client built against minor N talks to any server whose
//! `supported_minors` holds N; below that the server lacks something the client may use, so
//! the client checks before calling it (versioning rule in `types`).
//!
//! Pre-auth (`gateway::preauth`): no signature, and nothing in it about devices, settings or
//! state. `identity_fingerprint` is `core_fp`, the Core identity key's fingerprint (handshake
//! spec §3): every signed request names it, and a client compares it with the one it pinned.
//!
//! `POST /handshake {nonce}` (spec §4, §13) answers the same plus `core_spki` and `core_sig`, the
//! Core identity key's signature over `AINKRAD-CORE-V1` LF `<host>` LF `<nonce>`: a client that
//! pinned `core_fp` checks the key is the pinned one and that it signed the client's fresh
//! nonce, which a server merely echoing the fingerprint cannot do. `host` is the Host the
//! Core is configured for (the `Host` it requires). It proves the Core's identity at that
//! moment, not the channel or later answers: a relaying man in the middle with a misissued
//! certificate can pass it on (threat model T-GW-3). Vector:
//! `crates/server/tests/vectors/core-sig-v1.json`.

use axum::Json;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::gate;
use super::me::Versions;
use super::pair::bad;
use super::types::API_MINOR;
use crate::api::App;
use crate::auth::crypto::{b64, unb64};
use crate::gateway::preauth::PREAUTH_BODY;

/// What the server is and speaks, for anyone.
#[derive(Debug, Serialize, ToSchema)]
pub struct Handshake {
    /// The server's crate version, `0.1.0`.
    pub server_version: Option<String>,
    /// The commit it was built from (short sha), when the build knew it.
    pub git_sha: Option<String>,
    /// `v1`.
    pub api_major: Option<String>,
    /// The contract minor this server speaks (`GET /api/v1/me` has it too).
    pub api_minor: Option<u32>,
    /// Every minor a client may have been built against and still be served: 0 up to
    /// `api_minor`.
    pub supported_minors: Option<Vec<u32>>,
    /// `core_fp`: base64url SHA-256 of the Core identity key's SPKI, 43 characters. Signed
    /// into every request (handshake spec §5.2).
    pub identity_fingerprint: Option<String>,
}

/// `POST /handshake`'s answer: `GET`'s fields plus the proof, which is always present (review
/// L4). A client that pinned `core_fp` aborts with `core_identity_mismatch` when either is
/// missing or fails, and never falls back to `GET /handshake` (spec §13).
#[derive(Debug, Serialize, ToSchema)]
pub struct HandshakeProof {
    pub server_version: Option<String>,
    pub git_sha: Option<String>,
    pub api_major: Option<String>,
    pub api_minor: Option<u32>,
    pub supported_minors: Option<Vec<u32>>,
    /// `core_fp`, as in `GET /handshake`; a client checks `fp(core_spki)`, not this claim.
    pub identity_fingerprint: Option<String>,
    /// The Core identity key, a P-256 SubjectPublicKeyInfo, base64url. Its fingerprint is
    /// `identity_fingerprint`.
    pub core_spki: String,
    /// The Core identity key's ES256 signature (raw r||s, base64url) over the UTF-8 string
    /// `AINKRAD-CORE-V1` LF `<host>` LF `<nonce>`, no trailing newline; `host` is the Core's
    /// configured Host (the `Host` it requires), `nonce` the text the client sent.
    pub core_sig: String,
}

/// A liveness proof request: a fresh nonce from the client.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct HandshakeBody {
    /// 16 random bytes, base64url without padding (22 characters).
    pub nonce: String,
}

/// The bytes `core_sig` signs.
pub fn core_sig_message(host: &str, nonce: &str) -> Vec<u8> {
    format!("AINKRAD-CORE-V1\n{host}\n{nonce}").into_bytes()
}

fn current(app: &App) -> Handshake {
    let v = Versions::current();
    Handshake {
        server_version: Some(v.server),
        git_sha: v.git_sha,
        api_major: Some(v.api.major),
        api_minor: Some(v.api.minor),
        supported_minors: Some((0..=API_MINOR).collect()),
        identity_fingerprint: Some(app.auth.identity.fp.clone()),
    }
}

#[utoipa::path(get, path = "/handshake", operation_id = "getHandshake", tag = "handshake",
    security(()),
    responses((status = 200, description = "The server's version and build, the contract minor \
        and the minors it serves, and the Core identity fingerprint. Needs no signature", body = Handshake)))]
pub async fn handshake(State(app): State<App>) -> Json<Handshake> {
    Json(current(&app))
}

#[utoipa::path(post, path = "/handshake", operation_id = "proveHandshake", tag = "handshake",
    request_body = HandshakeBody, security(()),
    responses((status = 200, description = "As `GET /handshake`, plus `core_spki` and `core_sig`, \
        the Core identity key's signature over the client's nonce: check `fp(core_spki)` is the \
        pinned `core_fp` and that `core_sig` verifies before trusting this Core; anything else, \
        a missing proof or a status other than 200 included, is `core_identity_mismatch`, with \
        no fallback to `GET`. 400 for a nonce that is not 16 bytes of base64url; 429 past 30 a \
        minute from one address, shared with `POST /handshake/challenge`. Needs no signature",
        body = HandshakeProof)))]
pub async fn prove(State(app): State<App>, req: Request) -> Response {
    let (parts, raw) = req.into_parts();
    // One P-256 signature per call: under the pre-auth challenge rate (review L3).
    if let Err(r) = super::session::throttle(&app, &parts).await {
        return *r;
    }
    let bytes = match gate::body(raw, PREAUTH_BODY).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    let Ok(b) = serde_json::from_slice::<HandshakeBody>(&bytes) else {
        return bad("the body is {\"nonce\"}");
    };
    if unb64(&b.nonce, 22).is_none() {
        return bad("nonce is 16 bytes, base64url without padding");
    }
    let id = &app.auth.identity;
    let h = current(&app);
    Json(HandshakeProof {
        server_version: h.server_version,
        git_sha: h.git_sha,
        api_major: h.api_major,
        api_minor: h.api_minor,
        supported_minors: h.supported_minors,
        identity_fingerprint: h.identity_fingerprint,
        core_spki: b64(&id.spki),
        core_sig: b64(&id.sign(&core_sig_message(&app.host, &b.nonce))),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Identity;
    use crate::auth::crypto::{fingerprint, verify};

    /// The committed `core_sig` vector (`tests/vectors/core-sig-v1.json`) for client SDKs: the
    /// throwaway TEST Core key of `handshake-v1.json`, a fixed host and nonce, the exact message
    /// and a signature to verify. `UPDATE_VECTORS=1` rewrites it.
    #[test]
    fn the_core_sig_vector_holds() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/vectors/core-sig-v1.json"
        );
        let hs: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/vectors/handshake-v1.json")).unwrap();
        let der = unb64(hs["core_pkcs8"].as_str().unwrap(), 184).unwrap();
        let core = Identity::from_pkcs8(&der).unwrap();
        let (host, nonce) = ("core.example", "AAECAwQFBgcICQoLDA0ODw");
        let message = core_sig_message(host, nonce);
        if std::env::var_os("UPDATE_VECTORS").is_some() {
            let v = serde_json::json!({
                "comment": "POST /handshake core_sig vector (handshake spec §4, §13). message = \"AINKRAD-CORE-V1\" LF host LF nonce (UTF-8, no trailing newline); host is the Core's configured Host, nonce the 22-character base64url text the client sent. core_sig is ES256 raw r||s, base64url without padding, and randomised: verify it, never expect to reproduce it. The key is the throwaway TEST key of handshake-v1.json.",
                "host": host,
                "nonce": nonce,
                "message": String::from_utf8(message.clone()).unwrap(),
                "core_spki": b64(&core.spki),
                "core_fp": core.fp,
                "core_sig": b64(&core.sign(&message)),
            });
            std::fs::write(path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
        }
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let s = |k: &str| v[k].as_str().unwrap().to_owned();
        assert_eq!(s("message").as_bytes(), &message[..]);
        let spki = unb64(&s("core_spki"), 122).unwrap();
        assert_eq!(fingerprint(&spki), s("core_fp"));
        assert_eq!(s("core_fp"), core.fp);
        let sig = unb64(&s("core_sig"), 86).unwrap();
        assert!(verify(&spki, &message, &sig));
        let other = core_sig_message("evil.example", nonce);
        assert!(!verify(&spki, &other, &sig), "bound to the host");
    }
}
