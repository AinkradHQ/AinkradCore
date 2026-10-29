//! `GET /handshake` (E1-05.5): what a client asks before it has a key, or before it trusts
//! the server it reached: the server's version and build, the contract minor it speaks and
//! the minors it serves. A client built against minor N talks to any server whose
//! `supported_minors` holds N; below that the server lacks something the client may use, so
//! the client checks before calling it (versioning rule in `types`).
//!
//! Pre-auth (`gateway::preauth`): no signature, and nothing in it about devices, settings or
//! state. `identity_fingerprint` is `core_fp`, the Core identity key's fingerprint (handshake
//! spec §3): every signed request names it, and a client compares it with the one it pinned.

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::me::Versions;
use super::types::API_MINOR;
use crate::api::App;

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

#[utoipa::path(get, path = "/handshake", operation_id = "getHandshake", tag = "handshake",
    security(()),
    responses((status = 200, description = "The server's version and build, the contract minor \
        and the minors it serves, and the Core identity fingerprint. Needs no signature", body = Handshake)))]
pub async fn handshake(State(app): State<App>) -> Json<Handshake> {
    let v = Versions::current();
    Json(Handshake {
        server_version: Some(v.server),
        git_sha: v.git_sha,
        api_major: Some(v.api.major),
        api_minor: Some(v.api.minor),
        supported_minors: Some((0..=API_MINOR).collect()),
        identity_fingerprint: Some(app.auth.identity.fp.clone()),
    })
}
