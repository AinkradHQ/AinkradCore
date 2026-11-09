//! The connection proof (E1-11.3, handshake spec §13): who is on each end of a runner
//! connection, bound to this TLS session.
//!
//! 1. Runner → `hello` with `device_id` and `nonce` (`nonce_r`, 32 random bytes).
//! 2. Core → `auth` `{core_spki, nonce, sig}`: `nonce` is `nonce_c` (32 random bytes) and `sig`
//!    is the Core identity key over [`core_auth_message`].
//! 3. The runner checks `fp(core_spki)` against the fingerprint it pinned at enrolment and
//!    verifies `sig`. On a mismatch it closes and sends nothing more.
//! 4. Runner → `proof` `{sig}`: its routine key over [`runner_auth_message`]. The Core verifies
//!    it and answers `welcome`, or `error` `auth_failed` and closes.
//!
//! `X` is the TLS exporter (RFC 8446 §7.5): [`EXPORTER_LABEL`], no context, [`EXPORTER_LEN`]
//! bytes. A relay holding a valid certificate has two TLS sessions, so two different `X`, and
//! cannot pass either proof on. Without TLS (a Unix socket or a loopback peer only) `X` is
//! [`NO_CHANNEL_BINDING`]: nothing binds the proof to the connection there.
//!
//! Byte strings travel as base64url without padding; `fp` is the 43-character base64url
//! SHA-256 of a SPKI, as text. Vectors: `crates/server/tests/vectors/runner-auth-v1.json`.
//!
//! **Rotation (planned, §13).** The Core sends `rotation` on an authenticated connection,
//! signed by the key the runner pinned (the `core_spki` it just checked). A runner accepts it
//! only when `old_fp` is its pin, the signature verifies and `seq` is above the last rotation it
//! applied; it then pins `new_fp`. Anything else is ignored. A compromised key is not rotated:
//! the runner is paired again.

use serde::{Deserialize, Serialize};

/// The TLS exporter label (RFC 5705/8446).
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-ainkrad-core-v1";
/// The exporter's length, and that of each nonce.
pub const EXPORTER_LEN: usize = 32;
/// `X` on a connection without TLS: a Unix socket or a loopback peer, nothing else.
pub const NO_CHANNEL_BINDING: [u8; EXPORTER_LEN] = [0; EXPORTER_LEN];

/// Core to runner, the answer to `hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreAuth {
    /// The Core identity SPKI (91 bytes), base64url.
    pub core_spki: String,
    /// `nonce_c`, 32 bytes, base64url.
    pub nonce: String,
    /// ES256, raw r‖s, base64url: the Core key over `core_auth_message`.
    pub sig: String,
}

/// Runner to Core, once it has checked `CoreAuth`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerProof {
    /// ES256, raw r‖s, base64url: the runner's routine key over `runner_auth_message`.
    pub sig: String,
}

/// Core to runner: move the pin from `old_fp` to `new_fp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Rotation {
    pub old_fp: String,
    pub new_fp: String,
    /// Unix seconds from which the Core may present the new key.
    pub not_before: i64,
    /// Increases with every rotation; a runner applies only a higher one.
    pub seq: u64,
    /// ES256 by the old key over `rotation_message`, base64url.
    pub sig: String,
}

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `"AINKRAD-CORE-AUTH-V1" ‖ X ‖ nonce_r ‖ device_id` (UTF-8).
pub fn core_auth_message(exporter: &[u8], nonce_r: &[u8], device_id: &str) -> Vec<u8> {
    concat(&[
        b"AINKRAD-CORE-AUTH-V1",
        exporter,
        nonce_r,
        device_id.as_bytes(),
    ])
}

/// `"AINKRAD-RUNNER-AUTH-V1" ‖ X ‖ nonce_c ‖ core_fp` (the 43-character text).
pub fn runner_auth_message(exporter: &[u8], nonce_c: &[u8], core_fp: &str) -> Vec<u8> {
    concat(&[
        b"AINKRAD-RUNNER-AUTH-V1",
        exporter,
        nonce_c,
        core_fp.as_bytes(),
    ])
}

/// `AINKRAD-ROTATE-V1` LF old_fp LF new_fp LF not_before LF seq, no trailing newline.
pub fn rotation_message(r: &Rotation) -> Vec<u8> {
    format!(
        "AINKRAD-ROTATE-V1\n{}\n{}\n{}\n{}",
        r.old_fp, r.new_fp, r.not_before, r.seq
    )
    .into_bytes()
}
