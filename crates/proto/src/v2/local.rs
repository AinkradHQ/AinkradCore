//! The local terminal path (spec `Specs/2026-11-12-local-terminal-path.md`): what the Core signs
//! so an app on the runner's own Mac may attach to a terminal over the host's Unix socket
//! instead of through the Core. Not a runner frame (no schema): the grant travels Core -> app
//! -> host, and the host speaks its own line protocol (`ainkrad-ptyhost::wire`).
//!
//! A grant is `<b64url(JSON LocalGrant)>.<b64url(ES256 r||s)>`, signed by the Core's identity
//! key over `GRANT_CONTEXT || <the first part>`. The app proves it holds the device key the
//! grant names by signing `attach_message(challenge, grant)` with it.

use serde::{Deserialize, Serialize};

/// Domain separation of the Core's signature over a grant.
pub const GRANT_CONTEXT: &[u8] = b"AINKRAD-LOCAL-GRANT-V1\n";
/// Domain separation of the app's proof of possession.
pub const ATTACH_CONTEXT: &[u8] = b"AINKRAD-LOCAL-ATTACH-V1\n";
/// The grant format this build issues and accepts.
pub const GRANT_VERSION: u32 = 1;
/// How long a grant may be presented after it is issued, in seconds. Generous because Mac and
/// Core clocks differ; a grant is also single-use.
pub const GRANT_TTL_SECS: i64 = 60;
/// How long one authentication keeps a local connection open, in seconds. The app renews
/// before it ends with a fresh grant; a revoked device cannot get one.
pub const LEASE_SECS: u64 = 45;

/// What the Core vouches for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalGrant {
    pub v: u32,
    /// The terminal (`t_...`) this grant is for.
    pub terminal: String,
    /// The runner device the terminal lives on: the host checks it is its own runner's.
    pub runner: String,
    /// The app's device id, and its routine key (SPKI, base64url): the key that must sign
    /// the host's challenge.
    pub device: String,
    pub device_spki: String,
    /// Random, single-use.
    pub nonce: String,
    /// Unix seconds, Core clock.
    pub iat: i64,
    pub exp: i64,
    /// Seconds one authentication keeps the connection open.
    pub lease: u64,
}

/// The bytes the Core signs for the grant payload `payload_b64`.
pub fn grant_message(payload_b64: &str) -> Vec<u8> {
    [GRANT_CONTEXT, payload_b64.as_bytes()].concat()
}

/// The bytes the app signs: the host's `challenge` and the whole `grant` text, so a proof is
/// good for one challenge and one grant only.
pub fn attach_message(challenge: &str, grant: &str) -> Vec<u8> {
    [
        ATTACH_CONTEXT,
        challenge.as_bytes(),
        b"\n",
        grant.as_bytes(),
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app (Swift, `LocalTerminalAttachment.attachMessage`) builds these bytes on its own; a
    /// change here without the same change there breaks every local attach.
    #[test]
    fn the_signed_messages_are_the_bytes_the_app_builds() {
        assert_eq!(
            attach_message("chal", "grant"),
            b"AINKRAD-LOCAL-ATTACH-V1\nchal\ngrant"
        );
        assert_eq!(grant_message("p"), b"AINKRAD-LOCAL-GRANT-V1\np");
    }
}
