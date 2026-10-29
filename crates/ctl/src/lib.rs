//! `ainkradctl`, the reference client of the Ainkrad Core (E1-14): pairing, signed requests,
//! sessions, devices, the event stream and health, implemented from the handshake spec
//! (`Docs/Specs/2026-10-29-core-handshake-spec.md`), never from the server's code.
//!
//! Nothing here prints or logs a private key, a pairing code or secret it was given, a nonce
//! or a signature.

pub mod client;
pub mod cmd;
pub mod events;
pub mod keystore;
pub mod net;
pub mod pair;
pub mod proto;

/// Why a command failed; each kind has its own exit code (`code`).
#[derive(Debug)]
pub enum Error {
    /// Bad arguments or a malformed input (2).
    Usage(String),
    /// The Core could not be reached, or the connection broke (1).
    Unreachable(String),
    /// The Core answered something the spec does not allow (1).
    Protocol(String),
    /// The Core's identity is not the pinned one; nothing was signed or sent (3).
    Identity { pinned: String, served: String },
    /// The Core refused the request (4), or the clock is off (8, `clock_skew`).
    Refused {
        status: u16,
        code: String,
        message: String,
        server_time: Option<i64>,
        local_time: i64,
    },
    /// The resume point is below the event retention floor (5).
    PastRetention { floor: i64 },
    /// This device was revoked: the Core closed its stream with 4001 (6).
    Revoked,
    /// The pairing ended without approval: rejected or expired (7).
    NotApproved(String),
}

impl Error {
    pub fn code(&self) -> u8 {
        match self {
            Self::Unreachable(_) | Self::Protocol(_) => 1,
            Self::Usage(_) => 2,
            Self::Identity { .. } => 3,
            Self::Refused { code, .. } if code == "clock_skew" => 8,
            Self::Refused { .. } => 4,
            Self::PastRetention { .. } => 5,
            Self::Revoked => 6,
            Self::NotApproved(_) => 7,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(m) | Self::Unreachable(m) => f.write_str(m),
            Self::Protocol(m) => write!(f, "the Core broke the protocol: {m}"),
            Self::Identity { pinned, served } => write!(
                f,
                "core_identity_mismatch: this Core is {served}, the keystore pins {pinned}; \
                 refusing to sign or send anything"
            ),
            Self::Refused {
                status,
                code,
                message,
                server_time: Some(t),
                local_time,
            } => write!(
                f,
                "{status} {code}: {message}; server_time {t}, local {local_time} ({:+} s): fix this \
                 machine's clock",
                local_time - t
            ),
            Self::Refused {
                status,
                code,
                message,
                ..
            } => write!(f, "{status} {code}: {message}"),
            Self::PastRetention { floor } => write!(
                f,
                "past_retention: events up to {floor} were trimmed; re-sync, then resume from \
                 events/latest"
            ),
            Self::Revoked => f.write_str("revoked: the Core closed the stream (4001)"),
            Self::NotApproved(status) => write!(f, "the pairing ended {status}: not approved"),
        }
    }
}

impl std::error::Error for Error {}

/// The exit codes, for `--help`.
pub const EXIT_CODES: &str = "Exit codes:
  0  done
  1  the Core is unreachable, or answered off-protocol
  2  usage: bad arguments or input
  3  core_identity_mismatch: the Core is not the pinned one (nothing was signed or sent)
  4  refused by the Core (auth_failed, forbidden_scope, step_up_required, not_found, ...)
  5  past_retention: the resume point was trimmed (the floor is printed)
  6  revoked: the Core closed this device's stream with 4001
  7  the pairing was rejected or expired
  8  clock_skew: this machine's clock is over 60 s off (server_time is printed)";
