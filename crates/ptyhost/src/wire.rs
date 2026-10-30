//! The host socket protocol (E2-03.1, .5): one JSON message per line over the host's Unix
//! socket, bytes as standard base64.
//!
//! - The host speaks first: `hello` with [`HOST_PROTOCOL`] and the terminal's [`HostInfo`].
//! - **Versioning.** A runner and the hosts it adopts may be different builds (a runner
//!   upgraded under running terminals). Within a protocol major, messages and fields are only
//!   added: either side skips a message `type` it does not know (`Unknown`) and ignores fields
//!   it does not know. A client refuses a host whose major is newer than its own.
//! - Output is `out` with the byte offset of its first byte; a client that attaches at a point
//!   the host no longer holds gets `snapshot` first.

use ainkrad_proto::v2::{Size, TerminalState};
use serde::{Deserialize, Serialize};

use crate::pty::Exit;

/// The host protocol version this build speaks.
pub const HOST_PROTOCOL: u32 = 1;

/// What a host says about itself and its terminal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInfo {
    /// The terminal, `t_…`.
    pub id: String,
    /// The host process.
    pub pid: u32,
    /// Random per host process: with `pid`, tells this host from a later process that reused
    /// its pid.
    pub boot: String,
    /// Unix milliseconds the host started.
    pub started: u64,
    /// The child's pid (its process group).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child: Option<u32>,
    pub state: TerminalState,
    pub size: Size,
    /// Output bytes so far.
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<Exit>,
}

/// Client (the runner) to host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToHost {
    /// Send output from `seq` on (a `snapshot` first if it is no longer held), and the exit.
    Attach {
        seq: u64,
    },
    Input {
        data: String,
    },
    Resize {
        size: Size,
    },
    Signal {
        signal: String,
    },
    /// A fresh `snapshot` now (the client fell behind).
    Snapshot,
    /// Hang up: HUP, then TERM, then KILL, `grace_ms` apart.
    Close {
        grace_ms: u64,
    },
    /// The exit was read: the host cleans up and ends.
    Ack,
    /// From a newer client: ignored.
    #[serde(other)]
    Unknown,
}

/// Host to client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FromHost {
    Hello {
        protocol: u32,
        info: HostInfo,
    },
    Out {
        seq: u64,
        data: String,
    },
    Snapshot {
        seq: u64,
        data: String,
    },
    Exit {
        exit: Exit,
    },
    Error {
        message: String,
    },
    /// From a newer host: ignored.
    #[serde(other)]
    Unknown,
}

/// What the host keeps next to its socket, `<id>.json` (`0600`): enough to tell it is still
/// the same process when the runner scans on start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRecord {
    pub protocol: u32,
    pub pid: u32,
    pub boot: String,
    pub started: u64,
}

/// A terminal id: `t_` and 1 to 40 of `[A-Za-z0-9_-]`, so it is safe in a path.
pub fn valid_id(id: &str) -> bool {
    id.strip_prefix("t_").is_some_and(|r| {
        (1..=40).contains(&r.len())
            && r.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// E2-03.5: an older side reads what a newer one sends.
    #[test]
    fn newer_messages_and_fields_are_skipped() {
        let m: ToHost = serde_json::from_str(r#"{"type":"zoom","level":2}"#).unwrap();
        assert_eq!(m, ToHost::Unknown);
        let m: ToHost = serde_json::from_str(r#"{"type":"attach","seq":5,"mode":"x"}"#).unwrap();
        assert_eq!(m, ToHost::Attach { seq: 5 });
        let m: FromHost = serde_json::from_str(r#"{"type":"bell"}"#).unwrap();
        assert_eq!(m, FromHost::Unknown);
        let hello = r#"{"type":"hello","protocol":1,"info":{"id":"t_a","pid":9,"boot":"b",
            "started":1,"state":"running","size":{"rows":24,"cols":80},"seq":0,"cwd":"/x"}}"#;
        let FromHost::Hello { info, .. } = serde_json::from_str(hello).unwrap() else {
            panic!()
        };
        assert_eq!(info.pid, 9);
    }

    #[test]
    fn ids_are_path_safe() {
        assert!(valid_id("t_AAECAwQFBgcICQoL"));
        for bad in [
            "t_",
            "x_abc",
            "t_../x",
            "t_a/b",
            "t_a.b",
            &format!("t_{}", "a".repeat(41)),
        ] {
            assert!(!valid_id(bad), "{bad}");
        }
    }
}
