//! The Core's client of the root host helper (`ainkrad-host`, host-helper plan §3.1, §3.2): one
//! request line and one response line over the fixed Unix socket `/run/ainkrad/host.sock`.
//!
//! - **One call in flight.** A mutex serialises calls; a caller waits at most [`QUEUE`] for its turn
//!   and then gets [`Failure::Busy`], so no request thread ever waits on another call for long.
//! - **Deadlines.** The whole exchange (connect, write, one line back) is cut at [`CALL`] ([`LOGS`]
//!   for `logs`): [`Failure::Timeout`].
//! - **Absent is an answer, not a hang.** No socket file is [`Failure::Absent`]; a socket nobody
//!   serves (the socket unit stopped) or one this user may not open is [`Failure::Unavailable`].
//! - **A connection closed with no bytes is `Busy`.** systemd refuses a connection past
//!   `MaxConnections` by closing it.
//! - **One response line, then stop.** After a refusal the helper closes with unread bytes, so the
//!   client reads exactly one line (at most 512 KiB) and never reads to EOF.
//!
//! The path is a constant: there is no setting for it (the tests build a [`Client::at`] on their
//! own socket). This module shares no code with the helper crate, so the Core links none of its
//! root-side code; the wire format is the one in `crates/host/src/wire.rs`.

use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

/// The helper's socket (a fixed path: `ainkrad-host.socket`).
pub const SOCKET: &str = "/run/ainkrad/host.sock";

/// How long a call waits for the one in flight before it reports `Busy`.
const QUEUE: Duration = Duration::from_secs(2);
/// The deadline of one exchange (`logs`: [`LOGS`]).
const CALL: Duration = Duration::from_secs(10);
const LOGS: Duration = Duration::from_secs(30);
/// The helper's cap on a response line (`wire::MAX_RESPONSE`), plus its newline.
const MAX_RESPONSE: u64 = 512 * 1024 + 1;

/// A request id for the helper: a 26-character ULID (the part of a fresh error id after `err_`).
pub fn request_id() -> String {
    crate::api::v1::error_id()[4..].to_owned()
}

/// What the Core tells the helper it acts for; the helper records it as `claimed_by_core`.
#[derive(Debug, Clone)]
pub struct Actor {
    /// The calling device, `d_…`.
    pub device: String,
    /// The audit row written for this call (0 when there is none).
    pub audit_seq: u64,
}

/// Why a call produced no result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// There is no socket file: the helper is not installed here.
    Absent,
    /// The socket exists but cannot be used (nobody listens, or this user may not connect).
    Unavailable,
    /// Another call is in flight past [`QUEUE`], or the helper closed the connection unread.
    Busy,
    /// The exchange passed its deadline.
    Timeout,
    /// The helper answered with a refusal: its `code`, and `retry_after` seconds when it gave one.
    Refused {
        code: String,
        retry_after: Option<u64>,
    },
    /// The answer was not one well-formed response line for this request.
    Garbled,
}

pub struct Client {
    path: PathBuf,
    gate: Mutex<()>,
    /// The uid the socket's server must have (`SO_PEERCRED`): root in production.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    expect_uid: u32,
    /// Replaces [`CALL`] and [`LOGS`] (tests).
    deadline: Option<Duration>,
    /// Actions the helper just refused or failed, until when: `(unix seconds, why)`. A caller
    /// that keeps asking meanwhile is answered from here and costs the helper (and the audit
    /// log) nothing.
    backoff: std::sync::Mutex<HashMap<String, (u64, Failure)>>,
}

impl Default for Client {
    /// The real helper: [`SOCKET`], served by root.
    fn default() -> Self {
        Self::build(SOCKET.into(), 0)
    }
}

impl Client {
    fn build(path: PathBuf, expect_uid: u32) -> Self {
        Self {
            path,
            gate: Mutex::new(()),
            expect_uid,
            deadline: None,
            backoff: std::sync::Mutex::default(),
        }
    }

    /// A client of `path` whose server runs as this process's user: a fake helper's socket in tests.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self::build(path.into(), ainkrad_sys::getuid())
    }

    /// Requires the socket's server to run as `uid`.
    pub fn expecting_uid(mut self, uid: u32) -> Self {
        self.expect_uid = uid;
        self
    }

    /// Cuts every exchange at `d` (tests; production uses [`CALL`] and [`LOGS`]).
    pub fn with_deadline(mut self, d: Duration) -> Self {
        self.deadline = Some(d);
        self
    }

    /// Why `action` is held back at `now`, if it is: the failure it ended with, a rate limit
    /// with the wait that is left.
    pub fn blocked(&self, action: &str, now: u64) -> Option<Failure> {
        let mut held = self.backoff.lock().unwrap_or_else(|e| e.into_inner());
        let (until, why) = held.get(action)?.clone();
        if now >= until {
            held.remove(action);
            return None;
        }
        Some(match why {
            Failure::Refused { code, .. } if code == "rate_limited" => Failure::Refused {
                code,
                retry_after: Some(until - now),
            },
            other => other,
        })
    }

    /// Holds `action` back for `secs` with `why`.
    pub fn block(&self, action: &str, now: u64, secs: u64, why: Failure) {
        let mut held = self.backoff.lock().unwrap_or_else(|e| e.into_inner());
        held.insert(action.to_owned(), (now + secs, why));
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// One request, one response. `id` is a 26-character ULID; `params` are the action's.
    pub async fn call(
        &self,
        id: &str,
        action: &str,
        params: Value,
        actor: &Actor,
    ) -> Result<Value, Failure> {
        let mut line = json!({
            "v": 1, "id": id, "action": action, "params": params,
            "actor": {"device": actor.device, "audit_seq": actor.audit_seq},
        })
        .to_string()
        .into_bytes();
        line.push(b'\n');
        let _turn = tokio::time::timeout(QUEUE, self.gate.lock())
            .await
            .map_err(|_| Failure::Busy)?;
        let deadline = self
            .deadline
            .unwrap_or(if action == "logs" { LOGS } else { CALL });
        tokio::time::timeout(deadline, self.exchange(id, &line))
            .await
            .map_err(|_| Failure::Timeout)?
    }

    async fn exchange(&self, id: &str, request: &[u8]) -> Result<Value, Failure> {
        let mut stream = UnixStream::connect(&self.path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Failure::Absent
            } else {
                Failure::Unavailable
            }
        })?;
        // The kernel's record of who serves the socket: only root may. Linux only: the helper exists nowhere else, and
        // `peer_uid` is unsupported elsewhere (the macOS CI still runs the tests against a fake helper).
        #[cfg(target_os = "linux")]
        match ainkrad_sys::peer_uid(stream.as_fd()) {
            Ok(uid) if uid == self.expect_uid => {}
            _ => return Err(Failure::Unavailable),
        }
        // A connection systemd refuses is closed at once: the write may already fail.
        stream.write_all(request).await.map_err(closed)?;
        let mut reader = BufReader::new((&mut stream).take(MAX_RESPONSE));
        let mut response = Vec::new();
        let read = reader.read_until(b'\n', &mut response).await;
        match (read, response.last()) {
            (_, Some(b'\n')) => {}
            (Ok(0), None) => return Err(Failure::Busy),
            (Err(e), None) => return Err(closed(e)),
            _ => return Err(Failure::Garbled),
        }
        let v: Value = serde_json::from_slice(&response).map_err(|_| Failure::Garbled)?;
        if v["v"] != 1 || v["id"] != id {
            return Err(Failure::Garbled);
        }
        match v["ok"].as_bool() {
            Some(true) if v["result"].is_object() => Ok(v["result"].clone()),
            Some(false) => Err(Failure::Refused {
                code: v["code"]
                    .as_str()
                    .unwrap_or("failed")
                    .chars()
                    .take(32)
                    .collect(),
                retry_after: v["retry_after"].as_u64(),
            }),
            _ => Err(Failure::Garbled),
        }
    }
}

/// A reset or broken pipe before any byte came back: the helper (systemd) closed the connection.
fn closed(e: std::io::Error) -> Failure {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, UnexpectedEof};
    match e.kind() {
        BrokenPipe | ConnectionReset | ConnectionAborted | UnexpectedEof => Failure::Busy,
        _ => Failure::Unavailable,
    }
}
