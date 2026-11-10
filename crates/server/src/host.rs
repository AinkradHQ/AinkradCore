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
}

impl Default for Client {
    fn default() -> Self {
        Self::at(SOCKET)
    }
}

impl Client {
    /// A client of `path`: [`SOCKET`] in production, a fake helper's socket in tests.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            gate: Mutex::new(()),
        }
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
        let deadline = if action == "logs" { LOGS } else { CALL };
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
