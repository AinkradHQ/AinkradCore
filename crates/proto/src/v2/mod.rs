//! Runner protocol v2 (E1-11.1, decision P1.6): multiplexed streams over one WebSocket.
//!
//! v1 (`crate::runner`) stays as it is for the parked Citadel copy; v2 is a separate wire
//! format, told apart by its `protocol` (`"2.0"`) and by its frame shape.
//!
//! **Frame.** Every WebSocket text message is one JSON `Frame`:
//! `{"stream_id": u64, "kind": "...", "seq": u64, "payload": {...}}`.
//! - Text JSON for every frame, raw bytes as standard base64 inside the payload
//!   (`Output::data`). ponytail: base64 costs a third more bytes; that is nothing for `exec`
//!   and acceptable for terminals at E2's rates. A binary WebSocket frame for `output` is the
//!   upgrade if throughput ever needs it, and it is additive (a new frame type, not a change).
//! - `stream_id` 0 is the connection's control stream (`control` hello/welcome, `heartbeat`,
//!   connection-level `error`). The Core opens command streams with **odd** ids; even ids are
//!   reserved for streams a runner opens later (E2-03: terminals it re-announces).
//! - `seq` counts frames per stream and per sender, from 0, by one: what E1-11.4 resumes by.
//! - The payload is decoded only once `kind` is known (two stages), so an unknown `kind`
//!   decodes as `FrameKind::Unknown` and is skipped, and an unknown payload field is ignored.
//!
//! **Kinds.** `control` (hello/welcome now; resize/snapshot/signal later), `command` (opens a
//! stream: Core to runner), `result` (a command's last frame, success), `error` (a command's
//! last frame, failure; or a connection-level problem on stream 0), `output` (bytes on a
//! stream, either direction), `credit` (flow control: the receiver allows `bytes` more
//! `output`), `close` (abandon a stream: from the Core, a cancel), `heartbeat`.
//!
//! **Terminal frames (E2-01) map onto these with no break:** `out` = `output` runner to Core;
//! `in` = `output` Core to runner (direction is the sender's); `resize` = a `control` body
//! `{"type":"resize"}` on the terminal's stream; `snapshot` = a `control` body
//! `{"type":"snapshot"}` carrying base64 screen bytes; `exit` = `result`; `credit` = `credit`.
//! A peer ignores a `control` type it does not know, and the Core sends terminal frames only
//! to a runner that advertised the `pty` driver.
//!
//! **Negotiation.** The runner's first frame is `control` `hello` with its `protocol` and its
//! drivers (`exec` now; `pty`, `harness` later), each with the commands it takes and how many
//! it runs at once. The Core answers `welcome`, or `error` `unsupported_version` and closes.
//! The Core sends only commands some advertised driver lists; the runner refuses any other
//! with `unsupported_command`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

mod command;
pub use command::*;

/// The v2 protocol version, `major.minor`; minors only add optional fields and kinds.
pub const PROTOCOL_VERSION: &str = "2.0";

/// The connection's own stream.
pub const CONTROL_STREAM: u64 = 0;

/// One WebSocket text message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Frame {
    pub stream_id: u64,
    pub kind: FrameKind,
    pub seq: u64,
    /// The body for `kind` (`Body`; schema `V2Payload`); absent for `heartbeat`.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    #[schemars(with = "Option<Value>")]
    pub payload: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    Control,
    Command,
    Result,
    Error,
    Output,
    Credit,
    Close,
    Heartbeat,
    /// A kind from a newer peer: skipped. Never sent.
    #[serde(other)]
    Unknown,
}

/// A frame's payload, typed.
#[derive(Debug, Clone, PartialEq)]
pub enum Body {
    Control(Control),
    Command(Command),
    Result(Reply),
    Error(StreamError),
    Output(Output),
    Credit(Credit),
    Close(Close),
    Heartbeat,
}

impl Frame {
    pub fn new(stream_id: u64, seq: u64, body: Body) -> Self {
        let json = |v: Result<Value, serde_json::Error>| v.expect("payload serializes");
        let (kind, payload) = match body {
            Body::Control(b) => (FrameKind::Control, json(serde_json::to_value(b))),
            Body::Command(b) => (FrameKind::Command, json(serde_json::to_value(b))),
            Body::Result(b) => (FrameKind::Result, json(serde_json::to_value(b))),
            Body::Error(b) => (FrameKind::Error, json(serde_json::to_value(b))),
            Body::Output(b) => (FrameKind::Output, json(serde_json::to_value(b))),
            Body::Credit(b) => (FrameKind::Credit, json(serde_json::to_value(b))),
            Body::Close(b) => (FrameKind::Close, json(serde_json::to_value(b))),
            Body::Heartbeat => (FrameKind::Heartbeat, Value::Null),
        };
        Self {
            stream_id,
            kind,
            seq,
            payload,
        }
    }

    /// The typed payload: `Ok(None)` for an unknown kind (skip it), `Err` (`bad_frame`) for a
    /// payload that does not fit its kind.
    pub fn body(&self) -> Result<Option<Body>, StreamError> {
        fn de<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T, StreamError> {
            T::deserialize(v)
                .map_err(|e| StreamError::new(ErrorCode::BadFrame, format!("bad payload: {e}")))
        }
        let p = &self.payload;
        Ok(Some(match self.kind {
            FrameKind::Control => Body::Control(de(p)?),
            FrameKind::Command => Body::Command(de(p)?),
            FrameKind::Result => Body::Result(de(p)?),
            FrameKind::Error => Body::Error(de(p)?),
            FrameKind::Output => Body::Output(de(p)?),
            FrameKind::Credit => Body::Credit(de(p)?),
            FrameKind::Close => Body::Close(if p.is_null() {
                Close::default()
            } else {
                de(p)?
            }),
            FrameKind::Heartbeat => Body::Heartbeat,
            FrameKind::Unknown => return Ok(None),
        }))
    }
}

/// `control` payloads, tagged by `type`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    /// Runner to Core, the first frame of a connection, on stream 0.
    Hello(RunnerHello),
    /// Core to runner: the hello is accepted.
    Welcome(CoreWelcome),
    /// A type from a newer peer: ignored. Never sent.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RunnerHello {
    /// `PROTOCOL_VERSION` of the runner; the Core refuses a major it does not speak.
    pub protocol: String,
    pub runner_version: String,
    /// What it can run. The Core sends only commands listed here.
    pub drivers: Vec<DriverInfo>,
    /// `macos`/`linux` and `aarch64`/`x86_64`, as Rust names them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
}

/// A driver a runner offers (`exec` now; `pty`, `harness` later).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DriverInfo {
    pub name: String,
    /// The command ops it takes, e.g. `noop`, `exec.run`.
    pub commands: Vec<String>,
    /// How many of its commands run at once; one more is answered `busy`.
    pub capacity: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CoreWelcome {
    /// The version the Core speaks on this connection.
    pub protocol: String,
}

/// Bytes on a stream (exec output later, terminal `out`/`in`), standard base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Output {
    pub data: String,
}

/// Flow control: the sender of this frame accepts `bytes` more `output` bytes on the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Credit {
    pub bytes: u64,
}

/// A stream given up. From the Core on a running command: cancel it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Close {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A command's failure, or (on stream 0) a connection's. `message` is human text, redacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StreamError {
    pub code: ErrorCode,
    pub message: String,
}

impl StreamError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Machine codes, snake_case like the client API's (handshake spec §14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// A frame or payload that does not parse, or a stream id that breaks the rules.
    BadFrame,
    /// The peer's protocol major is not one this side speaks.
    UnsupportedVersion,
    /// No advertised driver takes this command op.
    UnsupportedCommand,
    /// The command's arguments are refused (e.g. a relative `cwd`).
    InvalidArgs,
    /// The driver is at its advertised capacity; retry later.
    Busy,
    /// The program could not be started.
    SpawnFailed,
    /// The command was cancelled by a `close`.
    Cancelled,
    /// Anything else on the runner's side.
    Internal,
    /// A code from a newer peer. Never sent.
    #[serde(other)]
    Unknown,
}
