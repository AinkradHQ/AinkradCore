//! Terminals (E2-01.2): the contract, ahead of the Core's terminal service (E2-05). A terminal
//! lives on a runner that advertised the `pty` driver, in a detached host process that outlives
//! clients, the Core and the runner (E2-03); its frames are the runner protocol's
//! (`ainkrad_proto::v2::terminal`).
//!
//! - Opening and attaching need `terminal` **and** a live step-up (`scopes::DESTRUCTIVE`);
//!   signalling and closing need `terminal`; listing and reading need only `read`.
//! - Input, resize and detach travel on the attach socket, not as routes.
//! - Events `terminal.opened`, `.attached`, `.detached`, `.exited`, `.closed` (scope
//!   `terminal`) carry who, where and when, never content (P2.11).
//!
//! ponytail: every handler answers 501 `not_implemented` until E2-05 wires them to the hub;
//! the shapes are fixed now so clients can be generated against them.

// The shapes are read and built by the terminal service (E2-05); until then only the contract uses them.
#![allow(dead_code)]

use std::collections::BTreeMap;

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::ApiError;
use super::types::Timestamp;

/// A terminal's size in cells, each 1 to 1000.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub struct TerminalSize {
    pub rows: u16,
    pub cols: u16,
}

/// Where a terminal is in its life.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TerminalStatus {
    Created,
    Running,
    Exited,
    Reaped,
}

/// A terminal on a runner.
#[derive(Debug, Serialize, ToSchema)]
pub struct Terminal {
    /// `t_…`.
    pub id: String,
    /// The runner's device id, `d_…`.
    pub runner: String,
    pub status: TerminalStatus,
    pub size: Option<TerminalSize>,
    /// Output bytes so far: where an attach resumes.
    pub seq: Option<u64>,
    /// The device that opened it, `d_…`.
    pub opened_by: Option<String>,
    pub created_at: Option<Timestamp>,
    /// Once it exited: its code, absent when a signal ended it.
    pub exit_code: Option<i32>,
    /// The signal that ended it, if one did.
    pub exit_signal: Option<String>,
    /// Clients attached now.
    pub attached: Option<u32>,
}

/// `createTerminal`'s body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewTerminal {
    /// The runner's device id, `d_…`; it must advertise the `pty` driver.
    pub runner: String,
    /// Absent: the user's login shell.
    pub program: Option<String>,
    pub args: Option<Vec<String>>,
    /// An absolute directory; absent, the user's home.
    pub cwd: Option<String>,
    /// Variables set as given; the rest of the environment is the runner's allow-list.
    pub env: Option<BTreeMap<String, String>>,
    pub size: TerminalSize,
}

/// `signalTerminal`'s body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TerminalSignal {
    /// `HUP`, `INT`, `QUIT`, `TERM`, `KILL`, `USR1`, `USR2`, `CONT`, `STOP`, `TSTP` or `WINCH`.
    pub signal: String,
}

fn not_yet() -> Response {
    ApiError::new(
        StatusCode::NOT_IMPLEMENTED,
        "not_implemented",
        "terminals are not served by this Core yet",
    )
    .into_response()
}

#[utoipa::path(post, path = "/api/v1/terminals", operation_id = "createTerminal",
    tag = "terminals", request_body = NewTerminal,
    responses((status = 201, description = "The terminal is open on its runner (audited and \
        `terminal.opened`). 409 `runner_offline` or `unsupported_command` (no `pty` driver), \
        503 `runner_busy`, 501 `not_implemented` before the terminal service", body = Terminal)))]
pub async fn create(Json(_): Json<NewTerminal>) -> Response {
    not_yet()
}

#[utoipa::path(get, path = "/api/v1/terminals", operation_id = "listTerminals", tag = "terminals",
    responses((status = 200, description = "Every terminal the Core knows of, live or exited \
        and not yet reaped", body = Vec<Terminal>)))]
pub async fn list() -> Response {
    not_yet()
}

#[utoipa::path(get, path = "/api/v1/terminals/{id}", operation_id = "getTerminal",
    tag = "terminals",
    params(("id" = String, Path, description = "The terminal, `t_…`")),
    responses((status = 200, description = "One terminal", body = Terminal)))]
pub async fn get() -> Response {
    not_yet()
}

#[utoipa::path(delete, path = "/api/v1/terminals/{id}", operation_id = "closeTerminal",
    tag = "terminals",
    params(("id" = String, Path, description = "The terminal, `t_…`")),
    responses((status = 200, description = "Hung up (HUP, then TERM, then KILL to its process \
        group) and reaped; its exit. Audited and `terminal.closed`", body = Terminal)))]
pub async fn close() -> Response {
    not_yet()
}

#[utoipa::path(post, path = "/api/v1/terminals/{id}/signal", operation_id = "signalTerminal",
    tag = "terminals", request_body = TerminalSignal,
    params(("id" = String, Path, description = "The terminal, `t_…`")),
    responses((status = 204, description = "Delivered to the terminal's process group")))]
pub async fn signal(Json(_): Json<TerminalSignal>) -> Response {
    not_yet()
}

#[utoipa::path(get, path = "/api/v1/terminals/{id}/ws", operation_id = "attachTerminal",
    tag = "terminals",
    params(("id" = String, Path, description = "The terminal, `t_…`"),
        ("after" = Option<i64>, Query, description = "Resume output at this byte offset \
            (`Terminal.seq` of an earlier attach); absent or older than the runner keeps: a \
            `snapshot` first"),
        ("Sec-WebSocket-Protocol" = Option<String>, Header,
            description = "A browser: `ainkrad.v1, ainkrad-ticket.<ticket>`, as for streamEvents")),
    responses((status = 101, description = "Switching to a WebSocket that carries the runner \
        protocol's terminal frames (`Frame` in runner.schema.json, stream 0): the server sends \
        `control` `opened`, `output` (out), `control` `snapshot`, `result` (exit); the client \
        sends `output` (in), `control` `resize` and `signal`, and `credit` (it starts with \
        65536 bytes of output and grants more as it renders). Closing the socket detaches; \
        the terminal keeps running. Input and resize follow the arbitration rules (every \
        attached client sees output; the most recent typist sets the size). A client that \
        falls behind is cut to a fresh snapshot. Closed with 4001 (device revoked), 4003 \
        (scopes changed)")))]
pub async fn attach() -> Response {
    not_yet()
}
