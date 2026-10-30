//! `ainkrad-ptyhost` (E2-02, E2-03, decision P2.3): one small detached process per terminal
//! that owns the PTY, its output ring and its screen, and serves them on a `0600` Unix socket,
//! so terminals outlive the runner (a restart, an upgrade, a crash) and the runner re-adopts
//! them on start.
//!
//! `pty` is the PTY and child (E2-02); `screen` the sink the emulator plugs into (E2-04);
//! `wire` the versioned host protocol; `host` the process's loop; `client` the runner's side.

pub mod client;
pub mod host;
pub mod pty;
pub mod screen;
pub mod wire;
