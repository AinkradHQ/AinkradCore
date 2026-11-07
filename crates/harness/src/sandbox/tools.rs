//! The connection-tools slot of the bubblewrap sandbox (C4b): the session's own tools socket and
//! the runner executable that runs as the harness's stdio shim. Nothing else of the runner's state
//! is mounted: the socket's directory, every other session's socket and the state dir are not in
//! the sandbox's mount namespace, and the socket is a unix pathname one (no TCP, and an abstract
//! socket is not reachable from another network namespace in the first place). Unlike the MCP
//! and gateway slots it needs no network namespace and no loopback port, so it is bound whatever
//! `AINKRAD_SANDBOX_NETWORK` is.

use std::ffi::OsStr;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use tokio::process::Command;

use crate::Spec;
use crate::connections::{SLOT_FWD, SLOT_SOCK};

/// Adds the slot's binds when the session has one. A half-set slot, a socket that is not there or
/// not a socket, or a relative path refuses the sandbox: it is never run without what the harness's
/// config points at, nor with something else mounted in its place.
pub(super) fn bind<'a>(
    c: &mut Command,
    spec: &'a Spec,
    bound: &mut Vec<&'a OsStr>,
) -> io::Result<()> {
    let (sock, fwd) = (super::env(spec, SLOT_SOCK), super::env(spec, SLOT_FWD));
    if sock.is_empty() && fwd.is_empty() {
        return Ok(());
    }
    let is_socket = |p: &OsStr| {
        std::fs::symlink_metadata(Path::new(p)).is_ok_and(|m| m.file_type().is_socket())
    };
    if sock.is_empty()
        || fwd.is_empty()
        || !Path::new(sock).is_absolute()
        || !Path::new(fwd).is_absolute()
        || !is_socket(sock)
        || !Path::new(fwd).is_file()
    {
        return Err(io::Error::other(
            "the connection tools slot needs the session's socket and the runner executable",
        ));
    }
    c.arg("--bind").arg(sock).arg(sock);
    if !bound.contains(&fwd) {
        c.arg("--ro-bind").arg(fwd).arg(fwd);
        bound.push(fwd);
    }
    Ok(())
}
