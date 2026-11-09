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
use std::path::{Path, PathBuf};

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

/// The slot's binds and the check that follows them, in one call for the sandbox builder.
pub(super) fn apply<'a>(
    c: &mut Command,
    spec: &'a Spec,
    bound: &mut Vec<&'a OsStr>,
) -> io::Result<()> {
    bind(c, spec, bound)?;
    only_own_sockets(c, spec)
}

/// `path` with every symlink resolved. A tail that does not exist yet (a state dir with no `agents/`
/// made so far) is kept as written after its longest existing ancestor is resolved; a `..` in that
/// tail cannot be judged, and refuses.
fn resolve(path: &Path) -> io::Result<PathBuf> {
    let mut tail: Vec<&OsStr> = Vec::new();
    let mut at = path;
    loop {
        match at.canonicalize() {
            Ok(mut real) => {
                real.extend(tail.iter().rev());
                return Ok(real);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let (Some(name), Some(up)) = (at.file_name(), at.parent()) else {
                    return Err(e);
                };
                tail.push(name);
                at = up;
            }
            Err(e) => return Err(e),
        }
    }
}

fn refused() -> io::Error {
    io::Error::other("a sandbox path would expose the sockets of other sessions")
}

/// Refuses the sandbox when a bind could hand it another session's sockets (tools or gateway) in the
/// runner's `agents/` dir: a bound path that is, or contains, the agents dir (a harness binary kept
/// in a folder that holds the state dir: `program_dirs` binds that folder whole, and a read-only bind
/// does not stop `connect()` on a unix socket), or one inside it but outside this session's own
/// directory. `c` holds every bind by now; the session's own socket files and the shim are exempt.
/// The agents dir is `<AINKRAD_SANDBOX_STATE>/agents`, else the one above the tools socket's
/// directory (the gateway socket's layout is not assumed). Every path is compared with its symlinks
/// resolved (a state path given through a symlink or with `..`, a harness folder that is a symlink),
/// (a path that does not exist yet keeps its tail, as `resolve` says), and a path that cannot be
/// resolved at all refuses the sandbox. It is the same builder the start-up
/// self-test uses, so a layout that fails here also leaves the capability off.
fn only_own_sockets(c: &Command, spec: &Spec) -> io::Result<()> {
    let socks: Vec<&Path> = ["AINKRAD_SANDBOX_TOOLS_SOCK", "AINKRAD_SANDBOX_GW_SOCK"]
        .iter()
        .map(|k| Path::new(super::env(spec, k)))
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    let state = super::env(spec, "AINKRAD_SANDBOX_STATE");
    let agents = if !state.is_empty() {
        resolve(&Path::new(state).join("agents"))?
    } else if let Some(own) = Some(Path::new(super::env(spec, SLOT_SOCK)))
        .filter(|s| !s.as_os_str().is_empty())
        .and_then(|s| s.parent().and_then(Path::parent))
    {
        // Without the state dir the layout is the tools socket's: `<agents>/<session>/tools.sock`.
        resolve(own)?
    } else {
        return Ok(());
    };
    let real = |p: &Path| resolve(p).map_err(|_| refused());
    let sockets = socks
        .iter()
        .map(|s| real(s))
        .collect::<io::Result<Vec<_>>>()?;
    let owns: Vec<&Path> = sockets.iter().filter_map(|s| s.parent()).collect();
    let fwd_arg = super::env(spec, SLOT_FWD);
    let fwd = if fwd_arg.is_empty() {
        None
    } else {
        Some(real(Path::new(fwd_arg))?)
    };
    let args: Vec<&OsStr> = c.as_std().get_args().collect();
    for pair in args.windows(2) {
        if pair[0] != "--bind" && pair[0] != "--ro-bind" {
            continue;
        }
        let src = real(Path::new(pair[1]))?;
        if sockets.contains(&src) || fwd.as_ref() == Some(&src) {
            continue;
        }
        let holds = agents.starts_with(&src);
        let inside_other = src.starts_with(&agents) && !owns.iter().any(|o| src.starts_with(o));
        if holds || inside_other {
            return Err(refused());
        }
    }
    Ok(())
}
