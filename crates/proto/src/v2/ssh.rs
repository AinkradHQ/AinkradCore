//! The `ssh` driver's ops (Leyline Y2-01, plan T1/T3/T4): the runner opens an SSH connection for the
//! Core, checks the host key against what the Core pinned, and runs one command to its end.
//!
//! The Core sends no key material: each hop names a secret `lease` the runner redeems itself, and the
//! runner drops the key once it has authenticated. Nothing here is ever passed to a local `ssh`
//! binary or shell; every field is data.

use serde::{Deserialize, Serialize};

use super::ExecLimits;

pub const OP_SSH_EXEC: &str = "ssh.exec";
/// Listed in the ssh driver's `commands` by a runner that opens interactive SSH terminals
/// (`PtyOpen.ssh`). Not an op: a runner without it would open a LOCAL shell for such a request, so
/// the Core must refuse to send one to a runner that does not list it.
pub const FEATURE_PTY_SSH: &str = "pty.ssh";

/// The most jump hosts in front of the target (plan T4); a longer chain is `invalid_args`.
pub const MAX_SSH_HOPS: usize = 3;

/// One machine on the path: where, as whom, which host keys are trusted, and which key to prove with.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshHop {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub user: String,
    /// Host keys the Core trusts for this machine, as `SHA256:<base64>` fingerprints (what
    /// `ssh-keygen -l` prints). A presented key not listed here ends the connection before any
    /// authentication: `host_key_unknown` when this list is empty, `host_key_changed` when not.
    #[serde(default)]
    pub pinned_keys: Vec<String>,
    /// A secret lease (`l_…`) for this hop's private key, redeemed by the runner, once.
    pub lease: String,
}

fn default_port() -> u16 {
    22
}

/// Not derived: a lease names a secret, and no log line or panic message should carry it.
impl std::fmt::Debug for SshHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshHop")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            .field("pinned_keys", &self.pinned_keys)
            .field("lease", &"[hidden]")
            .finish()
    }
}

/// Runs `run` on `target`, through `hops` (jump hosts, first to last), and answers with the exit and
/// output of the remote command: an `ExecResult` with `exec.run`'s limits, redaction and capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshExec {
    pub target: SshHop,
    /// At most `MAX_SSH_HOPS`.
    #[serde(default)]
    pub hops: Vec<SshHop>,
    /// The command line, given to the remote user's shell as the SSH `exec` request.
    pub run: String,
    #[serde(default)]
    pub limits: ExecLimits,
}

/// Which hop of an `ssh.exec` a host-key refusal is about, and the key it presented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostKeyEvidence {
    /// Index into `hops`; `hops.len()` is the target.
    pub hop: u8,
    /// `SHA256:<base64>` of the presented host key.
    pub fingerprint: String,
}

/// The machine an interactive SSH terminal (`PtyOpen::ssh`) reaches, through `hops` (first to last):
/// the same hops, pins and key leases as `ssh.exec`, and the same rules (at most `MAX_SSH_HOPS`).
/// The runner redeems the leases and passes the keys to `ssh-pty`; a password or keyboard-interactive
/// prompt is answered by the person typing in the terminal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshTerminal {
    pub target: SshHop,
    #[serde(default)]
    pub hops: Vec<SshHop>,
}

/// How `ainkrad-runner ssh-pty` ends (its exit code, visible as the terminal's exit): the remote
/// shell's own code, or one of these. `ssh-pty` maps a remote shell's own 70 to 72 to 1, so these
/// three can only come from `ssh-pty` itself, before a shell started. A host-key refusal
/// (70, 71) also hands the runner the hop and the fingerprint over a private descriptor, reported
/// as `TerminalExit::host_key`; nothing is read from the terminal's output.
pub const SSH_PTY_EXIT_HOST_KEY_UNKNOWN: i32 = 70;
pub const SSH_PTY_EXIT_HOST_KEY_CHANGED: i32 = 71;
pub const SSH_PTY_EXIT_AUTH_FAILED: i32 = 72;
/// Could not connect, the connection dropped, or the key handoff failed.
pub const SSH_PTY_EXIT_FAILED: i32 = 255;
