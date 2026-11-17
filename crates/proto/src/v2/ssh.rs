//! The `ssh` driver's ops (Leyline Y2-01, plan T1/T3/T4): the runner opens an SSH connection for the
//! Core, checks the host key against what the Core pinned, and runs one command to its end.
//!
//! The Core sends no key material: each hop names a secret `lease` the runner redeems itself, and the
//! runner drops the key once it has authenticated. Nothing here is ever passed to a local `ssh`
//! binary or shell; every field is data.

use serde::{Deserialize, Serialize};

use super::ExecLimits;

pub const OP_SSH_EXEC: &str = "ssh.exec";

/// The most jump hosts in front of the target (plan T4); a longer chain is `invalid_args`.
pub const MAX_SSH_HOPS: usize = 3;

/// One machine on the path: where, as whom, which host keys are trusted, and which key to prove with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
