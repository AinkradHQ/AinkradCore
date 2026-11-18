//! The `ssh` driver's agent ops (Leyline Y6-01, plan T7): a short-lived, host-bound ssh-agent that
//! lives in the runner (the user's Mac runner) so `ssh`, `scp` and editors on that machine can reach
//! ONE host, and its jump hops, without a key file anywhere.
//!
//! The Core sends no key: each entry names a secret `lease` the runner redeems itself, and the runner
//! keeps the key in memory only. The agent signs for a key only inside an ssh session whose host key
//! is one the Core pinned for that key's own host (`session-bind@openssh.com`), until `ttl_secs`
//! pass or the Core drops it.

use serde::{Deserialize, Serialize};

pub const OP_SSH_AGENT_LOAD: &str = "ssh.agent.load";
pub const OP_SSH_AGENT_DROP: &str = "ssh.agent.drop";

/// A lease lasts at most this long (12 h, plan T7); the default the Core asks for is 1 h.
pub const SSH_AGENT_MAX_TTL_SECS: u32 = 12 * 3600;
/// The target and at most `MAX_SSH_HOPS` jump hosts.
pub const SSH_AGENT_MAX_KEYS: usize = super::MAX_SSH_HOPS + 1;

/// One key of the lease: the secret lease to redeem and the host keys of the machine it logs in to.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentKey {
    /// A secret lease (`l_...`) for the private key, redeemed by the runner, once.
    pub lease: String,
    /// `SHA256:<base64>` fingerprints of the host keys this key may sign for: the pins of the one
    /// machine it logs in to. Never empty (a key with nothing pinned could sign for anyone).
    pub pinned_keys: Vec<String>,
}

/// Not derived: a lease names a secret, and no log line or panic message should carry it.
impl std::fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKey")
            .field("lease", &"[hidden]")
            .field("pinned_keys", &self.pinned_keys)
            .finish()
    }
}

/// Starts an agent on the runner under `id` (the Core's name for it): the keys are redeemed, a socket
/// opens in a 0700 directory of the runner's own temporary directory, and the agent answers
/// `SshAgentLoaded`. It ends at `ttl_secs`, on `ssh.agent.drop`, or when the runner has been cut off
/// from the Core for 5 minutes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshAgentLoad {
    /// `[A-Za-z0-9_]`, 1 to 64 characters.
    pub id: String,
    /// 1 to `SSH_AGENT_MAX_TTL_SECS`.
    pub ttl_secs: u32,
    /// 1 to `SSH_AGENT_MAX_KEYS`.
    pub keys: Vec<AgentKey>,
}

/// Where the agent listens, for the person's `ssh`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshAgentLoaded {
    /// The agent socket (`SSH_AUTH_SOCK`).
    pub socket: String,
    /// An `ssh_config` beside the socket: `IdentityAgent`, a private `UserKnownHostsFile`, public-key
    /// authentication only, no agent forwarding. `ssh -F <config> ...` is the whole ready command.
    pub config: String,
}

/// Ends the agent `id`: the listener and every connection close and the keys are wiped, before the
/// answer. Dropping an id that is not live (ended, never loaded) is not an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshAgentDrop {
    pub id: String,
}

/// What the agent did before it ended.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SshAgentDropped {
    /// The agent was live when the drop arrived (not already over).
    pub was_live: bool,
    /// Signatures made.
    pub signatures: u64,
    /// Sign requests refused (unbound session, unpinned host, expired, wrong data).
    pub refused: u64,
}

/// The two agent ops, and nothing else: what the Core's one entry for them takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshAgentCommand {
    Load(SshAgentLoad),
    Drop(SshAgentDrop),
}

impl From<SshAgentCommand> for super::Command {
    fn from(c: SshAgentCommand) -> Self {
        match c {
            SshAgentCommand::Load(l) => Self::SshAgentLoad(l),
            SshAgentCommand::Drop(d) => Self::SshAgentDrop(d),
        }
    }
}
