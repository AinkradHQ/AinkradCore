//! Agent sessions on runners (E2-08, P2.7): the `agent` driver's ops.
//!
//! A session is owned by the runner's agent driver, keyed by the Core's session id, not by a
//! command stream: a stream is only one request about it. So a Core restart, or a runner
//! reconnect, never touches a running harness.
//!
//! - `agent.start` starts (or, for a session it already holds, confirms) a harness in a session,
//!   with the leases of the secrets it gets (E2-07.2): the runner redeems each itself, once.
//!   `resume` names the harness's own session to continue (after a runner restart).
//! - `agent.read` is a long poll on the session's transcript: entries after `after`, waiting up
//!   to `wait_ms` for the first one. Every entry has its own per-session `seq`, assigned by the
//!   runner, so the Core persists each once and asks again from where its store ends: no gap,
//!   whatever frames or connections were lost. `after` also acknowledges what the Core holds.
//! - `agent.send` (a message), `agent.decide` (a tool approval) and `agent.stop` (cancel, or
//!   kill) are short commands.
//!
//! Capacity: the driver's `capacity` is how many sessions run at once, `slots` splits it per
//! harness, and `streams` is how many of its commands may be in flight (reads included), which
//! the hub counts per driver. A `waiting` session still holds its slot.
//!
//! A live session (`AgentStart::live`, `CAP_LIVE`) is one conversation: after each answer it is
//! `waiting` (a `waiting` transcript entry marks the boundary, after the harness's own
//! `turn_ended`), `agent.send` is the next message (queued if an answer is still running), and
//! it ends only on `agent.stop` or when the harness exits by itself. A harness process that is
//! gone (a crash) is started again with the harness's own resume at the next message.

use super::subscription::is_subscription_secret;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::runner::{Outcome, Policy, Tokens, Workspace};

pub const AGENT_DRIVER: &str = "agent";
pub const OP_AGENT_START: &str = "agent.start";
pub const OP_AGENT_READ: &str = "agent.read";
pub const OP_AGENT_SEND: &str = "agent.send";
pub const OP_AGENT_DECIDE: &str = "agent.decide";
pub const OP_AGENT_STOP: &str = "agent.stop";

/// The command an agent driver lists when it keeps a session's harness alive between answers: an
/// `agent.start` with `live` then runs one conversation (state `waiting` after each answer, each
/// `agent.send` is the next message, `agent.stop` with `turn` stops only the running answer). A
/// runner that does not list it ends a session at its first answer, as before.
pub const CAP_LIVE: &str = "live";

/// Every op of the `agent` driver.
pub const AGENT_OPS: [&str; 5] = [
    OP_AGENT_START,
    OP_AGENT_READ,
    OP_AGENT_SEND,
    OP_AGENT_DECIDE,
    OP_AGENT_STOP,
];

/// Variables a secret may not take: the ones that steer how programs are found and loaded.
const RESERVED_VARS: &[&str] = &["PATH", "HOME", "SHELL", "USER", "LOGNAME", "TMPDIR", "IFS"];

/// The variable a module's run token is delivered under; a client session may not name it.
pub const RUN_TOKEN_VAR: &str = "CITADEL_RUN_TOKEN";

/// A variable a secret may be delivered under: `[A-Z_][A-Z0-9_]{0,63}`, not one the runner
/// sets itself, not a loader's (`LD_*`, `DYLD_*`).
pub fn valid_secret_var(var: &str) -> bool {
    let b = var.as_bytes();
    (1..=64).contains(&b.len())
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
        && !RESERVED_VARS.contains(&var)
        && !var.starts_with("AINKRAD_")
        && !matches!(var, "BASH_ENV" | "ENV" | "NODE_OPTIONS" | "PYTHONPATH")
        && !var.starts_with("LD_")
        && !var.starts_with("DYLD_")
}

/// A file secret's name on the runner: `[A-Za-z0-9._-]{1,64}`, never `.` or `..` (it becomes a
/// path component under the session's secrets dir, so no separator can be in it).
pub fn valid_secret_file_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// A `.env` bundle's `NAME=value` pairs: one per line, blank lines and `#` comments skipped, one
/// pair of matching quotes around a value stripped. Every name passes [`valid_secret_var`]; a
/// bundle with no pair, or a line that is none, is an error (a line number, never the text).
pub fn parse_env_bundle(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("line {} is not NAME=value", i + 1));
        };
        let k = k.trim();
        if !valid_secret_var(k) {
            return Err(format!(
                "line {}: {k:?} is not an allowed variable name",
                i + 1
            ));
        }
        let v = v.trim();
        let v = ["\"", "'"]
            .iter()
            .find_map(|q| v.strip_prefix(q)?.strip_suffix(q))
            .unwrap_or(v);
        out.push((k.to_owned(), v.to_owned()));
    }
    match out.is_empty() {
        true => Err("the bundle has no NAME=value line".to_owned()),
        false => Ok(out),
    }
}

/// Names under this prefix are provider-account secrets: `acct.<provider>.<label>`.
pub const ACCOUNT_PREFIX: &str = "acct.";

/// The variables a harness authenticates with: the ONLY ones a provider-account secret may be
/// delivered under for it. A harness not listed takes no account secret at all. The runner
/// crate's tests keep this equal to `ainkrad_harness::auth_env`.
pub fn account_vars(harness: &str) -> &'static [&'static str] {
    match harness {
        "claude" => &["CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"],
        "codex" => &["CODEX_API_KEY", "OPENAI_API_KEY"],
        "agy" => &["GEMINI_API_KEY"],
        _ => &[],
    }
}

/// The provider whose account secrets a harness may carry (`acct.<provider>.<label>`). A harness
/// not listed takes none.
pub fn harness_provider(harness: &str) -> Option<&'static str> {
    match harness {
        "claude" => Some("anthropic"),
        "codex" => Some("openai"),
        "agy" => Some("google"),
        _ => None,
    }
}

/// The provider an account secret's name carries: `acct.<provider>.<label>` gives `<provider>`.
pub fn account_provider(name: &str) -> Option<&str> {
    name.strip_prefix(ACCOUNT_PREFIX)?.split('.').next()
}

/// Whether a variable can point a program at another endpoint or another trust root: a proxy, a
/// base URL, an endpoint, a certificate bundle. A session holding an account secret may not be
/// given one by any other secret either, or the key could be steered to a server of the
/// creator's choice.
pub fn redirects_traffic(var: &str) -> bool {
    const SUFFIXES: [&str; 6] = [
        "_PROXY",
        "_BASE_URL",
        "_API_BASE",
        "_API_URL",
        "_ENDPOINT",
        "_CA_BUNDLE",
    ];
    SUFFIXES.iter().any(|s| var.ends_with(s))
        || var.starts_with("PROXY")
        || matches!(
            var,
            "SSL_CERT_FILE"
                | "SSL_CERT_DIR"
                | "NODE_EXTRA_CA_CERTS"
                | "NODE_TLS_REJECT_UNAUTHORIZED"
                | "GIT_SSL_NO_VERIFY"
                | "GIT_SSL_CAINFO"
        )
}

/// Why a session of `harness` holding `grants` (each a secret's name and the variable it is
/// delivered under) may not run, when one of them is a provider-account secret: it sits in a
/// variable the harness does not authenticate with, or any grant could redirect traffic.
/// `None` for a session with no account secret. The one rule the Core's broker and the
/// runner both apply, so they cannot drift.
pub fn account_var_problem<'a>(
    harness: &str,
    grants: impl IntoIterator<Item = (&'a str, &'a str)> + Clone,
) -> Option<&'static str> {
    let allowed = account_vars(harness);
    // An ordinary secret may not take a harness authentication variable either: it would carry a
    // credential past every rule below.
    if !grants
        .clone()
        .into_iter()
        .any(|(name, var)| name.starts_with(ACCOUNT_PREFIX) || allowed.contains(&var))
    {
        return None;
    }
    let provider = harness_provider(harness);
    for (name, var) in grants {
        if !name.starts_with(ACCOUNT_PREFIX) && allowed.contains(&var) {
            return Some(
                "a harness authentication variable carries only a provider-account secret \
                 (acct.<provider>.<id>)",
            );
        }
        // A subscription's token has its own rule (`subscription_problem`); a variable that
        // redirects traffic is still refused beside it.
        if name.starts_with(ACCOUNT_PREFIX)
            && !is_subscription_secret(name)
            && (provider.is_none() || account_provider(name) != provider)
        {
            return Some(
                "a provider-account secret may only be used by its own provider's harness \
                 (anthropic: claude, openai: codex, google: agy)",
            );
        }
        if name.starts_with(ACCOUNT_PREFIX) && !allowed.contains(&var) {
            return Some(
                "a provider-account secret may only be delivered under one of its harness's own \
                 authentication variables (see account_vars)",
            );
        }
        if redirects_traffic(var) {
            return Some(
                "a session holding a provider-account secret may not set a proxy, base URL, \
                 endpoint or certificate variable: it could redirect the key",
            );
        }
    }
    None
}

/// A session id: `as_` and a lowercase alphanumeric tail, at most 64 bytes in all.
pub fn valid_session_id(id: &str) -> bool {
    id.len() <= 64
        && id.strip_prefix("as_").is_some_and(|t| {
            !t.is_empty()
                && t.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

/// What a runner answers for a session it does not hold (`invalid_args`).
pub const NO_SESSION: &str = "no such session on this runner";

/// Core to runner: run `harness` in session `session`.
#[derive(Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentStart {
    /// The Core's id, `as_…`.
    pub session: String,
    pub harness: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// The repo and worktree to work in; absent, a scratch dir of the session's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<Workspace>,
    #[serde(default)]
    pub policy: Policy,
    /// The harness's own session to continue (`AgentEvents::harness_session`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<String>,
    /// Leases the runner redeems for this session, once each. Never logged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretGrant>,
    /// The API key the runner's gateway serves this session (KAN-435); sent only to a runner
    /// that lists the `gateway` command. Never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<Box<super::GatewayGrant>>,
    /// Which resume this is, 0 for the first start. A session that has ended is started again
    /// (a wake) only by a `resume` whose `epoch` is newer than the one it last ran under; the
    /// same one again is a resent start and is answered, never run twice.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub epoch: u32,
    /// One live conversation (`CAP_LIVE`): the harness stays up after an answer and the session
    /// is `waiting` until the next `agent.send`; it ends only on `agent.stop` or when the CLI
    /// exits by itself. A resume (`resume`) of a live session starts no turn: it waits for the
    /// next message, which restarts the harness with its own resume. Without it the session
    /// ends with its first answer.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub live: bool,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// No `Debug` on anything carrying a lease (secrets review L4).
impl std::fmt::Debug for AgentStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentStart")
            .field("session", &self.session)
            .field("harness", &self.harness)
            .field("secrets", &self.secrets.len())
            .field("gateway", &self.gateway.is_some())
            .finish_non_exhaustive()
    }
}

/// One secret for a session: its lease, and the variable it is delivered under.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SecretGrant {
    /// `l_…`, redeemable once, by this runner only.
    pub lease: String,
    /// The environment variable: the value itself (`env`), the file's path (`file`), or the
    /// askpass helper's path (`askpass`, also set as `GIT_ASKPASS`). `[A-Z_][A-Z0-9_]*`.
    pub var: String,
}

/// Core to runner: the transcript after `after`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentRead {
    pub session: String,
    /// The last `seq` the Core holds (0 for none): entries above it are sent, those at or below
    /// it may be dropped by the runner.
    pub after: u64,
    /// How long to wait for a first entry; absent or 0 answers at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<u64>,
    /// The last `gw_seq` the Core holds (0 for none): gateway reports above it are sent, those at
    /// or below it may be dropped by the runner (KAN-435).
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub gw_after: u64,
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentSend {
    pub session: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentDecide {
    pub session: String,
    /// The `id` of the transcript's `approval_request`.
    pub request: String,
    pub approved: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentStop {
    pub session: String,
    /// Kill the harness now; otherwise let its tool call in flight finish, then end it.
    #[serde(default)]
    pub kill: bool,
    /// Only a live session's running answer is stopped (like Esc in the CLI): the session goes
    /// on, `waiting`. A runner that lists `CAP_LIVE` honours it; the Core sends it to no other.
    /// Nothing happens when no answer runs. Overrides `kill`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub turn: bool,
}

/// Where a session is, as its runner sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    Running,
    /// A live session (`AgentStart::live`) whose harness finished its answer and waits for the
    /// next `agent.send`. It still holds its slot. A runner sends it only for a live session.
    Waiting,
    /// Its harness ended (`outcome`).
    Ended,
    /// Its harness went with a runner restart; the transcript is kept. The Core resumes it.
    Interrupted,
    /// A state from a newer runner. Never sent.
    #[serde(other)]
    Unknown,
}

/// One transcript entry: redacted by the runner before it is kept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscriptEntry {
    /// From 1, by one, per session.
    pub seq: u64,
    /// Unix milliseconds.
    pub at: i64,
    /// The harness event, or the driver's own (`approval_request`, `gap`, `ended`, …).
    #[schemars(with = "Value")]
    pub body: Value,
}

/// Runner to Core: a session's state, and (for `agent.read`) its entries after `after`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentEvents {
    pub session: String,
    pub state: AgentState,
    /// The newest `seq` the session has.
    pub last_seq: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<TranscriptEntry>,
    /// The harness's own session id, once known: what a resume continues.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Tokens>,
    /// Once `ended`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    /// What the session's auth gateway reported after `AgentRead::gw_after` (KAN-435). A channel
    /// of its own, never the transcript: only the gateway task writes it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateway: Vec<super::GatewayReport>,
    /// The harness's latest plan-limit event (KAN-436), a snapshot that each newer one replaces.
    /// Sent only by a runner that lists `CAP_PLAN_LIMIT`. The agent can influence it (its tools can
    /// forge the harness's own output), so it is a hint: cool an account from it, never disable one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_limit: Option<super::PlanLimit>,
}

#[cfg(test)]
mod bundle_tests {
    use super::*;

    #[test]
    fn an_env_bundle_parses_lines_and_refuses_the_rest() {
        let got = parse_env_bundle("# c\nA=1\n B = \"two words\" \nC='x'\nD=\n").unwrap();
        let want = [("A", "1"), ("B", "two words"), ("C", "x"), ("D", "")];
        assert_eq!(
            got.iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<Vec<_>>(),
            want
        );
        for bad in [
            "",
            "# only\n",
            "x",
            "a=1",
            "PATH=/bin",
            "LD_PRELOAD=x",
            "OK=1\nbroken",
        ] {
            assert!(parse_env_bundle(bad).is_err(), "{bad:?}");
        }
        assert!(
            parse_env_bundle("PATH=/bin")
                .unwrap_err()
                .find("/bin")
                .is_none()
        );
    }

    #[test]
    fn a_file_name_is_one_plain_component() {
        for ok in ["a", ".env", "svc.json", "AuthKey_X1.p8"] {
            assert!(valid_secret_file_name(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "a b", "é", &"x".repeat(65)] {
            assert!(!valid_secret_file_name(bad), "{bad}");
        }
    }
}
