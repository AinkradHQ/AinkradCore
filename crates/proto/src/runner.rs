//! The runner protocol (E3.1, brainstorm §3): a runner dials out to
//! `GET /runner/v1/connect` over WebSocket, authenticated by `Authorization: Bearer <runner
//! key>`, and the two sides exchange one JSON message per text frame, tagged by `type`.
//!
//! A session: the runner sends `Hello` (protocol version, tags, harness versions, and the
//! runs it is still working on after a reconnect); the server answers `Welcome`, renews the
//! leases of those runs, and sends `Cancel` for any it no longer holds. `Ready` asks for one
//! run; the server answers `Assign` when one is due. Once the harness is up, the runner
//! sends `RunStarted`; the server starts the run, which mints its token, and sends it in
//! `Token`. So a token exists only for a run that really started, and it travels in one
//! message, never in an `Assign` or a URL. `Heartbeat` renews a lease every `lease_ttl_secs
//! / 3`; `RunEvent` streams the transcript; `RunEnded` ends the run, answered by `Ack`.
//! `Error` reports a refused message; with a `run`, the server has given up on that run.
//!
//! Workspaces (E3.7): an `Assign` for an issue of a project with a repo carries a
//! `Workspace`, which the runner keeps as a git worktree per issue and reuses on later runs.
//! Each `Ready` lists the issues whose worktrees it holds; the server answers `Prune` with
//! those that are done, cancelled or gone, and the runner removes them.
//!
//! Token caps (E3.8): `Assign.token_cap` is the run's cap; the runner stops the harness when
//! the run's tokens reach it and ends the run `TokenCap`. `RunUsage` reports the run's
//! running totals while it works, so spend is visible mid-run, with the harness's own cost
//! when it reports one (1.6, E7.3).
//!
//! Permissions (E3.10): `Assign.policy` is the project's harness permission policy (1.3); the
//! default asks. A tool call outside it becomes `ApprovalRequest`, which the server turns into
//! a `permission_escalation` approval; the run waits for `Approval` (or a timeout, which
//! denies, and which the request carries so the server expires it in step, 1.5), and the answer
//! goes back to the harness.
//!
//! Pushes (E9.1): a workspace marked `push` (1.7) has its branch pushed to the repo's origin
//! when the run ends, with the runner's own git credentials, so a PR can be opened from it.
//! The outcome is a transcript chunk: `branch_pushed`, `branch_unchanged` or `push_failed`.
//! Since 1.23 a `push_failed` says why: `reason` (the remote's and git's words, credentials cut
//! out, capped), `rejected` (`[{ref, reason}]`, each ref the remote refused), `sha` (the head
//! it tried) and `workflow_files` (the `.github/workflows` files the branch changes); the
//! server comments it on the issue, holds the issue's PR request and, for a token refused a
//! workflow change, opens a `workflow_push` approval.
//!
//! Accounts (E15.1): `Assign.account` (1.8) names the provider account the server picked for
//! the run: its config dir under the runner's config root, and where its token lives on the
//! runner host (`credential_ref`, under the runner's credentials dir). The runner reads the
//! file when the run starts; the secret itself never travels.
//!
//! Fallbacks (E15.3): `Assign.fallbacks` (1.9) is the rest of the agent's ordered (harness,
//! model) chain this runner can work, each with the account the server picked for it. When a
//! turn fails because the model is unavailable, rate-limited or out of quota, the runner
//! moves the run to the next entry and says so in `RunFallback` (resent after a reconnect,
//! applied once); the run records the model it used and every reason. With the chain spent,
//! the run fails with all the reasons.
//!
//! Provider drops (E15.4): a turn the provider dropped is resumed in the same session inside
//! the run; each drop is reported in `ProviderDrop` (1.10) and counted against the run's
//! account, which turns `unhealthy` after too many in a window.
//!
//! Limits (E15.17): `Assign.limits` (1.11) carries the server's settings for the run (how long
//! an escalation waits, how often and how slowly a dropped session is resumed), resolved for
//! the run's project and this runner, so the runner hardcodes none of them. Absent from an older
//! server: the runner's defaults.
//!
//! Fresh context (E15.5): every run starts a new harness session. `Assign.resume_session` (1.12)
//! names one to continue instead, sent only when the server's settings allow it and the
//! agent's previous run on the issue ended unfinished on the same harness.
//!
//! Warm harnesses (E15.6): `RunLimits.warm_max` (1.13) is how many idle long-lived harness
//! servers (OpenCode `serve`, Codex `app-server`) the runner keeps; a later run of the same
//! agent, harness, config and environment opens a new session on one instead of starting a
//! process.
//!
//! Progress (E15.7): `Progress` (1.14) says the run is getting somewhere (a tool call, a file
//! change, a new message, more tokens), unlike `Heartbeat` (its process is alive), with the
//! files its worktree differs from its base in. Past `RunLimits.stall_after_secs` without
//! progress, the runner stops the run and ends it `Stalled`.
//!
//! Disk (E15.9): `Welcome.limits` (1.15) carries the runner's disk settings (`RunnerLimits`):
//! its cap, when eviction starts, how long a worktree may sit idle, how long a warm harness
//! may. The runner reports its disk use (`DiskReport`) in `Hello` and in `Disk` after each
//! clean-up pass; a report that is `full` (over the cap, nothing left to evict) is the admin's.
//!
//! Multi-repo (E15.16): an issue touching several repos has the first as `Assign.workspace` and
//! the rest in its `also` (1.16), each named; the runner keeps a worktree per repo at
//! `<issue dir>/<name>`, all on the issue's one branch.
//!
//! Artifacts (E15.12): `ReadFile` (1.17) asks for a file of a run's worktree an agent published
//! by path; the runner refuses a path that leaves the worktree or a file over `max_bytes`
//! (checked before reading) and answers `FileRead` with the content (base64) or why not.
//!
//! Tool results (1.18): every tool call's end is a `tool_result` transcript chunk (`RunEvent`):
//! the call's `id` and `name`, `status` (`ok` or `error`), its `exit_code` when the harness gives
//! one, its `output` cut to `RunLimits.tool_output_bytes` (head and tail) with the full size in
//! `output_bytes`, and `duration_ms` since its `tool_use`; redacted like every chunk. `Progress`
//! also carries each repo's diff against its base (`repos`, `RepoDiff`).
//!
//! Controls (1.19, decision #34): `Pause` lets the run's tool call in flight finish, then stops
//! its turn and ends it `Cancelled` ("paused by admin"); a hard stop is `Cancel`. `Message` is
//! the admin's message for the run's harness, given to it as its next turn (the run keeps
//! going); the runner says it did with a `user_message` transcript chunk naming the message's
//! `id`. A message the run ends before taking becomes a comment on its issue (server side).
//!
//! Runner state (1.20): `Hello` and `Status` carry a `RunnerInfo` (how many runs it works at
//! once, how long it has been up, its harness logins, its last sleep, the Power Nap preference
//! it holds); `Status` goes after every clean-up pass. `ReadLog` asks for the tail of its own
//! log, answered by `LogTail`, redacted. `Welcome.power_nap` and `Prefs` carry the admin's
//! Power Nap preference for it, which it records. `RunLimits.fallback_on_*` say which failure
//! classes move a run along its fallback chain (absent: all of them).
//!
//! Harness versions (1.21): a harness version is no longer matched exactly. One at or above
//! its adapter's minimum and not known bad gets work, an untested newer one too unless the
//! server's `harness.allow_untested_newer` is 0 (`ainkrad_harness::compat`). A turn a newer
//! CLI breaks fails with a `<harness>:protocol` fingerprint, the `protocol` failure class,
//! which falls back along the chain.
//!
//! Agent context (E4.2): `Assign` carries the issue's key and the run's rendered skills (1.4).
//! Everything else the agent reads and writes through the Citadel MCP server at `/mcp/v1`,
//! authenticated by the run token.
//!
//! Run prompts (1.22): `Assign.prompt` is the run's first turn, built by the server from the
//! agent's role, the issue and why it was woken: what to do on this wake and when it is done.
//! Absent from an older server: the runner's own short prompt.
//!
//! Live policy (1.24): `PolicyUpdate` carries a running run's new permission policy (its
//! project's, plus the issue's "allow for this issue" rules) when it changes; the runner
//! decides that run's next tool calls by it. Approvals already asked for stay as they are.
//! An older runner skips the message and keeps the policy its `Assign` carried.
//!
//! Platform and probe (1.25): `Hello` may carry `os` and `arch` (`macos`, `aarch64`, as Rust
//! names them). `Probe` asks the runner to look again at itself now (its harnesses' versions,
//! its logins, its platform), answered by `Probed`. A server sends it only to a runner that
//! said 1.25 in its `Hello`; an older runner is "too old" to the admin who asked.
//!
//! Host load (1.26): `Heartbeat` carries the host's load (`HostLoad`), so the server gives a
//! loaded runner a longer lease (`lease::renew_lease_loaded`). The heartbeat goes out from its
//! own thread, so it keeps flowing while the daemon's loop is stalled by that load. An older
//! server ignores the field; an older runner sends none and keeps the plain lease.
//!
//! Cache-weighted run cap (1.27): `Assign.token_caps` splits the run's caps. The budgets' and
//! the issue's caps count every token in full; `run.token_cap` counts cache reads and writes
//! at `1 / cache_weight_divisor`, so a run's cap tracks the work it does rather than the context
//! it re-reads. `Assign.token_cap` keeps the least of all three, for a runner older than 1.27,
//! which counts every token in full.
//!
//! Workspace lease (1.28): a `Workspace` may carry `expected_head`, the sha its branch was
//! last pushed at. The runner pushes the branch with `--force-with-lease` on it, and refuses any
//! branch that is not its issue's. An older server sends none, so the push stays a plain one.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

mod limits;
mod policy;
mod workspace;
pub use limits::*;
pub use policy::*;
pub use workspace::*;

/// The protocol version a peer speaks, `major.minor`. A server refuses a `Hello` whose major
/// it does not know; minors only add optional fields.
pub const PROTOCOL_VERSION: &str = "1.28";

/// The token cap a run gets when no budget applies (#15): a safety net, never unlimited.
/// Counted as every token the harness reports, cache reads included. The server's is the
/// `run.token_cap` setting (E15.17); this is the runner's for an older server.
pub const DEFAULT_TOKEN_CAP: u64 = 2_000_000;

/// A run's caps, split (1.27): what the runner counts its tokens against. A run stops when
/// either applies. Its tokens are counted from its events, and the caps stay exact for the
/// budgets and the issue; only `run` is weighted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TokenCaps {
    /// The least left in the budgets and the issue's cap that apply, counted in full (0 is
    /// stop at once); absent when none applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<u64>,
    /// `run.token_cap`, compared with the run's tokens where cache reads and writes count at
    /// `1 / cache_weight_divisor` (0 is stop at once).
    pub run: u64,
    /// How much a cache token counts against `run`, as a divisor (1: every token in full).
    pub cache_weight_divisor: u64,
}

impl TokenCaps {
    /// The least of the caps, every token in full: what a runner older than 1.27 counts, and
    /// the `Assign.token_cap` a server sends with these.
    pub fn least(&self) -> u64 {
        self.exact.map_or(self.run, |exact| exact.min(self.run))
    }
}

/// How long a permission escalation waits for a decision (E3.10): the runner denies it after
/// this when the server sends no `limits` (1.11). It sends its timeout with each request (1.5),
/// and the server expires the approval at that deadline.
pub const APPROVAL_TIMEOUT_SECS: u64 = 15 * 60;

/// How long a run may go without progress before its runner stops it (E15.7), when the server
/// sends no `stall_after_secs` (1.14).
pub const STALL_AFTER_SECS: u64 = 10 * 60;

/// The most of a tool's output a `tool_result` transcript event carries when the server sends
/// no `tool_output_bytes` (1.18).
pub const TOOL_OUTPUT_BYTES: u64 = 2048;

/// The host's load when a heartbeat was sent (1.26): its one-minute load average and its CPU
/// count. The server stretches a loaded runner's lease by `avg1 / cores`, up to a cap.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HostLoad {
    pub avg1: f64,
    pub cores: u32,
}

/// The major part of a `major.minor` version, if it has one.
pub fn protocol_major(version: &str) -> Option<u32> {
    let (major, minor) = version.split_once('.')?;
    minor.parse::<u32>().ok()?;
    major.parse().ok()
}

/// Runner → server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RunnerMessage {
    /// The first message of every connection.
    Hello {
        protocol: String,
        runner_version: String,
        /// Capabilities it offers, e.g. `linux`, `macos`, `xcode`.
        tags: Vec<String>,
        /// Installed harness → version, e.g. `claude` → `2.1.306`, from its `--version` (or
        /// `unknown (…)` when unreadable). A version at or above the adapter's minimum and not
        /// known bad gets work (1.21); a refused one marks the runner unhealthy (E3.6).
        harnesses: BTreeMap<String, String>,
        /// Runs it is still working on, to resume after a reconnect.
        runs: Vec<i64>,
        /// Its last disk report (1.15), if it made one.
        #[serde(default)]
        disk: Option<Box<DiskReport>>,
        /// Its state (1.20); absent from an older runner.
        #[serde(default)]
        info: Option<Box<RunnerInfo>>,
        /// Its operating system and CPU architecture (1.25), e.g. `macos` and `aarch64`.
        #[serde(default)]
        os: Option<String>,
        #[serde(default)]
        arch: Option<String>,
    },
    /// The answer to `Probe` `request` (1.25): what it found now.
    Probed {
        request: i64,
        /// Installed harness → version, as in `Hello`.
        #[serde(default)]
        harnesses: BTreeMap<String, String>,
        info: Box<RunnerInfo>,
        #[serde(default)]
        os: Option<String>,
        #[serde(default)]
        arch: Option<String>,
        /// Why it could not look, if it could not.
        #[serde(default)]
        error: Option<String>,
    },
    /// Its state, after each clean-up pass (1.20).
    Status {
        info: Box<RunnerInfo>,
    },
    /// The answer to `ReadLog` `request` (1.20): the last lines of its log, redacted, or why
    /// not.
    LogTail {
        request: i64,
        #[serde(default)]
        lines: Vec<String>,
        #[serde(default)]
        error: Option<String>,
    },
    /// Its disk use after a clean-up pass (1.15, E15.9).
    Disk {
        report: Box<DiskReport>,
    },
    /// It has a free slot and wants one run. `workspaces`: the issues it holds a worktree
    /// for (1.1).
    Ready {
        #[serde(default)]
        workspaces: Vec<i64>,
    },
    /// It is still working on `run`; `load` (1.26) is the host's load when it says.
    Heartbeat {
        run: i64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        load: Option<HostLoad>,
    },
    /// `run` progressed (1.14): a tool call, a file change, a new message or more tokens.
    /// `diff_files`: how many files its worktree differs from the base in, when measured.
    Progress {
        run: i64,
        #[serde(default)]
        diff_files: Option<u32>,
        /// Each repo's diff against its base, in the issue's repo order (1.18); empty when not
        /// measured.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        repos: Vec<RepoDiff>,
    },
    /// The harness for `run` is up; `session` is its resumable session id, if it has one.
    RunStarted {
        run: i64,
        session: Option<String>,
    },
    /// One transcript chunk, numbered from 1 per run, redacted (`redact`). The server stores
    /// each `seq` once; a resend is ignored.
    RunEvent {
        run: i64,
        seq: u64,
        payload: serde_json::Value,
    },
    RunEnded {
        run: i64,
        outcome: Outcome,
    },
    /// The run's token totals so far, numbered from 1 per run (1.2). Totals, not deltas: a
    /// lost or repeated report loses or double-counts nothing.
    RunUsage {
        run: i64,
        seq: u64,
        usage: Tokens,
    },
    /// The harness asks for a tool call the run's policy does not allow (1.3). `id` is the
    /// harness's request id, unique within the run; `input` is redacted. Resent after a
    /// reconnect until answered; the server keeps one approval per `(run, id)`.
    /// The run moved to the next entry of its fallback chain (1.9): `harness` and `model` as
    /// in the `Assign`'s `fallbacks`, working as `account`; `class` is why (`model_unavailable`,
    /// `rate_limited`, `quota`, `no_account`), `reason` the harness's words, redacted.
    RunFallback {
        run: i64,
        harness: String,
        model: String,
        #[serde(default)]
        account: Option<i64>,
        class: String,
        reason: String,
    },
    /// The provider dropped the run's turn and the runner resumes its session (1.10). Not
    /// resent: a drop lost to a dropped connection is not counted.
    ProviderDrop {
        run: i64,
        reason: String,
    },
    ApprovalRequest {
        run: i64,
        id: String,
        tool: String,
        input: serde_json::Value,
        /// How long the runner waits before denying it (1.5), so the server expires the
        /// approval at the same moment. Absent from an older runner: the server's deadline.
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// The answer to `ReadFile` `request` (1.17): the file's bytes in standard base64, or why
    /// it was not read.
    FileRead {
        request: i64,
        #[serde(default)]
        content: Option<String>,
        #[serde(default)]
        error: Option<String>,
    },
}

/// Token counts. A cap counts their `sum`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct Tokens {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    /// What the harness itself says the run has cost so far, in millionths of a US dollar,
    /// when it says (Claude's `total_cost_usd`, OpenCode's session cost; 1.6). Not part of
    /// `sum`. Absent: the server prices the tokens, or leaves them unpriced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd_micros: Option<u64>,
}

impl Tokens {
    pub fn sum(&self) -> u64 {
        self.input + self.output + self.cache_read + self.cache_write
    }
}

/// How a run ended, as its runner saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    /// `fingerprint` is the error class + step, for the loop breaker.
    Failed {
        reason: String,
        fingerprint: Option<String>,
    },
    Cancelled {
        reason: String,
    },
    /// Usage reached the run's token cap.
    TokenCap,
    /// No progress for `RunLimits.stall_after_secs` (1.14): the runner stopped it.
    Stalled,
}

/// Server → runner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Welcome {
        runner: i64,
        lease_ttl_secs: i64,
        /// Its disk and warm-process settings (1.15); absent, the runner's defaults.
        #[serde(default)]
        limits: Option<RunnerLimits>,
        /// The admin's Power Nap preference for it (1.20); absent, none set.
        #[serde(default)]
        power_nap: Option<bool>,
    },
    /// A claimed run for the runner to start. Holds no secret.
    Assign {
        run: i64,
        agent: i64,
        issue: Option<i64>,
        harness: String,
        model: String,
        /// Where the run's context is read, through the Citadel MCP server (E4.2).
        context_ref: String,
        /// The issue's git worktree, when its project has a repo (1.1).
        #[serde(default)]
        workspace: Option<Box<Workspace>>,
        /// Tokens the run may use: the least left in any budget that applies, or the
        /// server's default (1.2). Absent from an older server: the runner's default.
        #[serde(default)]
        token_cap: Option<u64>,
        /// The run's caps split (1.27), see `TokenCaps`; absent from an older server, which
        /// sends `token_cap` alone.
        #[serde(default)]
        token_caps: Option<Box<TokenCaps>>,
        /// The project's permission policy (1.3); absent, the default (ask).
        #[serde(default)]
        policy: Policy,
        /// The issue's key, e.g. `CIT-12`, for the prompt (1.4).
        #[serde(default)]
        issue_key: Option<String>,
        /// The run's skills rendered as markdown, for the harness's instructions file (1.4,
        /// E4.3); absent when the run has none.
        #[serde(default)]
        instructions: Option<Box<String>>,
        /// The provider account to work as (1.8); absent, the runner's own harness login.
        #[serde(default)]
        account: Option<Box<Account>>,
        /// The rest of the agent's fallback chain, in order (1.9).
        #[serde(default)]
        fallbacks: Vec<Route>,
        /// The run's limits from the server's settings (1.11); absent, the runner's defaults.
        #[serde(default)]
        limits: Option<Box<RunLimits>>,
        /// A session of the run's harness to continue rather than starting a new one (1.12,
        /// E15.5); absent, a fresh session.
        #[serde(default)]
        resume_session: Option<Box<String>>,
        /// The run's first turn (1.22): its job on this wake and its done rule; absent, the
        /// runner's own.
        #[serde(default)]
        prompt: Option<Box<String>>,
    },
    /// The started run's token, for the harness to call back with. Sent once per start or
    /// re-start (a resumed `RunStarted` rotates it).
    Token { run: i64, token: RunToken },
    /// Stop and forget `run`: it was cancelled, ended already, or this runner no longer holds
    /// it. Send no `RunEnded`.
    Cancel { run: i64, reason: String },
    /// `RunEnded` for `run` was recorded.
    Ack { run: i64 },
    /// The answer to `ApprovalRequest` `id` of `run` (1.3): `reply` is the reviewer's note,
    /// which a denial passes to the agent as its reason.
    Approval {
        run: i64,
        id: String,
        approved: bool,
        reply: Option<String>,
    },
    /// Finish the tool call in flight, then stop `run`'s turn and end it `Cancelled` (1.19).
    Pause { run: i64 },
    /// The admin's message `id` for `run`'s harness, given to it as its next turn (1.19).
    Message { run: i64, id: i64, text: String },
    /// Remove the worktrees of these issues: they are done, cancelled or gone (1.1).
    Prune { issues: Vec<i64> },
    /// Read `path`, relative to `run`'s worktree, of at most `max_bytes` (1.17); answered by
    /// `FileRead`.
    ReadFile {
        run: i64,
        request: i64,
        path: String,
        max_bytes: u64,
    },
    /// The last `lines` lines of the runner's own log (1.20); answered by `LogTail`.
    ReadLog { request: i64, lines: u32 },
    /// The admin changed its Power Nap preference (1.20).
    Prefs { power_nap: bool },
    /// Look at yourself again now (1.25); answered by `Probed`.
    Probe { request: i64 },
    /// `run`'s permission policy changed (1.24): its next tool calls are decided by `policy`.
    PolicyUpdate { run: i64, policy: Policy },
    /// A message was refused for a reason other than the run: a protocol or storage error.
    Error { message: String },
}

/// A provider account, by reference only (E15.1): never its secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Account {
    pub id: i64,
    pub label: String,
    /// The harness's config dir, relative to the runner's config root (`relative_path_ok`).
    pub config_dir: String,
    /// The file holding the token, relative to the runner's credentials dir.
    #[serde(default)]
    pub credential_ref: Option<String>,
    /// The variable the token goes in, one of the harness's auth variables.
    #[serde(default)]
    pub credential_env: Option<String>,
}

/// One entry of an agent's fallback chain (E15.3), with the account picked for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Route {
    pub harness: String,
    pub model: String,
    #[serde(default)]
    pub account: Option<Account>,
}

/// A relative path of plain names (`[A-Za-z0-9._-]`, never `.` or `..`) joined by `/`: what
/// an account's config dir and credential reference must be, so neither escapes its root.
pub fn relative_path_ok(path: &str) -> bool {
    path.len() <= 255
        && path.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

/// A run token on the wire. Its `Debug` is redacted, so logging a message never logs it;
/// `expose` is the one way to read it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct RunToken(String);

impl RunToken {
    pub fn new(raw: String) -> Self {
        Self(raw)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RunToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RunToken(<redacted>)")
    }
}

#[cfg(test)]
mod tests;
