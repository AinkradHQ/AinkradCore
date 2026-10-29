//! The limits the server sends a runner: per run in `Assign` (`RunLimits`, 1.11), per runner in
//! `Welcome` (`RunnerLimits`, 1.15); and the disk use a runner reports back (`DiskReport`).

use serde::{Deserialize, Serialize};

use super::{STALL_AFTER_SECS, TOOL_OUTPUT_BYTES};

/// What the runner is told of the server's settings for one run (1.11, E15.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunLimits {
    /// How long an escalated tool call waits for a reviewer before it is denied.
    pub approval_timeout_secs: u64,
    /// Resumes of a dropped session before the run gives up on its model (E15.4).
    pub max_resumes: u32,
    /// The first wait before a resume, doubling per drop, and the longest.
    pub resume_backoff_ms: u64,
    pub resume_backoff_max_ms: u64,
    /// Idle harness servers the runner keeps for later runs (1.13, E15.6); 0, none. Absent
    /// from an older server: none.
    #[serde(default)]
    pub warm_max: u32,
    /// How long the run may go without progress before it is stopped as stalled (1.14,
    /// E15.7). Absent from an older server: `STALL_AFTER_SECS`.
    #[serde(default = "stall_after_secs")]
    pub stall_after_secs: u64,
    /// The most of a tool's output a `tool_result` transcript event carries (1.18). Absent
    /// from an older server: `TOOL_OUTPUT_BYTES`.
    #[serde(default = "tool_output_bytes")]
    pub tool_output_bytes: u64,
    /// Whether a turn failing for this class moves the run to the next entry of its fallback
    /// chain (1.20); otherwise the run fails. Absent from an older server: it does.
    #[serde(default = "yes")]
    pub fallback_on_model_unavailable: bool,
    #[serde(default = "yes")]
    pub fallback_on_rate_limited: bool,
    #[serde(default = "yes")]
    pub fallback_on_quota: bool,
    #[serde(default = "yes")]
    pub fallback_on_unhealthy: bool,
}

fn yes() -> bool {
    true
}

impl RunLimits {
    /// Whether a failure of `class` (`ainkrad_harness::ErrorClass::as_str`) may fall back.
    pub fn falls_back_on(&self, class: &str) -> bool {
        match class {
            "model_unavailable" => self.fallback_on_model_unavailable,
            "rate_limited" => self.fallback_on_rate_limited,
            "quota" => self.fallback_on_quota,
            "unhealthy" => self.fallback_on_unhealthy,
            _ => true,
        }
    }
}

fn stall_after_secs() -> u64 {
    STALL_AFTER_SECS
}

fn tool_output_bytes() -> u64 {
    TOOL_OUTPUT_BYTES
}

/// What the runner is told of the server's settings for it (1.15, E15.9, decision #57: server-wide
/// per runner, not per company).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerLimits {
    /// The most its work root may hold: worktrees, shared build caches and repo mirrors.
    pub disk_cap_bytes: u64,
    /// Share of the cap past which idle worktrees are evicted, oldest first, then caches.
    pub disk_evict_percent: u32,
    /// How long a worktree may sit with no run before it is removed (its work kept on its
    /// branch, uncommitted changes on `refs/citadel/wip/<issue>`), recreated on demand.
    pub workspace_idle_secs: u64,
    /// How long a warm harness server may sit idle before it is stopped (E15.6).
    pub warm_idle_secs: u64,
}

impl Default for RunnerLimits {
    /// The server's defaults, for a runner whose server sends none.
    fn default() -> Self {
        Self {
            disk_cap_bytes: 50_000_000_000,
            disk_evict_percent: 90,
            workspace_idle_secs: 86_400,
            warm_idle_secs: 900,
        }
    }
}

/// A runner's disk use (1.15, E15.9), as measured after its last clean-up pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskReport {
    /// Everything under its work root.
    pub used_bytes: u64,
    pub cap_bytes: u64,
    /// The shared build caches, one per repo (`CARGO_TARGET_DIR`, package stores, …).
    pub caches_bytes: u64,
    /// The bare repo mirrors, which hold every issue's branch: never evicted.
    pub mirrors_bytes: u64,
    /// Each worktree it holds, oldest use first.
    pub worktrees: Vec<WorktreeDisk>,
    /// Issues whose worktrees this pass removed: idle past the limit, or evicted for room.
    #[serde(default)]
    pub removed: Vec<i64>,
    /// Over the cap with nothing left it may evict.
    pub full: bool,
}

/// One issue's worktree in a `DiskReport`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorktreeDisk {
    pub issue: i64,
    pub bytes: u64,
    /// A run is using it: never evicted.
    pub active: bool,
    /// Seconds since a run last used it.
    pub idle_secs: u64,
}

/// What a runner says of itself (1.20).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerInfo {
    /// Runs it works at once.
    pub slots: u32,
    /// Seconds since the daemon started.
    pub uptime_secs: u64,
    /// Each harness and account config dir (and account token file) it found, and whether it
    /// is logged in there.
    #[serde(default)]
    pub logins: Vec<Login>,
    /// How long its machine last slept, if it slept since the daemon started.
    #[serde(default)]
    pub slept_secs: Option<u64>,
    /// The Power Nap preference it holds, as the server last sent it.
    #[serde(default)]
    pub power_nap: Option<bool>,
}

/// A login place on a runner host (1.20): `dir` is relative to its config root
/// (`claude`, `accounts/claude-a`), or `credentials/<file>` for an account's token file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    pub dir: String,
    /// The harness, when the dir is a harness's own.
    #[serde(default)]
    pub harness: Option<String>,
    /// `logged_in`, `logged_out`, or `unknown` (the login lives in the keychain).
    pub state: String,
}
