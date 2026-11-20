//! Runners as hardware (E15-1): what a runner says about its capacity in its hello and in every
//! heartbeat (`RunnerHello::capacity`, `Heartbeat::capacity`, beside `load`), so the Core can place
//! AI sessions and heavy jobs. The Core host is the online runner with `built_in = true`. Every
//! field defaults, so an older runner's frame (no `capacity`) and a newer one's (more fields) parse.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::sync::Hash;

/// A runner's capacity now.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct Capacity {
    /// Logical CPUs.
    pub cores: u32,
    /// CPU use, 0 to 100, averaged over 60 s.
    pub cpu_pct: u8,
    pub mem_total_mb: u64,
    /// Memory available to new work ("available", not "free").
    pub mem_free_mb: u64,
    /// Free disk under the runner's cache root.
    pub disk_free_mb: u64,
    /// Absent on a host with no battery.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub battery: Option<Battery>,
    /// Seconds since the last user input on the host (This Mac); absent where unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idle_secs: Option<u64>,
    /// The runner's own verdict on taking jobs (E15-4 `hwgate`).
    pub gate: Gate,
    /// Toolchains ready for jobs, `rust`, `node`, `python`, `go`, `xcode`, `swift`, `docker` to version.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub toolchains: BTreeMap<String, String>,
    /// The warm project caches this runner holds (§4.5).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub caches: Vec<CacheInfo>,
    /// How many jobs it runs at once: default `cores / 4`, at least 1.
    pub job_slots: u32,
}

impl Capacity {
    /// The default job slots for `cores`: a quarter, at least one.
    pub fn default_job_slots(cores: u32) -> u32 {
        (cores / 4).max(1)
    }
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(default)]
pub struct Battery {
    pub on_battery: bool,
    /// 0 to 100.
    pub percent: u8,
}

/// Whether a runner takes jobs now, by its own measure. The Core's pause always wins over `Open`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Gate {
    Open,
    /// The host is in use (This Mac: not idle and CPU at or above 30%).
    Busy,
    OnBattery,
    /// Paused on the host itself.
    Paused,
    /// Takes no jobs at all (no `job` driver, or switched off). Also what an absent gate reads as.
    #[default]
    Off,
    /// A gate from a newer runner: read as not open. Never sent.
    #[serde(other)]
    Unknown,
}

/// One warm project cache on a runner.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct CacheInfo {
    /// The project id.
    pub project: i64,
    /// The tree the cache holds now (`TreeHash`).
    pub tree_hash: Hash,
    pub bytes: u64,
}

/// What a piece of hardware is, to the Core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HwKind {
    /// The built-in runner: the Core host.
    Core,
    /// This Mac (the bundled runner).
    Mac,
    /// A remote runner.
    Runner,
    #[serde(other)]
    Unknown,
}

/// An operating system, as Rust names it (`std::env::consts::OS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Os {
    Linux,
    Macos,
    #[serde(other)]
    Unknown,
}

impl Os {
    /// From `RunnerHello::os`; `None` for a name this side does not know.
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "linux" => Some(Self::Linux),
            "macos" => Some(Self::Macos),
            _ => None,
        }
    }
}

/// A CPU architecture, as Rust names it (`std::env::consts::ARCH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    Aarch64,
    X86_64,
    #[serde(other)]
    Unknown,
}

impl Arch {
    /// From `RunnerHello::arch`; `None` for a name this side does not know.
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "aarch64" => Some(Self::Aarch64),
            "x86_64" => Some(Self::X86_64),
            _ => None,
        }
    }
}
