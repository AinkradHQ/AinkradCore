//! Heavy jobs (E15-3/E15-4, spec §6): the `job` driver runs one command in a project's warm cache
//! (or, on the built-in runner, in the canonical workspace with no sync). Output is credited
//! `output` frames, redacted with the leased values; `control` `signal` goes to the process group
//! and `close` cancels. A runner that takes `job.run` lists it under a driver named [`CAP_JOB`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::hardware::{Arch, Os};
use super::run::RunSecret;
use super::sync::{Entry, TreeHash};

pub const OP_JOB_RUN: &str = "job.run";

/// The driver (and capability) name of a runner that runs jobs.
pub const CAP_JOB: &str = "job";

/// The hosts a job's `filtered` network may reach (package registries only).
pub const JOB_REGISTRY_HOSTS: [&str; 8] = [
    "crates.io",
    "static.crates.io",
    "registry.npmjs.org",
    "pypi.org",
    "files.pythonhosted.org",
    "proxy.golang.org",
    "github.com",
    "objects.githubusercontent.com",
];

/// What a job needs of the hardware it runs on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct JobNeed {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<Os>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<Arch>,
    /// Toolchain names (`Capacity::toolchains` keys) it needs, reported or installable from pins.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub toolchains: Vec<String>,
    /// Needs Xcode: a macOS runner that reports `xcode`.
    pub xcode: bool,
}

/// Core to runner: run `argv` in `cwd_rel` of the cache (or workspace) of `project`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct JobRun {
    /// `j_…`.
    pub job: String,
    pub project: i64,
    /// The cache the job runs in: `<work_root>/cache/<core_id>/<project_id>/`, named by the runner
    /// from `project`; this is the Core id part. Empty on the built-in runner (the workspace).
    pub cache: String,
    pub argv: Vec<String>,
    /// A wire path, relative to the cache root; empty is the root.
    pub cwd_rel: String,
    /// The child's environment, which otherwise starts empty.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Single-use leases, redeemed into the env, never written to disk; their values are redacted
    /// from the output.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<RunSecret>,
    /// Run first, in the same folder (`npm ci` when the lockfile changed). Empty: nothing.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub prepare: Vec<Vec<String>>,
    /// Absent: the runner's default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    pub need: JobNeed,
}

impl std::fmt::Debug for JobRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobRun")
            .field("job", &self.job)
            .field("project", &self.project)
            .field("argv", &self.argv.first())
            .finish_non_exhaustive()
    }
}

/// Runner to Core: the answer to `job.run`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct JobDone {
    /// Absent when a signal ended it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// `TERM`, `KILL`, ...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    /// Every file the job changed or created, as it is now: the Core pulls them (§4.6).
    pub changed: Vec<Entry>,
    /// Wire paths the job deleted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub deleted: Vec<String>,
    /// The cache's tree after the job.
    pub tree: TreeHash,
    pub duration_ms: u64,
}

/// The env variable that names the job socket in a Core shell or an agent sandbox (§5.1).
pub const JOB_SOCK_ENV: &str = "AINKRAD_JOB_SOCK";

/// The shim's line protocol on `$AINKRAD_JOB_SOCK` (§5.1), one JSON object per line. The shim
/// (`ainkrad-job`) sends a [`ShimRequest`]; the endpoint answers one [`ShimVerdict`], then, for a
/// remote job, [`ShimFrame`]s until `exit`. The shim may send `signal` frames meanwhile, and after a
/// local verdict with `report` set it sends one `done` frame once the local tool exits (the
/// duration feeds the command history).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct ShimRequest {
    pub argv: Vec<String>,
    /// The absolute working directory, as the shim sees it.
    pub cwd: String,
    pub tty: bool,
    /// Only allow-listed names.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
}

/// The endpoint's first answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum ShimVerdict {
    /// Run the real tool here.
    Local {
        reason: String,
        /// Send a `done` frame after the local run.
        #[serde(default)]
        report: bool,
    },
    /// It runs on `device_name`; frames follow.
    Remote { job: String, device_name: String },
}

/// The frames after a verdict, tagged `t`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ShimFrame {
    /// Endpoint to shim: output on `fd` (1 or 2), standard base64.
    Out { fd: u8, b64: String },
    /// Endpoint to shim: the job ended; the shim exits the same way.
    Exit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<String>,
    },
    /// Shim to endpoint: forward `INT`, `TERM` or `HUP`; a second `INT` cancels.
    Signal { signal: String },
    /// Shim to endpoint, after a local verdict with `report`: how the local run went.
    Done {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<String>,
        duration_ms: u64,
    },
    /// Endpoint to shim (and `POST /runner/jobs` 201 streams): the job's state changed
    /// (`queued`, `syncing`, `running`, the API's `JobState`).
    State { state: String },
    /// A frame from a newer peer: ignored. Never sent.
    #[serde(other)]
    Unknown,
}
