//! `HarnessExecutor` (E3.2+): works an assigned run through a real harness adapter, picked by
//! the job's `harness`.
//!
//! `start` only picks the session id where the harness lets the caller choose it (Claude's
//! `--session-id`), so `RunStarted` carries it before the harness exists; the others announce
//! theirs as the first `session_started` event. `run` spawns the harness once the run token is
//! in hand, which is when the Citadel MCP config can be written (E4.2). One turn per run: the
//! run ends with the turn. Every run is a new session, so no task inherits another's context
//! (E15.5), unless the server names one to continue (`Job::resume_session`).
//!
//! Agent interface (E4.2): the harness gets a per-run MCP config pointing at the server's
//! `/mcp/v1` with the run token in a header, and the run's skills as its instructions, both by
//! file in the run's private dir (`files`), removed when the run ends. The prompt only names
//! the issue; the agent reads and reports through the Citadel MCP tools, which the policy
//! always lets through (they are scoped by the token).
//!
//! A job with a `Workspace` works in its issue's git worktree (`workspace`), or in its issue dir
//! holding a worktree per repo (`Job::repos`, E15.16), set up by `start`; any other in a scratch dir `<work_root>/run-<id>`. A workspace marked `push` has its
//! branch pushed to origin when the turn ends, whatever its outcome, reported as a transcript
//! event (`branch_pushed`, `branch_unchanged` or `push_failed`); a failed push does not fail the
//! run. A `push_failed` carries the remote's reason (1.23: `rejected` refs with theirs, the
//! branch's `sha`, and the `workflow_files` it changes), redacted like every chunk.
//!
//! Permissions (E3.10): the job's policy picks each harness's own mode (Claude's
//! `--permission-mode`, Codex's approval policy, OpenCode's rules; agy only when sandboxed)
//! and decides its approval requests here: allowed (the allowlist; edits in the run's
//! directory under `accept_edits`; anything under `sandboxed`) or escalated to a reviewer
//! through the server, waiting up to `approval_timeout` and then denied. A denial's reason
//! goes back to the agent. A project that wants sandboxed runs never runs here unless this
//! runner is sandboxed.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use ainkrad_harness::claude;
use ainkrad_harness::compat;
use ainkrad_proto::runner::{
    APPROVAL_TIMEOUT_SECS, DEFAULT_TOKEN_CAP, DiskReport, Outcome, PermissionMode, RunToken,
    RunnerLimits, STALL_AFTER_SECS, TOOL_OUTPUT_BYTES,
};
use serde_json::json;
use tokio::sync::mpsc;

use crate::workspace::{SessionWorkspace, Workspaces};
use crate::{Executor, Job, Report};

/// The harnesses this runner drives, with the model a job without one gets (the cheapest).
const HARNESSES: &[(&str, &str)] = &[
    ("claude", "haiku"),
    ("codex", "gpt-5.6-luna"),
    // One of OpenCode Zen's free models: no login needed.
    ("opencode", "opencode/nemotron-3.5-lightning-free"),
    ("agy", "gemini-3.8-flash-low"),
];

/// An entry's account token as `start` read it: none, the token, or why it could not be.
type Read = Result<Option<Credential>, String>;

pub struct HarnessExecutor {
    /// Worktrees and scratch dirs live here. Outside the user's home and under no
    /// `CLAUDE.md` / `AGENTS.md` / `GEMINI.md`, which harnesses read up the tree
    /// (`check_roots`).
    pub work_root: PathBuf,
    /// Each harness's private config dir is `<config_root>/<harness>`, logged in once (see
    /// each adapter's docs); a provider account's is `<config_root>/<its config dir>` (E15.1).
    pub config_root: PathBuf,
    /// Where accounts' token files live (`<config_root>/credentials` by default): an
    /// account's `credential_ref` is a file name under it.
    pub credentials_dir: PathBuf,
    /// Harness → executable; a missing one is the harness's name on `PATH`.
    pub bins: BTreeMap<String, PathBuf>,
    /// The runner's environment variables a harness may see.
    pub env_allow: Vec<String>,
    /// Those of `env_allow` holding secrets: their values are redacted from transcripts.
    pub secret_env: Vec<String>,
    /// The runner's `--env KEY=VAL` pairs, set for every harness process after the runner's own
    /// variables (`with_env`).
    harness_env: Vec<(String, String)>,
    /// The file-edit tools `accept_edits` lets through when every path they name is inside
    /// the run's working dir.
    pub edit_tools: Vec<String>,
    /// This runner's runs are confined by a sandbox it installs itself. Never set from the
    /// environment or a flag: nothing in this mode installs one, so it stays false and a
    /// project's sandboxed runs are refused (review A M1).
    pub sandboxed: bool,
    /// How long an escalated tool call waits for a reviewer before it is denied, when the
    /// server sends no `limits` (an older server); likewise the resume settings below.
    pub approval_timeout: Duration,
    /// Per-issue git worktrees under `work_root`; git's config under `<config_root>/git`.
    pub workspaces: Workspaces,
    agent_workspaces: Mutex<HashMap<(String, i64), PathBuf>>,
    /// The token cap of a job that carries none (an older server).
    pub default_token_cap: u64,
    /// How often a run's usage so far is reported.
    pub usage_every: Duration,
    /// Resumes of a session the provider dropped before the run gives up on its entry
    /// (E15.4), the first wait before one (doubling), and the longest.
    pub max_resumes: u32,
    pub resume_backoff: Duration,
    pub resume_backoff_max: Duration,
    /// The Citadel MCP server harnesses call back to (`mcp_url` of the server URL); `None`
    /// gives a harness no MCP server.
    pub mcp_url: Option<String>,
    /// The runner's pinned TLS config for the Core, used by the MCP bridge of a networkless sandbox.
    pub mcp_tls: Option<Arc<rustls::ClientConfig>>,
    /// The egress allow policy of `AINKRAD_AGENT_NETWORK=filtered`; a filtered run without it is refused.
    pub egress: Option<Arc<crate::egress::Policy>>,
    /// The executable a filtered sandbox runs as its in-sandbox forwarder (`mcp-forward`); `None`
    /// is this runner's own executable. Tests point it at the built binary.
    pub forwarder: Option<PathBuf>,
    /// Idle long-lived harness servers kept for later runs (E15.6), when the server sends no
    /// `limits`; 0 keeps none.
    pub warm_max: u32,
    /// How long a run may go without progress before it is stopped as stalled (E15.7), when
    /// the server sends no `limits`.
    pub stall_after: Duration,
    /// The most of a tool's output a `tool_result` event carries, when the server sends no
    /// `limits` (1.18).
    pub tool_output: usize,
    warm: warm::Warm,
    /// The runner's settings from the server's `Welcome` (E15.9).
    runner_limits: Mutex<RunnerLimits>,
    sessions: Mutex<HashMap<i64, String>>,
    /// Each running job's controls from the admin (1.19).
    inboxes: Mutex<HashMap<i64, Arc<inbox::Inbox>>>,
    /// Each run's own variables (`Executor::session_env`), set on its harness processes only.
    pub(crate) run_env: Mutex<HashMap<i64, Vec<(String, String)>>>,
    /// Account tokens read by `start` for each entry of the run's chain (or why one could not
    /// be), until `run` hands them to the harness.
    credentials: Mutex<HashMap<i64, Vec<Read>>>,
    /// Harness → the version `probe` found, named in a protocol failure.
    versions: Mutex<BTreeMap<String, String>>,
    /// Where harness processes start (E8a-06); `None` is the local backend (bubblewrap or
    /// Seatbelt, as `AINKRAD_SANDBOX*` say). Set it before the first run.
    pub backend: Option<Arc<dyn ainkrad_harness::exec::ExecBackend>>,
}

impl HarnessExecutor {
    pub fn new(work_root: PathBuf, config_root: PathBuf) -> Self {
        let mut env_allow: Vec<String> = [
            "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "SHELL",
        ]
        .map(str::to_owned)
        .into();
        let secret_env: Vec<String> = claude::AUTH_ENV.iter().map(|s| (*s).to_owned()).collect();
        env_allow.extend(secret_env.iter().cloned());
        Self {
            secret_env,
            harness_env: vec![],
            workspaces: Workspaces::new(work_root.clone(), config_root.join("git")),
            agent_workspaces: Mutex::default(),
            credentials_dir: config_root.join("credentials"),
            work_root,
            config_root,
            bins: BTreeMap::new(),
            env_allow,
            // Claude's file tools, Codex's `fileChange`, OpenCode's `edit`.
            edit_tools: [
                "Write",
                "Edit",
                "MultiEdit",
                "NotebookEdit",
                "fileChange",
                "edit",
            ]
            .map(str::to_owned)
            .into(),
            sandboxed: false,
            approval_timeout: Duration::from_secs(APPROVAL_TIMEOUT_SECS),
            default_token_cap: DEFAULT_TOKEN_CAP,
            usage_every: Duration::from_secs(5),
            max_resumes: 2,
            resume_backoff: Duration::from_secs(2),
            resume_backoff_max: Duration::from_secs(30),
            mcp_url: None,
            mcp_tls: None,
            egress: None,
            forwarder: None,
            warm_max: 0,
            stall_after: Duration::from_secs(STALL_AFTER_SECS),
            tool_output: TOOL_OUTPUT_BYTES as usize,
            warm: warm::Warm::default(),
            runner_limits: Mutex::new(RunnerLimits::default()),
            sessions: Mutex::new(HashMap::new()),
            inboxes: Mutex::new(HashMap::new()),
            run_env: Mutex::new(HashMap::new()),
            credentials: Mutex::new(HashMap::new()),
            versions: Mutex::new(BTreeMap::new()),
            backend: None,
        }
    }

    /// Probes every harness's `--version` (E3.6), each with its own config dir as `HOME`:
    /// installed harness → version, for `Hello`. A missing one is left out, so it is never
    /// offered. The server judges the versions; a refusal is logged here too.
    pub async fn probe(&self, timeout: Duration) -> BTreeMap<String, String> {
        let mut found = BTreeMap::new();
        for (name, _) in HARNESSES {
            let program = self.bins.get(*name).cloned();
            let program = program.unwrap_or_else(|| PathBuf::from(name));
            let home = self.config_root.join(name);
            if let Err(e) = std::fs::create_dir_all(&home) {
                tracing::warn!(harness = name, error = %e, "cannot create its config dir");
                continue;
            }
            match compat::probe(&program, &home, timeout).await {
                None => tracing::info!(harness = name, "not installed"),
                Some(version) => {
                    // The server judges under its settings; this is the default policy.
                    let verdict = compat::check(name, Some(&version), &Default::default());
                    match verdict.reason {
                        Some(why) if verdict.refused => {
                            tracing::error!(harness = name, %why, "harness will not be offered");
                        }
                        Some(note) => tracing::warn!(harness = name, %note, "untested version"),
                        None => {}
                    }
                    found.insert((*name).to_owned(), version);
                }
            }
        }
        *self.versions.lock().expect("versions") = found.clone();
        found
    }

    /// Sets the extra environment every harness process gets (the runner's `--env`). A name
    /// that holds a secret (`secret_env`) is dropped with a warning: a runner's own key never
    /// reaches a run through here, nor overrides the one a run's account sets.
    pub fn with_env(mut self, pairs: Vec<(String, String)>) -> Self {
        for (name, value) in pairs {
            if self.secret_env.contains(&name) {
                tracing::warn!(%name, "--env cannot set a secret variable; ignored");
                continue;
            }
            self.harness_env.retain(|(n, _)| *n != name);
            self.harness_env.push((name, value));
        }
        self
    }

    /// Why the work root cannot be used, given the user's `home`: it must be an absolute
    /// UTF-8 path outside the home, with no harness instruction file above it.
    pub fn check_roots(&self, home: &Path) -> Result<(), String> {
        let root = &self.work_root;
        let shown = root.display();
        if !root.is_absolute() || root.to_str().is_none() {
            return Err(format!("work root {shown} must be an absolute UTF-8 path"));
        }
        std::fs::create_dir_all(root).map_err(|e| format!("{shown}: {e}"))?;
        let real = root.canonicalize().map_err(|e| format!("{shown}: {e}"))?;
        if let Ok(home) = home.canonicalize()
            && real.starts_with(&home)
        {
            return Err(format!(
                "work root {shown} is inside the home {}; harnesses would read its \
                 instruction files",
                home.display()
            ));
        }
        for dir in real.ancestors() {
            for file in ["CLAUDE.md", "AGENTS.md", "GEMINI.md"] {
                if dir.join(file).exists() {
                    return Err(format!(
                        "work root {shown} is under {}, which harnesses would read",
                        dir.join(file).display()
                    ));
                }
            }
        }
        Ok(())
    }

    fn cwd(&self, job: &Job) -> PathBuf {
        match (&job.workspace, job.issue) {
            (Some(_), Some(issue)) => self.workspaces.path(issue),
            (Some(_), None) => self
                .agent_workspaces
                .lock()
                .expect("agent workspaces")
                .get(&(job.context_ref.clone(), job.run))
                .cloned()
                .unwrap_or_else(|| self.work_root.join(format!("run-{}", job.run))),
            _ => self.work_root.join(format!("run-{}", job.run)),
        }
    }
}

impl Executor for HarnessExecutor {
    async fn reprobe(&self) -> Option<BTreeMap<String, String>> {
        Some(self.probe(Duration::from_secs(10)).await)
    }

    fn logins(&self) -> Vec<ainkrad_proto::runner::Login> {
        let names = HARNESSES.iter().map(|(name, _)| *name);
        crate::state::logins(&self.config_root, &self.credentials_dir, names)
    }

    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        if !HARNESSES.iter().any(|(name, _)| *name == job.harness) {
            return Err(format!("harness {:?} is not supported", job.harness));
        }
        let contained = job.policy.sandboxed || job.policy.mode == PermissionMode::Sandboxed;
        if contained && !self.sandboxed {
            return Err("the project's runs must be sandboxed, and this runner is not".to_owned());
        }
        // The agent driver's sandbox marks the run's environment once it has applied the policy's
        // isolation fields; without that mark nothing has, and the run is refused.
        let isolated = self.sandboxed
            || self
                .run_env
                .lock()
                .expect("run env lock")
                .get(&job.run)
                .is_some_and(|e| e.iter().any(|(n, _)| n == "AINKRAD_SANDBOX"));
        if job.policy.asks_for_isolation() && !isolated {
            return Err(
                "the policy sets isolation fields, and this runner has no sandbox".to_owned(),
            );
        }
        let config = self.config_dir(job)?;
        std::fs::create_dir_all(&config).map_err(|e| format!("{}: {e}", config.display()))?;
        // The fallbacks' tokens are read now too, so the run redacts them from the start; one
        // that cannot be read only rules its entry out (E15.3).
        let mut read = vec![Ok(self.read_credential(job)?)];
        read.extend(routes(job).iter().skip(1).map(|r| self.read_credential(r)));
        self.credentials
            .lock()
            .expect("credentials lock")
            .insert(job.run, read);
        match (&job.workspace, job.issue) {
            (Some(_), Some(issue)) => {
                let path = self.workspaces.prepare(issue, &job.trees()).await;
                path.map_err(|e| format!("workspace: {e}"))?;
            }
            (Some(_), None) => {
                if !self
                    .agent_workspaces
                    .lock()
                    .expect("agent workspaces")
                    .contains_key(&(job.context_ref.clone(), job.run))
                {
                    return Err("agent workspace was not prepared".to_owned());
                }
            }
            _ => {
                let dir = self.cwd(job);
                std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
        }
        if job.harness != "claude" {
            return Ok(None);
        }
        // A resumed session keeps its id (E15.5); a new one gets a fresh one.
        let session = match &job.resume_session {
            Some(id) => id.clone(),
            None => claude::new_session_id().map_err(|e| e.to_string())?,
        };
        let mut sessions = self.sessions.lock().expect("sessions lock");
        sessions.insert(job.run, session.clone());
        Ok(Some(session))
    }

    async fn run(&self, job: &Job, token: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        let outcome = self.work_routes(job, &token, &reports).await;
        self.inboxes.lock().expect("inboxes lock").remove(&job.run);
        // ponytail: a run aborted by `Cancel` never gets here, so its worktree counts as in
        // use (unprunable) until the runner restarts. A drop guard is the upgrade.
        if let (Some(_), Some(issue)) = (&job.workspace, job.issue) {
            // Each repo's branch, one by one (E15.16).
            for ws in job.trees().iter().filter(|ws| ws.push) {
                let mut event = match self.workspaces.push(ws, job.issue_key.as_deref()).await {
                    Ok(Some(sha)) => {
                        json!({"type": "branch_pushed", "branch": ws.branch, "sha": sha})
                    }
                    Ok(None) => json!({"type": "branch_unchanged", "branch": ws.branch}),
                    Err(f) => {
                        let rejected: Vec<_> = f
                            .rejected
                            .iter()
                            .map(|(r, why)| json!({"ref": r, "reason": why}))
                            .collect();
                        json!({"type": "push_failed", "branch": ws.branch, "reason": f.reason,
                               "rejected": rejected, "sha": f.sha,
                               "workflow_files": f.workflow_files})
                    }
                };
                if !ws.name.is_empty() {
                    event["repo"] = ws.name.clone().into();
                }
                let _ = reports.send(Report::Event(event)).await;
            }
            self.workspaces.release(issue);
        }
        outcome
    }

    async fn secrets(&self) -> Vec<(String, String)> {
        let mut secrets: Vec<(String, String)> = self
            .secret_env
            .iter()
            .filter(|name| self.env_allow.contains(name))
            .filter_map(|name| Some((format!("env:{name}"), std::env::var(name).ok()?)))
            .collect();
        for answer in self.workspaces.askpass_answers().await {
            secrets.push(("git_askpass".to_owned(), answer));
        }
        secrets
    }

    fn run_secrets(&self, job: &Job) -> Vec<(String, String)> {
        let credentials = self.credentials.lock().expect("credentials lock");
        credentials
            .get(&job.run)
            .into_iter()
            .flatten()
            .filter_map(|c| c.as_ref().ok()?.as_ref())
            .map(|c| ("account_credential".to_owned(), c.value.clone()))
            .collect()
    }

    fn workspaces(&self) -> Vec<i64> {
        self.workspaces.held()
    }

    async fn prepare_agent_workspace(
        &self,
        session: &str,
        generation: i64,
        workspace: &ainkrad_proto::runner::Workspace,
        helper: Option<&Path>,
    ) -> Result<PathBuf, String> {
        let mut requests = vec![SessionWorkspace {
            repo: workspace.repo.clone(),
            reference: workspace.base.clone(),
            branch: workspace.branch.clone(),
            name: workspace.name.clone(),
        }];
        requests.extend(workspace.also.iter().map(|w| SessionWorkspace {
            repo: w.repo.clone(),
            reference: w.base.clone(),
            branch: w.branch.clone(),
            name: w.name.clone(),
        }));
        let path = self
            .workspaces
            .prepare_session(session, generation, &requests, helper)
            .await?;
        self.agent_workspaces
            .lock()
            .expect("agent workspaces")
            .insert((session.to_owned(), generation), path.clone());
        Ok(path)
    }

    async fn cleanup_agent_workspace(&self, session: &str, generation: i64) {
        self.agent_workspaces
            .lock()
            .expect("agent workspaces")
            .remove(&(session.to_owned(), generation));
        if let Err(why) = self.workspaces.cleanup_session(session, generation).await {
            tracing::warn!(session, %why, "agent workspace cleanup failed");
        }
    }

    fn recover_agent_workspaces(&self, adopted: &[String]) {
        self.workspaces.recover_sessions(adopted);
    }

    fn control(&self, run: i64, control: crate::Control) {
        self.inbox(run).put(control);
    }

    fn session_env(&self, run: i64, env: Option<Vec<(String, String)>>) {
        let mut all = self.run_env.lock().expect("run env lock");
        match env {
            Some(env) => drop(all.insert(run, env)),
            None => drop(all.remove(&run)),
        }
    }

    async fn prune(&self, issues: Vec<i64>) {
        self.workspaces.prune(issues).await;
    }

    async fn read_file(
        &self,
        issue: Option<i64>,
        path: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, String> {
        let issue = issue.ok_or("the run has no issue, so no worktree")?;
        self.workspaces.read_file(issue, path, max_bytes)
    }

    fn set_limits(&self, limits: RunnerLimits) {
        *self.runner_limits.lock().expect("limits lock") = limits;
    }

    async fn housekeep(&self) -> Option<DiskReport> {
        let limits = *self.runner_limits.lock().expect("limits lock");
        self.warm
            .evict_idle(Duration::from_secs(limits.warm_idle_secs))
            .await;
        Some(self.workspaces.gc(SystemTime::now(), &limits).await)
    }
}

mod account;
mod cli;
mod files;
mod inbox;
mod policy;
mod routes;
mod tools;
mod turn;
mod warm;
mod watch;

use account::Credential;
pub use files::{core_mcp_url, mcp_url};
use routes::routes;

#[cfg(test)]
mod tests;

/// What one run works with of the server's settings (E15.17).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub approval_timeout: Duration,
    pub max_resumes: u32,
    pub resume_backoff: Duration,
    pub resume_backoff_max: Duration,
    pub warm_max: u32,
    pub stall_after: Duration,
    pub tool_output: usize,
}

impl HarnessExecutor {
    /// Job `run`'s controls, made on first use (a control may come before its run's turn).
    fn inbox(&self, run: i64) -> Arc<inbox::Inbox> {
        let mut inboxes = self.inboxes.lock().expect("inboxes lock");
        inboxes.entry(run).or_default().clone()
    }

    /// Idle harness servers kept warm now (E15.6).
    pub fn warm_idle(&self) -> usize {
        self.warm.len()
    }

    /// The run's limits: the server's (`Assign.limits`), else this executor's own.
    pub(crate) fn limits(&self, job: &Job) -> Limits {
        match job.limits {
            Some(l) => Limits {
                approval_timeout: Duration::from_secs(l.approval_timeout_secs),
                max_resumes: l.max_resumes,
                resume_backoff: Duration::from_millis(l.resume_backoff_ms),
                resume_backoff_max: Duration::from_millis(l.resume_backoff_max_ms),
                warm_max: l.warm_max,
                stall_after: Duration::from_secs(l.stall_after_secs),
                tool_output: usize::try_from(l.tool_output_bytes).unwrap_or(usize::MAX),
            },
            None => Limits {
                approval_timeout: self.approval_timeout,
                max_resumes: self.max_resumes,
                resume_backoff: self.resume_backoff,
                resume_backoff_max: self.resume_backoff_max,
                warm_max: self.warm_max,
                stall_after: self.stall_after,
                tool_output: self.tool_output,
            },
        }
    }
}
