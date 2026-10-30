//! What runs a job: `HarnessExecutor` drives a real harness; `FakeExecutor` stands in for
//! one in tests.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::runner::{
    Account, DiskReport, Outcome, Policy, RepoDiff, Route, RunLimits, RunToken, RunnerLimits,
    TokenCaps, Tokens, Workspace,
};
use tokio::sync::{mpsc, oneshot};

/// A run the server assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub run: i64,
    pub agent: i64,
    pub issue: Option<i64>,
    pub harness: String,
    pub model: String,
    pub context_ref: String,
    /// The issue's git worktree, when its project has a repo (E3.7).
    pub workspace: Option<Workspace>,
    /// Tokens the run may use (E3.8); `None` from a server that sends none.
    pub token_cap: Option<u64>,
    /// The run's caps split (1.27): the budgets' exact cap and `run.token_cap` weighted for
    /// cache reads; `None` from a server older than 1.27, which sends `token_cap` alone.
    pub token_caps: Option<TokenCaps>,
    /// The project's harness permission policy (E3.10).
    pub policy: Policy,
    /// The issue's key, e.g. `CIT-12` (E4.2).
    pub issue_key: Option<String>,
    /// The run's skills as markdown, the harness's instructions (E4.2, E4.3).
    pub instructions: Option<String>,
    /// The provider account to work as (E15.1); `None`, the runner's own login.
    pub account: Option<Account>,
    /// The rest of the agent's (harness, model) chain, in order (E15.3).
    pub fallbacks: Vec<Route>,
    /// The server's settings for the run (E15.17); `None`, the executor's own.
    pub limits: Option<RunLimits>,
    /// A session to continue instead of starting a new one (E15.5); `None`, a fresh session.
    pub resume_session: Option<String>,
    /// The run's first turn from the server (1.22); `None`, the runner's own.
    pub prompt: Option<String>,
    /// Every repo of an issue touching more than one (E15.16): a worktree each, under the
    /// issue's workspace; empty for one repo (`workspace`) or none.
    pub repos: Vec<Workspace>,
}

impl Job {
    /// The caps the run's tokens are counted against: `token_caps` when the server split them
    /// (1.27), else its `token_cap` (or `default`) counting every token in full.
    pub fn caps(&self, default: u64) -> TokenCaps {
        self.token_caps.unwrap_or(TokenCaps {
            exact: Some(self.token_cap.unwrap_or(default)),
            run: u64::MAX,
            cache_weight_divisor: 1,
        })
    }

    /// The repos the run works in: `repos`, else its one `workspace`.
    pub fn trees(&self) -> Vec<Workspace> {
        match self.repos.is_empty() {
            true => self.workspace.iter().cloned().collect(),
            false => self.repos.clone(),
        }
    }
}

/// What a run reports while it works.
#[derive(Debug, Clone, PartialEq)]
pub enum Report {
    /// A transcript chunk.
    Event(serde_json::Value),
    /// The run's token totals so far.
    Usage(Tokens),
    /// The run moved to the next entry of its fallback chain (E15.3): sent before that
    /// entry's first report. `class` is why (`model_unavailable`, `rate_limited`, `quota`,
    /// `no_account`); `reason` the harness's words.
    Fallback {
        harness: String,
        model: String,
        account: Option<i64>,
        class: String,
        reason: String,
    },
    /// The provider dropped the turn and the run resumes its session (E15.4): one drop, for
    /// the account's count.
    Dropped { reason: String },
    /// The run progressed (E15.7): a tool call, a file change, a new message, more tokens;
    /// with the files its worktree differs from the base in, when measured.
    /// `repos`: each repo's diff when measured (1.18), else empty.
    Progress {
        diff_files: Option<u32>,
        repos: Vec<RepoDiff>,
    },
    /// A tool call outside the policy, for a reviewer (E3.10). The answer comes on `reply`;
    /// the run waits for it.
    Approval {
        id: String,
        tool: String,
        input: serde_json::Value,
        /// How long the run waits for the answer before denying it.
        timeout_secs: u64,
        reply: Reply,
    },
}

/// The admin's control of a running job (1.19, decision #34).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    /// Let the tool call in flight finish, then end the run `Cancelled` ("paused by admin").
    Pause,
    /// A message for the harness, given to it as its next turn.
    Message { id: i64, text: String },
    /// The run's new permission policy (1.24): its next tool calls are decided by it.
    Policy(Policy),
}

/// A reviewer's answer to an escalated tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub approved: bool,
    /// The reviewer's note; a denial's reason.
    pub reply: Option<String>,
}

/// Where an `Answer` goes: once, to the run that asked. Equal only to itself.
#[derive(Debug, Clone)]
pub struct Reply(Arc<Mutex<Option<oneshot::Sender<Answer>>>>);

impl Reply {
    pub fn new() -> (Self, oneshot::Receiver<Answer>) {
        let (tx, rx) = oneshot::channel();
        (Self(Arc::new(Mutex::new(Some(tx)))), rx)
    }

    /// Delivers `answer`; later sends, or a run that stopped waiting, are ignored.
    pub fn send(&self, answer: Answer) {
        if let Some(tx) = self.0.lock().expect("reply").take() {
            let _ = tx.send(answer);
        }
    }
}

impl PartialEq for Reply {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

pub trait Executor: Send + Sync + 'static {
    /// Prepares the job and launches its harness: its session id, if it has one, or why it
    /// could not start (the run then fails with that reason).
    fn start(&self, job: &Job) -> impl Future<Output = Result<Option<String>, String>> + Send;

    /// Works the started job with its run token until it ends, sending transcript chunks and
    /// usage to `reports`.
    fn run(
        &self,
        job: &Job,
        token: RunToken,
        reports: mpsc::Sender<Report>,
    ) -> impl Future<Output = Outcome> + Send;

    /// Secrets it knows of, (name, value), redacted from every transcript and reason (E3.9):
    /// git askpass answers, secret env values. Asked once, when the daemon starts.
    fn secrets(&self) -> impl Future<Output = Vec<(String, String)>> + Send {
        async { vec![] }
    }

    /// Secrets of this job it read at `start` (an account's token, E15.1), redacted from
    /// everything the run reports. Asked once, after a successful `start`.
    fn run_secrets(&self, job: &Job) -> Vec<(String, String)> {
        let _ = job;
        vec![]
    }

    /// Variables for run `run`'s harness processes only, before `start` (E2-07.2: a session's
    /// leased secrets); `None` drops them when it ends. Never the runner's own environment, and
    /// never another run's. Ignored by an executor that spawns nothing.
    fn session_env(&self, run: i64, env: Option<Vec<(String, String)>>) {
        let _ = (run, env);
    }

    /// The issues whose worktrees it holds (E3.7), listed in every `Ready`.
    fn workspaces(&self) -> Vec<i64> {
        vec![]
    }

    /// Removes the worktrees of these issues, which the server says are closed.
    fn prune(&self, issues: Vec<i64>) -> impl Future<Output = ()> + Send {
        let _ = issues;
        async {}
    }

    /// The bytes of `path`, relative to `issue`'s worktree, of at most `max_bytes` (E15.12), or
    /// why not.
    fn read_file(
        &self,
        issue: Option<i64>,
        path: &str,
        max_bytes: u64,
    ) -> impl Future<Output = Result<Vec<u8>, String>> + Send {
        let _ = (issue, path, max_bytes);
        async { Err("this runner keeps no worktree".to_owned()) }
    }

    /// The admin's `control` of running job `run` (1.19); ignored by an executor that has no
    /// harness to pause or tell (the run goes on).
    fn control(&self, run: i64, control: Control) {
        let _ = (run, control);
    }

    /// Takes the runner's settings from the server's `Welcome` (E15.9).
    fn set_limits(&self, limits: RunnerLimits) {
        let _ = limits;
    }

    /// One clean-up pass (E15.9): idle warm processes stopped, idle worktrees removed, the disk
    /// cap enforced. Its disk report, when it keeps anything on disk.
    fn housekeep(&self) -> impl Future<Output = Option<DiskReport>> + Send {
        async { None }
    }

    /// Each place a harness or account logs in on this host, and whether it is (1.20).
    fn logins(&self) -> Vec<ainkrad_proto::runner::Login> {
        vec![]
    }

    /// Looks for the installed harnesses and their versions again (1.25); `None` when it has
    /// none to look for.
    fn reprobe(
        &self,
    ) -> impl Future<Output = Option<std::collections::BTreeMap<String, String>>> + Send {
        async { None }
    }
}

/// Sleeps `delay` between `events` numbered chunks, then ends with `outcome`.
pub struct FakeExecutor {
    pub events: u32,
    pub delay: Duration,
    pub outcome: Outcome,
}

impl Default for FakeExecutor {
    fn default() -> Self {
        Self {
            events: 3,
            delay: Duration::from_millis(100),
            outcome: Outcome::Succeeded,
        }
    }
}

impl Executor for FakeExecutor {
    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        Ok(Some(format!("fake-session-{}", job.run)))
    }

    async fn run(&self, job: &Job, _token: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        for step in 1..=self.events {
            tokio::time::sleep(self.delay).await;
            let chunk = serde_json::json!({"fake": true, "run": job.run, "step": step});
            if reports.send(Report::Event(chunk)).await.is_err() {
                break;
            }
        }
        self.outcome.clone()
    }
}
