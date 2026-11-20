//! The `job` driver (E15-4, spec §6): `job.run` runs one command (after its `prepare` commands) in a
//! project's warm cache, or on the built-in runner in the canonical workspace with no sync.
//!
//! - **Sandbox:** the agent sandbox (`ainkrad_harness` bubblewrap or Seatbelt), never unconfined: the
//!   project folder is read-write, the toolchains read-only (`AINKRAD_SANDBOX_RO`), the job's own home
//!   holds the package caches, and the network is `filtered` to the registry list
//!   (`JOB_REGISTRY_HOSTS`) through a proxy outside it. A host whose sandbox or egress filter does not
//!   work refuses the job.
//! - **Environment:** starts empty. Only what the job names (`env`), the leased secrets (redeemed once,
//!   never written to disk) and the variables the toolchains need are set.
//! - **Output:** stdout and stderr in arrival order as credited `output` frames (`flow`), redacted with
//!   the leased values, also across chunk edges. A `signal` control frame goes to the process group; the
//!   Core's `close` cancels (TERM, then KILL after the grace).
//! - **Result:** `JobDone` with the files the job changed or created (as they are now), the paths it
//!   deleted and the cache's tree after (`sync`), measured against a snapshot taken before.
//! - **Mac gate:** a Mac that goes on battery during a job gets [`BATTERY_GRACE`], then the job is
//!   cancelled with `on_battery` so the Core places it again.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ainkrad_harness::Spec;
use ainkrad_harness::exec::{ExecBackend, Launch, LocalBackend, SpawnRequest, Stdio as HStdio};
use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::{
    CAP_JOB, DriverInfo, ErrorCode, JOB_REGISTRY_HOSTS, job_hosts_within, JobDone, JobRun, MAX_SYNC_OUT_BYTES,
    OP_JOB_RUN, StreamError, TreeHash,
};
use tokio::io::AsyncReadExt;
use tokio::sync::{Semaphore, mpsc};

use super::agent::secrets::{Form, Redeem, private_dir};
use super::flow::{Event, Flow, Stop};
use super::hwgate::{BATTERY_GRACE, HwGate};
use super::sync::{SyncDriver, job_delta};
use super::toolchains::{self, Toolchains};
use crate::egress;

pub const DRIVER: &str = CAP_JOB;
/// Output frames carry at most this many bytes.
const FRAME_BYTES: usize = 16 * 1024;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3600);

pub struct JobConfig {
    /// The runner's state folder: job folders and the workspace-mode homes live under it.
    pub state: PathBuf,
    /// `--workspace-root`: set on the built-in runner, which runs jobs in the canonical workspace.
    pub workspace_root: Option<PathBuf>,
    /// This executable: the egress forwarder the sandbox binds in.
    pub exe: PathBuf,
    /// Jobs at once; one more is `busy`.
    pub capacity: u32,
    pub max_timeout: Duration,
    /// Between TERM and KILL on cancel.
    pub kill_grace: Duration,
}

pub struct JobDriver {
    cfg: JobConfig,
    toolchains: Arc<Toolchains>,
    sync: Arc<SyncDriver>,
    redeem: Redeem,
    gate: HwGate,
    slots: Arc<Semaphore>,
    egress: tokio::sync::OnceCell<Result<Arc<egress::Policy>, String>>,
}

fn invalid(why: impl Into<String>) -> StreamError {
    StreamError::new(ErrorCode::InvalidArgs, why)
}

fn internal(why: impl Into<String>) -> StreamError {
    StreamError::new(ErrorCode::Internal, why)
}

/// How one command of a job ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Ended {
    code: Option<i32>,
    signal: Option<i32>,
}

/// Why a job stopped before its command could finish by itself.
enum Halt {
    Cancelled,
    Lost,
    OnBattery,
}

impl JobDriver {
    pub fn new(
        cfg: JobConfig,
        toolchains: Arc<Toolchains>,
        sync: Arc<SyncDriver>,
        redeem: Redeem,
        gate: HwGate,
    ) -> Self {
        let slots = Arc::new(Semaphore::new(cfg.capacity.max(1) as usize));
        Self {
            cfg,
            toolchains,
            sync,
            redeem,
            gate,
            slots,
            egress: tokio::sync::OnceCell::new(),
        }
    }

    /// Offered only where the sandbox works (the Core checks the `job` driver before placing).
    pub fn info(&self) -> Option<DriverInfo> {
        crate::v2::ProcessSandbox::available_here().then(|| DriverInfo {
            name: DRIVER.to_owned(),
            commands: vec![OP_JOB_RUN.to_owned()],
            capacity: self.cfg.capacity.max(1),
            ..DriverInfo::default()
        })
    }

    /// The registry-only egress policy, proven by the start-up check once.
    async fn policy(&self) -> Result<Arc<egress::Policy>, StreamError> {
        let made = self
            .egress
            .get_or_init(|| async {
                let policy = egress::Policy::parse("", &JOB_REGISTRY_HOSTS.join(","), "443")?
                    .with_host_addresses(egress::host_addresses()?);
                egress::selftest(&policy, &self.cfg.exe)
                    .await
                    .map_err(|why| format!("the egress filter failed its check: {why}"))?;
                Ok::<_, String>(Arc::new(policy))
            })
            .await;
        made.clone()
            .map_err(|why| internal(format!("jobs need a filtered network: {why}")))
    }

    /// The project folder the job runs in: the cache, or the canonical workspace on the Core's own runner.
    fn root(&self, req: &JobRun) -> Result<PathBuf, StreamError> {
        let root = if req.cache.is_empty() {
            let ws = self.cfg.workspace_root.as_ref().ok_or_else(|| {
                invalid("this runner has no canonical workspace; the job names a cache")
            })?;
            ws.join("p").join(req.project.to_string()).join("main")
        } else {
            self.sync.layout().root(req.project)
        };
        root.is_dir()
            .then_some(root)
            .ok_or_else(|| invalid("no such cache or workspace for the project"))
    }

    /// Runs the job to its end. `flow` carries its output, signals and cancel.
    pub async fn run(&self, req: JobRun, mut flow: Flow) -> Result<JobDone, StreamError> {
        if let Some(e) = problem(&req) {
            return Err(e);
        }
        if !crate::v2::ProcessSandbox::available_here() {
            return Err(internal(
                "this runner has no working sandbox; jobs never run unconfined",
            ));
        }
        if ainkrad_sys::getuid() == 0 {
            return Err(internal("jobs never run as root"));
        }
        if matches!(
            self.gate.sample(0).0,
            ainkrad_proto::v2::Gate::Paused | ainkrad_proto::v2::Gate::OnBattery
        ) {
            return Err(StreamError::new(
                ErrorCode::Busy,
                "this runner takes no jobs now (paused or on battery)",
            ));
        }
        let _slot = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_| StreamError::new(ErrorCode::Busy, "this runner is at its job limit"))?;
        let started = Instant::now();
        let cache_mode = !req.cache.is_empty();
        let root = self.root(&req)?;
        let cwd = root.join(&req.cwd_rel);
        if !within(&root, &cwd) {
            return Err(StreamError::new(
                ErrorCode::PathRefused,
                "cwd_rel leaves the project",
            ));
        }
        // Toolchains: what the job asks for and what its programs need, installed outside the sandbox.
        let mut tools: Vec<&str> = req
            .need
            .toolchains
            .iter()
            .map(String::as_str)
            .filter(|t| toolchains::installable(t))
            .collect();
        for argv in std::iter::once(&req.argv).chain(&req.prepare) {
            tools.extend(toolchains::tool_for(&argv[0]));
        }
        tools.sort_unstable();
        tools.dedup();
        if tools.contains(&"rust") {
            toolchains::check_rust_channel(&root).map_err(invalid)?;
        }
        for t in &tools {
            self.toolchains
                .ensure(t)
                .await
                .map_err(|e| internal(format!("installing {t}: {e}")))?;
        }
        let job_dir = self.cfg.state.join("jobs").join(&req.job);
        let _ = std::fs::remove_dir_all(&job_dir);
        for d in ["tmp", "secrets", "egress"] {
            private_dir(&job_dir.join(d)).map_err(|e| internal(e.to_string()))?;
        }
        let _cleanup = JobDir(job_dir.clone());
        let home = match cache_mode {
            true => self.sync.job_home(req.project),
            false => {
                let h = self
                    .cfg
                    .state
                    .join("jobs-home")
                    .join(req.project.to_string());
                private_dir(&h).map(|()| h)
            }
        }
        .map_err(|e| internal(e.to_string()))?;
        let job_tools = self.toolchains.job_tools(&tools, &home);
        // Secrets: redeemed once, held in memory, masked in the output.
        let mut redactor = Redactor::new();
        let mut secrets = Vec::new();
        for s in &req.secrets {
            let leased = (self.redeem)(s.lease.clone())
                .await
                .map_err(|e| invalid(format!("cannot redeem the lease of {}: {e}", s.name)))?;
            if leased.form != Form::Text || leased.value.contains(['\n', '\r', '\0']) {
                return Err(invalid(format!("{} is not a one-line text secret", s.name)));
            }
            redactor.known(&s.name, &leased.value);
            secrets.push((s.name.clone(), leased.value.to_string()));
        }
        // The network: a proxy outside the sandbox that dials only the registry list.
        let sock = egress::socket_in(&job_dir.join("egress"));
        let policy = match &req.hosts {
            // The asking session's own list, cut to the registry list again here (E15 H2).
            Some(hosts) => Arc::new(
                self.policy()
                    .await?
                    .only_hosts(&job_hosts_within(hosts)),
            ),
            None => self.policy().await?,
        };
        let _proxy = egress::start(&sock, policy)
            .map_err(|e| internal(format!("egress proxy: {e}")))?;
        let timeout = req
            .timeout_ms
            .map_or(DEFAULT_TIMEOUT, Duration::from_millis)
            .clamp(Duration::from_secs(1), self.cfg.max_timeout);
        let root_real = root.canonicalize().map_err(|e| internal(e.to_string()))?;
        let head = if cache_mode {
            self.sync.head(req.project).await
        } else {
            None
        };
        let mut env = sandbox_vars(
            &self.cfg.state,
            &job_dir,
            &job_tools.ro,
            timeout,
            egress::sandbox_env(&sock, &self.cfg.exe),
        );
        env.extend(command_env(
            &home,
            &job_dir.join("tmp"),
            &job_tools,
            head.as_deref(),
            &req,
            &secrets,
        ));
        let spec = Spec {
            cwd: root_real,
            process_dir: Some(cwd.canonicalize().map_err(|e| internal(e.to_string()))?),
            config_dir: home,
            env,
            ..Spec::default()
        };
        let before = match cache_mode {
            true => Some(self.sync.snapshot(req.project).await?),
            false => None,
        };
        // Prepare commands first (the lockfile changed: `npm ci`), then the command itself.
        let deadline = started + timeout;
        let mut ended = Ended::default();
        let mut halt = None;
        let mut out = Out {
            redactor,
            carry: [Vec::new(), Vec::new()],
        };
        for argv in req.prepare.iter().chain(std::iter::once(&req.argv)) {
            let left = deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_secs(1));
            match self.command(&spec, argv, left, &mut flow, &mut out).await? {
                Ok(e) => ended = e,
                Err(h) => {
                    halt = Some(h);
                    break;
                }
            }
            if ended.code != Some(0) {
                break;
            }
        }
        match halt {
            Some(Halt::Cancelled) => {
                return Err(StreamError::new(
                    ErrorCode::Cancelled,
                    "the job was cancelled",
                ));
            }
            Some(Halt::Lost) => {
                return Err(StreamError::new(ErrorCode::Lost, "the stream was lost"));
            }
            Some(Halt::OnBattery) => {
                return Err(StreamError::new(
                    ErrorCode::Cancelled,
                    "on_battery: this Mac went on battery; place the job again",
                ));
            }
            None => {}
        }
        // What the job changed: measured against the snapshot taken before it ran.
        let (changed, deleted, tree) = match before {
            Some(before) => {
                let after = self.sync.snapshot(req.project).await?;
                let (changed, deleted) = job_delta(&before.out, &after.out);
                if changed.iter().map(|e| e.size).sum::<u64>() > MAX_SYNC_OUT_BYTES {
                    return Err(StreamError::new(
                        ErrorCode::OutputsTooLarge,
                        "the job's outputs are over the sync-out limit",
                    ));
                }
                (changed, deleted, after.tree)
            }
            None => (Vec::new(), Vec::new(), TreeHash::default()),
        };
        Ok(JobDone {
            exit_code: ended.code,
            signal: ended.signal.map(signal_name),
            changed,
            deleted,
            tree,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// One command in the sandbox, its output on `flow`: how it ended, or why it was stopped.
    async fn command(
        &self,
        spec: &Spec,
        argv: &[String],
        limit: Duration,
        flow: &mut Flow,
        out: &mut Out,
    ) -> Result<Result<Ended, Halt>, StreamError> {
        let launch = Launch::new(&argv[0], argv[1..].to_vec());
        let mut spawned = LocalBackend
            .spawn(SpawnRequest {
                spec,
                launch: &launch,
                stdio: HStdio::Pipes,
                deadline: Some(limit),
            })
            .await
            .map_err(|e| {
                StreamError::new(
                    ErrorCode::SpawnFailed,
                    format!("the command did not start: {e}"),
                )
            })?;
        drop(spawned.stdin.take());
        let (tx, mut rx) = mpsc::channel::<(usize, Vec<u8>)>(16);
        let mut pumps = Vec::new();
        for (i, pipe) in [Some(spawned.stdout), spawned.stderr]
            .into_iter()
            .enumerate()
        {
            let Some(mut pipe) = pipe else { continue };
            let tx = tx.clone();
            pumps.push(tokio::spawn(async move {
                let mut buf = vec![0u8; FRAME_BYTES];
                while let Ok(n) = pipe.read(&mut buf).await {
                    if n == 0 || tx.send((i, buf[..n].to_vec())).await.is_err() {
                        break;
                    }
                }
            }));
        }
        drop(tx);
        let mut running = spawned.running;
        let mut exit = None;
        let mut halt = None;
        let mut on_battery_since: Option<Instant> = None;
        let mut beat = tokio::time::interval(Duration::from_secs(5));
        beat.tick().await;
        let mut piping = true;
        // Once it has ended, whatever still holds a pipe gets this long to finish.
        let mut drain: Option<tokio::time::Instant> = None;
        // Until it has ended and its pipes are drained (or the grace after it passes).
        while exit.is_none() || piping {
            tokio::select! {
                ev = flow.event(), if halt.is_none() => match ev {
                    Event::Signal(name) => match (name.as_str(), running.pid()) {
                        ("INT", _) => { let _ = running.interrupt().await; }
                        (n, Some(pid)) => {
                            if let Some(sig) = signal_number(n) { let _ = ainkrad_sys::killpg(pid, sig); }
                        }
                        _ => {}
                    },
                    Event::Stop(s) => halt = Some(match s { Stop::Cancelled => Halt::Cancelled, Stop::Dropped => Halt::Lost }),
                },
                chunk = rx.recv(), if piping => match chunk {
                    Some((i, bytes)) => {
                        let masked = redact_chunk(&mut out.redactor, &mut out.carry[i], &bytes);
                        if let Err(s) = flow.write(&masked, FRAME_BYTES).await {
                            halt.get_or_insert(match s { Stop::Cancelled => Halt::Cancelled, Stop::Dropped => Halt::Lost });
                        }
                    }
                    None => piping = false,
                },
                e = running.wait(), if exit.is_none() => {
                    exit = Some(e.map_err(|e| internal(format!("waiting for the command: {e}")))?);
                    // The leader is gone: stragglers of its group are ended, and the pipes drained.
                    if let Some(pid) = running.pid() { let _ = ainkrad_sys::killpg(pid, 15); }
                    drain = Some(tokio::time::Instant::now() + Duration::from_secs(2));
                }
                () = async { tokio::time::sleep_until(drain.unwrap_or_else(tokio::time::Instant::now)).await }, if drain.is_some() && piping => {
                    piping = false;
                }
                _ = beat.tick(), if self.gate.is_mac() && halt.is_none() => {
                    let gate = self.gate.clone();
                    let on = tokio::task::spawn_blocking(move || gate.on_battery()).await.unwrap_or(false);
                    match (on, on_battery_since) {
                        (true, None) => on_battery_since = Some(Instant::now()),
                        (true, Some(t)) if t.elapsed() >= BATTERY_GRACE => halt = Some(Halt::OnBattery),
                        (false, _) => on_battery_since = None,
                        _ => {}
                    }
                }
            }
            if halt.is_some() && exit.is_none() {
                // Cancelled: TERM the group, KILL after the grace.
                if let Some(pid) = running.pid() {
                    let _ = ainkrad_sys::killpg(pid, 15);
                }
                match tokio::time::timeout(self.cfg.kill_grace, running.wait()).await {
                    Ok(e) => exit = e.ok(),
                    Err(_) => exit = running.kill().await,
                }
                piping = false;
            } else if halt.is_some() {
                piping = false;
            }
        }
        for p in pumps {
            p.abort();
        }
        // A character or secret held back at the end goes out as it is.
        for i in 0..2 {
            let tail = std::mem::take(&mut out.carry[i]);
            let masked = out.redactor.stream_text(&String::from_utf8_lossy(&tail));
            let _ = flow.write(masked.as_bytes(), FRAME_BYTES).await;
        }
        if let Some(h) = halt {
            return Ok(Err(h));
        }
        let e = exit.unwrap_or_default();
        Ok(Ok(match (e.deadline || e.oom, e.signal) {
            (true, _) => Ended {
                code: None,
                signal: Some(9),
            },
            (false, Some(s)) => Ended {
                code: None,
                signal: Some(s),
            },
            (false, None) => Ended {
                code: e.code,
                signal: None,
            },
        }))
    }
}

/// Redaction state shared by a job's commands: the leased values, and each pipe's cut UTF-8.
struct Out {
    redactor: Redactor,
    carry: [Vec<u8>; 2],
}

mod prep;
use prep::{
    JobDir, command_env, problem, redact_chunk, sandbox_vars, signal_name, signal_number, within,
};

#[cfg(test)]
mod tests;
