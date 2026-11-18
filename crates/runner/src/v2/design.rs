//! The `design` driver (Design V6-01, plan T7): `design.render`, `design.measure`, `design.review` and
//! `design.check`, `design.export` and `design.fidelity` run the `ainkrad-design` helper (CPU Skia); `design.shot` runs headless Chromium.
//!
//! Security model. Library fonts, images, SVG and HTML are untrusted, and so is a design document:
//! a parser bug in Skia, FreeType or Blink must cost one job, never the runner or the host. So:
//! - The runner never parses a job's files. It writes the job into a fresh 0700 directory and starts
//!   the helper (or Chromium) in bubblewrap: every namespace unshared, **no network** (an empty
//!   network namespace), no capabilities, no nested user namespace, an empty environment, a
//!   seccomp deny-list (`seccomp.rs`), a read-only root of `/usr` and font config only, and the job
//!   at `/in` **read-only**. The only writable places are tmpfs inside the sandbox (`/tmp`, an 8 MiB
//!   `/out`): no host path is writable, so nothing the job plants (a symlink, a FIFO, a flood of
//!   files) is ever opened by the runner. Chromium's screenshot comes back on stdout, read by
//!   `head -c` inside the sandbox and capped again outside. The runner's state, keys and HOME are
//!   not there.
//! - Limits: 60 s of wall clock and 30 s of CPU (so a spinning file is `design_failed` and only load is `design_limit`), 2 GiB of address space for the helper, 64 MiB per
//!   written file, 256 processes (`ulimit -u`), at most 2 jobs at once (`busy` past that). In the
//!   runner unit (`Delegate=yes`), each job runs in its own child cgroup of the unit's subtree with
//!   `memory.max` 1 GiB and `pids.max` 256 (kernel limits, `cgroup.rs`); everywhere, the runner also
//!   polls the whole process tree's resident memory from outside and kills it over 1 GiB. The
//!   cgroup tests mean something only when run inside that real unit. A sandbox dies with the runner (`PR_SET_PDEATHSIG`), and job
//!   directories a crash left behind are removed at start.
//! - Whatever it prints is data: parsed into the one reply type the op allows, size-capped. A
//!   failure, crash or limit of the helper is `design_failed`; running out of wall clock is
//!   `design_limit` (load can cause it, so the Core keeps the asset pending); a sandbox that did not
//!   start (before the helper ran) is `spawn_failed`, so the Core does not take either as a verdict.
//! - Trust: a `design.check` verdict is the runner's word, and the Core records it as such. Every
//!   runner is paired by the one owner of the Core, so a runner is the trust root for checks; a
//!   compromised runner could pass a hostile font, which then still only ever reaches other sandboxed
//!   helpers (the Core never parses it).
//! - Linux only (bubblewrap); the driver is offered only when this exact sandbox starts.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{
    Command, DESIGN_MAX_INPUT, DESIGN_MAX_PNG, DESIGN_MAX_SIDE, DriverInfo, ErrorCode,
    OP_DESIGN_CHECK, OP_DESIGN_EXPORT, OP_DESIGN_FIDELITY, OP_DESIGN_MEASURE, OP_DESIGN_RENDER,
    OP_DESIGN_REVIEW, OP_DESIGN_SHOT, Reply, StreamError,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

pub const DRIVER: &str = "design";
/// Where an installed runner finds them (`deploy/install-linux.sh`).
const HELPER: &str = "/usr/local/bin/ainkrad-design";
const CHROMIUM_DIR: &str = "/usr/local/lib/ainkrad-chromium";
const CHROMIUM: &str = "/usr/local/lib/ainkrad-chromium/chrome-headless-shell";
/// Why a job that ran out of wall clock stopped (answered `design_limit`, not `design_failed`).
const TIME_LIMIT: &str = "it ran past its time limit";
/// What the helper may print: a PNG in base64 plus its JSON.
const MAX_STDOUT: usize = DESIGN_MAX_PNG / 3 * 4 + (1 << 20);

mod cgroup;
mod sandbox;
mod seccomp;
mod shot;

pub use cgroup::Cgroups;
use sandbox::{Job, command, outcome, probe, read_capped, sweep, tree_rss};
use shot::{png_size, shot_args};

pub struct DesignConfig {
    pub helper: PathBuf,
    /// Headless Chromium (or a wrapper script beside it); `design.shot` is offered only with it.
    pub chromium: Option<PathBuf>,
    pub capacity: u32,
    pub timeout: Duration,
    /// Resident bytes of the whole sandboxed tree.
    pub max_rss: u64,
    /// The helper's address space (Chromium reserves terabytes of it, so it gets only `max_rss`).
    pub max_vm: u64,
    /// The runner unit's delegated cgroup: each job gets a child with `memory.max` = `max_rss`
    /// and `pids.max` 256. `None` outside that unit.
    pub cgroups: Option<Arc<Cgroups>>,
}

impl DesignConfig {
    pub fn new(helper: PathBuf, chromium: Option<PathBuf>) -> Self {
        Self {
            helper,
            chromium,
            capacity: 2,
            timeout: Duration::from_secs(60),
            max_rss: 1 << 30,
            max_vm: 2 << 30,
            cgroups: None,
        }
    }
}

pub struct DesignDriver {
    config: DesignConfig,
    slots: Arc<Semaphore>,
}

/// `AINKRAD_DESIGN_HELPER` / `AINKRAD_CHROMIUM` (the unit's environment, for a user-local install),
/// else beside the runner, else the installed path.
fn find(env: &str, beside: &str, installed: &str) -> Option<PathBuf> {
    let near = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join(beside)));
    std::env::var_os(env)
        .map(PathBuf::from)
        .into_iter()
        .chain(near)
        .chain(std::iter::once(PathBuf::from(installed)))
        .find(|p| p.is_absolute() && p.is_file())
}

/// Whether Chromium at `p` may be bound read-only into the sandbox with its whole folder: the
/// installed folder, or one holding nothing but Chromium. Never the runner's own folder, nor one
/// that holds an `ainkrad-*` file (the runner, the helper, a key).
fn chromium_ok(p: &Path) -> bool {
    let Some(dir) = p.parent() else { return false };
    if dir == Path::new(CHROMIUM_DIR) {
        return true;
    }
    let ours = std::env::current_exe()
        .ok()
        .and_then(|e| e.canonicalize().ok()?.parent().map(Path::to_path_buf));
    if ours.as_deref() == Some(dir) {
        return false;
    }
    std::fs::read_dir(dir).is_ok_and(|d| {
        d.flatten()
            .all(|e| !e.file_name().to_string_lossy().starts_with("ainkrad-"))
    })
}

impl DesignDriver {
    pub fn new(config: DesignConfig) -> Self {
        let slots = Arc::new(Semaphore::new(config.capacity as usize));
        Self { config, slots }
    }

    /// The driver when this host has the helper and this exact sandbox starts (`probe`); `None`
    /// otherwise. Job cgroups are used when the runner unit's subtree is delegated.
    pub fn discover() -> Option<Self> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        sweep(&std::env::temp_dir(), Duration::from_secs(600));
        let helper = find("AINKRAD_DESIGN_HELPER", "ainkrad-design", HELPER)?;
        let chromium = find("AINKRAD_CHROMIUM", "chrome-headless-shell", CHROMIUM)
            .and_then(|p| p.canonicalize().ok())
            .filter(|p| chromium_ok(p));
        let mut config = DesignConfig::new(helper, chromium);
        config.cgroups = Cgroups::delegated().map(Arc::new);
        if !probe(&config) {
            config.cgroups = None;
            if !probe(&config) {
                tracing::warn!(
                    "design helper found, but its sandbox does not start: design ops are off"
                );
                return None;
            }
            tracing::info!(
                "design jobs run without a job cgroup: the memory limit is the runner's own watch"
            );
        }
        Some(Self::new(config))
    }

    pub fn info(&self) -> DriverInfo {
        let mut commands = [
            OP_DESIGN_RENDER,
            OP_DESIGN_MEASURE,
            OP_DESIGN_REVIEW,
            OP_DESIGN_CHECK,
            OP_DESIGN_EXPORT,
            OP_DESIGN_FIDELITY,
        ]
        .map(str::to_owned)
        .to_vec();
        if self.config.chromium.is_some() {
            commands.push(OP_DESIGN_SHOT.to_owned());
        }
        DriverInfo {
            name: DRIVER.to_owned(),
            commands,
            capacity: self.config.capacity,
            streams: Some(self.config.capacity),
            ..DriverInfo::default()
        }
    }

    /// For the runner's facts: what it has (display only).
    pub fn facts(&self) -> Vec<(String, String)> {
        let mut v = vec![("design helper".to_owned(), "sandboxed".to_owned())];
        if self.config.chromium.is_some() {
            v.push(("chromium".to_owned(), "sandboxed".to_owned()));
        }
        v
    }

    pub fn slot(&self) -> Result<OwnedSemaphorePermit, StreamError> {
        self.slots.clone().try_acquire_owned().map_err(|_| {
            let cap = self.config.capacity;
            StreamError::new(ErrorCode::Busy, format!("design is at capacity ({cap})"))
        })
    }

    /// Runs one design command to its reply.
    pub async fn run(
        &self,
        command: &Command,
        cancel: oneshot::Receiver<()>,
    ) -> Result<Reply, StreamError> {
        let job = Job::new().map_err(|e| internal(&e))?;
        let size = serde_json::to_vec(command).map_or(usize::MAX, |v| v.len());
        if size > DESIGN_MAX_INPUT {
            return Err(StreamError::new(
                ErrorCode::TooLarge,
                format!("a design job is at most {DESIGN_MAX_INPUT} bytes"),
            ));
        }
        let (program, args, vm) = match command {
            Command::DesignShot(s) => {
                let chromium = self.config.chromium.as_ref().ok_or_else(|| {
                    StreamError::new(ErrorCode::UnsupportedCommand, "no Chromium on this runner")
                })?;
                // Chromium's own output goes to stderr; stdout carries only the PNG, read inside the
                // sandbox with a cap, so a planted FIFO or a link to /dev/zero costs only this job.
                let mut args = vec![
                    "-c".to_owned(),
                    format!(
                        "\"$@\" >&2 </dev/null || exit $?; exec head -c {} /out/shot.png",
                        DESIGN_MAX_PNG + 1
                    ),
                    "shot".to_owned(),
                    chromium.to_string_lossy().into_owned(),
                ];
                args.extend(shot_args(s, &job)?);
                (PathBuf::from("/bin/bash"), args, None)
            }
            Command::DesignRender(_)
            | Command::DesignMeasure(_)
            | Command::DesignReview(_)
            | Command::DesignCheck(_)
            | Command::DesignExport(_)
            | Command::DesignFidelity(_) => {
                let json = serde_json::to_vec(command).map_err(|e| internal(&e))?;
                std::fs::write(job.dir.join("in/job.json"), json).map_err(|e| internal(&e))?;
                (
                    self.config.helper.clone(),
                    vec!["/in/job.json".to_owned()],
                    Some(self.config.max_vm),
                )
            }
            _ => {
                return Err(StreamError::new(
                    ErrorCode::UnsupportedCommand,
                    "not a design op",
                ));
            }
        };
        // The helper alone; Chromium with the files beside it.
        let bind = match command {
            Command::DesignShot(_) => self
                .config
                .chromium
                .as_ref()
                .and_then(|c| c.parent())
                .map(Path::to_path_buf),
            _ => Some(self.config.helper.clone()),
        };
        let out = self
            .sandboxed(&job, &program, &args, bind.as_deref(), vm, cancel)
            .await?;
        reply(command, &out)
    }

    /// Runs `program args` in the sandbox: its stdout when it exited 0.
    async fn sandboxed(
        &self,
        job: &Job,
        program: &Path,
        args: &[String],
        bind: Option<&Path>,
        vm: Option<u64>,
        cancel: oneshot::Receiver<()>,
    ) -> Result<Vec<u8>, StreamError> {
        let (c, keep) =
            command(&self.config, job, program, args, bind, vm).map_err(|e| internal(&e))?;
        let mut c = tokio::process::Command::from(c);
        c.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = c.spawn().map_err(|e| {
            StreamError::new(
                ErrorCode::SpawnFailed,
                format!("cannot start the sandbox: {e}"),
            )
        })?;
        let pid = child.id().unwrap_or(0);
        let stdout = tokio::spawn(read_capped(child.stdout.take(), MAX_STDOUT));
        let stderr = tokio::spawn(read_capped(child.stderr.take(), 4096));
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        let deadline = tokio::time::sleep(self.config.timeout);
        tokio::pin!(deadline, cancel);
        let stopped = loop {
            tokio::select! {
                s = child.wait() => break s.map_err(|e| internal(&e))?.code().ok_or("it was killed by a signal (a crash)"),
                () = &mut deadline => break Err(TIME_LIMIT),
                _ = &mut cancel => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
                    keep.release().await;
                    return Err(StreamError::new(ErrorCode::Cancelled, "cancelled"));
                }
                _ = tick.tick() => {
                    if tree_rss(pid) > self.config.max_rss {
                        break Err("it used more memory than allowed");
                    }
                }
            }
        };
        if stopped.is_err() {
            // bwrap dies, and with it the namespace's init and every process in it.
            let _ = child.start_kill();
            let _ = child.wait().await;
        }
        // Whatever of the tree outlived bubblewrap dies with the job cgroup.
        keep.release().await;
        let out = stdout.await.unwrap_or_default();
        let err = stderr.await.unwrap_or_default();
        outcome(stopped, out, &err)
    }
}

/// The helper's stdout (or Chromium's PNG) as the op's one reply type.
fn reply(command: &Command, out: &[u8]) -> Result<Reply, StreamError> {
    let bad = || failed("the design helper's answer is not valid");
    fn parse<T: serde::de::DeserializeOwned>(o: &[u8]) -> Result<T, StreamError> {
        serde_json::from_slice(o).map_err(|_| failed("the design helper's answer is not valid"))
    }
    let image = |i: &ainkrad_proto::v2::DesignImage| {
        let ok = i.png.len() <= DESIGN_MAX_PNG / 3 * 4 + 4
            && (1..=DESIGN_MAX_SIDE).contains(&i.width)
            && (1..=DESIGN_MAX_SIDE).contains(&i.height);
        if ok { Ok(()) } else { Err(bad()) }
    };
    Ok(match command {
        Command::DesignRender(_) => {
            let i = parse(out)?;
            image(&i)?;
            Reply::DesignRender(i)
        }
        Command::DesignMeasure(_) => Reply::DesignMeasure(parse(out)?),
        Command::DesignReview(_) => Reply::DesignReview(parse(out)?),
        Command::DesignCheck(_) => Reply::DesignCheck(parse(out)?),
        Command::DesignExport(_) => Reply::DesignExport(parse(out)?),
        Command::DesignFidelity(_) => Reply::DesignFidelity(parse(out)?),
        Command::DesignShot(_) => {
            let png = out;
            let (width, height) =
                png_size(png).ok_or_else(|| failed("the screenshot is not a PNG"))?;
            let i = ainkrad_proto::v2::DesignImage {
                png: STANDARD.encode(png),
                width,
                height,
                metrics_differ: false,
            };
            if png.len() > DESIGN_MAX_PNG {
                return Err(failed("the screenshot is too large"));
            }
            image(&i)?;
            Reply::DesignShot(i)
        }
        _ => return Err(bad()),
    })
}

fn failed(m: &str) -> StreamError {
    StreamError::new(ErrorCode::DesignFailed, m)
}

fn internal(e: &dyn std::fmt::Display) -> StreamError {
    StreamError::new(ErrorCode::Internal, format!("design job: {e}"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
#[cfg(all(test, target_os = "linux"))]
mod tests_review2;
#[cfg(all(test, target_os = "linux"))]
mod tests_review3;
