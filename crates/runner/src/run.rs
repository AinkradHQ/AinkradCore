//! Project runs with rootless Podman (Core 0.9 Projects, P5-02, plan T3/T5/T7).
//!
//! Security model. The runner (`ainkrad-runner`) never runs Podman itself: project containers belong
//! to the separate `ainkrad-run` user (P5-01). The runner hands each `run.*` op, with its secrets
//! already redeemed, to `ainkrad-runner run-helper`, which systemd starts as `ainkrad-run` for each
//! connection to [`helper::SOCKET`] (mode 0660, group `ainkrad-runner`; the helper checks the peer's
//! uid too). The helper builds every `podman` argument here from the typed, re-validated spec
//! ([`RunStart::problem`]); no field of it is ever a flag or a host path:
//! - every project network is created with `--opt isolate=true` (one network per project, an existing
//!   one without it is refused), so a project cannot reach another project's containers;
//! - every container gets `--cpus`, `--memory` with `--memory-swap` equal to it, `--pids-limit` and
//!   `no-new-privileges`; never `--privileged`, a host network or a host path, except its own run's
//!   checkout at `/repo/<name>`;
//! - ports are published on `127.0.0.1` only, at a port Podman picks;
//! - environment goes through an env file (never argv) in the helper's private runtime dir (tmpfs),
//!   removed as soon as the container is created;
//! - egress to the cloud metadata address and the host's private ranges is refused by the host's
//!   nftables for the `ainkrad-run` uid (`deploy/run-egress.nft`, installed with `--with-run`).
//!
//! The runner keeps no run state: a run is its containers' labels (`ainkrad.project`, `ainkrad.run`,
//! `ainkrad.service`), so status after a runner restart reads the same as before it.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use ainkrad_proto::v2::{
    PublishedPort, RunInfo, RunLimits, RunList, RunPhase, RunService, RunStart, ServiceStatus,
};

pub mod helper;
#[cfg(test)]
mod tests;

const LABEL_PROJECT: &str = "ainkrad.project";
const LABEL_RUN: &str = "ainkrad.run";
const LABEL_SERVICE: &str = "ainkrad.service";
/// How long a service with a health check has to turn healthy.
const HEALTH_WAIT: Duration = Duration::from_secs(120);

pub fn network(project: u64) -> String {
    format!("ainkrad-p{project}")
}

fn container(run: &str, service: &str) -> String {
    format!("ainkrad-{run}-{service}")
}

/// Podman, run as the current user (the helper's `ainkrad-run`, or the test user).
pub struct Engine {
    pub podman: String,
    /// Run dirs (checkouts) live under it: `<root>/<run>`.
    pub root: PathBuf,
    /// Env files, briefly: a private tmpfs dir.
    pub env_dir: PathBuf,
    /// The user's runtime dir, given to Podman as `XDG_RUNTIME_DIR` (with its bus); `None` keeps
    /// the caller's environment.
    pub runtime_dir: Option<PathBuf>,
}

/// The env file of one container, removed when dropped (on every path, errors included).
struct EnvFile(PathBuf);

impl Drop for EnvFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn private_dir(p: &Path) -> Result<(), String> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .map_err(|e| format!("creating {}: {e}", p.display()))
}

/// The `podman create` arguments of one service (pure, so the rules are tested without Podman).
#[allow(clippy::too_many_arguments)]
pub fn create_args(
    run: &str,
    project: u64,
    name: &str,
    s: &RunService,
    image: &str,
    limits: RunLimits,
    env_file: Option<&Path>,
    run_dir: &Path,
) -> Vec<String> {
    let mem = format!("{}m", limits.memory_mb);
    let mut a: Vec<String> = [
        "create",
        "--name",
        &container(run, name),
        "--network",
        &network(project),
        "--network-alias",
        name,
        "--label",
        &format!("{LABEL_PROJECT}={project}"),
        "--label",
        &format!("{LABEL_RUN}={run}"),
        "--label",
        &format!("{LABEL_SERVICE}={name}"),
        "--cpus",
        &limits.cpus.to_string(),
        "--memory",
        &mem,
        "--memory-swap",
        &mem,
        "--pids-limit",
        &limits.pids.to_string(),
        "--security-opt",
        "no-new-privileges",
        "--pull",
        "missing",
    ]
    .map(str::to_owned)
    .into();
    if let Some(f) = env_file {
        a.extend(["--env-file".to_owned(), f.display().to_string()]);
    }
    if let Some(w) = &s.workdir {
        a.extend(["--workdir".to_owned(), w.clone()]);
    }
    for (v, path) in &s.volumes {
        a.extend(["-v".to_owned(), format!("{}-{v}:{path}", network(project))]);
    }
    if let Some(r) = &s.repo {
        a.extend([
            "-v".to_owned(),
            format!("{}:/repo/{r}", run_dir.join("repos").join(r).display()),
        ]);
    }
    for p in &s.ports {
        a.extend(["-p".to_owned(), format!("127.0.0.1::{}", p.port)]);
    }
    if let Some(h) = &s.health {
        a.extend([
            "--health-cmd".to_owned(),
            h.cmd.clone(),
            "--health-interval".to_owned(),
            "disable".to_owned(),
        ]);
    }
    a.push(image.to_owned());
    a.extend(s.command.iter().flatten().cloned());
    a
}

/// What `podman ps --format json` says of one container (the fields used).
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Ps {
    #[serde(default)]
    state: String,
    #[serde(default)]
    exit_code: i32,
    #[serde(default)]
    labels: Option<BTreeMap<String, String>>,
    #[serde(default)]
    ports: Option<Vec<PsPort>>,
}

#[derive(serde::Deserialize)]
struct PsPort {
    #[serde(default)]
    host_ip: String,
    container_port: u16,
    host_port: u16,
}

/// Runs, grouped from `podman ps -a --format json` output.
pub fn runs_from_ps(json: &str) -> Result<Vec<RunInfo>, String> {
    let list: Vec<Ps> =
        serde_json::from_str(json).map_err(|e| format!("reading podman ps: {e}"))?;
    let mut runs: BTreeMap<String, RunInfo> = BTreeMap::new();
    for c in list {
        let labels = c.labels.unwrap_or_default();
        let (Some(run), Some(service)) = (labels.get(LABEL_RUN), labels.get(LABEL_SERVICE)) else {
            continue;
        };
        let info = runs.entry(run.clone()).or_insert_with(|| RunInfo {
            run: run.clone(),
            project: labels
                .get(LABEL_PROJECT)
                .and_then(|p| p.parse().ok())
                .unwrap_or(0),
            phase: RunPhase::Running,
            failed_service: None,
            reason: None,
            services: Vec::new(),
        });
        let running = c.state == "running";
        info.services.push(ServiceStatus {
            name: service.clone(),
            exit_code: (!running && c.state == "exited").then_some(c.exit_code),
            state: c.state,
            ports: c
                .ports
                .unwrap_or_default()
                .into_iter()
                // Anything published off loopback would be a bug; it is never reported as reachable.
                .filter(|p| p.host_ip == "127.0.0.1")
                .map(|p| PublishedPort {
                    port: p.container_port,
                    host_port: p.host_port,
                })
                .collect(),
        });
    }
    let mut out: Vec<RunInfo> = runs.into_values().collect();
    for r in &mut out {
        r.services.sort_by(|a, b| a.name.cmp(&b.name));
        let starting = |s: &str| matches!(s, "created" | "configured" | "initialized" | "stopping");
        if let Some(s) = r
            .services
            .iter()
            .find(|s| s.state != "running" && !starting(&s.state))
        {
            r.phase = RunPhase::Failed;
            r.failed_service = Some(s.name.clone());
            r.reason = Some(match s.exit_code {
                Some(c) => format!("{} exited with code {c}", s.name),
                None => format!("{} is {}", s.name, s.state),
            });
        } else if r.services.iter().any(|s| starting(&s.state)) {
            r.phase = RunPhase::Starting;
        }
    }
    Ok(out)
}

fn failed(run: &RunStart, service: &str, reason: String) -> RunInfo {
    RunInfo {
        run: run.run.clone(),
        project: run.project,
        phase: RunPhase::Failed,
        failed_service: Some(service.to_owned()),
        reason: Some(reason),
        services: Vec::new(),
    }
}

impl Engine {
    /// The helper's: `$HOME/runs`; env files in `/run/user/<uid>` (tmpfs), its own uid's (a unit
    /// cannot name another user's uid with a specifier, so it is not taken from the environment).
    pub fn from_env() -> Result<Self, String> {
        let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
        let runtime = PathBuf::from(format!("/run/user/{}", ainkrad_sys::getuid()));
        Ok(Self {
            podman: "podman".to_owned(),
            root: PathBuf::from(home).join("runs"),
            env_dir: runtime.join("ainkrad-env"),
            runtime_dir: Some(runtime),
        })
    }

    /// `podman args…`: its stdout, or its stderr as the reason.
    fn podman(&self, args: &[&str]) -> Result<String, String> {
        let mut cmd = Command::new(&self.podman);
        if let Some(r) = &self.runtime_dir {
            cmd.env("XDG_RUNTIME_DIR", r).env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", r.join("bus").display()),
            );
        }
        let out = cmd
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("podman: {e}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        let err = String::from_utf8_lossy(&out.stderr);
        let err: String = err.trim().chars().take(400).collect();
        Err(format!("podman {}: {err}", args.first().unwrap_or(&"")))
    }

    /// The project's network, isolated from every other (`--opt isolate=true`). One that exists
    /// without isolation is refused, never used.
    fn ensure_network(&self, project: u64) -> Result<(), String> {
        let n = network(project);
        if let Ok(json) = self.podman(&["network", "inspect", &n]) {
            let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
            return match v[0]["options"]["isolate"].as_str() {
                Some("true") => Ok(()),
                _ => Err(format!(
                    "network {n} exists without isolate=true; refusing to use it"
                )),
            };
        }
        let label = format!("{LABEL_PROJECT}={project}");
        self.podman(&[
            "network",
            "create",
            "--opt",
            "isolate=true",
            "--label",
            &label,
            &n,
        ])
        .map(drop)
    }

    fn ps(&self, filter: &str) -> Result<Vec<RunInfo>, String> {
        runs_from_ps(&self.podman(&["ps", "-a", "--filter", filter, "--format", "json"])?)
    }

    /// One run's state; `Stopped` when it has no container.
    pub fn status(&self, run: &str, project: u64) -> Result<RunInfo, String> {
        let filter = format!("label={LABEL_RUN}={run}");
        Ok(self.ps(&filter)?.pop().unwrap_or(RunInfo {
            run: run.to_owned(),
            project,
            phase: RunPhase::Stopped,
            failed_service: None,
            reason: None,
            services: Vec::new(),
        }))
    }

    /// Every run on this host (the reconcile after a runner restart).
    pub fn list(&self) -> Result<RunList, String> {
        Ok(RunList {
            runs: self.ps(&format!("label={LABEL_RUN}"))?,
        })
    }

    /// Stops and removes the run's containers (`stop -t 10`); volumes and the network stay.
    pub fn stop(&self, run: &str) -> Result<RunInfo, String> {
        let before = self.status(run, 0)?;
        let filter = format!("label={LABEL_RUN}={run}");
        let ids = self.podman(&["ps", "-a", "-q", "--filter", &filter])?;
        let ids: Vec<&str> = ids.split_whitespace().collect();
        if !ids.is_empty() {
            let _ = self.podman(&[&["stop", "-t", "10"][..], &ids].concat());
            self.podman(&[&["rm", "-f"][..], &ids].concat())?;
        }
        if ainkrad_proto::v2::valid_run_id(run) {
            let _ = std::fs::remove_dir_all(self.root.join(run));
        }
        Ok(RunInfo {
            phase: RunPhase::Stopped,
            failed_service: None,
            reason: None,
            services: Vec::new(),
            ..before
        })
    }

    /// Starts `req` (secrets already in its env). `bundles` are the checkouts, as git bundles, by
    /// repo. A service that fails to build, start or turn healthy answers `Failed` naming it.
    pub fn start(
        &self,
        req: &RunStart,
        bundles: &BTreeMap<String, PathBuf>,
    ) -> Result<RunInfo, String> {
        if let Some(p) = req.problem() {
            return Err(p);
        }
        let order = req.spec.start_order().ok_or("a depends_on cycle")?;
        if !self.status(&req.run, req.project)?.services.is_empty() {
            return Err(format!("run {} already has containers", req.run));
        }
        self.ensure_network(req.project)?;
        let run_dir = self.root.join(&req.run);
        private_dir(&run_dir.join("repos"))?;
        for c in &req.checkouts {
            let bundle = bundles
                .get(&c.repo)
                .ok_or(format!("no checkout for {}", c.repo))?;
            let dest = run_dir.join("repos").join(&c.repo);
            let out = Command::new("git")
                .args(["clone", "--no-hardlinks", "-q"])
                .arg(bundle)
                .arg(&dest)
                .env_clear()
                .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                .output()
                .map_err(|e| format!("git: {e}"))?;
            let _ = std::fs::remove_file(bundle);
            if !out.status.success() {
                return Err(format!(
                    "checking out {}: {}",
                    c.repo,
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
        }
        let label = format!("{LABEL_PROJECT}={}", req.project);
        for v in req.spec.services.values().flat_map(|s| s.volumes.keys()) {
            let name = format!("{}-{v}", network(req.project));
            self.podman(&["volume", "create", "--ignore", "--label", &label, &name])?;
        }
        private_dir(&self.env_dir)?;
        for name in order {
            let s = &req.spec.services[name];
            let image = match (&s.image, &s.build) {
                (Some(i), _) => i.clone(),
                (None, Some(b)) => {
                    let tag = format!("localhost/{}-{name}:{}", network(req.project), req.run);
                    let repo = run_dir.join("repos").join(&b.repo);
                    let file = repo.join(b.dockerfile.as_deref().unwrap_or("Dockerfile"));
                    let ctx = repo.join(b.context.as_deref().unwrap_or("."));
                    let (file, ctx) = (file.display().to_string(), ctx.display().to_string());
                    if let Err(e) = self.podman(&["build", "-q", "-t", &tag, "-f", &file, &ctx]) {
                        return Ok(failed(req, name, format!("{name} did not build: {e}")));
                    }
                    tag
                }
                (None, None) => return Err(format!("{name} has no image")),
            };
            if let Err(e) = self.create(req, name, s, &image, &run_dir) {
                return Ok(failed(req, name, format!("{name} did not start: {e}")));
            }
            if let Err(why) = self.wait_ready(req, name, s.health.is_some()) {
                return Ok(failed(req, name, why));
            }
        }
        // A crash right after start shows here rather than at the next status.
        std::thread::sleep(Duration::from_secs(2));
        self.status(&req.run, req.project)
    }

    /// `podman create` with the env in a private file removed right after, then `podman start`.
    fn create(
        &self,
        req: &RunStart,
        name: &str,
        s: &RunService,
        image: &str,
        run_dir: &Path,
    ) -> Result<(), String> {
        let env = if s.env.is_empty() {
            None
        } else {
            let path = self.env_dir.join(format!("{}-{name}.env", req.run));
            let file = EnvFile(path.clone());
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| format!("writing the env file: {e}"))?;
            for (k, v) in &s.env {
                writeln!(f, "{k}={v}").map_err(|e| format!("writing the env file: {e}"))?;
            }
            Some(file)
        };
        let args = create_args(
            &req.run,
            req.project,
            name,
            s,
            image,
            req.limits,
            env.as_ref().map(|e| e.0.as_path()),
            run_dir,
        );
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.podman(&args)?;
        drop(env);
        self.podman(&["start", &container(&req.run, name)])
            .map(drop)
    }

    /// Running, and (with a health check) healthy within [`HEALTH_WAIT`]; `Err` names the service.
    fn wait_ready(&self, req: &RunStart, name: &str, health: bool) -> Result<(), String> {
        let ctr = container(&req.run, name);
        let deadline = Instant::now() + HEALTH_WAIT;
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let state = self
                .podman(&[
                    "inspect",
                    "--format",
                    "{{.State.Status}} {{.State.ExitCode}}",
                    &ctr,
                ])
                .map_err(|e| format!("{name}: {e}"))?;
            let mut f = state.split_whitespace();
            match (f.next(), f.next()) {
                (Some("running"), _) => {}
                (Some(s), code) => {
                    return Err(format!("{name} is {s} (exit code {})", code.unwrap_or("?")));
                }
                (None, _) => return Err(format!("{name} is gone")),
            }
            if !health || self.podman(&["healthcheck", "run", &ctr]).is_ok() {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "{name} did not turn healthy in {}s",
                    HEALTH_WAIT.as_secs()
                ));
            }
        }
    }
}
