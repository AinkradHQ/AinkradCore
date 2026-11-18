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
//!   checkout, read-only at `/repo/<name>`;
//! - every project runs as the same `ainkrad-run` uid, so nothing a project controls may name a path
//!   or an image on the host: a spec image is a registry image ([`ainkrad_proto::v2::image_ok`]),
//!   the build context and Dockerfile must resolve (symlinks included) inside the run's own
//!   checkout, builds pull their base images (`--pull=always`, never another project's build) and
//!   keep no shared layer cache, and a run's built images are removed when it stops;
//! - each project has its own Podman store (`--root`/`--runroot` under [`Engine::projects`]), so a
//!   Dockerfile's `FROM containers-storage:…`, `COPY --from` or `RUN --mount=from=` finds only that
//!   project's images, and each build has its own `TMPDIR` (the `RUN --mount=type=cache` dir);
//! - builds get the project's caps (memory, swap, CPU, and its pids in a per-build user slice),
//!   every child (`git`, `podman`) has its own timeout, its own process group killed on timeout,
//!   and dies with the helper (`PR_SET_PDEATHSIG`); the whole start fits in [`START_BUDGET`], and
//!   the cleanup of a failed one in [`CLEANUP_BUDGET`], both inside the unit's `RuntimeMaxSec`;
//! - container logs are capped (`k8s-file`, 10 MiB);
//! - checkouts are capped in number (16) and in bytes on disk ([`MAX_CHECKOUT_BYTES`]), measured
//!   before the work tree is written;
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

use ainkrad_proto::v2::{RunInfo, RunLimits, RunPhase, RunService, RunStart};

pub mod helper;
mod prepare;
mod ps;
mod state;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_review2;

pub use prepare::inside;
use prepare::{exec, left};
pub use ps::runs_from_ps;

const LABEL_PROJECT: &str = "ainkrad.project";
const LABEL_RUN: &str = "ainkrad.run";
const LABEL_SERVICE: &str = "ainkrad.service";
/// How long a service with a health check has to turn healthy.
const HEALTH_WAIT: Duration = Duration::from_secs(120);
/// A whole start: below the helper unit's `RuntimeMaxSec=1800`, so the cleanup of a failed one fits.
pub const START_BUDGET: Duration = Duration::from_secs(1500);
/// A stop (the cleanup of a failed start included): every podman call of it within this.
/// `START_BUDGET + CLEANUP_BUDGET` stays below `RuntimeMaxSec` (a test reads the unit).
pub const CLEANUP_BUDGET: Duration = Duration::from_secs(240);
/// Each child's own cap (within what is left of [`START_BUDGET`]).
const QUICK: Duration = Duration::from_secs(60);
const CLONE_MAX: Duration = Duration::from_secs(300);
const BUILD_MAX: Duration = Duration::from_secs(900);
/// `podman create` pulls a missing image.
const CREATE_MAX: Duration = Duration::from_secs(600);
/// All checkouts of one run on disk: `.git` plus the work tree, measured before it is written.
pub const MAX_CHECKOUT_BYTES: u64 = 8 << 30;

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
    /// Each project's own Podman store: `<projects>/<project>/storage` (`--root`) and `…/runroot`
    /// (`--runroot`). Images, containers and volumes of one project are not in another's store.
    pub projects: PathBuf,
    /// Network definitions (`--network-config-dir`), shared so every project network gets its own
    /// subnet; the names are the helper's own (`ainkrad-p<id>`).
    pub networks: PathBuf,
    /// Env files, briefly: a private tmpfs dir.
    pub env_dir: PathBuf,
    /// The user's runtime dir, given to Podman as `XDG_RUNTIME_DIR` (with its bus); `None` keeps
    /// the caller's environment.
    pub runtime_dir: Option<PathBuf>,
    /// [`MAX_CHECKOUT_BYTES`], lower in tests.
    pub checkout_cap: u64,
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
        // Logs live in the project's store; capped so a chatty service cannot fill the disk.
        // (Podman's k8s-file truncates at max-size; max-file is passed for drivers that rotate.)
        "--log-driver",
        "k8s-file",
        "--log-opt",
        "max-size=10m",
        "--log-opt",
        "max-file=2",
        "--pull",
        // A build's own tag is never pulled; a registry image is, when missing.
        if s.build.is_some() {
            "never"
        } else {
            "missing"
        },
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
            format!("{}:/repo/{r}:ro", run_dir.join("repos").join(r).display()),
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
    /// The helper's: `$HOME/runs`, stores in `$HOME/projects`; env files in `/run/user/<uid>` (tmpfs), its own uid's (a unit
    /// cannot name another user's uid with a specifier, so it is not taken from the environment).
    pub fn from_env() -> Result<Self, String> {
        let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
        let runtime = PathBuf::from(format!("/run/user/{}", ainkrad_sys::getuid()));
        Ok(Self {
            podman: "podman".to_owned(),
            root: PathBuf::from(&home).join("runs"),
            projects: PathBuf::from(&home).join("projects"),
            networks: PathBuf::from(&home).join("networks"),
            env_dir: runtime.join("ainkrad-env"),
            runtime_dir: Some(runtime),
            checkout_cap: MAX_CHECKOUT_BYTES,
        })
    }

    /// `prog`, with the user's runtime dir and bus when set.
    fn user_cmd(&self, prog: &str) -> Command {
        let mut cmd = Command::new(prog);
        if let Some(r) = &self.runtime_dir {
            cmd.env("XDG_RUNTIME_DIR", r).env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", r.join("bus").display()),
            );
        }
        cmd
    }

    /// `podman <store of project> args…`, not run yet.
    fn podman_cmd(&self, project: u64, args: &[&str]) -> Command {
        let mut cmd = self.user_cmd(&self.podman);
        cmd.args(self.store_args(project)).args(args);
        cmd
    }

    /// `podman args…` in `project`'s store within `timeout`: its stdout, or its stderr as the reason.
    fn podman_t(&self, project: u64, args: &[&str], timeout: Duration) -> Result<String, String> {
        exec(
            self.podman_cmd(project, args),
            &format!("podman {}", args.first().unwrap_or(&"")),
            timeout,
        )
    }

    /// A quick podman call, within what is left of `deadline`.
    fn podman(&self, project: u64, args: &[&str], deadline: Instant) -> Result<String, String> {
        self.podman_t(project, args, left(deadline, QUICK))
    }

    /// `systemctl --user args…` (the user's manager: build slices), within what is left of `deadline`.
    fn systemctl(&self, args: &[&str], deadline: Instant) -> Result<String, String> {
        let mut cmd = self.user_cmd("systemctl");
        cmd.arg("--user").args(args);
        exec(cmd, "systemctl", left(deadline, QUICK))
    }

    /// The project's network, isolated from every other (`--opt isolate=true`). One that exists
    /// without isolation is refused, never used.
    fn ensure_network(&self, project: u64, deadline: Instant) -> Result<(), String> {
        let n = network(project);
        if let Ok(json) = self.podman(project, &["network", "inspect", &n], deadline) {
            let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
            return match v[0]["options"]["isolate"].as_str() {
                Some("true") => Ok(()),
                _ => Err(format!(
                    "network {n} exists without isolate=true; refusing to use it"
                )),
            };
        }
        let label = format!("{LABEL_PROJECT}={project}");
        self.podman(
            project,
            &[
                "network",
                "create",
                "--opt",
                "isolate=true",
                "--label",
                &label,
                &n,
            ],
            deadline,
        )
        .map(drop)
    }

    /// Starts `req` (secrets already in its env). `bundles` are the checkouts, as git bundles, by
    /// repo. A service that fails to build, start or turn healthy answers `Failed` naming it; a
    /// start that fails in any way is stopped first, so nothing of it is left.
    pub fn start(
        &self,
        req: &RunStart,
        bundles: &BTreeMap<String, PathBuf>,
    ) -> Result<RunInfo, String> {
        if let Some(p) = req.problem() {
            return Err(p);
        }
        if !self.find(&req.run)?.services.is_empty() {
            return Err(format!("run {} already has containers", req.run));
        }
        let r = self.launch(req, bundles, Instant::now() + START_BUDGET);
        if !matches!(&r, Ok(i) if i.phase != RunPhase::Failed) {
            let _ = self.stop(&req.run);
        }
        r
    }

    fn launch(
        &self,
        req: &RunStart,
        bundles: &BTreeMap<String, PathBuf>,
        deadline: Instant,
    ) -> Result<RunInfo, String> {
        let order = req.spec.start_order().ok_or("a depends_on cycle")?;
        private_dir(&self.projects.join(req.project.to_string()))?;
        private_dir(&self.networks)?;
        if let Some(r) = &self.runtime_dir {
            private_dir(&r.join(network(req.project)))?;
        }
        self.ensure_network(req.project, deadline)?;
        let repos = self.root.join(&req.run).join("repos");
        private_dir(&repos)?;
        let mut used = 0;
        for c in &req.checkouts {
            let bundle = bundles
                .get(&c.repo)
                .ok_or(format!("no checkout for {}", c.repo))?;
            let r = self.checkout(bundle, &repos.join(&c.repo), &mut used, deadline);
            let _ = std::fs::remove_file(bundle);
            r.map_err(|e| format!("checking out {}: {e}", c.repo))?;
        }
        let label = format!("{LABEL_PROJECT}={}", req.project);
        for v in req.spec.services.values().flat_map(|s| s.volumes.keys()) {
            let name = format!("{}-{v}", network(req.project));
            self.podman(
                req.project,
                &["volume", "create", "--ignore", "--label", &label, &name],
                deadline,
            )?;
        }
        // Every image is built before any container starts: no service of the run is up while
        // the project's build steps run.
        let mut images = BTreeMap::new();
        for &name in &order {
            let s = &req.spec.services[name];
            let image = match (&s.image, &s.build) {
                (Some(i), _) => i.clone(),
                (None, Some(b)) => match self.build(req, name, b, &repos, deadline) {
                    Ok(tag) => tag,
                    Err(e) => return Ok(failed(req, name, format!("{name} did not build: {e}"))),
                },
                (None, None) => return Err(format!("{name} has no image")),
            };
            images.insert(name, image);
        }
        private_dir(&self.env_dir)?;
        let run_dir = self.root.join(&req.run);
        for name in order {
            let s = &req.spec.services[name];
            if let Err(e) = self.create(req, name, s, &images[name], &run_dir, deadline) {
                return Ok(failed(req, name, format!("{name} did not start: {e}")));
            }
            if let Err(why) = self.wait_ready(req, name, s.health.is_some(), deadline) {
                return Ok(failed(req, name, why));
            }
        }
        // A crash right after start shows here rather than at the next status.
        std::thread::sleep(Duration::from_secs(2));
        self.status_by(&req.run, req.project, deadline)
    }

    /// `podman create` with the env in a private file removed right after, then `podman start`.
    fn create(
        &self,
        req: &RunStart,
        name: &str,
        s: &RunService,
        image: &str,
        run_dir: &Path,
        deadline: Instant,
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
        self.podman_t(req.project, &args, left(deadline, CREATE_MAX))?;
        drop(env);
        self.podman(
            req.project,
            &["start", &container(&req.run, name)],
            deadline,
        )
        .map(drop)
    }

    /// Running, and (with a health check) healthy within [`HEALTH_WAIT`] and the start's own
    /// deadline (so 16 slow services cannot outlast the helper); `Err` names the service.
    fn wait_ready(
        &self,
        req: &RunStart,
        name: &str,
        health: bool,
        start_deadline: Instant,
    ) -> Result<(), String> {
        let ctr = container(&req.run, name);
        let deadline = start_deadline.min(Instant::now() + HEALTH_WAIT);
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let state = self
                .podman(
                    req.project,
                    &[
                        "inspect",
                        "--format",
                        "{{.State.Status}} {{.State.ExitCode}}",
                        &ctr,
                    ],
                    start_deadline,
                )
                .map_err(|e| format!("{name}: {e}"))?;
            let mut f = state.split_whitespace();
            match (f.next(), f.next()) {
                (Some("running"), _) => {}
                (Some(s), code) => {
                    return Err(format!("{name} is {s} (exit code {})", code.unwrap_or("?")));
                }
                (None, _) => return Err(format!("{name} is gone")),
            }
            if !health
                || self
                    .podman(req.project, &["healthcheck", "run", &ctr], start_deadline)
                    .is_ok()
            {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(format!("{name} did not turn healthy in time"));
            }
        }
    }
}
