//! A run's preparation, before any container: its checkouts (sized before the work tree is
//! written), its builds (confined to the run's own checkout, capped like its containers), and the
//! one way the helper runs a child process (own timeout, own process group, dies with the helper).

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use ainkrad_proto::v2::{RunBuild, RunStart};

use super::{BUILD_MAX, CLONE_MAX, Engine, QUICK, network};

/// `rel` under `repo` with every symlink resolved: `Err` unless it stays inside the repo (a
/// committed symlink must not hand the build another project's files or the image store).
pub fn inside(repo: &Path, rel: &str) -> Result<PathBuf, String> {
    let root = repo
        .canonicalize()
        .map_err(|e| format!("{}: {e}", repo.display()))?;
    let p = root
        .join(rel)
        .canonicalize()
        .map_err(|e| format!("{rel}: {e}"))?;
    if p.starts_with(&root) {
        Ok(p)
    } else {
        Err(format!("{rel} leads outside the repo"))
    }
}

/// Bytes under `p`, symlinks not followed.
pub(super) fn du(p: &Path) -> u64 {
    let Ok(m) = std::fs::symlink_metadata(p) else {
        return 0;
    };
    if !m.is_dir() {
        return m.len();
    }
    std::fs::read_dir(p)
        .map(|rd| rd.flatten().map(|e| du(&e.path())).sum())
        .unwrap_or(0)
}

/// What is left of `deadline`, at most `cap`.
pub(super) fn left(deadline: Instant, cap: Duration) -> Duration {
    cap.min(deadline.saturating_duration_since(Instant::now()))
}

/// Runs `cmd` in its own process group, killed with the helper (`PR_SET_PDEATHSIG`) and, as a
/// group, when `timeout` passes: its stdout, or its stderr as the reason.
pub(super) fn exec(mut cmd: Command, what: &str, timeout: Duration) -> Result<String, String> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    ainkrad_sys::die_with_parent(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| format!("{what}: {e}"))?;
    let read = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut v = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut v);
            }
            v
        })
    };
    let out = read(child.stdout.take().map(|r| Box::new(r) as _));
    let err = read(child.stderr.take().map(|r| Box::new(r) as _));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            other => {
                // Not reaped yet, so the group id is still ours to signal.
                if let Some(kill) = ainkrad_sys::signal_number("KILL") {
                    let _ = ainkrad_sys::killpg(child.id(), kill);
                }
                let _ = child.wait();
                return Err(match other {
                    Err(e) => format!("{what}: {e}"),
                    _ => format!("{what} did not finish in {}s", timeout.as_secs()),
                });
            }
        }
    };
    let out = out.join().unwrap_or_default();
    if status.success() {
        return Ok(String::from_utf8_lossy(&out).into_owned());
    }
    let err = err.join().unwrap_or_default();
    let err: String = String::from_utf8_lossy(&err)
        .trim()
        .chars()
        .take(400)
        .collect();
    Err(format!("{what}: {err}"))
}

/// `git`, with no inherited environment or config.
fn git() -> Command {
    let mut c = Command::new("git");
    c.env_clear().env("PATH", "/usr/local/bin:/usr/bin:/bin");
    c
}

impl Engine {
    /// Clones `bundle` to `dest` without a work tree, adds its `.git` and the size of the tree it
    /// would write to `used`, refuses past `checkout_cap`, and only then writes the tree.
    pub(super) fn checkout(
        &self,
        bundle: &Path,
        dest: &Path,
        used: &mut u64,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut clone = git();
        clone
            .args(["clone", "--no-checkout", "--no-hardlinks", "-q"])
            .arg(bundle)
            .arg(dest);
        exec(clone, "git clone", left(deadline, CLONE_MAX))?;
        let mut tree = git();
        tree.arg("-C")
            .arg(dest)
            .args(["ls-tree", "-r", "-l", "--full-tree", "HEAD"]);
        let tree = exec(tree, "git ls-tree", left(deadline, QUICK))?;
        // `<mode> <type> <object> <size>\t<path>`; a submodule's size is `-`.
        let files: u64 = tree
            .lines()
            .filter_map(|l| l.split_whitespace().nth(3)?.parse::<u64>().ok())
            .sum();
        *used = used.saturating_add(du(dest)).saturating_add(files);
        if *used > self.checkout_cap {
            return Err(format!(
                "the run's checkouts take more than {} MiB",
                self.checkout_cap >> 20
            ));
        }
        let mut reset = git();
        reset
            .arg("-C")
            .arg(dest)
            .args(["reset", "-q", "--hard", "HEAD"]);
        exec(reset, "git reset", left(deadline, CLONE_MAX)).map(drop)
    }

    /// Builds service `name` from its repo in the project's own store, capped like its containers;
    /// the build's processes live in a user slice of their own (its pids cap), stopped when the
    /// build ends. Its `TMPDIR` is the run's own (`RUN --mount=type=cache` keeps its cache there).
    pub(super) fn build(
        &self,
        req: &RunStart,
        name: &str,
        b: &RunBuild,
        repos: &Path,
        deadline: Instant,
    ) -> Result<String, String> {
        let repo = repos.join(&b.repo);
        let ctx = inside(&repo, b.context.as_deref().unwrap_or("."))?;
        let file = inside(&repo, b.dockerfile.as_deref().unwrap_or("Dockerfile"))?;
        let (ctx, file) = (ctx.display().to_string(), file.display().to_string());
        let tag = format!("localhost/{}-{name}:{}", network(req.project), req.run);
        let slice = build_slice(&req.run, name);
        // Held while the slice exists: a helper starting meanwhile leaves the slice alone
        // (`reap_build_slices`). Released (and the file gone) only after the slice is stopped.
        let lock_path = self.root.join(format!(".{slice}.lock"));
        let lock = std::fs::File::create(&lock_path).map_err(|e| format!("build lock: {e}"))?;
        lock.lock().map_err(|e| format!("build lock: {e}"))?;
        let tmp = self.root.join(&req.run).join("tmp");
        super::private_dir(&tmp)?;
        let l = req.limits;
        let mem = format!("{}m", l.memory_mb);
        let quota = format!("{:.0}", l.cpus * 100_000.0);
        // No pids cap, no build.
        let capped = self.systemctl(
            &[
                "set-property",
                "--runtime",
                &slice,
                &format!("TasksMax={}", l.pids),
            ],
            deadline,
        );
        let r = capped.and_then(|_| {
            let mut cmd = self.podman_cmd(
                req.project,
                &[
                    "build",
                    "-q",
                    "--pull=always",
                    "--layers=false",
                    "--cgroup-parent",
                    &slice,
                    "--memory",
                    &mem,
                    "--memory-swap",
                    &mem,
                    "--cpu-period",
                    "100000",
                    "--cpu-quota",
                    &quota,
                    "-t",
                    &tag,
                    "-f",
                    &file,
                    &ctx,
                ],
            );
            cmd.env("TMPDIR", &tmp);
            exec(cmd, "podman build", left(deadline, BUILD_MAX))
        });
        // Whatever the build left in its slice dies with it; a cleanup gets its own short time.
        let cleanup = Instant::now() + QUICK;
        let _ = self.systemctl(&["stop", &slice], cleanup);
        let _ = self.systemctl(&["revert", &slice], cleanup);
        let _ = std::fs::remove_file(&lock_path);
        drop(lock);
        r.map(|_| tag)
    }

    /// Build slices a dead helper left behind (no build holds their lock): stopped and reverted,
    /// so their processes go. Called when the helper starts.
    pub fn reap_build_slices(&self) {
        let deadline = Instant::now() + QUICK;
        let Ok(units) = self.systemctl(
            &[
                "list-units",
                "--all",
                "--plain",
                "--no-legend",
                "ainkradbuild_*.slice",
            ],
            deadline,
        ) else {
            return;
        };
        for slice in units.lines().filter_map(|l| l.split_whitespace().next()) {
            if !stale_slice(&self.root, slice) {
                continue;
            }
            let _ = self.systemctl(&["stop", slice], deadline);
            let _ = self.systemctl(&["revert", slice], deadline);
        }
    }
}

/// One build's user slice: hex, because `-` in a slice name means nesting.
pub(super) fn build_slice(run: &str, service: &str) -> String {
    let hex: String = format!("{run}/{service}")
        .bytes()
        .map(|c| format!("{c:02x}"))
        .collect();
    format!("ainkradbuild_{hex}.slice")
}

/// An `ainkradbuild_*.slice` whose build lock under `root` is not held (or gone).
pub(super) fn stale_slice(root: &Path, slice: &str) -> bool {
    if !slice.starts_with("ainkradbuild_") || !slice.ends_with(".slice") || slice.contains('/') {
        return false;
    }
    match std::fs::File::open(root.join(format!(".{slice}.lock"))) {
        Ok(f) => f.try_lock().is_ok(),
        Err(_) => true,
    }
}
