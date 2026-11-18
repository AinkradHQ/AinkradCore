//! The sandbox one design job runs in (the security model is in `design.rs`): the command
//! (systemd scope, bubblewrap, seccomp, limits script), the probe, the outcome, the job directory.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use ainkrad_proto::v2::{ErrorCode, StreamError};
use tokio::io::AsyncReadExt;

use super::{DesignConfig, MAX_STDOUT, failed, seccomp};

/// Marks that the sandbox is up and the limits are set: anything that fails before it is the
/// sandbox's failure, not the job's.
const STARTED: &str = "ainkrad-design: started";
/// Kernel task cap of a job's scope.
const TASKS_MAX: u32 = 256;
/// Bytes of `/out` (a tmpfs): Chromium's screenshot and nothing else.
const OUT_BYTES: u64 = 8 << 20;
const BWRAP: &str = "/usr/bin/bwrap";

/// Sets the limits, then becomes the program: `$1` seconds of CPU, `$2` KiB of address space.
const LIMITS: &str = "ulimit -S -t \"$1\" && ulimit -H -t \"$1\" && ulimit -S -f 65536 && ulimit -H -f 65536 \
    && ulimit -S -c 0 && ulimit -H -c 0 && ulimit -S -v \"$2\" && ulimit -H -v \"$2\" || exit 125; shift 2; \
    echo 'ainkrad-design: started' >&2; exec \"$@\"";

/// A finished run as its answer: stdout on success; `spawn_failed` when the sandbox never reached
/// the helper (no `STARTED` line, or the limits could not be set); `design_failed` otherwise.
pub(super) fn outcome(
    stopped: Result<i32, &str>,
    out: Vec<u8>,
    err: &[u8],
) -> Result<Vec<u8>, StreamError> {
    let err = String::from_utf8_lossy(err);
    let started = err.lines().any(|l| l == STARTED);
    let first = |text: &str| -> String {
        let l = text.lines().find(|l| !l.trim().is_empty() && *l != STARTED);
        l.unwrap_or("").chars().take(200).collect()
    };
    let why = match stopped {
        Ok(0) if out.len() <= MAX_STDOUT => return Ok(out),
        Ok(0) => "its answer was too large".to_owned(),
        Ok(_) if !started => {
            return Err(StreamError::new(
                ErrorCode::SpawnFailed,
                format!("the design sandbox did not start: {}", first(&err)),
            ));
        }
        Ok(code) => format!("it exited with status {code}"),
        Err(why) => why.to_owned(),
    };
    let after = err.split_once(STARTED).map_or("", |(_, a)| a);
    Err(failed(&format!(
        "the design helper failed: {why}. {}",
        first(after)
    )))
}

/// The whole command for one job: `systemd-run --user --scope` when configured, then bubblewrap
/// with the seccomp filter on an inherited descriptor, then the limits script and `program`. The
/// returned file holds that descriptor open until the spawn.
pub(super) fn command(
    cfg: &DesignConfig,
    job: &Job,
    program: &Path,
    args: &[String],
    bind: Option<&Path>,
    vm: Option<u64>,
) -> std::io::Result<(std::process::Command, std::fs::File)> {
    use std::os::fd::AsRawFd;
    let bpf =
        seccomp::program().ok_or_else(|| std::io::Error::other("no seccomp table for this CPU"))?;
    let path = job.dir.join("seccomp.bpf");
    std::fs::write(&path, bpf)?;
    let filter = std::fs::File::open(&path)?;
    let fd = filter.as_raw_fd();
    let mut c = if cfg.scope {
        let mut c = std::process::Command::new("systemd-run");
        c.args(["--user", "--scope", "--quiet", "--collect", "-p"])
            .arg(format!("MemoryMax={}", cfg.max_rss))
            .args(["-p", &format!("TasksMax={TASKS_MAX}"), "--", BWRAP]);
        c
    } else {
        std::process::Command::new(BWRAP)
    };
    c.env_clear();
    // systemd-run finds the user manager through these; bubblewrap clears them for the job.
    for k in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
        if let Some(v) = std::env::var_os(k).filter(|_| cfg.scope) {
            c.env(k, v);
        }
    }
    ainkrad_sys::close_fds_on_exec(&mut c);
    ainkrad_sys::sandbox_child(&mut c, Some(fd));
    c.args(sandbox_args(&job.dir, bind))
        .args(["--seccomp", &fd.to_string(), "--"])
        .args(["/bin/bash", "-c", LIMITS, "design"])
        .arg(cfg.timeout.as_secs().max(1).to_string())
        .arg(vm.map_or("unlimited".to_owned(), |v| (v / 1024).to_string()))
        .arg(program)
        .args(args);
    Ok((c, filter))
}

/// Whether this exact sandbox (scope, bubblewrap flags and the helper's bind, seccomp, limits
/// script) runs `/bin/true`.
pub(super) fn probe(cfg: &DesignConfig) -> bool {
    let Ok(job) = Job::new() else { return false };
    let Ok((mut c, _filter)) = command(
        cfg,
        &job,
        Path::new("/bin/true"),
        &[],
        Some(&cfg.helper),
        Some(cfg.max_vm),
    ) else {
        return false;
    };
    let out = c
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output();
    out.is_ok_and(|o| {
        o.status.success()
            && String::from_utf8_lossy(&o.stderr)
                .lines()
                .any(|l| l == STARTED)
    })
}

/// Removes job directories older than `age` that a crashed runner left in `tmp`.
pub(super) fn sweep(tmp: &Path, age: Duration) {
    let Ok(dir) = std::fs::read_dir(tmp) else {
        return;
    };
    for e in dir.flatten() {
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .is_ok_and(|t| t.elapsed().is_ok_and(|d| d > age));
        let ours = e
            .file_name()
            .to_str()
            .is_some_and(|n| n.starts_with("ainkrad-design-"));
        if ours && old && e.file_type().is_ok_and(|t| t.is_dir()) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// The bubblewrap arguments for a job in `dir`; `bind`'s directory is bound read-only where it lies
/// (the helper, or Chromium and the files beside it).
pub(super) fn sandbox_args(dir: &Path, bind: Option<&Path>) -> Vec<String> {
    let mut a: Vec<String> = [
        "--die-with-parent",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/etc/fonts",
        "/etc/fonts",
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        "268435456",
        "--tmpfs",
        "/tmp",
        "--size",
        "67108864",
        "--tmpfs",
        "/dev/shm",
    ]
    .map(str::to_owned)
    .to_vec();
    // Merged /usr: /lib, /bin are links into it; elsewhere, directories of their own.
    for d in ["/bin", "/sbin", "/lib", "/lib64", "/lib32"] {
        let p = Path::new(d);
        match std::fs::read_link(p) {
            Ok(t) => a.extend([
                "--symlink".into(),
                t.to_string_lossy().into_owned(),
                d.into(),
            ]),
            Err(_) if p.is_dir() => a.extend(["--ro-bind".into(), d.into(), d.into()]),
            Err(_) => {}
        }
    }
    if let Some(home) = bind
        .and_then(Path::parent)
        .filter(|p| !p.starts_with("/usr"))
    {
        let h = home.to_string_lossy().into_owned();
        a.extend(["--ro-bind".into(), h.clone(), h]);
    }
    let path = |s: &str| dir.join(s).to_string_lossy().into_owned();
    a.extend([
        "--ro-bind".into(),
        path("in"),
        "/in".into(),
        "--size".into(),
        OUT_BYTES.to_string(),
        "--tmpfs".into(),
        "/out".into(),
        "--remount-ro".into(),
        "/".into(),
        "--chdir".into(),
        "/tmp".into(),
    ]);
    a
}

/// A job's private directory (`in/`, the seccomp program), removed when dropped.
pub(super) struct Job {
    pub(super) dir: PathBuf,
}

impl Job {
    pub(super) fn new() -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let name: String = crate::v2::key::random::<12>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let dir = std::env::temp_dir().join(format!("ainkrad-design-{name}"));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let job = Self { dir };
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(job.dir.join("in"))?;
        Ok(job)
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Resident bytes of `root` and every process below it (from `/proc`, outside the sandbox).
pub(super) fn tree_rss(root: u32) -> u64 {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return 0;
    };
    let mut kids: Vec<(u32, u32, u64)> = Vec::new();
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(e.path().join("status")) else {
            continue;
        };
        let field = |k: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(k))
                .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
        };
        if let Some(ppid) = field("PPid:") {
            kids.push((pid, ppid as u32, field("VmRSS:").unwrap_or(0) * 1024));
        }
    }
    let mut tree = vec![root];
    let mut i = 0;
    while i < tree.len() {
        let p = tree[i];
        tree.extend(kids.iter().filter(|k| k.1 == p).map(|k| k.0));
        i += 1;
    }
    kids.iter()
        .filter(|k| tree.contains(&k.0))
        .map(|k| k.2)
        .sum()
}

pub(super) async fn read_capped(
    pipe: Option<impl tokio::io::AsyncRead + Unpin>,
    cap: usize,
) -> Vec<u8> {
    let mut kept = Vec::new();
    let Some(mut pipe) = pipe else { return kept };
    let mut buf = [0u8; 16384];
    while let Ok(n @ 1..) = pipe.read(&mut buf).await {
        // One byte past the cap marks "too large"; the rest is drained so the child never blocks.
        let room = (cap + 1).saturating_sub(kept.len()).min(n);
        kept.extend_from_slice(&buf[..room]);
    }
    kept
}
