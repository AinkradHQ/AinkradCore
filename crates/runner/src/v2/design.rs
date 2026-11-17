//! The `design` driver (Design V6-01, plan T7): `design.render`, `design.measure`, `design.review` and
//! `design.check` run the `ainkrad-design` helper (CPU Skia); `design.shot` runs headless Chromium.
//!
//! Security model. Library fonts, images, SVG and HTML are untrusted, and so is a design document:
//! a parser bug in Skia, FreeType or Blink must cost one job, never the runner or the host. So:
//! - The runner never parses a job's files. It writes the job into a fresh 0700 directory and starts
//!   the helper (or Chromium) in bubblewrap: every namespace unshared, **no network** (an empty
//!   network namespace), no capabilities, no nested user namespace, an empty environment, a
//!   read-only root of `/usr` and font config only, the job at `/in` **read-only**, `/out` and a
//!   small `/tmp` the only writable places. The runner's state, keys and HOME are not there.
//! - Limits: 60 s of wall clock and of CPU, 1 GiB resident for the whole process tree (watched from
//!   outside, so a renderer that forks is counted), 2 GiB of address space for the helper, 64 MiB
//!   per written file, and at most 2 jobs at once (`busy` past that).
//! - Whatever it prints is data: parsed into the one reply type the op allows, size-capped. A
//!   failure, crash or limit is the error `design_failed`; nothing of the job survives it.
//! - Linux only (bubblewrap); the driver is not offered when the sandbox does not start.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_proto::v2::{
    Command, DESIGN_MAX_FILES, DESIGN_MAX_INPUT, DESIGN_MAX_PIXELS, DESIGN_MAX_PNG,
    DESIGN_MAX_SIDE, DesignShot, DriverInfo, ErrorCode, OP_DESIGN_CHECK, OP_DESIGN_MEASURE,
    OP_DESIGN_RENDER, OP_DESIGN_REVIEW, OP_DESIGN_SHOT, Reply, StreamError,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::AsyncReadExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

pub const DRIVER: &str = "design";
const BWRAP: &str = "/usr/bin/bwrap";
/// Where an installed runner finds them (`deploy/install-linux.sh`).
const HELPER: &str = "/usr/local/bin/ainkrad-design";
const CHROMIUM: &str = "/usr/local/lib/ainkrad-chromium/chrome-headless-shell";
/// What the helper may print: a PNG in base64 plus its JSON.
const MAX_STDOUT: usize = DESIGN_MAX_PNG / 3 * 4 + (1 << 20);

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

impl DesignDriver {
    pub fn new(config: DesignConfig) -> Self {
        let slots = Arc::new(Semaphore::new(config.capacity as usize));
        Self { config, slots }
    }

    /// The driver when this host has the helper and a working sandbox; `None` otherwise.
    pub fn discover() -> Option<Self> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let helper = find("AINKRAD_DESIGN_HELPER", "ainkrad-design", HELPER)?;
        let chromium = find("AINKRAD_CHROMIUM", "chrome-headless-shell", CHROMIUM);
        let ok = std::process::Command::new(BWRAP)
            .args(["--unshare-all", "--ro-bind", "/", "/", "true"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            tracing::warn!(
                "design helper found, but bubblewrap does not start: design ops are off"
            );
            return None;
        }
        Some(Self::new(DesignConfig::new(helper, chromium)))
    }

    pub fn info(&self) -> DriverInfo {
        let mut commands = [
            OP_DESIGN_RENDER,
            OP_DESIGN_MEASURE,
            OP_DESIGN_REVIEW,
            OP_DESIGN_CHECK,
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
                (chromium.clone(), shot_args(s, &job)?, None)
            }
            Command::DesignRender(_)
            | Command::DesignMeasure(_)
            | Command::DesignReview(_)
            | Command::DesignCheck(_) => {
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
        let out = self.sandboxed(&job, &program, &args, vm, cancel).await?;
        reply(command, &out, &job)
    }

    /// Runs `program args` in the sandbox: its stdout when it exited 0.
    async fn sandboxed(
        &self,
        job: &Job,
        program: &Path,
        args: &[String],
        vm: Option<u64>,
        cancel: oneshot::Receiver<()>,
    ) -> Result<Vec<u8>, StreamError> {
        let mut c = tokio::process::Command::new(BWRAP);
        ainkrad_sys::close_fds_on_exec(c.as_std_mut());
        c.args(sandbox_args(&job.dir, program))
            .arg("--")
            .args(["/bin/bash", "-c", LIMITS, "design"])
            .arg(self.config.timeout.as_secs().max(1).to_string())
            .arg(vm.map_or("unlimited".to_owned(), |v| (v / 1024).to_string()))
            .arg(program)
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
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
                () = &mut deadline => break Err("it ran past its time limit"),
                _ = &mut cancel => {
                    let _ = child.start_kill();
                    let _ = child.wait().await;
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
        let out = stdout.await.unwrap_or_default();
        let err = stderr.await.unwrap_or_default();
        let why = match stopped {
            Ok(0) if out.len() <= MAX_STDOUT => return Ok(out),
            Ok(0) => "its answer was too large".to_owned(),
            Ok(125) => "the sandbox limits could not be set".to_owned(),
            Ok(code) => format!("it exited with status {code}"),
            Err(why) => why.to_owned(),
        };
        let detail = String::from_utf8_lossy(&err);
        let detail = detail.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
        let detail: String = detail.chars().take(200).collect();
        Err(failed(&format!(
            "the design helper failed: {why}. {detail}"
        )))
    }
}

/// Sets the limits, then becomes the program: `$1` seconds of CPU, `$2` KiB of address space.
const LIMITS: &str = "ulimit -S -t \"$1\" && ulimit -H -t \"$1\" && ulimit -S -f 65536 && ulimit -H -f 65536 \
    && ulimit -S -c 0 && ulimit -H -c 0 && ulimit -S -v \"$2\" && ulimit -H -v \"$2\" || exit 125; shift 2; exec \"$@\"";

/// The bubblewrap arguments for a job in `dir` running `program` (bound read-only where it lies).
fn sandbox_args(dir: &Path, program: &Path) -> Vec<String> {
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
    if let Some(home) = program.parent().filter(|p| !p.starts_with("/usr")) {
        let h = home.to_string_lossy().into_owned();
        a.extend(["--ro-bind".into(), h.clone(), h]);
    }
    let path = |s: &str| dir.join(s).to_string_lossy().into_owned();
    a.extend([
        "--ro-bind".into(),
        path("in"),
        "/in".into(),
        "--bind".into(),
        path("out"),
        "/out".into(),
        "--remount-ro".into(),
        "/".into(),
        "--chdir".into(),
        "/tmp".into(),
    ]);
    a
}

/// A job's private directory (`in/`, `out/`), removed when dropped.
struct Job {
    dir: PathBuf,
}

impl Job {
    fn new() -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let name: String = super::key::random::<12>()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let dir = std::env::temp_dir().join(format!("ainkrad-design-{name}"));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        let job = Self { dir };
        for s in ["in", "out"] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(job.dir.join(s))?;
        }
        Ok(job)
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A `design.shot` site path: relative, plain segments, no NUL or backslash.
fn path_ok(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 512
        && !p.starts_with('/')
        && !p.contains(['\0', '\\'])
        && p.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

/// Writes the site under `in/site` and answers Chromium's arguments.
fn shot_args(s: &DesignShot, job: &Job) -> Result<Vec<String>, StreamError> {
    let bad = |m: &str| StreamError::new(ErrorCode::InvalidArgs, m);
    if s.files.is_empty() || s.files.len() > DESIGN_MAX_FILES {
        return Err(bad("a shot has 1 to 200 files"));
    }
    let (w, h) = (s.width, s.height);
    let px = |v: u32| (f64::from(v) * f64::from(s.scale)).round() as u64;
    if !(0.25..=4.0).contains(&s.scale)
        || !(1..=4096).contains(&w)
        || !(1..=4096).contains(&h)
        || px(w) > u64::from(DESIGN_MAX_SIDE)
        || px(h) > u64::from(DESIGN_MAX_SIDE)
        || px(w) * px(h) > DESIGN_MAX_PIXELS
    {
        return Err(bad("the shot size is out of range"));
    }
    if !path_ok(&s.entry) || !s.files.iter().any(|f| f.path == s.entry) {
        return Err(bad("the entry must be one of the files"));
    }
    let site = job.dir.join("in/site");
    for f in &s.files {
        if !path_ok(&f.path) {
            return Err(bad(
                "a file path must be relative, without `..`, NUL or `\\`",
            ));
        }
        let bytes = STANDARD
            .decode(&f.data)
            .map_err(|_| bad("a file is not base64"))?;
        let to = site.join(&f.path);
        if let Some(d) = to.parent() {
            std::fs::create_dir_all(d).map_err(|e| internal(&e))?;
        }
        // `create_new`: two files with one path, or a file over a directory, is refused.
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&to)
            .and_then(|mut o| std::io::Write::write_all(&mut o, &bytes))
            .map_err(|_| bad("two files have the same path"))?;
    }
    let url: String = s
        .entry
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    Ok([
        "--headless",
        "--no-sandbox",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-sync",
        "--hide-scrollbars",
        "--mute-audio",
        "--user-data-dir=/tmp/profile",
        "--virtual-time-budget=3000",
        "--screenshot=/out/shot.png",
    ]
    .map(str::to_owned)
    .into_iter()
    .chain([
        format!("--window-size={w},{h}"),
        format!("--force-device-scale-factor={}", s.scale),
        format!("file:///in/site/{url}"),
    ])
    .collect())
}

/// The helper's stdout (or Chromium's PNG) as the op's one reply type.
fn reply(command: &Command, out: &[u8], job: &Job) -> Result<Reply, StreamError> {
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
        Command::DesignShot(_) => {
            let png = std::fs::read(job.dir.join("out/shot.png"))
                .map_err(|_| failed("Chromium wrote no screenshot"))?;
            let (width, height) =
                png_size(&png).ok_or_else(|| failed("the screenshot is not a PNG"))?;
            let i = ainkrad_proto::v2::DesignImage {
                png: STANDARD.encode(&png),
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

/// Width and height from a PNG's IHDR.
fn png_size(b: &[u8]) -> Option<(u32, u32)> {
    if b.len() < 24 || !b.starts_with(b"\x89PNG\r\n\x1a\n") || &b[12..16] != b"IHDR" {
        return None;
    }
    let n = |i: usize| u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
    Some((n(16), n(20)))
}

/// Resident bytes of `root` and every process below it (from `/proc`, outside the sandbox).
fn tree_rss(root: u32) -> u64 {
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

async fn read_capped(pipe: Option<impl tokio::io::AsyncRead + Unpin>, cap: usize) -> Vec<u8> {
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

fn failed(m: &str) -> StreamError {
    StreamError::new(ErrorCode::DesignFailed, m)
}

fn internal(e: &dyn std::fmt::Display) -> StreamError {
    StreamError::new(ErrorCode::Internal, format!("design job: {e}"))
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
