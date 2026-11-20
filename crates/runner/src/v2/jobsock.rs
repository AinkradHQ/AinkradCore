//! The heavy-job endpoint (E15-3, spec §5.1): one Unix socket per sandbox, served by the built-in
//! runner, that the `ainkrad-job` shim asks where a command should run.
//!
//! The runner stamps the origin (which terminal or session this socket belongs to) and forwards
//! the request, signed with its own key, to `POST /api/v1/runner/jobs`, which only the built-in
//! runner may call. The Core answers a JSON-lines stream (`{verdict}`, `{t:"state"}`, `{t:"out"}`,
//! `{t:"exit"}`) that this module passes to the shim unchanged. The shim's `{t:"signal"}` and
//! `{t:"cancel"}` frames become `POST /api/v1/runner/jobs/{job}/signal`; a shim that vanishes
//! before the exit cancels the job.
//!
//! A `local` verdict with `report:true` keeps the connection for the shim's `{t:"done",ms,code}`,
//! which goes to `POST /api/v1/runner/jobs/report` (tier 2 learns how long commands take here).
//!
//! Nothing here decides anything: any trouble answers `{verdict:"local"}` and the shim runs the
//! tool itself. The sandbox sees only its own socket's directory (read-only) and the shims.

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::workspace::relay::{Call, Upstream};

/// The commands the shim stands in for (spec §5.1).
pub const SHIM_NAMES: [&str; 21] = [
    "cargo", "go", "npm", "pnpm", "yarn", "bun", "make", "cmake", "ninja", "gradle", "gradlew", "mvn",
    "bazel", "swift", "xcodebuild", "pytest", "tox", "dotnet", "tsc", "vitest", "jest",
];
/// Environment names a request may carry; the shim sends the same list and this side checks again.
pub const ENV_ALLOW: [&str; 11] = [
    "CI",
    "TERM",
    "NO_COLOR",
    "FORCE_COLOR",
    "CARGO_TERM_COLOR",
    "RUST_BACKTRACE",
    "RUST_LOG",
    "RUSTFLAGS",
    "NODE_ENV",
    "GOFLAGS",
    "CGO_ENABLED",
];

/// The signed route the request goes to, and the one that carries a job's signals.
const JOBS_PATH: &str = "/api/v1/runner/jobs";
/// A request line is at most this long; a frame from the shim is far smaller.
const MAX_REQUEST: u64 = 64 * 1024;
const MAX_FRAME: u64 = 1024;
/// The shim sends its request at once.
const REQUEST_WAIT: Duration = Duration::from_secs(5);
/// The Core's answer starts (verdict line) within this, else the shim is told `local`.
const VERDICT_WAIT: Duration = Duration::from_millis(1500);
/// The longest a command that runs on the shim's side is waited for.
const LOCAL_RUN_LIMIT: Duration = Duration::from_secs(12 * 3600);
/// A socket this old may be swept when its terminal is gone (a new one may not be listed yet).
const SWEEP_AGE: Duration = Duration::from_secs(60);
const MAX_ARGV: usize = 256;
const MAX_ARG: usize = 4096;

/// Whose socket this is: stamped by the runner when it opens the socket, never taken from the
/// sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Origin {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// Hardlinks `shim` (the `ainkrad-job` binary) as every name in [`SHIM_NAMES`] under
/// `<state>/shims/bin`, and returns that directory. Idempotent; a copy where a link is not
/// possible (another filesystem).
pub fn install_shims(state: &Path, shim: &Path) -> io::Result<PathBuf> {
    let bin = state.join("shims").join("bin");
    std::fs::create_dir_all(&bin)?;
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))?;
    for name in SHIM_NAMES {
        let dst = bin.join(name);
        let _ = std::fs::remove_file(&dst);
        if std::fs::hard_link(shim, &dst).is_err() {
            std::fs::copy(shim, &dst)?;
        }
    }
    Ok(bin)
}

/// The `ainkrad-job` binary that ships next to `exe` (the runner).
pub fn shim_binary(exe: &Path) -> Option<PathBuf> {
    let p = exe.parent()?.join("ainkrad-job");
    p.is_file().then_some(p)
}

/// The environment of a sandbox that has job shims: `bin` first on `PATH`, the socket, and
/// `AINKRAD_SHIM_BIN` (the Ainkrad zsh profile re-applies it after `/etc/zprofile`).
pub fn shim_env(path: Option<&str>, bin: &Path, sock: &Path) -> Vec<(String, String)> {
    let bin_s = bin.to_string_lossy().into_owned();
    let path = match path.filter(|p| !p.is_empty()) {
        Some(p) => format!("{bin_s}:{p}"),
        None => format!("{bin_s}:/usr/local/bin:/usr/bin:/bin"),
    };
    vec![
        ("PATH".to_owned(), path),
        ("AINKRAD_SHIM_BIN".to_owned(), bin_s),
        (
            "AINKRAD_JOB_SOCK".to_owned(),
            sock.to_string_lossy().into_owned(),
        ),
    ]
}

/// The sockets of this runner's sandboxes, one directory each under `dir`.
pub struct JobSocks {
    dir: PathBuf,
    up: Upstream,
    open: Mutex<HashMap<String, (tokio::task::JoinHandle<()>, std::time::Instant)>>,
}

impl JobSocks {
    pub fn new(dir: PathBuf, up: Upstream) -> Arc<Self> {
        Arc::new(Self {
            dir,
            up,
            open: Mutex::new(HashMap::new()),
        })
    }

    /// The directory a sandbox keeps its socket in (the only part of this tree it may see).
    pub fn dir_of(&self, key: &str) -> PathBuf {
        self.dir.join(key)
    }

    pub fn sock_of(&self, key: &str) -> PathBuf {
        self.dir_of(key).join("job.sock")
    }

    /// Starts serving `key`'s socket for `origin`; the socket's path. `key` is the terminal or
    /// session id, which is unguessable, so it is also what keeps another sandbox off the socket.
    pub async fn open(&self, key: &str, origin: Origin) -> io::Result<PathBuf> {
        if key.is_empty() || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad socket key"));
        }
        self.close(key);
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o711))?;
        let d = self.dir_of(key);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir(&d)?;
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o711))?;
        let sock = self.sock_of(key);
        let listener = UnixListener::bind(&sock)?;
        // Any account a sandbox runs as may connect; the directory is what scopes it.
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666))?;
        let up = Arc::clone(&self.up);
        let task = tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let (up, origin) = (Arc::clone(&up), origin.clone());
                tokio::spawn(async move {
                    let _ = serve(conn, up, origin).await;
                });
            }
        });
        self.open
            .lock()
            .unwrap()
            .insert(key.to_owned(), (task, std::time::Instant::now()));
        Ok(sock)
    }

    /// Stops serving `key` and removes its directory.
    pub fn close(&self, key: &str) {
        if let Some((t, _)) = self.open.lock().unwrap().remove(key) {
            t.abort();
        }
        let _ = std::fs::remove_dir_all(self.dir_of(key));
    }

    /// Closes the terminal sockets (`t_…`) opened over a minute ago whose terminal is not in
    /// `live`: a terminal that ended leaves nothing behind.
    pub fn sweep(&self, live: &std::collections::HashSet<String>) {
        let stale: Vec<String> = self
            .open
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, (_, at))| k.starts_with("t_") && at.elapsed() > SWEEP_AGE && !live.contains(k))
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            self.close(&k);
        }
    }
}

/// One line, at most `max` bytes. `None` at the end of the stream or past the limit.
async fn line<R: tokio::io::AsyncBufRead + Unpin>(rd: &mut R, max: u64) -> Option<String> {
    let mut s = String::new();
    let n = (&mut *rd).take(max).read_line(&mut s).await.ok()?;
    (n > 0 && s.ends_with('\n')).then_some(s)
}

async fn say(wr: &mut tokio::net::unix::OwnedWriteHalf, v: Value) {
    let _ = wr.write_all(format!("{v}\n").as_bytes()).await;
}

/// The request the Core gets, or why the shim should run the tool itself.
fn build(req: &Value, origin: &Origin) -> Option<Vec<u8>> {
    let argv = req["argv"].as_array()?;
    let ok_str = |v: &Value| v.as_str().filter(|s| s.len() <= MAX_ARG && !s.contains('\0'));
    let argv: Vec<&str> = argv.iter().map(ok_str).collect::<Option<_>>()?;
    if argv.is_empty() || argv.len() > MAX_ARGV || argv[0].is_empty() {
        return None;
    }
    let cwd = ok_str(&req["cwd"]).filter(|c| c.starts_with('/'))?;
    let env: serde_json::Map<String, Value> = req["env"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter(|(k, v)| ENV_ALLOW.contains(&k.as_str()) && ok_str(v).is_some())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    let body = json!({
        "origin": origin,
        "argv": argv,
        "cwd": cwd,
        "tty": req["tty"].as_bool().unwrap_or(false),
        "env": env,
    });
    Some(body.to_string().into_bytes())
}

/// The report of a command that ran here: what `build` made, plus how long it took.
fn report_call(request: &[u8], ms: u64, code: i64) -> Option<Call> {
    let mut v: Value = serde_json::from_slice(request).ok()?;
    v["ms"] = json!(ms);
    v["code"] = json!(code);
    Some(Call {
        method: "POST",
        path: format!("{JOBS_PATH}/report"),
        query: String::new(),
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: v.to_string().into_bytes(),
    })
}

/// A job id as the Core makes them, safe to put in a path.
fn job_id_ok(id: &str) -> bool {
    id.strip_prefix("j_")
        .is_some_and(|r| !r.is_empty() && r.len() <= 64 && r.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// What the shim asks of a running job, or tells after a local run.
#[derive(Debug, PartialEq, Eq)]
enum Ask {
    Signal(&'static str),
    Cancel,
    Done { ms: u64, code: i64 },
}

fn parse_ask(l: &str) -> Option<Ask> {
    let v: Value = serde_json::from_str(l).ok()?;
    match v["t"].as_str()? {
        "cancel" => Some(Ask::Cancel),
        "done" => Some(Ask::Done {
            ms: v["ms"].as_u64()?,
            code: v["code"].as_i64()?,
        }),
        "signal" => Some(Ask::Signal(match v["sig"].as_str()? {
            "INT" => "INT",
            "TERM" => "TERM",
            "HUP" => "HUP",
            _ => return None,
        })),
        _ => None,
    }
}

fn signal_call(job: &str, ask: &Ask) -> Call {
    let sig = match ask {
        Ask::Signal(s) => *s,
        Ask::Cancel | Ask::Done { .. } => "cancel",
    };
    Call {
        method: "POST",
        path: format!("{JOBS_PATH}/{job}/signal"),
        query: String::new(),
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: json!({ "sig": sig }).to_string().into_bytes(),
    }
}

async fn serve(conn: UnixStream, up: Upstream, origin: Origin) -> io::Result<()> {
    let (rd, mut wr) = conn.into_split();
    let mut rd = BufReader::new(rd);
    let local = |why: &str| json!({"verdict": "local", "reason": why});
    let first = tokio::time::timeout(REQUEST_WAIT, line(&mut rd, MAX_REQUEST))
        .await
        .ok()
        .flatten();
    let body = first
        .and_then(|l| serde_json::from_str::<Value>(&l).ok())
        .and_then(|r| build(&r, &origin));
    let Some(body) = body else {
        say(&mut wr, local("bad_request")).await;
        return Ok(());
    };
    let call = Call {
        method: "POST",
        path: JOBS_PATH.to_owned(),
        query: String::new(),
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: body.clone(),
    };
    let body_sent = body;
    let reply = match tokio::time::timeout(VERDICT_WAIT, up(call)).await {
        Ok(Ok(r)) if r.status == 200 => r,
        _ => {
            say(&mut wr, local("core_unavailable")).await;
            return Ok(());
        }
    };
    // What the shim asks, read apart so a slow Core never blocks a signal.
    let (tx, mut asks) = mpsc::channel::<Option<Ask>>(8);
    tokio::spawn(async move {
        while let Some(l) = line(&mut rd, MAX_FRAME).await {
            if let Some(a) = parse_ask(&l) {
                let _ = tx.send(Some(a)).await;
            }
        }
        let _ = tx.send(None).await;
    });
    let mut body = reply.body;
    let (mut buf, mut job) = (Vec::<u8>::new(), None::<String>);
    // A local verdict that wants the run timed: the shim reports when the command ends.
    let mut report_local = false;
    loop {
        tokio::select! {
            chunk = body.recv() => {
                let Some(Ok(c)) = chunk else {
                    if !report_local {
                        return Ok(());
                    }
                    // The command runs on the shim's side; its report (or the shim's end) closes this.
                    let done = tokio::time::timeout(LOCAL_RUN_LIMIT, asks.recv()).await;
                    if let Ok(Some(Some(Ask::Done { ms, code }))) = done
                        && let Some(call) = report_call(&body_sent, ms, code)
                    {
                        let _ = up(call).await;
                    }
                    return Ok(());
                };
                buf.extend_from_slice(&c);
                if buf.len() > 4 * 1024 * 1024 {
                    return Ok(());
                }
                while let Some(i) = buf.iter().position(|b| *b == b'\n') {
                    let l: Vec<u8> = buf.drain(..=i).collect();
                    let v: Value = serde_json::from_slice(&l).unwrap_or(Value::Null);
                    report_local |= v["verdict"] == "local" && v["report"] == true;
                    if job.is_none() {
                        job = v["job"].as_str().filter(|j| job_id_ok(j)).map(str::to_owned);
                    }
                    wr.write_all(&l).await?;
                    if v["t"] == "exit" {
                        return Ok(());
                    }
                }
            }
            ask = asks.recv() => match ask.flatten() {
                Some(a) => {
                    if let Some(j) = &job
                        && !matches!(a, Ask::Done { .. })
                    {
                        tokio::spawn(up(signal_call(j, &a)));
                    }
                }
                // The shim is gone (a killed shim cannot cancel itself): the job is cancelled.
                None => {
                    if let Some(j) = &job {
                        tokio::spawn(up(signal_call(j, &Ask::Cancel)));
                    }
                    return Ok(());
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> Origin {
        Origin {
            terminal: Some("t1".into()),
            session: None,
        }
    }

    #[test]
    fn shims_are_linked_and_found_first_on_path() {
        let dir = std::env::temp_dir().join(format!("ainkrad-shims-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let shim = dir.join("ainkrad-job");
        std::fs::write(&shim, "x").unwrap();
        let bin = install_shims(&dir, &shim).unwrap();
        for n in SHIM_NAMES {
            assert!(bin.join(n).is_file(), "{n}");
        }
        install_shims(&dir, &shim).unwrap();
        let env = shim_env(Some("/usr/bin"), &bin, Path::new("/s/job.sock"));
        assert!(env[0].1.starts_with(&format!("{}:/usr/bin", bin.display())));
        assert_eq!(env[2], ("AINKRAD_JOB_SOCK".into(), "/s/job.sock".into()));
        assert!(shim_env(None, &bin, Path::new("/s"))[0].1.ends_with(":/usr/bin:/bin"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_request_is_checked_and_its_env_filtered() {
        let ok = json!({"argv": ["cargo", "test"], "cwd": "/w/p", "tty": true,
            "env": {"CI": "1", "AWS_SECRET_ACCESS_KEY": "x"}});
        let b: Value = serde_json::from_slice(&build(&ok, &origin()).unwrap()).unwrap();
        assert_eq!(b["origin"], json!({"terminal": "t1"}));
        assert_eq!(b["env"], json!({"CI": "1"}));
        assert_eq!(b["tty"], true);
        for bad in [
            json!({"argv": [], "cwd": "/w"}),
            json!({"argv": ["cargo"], "cwd": "w"}),
            json!({"argv": ["cargo", 1], "cwd": "/w"}),
            json!({"argv": [""], "cwd": "/w"}),
            json!({"cwd": "/w"}),
        ] {
            assert!(build(&bad, &origin()).is_none(), "{bad}");
        }
    }

    #[test]
    fn shim_frames_and_job_ids_are_checked() {
        assert_eq!(parse_ask(r#"{"t":"signal","sig":"INT"}"#), Some(Ask::Signal("INT")));
        assert_eq!(parse_ask(r#"{"t":"cancel"}"#), Some(Ask::Cancel));
        assert_eq!(parse_ask(r#"{"t":"signal","sig":"KILL"}"#), None);
        assert!(job_id_ok("j_abc123"));
        assert!(!job_id_ok("j_../x") && !job_id_ok("x_abc") && !job_id_ok("j_"));
        assert_eq!(signal_call("j_a", &Ask::Cancel).path, "/api/v1/runner/jobs/j_a/signal");
    }

    #[test]
    fn the_shim_and_the_endpoint_agree_on_env_names() {
        let shim = include_str!("../bin/ainkrad-job.rs");
        for n in ENV_ALLOW {
            assert!(shim.contains(&format!("\"{n}\"")), "{n}");
        }
    }

    fn fake(reply: Vec<&'static str>, seen: Arc<Mutex<Vec<(String, String)>>>) -> Upstream {
        Arc::new(move |call: Call| {
            let (reply, seen) = (reply.clone(), Arc::clone(&seen));
            Box::pin(async move {
                seen.lock()
                    .unwrap()
                    .push((call.path.clone(), String::from_utf8_lossy(&call.body).into_owned()));
                let (tx, body) = mpsc::channel(8);
                if call.path == JOBS_PATH {
                    for l in reply {
                        tx.send(Ok(l.as_bytes().to_vec())).await.unwrap();
                    }
                    // Held open until the test ends: a job that has not exited.
                    std::mem::forget(tx);
                }
                Ok(crate::workspace::relay::Reply {
                    status: 200,
                    content_type: "application/x-ndjson".into(),
                    body,
                })
            })
        })
    }

    async fn talk(up: Upstream, send: &str) -> (UnixStream, tempdir::Guard) {
        let dir = tempdir::Guard::new();
        let socks = JobSocks::new(dir.0.clone(), up);
        let sock = socks.open("t1", origin()).await.unwrap();
        let mut c = UnixStream::connect(&sock).await.unwrap();
        c.write_all(send.as_bytes()).await.unwrap();
        (c, dir)
    }

    mod tempdir {
        pub struct Guard(pub std::path::PathBuf);
        impl Guard {
            pub fn new() -> Self {
                let p = std::env::temp_dir().join(format!(
                    "ainkrad-jobsock-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .subsec_nanos()
                ));
                Self(p)
            }
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[tokio::test]
    async fn a_remote_job_is_streamed_through_and_a_signal_reaches_the_core() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let up = fake(
            vec![
                "{\"verdict\":\"remote\",\"job\":\"j_a1\",\"device_name\":\"box\"}\n{\"t\":\"state\",\"state\":\"running\"}\n",
            ],
            Arc::clone(&seen),
        );
        let (c, _g) = talk(up, "{\"argv\":[\"cargo\",\"build\"],\"cwd\":\"/w\",\"tty\":false,\"env\":{}}\n").await;
        let (rd, mut wr) = c.into_split();
        let mut rd = BufReader::new(rd);
        let v = line(&mut rd, 4096).await.unwrap();
        assert!(v.contains("\"remote\""));
        assert!(line(&mut rd, 4096).await.unwrap().contains("running"));
        wr.write_all(b"{\"t\":\"signal\",\"sig\":\"TERM\"}\n").await.unwrap();
        for _ in 0..50 {
            if seen.lock().unwrap().iter().any(|(p, _)| p.ends_with("/j_a1/signal")) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let calls = seen.lock().unwrap().clone();
        assert_eq!(calls[0].0, JOBS_PATH);
        assert!(calls[0].1.contains("\"terminal\":\"t1\""));
        assert!(calls.iter().any(|(p, b)| p.ends_with("/j_a1/signal") && b.contains("TERM")));
    }

    #[tokio::test]
    async fn a_bad_request_is_told_to_run_locally() {
        let up = fake(vec![], Arc::new(Mutex::new(Vec::new())));
        let (c, _g) = talk(up, "{\"argv\":[]}\n").await;
        let mut rd = BufReader::new(c);
        assert!(line(&mut rd, 4096).await.unwrap().contains("\"local\""));
    }
}
