//! `ainkrad-job`, the heavy-job shim (E15-3, spec §5.1): one binary, hardlinked as `cargo`, `npm`,
//! `make` and the other build tools, and put first on `PATH` inside Core terminals and agent
//! sandboxes. It asks the built-in runner's job socket (`$AINKRAD_JOB_SOCK`) where the command
//! should run. A `remote` verdict streams the job's output and mirrors its exit; anything else, or
//! any trouble before the job started, runs the real tool here, exactly as if the shim were absent.
//!
//! Line protocol (JSON lines). Shim to endpoint: one request `{argv,cwd,tty,env}`, then
//! `{t:"signal",sig}` and `{t:"cancel"}`. Endpoint to shim: `{verdict:"local",reason}` or
//! `{verdict:"remote",job,device_name}`, then `{t:"state",state}`, `{t:"out",fd,b64}` and
//! `{t:"exit",code,signal?}`. A `local` verdict may carry `report:true`: the shim then runs the
//! tool as a child instead of replacing itself, and ends with `{t:"done",ms,code}` so the Core
//! learns how long the command takes (tier 2 of the decision).

use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

/// The verdict has this long to arrive; after it the shim runs the tool itself.
const VERDICT_WAIT: Duration = Duration::from_secs(2);
/// Environment names the shim sends along. Nothing else leaves the sandbox through it.
const ENV_ALLOW: &[&str] = &[
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
/// Exit status when neither the job nor the local tool could be run (`command not runnable`).
const EXIT_MISSING: i32 = 125;

/// How the conversation with the endpoint ended.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The job ran remotely and finished; mirror this status.
    Exit(i32),
    /// Run the real tool here. `note` is shown when the job had already started.
    Local { note: Option<&'static str> },
}

/// The tool a call names: the name it was linked as, or `argv[1]` when called as `ainkrad-job`.
fn tool_of(argv: &[String]) -> Option<(String, Vec<String>)> {
    let base = |s: &str| s.rsplit('/').next().unwrap_or(s).to_owned();
    let me = base(argv.first()?);
    if me == "ainkrad-job" {
        let tool = base(argv.get(1)?);
        return Some((tool, argv[2..].to_vec()));
    }
    Some((me, argv[1..].to_vec()))
}

/// The first `name` on `path` that is an executable file other than this binary or a hardlink of
/// it (same device and inode), so the shim never finds itself.
fn find_real(name: &str, path: &str, me: Option<&Path>) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let mine = me
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| (m.dev(), m.ino()));
    path.split(':')
        .filter(|d| d.starts_with('/'))
        .map(|d| Path::new(d).join(name))
        .find(|p| {
            std::fs::metadata(p).is_ok_and(|m| {
                m.is_file()
                    && m.permissions().mode() & 0o111 != 0
                    && Some((m.dev(), m.ino())) != mine
            })
        })
}

/// The request line for the endpoint.
fn request(tool: &str, args: &[String], cwd: &str, tty: bool, env: &[(String, String)]) -> String {
    let argv: Vec<&str> = std::iter::once(tool)
        .chain(args.iter().map(String::as_str))
        .collect();
    let env: serde_json::Map<String, Value> = env
        .iter()
        .filter(|(k, _)| ENV_ALLOW.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect();
    let mut line = json!({"argv": argv, "cwd": cwd, "tty": tty, "env": env}).to_string();
    line.push('\n');
    line
}

/// The status a shell reports for a job that ended with `code`, or by `signal`.
fn status_of(code: Option<i64>, signal: Option<i64>) -> i32 {
    match (code, signal) {
        (Some(c), _) => c.clamp(0, 255) as i32,
        (None, Some(s)) => 128 + s.clamp(1, 127) as i32,
        (None, None) => 1,
    }
}

/// Reads the endpoint's frames after a `remote` verdict, writing the job's output to `out` and
/// `err`.
fn follow(frames: impl BufRead, out: &mut impl Write, err: &mut impl Write) -> Outcome {
    let mut started = false;
    for line in frames.lines() {
        let Ok(line) = line else { break };
        let Ok(f) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        match f["t"].as_str() {
            Some("state") => started |= f["state"] == "running",
            Some("out") => {
                started = true;
                let bytes = f["b64"].as_str().and_then(|b| STANDARD.decode(b).ok());
                let sink: &mut dyn Write = if f["fd"] == 2 { err } else { out };
                if let Some(b) = bytes {
                    let _ = sink.write_all(&b);
                    let _ = sink.flush();
                }
            }
            Some("exit") => {
                return Outcome::Exit(status_of(f["code"].as_i64(), f["signal"].as_i64()));
            }
            _ => {}
        }
    }
    Outcome::Local {
        note: started.then_some("ainkrad: the runner was lost; running the command here"),
    }
}

/// Asks the endpoint and follows a remote job. Anything but a clean remote exit is `Local`; the
/// stream comes back with it when the Core wants the local run timed (`report`).
fn ask(sock: &str, req: &str, tool: &str) -> (Outcome, Option<UnixStream>) {
    let local = (Outcome::Local { note: None }, None);
    let Ok(mut stream) = UnixStream::connect(sock) else {
        return local;
    };
    let _ = stream.set_read_timeout(Some(VERDICT_WAIT));
    if stream.write_all(req.as_bytes()).is_err() {
        return local;
    }
    let Ok(read) = stream.try_clone() else {
        return local;
    };
    let mut frames = BufReader::new(read);
    let mut first = String::new();
    if frames.read_line(&mut first).is_err() {
        return local;
    }
    let Ok(v) = serde_json::from_str::<Value>(&first) else {
        return local;
    };
    if v["verdict"] != "remote" {
        let report = v["verdict"] == "local" && v["report"] == true;
        return (Outcome::Local { note: None }, report.then_some(stream));
    }
    // The job is placed: it may queue and sync for a long while, so the wait is off.
    let _ = stream.set_read_timeout(None);
    let device = v["device_name"].as_str().unwrap_or("another machine");
    eprintln!("ainkrad: {tool} runs on {device}");
    forward_signals(&stream);
    (
        follow(frames, &mut std::io::stdout(), &mut std::io::stderr()),
        None,
    )
}

/// Runs the real tool as a child, mirrors its status and tells the endpoint how long it took.
/// Signals go to the child: all three when no terminal is there to send them itself, else only
/// TERM (a terminal's Ctrl-C and hang-up already reach the child's process group).
fn run_and_report(
    real: &Path,
    tool: &str,
    args: &[String],
    mut stream: UnixStream,
    tty: bool,
) -> ! {
    let signals = ainkrad_sys::catch_signals(&[libc_int::HUP, libc_int::INT, libc_int::TERM]).ok();
    let start = std::time::Instant::now();
    let mut child = match std::process::Command::new(real)
        .arg0(tool)
        .args(args)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ainkrad-job: cannot run {}: {e}", real.display());
            std::process::exit(EXIT_MISSING);
        }
    };
    let pid = child.id();
    if let Some(mut rd) = signals {
        std::thread::spawn(move || {
            let mut b = [0u8; 1];
            while rd.read_exact(&mut b).is_ok() {
                let sig = i32::from(b[0]);
                if !tty || sig == libc_int::TERM {
                    let _ = ainkrad_sys::kill_pid(pid, sig);
                }
            }
        });
    }
    let code = match child.wait() {
        Ok(s) => s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0)),
        Err(_) => 1,
    };
    let ms = start.elapsed().as_millis();
    let _ = writeln!(stream, "{}", json!({"t": "done", "ms": ms, "code": code}));
    std::process::exit(code)
}

/// Sends SIGINT, SIGTERM and SIGHUP on to the job; a second SIGINT cancels it.
fn forward_signals(stream: &UnixStream) {
    let sigs = [libc_int::INT, libc_int::TERM, libc_int::HUP];
    let (Ok(mut rd), Ok(mut tx)) = (ainkrad_sys::catch_signals(&sigs), stream.try_clone()) else {
        return;
    };
    std::thread::spawn(move || {
        let mut ints = 0;
        let mut b = [0u8; 1];
        while rd.read_exact(&mut b).is_ok() {
            let frame = match i32::from(b[0]) {
                libc_int::INT => {
                    ints += 1;
                    if ints > 1 {
                        json!({"t": "cancel"})
                    } else {
                        json!({"t": "signal", "sig": "INT"})
                    }
                }
                libc_int::TERM => json!({"t": "signal", "sig": "TERM"}),
                _ => json!({"t": "signal", "sig": "HUP"}),
            };
            if writeln!(tx, "{frame}").is_err() {
                break;
            }
        }
    });
}

/// Signal numbers shared by Linux and macOS for the three the shim forwards.
mod libc_int {
    pub const HUP: i32 = 1;
    pub const INT: i32 = 2;
    pub const TERM: i32 = 15;
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let Some((tool, args)) = tool_of(&argv) else {
        eprintln!("usage: ainkrad-job <tool> [args]");
        std::process::exit(EXIT_MISSING);
    };
    let path = std::env::var("PATH").unwrap_or_default();
    let me = std::env::current_exe().ok();
    let sock = std::env::var("AINKRAD_JOB_SOCK")
        .ok()
        .filter(|s| !s.is_empty());
    // AINKRAD_JOB_LOCAL: set for a command the job runner itself starts, so it cannot loop back.
    if let Some(sock) = sock.filter(|_| std::env::var_os("AINKRAD_JOB_LOCAL").is_none()) {
        let cwd = std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        let env: Vec<(String, String)> = std::env::vars().collect();
        let (outcome, report) = ask(&sock, &request(&tool, &args, &cwd, tty, &env), &tool);
        match outcome {
            Outcome::Exit(code) => std::process::exit(code),
            Outcome::Local { note } => {
                if let Some(n) = note {
                    eprintln!("{n}");
                }
            }
        }
        if let (Some(stream), Some(real)) = (report, find_real(&tool, &path, me.as_deref())) {
            run_and_report(&real, &tool, &args, stream, tty);
        }
    }
    match find_real(&tool, &path, me.as_deref()) {
        Some(real) => {
            let e = std::process::Command::new(&real)
                .arg0(&tool)
                .args(&args)
                .exec();
            eprintln!("ainkrad-job: cannot run {}: {e}", real.display());
        }
        None => eprintln!("ainkrad-job: {tool}: command not found"),
    }
    std::process::exit(EXIT_MISSING);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn the_tool_is_the_link_name_or_the_first_argument() {
        assert_eq!(
            tool_of(&s(&["/x/shims/cargo", "build"])),
            Some(("cargo".into(), s(&["build"])))
        );
        assert_eq!(
            tool_of(&s(&["ainkrad-job", "/usr/bin/go", "test"])),
            Some(("go".into(), s(&["test"])))
        );
        assert_eq!(tool_of(&s(&["ainkrad-job"])), None);
    }

    #[test]
    fn the_request_carries_only_allowed_env() {
        let env = vec![("CI".into(), "1".into()), ("AWS_SECRET".into(), "x".into())];
        let line = request("cargo", &s(&["test"]), "/w", true, &env);
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["argv"], json!(["cargo", "test"]));
        assert_eq!(v["env"], json!({"CI": "1"}));
        assert_eq!(v["tty"], true);
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn exit_codes_and_signals_are_mirrored() {
        assert_eq!(status_of(Some(3), None), 3);
        assert_eq!(status_of(None, Some(2)), 130);
        assert_eq!(status_of(None, Some(15)), 143);
    }

    fn frames(lines: &[Value]) -> (Outcome, Vec<u8>, Vec<u8>) {
        let text: String = lines.iter().map(|l| format!("{l}\n")).collect();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let o = follow(BufReader::new(text.as_bytes()), &mut out, &mut err);
        (o, out, err)
    }

    #[test]
    fn a_remote_job_streams_output_and_exits_with_its_code() {
        let (o, out, err) = frames(&[
            json!({"t": "state", "state": "running"}),
            json!({"t": "out", "fd": 1, "b64": STANDARD.encode("hi\n")}),
            json!({"t": "out", "fd": 2, "b64": STANDARD.encode("warn\n")}),
            json!({"t": "exit", "code": 101}),
        ]);
        assert_eq!(
            (o, out, err),
            (Outcome::Exit(101), b"hi\n".to_vec(), b"warn\n".to_vec())
        );
        assert_eq!(
            frames(&[json!({"t": "exit", "signal": 9})]).0,
            Outcome::Exit(137)
        );
    }

    #[test]
    fn a_stream_that_ends_early_falls_back_and_says_so_only_after_the_start() {
        assert_eq!(
            frames(&[json!({"t": "state", "state": "syncing"})]).0,
            Outcome::Local { note: None }
        );
        let after = frames(&[json!({"t": "state", "state": "running"})]).0;
        assert!(matches!(after, Outcome::Local { note: Some(_) }));
    }

    #[test]
    fn no_socket_means_local_and_a_missing_tool_is_not_found() {
        assert_eq!(
            ask("/nonexistent/sock", "{}\n", "cargo").0,
            Outcome::Local { note: None }
        );
        assert_eq!(
            find_real("definitely-not-a-tool", "/usr/bin:/bin", None),
            None
        );
    }

    #[test]
    fn the_shim_never_finds_itself() {
        let dir = std::env::temp_dir().join(format!("ainkrad-job-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let me = std::env::current_exe().unwrap();
        let link = dir.join("cargo-shim-test");
        let _ = std::fs::remove_file(&link);
        std::fs::hard_link(&me, &link).unwrap();
        let path = dir.to_string_lossy().into_owned();
        assert_eq!(find_real("cargo-shim-test", &path, Some(&me)), None);
        assert!(find_real("cargo-shim-test", &path, None).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_local_verdict_over_a_real_socket_falls_back() {
        let dir = std::env::temp_dir().join(format!("ainkrad-job-sock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s");
        let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let t = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut line = String::new();
            BufReader::new(c.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            writeln!(c, "{}", json!({"verdict": "local", "reason": "light"})).unwrap();
            line
        });
        let (o, report) = ask(
            sock.to_str().unwrap(),
            &request("make", &[], "/w", false, &[]),
            "make",
        );
        assert_eq!(o, Outcome::Local { note: None });
        assert!(report.is_none());
        assert!(t.join().unwrap().contains("\"argv\":[\"make\"]"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
