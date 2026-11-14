//! The stdio shim with Code Mode (E3.4): `ainkrad-runner mcp-stdio <sock>`, inside the sandbox.
//! It is still a line pipe between the harness and the session's socket, except that a
//! `tools/call ainkrad_run {code}` is NOT forwarded: the shim runs the script itself, in a child
//! process ([`super::child`]), and answers with ONE tool result however many operations ran:
//! the final value (bounded), the captured console output (bounded) and a one-line cost footer.
//! Every other line, notifications and the Core's answers included, passes through unchanged.
//!
//! Whether the session has Code Mode at all is the Core's call: without it a script's first
//! operation is refused (`unknown_tool`), and `tools/list` never offered `ainkrad_run`.

use std::process::{ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, stdin, stdout};
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use super::child::{Envelope, Request};
use super::{Limits, MAX_CODE, MAX_ENVELOPE};

const TOOL: &str = "ainkrad_run";
/// How long past its own time limit the child gets before it is killed.
const GRACE: Duration = Duration::from_secs(10);

static RUNS: AtomicU64 = AtomicU64::new(0);

/// A run id: `[A-Za-z0-9_.-]`, short, unique to this process and moment.
fn run_id() -> String {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "r{:x}-{:x}-{}",
        std::process::id(),
        t & 0xffff_ffff_ffff,
        RUNS.fetch_add(1, Ordering::Relaxed)
    )
}

/// The text the harness reads for a finished script, and whether it is an error.
pub fn reply_text(e: &Envelope) -> (bool, String) {
    let footer = format!("[{} calls, {} ms]", e.calls, e.ms);
    let mut console = if e.logs.is_empty() {
        String::new()
    } else {
        format!("\nconsole:\n{}", e.logs.join("\n"))
    };
    if !e.approvals.is_empty() {
        let each: Vec<String> = e
            .approvals
            .iter()
            .map(|a| format!("{} {} ({})", a.op, a.outcome, a.request))
            .collect();
        console.push_str(&format!("\napprovals: {}", each.join("; ")));
    }
    if e.ok {
        let v = e.value.as_deref().unwrap_or("null");
        return (true, format!("{v}{console}\n{footer}"));
    }
    let err = e.error.as_ref();
    let msg = err.map_or("the script failed", |x| x.message.as_str());
    let at = err
        .and_then(|x| x.line)
        .map_or(String::new(), |l| format!(" (line {l})"));
    let code = err
        .and_then(|x| x.code.as_deref())
        .map_or(String::new(), |c| format!(" [{c}]"));
    (false, format!("error: {msg}{at}{code}{console}\n{footer}"))
}

/// Runs `code` in a child process of this one (so inside the same sandbox) and returns the
/// harness-facing text.
pub async fn run_script(sock: &str, code: &str, limits: Limits) -> (bool, String) {
    match std::env::current_exe() {
        Ok(exe) => run_script_with(&exe, sock, code, limits, GRACE).await,
        Err(_) => (
            false,
            "error: the script engine is not available".to_owned(),
        ),
    }
}

/// [`run_script`] with the executable and the grace given (a test runs a fake engine).
pub async fn run_script_with(
    exe: &std::path::Path,
    sock: &str,
    code: &str,
    limits: Limits,
    grace: Duration,
) -> (bool, String) {
    if code.len() > MAX_CODE {
        return (false, format!("error: the script is over {MAX_CODE} bytes"));
    }
    let request = serde_json::to_vec(&Request {
        code: code.to_owned(),
        run: run_id(),
        limits,
    })
    .unwrap_or_default();
    let spawned = Command::new(exe)
        .arg("__script")
        .arg(sock)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let Ok(mut child) = spawned else {
        return (false, "error: the script engine could not start".to_owned());
    };
    let (mut input, output) = (child.stdin.take(), child.stdout.take());
    let work = async {
        if let Some(mut i) = input.take() {
            let _ = i.write_all(&request).await;
        } // dropped: the child sees the end of its input
        let mut buf = Vec::new();
        if let Some(o) = output {
            let _ = o.take(MAX_ENVELOPE as u64 + 1).read_to_end(&mut buf).await;
        }
        let status = child.wait().await;
        (buf, status)
    };
    let Ok((buf, status)) = tokio::time::timeout(limits.clamped().deadline() + grace, work).await
    else {
        // `work` is dropped with the child, which `kill_on_drop` ends.
        return (
            false,
            "error: the script did not finish in time and was stopped".to_owned(),
        );
    };
    let parsed = (buf.len() <= MAX_ENVELOPE)
        .then(|| serde_json::from_slice::<Envelope>(&buf).ok())
        .flatten();
    match (parsed, status) {
        (Some(e), Ok(s)) if s.success() => reply_text(&e),
        _ => (
            false,
            "error: the script engine stopped unexpectedly; the session is fine".to_owned(),
        ),
    }
}

fn tool_result(id: &Value, ok: bool, text: &str) -> Vec<u8> {
    let mut line = json!({"jsonrpc": "2.0", "id": id,
        "result": {"content": [{"type": "text", "text": text}], "isError": !ok}})
    .to_string()
    .into_bytes();
    line.push(b'\n');
    line
}

/// `(id, code)` when `line` is a call of `ainkrad_run` the shim runs itself.
fn run_request(line: &[u8]) -> Option<(Value, Option<String>)> {
    if !line.windows(TOOL.len()).any(|w| w == TOOL.as_bytes()) {
        return None;
    }
    let v: Value = serde_json::from_slice(line).ok()?;
    let id = v.get("id")?.clone();
    (v["method"] == "tools/call" && v["params"]["name"] == TOOL).then(|| {
        (
            id,
            v["params"]["arguments"]["code"].as_str().map(str::to_owned),
        )
    })
}

/// `ainkrad-runner mcp-stdio <sock>` with Code Mode.
pub async fn stdio_main(sock: &str) -> ExitCode {
    let Ok(stream) = UnixStream::connect(sock).await else {
        return ExitCode::FAILURE;
    };
    let (from, mut to) = stream.into_split();
    let out = Arc::new(Mutex::new(stdout()));
    let say = |out: &Arc<Mutex<tokio::io::Stdout>>, bytes: Vec<u8>| {
        let out = out.clone();
        async move {
            let mut o = out.lock().await;
            o.write_all(&bytes).await.is_ok() && o.flush().await.is_ok()
        }
    };
    // The Core's lines to the harness.
    let pump = {
        let out = out.clone();
        tokio::spawn(async move {
            let mut r = BufReader::new(from);
            let mut line = Vec::new();
            loop {
                line.clear();
                match r.read_until(b'\n', &mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if !say(&out, line.clone()).await {
                            break;
                        }
                    }
                }
            }
        })
    };
    let mut local = JoinSet::new();
    let mut input = BufReader::new(stdin());
    let mut line = Vec::new();
    loop {
        line.clear();
        match input.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if let Some((id, code)) = run_request(&line) {
            let (out, sock) = (out.clone(), sock.to_owned());
            local.spawn(async move {
                let (ok, text) = match code {
                    Some(c) => run_script(&sock, &c, Limits::default()).await,
                    None => (false, "error: code is a string".to_owned()),
                };
                say(&out, tool_result(&id, ok, &text)).await;
            });
        } else {
            if line.last() != Some(&b'\n') {
                line.push(b'\n');
            }
            if to.write_all(&line).await.is_err() {
                break;
            }
        }
    }
    // The harness is done sending: the Core answers what it was sent, the scripts finish, then out.
    let _ = to.shutdown().await;
    while local.join_next().await.is_some() {}
    let _ = pump.await;
    let _ = out.lock().await.flush().await;
    // Not a return: the runtime would wait for the thread blocked reading stdin.
    std::process::exit(0)
}
