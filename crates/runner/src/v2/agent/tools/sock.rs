//! The socket that serves a session's connection tools to its sandboxed harness (C4b).
//!
//! One unix socket per session, `<agents>/<session>/tools.sock` (the session's private dir, 0700,
//! the socket 0600), listened on by a task that was handed the session at open time. THE SESSION IS
//! THE SOCKET: nothing in a request names a session, and a body that does is ignored, so what a
//! harness can reach is decided by which socket the sandbox was given. The sandbox is given exactly
//! this file (bind-mounted by the harness sandbox's `TOOLS` slot) and the runner executable to run
//! as the stdio shim ([`stdio_main`]); the directory, every other session's socket and the state
//! dir are not in its mount namespace. There is no TCP listener and no abstract socket.
//!
//! Framing is the MCP stdio one: one JSON-RPC message per line. The agent can skip the shim and
//! speak to the socket directly, so every limit is enforced HERE, never in the shim:
//! a request line is at most [`MAX_REQUEST`] bytes and is read with a bound (over it: one error
//! reply, then the connection is closed, it cannot be resynchronised), a line that is started must
//! be finished within [`LINE_DEADLINE`], at most [`PER_CONN`] requests of a connection are
//! worked at once (more are refused at once, `busy`), a session has at most [`PER_SESSION`]
//! connections and the runner [`GLOBAL`], a peer that does not read its answers is dropped
//! after [`WRITE_TIMEOUT`], and a call's wait and result size are bounded by `Tools` itself.
//! A connection has no idle timeout (a harness holds its MCP server open for the whole session):
//! it ends with the peer, or with the session ([`Front`] dropped).
//!
//! No credential passes here: a request is a tool name and arguments, an answer is the Core's
//! plain result or refusal.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader, copy, stdin, stdout};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use super::{Tools, mcp};

/// The longest request line (a tool call's arguments are at most `MAX_ARGS_BYTES`, 384 KiB).
pub const MAX_REQUEST: usize = 512 * 1024;
/// Requests of one connection worked at once.
pub const PER_CONN: usize = 8;
/// Open connections per session, and across the runner.
pub const PER_SESSION: usize = 4;
pub const GLOBAL: usize = 64;
/// A line that has begun must end within this.
pub const LINE_DEADLINE: Duration = Duration::from_secs(30);
/// A peer that takes this long to accept an answer is dropped.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// A unix socket path is 108 bytes at most; the gateway keeps to 100.
pub const MAX_SOCK_PATH: usize = 100;

static OPEN: Semaphore = Semaphore::const_new(GLOBAL);

/// The socket a session's tools are served on, in its private dir.
pub fn socket_in(dir: &Path) -> PathBuf {
    dir.join("tools.sock")
}

/// The environment the sandbox needs for the slot: the socket to bind in and the executable the
/// harness's MCP config runs as the shim (the harness crate's `TOOLS` slot reads these two).
pub fn sandbox_env(sock: &Path, exe: &Path) -> Vec<(String, String)> {
    let text = |p: &Path| p.to_string_lossy().into_owned();
    vec![
        ("AINKRAD_SANDBOX_TOOLS_SOCK".to_owned(), text(sock)),
        ("AINKRAD_SANDBOX_TOOLS_FWD".to_owned(), text(exe)),
    ]
}

/// Serves the session until dropped (it ended): the listener and every connection are aborted and
/// the socket file is removed.
pub struct Front {
    task: JoinHandle<()>,
    sock: PathBuf,
}

impl Drop for Front {
    fn drop(&mut self) {
        self.task.abort(); // the accept task owns the JoinSet; dropping it aborts every connection
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// Listens on `sock` (mode 0600) for `session`. A socket a crashed runner left is replaced.
pub fn start(sock: &Path, tools: Arc<Tools>, session: &str) -> io::Result<Front> {
    if sock.as_os_str().len() > MAX_SOCK_PATH {
        return Err(io::Error::other("the tools socket path is too long"));
    }
    match std::fs::remove_file(sock) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))?;
    let session: Arc<str> = session.into();
    let mine = Arc::new(Semaphore::new(PER_SESSION));
    let task = tokio::spawn(async move {
        let mut conns = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((client, _)) = accepted else { break };
                    // Over a limit: closed at once, nothing queued.
                    let (Ok(mine), Ok(global)) = (mine.clone().try_acquire_owned(), OPEN.try_acquire()) else {
                        continue;
                    };
                    let (tools, session) = (tools.clone(), session.clone());
                    conns.spawn(async move {
                        let _held = (mine, global);
                        serve(client, tools, session).await;
                    });
                }
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        }
    });
    Ok(Front {
        task,
        sock: sock.to_owned(),
    })
}

enum Line {
    Data(Vec<u8>),
    TooLong,
    Eof,
}

/// The next non-empty line, at most `max` bytes (the newline excluded). Bounded as it reads:
/// nothing past `max` is ever buffered.
async fn read_line<R: AsyncBufRead + Unpin>(r: &mut R, max: usize) -> io::Result<Line> {
    let mut buf = Vec::new();
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(if buf.is_empty() {
                Line::Eof
            } else {
                Line::Data(buf)
            });
        }
        let end = chunk.iter().position(|b| *b == b'\n');
        let take = end.unwrap_or(chunk.len());
        if buf.len() + take > max {
            return Ok(Line::TooLong);
        }
        buf.extend_from_slice(&chunk[..take]);
        r.consume(end.map_or(take, |_| take + 1));
        if end.is_some() {
            if buf.iter().all(u8::is_ascii_whitespace) {
                buf.clear(); // a blank line is nothing
                continue;
            }
            return Ok(Line::Data(buf));
        }
    }
}

fn error_line(id: Value, code: i64, message: &str) -> Vec<u8> {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
        .to_string()
        .into_bytes()
}

/// The id of a request that is refused unparsed, so the refusal can name it (`null` when the line
/// is not a request with one). `None` for a notification: it is not answered.
fn refusal_target(line: &[u8]) -> Option<Value> {
    match serde_json::from_slice::<Value>(line) {
        Ok(v) => v.get("id").cloned().or_else(|| {
            // An object with a method and no id is a notification; anything else gets a `null` id.
            (!(v.is_object() && v.get("method").is_some())).then_some(Value::Null)
        }),
        Err(_) => Some(Value::Null),
    }
}

/// Aborts its task when dropped, so a connection aborted from outside takes its helpers with it.
struct Abort(JoinHandle<()>);

impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn serve(stream: UnixStream, tools: Arc<Tools>, session: Arc<str>) {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    // Answers wait in a bounded queue for the one writer; a slow peer stops being served instead
    // of growing it. At most `PER_CONN` requests plus the notifications and the refusals.
    let (out, mut queue) = mpsc::channel::<Vec<u8>>(PER_CONN * 2);
    let mut writer = Abort(tokio::spawn(async move {
        while let Some(mut line) = queue.recv().await {
            line.push(b'\n');
            if !matches!(
                timeout(WRITE_TIMEOUT, write.write_all(&line)).await,
                Ok(Ok(()))
            ) {
                return;
            }
        }
        let _ = write.shutdown().await;
    }));
    // A changed tool list is told to the harness (it may or may not look again at once; the next
    // `tools/list` is always the live list).
    let notifier = {
        let (tools, session, out) = (tools.clone(), session.clone(), out.clone());
        // Taken here, not in the task: a change between now and the task's first run is seen.
        let mut ticks = tools.subscribe();
        let mut seen = tools.list(&session);
        Abort(tokio::spawn(async move {
            while ticks.changed().await.is_ok() {
                let now = tools.list(&session);
                if now != seen {
                    seen = now;
                    let note = json!({"jsonrpc": "2.0",
                        "method": "notifications/tools/list_changed"});
                    if out.try_send(note.to_string().into_bytes()).is_err() {
                        return; // the peer is not keeping up: it asks for the list when it wants it
                    }
                }
            }
        }))
    };
    let inflight = Arc::new(Semaphore::new(PER_CONN));
    let mut requests = JoinSet::new();
    let clean = loop {
        while requests.try_join_next().is_some() {}
        // Wait for the first byte of a request without a clock; once one has begun, it must end.
        match reader.fill_buf().await {
            Ok(b) if !b.is_empty() => {}
            _ => break true, // the peer closed (or failed): finish what is in flight
        }
        let line = match timeout(LINE_DEADLINE, read_line(&mut reader, MAX_REQUEST)).await {
            Ok(Ok(Line::Data(line))) => line,
            Ok(Ok(Line::Eof)) => break true,
            Ok(Ok(Line::TooLong)) => {
                let _ = out
                    .send(error_line(Value::Null, -32600, "the request is too large"))
                    .await;
                break false; // it cannot be resynchronised
            }
            _ => break false, // too slow, or an error
        };
        let Ok(permit) = inflight.clone().try_acquire_owned() else {
            if let Some(id) = refusal_target(&line) {
                let _ = out
                    .send(error_line(id, -32001, "too many requests at once"))
                    .await;
            }
            continue;
        };
        let (tools, session, out) = (tools.clone(), session.clone(), out.clone());
        requests.spawn(async move {
            let _permit = permit;
            // The session is the one this socket was opened for: the body has no say.
            if let Some(answer) = mcp::handle(&tools, &session, &line).await {
                let _ = out.send(answer).await;
            }
        });
    };
    if clean {
        // The peer is done sending (a shim whose stdin ended): let its calls finish and be told.
        while requests.join_next().await.is_some() {}
    } else {
        requests.abort_all();
    }
    drop(notifier);
    drop(out);
    // The writer ends when the queue is closed and drained, or when the peer stopped reading.
    let _ = (&mut writer.0).await;
}

/// `ainkrad-runner mcp-stdio <sock>`: runs inside the sandbox as the harness's MCP server. A byte
/// pipe between its stdin/stdout and the socket, nothing more: it writes nothing of its own to
/// stdout, and it holds no limit (the runner's socket does). When stdin ends it half-closes the
/// socket and waits for the answers still owed.
pub async fn stdio_main(sock: &str) -> ExitCode {
    let Ok(stream) = UnixStream::connect(sock).await else {
        return ExitCode::FAILURE;
    };
    let (mut from, mut to) = stream.into_split();
    tokio::spawn(async move {
        let _ = copy(&mut stdin(), &mut to).await;
        let _ = to.shutdown().await;
    });
    // The server closes once it has answered everything sent before the half-close.
    let mut out = stdout();
    let _ = copy(&mut from, &mut out).await;
    let _ = out.flush().await;
    // Not a return: the runtime would wait for the thread blocked reading stdin.
    std::process::exit(0)
}

#[cfg(test)]
mod tests;
