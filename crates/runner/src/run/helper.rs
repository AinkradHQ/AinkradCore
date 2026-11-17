//! The door between the runner and Podman: `ainkrad-runner run-helper`, started by systemd as
//! `ainkrad-run` for each connection to [`SOCKET`] (`deploy/systemd/ainkrad-run.socket`), and the
//! runner's client of it.
//!
//! Wire: one JSON line [`Request`] (at most 1 MiB, within 10 s), then for `start` each checkout's git
//! bundle as raw bytes, in `checkouts` order, of the lengths the request gives (each at most 2 GiB).
//! The answer is one JSON line, `{"ok": RunInfo | RunList}` or `{"err": "why"}`. The peer must be the
//! runner's user or root (`SO_PEERCRED`), on top of the socket's mode.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ainkrad_proto::v2::RunStart;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::Engine;

pub const SOCKET: &str = "/run/ainkrad-run.sock";
const RUNNER_USER: &str = "ainkrad-runner";
const MAX_LINE: usize = 1 << 20;
const MAX_BUNDLE: u64 = 2 << 30;

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// `start.secrets` is empty: their values are already in the env.
    Start {
        start: RunStart,
        bundles: Vec<u64>,
    },
    Stop {
        run: String,
    },
    Status {
        run: Option<String>,
    },
}

fn read_line(stream: &mut UnixStream) -> Option<Vec<u8>> {
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => return Some(buf),
            Ok(1) if buf.len() < MAX_LINE => buf.push(byte[0]),
            _ => return None,
        }
    }
}

/// Receives the bundles into `dir`, by repo.
fn receive(
    stream: &mut UnixStream,
    start: &RunStart,
    lens: &[u64],
    dir: &Path,
) -> Result<BTreeMap<String, PathBuf>, String> {
    if lens.len() != start.checkouts.len() || lens.iter().any(|l| *l > MAX_BUNDLE) {
        return Err("one bundle per checkout, each at most 2 GiB".to_owned());
    }
    super::private_dir(dir)?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let mut out = BTreeMap::new();
    for (c, len) in start.checkouts.iter().zip(lens) {
        let path = dir.join(&c.repo);
        let mut f = std::fs::File::create(&path).map_err(|e| e.to_string())?;
        let got =
            std::io::copy(&mut (&mut *stream).take(*len), &mut f).map_err(|e| e.to_string())?;
        if got != *len {
            return Err(format!("the bundle of {} was cut short", c.repo));
        }
        out.insert(c.repo.clone(), path);
    }
    Ok(out)
}

fn handle(engine: &Engine, stream: &mut UnixStream, req: Request) -> Result<Value, String> {
    fn v<T: Serialize>(r: Result<T, String>) -> Result<Value, String> {
        r.and_then(|x| serde_json::to_value(x).map_err(|e| e.to_string()))
    }
    match req {
        Request::Start { start, bundles } => {
            if let Some(p) = start.problem() {
                return Err(p);
            }
            let dir = engine.root.join(format!(".incoming-{}", start.run));
            let got = receive(stream, &start, &bundles, &dir);
            let r = got.and_then(|b| engine.start(&start, &b));
            let _ = std::fs::remove_dir_all(&dir);
            v(r)
        }
        Request::Stop { run } if ainkrad_proto::v2::valid_run_id(&run) => v(engine.stop(&run)),
        Request::Status { run: Some(run) } if ainkrad_proto::v2::valid_run_id(&run) => v(engine
            .status(&run, 0)
            .map(|r| ainkrad_proto::v2::RunList { runs: vec![r] })),
        Request::Status { run: None } => v(engine.list()),
        _ => Err("not a run id".to_owned()),
    }
}

/// Serves one connection (`stream` is its socket).
pub fn serve(engine: &Engine, mut stream: UnixStream, runner_uid: Option<u32>) {
    use std::os::fd::AsFd;
    let allowed = match ainkrad_sys::peer_uid(stream.as_fd()) {
        Ok(0) => true,
        Ok(p) => Some(p) == runner_uid,
        Err(_) => false,
    };
    let answer = if !allowed {
        Err("this peer is not allowed".to_owned())
    } else {
        match read_line(&mut stream).and_then(|l| serde_json::from_slice::<Request>(&l).ok()) {
            Some(req) => handle(engine, &mut stream, req),
            None => Err("the request was refused".to_owned()),
        }
    };
    let line = match answer {
        Ok(v) => json!({ "ok": v }),
        Err(e) => json!({ "err": e }),
    };
    let _ = writeln!(stream, "{line}");
}

/// `ainkrad-runner run-helper`: the connected socket is standard input.
pub fn main() -> std::process::ExitCode {
    use std::os::fd::AsFd;
    let Ok(fd) = std::io::stdin().as_fd().try_clone_to_owned() else {
        return std::process::ExitCode::FAILURE;
    };
    let mut stream = UnixStream::from(fd);
    let engine = match Engine::from_env() {
        Ok(e) => e,
        Err(e) => {
            let _ = writeln!(stream, "{}", json!({ "err": e }));
            return std::process::ExitCode::FAILURE;
        }
    };
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    serve(
        &engine,
        stream,
        crate::toolhelper::uid_in(&passwd, RUNNER_USER),
    );
    std::process::ExitCode::SUCCESS
}

/// The runner's side: sends `req` and the bundle files, and reads the answer.
pub async fn call(socket: &Path, req: &Request, bundles: &[PathBuf]) -> Result<Value, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut s = tokio::net::UnixStream::connect(socket).await.map_err(|e| {
        format!(
            "the run helper is not reachable ({e}); re-run the runner installer with --with-run"
        )
    })?;
    let mut line = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    line.push(b'\n');
    s.write_all(&line).await.map_err(|e| e.to_string())?;
    for b in bundles {
        // Local files; a blocking read per 64 KiB chunk is fine here.
        let mut f = std::fs::File::open(b).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = f.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            s.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
        }
    }
    s.flush().await.map_err(|e| e.to_string())?;
    let mut answer = String::new();
    // Pulls and builds are slow; the helper unit's RuntimeMaxSec ends a stuck one first.
    tokio::time::timeout(
        Duration::from_secs(1800),
        BufReader::new(s).read_line(&mut answer),
    )
    .await
    .map_err(|_| "the run helper did not answer in 30 minutes".to_owned())?
    .map_err(|e| e.to_string())?;
    let mut v: Value = serde_json::from_str(&answer)
        .map_err(|_| "the run helper's answer is unreadable".to_owned())?;
    match (v.get_mut("ok").map(Value::take), v["err"].as_str()) {
        (Some(ok), _) => Ok(ok),
        (None, Some(e)) => Err(e.to_owned()),
        _ => Err("the run helper's answer is unreadable".to_owned()),
    }
}
