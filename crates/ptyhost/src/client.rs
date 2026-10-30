//! The runner's side of the host (E2-03.2, .3): start a detached host, connect to one, and find
//! and re-adopt every host still running after a runner restart.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use crate::host::{owned_dir, random_hex, record_path, socket_path};
use crate::pty::Spec;
use crate::wire::{FromHost, HOST_PROTOCOL, HostInfo, HostRecord, ToHost, read_line, valid_id};

/// How long a host may take to answer its socket, or to start.
const CONNECT: Duration = Duration::from_secs(2);
const START: Duration = Duration::from_secs(10);

/// A fresh terminal id: 64 random bits, short enough that `<dir>/<id>.sock` stays within the
/// 104 bytes a Unix socket path may have on macOS.
pub fn new_id() -> io::Result<String> {
    Ok(format!("t_{}", &random_hex()?[..16]))
}

/// The reading half of a host connection.
pub struct HostReader {
    r: BufReader<OwnedReadHalf>,
    buf: Vec<u8>,
}

/// The writing half of a host connection.
pub struct HostWriter(OwnedWriteHalf);

impl HostReader {
    /// The next message; `None` when the host closed the connection (or ended).
    pub async fn recv(&mut self) -> io::Result<Option<FromHost>> {
        loop {
            let Some(line) = read_line(&mut self.r, &mut self.buf).await? else {
                return Ok(None);
            };
            match serde_json::from_str::<FromHost>(&line) {
                Ok(FromHost::Unknown) => continue,
                Ok(m) => return Ok(Some(m)),
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            }
        }
    }
}

impl HostWriter {
    pub async fn send(&mut self, m: &ToHost) -> io::Result<()> {
        let mut line = serde_json::to_vec(m).map_err(io::Error::other)?;
        line.push(b'\n');
        self.0.write_all(&line).await
    }
}

/// Connects to host `id` in `dir` and reads its hello. A host of a newer protocol major is
/// refused; an older one is spoken to as it is (it skips what it does not know). The
/// directory must be ours, private and not a symlink, and the peer must be our own uid
/// (review L2): a socket planted by someone else is never fed keystrokes. A socket nobody
/// listens on fails with `NotFound` or `ConnectionRefused`; only those mean it is dead.
pub async fn connect(dir: &Path, id: &str) -> io::Result<(HostInfo, HostReader, HostWriter)> {
    if !valid_id(id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad terminal id",
        ));
    }
    owned_dir(dir, true)?;
    let stream = tokio::time::timeout(CONNECT, UnixStream::connect(socket_path(dir, id)))
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    if !stream
        .peer_cred()
        .is_ok_and(|c| c.uid() == ainkrad_sys::getuid())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the terminal socket is served by another user",
        ));
    }
    let (rd, wr) = stream.into_split();
    let mut reader = HostReader {
        r: BufReader::new(rd),
        buf: Vec::new(),
    };
    let hello = tokio::time::timeout(CONNECT, reader.recv())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
    match hello {
        Some(FromHost::Hello { protocol, info }) if protocol <= HOST_PROTOCOL && info.id == id => {
            Ok((info, reader, HostWriter(wr)))
        }
        Some(FromHost::Hello { protocol, .. }) if protocol > HOST_PROTOCOL => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("the host speaks protocol {protocol}, newer than this runner"),
        )),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "no hello")),
    }
}

/// Starts host `id` for `spec` from the binary `bin`, detached: it makes itself a session
/// leader, its stdio is a pipe that closes once it is ready, and it inherits no other fd (Rust
/// opens every fd close-on-exec) and none of the runner's environment. The runner reaps it if
/// it ends while the runner lives; if the runner dies first, init adopts it and it keeps
/// running. Returns its info once it serves its socket.
pub async fn launch(bin: &Path, dir: &Path, id: &str, spec: &Spec) -> io::Result<HostInfo> {
    let mut child = tokio::process::Command::new(bin)
        .arg("serve")
        .arg("--dir")
        .arg(dir)
        .arg("--id")
        .arg(id)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(false)
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("no stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("no stdout"))?;
    stdin
        .write_all(&serde_json::to_vec(spec).map_err(io::Error::other)?)
        .await?;
    drop(stdin);
    let line = tokio::time::timeout(START, BufReader::new(stdout).lines().next_line())
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??
        .unwrap_or_default();
    // Reaped here should it end while this runner lives; no zombie either way.
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    match line.strip_prefix("ready ") {
        Some(info) => serde_json::from_str(info).map_err(io::Error::other),
        None => Err(io::Error::other(format!(
            "the host did not start: {}",
            line.strip_prefix("error ").unwrap_or(&line)
        ))),
    }
}

/// Every host in `dir` that is still the process its record names (pid and boot answer on
/// its socket), for re-adoption. Files are removed only for a host that is provably gone: its
/// socket is missing or refuses the connection (review M1). A host that is slow to answer,
/// speaks a newer protocol, or answers as another process is left alone and not listed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub live: Vec<HostInfo>,
    /// Records whose host was provably gone. The runner can report these to Core before cleanup.
    pub orphaned: Vec<String>,
}

pub async fn scan_report(dir: &Path) -> ScanReport {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return ScanReport::default();
    };
    let ids: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let id = name.strip_suffix(".json")?;
            valid_id(id).then(|| id.to_owned())
        })
        .collect();
    let mut live = Vec::new();
    let mut orphaned = Vec::new();
    for id in ids {
        let record: Option<HostRecord> = std::fs::read(record_path(dir, &id))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok());
        match (record, connect(dir, &id).await) {
            (Some(r), Ok((info, _, _))) if info.pid == r.pid && info.boot == r.boot => {
                live.push(info);
            }
            (_, Err(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) =>
            {
                orphaned.push(id.clone());
                let _ = std::fs::remove_file(record_path(dir, &id));
                let _ = std::fs::remove_file(socket_path(dir, &id));
            }
            _ => {}
        }
    }
    live.sort_by(|a, b| a.id.cmp(&b.id));
    orphaned.sort();
    ScanReport { live, orphaned }
}

pub async fn scan(dir: &Path) -> Vec<HostInfo> {
    scan_report(dir).await.live
}

/// The host binary: `$AINKRAD_PTYHOST`, else `ainkrad-ptyhost` next to the running executable
/// (or one directory up, where cargo puts binaries next to test executables).
pub fn find_host_binary() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("AINKRAD_PTYHOST") {
        return Some(PathBuf::from(p));
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    [dir.to_path_buf(), dir.parent()?.to_path_buf()]
        .into_iter()
        .map(|d| d.join("ainkrad-ptyhost"))
        .find(|p| p.is_file())
}
