//! The host process's loop (E2-03.1): one terminal, its socket, its ring and its screen.
//!
//! - The PTY master is read on its own thread, always, whether or not anyone is attached, so
//!   the child never blocks on a full PTY; every byte goes to the ring, the screen, and each
//!   attached client.
//! - Each client has a bounded queue. Output waits for an attached client's room (that is the
//!   PTY's backpressure on a burst, as with any terminal), but at most `SLOW`: a client stuck
//!   longer is dropped. It reattaches at its last `seq` (a snapshot, if that is gone).
//! - The socket is `0600` in a `0700` directory, and a peer whose uid is not the allowed one
//!   (the host's own) is closed before it gets a byte (E2-03.4).
//! - The child's exit goes to every connected client, once each, after its last output byte:
//!   the host holds its own slave fd for `DRAIN` after the exit (macOS may drop unread output
//!   when the last slave closes), then waits for EOF (`LATE` at most, if a background job keeps
//!   the PTY open). The host ends when a client acks it.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ainkrad_proto::v2::{Lifecycle, SIGNALS, Size, TerminalState};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use crate::pty::{Exit, Pty, Spawned, Spec, hang_up};
use crate::screen::{Ring, Screen};
use crate::store::{self, DiskRing};
use crate::wire::{FromHost, HOST_PROTOCOL, HostInfo, HostRecord, ToHost, read_line, valid_id};

/// How the host runs.
pub struct HostConfig {
    /// The runner's terminal directory: `<id>.sock` and `<id>.json` go here.
    pub dir: PathBuf,
    pub id: String,
    /// The only uid whose connections are served (the host's own, outside tests).
    pub allow_uid: u32,
    /// Output bytes kept in memory for a resume by `seq`; older bytes come from the disk ring.
    pub ring: usize,
    /// The on-disk scrollback ring (E2-04.3); `None`: memory only.
    pub disk: Option<DiskConfig>,
    /// Messages queued per client before it is dropped as too slow.
    pub client_queue: usize,
}

/// Where and how large the disk ring is.
pub struct DiskConfig {
    /// A `0700` directory shared by this runner's hosts (`<terminals>/scrollback`).
    pub dir: PathBuf,
    pub cap: u64,
}

/// The directory of the disk rings under the runner's terminal directory.
pub fn scrollback_dir(dir: &Path) -> PathBuf {
    dir.join("scrollback")
}

/// The most output bytes in one `out` message of a replay: a line stays far below `MAX_LINE`.
const REPLAY_CHUNK: usize = 512 * 1024;

impl HostConfig {
    pub fn new(dir: PathBuf, id: String) -> Self {
        let disk = Some(DiskConfig {
            dir: scrollback_dir(&dir),
            cap: store::CAP_DEFAULT,
        });
        Self {
            dir,
            disk,
            id,
            allow_uid: ainkrad_sys::getuid(),
            // Memory keeps the last 1 MiB for a resume; the disk ring holds the rest of the
            // scrollback (8 MiB by default). The VT screen has its own bounded history.
            ring: 1 << 20,
            client_queue: 1024,
        }
    }
}

/// How long output waits for an attached client's room before the client is dropped.
const SLOW: Duration = Duration::from_secs(5);
/// How long after the exit our slave fd is held while the output drains (`Pty::slave`).
const DRAIN: Duration = Duration::from_millis(200);
/// How long the exit then waits for the reader to finish (a background job may hold the
/// PTY open for good).
const LATE: Duration = Duration::from_secs(2);
/// The bounds of a `close`'s grace between signals.
const GRACE: (u64, u64) = (50, 10_000);

pub fn socket_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.sock"))
}

pub fn record_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

/// 16 random bytes as hex.
pub fn random_hex() -> io::Result<String> {
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// A `0700` directory for terminal sockets (created if missing).
/// Refuses a symlink in its place, and one owned by another user.
pub fn private_dir(dir: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    owned_dir(dir, false)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// Whether `dir` is a real directory (not a symlink) owned by this user, and, when `private`,
/// open to nobody else (no group or other bits): what the runner requires before it trusts a
/// socket in it (review L2).
pub fn owned_dir(dir: &Path, private: bool) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(dir)?;
    let refuse = |why: &str| io::Error::new(io::ErrorKind::PermissionDenied, why.to_owned());
    if !m.file_type().is_dir() {
        return Err(refuse("the terminal directory is not a directory"));
    }
    if m.uid() != ainkrad_sys::getuid() {
        return Err(refuse("the terminal directory belongs to another user"));
    }
    if private && m.mode() & 0o077 != 0 {
        return Err(refuse("the terminal directory is open to other users"));
    }
    Ok(())
}

enum Event {
    Msg(u64, ToHost),
    Gone(u64),
}

struct Client {
    tx: mpsc::Sender<FromHost>,
    attached: bool,
    /// The exit was sent to this client: it gets it once.
    told: bool,
}

struct State {
    cfg: HostConfig,
    pty: Pty,
    pid: u32,
    boot: String,
    started: u64,
    size: Size,
    state: TerminalState,
    exit: Option<Exit>,
    announced: bool,
    ring: Ring,
    disk: Option<DiskRing>,
    screen: Box<dyn Screen>,
    clients: HashMap<u64, Client>,
    input: mpsc::Sender<Vec<u8>>,
    exit_rx: watch::Receiver<Option<Exit>>,
    closing: bool,
}

impl State {
    fn info(&self) -> HostInfo {
        HostInfo {
            id: self.cfg.id.clone(),
            pid: self.pid,
            boot: self.boot.clone(),
            started: self.started,
            child: Some(self.pty.pid),
            state: self.state,
            size: self.size,
            seq: self.ring.end(),
            exit: self.exit.clone(),
        }
    }

    /// Queues `m` for `client`; a full or closed queue drops the client.
    fn send(&mut self, client: u64, m: FromHost) {
        let ok = self
            .clients
            .get(&client)
            .is_some_and(|c| c.tx.try_send(m).is_ok());
        if !ok {
            self.clients.remove(&client);
        }
    }

    /// `m` to every connected client (`attached_only`: the attached ones), each waited for at
    /// most `SLOW`; a client stuck longer is dropped.
    async fn broadcast(&mut self, m: &FromHost, attached_only: bool) {
        let mut stuck = Vec::new();
        for (id, c) in &self.clients {
            if attached_only && !c.attached {
                continue;
            }
            let sent = tokio::time::timeout(SLOW, c.tx.send(m.clone())).await;
            if !matches!(sent, Ok(Ok(()))) {
                stuck.push(*id);
            }
        }
        for id in stuck {
            self.clients.remove(&id);
        }
    }

    /// ponytail: one stuck client holds the loop (and the other clients) up to `SLOW`; a
    /// per-client writer with its own drop rule is the upgrade if hosts get many clients.
    async fn output(&mut self, bytes: &[u8]) {
        let seq = self.ring.end();
        self.ring.push(bytes);
        // Output only: nothing typed is written here. A disk error ends the disk ring for this
        // terminal (memory still serves it); no other terminal is touched.
        if let Some(d) = self.disk.as_mut()
            && d.append(seq, bytes).is_err()
            && let Some(d) = self.disk.take()
        {
            d.destroy();
        }
        self.screen.feed(bytes);
        let m = FromHost::Out {
            seq,
            data: STANDARD.encode(bytes),
        };
        self.broadcast(&m, true).await;
    }

    fn snapshot(&self) -> FromHost {
        FromHost::Snapshot {
            seq: self.ring.end(),
            data: STANDARD.encode(self.screen.snapshot()),
        }
    }

    /// One client message; `true` when the host is done.
    fn handle(&mut self, client: u64, m: ToHost) -> bool {
        let refuse = |why: &str| FromHost::Error {
            message: why.to_owned(),
        };
        match m {
            ToHost::Attach { seq } => {
                if let Some(c) = self.clients.get_mut(&client) {
                    c.attached = true;
                }
                let held = self
                    .ring
                    .since(seq)
                    .or_else(|| self.disk.as_ref().and_then(|d| d.since(seq)));
                match held {
                    Some(b) if b.is_empty() => {}
                    Some(b) => {
                        let mut at = seq;
                        for part in b.chunks(REPLAY_CHUNK) {
                            self.send(
                                client,
                                FromHost::Out {
                                    seq: at,
                                    data: STANDARD.encode(part),
                                },
                            );
                            at += part.len() as u64;
                        }
                    }
                    None => self.send(client, self.snapshot()),
                }
                let told = self.clients.get(&client).is_none_or(|c| c.told);
                if self.announced
                    && !told
                    && let Some(exit) = self.exit.clone()
                {
                    if let Some(c) = self.clients.get_mut(&client) {
                        c.told = true;
                    }
                    self.send(client, FromHost::Exit { exit });
                }
            }
            ToHost::Input { data } => match STANDARD.decode(data) {
                // ponytail: input past a full queue (a child that reads nothing) is dropped.
                Ok(b) => drop(self.input.try_send(b)),
                Err(_) => self.send(client, refuse("input is not base64")),
            },
            ToHost::Resize { size } => {
                if self.pty.resize(size).is_ok() {
                    self.size = size;
                    self.screen.resize(size);
                } else {
                    self.send(client, refuse("bad size"));
                }
            }
            // After the exit nothing is signalled (review H1).
            ToHost::Signal { .. } if self.exit.is_some() => {
                self.send(client, refuse("the terminal has exited"));
            }
            ToHost::Signal { signal } => {
                if !SIGNALS.contains(&signal.as_str()) || self.pty.signal(&signal).is_err() {
                    self.send(client, refuse("unknown signal"));
                }
            }
            ToHost::Snapshot => self.send(client, self.snapshot()),
            ToHost::Close { grace_ms } => {
                if !self.closing && self.exit.is_none() {
                    self.closing = true;
                    let grace = Duration::from_millis(grace_ms.clamp(GRACE.0, GRACE.1));
                    tokio::spawn(hang_up(self.pty.pid, grace, self.exit_rx.clone()));
                }
            }
            ToHost::Ack => {
                if self.announced {
                    self.state = self
                        .state
                        .next(Lifecycle::ExitRead)
                        .unwrap_or(TerminalState::Reaped);
                    return true;
                }
            }
            ToHost::Shed => {
                if let Some(d) = self.disk.as_mut()
                    && d.shed().is_err()
                    && let Some(d) = self.disk.take()
                {
                    d.destroy();
                }
            }
            ToHost::Unknown => {}
        }
        false
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Writes `value` to `path` as JSON, `0600`, through a rename (never half written).
pub fn write_private(path: &Path, value: &impl serde::Serialize) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(&serde_json::to_vec(value).map_err(io::Error::other)?)?;
    f.sync_all()?;
    std::fs::rename(tmp, path)
}

/// Serves one connection: the uid check, `hello`, then lines both ways until either ends.
fn serve_client(
    stream: UnixStream,
    id: u64,
    allow_uid: u32,
    hello: FromHost,
    queue: usize,
    events: mpsc::UnboundedSender<Event>,
) -> Option<mpsc::Sender<FromHost>> {
    // E2-03.4: another OS user gets nothing, not even the hello.
    if !stream.peer_cred().is_ok_and(|c| c.uid() == allow_uid) {
        return None;
    }
    let (rd, mut wr) = stream.into_split();
    let (tx, mut rx) = mpsc::channel::<FromHost>(queue);
    let _ = tx.try_send(hello);
    tokio::spawn(async move {
        while let Some(m) = rx.recv().await {
            let mut line = serde_json::to_vec(&m).expect("a message serializes");
            line.push(b'\n');
            if wr.write_all(&line).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        let (mut rd, mut buf) = (BufReader::new(rd), Vec::new());
        while let Ok(Some(line)) = read_line(&mut rd, &mut buf).await {
            match serde_json::from_str::<ToHost>(&line) {
                Ok(m) => {
                    if events.send(Event::Msg(id, m)).is_err() {
                        return;
                    }
                }
                // A line that is not a message: the client is broken; drop it.
                Err(_) => break,
            }
        }
        let _ = events.send(Event::Gone(id));
    });
    Some(tx)
}

/// Checks `cfg` and makes its directory: before the child is spawned.
pub fn prepare(cfg: &HostConfig) -> io::Result<()> {
    if !valid_id(&cfg.id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bad terminal id",
        ));
    }
    private_dir(&cfg.dir)?;
    cfg.disk.as_ref().map_or(Ok(()), |d| private_dir(&d.dir))
}

/// Runs the terminal `spec` as host `cfg` until a client acks its exit. `ready` is called once
/// the socket and record are in place (the binary prints `ready` for the runner then).
///
/// The binary spawns the child itself, with [`prepare`] and `Pty::spawn`, before any runtime
/// thread exists (the fork in a multi-threaded process is what review L1 warns of), then calls
/// [`serve`]; this is the same for an in-process host (tests).
pub async fn run(
    cfg: HostConfig,
    spec: Spec,
    screen: Box<dyn Screen>,
    ready: impl FnOnce(&HostInfo),
) -> io::Result<()> {
    prepare(&cfg)?;
    let spawned = Pty::spawn(&spec)?;
    serve(cfg, spawned, spec.size, screen, ready).await
}

/// [`run`] for a child already spawned.
pub async fn serve(
    cfg: HostConfig,
    spawned: Spawned,
    size: Size,
    screen: Box<dyn Screen>,
    ready: impl FnOnce(&HostInfo),
) -> io::Result<()> {
    let sock = socket_path(&cfg.dir, &cfg.id);
    let record = record_path(&cfg.dir, &cfg.id);
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)?;
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;

    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(64);
    let mut reader = spawned.reader;
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let (input, mut input_rx) = mpsc::channel::<Vec<u8>>(256);
    let mut writer = spawned.writer;
    std::thread::spawn(move || {
        while let Some(b) = input_rx.blocking_recv() {
            if writer.write_all(&b).and_then(|()| writer.flush()).is_err() {
                break;
            }
        }
    });

    let pid = std::process::id();
    let mut st = State {
        pid,
        boot: random_hex()?,
        started: now_ms(),
        size,
        state: TerminalState::Created
            .next(Lifecycle::Spawned)
            .unwrap_or(TerminalState::Running),
        exit: None,
        announced: false,
        ring: Ring::new(cfg.ring),
        // No disk ring is better than a failed terminal: the open goes on in memory.
        disk: cfg
            .disk
            .as_ref()
            .and_then(|d| DiskRing::open(&d.dir, &cfg.id, d.cap).ok()),
        screen,
        clients: HashMap::new(),
        input,
        exit_rx: spawned.exit.clone(),
        closing: false,
        pty: spawned.pty,
        cfg,
    };
    write_private(
        &record,
        &HostRecord {
            protocol: HOST_PROTOCOL,
            pid,
            boot: st.boot.clone(),
            started: st.started,
        },
    )?;
    ready(&st.info());

    let (events_tx, mut events) = mpsc::unbounded_channel();
    let mut exit_rx = spawned.exit;
    let mut reader_done = false;
    let mut drain_until: Option<Instant> = None;
    let mut released = false;
    let mut next_client = 0u64;
    loop {
        let now = Instant::now();
        // The exit is known and the output had DRAIN to arrive: let the master see EOF.
        if !released && drain_until.is_some_and(|d| now >= d) {
            st.pty.release_slave();
            released = true;
        }
        // Announced once the output is all read (EOF), or LATE after that if a background job
        // keeps the PTY open: after every output byte, so the exit is always last.
        if !st.announced
            && let Some(exit) = st.exit.clone()
            && released
            && (reader_done || drain_until.is_some_and(|d| now >= d + LATE))
        {
            st.announced = true;
            for c in st.clients.values_mut() {
                c.told = true;
            }
            st.broadcast(&FromHost::Exit { exit }, false).await;
        }
        let due = drain_until
            .filter(|_| !st.announced)
            .map(|d| if released { d + LATE } else { d });
        let wake = async move {
            match due {
                Some(d) => tokio::time::sleep_until(d).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            chunk = out_rx.recv(), if !reader_done => match chunk {
                Some(b) => st.output(&b).await,
                None => reader_done = true,
            },
            changed = exit_rx.changed(), if st.exit.is_none() => {
                if changed.is_err() {
                    // The waiter thread is gone without a status: treat as an exit.
                    st.exit = Some(Exit { code: None, signal: Some("lost".to_owned()) });
                } else {
                    st.exit = exit_rx.borrow().clone();
                }
                if st.exit.is_some() {
                    st.state = st.state.next(Lifecycle::ChildExited).unwrap_or(TerminalState::Exited);
                    drain_until = Some(Instant::now() + DRAIN);
                }
            }
            () = wake => {}
            accepted = listener.accept() => {
                if let Ok((stream, _)) = accepted {
                    next_client += 1;
                    let hello = FromHost::Hello { protocol: HOST_PROTOCOL, info: st.info() };
                    if let Some(tx) = serve_client(stream, next_client, st.cfg.allow_uid, hello,
                        st.cfg.client_queue, events_tx.clone())
                    {
                        st.clients.insert(next_client, Client { tx, attached: false, told: false });
                    }
                }
            }
            Some(ev) = events.recv() => match ev {
                Event::Gone(id) => drop(st.clients.remove(&id)),
                Event::Msg(id, m) => {
                    if st.handle(id, m) {
                        break;
                    }
                }
            },
        }
    }
    let _ = std::fs::remove_file(&record);
    let _ = std::fs::remove_file(&sock);
    // The terminal is over and its exit was read: its scrollback goes with it.
    if let Some(d) = st.disk.take() {
        d.destroy();
    }
    // Nothing signals the group any more: the zombie leader can go.
    st.pty.reap();
    Ok(())
}
