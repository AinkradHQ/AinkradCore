//! The egress proxy of a filtered agent sandbox (E8a-01).
//!
//! The sandbox keeps `--unshare-net` and has no network interface. The runner listens on a unix
//! socket bound into it; inside, `ainkrad-runner mcp-forward` (the MCP bridge's forwarder) listens on
//! the namespace's own loopback and copies to that socket, and `HTTPS_PROXY` points there. The only
//! thing the proxy speaks is `CONNECT host:port`; after the `200` it is an opaque byte copy.
//!
//! The client is a hostile agent at worst, so: the request head is bounded in size and time;
//! the port is checked first; a name is looked up only when it is listed exactly (an unlisted name
//! never reaches the resolver, so it cannot carry data out in a DNS query); every address, literal
//! or resolved, is checked by the [`Policy`], and the proxy dials the address it checked (no second
//! lookup, so no rebinding window). Refusals say no more than a status. Nothing is logged about
//! the destination or the payload.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{
    AsyncBufRead, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, split,
};
use tokio::net::{TcpStream, UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

use crate::mcp_bridge::filter::{self, Refusal};

pub mod policy;
mod selftest;

pub use policy::{Deny, Policy};
pub use selftest::selftest;

/// The forwarder's port inside the sandbox (its own network namespace, so a fixed number is safe):
/// the MCP route is on `FORWARD_PORT`, this is the next one.
pub const EGRESS_PORT: u16 = 47832;

/// Open connections per run, and across every run of this runner.
const PER_RUN: usize = 32;
const GLOBAL: usize = 256;
static OPEN: Semaphore = Semaphore::const_new(GLOBAL);
/// Addresses taken from one answer, and dialled for one connection.
const MAX_ANSWERS: usize = 16;
const MAX_DIALS: usize = 4;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// From accepting a connection to the blank line ending the `CONNECT` head.
    pub head: Duration,
    pub resolve: Duration,
    pub connect: Duration,
    /// Without a byte either way for this long, a tunnel closes.
    pub idle: Duration,
    /// No tunnel outlives this.
    pub lifetime: Duration,
    pub per_run: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            head: Duration::from_secs(10),
            resolve: Duration::from_secs(5),
            connect: Duration::from_secs(10),
            idle: Duration::from_secs(900),
            lifetime: Duration::from_secs(6 * 3600),
            per_run: PER_RUN,
        }
    }
}

pub type Answers<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send + 'a>>;

/// Looks a name up. Only the proxy, outside the sandbox, ever holds one.
pub trait Resolve: Send + Sync {
    fn resolve<'a>(&'a self, name: &'a str) -> Answers<'a>;
}

/// The host's resolver.
pub struct System;

impl Resolve for System {
    fn resolve<'a>(&'a self, name: &'a str) -> Answers<'a> {
        Box::pin(async move {
            let found = tokio::net::lookup_host((name, 0)).await?;
            Ok(found.map(|a| a.ip()).take(MAX_ANSWERS).collect())
        })
    }
}

struct Shared {
    policy: Arc<Policy>,
    resolver: Arc<dyn Resolve>,
    limits: Limits,
    dials: AtomicUsize,
}

/// Aborts the listener and every tunnel it spawned when dropped (the run ended).
pub struct Proxy {
    task: JoinHandle<()>,
    shared: Arc<Shared>,
}

impl Proxy {
    /// How many upstream connections were attempted (test support).
    #[doc(hidden)]
    pub fn dials(&self) -> usize {
        self.shared.dials.load(Ordering::SeqCst)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort(); // the accept task owns the JoinSet; dropping it aborts every tunnel
    }
}

/// Listens on `sock` (mode 0600) for this run, with the host resolver and default limits.
pub fn start(sock: &Path, policy: Arc<Policy>) -> io::Result<Proxy> {
    start_with(sock, policy, Arc::new(System), Limits::default())
}

pub fn start_with(
    sock: &Path,
    policy: Arc<Policy>,
    resolver: Arc<dyn Resolve>,
    limits: Limits,
) -> io::Result<Proxy> {
    let listener = UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let shared = Arc::new(Shared {
        policy,
        resolver,
        limits,
        dials: AtomicUsize::new(0),
    });
    let run = Arc::new(Semaphore::new(limits.per_run));
    let me = shared.clone();
    let task = tokio::spawn(async move {
        let mut conns = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((client, _)) = accepted else { break };
                    // Over a limit: close at once; nothing is queued.
                    let (Ok(mine), Ok(global)) = (run.clone().try_acquire_owned(), OPEN.try_acquire()) else {
                        continue;
                    };
                    let shared = me.clone();
                    conns.spawn(async move {
                        let _held = (mine, global);
                        match timeout(shared.limits.lifetime, serve(&shared, client)).await {
                            Ok(Err(e)) => tracing::debug!(error = %e, "egress tunnel ended"),
                            Err(_) => tracing::debug!("egress tunnel reached its lifetime cap"),
                            Ok(Ok(())) => {}
                        }
                    });
                }
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        }
    });
    Ok(Proxy { task, shared })
}

/// The environment a sandbox needs to reach the proxy at `sock`: the socket, the forwarder (this
/// executable) and the port. One definition, used by the run and by the tests.
pub fn sandbox_env(sock: &Path, exe: &Path) -> Vec<(String, std::ffi::OsString)> {
    vec![
        ("AINKRAD_SANDBOX_EGRESS_SOCK".to_owned(), sock.into()),
        ("AINKRAD_SANDBOX_EGRESS_FWD".to_owned(), exe.into()),
        (
            "AINKRAD_SANDBOX_EGRESS_PORT".to_owned(),
            EGRESS_PORT.to_string().into(),
        ),
    ]
}

/// The socket a run's proxy listens on, in its private dir.
pub fn socket_in(dir: &Path) -> PathBuf {
    dir.join("egress.sock")
}

const BAD: Refusal = Refusal(400, "Bad Request");
const FORBIDDEN: Refusal = Refusal(403, "Forbidden");
const MAX_HEAD: usize = 8 * 1024;
const MAX_HEADERS: usize = 32;

#[derive(Debug, PartialEq, Eq)]
enum Host {
    Ip(IpAddr),
    Name(String),
}

/// `host:port`, `[v6]:port`. Nothing else: no scheme, userinfo, path or zone.
fn authority(text: &str) -> Option<(Host, u16)> {
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (inner, rest) = rest.split_once(']')?;
        let v6: Ipv6Addr = inner.parse().ok()?;
        (Host::Ip(IpAddr::V6(v6)), rest.strip_prefix(':')?)
    } else {
        let (host, port) = text.rsplit_once(':')?;
        let host = match host.parse::<Ipv4Addr>() {
            Ok(a) => Host::Ip(IpAddr::V4(a)),
            Err(_) => {
                // A name as the policy spells one; anything else is not listable, so is refused later.
                let lower = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
                let plain = !lower.is_empty()
                    && lower.len() <= 253
                    && lower
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
                if !plain {
                    return None;
                }
                Host::Name(lower)
            }
        };
        (host, port)
    };
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    Some((host, port))
}

/// The `CONNECT` request's target, or the refusal to send. Reads at most `MAX_HEAD` bytes.
async fn read_connect<R: AsyncBufRead + Unpin>(r: &mut R) -> Result<(Host, u16), Refusal> {
    let mut buf = Vec::new();
    let n = filter::line(r, &mut buf).await?;
    if n == 0 {
        return Err(BAD);
    }
    let mut size = n;
    let text = std::str::from_utf8(&buf[..n - 2]).map_err(|_| BAD)?;
    let parts: Vec<&str> = text.split(' ').collect();
    let [method, target, version] = parts[..] else {
        return Err(BAD);
    };
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(BAD);
    }
    if method != "CONNECT" {
        return Err(Refusal(405, "Method Not Allowed"));
    }
    let target = authority(target).ok_or(BAD)?;
    let mut count = 0;
    let mut head = Vec::new();
    loop {
        let n = filter::line(r, &mut head).await?;
        if n == 0 {
            return Err(BAD);
        }
        size += n;
        if size > MAX_HEAD {
            return Err(Refusal(431, "Request Header Fields Too Large"));
        }
        if head == b"\r\n" {
            break;
        }
        count += 1;
        if count > MAX_HEADERS {
            return Err(Refusal(431, "Request Header Fields Too Large"));
        }
        if matches!(head[0], b' ' | b'\t') {
            return Err(BAD); // obsolete line folding
        }
        let header = std::str::from_utf8(&head[..n - 2]).map_err(|_| BAD)?;
        let (name, value) = header.split_once(':').ok_or(BAD)?;
        // A CONNECT carries no body: a length or encoding is framing the proxy will not guess at.
        let name = name.to_ascii_lowercase();
        let body = name == "transfer-encoding" || (name == "content-length" && value.trim() != "0");
        if name.is_empty() || name.ends_with([' ', '\t']) || body {
            return Err(BAD);
        }
    }
    Ok(target)
}

async fn reply<W: AsyncWrite + Unpin>(w: &mut W, status: u16, reason: &str) {
    let text =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = timeout(Duration::from_secs(5), w.write_all(text.as_bytes())).await;
}

/// The addresses to dial for `host:port`, checked; or the refusal. Looks a name up only when it
/// is listed.
async fn destinations(shared: &Shared, host: Host, port: u16) -> Result<Vec<IpAddr>, Refusal> {
    if !shared.policy.port_ok(port) {
        return Err(FORBIDDEN);
    }
    let name = match host {
        Host::Ip(ip) => {
            return shared
                .policy
                .check_ip(ip, false)
                .map(|ip| vec![ip])
                .map_err(|_| FORBIDDEN);
        }
        Host::Name(name) => name,
    };
    if !shared.policy.host_listed(&name) {
        return Err(FORBIDDEN); // before any lookup: an unlisted name never reaches the resolver
    }
    let answers = timeout(shared.limits.resolve, shared.resolver.resolve(&name))
        .await
        .map_err(|_| Refusal(504, "Gateway Timeout"))?
        .map_err(|_| Refusal(502, "Bad Gateway"))?;
    let mut ok: Vec<IpAddr> = answers
        .into_iter()
        .take(MAX_ANSWERS)
        .filter_map(|a| shared.policy.check_ip(a, true).ok())
        .collect();
    ok.dedup();
    ok.truncate(MAX_DIALS);
    if ok.is_empty() {
        Err(FORBIDDEN)
    } else {
        Ok(ok)
    }
}

/// Dials the first address that answers; the addresses were checked, so this is the connection
/// the policy approved.
async fn dial(shared: &Shared, addrs: &[IpAddr], port: u16) -> Result<TcpStream, Refusal> {
    for ip in addrs {
        shared.dials.fetch_add(1, Ordering::SeqCst);
        if let Ok(Ok(tcp)) = timeout(
            shared.limits.connect,
            TcpStream::connect(SocketAddr::new(*ip, port)),
        )
        .await
        {
            let _ = tcp.set_nodelay(true);
            return Ok(tcp);
        }
    }
    Err(Refusal(502, "Bad Gateway"))
}

/// Copies `a` to `b` and `b` to `a` (each side: reader, writer) until both end; fails when nothing moves in either direction for `idle`.
async fn pipe<AR, AW, BR, BW>(
    ar: &mut AR,
    aw: &mut AW,
    br: &mut BR,
    bw: &mut BW,
    idle: Duration,
) -> io::Result<()>
where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    BR: AsyncRead + Unpin,
    BW: AsyncWrite + Unpin,
{
    let (mut abuf, mut bbuf) = (vec![0u8; 16 * 1024], vec![0u8; 16 * 1024]);
    let (mut a_open, mut b_open) = (true, true);
    let stalled = || io::Error::other("idle");
    let timer = tokio::time::sleep(idle);
    tokio::pin!(timer);
    while a_open || b_open {
        tokio::select! {
            n = ar.read(&mut abuf), if a_open => {
                let n = n?;
                if n == 0 {
                    a_open = false;
                    let _ = bw.shutdown().await;
                } else {
                    timeout(idle, bw.write_all(&abuf[..n])).await.map_err(|_| stalled())??;
                }
            }
            n = br.read(&mut bbuf), if b_open => {
                let n = n?;
                if n == 0 {
                    b_open = false;
                    let _ = aw.shutdown().await;
                } else {
                    timeout(idle, aw.write_all(&bbuf[..n])).await.map_err(|_| stalled())??;
                }
            }
            () = &mut timer => return Err(stalled()),
        }
        timer.as_mut().reset(tokio::time::Instant::now() + idle);
    }
    Ok(())
}

async fn serve(shared: &Shared, client: UnixStream) -> io::Result<()> {
    let (cr, mut cw) = split(client);
    let mut reader = BufReader::with_capacity(MAX_HEAD, cr);
    // The head, the policy and the dial all happen inside the head budget: a client that stalls
    // anywhere before the tunnel opens is cut off.
    let opened = timeout(shared.limits.head, async {
        let (host, port) = read_connect(&mut reader).await?;
        // The client waits for the 200; bytes sent ahead of it would be tunnelled unchecked framing.
        if !reader.buffer().is_empty() {
            return Err(BAD);
        }
        let addrs = destinations(shared, host, port).await?;
        dial(shared, &addrs, port).await
    })
    .await;
    let up = match opened {
        Ok(Ok(up)) => up,
        Err(_) => {
            reply(&mut cw, 408, "Request Timeout").await;
            return Ok(());
        }
        Ok(Err(Refusal(status, reason))) => {
            reply(&mut cw, status, reason).await;
            return Ok(());
        }
    };
    timeout(
        Duration::from_secs(5),
        cw.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
    )
    .await
    .map_err(|_| io::Error::other("client stalled"))??;
    let (mut ur, mut uw) = split(up);
    pipe(&mut reader, &mut cw, &mut ur, &mut uw, shared.limits.idle).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
