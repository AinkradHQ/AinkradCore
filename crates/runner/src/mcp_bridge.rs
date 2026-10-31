//! A run's MCP route into a sandbox with no network (`--unshare-net`).
//!
//! The runner listens on a unix socket bound into the sandbox and forwards each connection to the
//! Core (TLS when the Core is https). Inside, `ainkrad-runner mcp-forward` listens on the netns's
//! own loopback (`FORWARD_PORT`) and copies to that socket; the harness's MCP config points there.
//! The sandbox reaches the Core's MCP URL and nothing else: no host loopback, no metadata address.

use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, copy, copy_bidirectional, split};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;

pub mod filter;

/// The port inside the sandbox's own network namespace (a fresh one, so a fixed number is safe).
pub const FORWARD_PORT: u16 = 47831;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// The Core as the enrolment names it (`host[:port]`): what the Core expects in `Host`.
    pub authority: String,
    /// The one path the bridge forwards (`POST` only).
    pub path: String,
}

/// The Core MCP URL's authority, and the same URL as the sandbox sees it.
pub fn parse(url: &str) -> Option<(Target, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let tls = match scheme {
        "https" => true,
        "http" => false,
        _ => return None,
    };
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => (h, p.parse().ok()?),
        _ => (authority, if tls { 443 } else { 80 }),
    };
    let host = host.trim_matches(['[', ']']).to_owned();
    (!host.is_empty()).then(|| {
        (
            Target {
                host,
                port,
                tls,
                authority: authority.to_owned(),
                path: format!("/{path}"),
            },
            format!("http://127.0.0.1:{FORWARD_PORT}/{path}"),
        )
    })
}

/// Open connections per run, and across every run of this runner.
const PER_RUN: usize = 16;
const GLOBAL: usize = 128;
static OPEN: Semaphore = Semaphore::const_new(GLOBAL);
/// No connection outlives this, whatever it is doing.
const LIFETIME: Duration = Duration::from_secs(6 * 3600);
const CONNECT: Duration = Duration::from_secs(10);

/// Aborts the listener and every connection it spawned when dropped (the run ended).
pub struct Bridge(JoinHandle<()>);

impl Drop for Bridge {
    fn drop(&mut self) {
        self.0.abort(); // the accept task owns the JoinSet; dropping it aborts every connection
    }
}

fn tls_config(given: Option<Arc<rustls::ClientConfig>>) -> Arc<rustls::ClientConfig> {
    given.unwrap_or_else(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("ring supports the default versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    })
}

trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

async fn connect(target: &Target, tls: &Arc<rustls::ClientConfig>) -> io::Result<Box<dyn Duplex>> {
    let tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
    if !target.tls {
        return Ok(Box::new(tcp));
    }
    let name =
        rustls::pki_types::ServerName::try_from(target.host.clone()).map_err(io::Error::other)?;
    let tls = tokio_rustls::TlsConnector::from(tls.clone())
        .connect(name, tcp)
        .await?;
    Ok(Box::new(tls))
}

async fn refuse<W: AsyncWrite + Unpin>(w: &mut W, r: filter::Refusal) {
    let reply = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        r.0, r.1
    );
    let _ = timeout(Duration::from_secs(5), w.write_all(reply.as_bytes())).await;
}

/// One client: the first request is checked before the Core is dialled at all; a refusal is
/// answered and nothing is sent upstream.
async fn serve(
    target: &Target,
    tls: &Arc<rustls::ClientConfig>,
    client: UnixStream,
) -> io::Result<()> {
    let (cr, mut cw) = split(client);
    let mut reader = BufReader::new(cr);
    let first = match filter::read_request(&mut reader, &target.authority, &target.path).await {
        Ok(Some(q)) => q,
        Ok(None) => return Ok(()),
        Err(refusal) => {
            refuse(&mut cw, refusal).await;
            return Ok(());
        }
    };
    let up = timeout(CONNECT, connect(target, tls))
        .await
        .map_err(|_| io::Error::other("connecting to the Core timed out"))??;
    let (mut ur, mut uw) = split(up);
    let requests = async {
        let mut q = first;
        loop {
            uw.write_all(&q.head).await?;
            filter::forward_body(&mut reader, &mut uw, q.body).await?;
            uw.flush().await?;
            match filter::read_request(&mut reader, &target.authority, &target.path).await {
                Ok(Some(next)) => q = next,
                Ok(None) => return uw.shutdown().await, // the client is done; let responses finish
                Err(_) => return Err(io::Error::other("refused a later request")),
            }
        }
    };
    // Either side failing drops the other: the connection closes.
    tokio::try_join!(requests, async { copy(&mut ur, &mut cw).await.map(|_| ()) })?;
    Ok(())
}

/// Listens on `sock` (mode 0600) and forwards every connection to `target`.
pub fn start(
    sock: &Path,
    target: Target,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> io::Result<Bridge> {
    let listener = UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    let tls = tls_config(tls);
    let run = Arc::new(Semaphore::new(PER_RUN));
    Ok(Bridge(tokio::spawn(async move {
        let mut conns = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((client, _)) = accepted else { break };
                    // Over a limit: close at once; nothing is queued.
                    let (Ok(mine), Ok(global)) = (run.clone().try_acquire_owned(), OPEN.try_acquire()) else {
                        continue;
                    };
                    let (target, tls) = (target.clone(), tls.clone());
                    conns.spawn(async move {
                        let _held = (mine, global);
                        match timeout(LIFETIME, serve(&target, &tls, client)).await {
                            Ok(Err(e)) => tracing::debug!(error = %e, "mcp bridge connection ended"),
                            Err(_) => tracing::debug!("mcp bridge connection reached its lifetime cap"),
                            Ok(Ok(())) => {}
                        }
                    });
                }
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        }
    })))
}

/// `ainkrad-runner mcp-forward <port> <sock>`: runs inside the sandbox, loopback to the socket.
pub async fn forward_main(port: &str, sock: &str) -> ExitCode {
    let Ok(port) = port.parse::<u16>() else {
        return ExitCode::from(2);
    };
    let Ok(listener) = TcpListener::bind(("127.0.0.1", port)).await else {
        return ExitCode::FAILURE;
    };
    let sock = PathBuf::from(sock);
    while let Ok((mut tcp, _)) = listener.accept().await {
        let sock = sock.clone();
        tokio::spawn(async move {
            if let Ok(mut unix) = UnixStream::connect(sock).await {
                let _ = copy_bidirectional(&mut tcp, &mut unix).await;
            }
        });
    }
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;

    const REQ: &str = "POST /token/citadel/v1/mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";

    /// A counting upstream and a bridge to it; the socket lives in a fresh temp dir.
    async fn rig(name: &str) -> (Bridge, PathBuf, Arc<AtomicUsize>) {
        let up = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = up.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = up.accept().await {
                h.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut buf = [0; 1024];
                    while c.read(&mut buf).await.is_ok_and(|n| n > 0) {
                        let _ = c
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .await;
                    }
                });
            }
        });
        let dir = std::env::temp_dir().join(format!("mcp-bridge-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("s");
        let target = Target {
            host: "127.0.0.1".into(),
            port,
            tls: false,
            authority: format!("127.0.0.1:{port}"),
            path: "/token/citadel/v1/mcp".into(),
        };
        (start(&sock, target, None).unwrap(), sock, hits)
    }

    async fn status(sock: &Path, raw: &[u8]) -> String {
        let mut c = UnixStream::connect(sock).await.unwrap();
        // The bridge may refuse and close before the whole request is written (EPIPE on macOS):
        // the status line it already sent is what the test checks.
        let _ = c.write_all(raw).await;
        let mut out = Vec::new();
        let _ = timeout(Duration::from_secs(5), c.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out)
            .lines()
            .next()
            .unwrap_or("")
            .to_owned()
    }

    #[tokio::test]
    async fn refused_requests_never_reach_the_core() {
        let (_bridge, sock, hits) = rig("refuse").await;
        for (raw, want) in [
            ("GET /token/citadel/v1/mcp HTTP/1.1\r\n\r\n".to_owned(), "403"),
            ("CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n".to_owned(), "403"),
            ("POST /handshake HTTP/1.1\r\n\r\n".to_owned(), "404"),
            ("POST /token/citadel/v1/mcp?x=1 HTTP/1.1\r\n\r\n".to_owned(), "404"),
            ("POST /token/citadel/v1/mcp HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".to_owned(), "403"),
            ("POST /token/citadel/v1/mcp HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n".to_owned(), "400"),
            ("POST /token/citadel/v1/mcp HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n".to_owned(), "400"),
            (format!("POST /token/citadel/v1/mcp HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(20_000)), "431"),
        ] {
            let got = status(&sock, raw.as_bytes()).await;
            assert!(got.contains(want), "{want}: {got}");
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a refused request reached the Core"
        );
        assert!(status(&sock, REQ.as_bytes()).await.contains("200"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn connections_are_capped_and_ending_the_bridge_closes_them_all() {
        let (bridge, sock, _) = rig("cap").await;
        let mut held = Vec::new();
        for _ in 0..PER_RUN {
            held.push(UnixStream::connect(&sock).await.unwrap());
        }
        // Every slot is taken by an idle client: the next one is closed without a reply.
        let mut extra = UnixStream::connect(&sock).await.unwrap();
        let mut buf = [0; 8];
        let n = timeout(Duration::from_secs(5), extra.read(&mut buf))
            .await
            .expect("the extra connection hung");
        assert!(matches!(n, Ok(0)), "over the limit: {n:?}");
        drop(bridge);
        for mut c in held {
            let n = timeout(Duration::from_secs(5), c.read(&mut buf))
                .await
                .expect("a connection outlived the bridge");
            assert!(matches!(n, Ok(0) | Err(_)));
        }
    }

    #[test]
    fn the_sandbox_url_keeps_the_path_and_drops_the_host() {
        let (t, local) = parse("https://core.example:8443/token/citadel/v1/mcp").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.tls),
            ("core.example", 8443, true)
        );
        assert_eq!(
            local,
            format!("http://127.0.0.1:{FORWARD_PORT}/token/citadel/v1/mcp")
        );
        assert_eq!(parse("http://127.0.0.1:7700/x").unwrap().0.port, 7700);
        assert_eq!(parse("https://h/x").unwrap().0.port, 443);
        assert!(parse("ftp://h/x").is_none());
    }
}
