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

use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
    copy, copy_bidirectional, split,
};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::task::JoinHandle;

/// The port inside the sandbox's own network namespace (a fresh one, so a fixed number is safe).
pub const FORWARD_PORT: u16 = 47831;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    /// The Core as the enrolment names it (`host[:port]`): what the Core expects in `Host`.
    pub authority: String,
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
            },
            format!("http://127.0.0.1:{FORWARD_PORT}/{path}"),
        )
    })
}

/// Aborts the listener when dropped (the run ended).
pub struct Bridge(JoinHandle<()>);

impl Drop for Bridge {
    fn drop(&mut self) {
        self.0.abort();
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

async fn upstream(
    target: &Target,
    tls: &Arc<rustls::ClientConfig>,
    client: UnixStream,
) -> io::Result<()> {
    let tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
    if target.tls {
        let name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(io::Error::other)?;
        let tls = tokio_rustls::TlsConnector::from(tls.clone())
            .connect(name, tcp)
            .await?;
        relay(client, tls, &target.authority).await
    } else {
        relay(client, tcp, &target.authority).await
    }
}

/// Client requests go through `rewrite_requests`; responses are copied as they come.
async fn relay<U: AsyncRead + AsyncWrite + Unpin>(
    client: UnixStream,
    up: U,
    authority: &str,
) -> io::Result<()> {
    let (cr, mut cw) = split(client);
    let (mut ur, mut uw) = split(up);
    let requests = async {
        let r = rewrite_requests(BufReader::new(cr), &mut uw, authority).await;
        let _ = uw.shutdown().await;
        r
    };
    let (a, b) = tokio::join!(requests, copy(&mut ur, &mut cw));
    a.and(b.map(|_| ()))
}

const MAX_HEAD: usize = 64 * 1024;

/// Copies HTTP/1.x requests from `r` to `w`, setting `Host` to `authority` on each: the sandbox
/// dialled the forwarder's loopback address, but the Core only answers to its own name. Handles
/// keep-alive (many requests per connection), heads split across reads, and bodies sized by
/// `Content-Length` or `chunked`.
pub async fn rewrite_requests<R, W>(mut r: R, mut w: W, authority: &str) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_owned());
    let mut line = Vec::new();
    loop {
        let mut head = Vec::new();
        let (mut length, mut chunked, mut first) = (0u64, false, true);
        loop {
            line.clear();
            if r.read_until(b'\n', &mut line).await? == 0 {
                return if first {
                    w.flush().await
                } else {
                    Err(bad("truncated head"))
                };
            }
            first = false;
            if head.len() + line.len() > MAX_HEAD {
                return Err(bad("head too large"));
            }
            if line == b"\r\n" {
                break;
            }
            let text = String::from_utf8_lossy(&line).to_ascii_lowercase();
            if text.starts_with("host:") {
                head.extend_from_slice(format!("Host: {authority}\r\n").as_bytes());
                continue;
            }
            if let Some(v) = text.strip_prefix("content-length:") {
                length = v.trim().parse().map_err(|_| bad("content-length"))?;
            } else if text.starts_with("transfer-encoding:") && text.contains("chunked") {
                chunked = true;
            }
            head.extend_from_slice(&line);
        }
        head.extend_from_slice(b"\r\n");
        w.write_all(&head).await?;
        if chunked {
            loop {
                line.clear();
                r.read_until(b'\n', &mut line).await?;
                w.write_all(&line).await?;
                let size = u64::from_str_radix(
                    String::from_utf8_lossy(&line)
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim(),
                    16,
                )
                .map_err(|_| bad("chunk size"))?;
                if size == 0 {
                    // Trailers, up to the blank line.
                    loop {
                        line.clear();
                        if r.read_until(b'\n', &mut line).await? == 0 {
                            return Err(bad("truncated trailer"));
                        }
                        w.write_all(&line).await?;
                        if line == b"\r\n" {
                            break;
                        }
                    }
                    break;
                }
                copy(&mut (&mut r).take(size + 2), &mut w).await?;
            }
        } else {
            copy(&mut (&mut r).take(length), &mut w).await?;
        }
        w.flush().await?;
    }
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
    Ok(Bridge(tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let (target, tls) = (target.clone(), tls.clone());
            tokio::spawn(async move {
                if let Err(e) = upstream(&target, &tls, client).await {
                    tracing::debug!(error = %e, "mcp bridge connection ended");
                }
            });
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

    #[tokio::test]
    async fn every_request_on_a_connection_gets_the_core_host() {
        let input = b"POST /a HTTP/1.1\r\nhOsT: 127.0.0.1:47831\r\nContent-Length: 5\r\n\r\nHost:\
            GET /b HTTP/1.1\r\nHost: 127.0.0.1:47831\r\n\r\n\
            POST /c HTTP/1.1\r\nTransfer-Encoding: chunked\r\nHost: x\r\n\r\n3\r\nabc\r\n0\r\n\r\n\
            GET /d HTTP/1.1\r\nHost: y\r\n\r\n";
        // One byte per read: a head split anywhere still parses.
        let (mut tx, rx) = tokio::io::duplex(1);
        let feed = tokio::spawn(async move {
            for b in input.iter() {
                tx.write_all(&[*b]).await.unwrap();
            }
        });
        let mut out = Vec::new();
        rewrite_requests(BufReader::new(rx), &mut out, "core.example:8443")
            .await
            .unwrap();
        feed.await.unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(
            out.matches("Host: core.example:8443\r\n").count(),
            4,
            "{out}"
        );
        assert!(!out.contains("47831") && !out.contains("Host: x") && !out.contains("Host: y"));
        assert!(out.contains("\r\n\r\nHost:GET /b") && out.contains("3\r\nabc\r\n0\r\n\r\nGET /d"));
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
