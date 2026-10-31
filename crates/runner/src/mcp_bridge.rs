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

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::task::JoinHandle;

/// The port inside the sandbox's own network namespace (a fresh one, so a fixed number is safe).
pub const FORWARD_PORT: u16 = 47831;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
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
            Target { host, port, tls },
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
    mut client: UnixStream,
) -> io::Result<()> {
    let tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
    if target.tls {
        let name = rustls::pki_types::ServerName::try_from(target.host.clone())
            .map_err(io::Error::other)?;
        let mut tls = tokio_rustls::TlsConnector::from(tls.clone())
            .connect(name, tcp)
            .await?;
        copy_bidirectional(&mut client, &mut tls).await?;
    } else {
        let mut tcp = tcp;
        copy_bidirectional(&mut client, &mut tcp).await?;
    }
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
