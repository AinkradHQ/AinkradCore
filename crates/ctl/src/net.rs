//! Getting bytes to the Core: HTTP/1.1 over a Unix socket, plain TCP (`loopback`), or TLS 1.3
//! (`public`), one connection per request; and the event WebSocket over the same streams.
//!
//! TLS verifies the certificate against the web PKI roots (plus `--ca` for a private CA). The
//! certificate is **not** pinned (spec §13: ACME rotates it); what is pinned is the Core
//! identity, checked at the application layer before anything is signed (`client`).

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

use crate::Error;

/// Any of the three streams.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Stream = Pin<Box<dyn Io>>;
pub type Ws = WebSocketStream<Stream>;

/// Where the Core is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Unix(PathBuf),
    /// `host:port`, plain HTTP.
    Http(String),
    /// `host:port`, TLS.
    Https(String),
}

impl Endpoint {
    /// `unix:<path>`, `http://host:port` or `https://host[:port]`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let bad = || {
            Error::Usage(format!(
                "{text:?}: an endpoint is unix:<path>, http://host:port or https://host[:port]"
            ))
        };
        if let Some(p) = text.strip_prefix("unix:") {
            return (!p.is_empty())
                .then(|| Self::Unix(p.into()))
                .ok_or_else(bad);
        }
        let (tls, rest) = match text.split_once("://") {
            Some(("http", r)) => (false, r),
            Some(("https", r)) => (true, r),
            _ => return Err(bad()),
        };
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
            return Err(bad());
        }
        Ok(match (tls, authority.contains(':')) {
            (true, _) => Self::Https(authority.to_owned()),
            (false, true) => Self::Http(authority.to_owned()),
            (false, false) => return Err(bad()),
        })
    }

    /// The `Host` the Core expects by default: `localhost` on a socket, else the authority
    /// as written (the server's own default, `Listen::default_host`).
    pub fn default_host(&self) -> String {
        match self {
            Self::Unix(_) => "localhost".to_owned(),
            Self::Http(a) | Self::Https(a) => a.clone(),
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unix(p) => write!(f, "unix:{}", p.display()),
            Self::Http(a) => write!(f, "http://{a}"),
            Self::Https(a) => write!(f, "https://{a}"),
        }
    }
}

/// A response, read whole.
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub headers: hyper::HeaderMap,
    pub body: Vec<u8>,
}

/// How to reach the Core: the endpoint, the `Host` to send, and the TLS client.
#[derive(Clone)]
pub struct Net {
    pub endpoint: Endpoint,
    pub host: String,
    tls: Arc<rustls::ClientConfig>,
}

impl Net {
    /// `ca`: a PEM file of extra roots to trust (a private CA), beside the web PKI's.
    pub fn new(
        endpoint: Endpoint,
        host: Option<String>,
        ca: Option<&std::path::Path>,
    ) -> Result<Self, Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(ca) = ca {
            let certs = CertificateDer::pem_file_iter(ca)
                .and_then(|i| i.collect::<Result<Vec<_>, _>>())
                .map_err(|e| Error::Usage(format!("--ca {}: {e}", ca.display())))?;
            for c in certs {
                roots
                    .add(c)
                    .map_err(|e| Error::Usage(format!("--ca {}: {e}", ca.display())))?;
            }
        }
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring supports TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            host: host.unwrap_or_else(|| endpoint.default_host()),
            endpoint,
            tls: Arc::new(tls),
        })
    }

    async fn connect(&self) -> Result<Stream, Error> {
        let down = |e: std::io::Error| Error::Unreachable(format!("{}: {e}", self.endpoint));
        Ok(match &self.endpoint {
            Endpoint::Unix(p) => Box::pin(UnixStream::connect(p).await.map_err(down)?),
            Endpoint::Http(a) => Box::pin(TcpStream::connect(a).await.map_err(down)?),
            Endpoint::Https(a) => {
                let tcp = match a.contains(':') {
                    true => TcpStream::connect(a.as_str()).await,
                    false => TcpStream::connect((a.as_str(), 443)).await,
                }
                .map_err(down)?;
                let name = a.rsplit_once(':').map_or(a.as_str(), |(h, _)| h);
                let name = ServerName::try_from(name.to_owned())
                    .map_err(|_| Error::Usage(format!("{name:?} is not a TLS server name")))?;
                let tls = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls))
                    .connect(name, tcp)
                    .await
                    .map_err(|e| Error::Unreachable(format!("TLS with {}: {e}", self.endpoint)))?;
                Box::pin(tls)
            }
        })
    }

    /// One request on a new connection. `target` is the path and query exactly as signed.
    pub async fn send(
        &self,
        method: &str,
        target: &str,
        headers: &[(&str, String)],
        body: Vec<u8>,
    ) -> Result<Response, Error> {
        let io = TokioIo::new(self.connect().await?);
        let lost = |e: hyper::Error| Error::Unreachable(format!("{}: {e}", self.endpoint));
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(lost)?;
        tokio::spawn(conn);
        let mut req = hyper::Request::builder()
            .method(method)
            .uri(target)
            .header("host", &self.host);
        if !body.is_empty() {
            req = req.header("content-type", "application/json");
        }
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        let req = req
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| Error::Usage(format!("{method} {target}: {e}")))?;
        let res = sender.send_request(req).await.map_err(lost)?;
        let (parts, body) = res.into_parts();
        let body = body.collect().await.map_err(lost)?.to_bytes().to_vec();
        Ok(Response {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body,
        })
    }

    /// Opens a WebSocket at `path` with `headers` on the upgrade request.
    pub async fn websocket(
        &self,
        path: &str,
        headers: &[(&str, String)],
    ) -> Result<WebSocketStream<Stream>, WsError> {
        let stream = self.connect().await.map_err(WsError::Net)?;
        let mut req = format!("ws://{}{path}", self.host)
            .into_client_request()
            .map_err(|e| WsError::Net(Error::Usage(format!("{path}: {e}"))))?;
        for (k, v) in headers {
            let value = v
                .parse()
                .map_err(|_| WsError::Net(Error::Usage(format!("header {k}"))))?;
            let name = hyper::header::HeaderName::from_bytes(k.as_bytes())
                .map_err(|_| WsError::Net(Error::Usage(format!("header {k}"))))?;
            req.headers_mut().insert(name, value);
        }
        match tokio_tungstenite::client_async(req, stream).await {
            Ok((ws, _)) => Ok(ws),
            Err(tokio_tungstenite::tungstenite::Error::Http(res)) => {
                let (parts, body) = res.into_parts();
                Err(WsError::Refused(Box::new(Response {
                    status: parts.status.as_u16(),
                    headers: parts.headers,
                    body: body.unwrap_or_default(),
                })))
            }
            Err(e) => Err(WsError::Net(Error::Unreachable(format!(
                "{}: {e}",
                self.endpoint
            )))),
        }
    }
}

/// Why an upgrade failed: the Core answered with something other than 101, or never answered.
#[derive(Debug)]
pub enum WsError {
    Refused(Box<Response>),
    Net(Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_parse() {
        assert_eq!(
            Endpoint::parse("unix:/s").unwrap(),
            Endpoint::Unix("/s".into())
        );
        assert_eq!(
            Endpoint::parse("http://127.0.0.1:7700/")
                .unwrap()
                .default_host(),
            "127.0.0.1:7700"
        );
        assert_eq!(
            Endpoint::parse("https://core.example").unwrap().to_string(),
            "https://core.example"
        );
        for bad in [
            "unix:",
            "ftp://x",
            "http://x",
            "https://x/api",
            "https://u@x",
            "x",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }
}
