//! The accept loop and connection limits, the same for every listener, and the drain.
//!
//! Limits: a TLS handshake, the request headers (slowloris), a whole request and a silent
//! connection (`idle`) each get a deadline; the header block is capped in bytes and in count; a body is capped at
//! `Limits::body` (`preauth` caps pre-auth bodies lower). A WebSocket upgrade answers at
//! once, so the request deadline does not cut a socket short.
//!
//! Drain (E1-06.5): once `closing` is set, every listener stops accepting, event sockets
//! close themselves with 1012 (`api::v1::events`), and requests in flight get up to `grace`
//! to finish; idle keep-alive connections are closed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use super::{Exporter, Gateway, Listener, Local, preauth, tls};
use crate::api::v1::ApiError;

/// Request and connection limits.
#[derive(Debug, Clone)]
pub struct Limits {
    /// To finish a TLS handshake.
    pub tls_handshake: Duration,
    /// To send a request's headers: the slowloris deadline.
    pub header_read: Duration,
    /// For a whole request, body and answer included.
    pub request: Duration,
    /// The header block in bytes (hyper's floor is 8 KiB).
    pub header_bytes: usize,
    /// Headers per request.
    pub headers: usize,
    /// A request body in bytes.
    pub body: usize,
    /// With no byte moving either way (`idle`); longer than `request`, so a slow handler is
    /// cut by its deadline (408), not by this.
    pub idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            tls_handshake: Duration::from_secs(10),
            header_read: Duration::from_secs(10),
            request: Duration::from_secs(30),
            header_bytes: 16 * 1024,
            headers: 64,
            body: 1024 * 1024,
            idle: Duration::from_secs(60),
        }
    }
}

impl Gateway {
    /// Serves `app` until `closing` is set, then drains for up to `grace`. In public mode the
    /// certificate is renewed alongside (`acme::renew`) and :80 serves only HTTP-01.
    pub async fn serve(
        self,
        app: Router,
        closing: Arc<watch::Sender<bool>>,
        grace: Duration,
    ) -> std::io::Result<()> {
        let limits = Arc::new(self.limits);
        let deadline = limits.request;
        let app = app
            .layer(middleware::from_fn(move |req: Request, next: Next| {
                request_deadline(deadline, req, next)
            }))
            .layer(DefaultBodyLimit::max(limits.body));
        let graceful = GracefulShutdown::new();
        let tls = self
            .tls
            .as_ref()
            .map(|(certs, _)| TlsAcceptor::from(tls::server_config(Arc::clone(certs))));
        let renewing = self.tls.as_ref().map(|(certs, acme)| {
            let (certs, acme) = (Arc::clone(certs), acme.clone());
            let mut stopped = closing.subscribe();
            let held = Arc::clone(&certs);
            tokio::spawn(async move {
                let order = move || {
                    let (acme, certs) = (acme.clone(), Arc::clone(&certs));
                    async move { acme.order(&certs).await }
                };
                let stop = async move { crate::api::stopping(&mut stopped).await };
                let now = std::time::SystemTime::now;
                super::acme::renew(held, now, Duration::from_secs(60), order, stop).await;
            })
        });
        let app_admin = app.clone();
        let main = accept(self.main, tls, app, &limits, &graceful, closing.subscribe());
        let http01 = async {
            if let (Some(l80), Some((certs, _))) = (self.http01, &self.tls) {
                let router = preauth::http01_router(Arc::clone(certs));
                let l80 = Listener::Tcp(l80);
                accept(l80, None, router, &limits, &graceful, closing.subscribe()).await;
            }
        };
        let admin = async {
            if let Some(admin) = self.admin {
                let app = app_admin.clone();
                accept(admin, None, app, &limits, &graceful, closing.subscribe()).await;
            }
        };
        // Every loop ends once `closing` is set and drops its listener: nothing new comes.
        tokio::join!(main, http01, admin);
        if let Some(renewing) = renewing {
            renewing.abort();
        }
        if tokio::time::timeout(grace, graceful.shutdown())
            .await
            .is_err()
        {
            tracing::warn!(?grace, "requests still in flight after the grace; dropped");
        }
        Ok(())
    }
}

/// Accepts until `closing` is set; each connection is served on its own task.
async fn accept(
    listener: Listener,
    tls: Option<TlsAcceptor>,
    app: Router,
    limits: &Arc<Limits>,
    graceful: &GracefulShutdown,
    mut closing: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            a = next(&listener) => a,
            () = crate::api::stopping(&mut closing) => return,
        };
        let (io, peer) = match accepted {
            Ok(a) => a,
            Err(e) => {
                // Out of file descriptors and the like: back off instead of spinning.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (app, limits, watcher) = (app.clone(), Arc::clone(limits), graceful.watcher());
        match (io, &tls) {
            (Stream::Tcp(tcp), Some(tls)) => {
                let tls = tls.clone();
                tokio::spawn(async move {
                    let shake = tokio::time::timeout(limits.tls_handshake, tls.accept(tcp));
                    let Ok(Ok(stream)) = shake.await else { return };
                    // A TLS-ALPN-01 validation is over once the handshake is.
                    if stream.get_ref().1.alpn_protocol() == Some(tls::ACME_ALPN) {
                        return;
                    }
                    let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                    // TLS 1.3 only, so one exporter for the whole connection.
                    let mut x = [0; 32];
                    let label = ainkrad_proto::v2::EXPORTER_LABEL;
                    let exporter = match stream
                        .get_ref()
                        .1
                        .export_keying_material(&mut x, label, None)
                    {
                        Ok(_) => Some(Exporter(x)),
                        Err(e) => {
                            tracing::warn!(error = %e, "no TLS exporter");
                            None
                        }
                    };
                    let peer = Peer::Tls(peer, exporter);
                    serve_conn(stream, h2, peer, app, &limits, watcher).await;
                });
            }
            (Stream::Tcp(tcp), None) => {
                tokio::spawn(async move {
                    serve_conn(tcp, false, Peer::Tcp(peer), app, &limits, watcher).await
                });
            }
            (Stream::Unix(unix, local), _) => {
                tokio::spawn(async move {
                    let peer = Peer::Local(local);
                    serve_conn(unix, false, peer, app, &limits, watcher).await
                });
            }
        }
    }
}

enum Stream {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream, Local),
}

async fn next(listener: &Listener) -> std::io::Result<(Stream, Option<SocketAddr>)> {
    match listener {
        Listener::Tcp(l) => l.accept().await.map(|(s, a)| (Stream::Tcp(s), Some(a))),
        Listener::Unix(l, owner) => l.accept().await.map(|(s, _)| {
            let same_user = s.peer_cred().is_ok_and(|c| c.uid() == *owner);
            (Stream::Unix(s, Local { same_user }), None)
        }),
    }
}

/// HTTP/1.1 or HTTP/2 on one connection, upgrades (WebSockets) included. The peer address
/// reaches handlers as `ConnectInfo` (a socket peer has none: the client gate calls it
/// `local`).
/// Who is on the other end: a TCP address, or a local socket peer.
enum Peer {
    Tcp(Option<SocketAddr>),
    /// Over TLS, with its exporter.
    Tls(Option<SocketAddr>, Option<Exporter>),
    Local(Local),
}

async fn serve_conn<I>(io: I, h2: bool, peer: Peer, app: Router, limits: &Limits, w: Watcher)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
        match peer {
            Peer::Tcp(Some(addr)) => drop(req.extensions_mut().insert(ConnectInfo(addr))),
            Peer::Tls(addr, exporter) => {
                if let Some(addr) = addr {
                    req.extensions_mut().insert(ConnectInfo(addr));
                }
                if let Some(x) = exporter {
                    req.extensions_mut().insert(x);
                }
            }
            Peer::Local(local) => drop(req.extensions_mut().insert(local)),
            Peer::Tcp(None) => {}
        }
        app.clone().oneshot(req.map(axum::body::Body::new))
    });
    // The protocol is known (ALPN on TLS, HTTP/1.1 otherwise), so hyper does not sniff for
    // the HTTP/2 preface first: that read has no deadline, and a silent client would sit in it.
    let builder = auto::Builder::new(TokioExecutor::new());
    let mut builder = match h2 {
        true => builder.http2_only(),
        false => builder.http1_only(),
    };
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read)
        .max_buf_size(limits.header_bytes.max(8192))
        .max_headers(limits.headers);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_header_list_size(u32::try_from(limits.header_bytes).unwrap_or(u32::MAX));
    let (io, activity) = super::idle::wrap(io);
    let conn = w.watch(builder.serve_connection_with_upgrades(TokioIo::new(io), service));
    tokio::pin!(conn);
    loop {
        tokio::select! {
            ended = &mut conn => {
                if let Err(e) = ended {
                    tracing::debug!(error = %e, "connection ended");
                }
                return;
            }
            () = tokio::time::sleep_until(activity.deadline(limits.idle)) => {
                if activity.deadline(limits.idle) <= tokio::time::Instant::now() {
                    tracing::debug!("idle connection closed");
                    return;
                }
            }
        }
    }
}

/// The whole-request deadline: 408 when a handler (or a slow body) takes longer.
async fn request_deadline(deadline: Duration, req: Request, next: Next) -> Response {
    match tokio::time::timeout(deadline, next.run(req)).await {
        Ok(response) => response,
        Err(_) => ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            "timeout",
            "the request took too long",
        )
        .into_response(),
    }
}
