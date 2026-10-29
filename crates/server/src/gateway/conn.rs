//! The accept loop and connection limits, the same for every listener, and the drain.
//!
//! Limits: a TLS handshake, the request headers (slowloris) and a whole request each get a
//! deadline; the header block is capped in bytes and in count; a body is capped at
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

use super::{Gateway, Listener, preauth, tls};
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
        let main = accept(self.main, tls, app, &limits, &graceful, closing.subscribe());
        let http01 = async {
            if let (Some(l80), Some((certs, _))) = (self.http01, &self.tls) {
                let router = preauth::http01_router(Arc::clone(certs));
                let l80 = Listener::Tcp(l80);
                accept(l80, None, router, &limits, &graceful, closing.subscribe()).await;
            }
        };
        // Both loops end once `closing` is set and drop their listeners: nothing new comes.
        tokio::join!(main, http01);
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
                    serve_conn(stream, peer, app, &limits, watcher).await;
                });
            }
            (Stream::Tcp(tcp), None) => {
                tokio::spawn(async move { serve_conn(tcp, peer, app, &limits, watcher).await });
            }
            (Stream::Unix(unix), _) => {
                tokio::spawn(async move { serve_conn(unix, peer, app, &limits, watcher).await });
            }
        }
    }
}

enum Stream {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}

async fn next(listener: &Listener) -> std::io::Result<(Stream, Option<SocketAddr>)> {
    match listener {
        Listener::Tcp(l) => l.accept().await.map(|(s, a)| (Stream::Tcp(s), Some(a))),
        Listener::Unix(l) => l.accept().await.map(|(s, _)| (Stream::Unix(s), None)),
    }
}

/// HTTP/1.1 or HTTP/2 on one connection, upgrades (WebSockets) included. The peer address
/// reaches handlers as `ConnectInfo` (a socket peer has none: the client gate calls it
/// `local`).
async fn serve_conn<I>(io: I, peer: Option<SocketAddr>, app: Router, limits: &Limits, w: Watcher)
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
        if let Some(peer) = peer {
            req.extensions_mut().insert(ConnectInfo(peer));
        }
        app.clone().oneshot(req.map(axum::body::Body::new))
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
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
    let conn = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    if let Err(e) = w.watch(conn).await {
        tracing::debug!(error = %e, "connection ended");
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
