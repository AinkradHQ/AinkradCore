//! A loopback relay between git and the Core's repo copies (Projects P3-02). The Core serves a
//! copy only to signed requests of a runner device that holds a lease for the repo
//! (`ainkrad_core_server::mirrors`), and git cannot sign: for the minutes a session's checkout is
//! made, this relay takes git's plain HTTP on `127.0.0.1`, has the runner's own key sign it
//! (`Upstream`), and passes the Core's answer back.
//!
//! Security model:
//! - Only for the clone: one relay per `prepare_session`, dropped (its socket closed) as soon as
//!   the clones end. It carries no credential; the signing key stays in the closure `Upstream`.
//! - Only the two upload-pack calls of the repo ids the session was granted: any other path,
//!   method or repo id is a 404 before anything leaves the machine. A push is not expressible.
//! - Another process on this machine (another session's agent) must not ride it: the port is
//!   random and every path starts with a 128-bit random token, so a stranger cannot name a URL.
//!   The token is in git's argv for seconds, as visible to the same user as the checkout itself;
//!   the checkout's `origin` is reset to the real remote afterwards, so neither token nor port is
//!   left in the repo.
//! - Bounded: heads of at most 16 KiB, bodies of at most 1 MiB (the Core's signed-body limit),
//!   one request per connection, 30 s to send a request.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HEAD_MAX: usize = 16 * 1024;
const BODY_MAX: usize = 1024 * 1024;

/// One call to the Core: the path and query it signs for, git's `Git-Protocol` and
/// `Content-Encoding` headers, the body.
pub struct Call {
    pub method: &'static str,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// What the Core answered: the status, the content type, and the body as it arrives (`Err` ends it).
pub struct Reply {
    pub status: u16,
    pub content_type: String,
    pub body: tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
}

pub type Upstream = Arc<
    dyn Fn(Call) -> Pin<Box<dyn Future<Output = Result<Reply, String>> + Send>> + Send + Sync,
>;

pub struct Relay {
    port: u16,
    token: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Relay {
    /// Listens on a loopback port; serves only the copies of `allowed` repo ids.
    pub async fn start(up: Upstream, allowed: Vec<i64>) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let mut raw = [0u8; 16];
        SystemRandom::new()
            .fill(&mut raw)
            .map_err(|_| std::io::Error::other("no randomness"))?;
        let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let (t, allowed) = (token.clone(), Arc::new(allowed));
        let task = tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let (up, t, allowed) = (Arc::clone(&up), t.clone(), Arc::clone(&allowed));
                tokio::spawn(async move {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(30 * 60),
                        serve(conn, &up, &t, &allowed),
                    )
                    .await;
                });
            }
        });
        Ok(Self { port, token, task })
    }

    /// The URL git clones repo `id`'s copy from.
    pub fn url(&self, id: i64) -> String {
        format!("http://127.0.0.1:{}/{}/mirrors/{id}", self.port, self.token)
    }
}

async fn status(conn: &mut TcpStream, code: u16, why: &str) {
    let head = format!(
        "HTTP/1.1 {code} {why}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
    );
    let _ = conn.write_all(head.as_bytes()).await;
}

/// The request head: method, target, headers (names lowercased), and what was read past it.
async fn head(conn: &mut TcpStream) -> Option<(String, String, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::new();
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > HEAD_MAX {
            return None;
        }
        let mut chunk = [0u8; 2048];
        let n = tokio::time::timeout(Duration::from_secs(30), conn.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let text = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target) = (first.next()?.to_owned(), first.next()?.to_owned());
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    Some((method, target, headers, buf[end + 4..].to_vec()))
}

async fn serve(mut conn: TcpStream, up: &Upstream, token: &str, allowed: &[i64]) {
    let Some((method, target, headers, mut body)) = head(&mut conn).await else {
        return status(&mut conn, 400, "Bad Request").await;
    };
    // `/<token>/mirrors/<id>/<tail>[?query]`, nothing else.
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let mut parts = path.trim_start_matches('/').splitn(4, '/');
    let routed = (|| {
        if parts.next()? != token || parts.next()? != "mirrors" {
            return None;
        }
        let id: i64 = parts.next()?.parse().ok().filter(|id| allowed.contains(id))?;
        match (method.as_str(), parts.next()?, query) {
            ("GET", "info/refs", "service=git-upload-pack") => Some((id, "GET", "info/refs")),
            ("POST", "git-upload-pack", "") => Some((id, "POST", "git-upload-pack")),
            _ => None,
        }
    })();
    let Some((id, method, tail)) = routed else {
        return status(&mut conn, 404, "Not Found").await;
    };
    let header = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
    if method == "POST" {
        if header("transfer-encoding").is_some() {
            return status(&mut conn, 411, "Length Required").await;
        }
        let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) else {
            return status(&mut conn, 411, "Length Required").await;
        };
        if len > BODY_MAX {
            return status(&mut conn, 413, "Payload Too Large").await;
        }
        if header("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
            let _ = conn.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await;
        }
        while body.len() < len {
            let mut chunk = [0u8; 8192];
            match tokio::time::timeout(Duration::from_secs(30), conn.read(&mut chunk)).await {
                Ok(Ok(n)) if n > 0 => body.extend_from_slice(&chunk[..n]),
                _ => return,
            }
        }
        body.truncate(len);
    } else {
        body.clear();
    }
    let forward = ["git-protocol", "content-encoding"]
        .into_iter()
        .filter_map(|n| Some((n.to_owned(), header(n)?)))
        .collect();
    let call = Call {
        method,
        path: format!("/api/v1/mirrors/{id}/{tail}"),
        query: query.to_owned(),
        headers: forward,
        body,
    };
    let Ok(mut reply) = up(call).await else {
        return status(&mut conn, 502, "Bad Gateway").await;
    };
    let head = format!(
        "HTTP/1.1 {} X\r\ncontent-type: {}\r\ncache-control: no-cache\r\nconnection: close\r\n\r\n",
        reply.status, reply.content_type
    );
    if conn.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    while let Some(Ok(chunk)) = reply.body.recv().await {
        if conn.write_all(&chunk).await.is_err() {
            return;
        }
    }
    let _ = conn.shutdown().await;
}
