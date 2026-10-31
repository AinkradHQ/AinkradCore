//! The TLS accept loop and the minimal HTTP/1.1 in front of `git http-backend`.

use std::io;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use crate::Ca;

/// How one server behaves. Checks run in this order: stall, token, redirect, serve.
#[derive(Clone, Default)]
pub struct Config {
    /// The directory holding the bare repos, served at `/<name>`.
    pub root: PathBuf,
    /// Require `Authorization: Basic x-access-token:<token>`; otherwise answer 401.
    pub token: Option<String>,
    /// Answer 302 to `<base><same path and query>`, once the token (if any) was accepted.
    pub redirect: Option<String>,
    /// Read the request and then never answer, until the client hangs up.
    pub stall: bool,
    /// Forward the git response `n` bytes per `delay`, so a transfer can be cut off mid-way.
    pub throttle: Option<(usize, Duration)>,
}

/// One request the server saw.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub target: String,
    /// The `Authorization` header, if the client sent one.
    pub authorization: Option<String>,
}

#[derive(Default)]
struct State {
    seen: Mutex<Vec<Seen>>,
    sent: AtomicU64,
    hung_up: AtomicU64,
}

/// A running server; dropping it stops the accept loop, every connection and every git child.
pub struct Server {
    pub port: u16,
    state: Arc<State>,
    accept: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        // Aborting the loop drops its `JoinSet`, which aborts the connections, which drop (and
        // so kill) their `kill_on_drop` git children.
        self.accept.abort();
    }
}

impl Server {
    pub async fn start(ca: &Ca, config: Config) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(State::default());
        let (acceptor, config) = (TlsAcceptor::from(ca.tls.clone()), Arc::new(config));
        let shared = state.clone();
        let accept = tokio::spawn(async move {
            let mut conns = JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let (acceptor, config, state) = (acceptor.clone(), config.clone(), shared.clone());
                conns.spawn(async move {
                    let _ = connection(stream, acceptor, &config, &state).await;
                });
            }
        });
        Self {
            port,
            state,
            accept,
        }
    }

    /// `https://<host>:<port>/<repo>`: pass `localhost` or `127.0.0.1` (both are in the cert),
    /// so one server answers as two different hosts.
    pub fn url(&self, host: &str, repo: &str) -> String {
        format!("https://{host}:{}/{repo}", self.port)
    }

    pub fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().unwrap().clone()
    }

    /// Bytes of git response forwarded so far.
    pub fn sent(&self) -> u64 {
        self.state.sent.load(Ordering::Relaxed)
    }

    /// Connections a stalled request ended by the client hanging up.
    pub fn hung_up(&self) -> u64 {
        self.state.hung_up.load(Ordering::Relaxed)
    }
}

fn base64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in input.chunks(3) {
        let n = u32::from(c[0]) << 16
            | u32::from(*c.get(1).unwrap_or(&0)) << 8
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            match i <= c.len() {
                true => out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char),
                false => out.push('='),
            }
        }
    }
    out
}

async fn line(r: &mut (impl AsyncBufReadExt + Unpin)) -> io::Result<String> {
    let mut s = String::new();
    if r.read_line(&mut s).await? == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(s.trim_end().to_owned())
}

async fn connection(
    stream: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    config: &Config,
    state: &State,
) -> io::Result<()> {
    let (rd, mut wr) = tokio::io::split(acceptor.accept(stream).await?);
    let mut rd = BufReader::new(rd);
    let request = line(&mut rd).await?;
    let mut words = request.split_whitespace();
    let (method, target) = (words.next().unwrap_or(""), words.next().unwrap_or("/"));
    let mut headers = vec![];
    loop {
        let l = line(&mut rd).await?;
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.to_ascii_lowercase(), v.trim().to_owned()));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    if header("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
        wr.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
    }
    let mut body = vec![];
    if header("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        loop {
            let size = line(&mut rd).await?;
            let size = usize::from_str_radix(size.split(';').next().unwrap_or("0"), 16)
                .map_err(io::Error::other)?;
            if size == 0 {
                while !line(&mut rd).await?.is_empty() {}
                break;
            }
            let at = body.len();
            body.resize(at + size, 0);
            rd.read_exact(&mut body[at..]).await?;
            line(&mut rd).await?;
        }
    } else if let Some(n) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        body.resize(n, 0);
        rd.read_exact(&mut body).await?;
    }
    let authorization = header("authorization");
    state.seen.lock().unwrap().push(Seen {
        method: method.to_owned(),
        target: target.to_owned(),
        authorization: authorization.clone(),
    });
    if config.stall {
        let mut byte = [0u8; 1];
        while matches!(rd.read(&mut byte).await, Ok(n) if n > 0) {}
        state.hung_up.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    if let Some(token) = &config.token {
        let want = format!(
            "Basic {}",
            base64(format!("x-access-token:{token}").as_bytes())
        );
        if authorization.as_deref() != Some(&want) {
            let reply = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"git\"\r\n\
                         Content-Length: 0\r\nConnection: close\r\n\r\n";
            wr.write_all(reply.as_bytes()).await?;
            return wr.shutdown().await;
        }
    }
    if let Some(base) = &config.redirect {
        let reply = format!(
            "HTTP/1.1 302 Found\r\nLocation: {base}{target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        wr.write_all(reply.as_bytes()).await?;
        return wr.shutdown().await;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut cgi = Command::new("git");
    cgi.arg("http-backend")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_PROJECT_ROOT", &config.root)
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("REQUEST_METHOD", method)
        .env("PATH_INFO", path)
        .env("QUERY_STRING", query)
        .env("CONTENT_TYPE", header("content-type").unwrap_or_default())
        .env("CONTENT_LENGTH", body.len().to_string())
        .env("REMOTE_ADDR", "127.0.0.1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    if let Some(v) = header("content-encoding") {
        cgi.env("HTTP_CONTENT_ENCODING", v);
    }
    if let Some(v) = header("git-protocol") {
        cgi.env("HTTP_GIT_PROTOCOL", v);
    }
    let mut child = cgi.spawn()?;
    let mut stdin = child.stdin.take().expect("piped");
    tokio::spawn(async move {
        let _ = stdin.write_all(&body).await;
    });
    let mut out = BufReader::new(child.stdout.take().expect("piped"));
    let mut status = "200 OK".to_owned();
    let mut head = String::new();
    loop {
        let l = line(&mut out).await?;
        if l.is_empty() {
            break;
        }
        match l.strip_prefix("Status:") {
            Some(s) => status = s.trim().to_owned(),
            None => head.push_str(&format!("{l}\r\n")),
        }
    }
    wr.write_all(format!("HTTP/1.1 {status}\r\n{head}Connection: close\r\n\r\n").as_bytes())
        .await?;
    let (step, delay) = config.throttle.unwrap_or((16 * 1024, Duration::ZERO));
    let mut buf = vec![0u8; step];
    loop {
        let n = out.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        wr.write_all(&buf[..n]).await?;
        state.sent.fetch_add(n as u64, Ordering::Relaxed);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
    let _ = child.wait().await;
    wr.shutdown().await
}
