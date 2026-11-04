//! One connection of the gateway: one request, one response, then close (`Connection: close`),
//! so there is no pipelining and no connection outlives its check (KAN-435 G3).
//!
//! Order of refusals: the head is bounded and parsed strictly (400/411/426/431), then the route
//! (403/405), the body is read by its length (411/413) and parsed (400), the model is checked
//! (403), then the rate and concurrency caps (429), and only then is the upstream dialled. Nothing
//! the agent sent as auth, and no header outside the allowlist, goes upstream.

use std::time::Duration;

use ainkrad_proto::v2::{GatewayAuth, Wire};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Instant, timeout};

use super::dial::DialError;
use super::request::{MAX_HEAD, Refusal, Request, header_ok, refuse};
use super::route::route;
use super::{Config, Shared};

/// From accepting a connection to the blank line ending the head.
const HEAD: Duration = Duration::from_secs(10);
/// The whole request body.
const BODY: Duration = Duration::from_secs(60);
/// One write to the harness; a client that stops reading is dropped.
const WRITE: Duration = Duration::from_secs(60);

/// How a connection ends without a response the gateway wrote.
enum End {
    Refuse(Refusal),
    /// Close without a word: the response was already started.
    Drop,
}

impl From<Refusal> for End {
    fn from(r: Refusal) -> End {
        End::Refuse(r)
    }
}

/// What the body is probed for. A derived struct refuses a duplicate `model` key, so the model
/// checked here is the one the upstream reads; unknown fields are only syntax-checked.
#[derive(Deserialize)]
struct Probe {
    model: Option<String>,
}

pub(super) async fn connection(sh: &Shared, mut c: UnixStream) {
    match serve(sh, &mut c).await {
        Ok(()) | Err(End::Drop) => {}
        Err(End::Refuse(r)) => {
            let _ = write_error(&mut c, r).await;
        }
    }
    let _ = c.shutdown().await;
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Content Too Large",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

async fn put(c: &mut UnixStream, bytes: &[u8]) -> Result<(), End> {
    match timeout(WRITE, async {
        c.write_all(bytes).await?;
        c.flush().await
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        _ => Err(End::Drop),
    }
}

/// A refusal's answer: a small JSON error the harness's SDK can read, never provider text.
async fn write_error(c: &mut UnixStream, r: Refusal) -> Result<(), End> {
    let body = format!(
        "{{\"type\":\"error\",\"error\":{{\"type\":\"{0}\",\"message\":\"{0}\"}}}}",
        r.code
    );
    let extra = match r.status {
        405 => "Allow: POST\r\n",
        429 => "Retry-After: 5\r\n",
        _ => "",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
        r.status,
        reason(r.status),
        body.len()
    );
    put(c, head.as_bytes()).await?;
    put(c, body.as_bytes()).await
}

/// The head, and the bytes read past it (the start of the body).
async fn read_head(c: &mut UnixStream) -> Result<(Vec<u8>, Vec<u8>), Refusal> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let read = async {
        loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let rest = buf.split_off(i + 4);
                buf.truncate(i);
                return Ok((buf, rest));
            }
            if buf.len() > MAX_HEAD {
                return Err(refuse(431, "head_too_large"));
            }
            match c.read(&mut chunk).await {
                Ok(n) if n > 0 => buf.extend_from_slice(&chunk[..n]),
                _ => return Err(refuse(400, "bad_request")),
            }
        }
    };
    timeout(HEAD, read)
        .await
        .map_err(|_| refuse(400, "bad_request"))?
}

async fn read_body(c: &mut UnixStream, mut have: Vec<u8>, len: usize) -> Result<Vec<u8>, Refusal> {
    have.truncate(len); // bytes past the length would be a second request: dropped, then closed
    let read = async {
        while have.len() < len {
            let mut chunk = vec![0u8; (len - have.len()).min(64 * 1024)];
            match c.read(&mut chunk).await {
                Ok(n) if n > 0 => have.extend_from_slice(&chunk[..n]),
                _ => return false,
            }
        }
        true
    };
    match timeout(BODY, read).await {
        Ok(true) => Ok(have),
        _ => Err(refuse(400, "bad_request")),
    }
}

/// Counts a request against the per-minute window; the permit is the concurrency cap.
fn admit(sh: &Shared) -> Result<tokio::sync::OwnedSemaphorePermit, Refusal> {
    let permit = sh
        .inflight
        .clone()
        .try_acquire_owned()
        .map_err(|_| refuse(429, "gateway_busy"))?;
    let now = Instant::now();
    let mut w = sh.window.lock().expect("rate window lock");
    while w
        .front()
        .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60))
    {
        w.pop_front();
    }
    if w.len() >= sh.cfg.rate.per_minute as usize {
        return Err(refuse(429, "gateway_rate"));
    }
    w.push_back(now);
    Ok(permit)
}

fn dial_refusal(e: DialError) -> Refusal {
    match e {
        DialError::Refused(_) => refuse(502, "gateway_refused_address"),
        DialError::Tls => refuse(502, "gateway_tls_failed"),
        DialError::BadRequest => refuse(400, "bad_request"),
        DialError::Upstream | DialError::Truncated => refuse(502, "gateway_bad_upstream"),
        DialError::BadHost | DialError::Resolve | DialError::Unreachable => {
            refuse(502, "gateway_upstream_unreachable")
        }
    }
}

/// The headers of the upstream request: the allow-listed ones the agent sent (a repeat of one is
/// ambiguous, so refused), a JSON content type if none, and the gateway's own auth.
fn upstream_headers(cfg: &Config, req: &Request) -> Result<Vec<(String, String)>, Refusal> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (n, v) in req.headers.iter().filter(|(n, _)| header_ok(n)) {
        if out.iter().any(|o| &o.0 == n) {
            return Err(refuse(400, "bad_request"));
        }
        out.push((n.clone(), v.clone()));
    }
    if !out.iter().any(|(n, _)| n == "content-type") {
        out.push(("content-type".to_owned(), "application/json".to_owned()));
    }
    let key = cfg.key.expose();
    out.push(match cfg.upstream.auth {
        GatewayAuth::XApiKey => ("x-api-key".to_owned(), key.to_owned()),
        GatewayAuth::Bearer => ("authorization".to_owned(), format!("Bearer {key}")),
        GatewayAuth::XGoogApiKey => ("x-goog-api-key".to_owned(), key.to_owned()),
    });
    Ok(out)
}

async fn serve(sh: &Shared, c: &mut UnixStream) -> Result<(), End> {
    let cfg = &sh.cfg;
    let (raw, early) = read_head(c).await?;
    let req = Request::parse(&raw)?;
    let routed = route(
        cfg.upstream.wire,
        &cfg.upstream.base_path,
        &req.method,
        &req.target,
    )?;
    let len = req.length.ok_or(refuse(411, "length_required"))?;
    if len > cfg.max_body {
        return Err(refuse(413, "body_too_large").into());
    }
    let body = read_body(c, early, len).await?;
    // An object only: a derived struct would also read a JSON array as its fields in order.
    if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(refuse(400, "bad_json").into());
    }
    let probe: Probe = serde_json::from_slice(&body).map_err(|_| refuse(400, "bad_json"))?;
    // The model: in the path on the Gemini wire, in the body on the others.
    let model = match cfg.upstream.wire {
        Wire::GeminiGenerate => routed.path_model,
        _ => probe.model,
    };
    if !model.is_some_and(|m| cfg.models.contains(&m)) {
        return Err(refuse(403, "model_not_allowed").into());
    }
    let headers = upstream_headers(cfg, &req)?;
    let _permit = admit(sh)?;
    let pairs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let mut up = cfg
        .dialer
        .open(
            &cfg.upstream.host,
            "POST",
            &routed.target,
            &pairs,
            &body,
            cfg.max_response,
        )
        .await
        .map_err(|e| {
            tracing::debug!(error = ?e, "gateway upstream not opened");
            dial_refusal(e)
        })?;
    // The response head: the allow-listed headers, minus any whose value holds the key.
    let key = cfg.key.expose();
    let mut head = format!("HTTP/1.1 {} {}\r\n", up.status, reason(up.status));
    for (n, v) in up.headers.iter().filter(|(_, v)| !v.contains(key)) {
        head.push_str(&format!("{n}: {v}\r\n"));
    }
    // The body's framing is the gateway's own: a length is passed on and checked, anything else
    // is chunked, and a chunked stream that ends in an error never gets its last chunk.
    let framed = !matches!(up.status, 204 | 304);
    let chunked = framed && up.length.is_none();
    match up.length {
        Some(n) if framed => head.push_str(&format!("Content-Length: {n}\r\n")),
        _ if chunked => head.push_str("Transfer-Encoding: chunked\r\n"),
        _ => {}
    }
    head.push_str("Connection: close\r\n\r\n");
    put(c, head.as_bytes()).await?;
    let mut sent = 0usize;
    loop {
        match up.body.next().await {
            Ok(Some(piece)) => {
                sent += piece.len();
                let mut out = Vec::with_capacity(piece.len() + 16);
                if chunked {
                    out.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                }
                out.extend_from_slice(&piece);
                if chunked {
                    out.extend_from_slice(b"\r\n");
                }
                put(c, &out).await?; // flushed per piece: a stream is not buffered here
            }
            Ok(None) => break,
            Err(e) => {
                // A read error, a truncation or the ceiling: the stream ends without a last
                // chunk (or short of its length), so the harness sees an error, not a clean end.
                tracing::debug!(error = ?e, sent, "gateway response cut");
                return Err(End::Drop);
            }
        }
    }
    if chunked {
        put(c, b"0\r\n\r\n").await?;
    }
    tracing::debug!(status = up.status, sent, "gateway response");
    Ok(())
}
