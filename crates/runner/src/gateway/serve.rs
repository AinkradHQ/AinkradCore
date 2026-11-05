//! One connection of the gateway: one request, one response, then close (`Connection: close`),
//! so there is no pipelining and no connection outlives its check (KAN-435 G3).
//!
//! Order of refusals: the head is bounded and parsed strictly (400/411/426/431), then the route
//! (403/405) and the body's length (411/413), then the concurrency permit (429: it is taken
//! before the body is read, so what the gateway holds in memory is bounded by the cap, not by the
//! connections), the body is read and parsed (400), the model and its tools are checked (403),
//! the rate cap (429), the reservation against the ceiling (429), and only then is the upstream
//! dialled. Nothing the agent sent as auth, and no header outside the allowlist, goes upstream.

use std::time::Duration;

use ainkrad_proto::v2::{GatewayAuth, Wire};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::{Instant, timeout};
use zeroize::Zeroizing;

use super::charge::Charge;
use super::dial::DialError;
use super::meter::{Denied, estimate};
use super::probe::{self, betas};
use super::request::{MAX_HEAD, Refusal, Request, header_ok, refuse};
use super::route::route;
use super::stream::respond;
use super::{Config, Shared};

/// From accepting a connection to the blank line ending the head.
const HEAD: Duration = Duration::from_secs(10);
/// The whole request body.
const BODY: Duration = Duration::from_secs(60);
/// One write to the harness; a client that stops reading is dropped.
const WRITE: Duration = Duration::from_secs(60);

/// How a connection ends without a response the gateway wrote.
pub(super) enum End {
    Refuse(Refusal),
    /// Close without a word: the response was already started.
    Drop,
}

impl From<Refusal> for End {
    fn from(r: Refusal) -> End {
        End::Refuse(r)
    }
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

pub(super) fn reason(status: u16) -> &'static str {
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

pub(super) async fn put(c: &mut UnixStream, bytes: &[u8]) -> Result<(), End> {
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

/// The concurrency cap: a request holds a permit from before its body is read to its last byte.
fn take_permit(sh: &Shared) -> Result<tokio::sync::OwnedSemaphorePermit, Refusal> {
    sh.inflight
        .clone()
        .try_acquire_owned()
        .map_err(|_| refuse(429, "gateway_busy"))
}

/// Counts a request against the per-minute window.
fn count_rate(sh: &Shared) -> Result<(), Refusal> {
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
    Ok(())
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
/// ambiguous, so refused), `anthropic-beta` cut to the betas the gateway allows, a JSON content
/// type of the gateway's own (the agent's is dropped: the body is JSON or it was refused), and
/// the gateway's own auth. The auth value is wiped when dropped.
fn upstream_headers(
    cfg: &Config,
    req: &Request,
) -> Result<Vec<(String, Zeroizing<String>)>, Refusal> {
    let mut out: Vec<(String, Zeroizing<String>)> = Vec::new();
    for (n, v) in req
        .headers
        .iter()
        .filter(|(n, _)| header_ok(n) && n != "content-type")
    {
        if out.iter().any(|o| &o.0 == n) {
            return Err(refuse(400, "bad_request"));
        }
        let v = if n == "anthropic-beta" {
            match betas(v) {
                Some(kept) => kept,
                None => continue,
            }
        } else {
            v.clone()
        };
        out.push((n.clone(), Zeroizing::new(v)));
    }
    if req.headers.iter().filter(|h| h.0 == "content-type").count() > 1 {
        return Err(refuse(400, "bad_request"));
    }
    out.push((
        "content-type".to_owned(),
        Zeroizing::new("application/json".to_owned()),
    ));
    let key = cfg.key.expose();
    out.push(match cfg.upstream.auth {
        GatewayAuth::XApiKey => ("x-api-key".to_owned(), Zeroizing::new(key.to_owned())),
        GatewayAuth::Bearer => (
            "authorization".to_owned(),
            Zeroizing::new(format!("Bearer {key}")),
        ),
        GatewayAuth::XGoogApiKey => ("x-goog-api-key".to_owned(), Zeroizing::new(key.to_owned())),
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
    let _permit = take_permit(sh)?;
    let mut body = read_body(c, early, len).await?;
    // An object only: a derived struct would also read a JSON array as its fields in order.
    if body.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{') {
        return Err(refuse(400, "bad_json").into());
    }
    let probe = probe::parse(&body).map_err(|_| refuse(400, "bad_json"))?;
    // The model: in the path on the Gemini wire, in the body on the others.
    let model = match cfg.upstream.wire {
        Wire::GeminiGenerate => routed.path_model.clone(),
        _ => probe.model.clone(),
    };
    let Some(model) = model.filter(|m| cfg.models.contains(m)) else {
        return Err(refuse(403, "model_not_allowed").into());
    };
    if let Some(code) = probe.refusal() {
        return Err(refuse(403, code).into());
    }
    // Only a client-side tool is allowed, at any depth: the provider runs none for the agent.
    if super::tools::refusal(&body) {
        return Err(refuse(403, "tool_not_allowed").into());
    }
    // No provider-side web search either: OpenRouter's `web` plugin and `:online` model suffix.
    if super::online::refusal(&body) {
        return Err(refuse(403, "web_not_allowed").into());
    }
    // A Responses request may name stored state, or leave some for later: only `store: false`
    // passes. (Chat completions does not store by default, and has no such fields.)
    if cfg.upstream.wire == Wire::OpenaiResponses
        && routed.target.ends_with("/responses")
        && let Some(code) = super::stored::refusal(&body)
    {
        return Err(refuse(if code == "bad_json" { 400 } else { 403 }, code).into());
    }
    let headers = upstream_headers(cfg, &req)?;
    count_rate(sh)?;
    let price = cfg
        .meter
        .price(&model)
        .ok_or(refuse(403, "model_not_allowed"))?
        .clone();
    // A request that costs nothing (`count_tokens`) is held at nothing. Any other is held at its
    // estimate, and one that is not streamed must say how long its reply may be.
    let (held, est) = if routed.free {
        (Default::default(), Default::default())
    } else {
        let cap = match probe.output_cap(routed.streams) {
            Some(cap) => cap,
            // Gemini side calls that name no cap are given the one the hold is priced at: how the
            // Gemini harness behaves was not checked, so these are not refused (the OpenAI and
            // Anthropic wires, whose harnesses stream or name a cap, are).
            None if cfg.upstream.wire == Wire::GeminiGenerate => {
                body = probe::with_default_cap(&body).ok_or(refuse(400, "bad_json"))?;
                probe::DEFAULT_MAX_OUTPUT
            }
            None => return Err(refuse(400, "max_output_required").into()),
        };
        estimate(&price, body.len(), cap)
    };
    let reservation = cfg.meter.reserve(est).map_err(|d| match d {
        Denied::Ceiling => refuse(429, "gateway_ceiling"),
        Denied::Unreported => refuse(429, "gateway_unreported"),
        Denied::AuthFailed => refuse(403, "gateway_account_unusable"),
    })?;
    // From here on the body may reach the upstream: the account exists before the dial, so an
    // error after the write or an abort is charged as the estimate, never as nothing.
    let mut charge = Charge::new(
        reservation,
        sh.events.clone(),
        model,
        price,
        held,
        cfg.upstream.wire,
        routed.free,
    );
    let pairs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let up = cfg
        .dialer
        .open(
            &cfg.upstream.host,
            "POST",
            &routed.target,
            &pairs,
            &body,
            cfg.max_response,
        )
        .await;
    let up = match up {
        Ok(up) => up,
        Err(e) => {
            tracing::debug!(error = ?e, "gateway upstream not opened");
            charge.dial_failed(e);
            return Err(dial_refusal(e).into());
        }
    };
    charge.attach(&up);
    respond(cfg, c, up, &mut charge).await
}
