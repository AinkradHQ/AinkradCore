//! Reading one HTTP/1.1 response from an upstream (KAN-435 G2/G3): strict about the head, exact
//! about the body's framing, explicit about truncation. Never trusts a close as the end of a body
//! that was framed by a length or by chunks. The body is read in pieces ([`Body`]), so a stream
//! can be passed on as it arrives; [`Reply`] is the buffered form of the same read.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::time::{Instant, timeout};

use super::body::{Body, Framing};
use super::dial::DialError;

/// Nothing read for this long ends the response.
pub(super) const IDLE: Duration = Duration::from_secs(30);
/// How long the head of a response may take to come: a generation that is not streamed sends
/// nothing until it is done. The request's total deadline caps it; once the head is in, a
/// silence of [`IDLE`] ends the body.
const HEAD_WAIT: Duration = Duration::from_secs(30 * 60);
/// The largest response head kept.
const MAX_HEAD: usize = 32 * 1024;
/// The longest chunk-size or trailer line.
pub(super) const MAX_LINE: usize = 1024;
/// Interim (1xx) responses skipped before the real one.
const MAX_INTERIM: usize = 8;

/// What came back from one request: the status, the allow-listed headers, a bounded body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The body was sent chunked (and `body` is the decoded data).
    pub chunked: bool,
    /// The upstream sent more than `max_body` bytes: `body` is the first `max_body`.
    pub truncated: bool,
}

/// A response whose head is read and whose body is still on the wire.
pub struct Opened<R> {
    pub status: u16,
    /// The allow-listed headers only.
    pub headers: Vec<(String, String)>,
    /// The body is chunked on the wire (and [`Body`] yields decoded data).
    pub chunked: bool,
    /// The body's length when the upstream gave one.
    pub length: Option<u64>,
    pub body: Body<R>,
}

/// Response headers that may reach the harness. `Location`, `Set-Cookie` and organisation ids
/// are not among them.
fn header_ok(name: &str) -> bool {
    matches!(
        name,
        "content-type" | "retry-after" | "request-id" | "x-request-id"
    ) || name.starts_with("anthropic-ratelimit-")
        || name.starts_with("x-ratelimit-")
}

fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// The first line of a head and its headers.
pub(super) type Lines<'a> = (&'a str, Vec<(String, String)>);

/// One head split into its first line and its `name: value` lines (names lower-cased, values
/// trimmed). No bare CR, bare LF or NUL anywhere, UTF-8 only, and every header line is
/// `token: value`, so an obs-fold, a space before the colon or a line without one is refused whole.
/// Shared by the response head here and the gateway's request head.
pub(super) fn parse_lines(raw: &[u8]) -> Result<Lines<'_>, ()> {
    for (i, b) in raw.iter().enumerate() {
        let ok = match b {
            0 => false,
            b'\r' => raw.get(i + 1) == Some(&b'\n'),
            b'\n' => i > 0 && raw[i - 1] == b'\r',
            c => *c == b'\t' || (*c >= 0x20 && *c != 0x7f),
        };
        if !ok {
            return Err(());
        }
    }
    let text = std::str::from_utf8(raw).map_err(|_| ())?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or(())?;
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(())?;
        if name.is_empty() || !name.bytes().all(tchar) {
            return Err(());
        }
        headers.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_owned(),
        ));
    }
    Ok((first, headers))
}

struct Head {
    status: u16,
    headers: Vec<(String, String)>,
}

/// A head with a 3-digit status of 100 to 599 and only `token: value` lines. Anything else
/// refuses the whole response.
fn parse_head(raw: &[u8]) -> Result<Head, DialError> {
    let bad = DialError::Upstream;
    let (first, headers) = parse_lines(raw).map_err(|()| bad)?;
    let code = first.strip_prefix("HTTP/1.1 ").ok_or(bad)?;
    let digits = code.get(..3).ok_or(bad)?;
    if !digits.bytes().all(|b| b.is_ascii_digit())
        || (code.len() > 3 && !code[3..].starts_with(' '))
    {
        return Err(bad);
    }
    let status: u16 = digits.parse().map_err(|_| bad)?;
    if !(100..=599).contains(&status) {
        return Err(bad);
    }
    Ok(Head { status, headers })
}

fn framing(status: u16, headers: &[(String, String)]) -> Result<Framing, DialError> {
    fn of<'a>(
        headers: &'a [(String, String)],
        name: &'a str,
    ) -> impl Iterator<Item = &'a (String, String)> {
        headers.iter().filter(move |h| h.0 == name)
    }
    let (mut cl, mut te) = (
        of(headers, "content-length"),
        of(headers, "transfer-encoding"),
    );
    if status == 204 || status == 304 {
        return Ok(Framing::None);
    }
    match (cl.next(), te.next()) {
        (Some(_), Some(_)) => Err(DialError::Upstream),
        (Some((_, v)), None) => {
            let ok = cl.next().is_none()
                && !v.is_empty()
                && v.len() <= 18
                && v.bytes().all(|b| b.is_ascii_digit());
            ok.then(|| v.parse().ok())
                .flatten()
                .map(Framing::Length)
                .ok_or(DialError::Upstream)
        }
        (None, Some((_, v))) => (te.next().is_none() && v.eq_ignore_ascii_case("chunked"))
            .then_some(Framing::Chunked)
            .ok_or(DialError::Upstream),
        (None, None) => Ok(Framing::Close),
    }
}

/// A buffered reader whose every wait is bounded and whose read errors (a TLS stream that ends
/// without `close_notify` included) are errors, never an end of data.
pub(super) struct Rd<R> {
    r: R,
    buf: Vec<u8>,
    at: usize,
    /// How long a read may wait.
    idle: Duration,
}

impl<R: AsyncReadExt + Unpin> Rd<R> {
    pub(super) fn new(r: R) -> Rd<R> {
        Rd {
            r,
            buf: Vec::new(),
            at: 0,
            idle: IDLE,
        }
    }

    pub(super) fn pending(&self) -> &[u8] {
        &self.buf[self.at..]
    }

    pub(super) fn consume(&mut self, n: usize) {
        self.at += n;
        if self.at == self.buf.len() {
            self.buf.clear();
            self.at = 0;
        }
    }

    /// Reads more. `Ok(false)` only for a clean end of stream.
    pub(super) async fn fill(&mut self) -> Result<bool, DialError> {
        let mut chunk = [0u8; 8192];
        match timeout(self.idle, self.r.read(&mut chunk)).await {
            Ok(Ok(0)) => Ok(false),
            Ok(Ok(n)) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            _ => Err(DialError::Upstream),
        }
    }

    /// Reads more where an end of stream is an error.
    pub(super) async fn need(&mut self) -> Result<(), DialError> {
        self.fill().await?.then_some(()).ok_or(DialError::Upstream)
    }

    /// Up to and excluding the next CRLF, at most `max` bytes.
    pub(super) async fn line(&mut self, max: usize) -> Result<Vec<u8>, DialError> {
        loop {
            if let Some(i) = self.pending().windows(2).position(|w| w == b"\r\n") {
                let line = self.pending()[..i].to_vec();
                self.consume(i + 2);
                return Ok(line);
            }
            if self.pending().len() > max {
                return Err(DialError::Upstream);
            }
            self.need().await?;
        }
    }

    /// A response head: up to and excluding the blank line.
    async fn head(&mut self) -> Result<Vec<u8>, DialError> {
        loop {
            if let Some(i) = self.pending().windows(4).position(|w| w == b"\r\n\r\n") {
                let head = self.pending()[..i].to_vec();
                self.consume(i + 4);
                return Ok(head);
            }
            if self.pending().len() > MAX_HEAD {
                return Err(DialError::Upstream);
            }
            self.need().await?;
        }
    }

    /// Up to `n` bytes (at least one), reading more when none are pending.
    pub(super) async fn take_some(&mut self, n: usize) -> Result<Vec<u8>, DialError> {
        if self.pending().is_empty() {
            self.need().await?;
        }
        let k = n.min(self.pending().len());
        let out = self.pending()[..k].to_vec();
        self.consume(k);
        Ok(out)
    }
}

/// Reads one response head: skips 1xx interim heads, refuses a malformed head whole, and returns
/// the body reader, framed by `Content-Length` or chunks (a short or cut body is an error) or by a
/// clean close, that yields at most `max_body` bytes and then says so ([`DialError::Truncated`]).
/// Every wait of the body is bounded by the idle timeout and by `deadline`.
pub(super) async fn open_reply<R: AsyncReadExt + Unpin>(
    r: R,
    max_body: usize,
    deadline: Instant,
) -> Result<Opened<R>, DialError> {
    let mut rd = Rd::new(r);
    rd.idle = HEAD_WAIT;
    let mut interim = 0;
    let head = loop {
        let head = parse_head(&rd.head().await?)?;
        match head.status {
            101 => return Err(DialError::Upstream), // nothing was asked to switch
            100..=199 if interim < MAX_INTERIM => interim += 1,
            100..=199 => return Err(DialError::Upstream),
            _ => break head,
        }
    };
    rd.idle = IDLE;
    let framing = framing(head.status, &head.headers)?;
    Ok(Opened {
        status: head.status,
        chunked: matches!(framing, Framing::Chunked),
        length: match framing {
            Framing::Length(n) => Some(n),
            _ => None,
        },
        headers: head
            .headers
            .into_iter()
            .filter(|(n, _)| header_ok(n))
            .collect(),
        body: Body::new(rd, framing, max_body, deadline),
    })
}
