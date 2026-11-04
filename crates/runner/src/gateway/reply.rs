//! Reading one HTTP/1.1 response from an upstream (KAN-435 G2): strict about the head, exact about
//! the body's framing, explicit about truncation. Never trusts a close as the end of a body that
//! was framed by a length or by chunks.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use super::dial::DialError;

/// Nothing read for this long ends the response.
const IDLE: Duration = Duration::from_secs(30);
/// The largest response head kept.
const MAX_HEAD: usize = 32 * 1024;
/// The longest chunk-size or trailer line.
const MAX_LINE: usize = 1024;
/// Interim (1xx) responses skipped before the real one.
const MAX_INTERIM: usize = 8;
/// Trailer lines read and dropped after the last chunk.
const MAX_TRAILERS: usize = 32;

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

struct Head {
    status: u16,
    headers: Vec<(String, String)>,
}

/// A head with no bare CR, bare LF or NUL, a 3-digit status of 100 to 599, and only
/// `token: value` lines. Anything else refuses the whole response.
fn parse_head(raw: &[u8]) -> Result<Head, DialError> {
    let bad = DialError::Upstream;
    for (i, b) in raw.iter().enumerate() {
        let ok = match b {
            0 => false,
            b'\r' => raw.get(i + 1) == Some(&b'\n'),
            b'\n' => i > 0 && raw[i - 1] == b'\r',
            c => *c == b'\t' || (*c >= 0x20 && *c != 0x7f),
        };
        if !ok {
            return Err(bad);
        }
    }
    let text = std::str::from_utf8(raw).map_err(|_| bad)?;
    let mut lines = text.split("\r\n");
    let first = lines.next().ok_or(bad)?;
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
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(bad)?;
        if name.is_empty() || !name.bytes().all(tchar) {
            return Err(bad);
        }
        headers.push((
            name.to_ascii_lowercase(),
            value.trim_matches([' ', '\t']).to_owned(),
        ));
    }
    Ok(Head { status, headers })
}

enum Framing {
    None,
    Length(u64),
    Chunked,
    /// Until the connection closes cleanly (`Connection: close`).
    Close,
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
struct Rd<'a, R> {
    r: &'a mut R,
    buf: Vec<u8>,
    at: usize,
}

impl<R: AsyncReadExt + Unpin> Rd<'_, R> {
    fn pending(&self) -> &[u8] {
        &self.buf[self.at..]
    }

    fn consume(&mut self, n: usize) {
        self.at += n;
        if self.at == self.buf.len() {
            self.buf.clear();
            self.at = 0;
        }
    }

    /// Reads more. `Ok(false)` only for a clean end of stream.
    async fn fill(&mut self) -> Result<bool, DialError> {
        let mut chunk = [0u8; 4096];
        match timeout(IDLE, self.r.read(&mut chunk)).await {
            Ok(Ok(0)) => Ok(false),
            Ok(Ok(n)) => {
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            _ => Err(DialError::Upstream),
        }
    }

    /// Reads more where an end of stream is an error.
    async fn need(&mut self) -> Result<(), DialError> {
        self.fill().await?.then_some(()).ok_or(DialError::Upstream)
    }

    /// Up to and excluding the next CRLF, at most `max` bytes.
    async fn line(&mut self, max: usize) -> Result<Vec<u8>, DialError> {
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

    /// Moves up to `n` pending bytes into `body`, reading more when none are pending.
    async fn take(&mut self, n: usize, body: &mut Vec<u8>) -> Result<usize, DialError> {
        if self.pending().is_empty() {
            self.need().await?;
        }
        let k = n.min(self.pending().len());
        body.extend_from_slice(&self.pending()[..k]);
        self.consume(k);
        Ok(k)
    }
}

/// The body, at most `max` bytes, and whether the upstream sent more.
async fn body<R: AsyncReadExt + Unpin>(
    rd: &mut Rd<'_, R>,
    framing: Framing,
    max: usize,
) -> Result<(Vec<u8>, bool), DialError> {
    let mut out = Vec::new();
    match framing {
        Framing::None => {}
        Framing::Length(n) => {
            let want = usize::try_from(n).unwrap_or(usize::MAX).min(max);
            while out.len() < want {
                rd.take(want - out.len(), &mut out).await?;
            }
            return Ok((out, n > max as u64));
        }
        Framing::Close => {
            while out.len() < max {
                if rd.pending().is_empty() && !rd.fill().await? {
                    return Ok((out, false));
                }
                rd.take(max - out.len(), &mut out).await?;
            }
            let more = !rd.pending().is_empty() || rd.fill().await?;
            return Ok((out, more));
        }
        Framing::Chunked => loop {
            let line = rd.line(MAX_LINE).await?;
            let size = line.split(|b| *b == b';').next().unwrap_or_default();
            let ok = !size.is_empty() && size.len() <= 15 && size.iter().all(u8::is_ascii_hexdigit);
            let size = ok
                .then(|| usize::from_str_radix(std::str::from_utf8(size).ok()?, 16).ok())
                .flatten()
                .ok_or(DialError::Upstream)?;
            if size == 0 {
                for _ in 0..=MAX_TRAILERS {
                    if rd.line(MAX_LINE).await?.is_empty() {
                        return Ok((out, false));
                    }
                }
                return Err(DialError::Upstream);
            }
            let mut left = size;
            while left > 0 {
                if out.len() >= max {
                    return Ok((out, true));
                }
                left -= rd.take(left.min(max - out.len()), &mut out).await?;
            }
            while rd.pending().len() < 2 {
                rd.need().await?;
            }
            if &rd.pending()[..2] != b"\r\n" {
                return Err(DialError::Upstream);
            }
            rd.consume(2);
        },
    }
    Ok((out, false))
}

/// Reads one response: skips 1xx interim heads, refuses a malformed head whole, frames the body
/// by `Content-Length` or chunks (a short or cut body is an error) or by a clean close, and
/// keeps at most `max_body` bytes, saying so when it cut.
pub(super) async fn read_reply<R: AsyncReadExt + Unpin>(
    r: &mut R,
    max_body: usize,
) -> Result<Reply, DialError> {
    let mut rd = Rd {
        r,
        buf: Vec::new(),
        at: 0,
    };
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
    let framing = framing(head.status, &head.headers)?;
    let chunked = matches!(framing, Framing::Chunked);
    let (body, truncated) = body(&mut rd, framing, max_body).await?;
    Ok(Reply {
        status: head.status,
        headers: head
            .headers
            .into_iter()
            .filter(|(n, _)| header_ok(n))
            .collect(),
        body,
        chunked,
        truncated,
    })
}
