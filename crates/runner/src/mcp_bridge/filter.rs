//! The request filter in front of the Core: only `POST <the MCP path> HTTP/1.1`, strictly framed.
//!
//! The bridge runs in the runner, outside the sandbox, for a client that is a hostile agent at
//! worst. So every read is bounded in size and time, anything but the one route is refused before
//! a byte reaches the Core, and anything that could desynchronise framing (duplicate or mixed
//! `Content-Length`/`Transfer-Encoding`, obsolete folding, bare line feeds) is refused.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy};
use tokio::time::timeout;

pub const MAX_LINE: usize = 8 * 1024;
pub const MAX_HEAD: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 64;
pub const MAX_BODY: u64 = 8 * 1024 * 1024;
/// Waiting for the next request on an open connection.
pub const IDLE: Duration = Duration::from_secs(3600);
/// From the first byte of a request line to the blank line ending its head.
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(15);
/// A whole request body.
pub const BODY_TIMEOUT: Duration = Duration::from_secs(120);

/// An HTTP status the client is told before the connection closes.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal(pub u16, pub &'static str);

#[derive(Debug, PartialEq, Eq)]
pub enum Body {
    None,
    Length(u64),
    Chunked,
}

#[derive(Debug)]
pub struct Request {
    pub head: Vec<u8>,
    pub body: Body,
}

const BAD: Refusal = Refusal(400, "Bad Request");
const TOO_BIG: Refusal = Refusal(431, "Request Header Fields Too Large");

/// One line including its CRLF, at most `MAX_LINE` bytes: never buffers past the cap.
async fn line<R: AsyncBufRead + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> Result<usize, Refusal> {
    buf.clear();
    let n = (&mut *r)
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', buf)
        .await
        .map_err(|_| BAD)?;
    if buf.len() > MAX_LINE {
        return Err(TOO_BIG);
    }
    if n > 0 && !buf.ends_with(b"\r\n") {
        return Err(BAD); // a bare line feed, or EOF inside a line
    }
    if buf[..n.saturating_sub(2)]
        .iter()
        .any(|b| matches!(b, b'\r' | 0))
    {
        return Err(BAD);
    }
    Ok(n)
}

fn token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// The next request, rewritten for the Core (`Host` set, hop-by-hop headers dropped), or `None`
/// when the client closed between requests.
pub async fn read_request<R: AsyncBufRead + Unpin>(
    r: &mut R,
    authority: &str,
    path: &str,
) -> Result<Option<Request>, Refusal> {
    let mut first = Vec::new();
    let n = timeout(IDLE, line(r, &mut first))
        .await
        .map_err(|_| Refusal(408, "Request Timeout"))??;
    if n == 0 {
        return Ok(None);
    }
    timeout(HEAD_TIMEOUT, rest(r, &first, authority, path))
        .await
        .map_err(|_| Refusal(408, "Request Timeout"))?
        .map(Some)
}

async fn rest<R: AsyncBufRead + Unpin>(
    r: &mut R,
    first: &[u8],
    authority: &str,
    path: &str,
) -> Result<Request, Refusal> {
    let text = std::str::from_utf8(&first[..first.len() - 2]).map_err(|_| BAD)?;
    let parts: Vec<&str> = text.split(' ').collect();
    let [method, target, version] = parts[..] else {
        return Err(BAD);
    };
    if version != "HTTP/1.1" {
        return Err(BAD);
    }
    // CONNECT, GET (an SSE stream), absolute-form targets and everything else but the one call.
    if method != "POST" {
        return Err(Refusal(403, "Forbidden"));
    }
    if target != path {
        return Err(Refusal(404, "Not Found"));
    }
    let mut head = format!("POST {path} HTTP/1.1\r\n").into_bytes();
    let (mut length, mut chunked, mut count, mut size) = (None, false, 0, first.len());
    let mut buf = Vec::new();
    loop {
        let n = line(r, &mut buf).await?;
        if n == 0 {
            return Err(BAD);
        }
        size += n;
        if size > MAX_HEAD {
            return Err(TOO_BIG);
        }
        if buf == b"\r\n" {
            break;
        }
        count += 1;
        if count > MAX_HEADERS {
            return Err(TOO_BIG);
        }
        if matches!(buf[0], b' ' | b'\t') {
            return Err(BAD); // obsolete line folding
        }
        let text = std::str::from_utf8(&buf[..n - 2]).map_err(|_| BAD)?;
        let (name, value) = text.split_once(':').ok_or(BAD)?;
        if !token(name) {
            return Err(BAD); // includes "Content-Length : 5"
        }
        let value = value.trim_matches([' ', '\t']);
        match name.to_ascii_lowercase().as_str() {
            "host" => {}
            "content-length" => {
                if length.is_some()
                    || value.is_empty()
                    || value.len() > 18
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(BAD);
                }
                length = value.parse::<u64>().ok();
                head.extend_from_slice(&buf);
            }
            "transfer-encoding" => {
                if chunked || !value.eq_ignore_ascii_case("chunked") {
                    return Err(BAD);
                }
                chunked = true;
                head.extend_from_slice(&buf);
            }
            "upgrade" | "expect" => return Err(Refusal(403, "Forbidden")),
            "connection" => {
                if value
                    .split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
                {
                    return Err(Refusal(403, "Forbidden"));
                }
            }
            "keep-alive"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "te"
            | "trailer" => {}
            _ => head.extend_from_slice(&buf),
        }
    }
    if chunked && length.is_some() {
        return Err(BAD);
    }
    let body = match (length, chunked) {
        (_, true) => Body::Chunked,
        (Some(n), _) if n > MAX_BODY => return Err(Refusal(413, "Content Too Large")),
        (Some(n), _) => Body::Length(n),
        (None, _) => Body::None,
    };
    head.extend_from_slice(format!("Host: {authority}\r\n\r\n").as_bytes());
    Ok(Request { head, body })
}

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_owned())
}

/// Copies the request's body to `w`, bounded in size and time; chunked bodies are re-framed
/// (no extensions, no trailers).
pub async fn forward_body<R, W>(r: &mut R, w: &mut W, body: Body) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    timeout(BODY_TIMEOUT, async {
        match body {
            Body::None => Ok(()),
            Body::Length(n) => {
                if copy(&mut (&mut *r).take(n), w).await? != n {
                    return Err(bad("truncated body"));
                }
                Ok(())
            }
            Body::Chunked => chunked(r, w).await,
        }
    })
    .await
    .map_err(|_| bad("body timeout"))?
}

async fn chunked<R, W>(r: &mut R, w: &mut W) -> io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut buf, mut total) = (Vec::new(), 0u64);
    loop {
        line(r, &mut buf)
            .await
            .map_err(|_| bad("chunk size line"))?;
        let hex = std::str::from_utf8(&buf[..buf.len().saturating_sub(2)])
            .map_err(|_| bad("chunk size"))?;
        if hex.is_empty() || hex.len() > 8 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(bad("chunk size"));
        }
        let size = u64::from_str_radix(hex, 16).map_err(|_| bad("chunk size"))?;
        total = total
            .checked_add(size)
            .filter(|t| *t <= MAX_BODY)
            .ok_or_else(|| bad("body too large"))?;
        w.write_all(format!("{size:x}\r\n").as_bytes()).await?;
        if size == 0 {
            for _ in 0..8 {
                line(r, &mut buf).await.map_err(|_| bad("trailer"))?;
                if buf == b"\r\n" {
                    return w.write_all(b"\r\n").await;
                }
            }
            return Err(bad("too many trailers"));
        }
        if copy(&mut (&mut *r).take(size), w).await? != size {
            return Err(bad("truncated chunk"));
        }
        let mut crlf = [0; 2];
        r.read_exact(&mut crlf).await?;
        if &crlf != b"\r\n" {
            return Err(bad("chunk terminator"));
        }
        w.write_all(b"\r\n").await?;
    }
}

#[cfg(test)]
mod tests;
