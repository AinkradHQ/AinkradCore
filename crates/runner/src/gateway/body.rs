//! The body of an upstream response, read in pieces (KAN-435 G3): de-chunked, bounded, under the
//! request's total deadline. An end of data is `Ok(None)` only when the framing says so (the
//! length reached, the last chunk read, or a clean close of a close-framed body). A read error,
//! a TLS stream that ends without `close_notify`, a short or malformed body, the deadline, and
//! the ceiling are all errors, and an error is final: the reader never reports a clean end after.

use tokio::io::AsyncReadExt;
use tokio::time::{Instant, timeout_at};

use super::dial::DialError;
use super::reply::{MAX_LINE, Rd};

/// Trailer lines read and dropped after the last chunk.
const MAX_TRAILERS: usize = 32;

pub(super) enum Framing {
    None,
    Length(u64),
    Chunked,
    /// Until the connection closes cleanly (`Connection: close`).
    Close,
}

enum Mode {
    Done,
    Length(u64),
    /// Bytes left in the current chunk; 0 means a size line comes next.
    Chunk(usize),
    Close,
    Failed(DialError),
}

pub struct Body<R> {
    rd: Rd<R>,
    mode: Mode,
    /// Bytes still allowed out.
    budget: usize,
    deadline: Instant,
}

impl<R: AsyncReadExt + Unpin> Body<R> {
    pub(super) fn new(rd: Rd<R>, framing: Framing, max: usize, deadline: Instant) -> Body<R> {
        let mode = match framing {
            Framing::None | Framing::Length(0) => Mode::Done,
            Framing::Length(n) => Mode::Length(n),
            Framing::Chunked => Mode::Chunk(0),
            Framing::Close => Mode::Close,
        };
        Body {
            rd,
            mode,
            budget: max,
            deadline,
        }
    }

    /// The next piece of the body (never empty), or `None` at its end. More than the ceiling is
    /// [`DialError::Truncated`]; the deadline or a broken body is [`DialError::Upstream`].
    pub async fn next(&mut self) -> Result<Option<Vec<u8>>, DialError> {
        if let Mode::Failed(e) = self.mode {
            return Err(e);
        }
        let got = match timeout_at(self.deadline, self.step()).await {
            Ok(got) => got,
            Err(_) => Err(DialError::Upstream),
        };
        if let Err(e) = got {
            self.mode = Mode::Failed(e);
        }
        got
    }

    async fn step(&mut self) -> Result<Option<Vec<u8>>, DialError> {
        loop {
            match self.mode {
                Mode::Done => return Ok(None),
                Mode::Failed(e) => return Err(e),
                Mode::Length(0) => {
                    self.mode = Mode::Done;
                }
                Mode::Length(left) => {
                    if self.budget == 0 {
                        return Err(DialError::Truncated);
                    }
                    let n = usize::try_from(left).unwrap_or(usize::MAX).min(self.budget);
                    let piece = self.rd.take_some(n).await?;
                    self.budget -= piece.len();
                    self.mode = Mode::Length(left - piece.len() as u64);
                    return Ok(Some(piece));
                }
                Mode::Close => {
                    if self.budget == 0 {
                        let more = !self.rd.pending().is_empty() || self.rd.fill().await?;
                        self.mode = Mode::Done;
                        return if more {
                            Err(DialError::Truncated)
                        } else {
                            Ok(None)
                        };
                    }
                    if self.rd.pending().is_empty() && !self.rd.fill().await? {
                        self.mode = Mode::Done;
                        return Ok(None);
                    }
                    let piece = self.rd.take_some(self.budget).await?;
                    self.budget -= piece.len();
                    return Ok(Some(piece));
                }
                Mode::Chunk(0) => {
                    let size = self.chunk_size().await?;
                    if size == 0 {
                        for _ in 0..=MAX_TRAILERS {
                            if self.rd.line(MAX_LINE).await?.is_empty() {
                                self.mode = Mode::Done;
                                return Ok(None);
                            }
                        }
                        return Err(DialError::Upstream);
                    }
                    if self.budget == 0 {
                        return Err(DialError::Truncated);
                    }
                    self.mode = Mode::Chunk(size);
                }
                Mode::Chunk(left) => {
                    if self.budget == 0 {
                        return Err(DialError::Truncated);
                    }
                    let piece = self.rd.take_some(left.min(self.budget)).await?;
                    self.budget -= piece.len();
                    let left = left - piece.len();
                    if left == 0 {
                        while self.rd.pending().len() < 2 {
                            self.rd.need().await?;
                        }
                        if &self.rd.pending()[..2] != b"\r\n" {
                            return Err(DialError::Upstream);
                        }
                        self.rd.consume(2);
                    }
                    self.mode = Mode::Chunk(left);
                    return Ok(Some(piece));
                }
            }
        }
    }

    async fn chunk_size(&mut self) -> Result<usize, DialError> {
        let line = self.rd.line(MAX_LINE).await?;
        let size = line.split(|b| *b == b';').next().unwrap_or_default();
        let ok = !size.is_empty() && size.len() <= 15 && size.iter().all(u8::is_ascii_hexdigit);
        ok.then(|| usize::from_str_radix(std::str::from_utf8(size).ok()?, 16).ok())
            .flatten()
            .ok_or(DialError::Upstream)
    }
}
