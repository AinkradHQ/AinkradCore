//! Where a terminal's output goes besides the attached clients: the screen model a reattach is
//! restored from, and the byte ring a resume by `seq` is served from.
//!
//! [`Screen`] is the boundary for the headless emulator and scrollback (E2-04, `crates/term`):
//! the host feeds it every output byte and asks it for a snapshot when a client attaches at a
//! point the ring no longer holds or falls behind. [`Raw`] is the stand-in until then.

use std::collections::VecDeque;

use ainkrad_proto::v2::Size;

/// A screen/scrollback sink fed with PTY bytes (E2-04 implements it on an emulator).
pub trait Screen: Send {
    /// Output bytes, in order, exactly as the PTY produced them.
    fn feed(&mut self, bytes: &[u8]);
    /// The terminal was resized.
    fn resize(&mut self, size: Size);
    /// Bytes a fresh terminal view replays to show the screen as it is now.
    fn snapshot(&self) -> Vec<u8>;
}

/// The stand-in screen: replays the last `cap` output bytes.
///
/// ponytail: a raw tail restores a shell prompt but not an alt-screen app (vim, htop) and may
/// start mid escape sequence; the emulator of E2-04 replaces it behind [`Screen`].
pub struct Raw {
    tail: Ring,
}

impl Raw {
    pub fn new(cap: usize) -> Self {
        Self {
            tail: Ring::new(cap),
        }
    }
}

impl Screen for Raw {
    fn feed(&mut self, bytes: &[u8]) {
        self.tail.push(bytes);
    }

    fn resize(&mut self, _: Size) {}

    fn snapshot(&self) -> Vec<u8> {
        self.tail.since(self.tail.start()).unwrap_or_default()
    }
}

/// The last `cap` output bytes, with their offsets: what a resume at `seq` is served from.
pub struct Ring {
    buf: VecDeque<u8>,
    /// The offset of `buf[0]`.
    start: u64,
    cap: usize,
}

impl Ring {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            start: 0,
            cap,
        }
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes);
        let over = self.buf.len().saturating_sub(self.cap);
        self.buf.drain(..over);
        self.start += over as u64;
    }

    /// The offset of the oldest byte held.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// The offset of the next byte.
    pub fn end(&self) -> u64 {
        self.start + self.buf.len() as u64
    }

    /// The bytes from `seq` on, or `None` when `seq` is outside what is held.
    pub fn since(&self, seq: u64) -> Option<Vec<u8>> {
        if seq < self.start || seq > self.end() {
            return None;
        }
        let skip = usize::try_from(seq - self.start).ok()?;
        Some(self.buf.iter().skip(skip).copied().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ring_keeps_the_last_bytes_with_their_offsets() {
        let mut r = Ring::new(4);
        r.push(b"abc");
        assert_eq!(r.since(1), Some(b"bc".to_vec()));
        r.push(b"def");
        assert_eq!((r.start(), r.end()), (2, 6));
        assert_eq!(r.since(2), Some(b"cdef".to_vec()));
        assert_eq!(r.since(6), Some(vec![]));
        assert_eq!(r.since(1), None, "dropped");
        assert_eq!(r.since(7), None, "not yet written");
        let mut s = Raw::new(3);
        s.feed(b"hello");
        assert_eq!(s.snapshot(), b"llo");
    }
}
