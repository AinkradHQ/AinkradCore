//! The replay window: the newest output bytes, bounded by bytes, addressed by `seq`.

use std::collections::VecDeque;
use std::ops::Range;

use crate::Seq;

#[derive(Debug)]
pub(crate) struct Ring {
    buf: VecDeque<u8>,
    head: Seq,
    cap: usize,
}

impl Ring {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            buf: VecDeque::new(),
            head: 0,
            cap,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.head += bytes.len() as Seq;
        let keep = &bytes[bytes.len().saturating_sub(self.cap)..];
        self.buf.extend(keep);
        let excess = self.buf.len().saturating_sub(self.cap);
        self.buf.drain(..excess);
    }

    /// `start..head`: the bytes still held.
    pub(crate) fn window(&self) -> Range<Seq> {
        self.head - self.buf.len() as Seq..self.head
    }

    /// The bytes from `seq` to the head, or `None` when `seq` is outside the window.
    pub(crate) fn since(&self, seq: Seq) -> Option<Vec<u8>> {
        let w = self.window();
        if seq < w.start || seq > w.end {
            return None;
        }
        Some(
            self.buf
                .range((seq - w.start) as usize..)
                .copied()
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Ring;

    #[test]
    fn keeps_the_newest_bytes() {
        let mut r = Ring::new(4);
        r.push(b"abc");
        assert_eq!(r.since(1).unwrap(), b"bc");
        r.push(b"defgh");
        assert_eq!(r.window(), 4..8);
        assert_eq!(r.since(4).unwrap(), b"efgh");
        assert_eq!(r.since(3), None);
        assert_eq!(r.since(8).unwrap(), b"");
        assert_eq!(r.since(9), None);
    }
}
