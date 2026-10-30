//! Where a byte stream is back in the ground state: not inside an escape sequence, a string
//! (OSC/DCS/APC/PM/SOS) or a UTF-8 character. The emulator is fed only up to such a point, so a
//! snapshot's `seq` never lands mid-sequence and the `out` bytes that follow it parse the same in
//! the client as in the host.
//!
//! This mirrors the VT500 state machine (`vte`) closely enough for cutting: it only has to agree
//! with `vte` on where a sequence ends, not on what it means.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Scan {
    #[default]
    Ground,
    /// Continuation bytes still owed by a UTF-8 character.
    Utf8(u8),
    Esc,
    EscIntermediate,
    Csi,
    /// OSC, DCS, SOS, PM or APC: ends at BEL or ST (`ESC \`).
    Str,
    /// An ESC inside a string: `\` ends it, anything else starts a new escape.
    StrEsc,
}

impl Scan {
    pub(crate) fn step(self, b: u8) -> Self {
        // CAN and SUB abort any sequence.
        if b == 0x18 || b == 0x1a {
            return Scan::Ground;
        }
        match self {
            Scan::Ground => match b {
                0x1b => Scan::Esc,
                0xc2..=0xdf => Scan::Utf8(1),
                0xe0..=0xef => Scan::Utf8(2),
                0xf0..=0xf4 => Scan::Utf8(3),
                _ => Scan::Ground,
            },
            Scan::Utf8(n) => match b {
                0x80..=0xbf if n > 1 => Scan::Utf8(n - 1),
                0x80..=0xbf => Scan::Ground,
                // An invalid sequence: the decoder emits U+FFFD and starts over with this byte.
                _ => Scan::Ground.step(b),
            },
            Scan::Esc => match b {
                b'[' => Scan::Csi,
                b']' | b'P' | b'X' | b'^' | b'_' => Scan::Str,
                0x20..=0x2f => Scan::EscIntermediate,
                0x30..=0x7e => Scan::Ground,
                // ESC restarts; C0 controls execute without leaving the escape; DEL is ignored.
                _ => Scan::Esc,
            },
            Scan::EscIntermediate => match b {
                0x1b => Scan::Esc,
                0x30..=0x7e => Scan::Ground,
                _ => Scan::EscIntermediate,
            },
            Scan::Csi => match b {
                0x1b => Scan::Esc,
                0x40..=0x7e => Scan::Ground,
                _ => Scan::Csi,
            },
            Scan::Str => match b {
                0x07 => Scan::Ground,
                0x1b => Scan::StrEsc,
                _ => Scan::Str,
            },
            Scan::StrEsc => match b {
                b'\\' => Scan::Ground,
                _ => Scan::Esc.step(b),
            },
        }
    }

    /// Advances over `bytes`; returns the new state and the length of the longest prefix of
    /// `bytes` that ends in the ground state (`0` when none does).
    pub(crate) fn advance(mut self, bytes: &[u8]) -> (Self, usize) {
        let mut ground = 0;
        for (i, &b) in bytes.iter().enumerate() {
            self = self.step(b);
            if self == Scan::Ground {
                ground = i + 1;
            }
        }
        (self, ground)
    }
}

#[cfg(test)]
mod tests {
    use super::Scan;

    fn cut(bytes: &[u8]) -> usize {
        Scan::Ground.advance(bytes).1
    }

    #[test]
    fn cuts_only_at_ground() {
        assert_eq!(cut(b"abc"), 3);
        assert_eq!(cut(b"ab\x1b[3"), 2);
        assert_eq!(cut(b"ab\x1b[31m"), 7);
        assert_eq!(cut(b"x\x1b]0;title"), 1);
        assert_eq!(cut(b"x\x1b]0;title\x07"), 11);
        assert_eq!(cut(b"x\x1b]0;t\x1b\\"), 8);
        assert_eq!(cut("a漢".as_bytes()), 4);
        assert_eq!(cut(&"a漢".as_bytes()[..3]), 1);
        assert_eq!(cut(b"a\x1b(B"), 4);
        assert_eq!(cut(b"a\x1b[1\x18"), 5);
    }
}
