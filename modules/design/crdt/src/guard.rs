//! A bounded structural scan of a yrs v1 update, run on the raw bytes BEFORE yrs decodes them.
//!
//! Why: yrs decodes (and later drops and encodes) nested `Any` values recursively, so a crafted update can overflow
//! the stack, which aborts the process (`catch_unwind` cannot help); its decoders can panic on malformed input; and
//! it reserves memory from lengths read off the wire. This scan allocates nothing, recurses to at most `MAX_DEPTH`,
//! checks every declared count against the bytes that are left (an item takes at least one byte), and accepts only
//! the content kinds this document uses: deleted ranges, GC/skip, strings (text), `Any`, and Map/Array/Text types.
//! Embeds, formats, JSON, binaries, sub-documents, XML and weak types are refused: our editors never write them.
//! The scan is deliberately stricter than yrs; an honest client's update always passes (tests build real ones).

use crate::Refused;

/// Nesting of one `Any` value (the model's validators accept far less).
pub const MAX_DEPTH: usize = 24;

struct Cur<'a> {
    b: &'a [u8],
    at: usize,
}

type R<T> = Result<T, Refused>;

fn bad<T>() -> R<T> {
    Err(Refused::Malformed)
}

impl Cur<'_> {
    fn left(&self) -> usize {
        self.b.len() - self.at
    }
    fn u8(&mut self) -> R<u8> {
        let v = *self.b.get(self.at).ok_or(Refused::Malformed)?;
        self.at += 1;
        Ok(v)
    }
    /// A varuint, at most 10 bytes.
    fn var(&mut self) -> R<u64> {
        let (mut v, mut shift) = (0u64, 0);
        for _ in 0..10 {
            let b = self.u8()?;
            v |= u64::from(b & 0x7f).checked_shl(shift).unwrap_or(0);
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
        }
        bad()
    }
    /// A signed varint (lib0): skip its bytes.
    fn svar(&mut self) -> R<()> {
        for _ in 0..10 {
            if self.u8()? & 0x80 == 0 {
                return Ok(());
            }
        }
        bad()
    }
    fn skip(&mut self, n: u64) -> R<()> {
        if n > self.left() as u64 {
            return bad();
        }
        self.at += n as usize;
        Ok(())
    }
    fn string(&mut self) -> R<()> {
        let n = self.var()?;
        self.skip(n)
    }
    /// A count of items that each take at least one byte: more than the bytes left is a lie.
    fn count(&mut self) -> R<u64> {
        let n = self.var()?;
        if n > self.left() as u64 {
            return bad();
        }
        Ok(n)
    }
    fn any(&mut self, depth: usize) -> R<()> {
        if depth > MAX_DEPTH {
            return bad();
        }
        match self.u8()? {
            126 | 121 | 120 => Ok(()),
            125 => self.svar(),
            124 => self.skip(4),
            123 | 122 => self.skip(8),
            119 => self.string(),
            118 => {
                for _ in 0..self.count()? {
                    self.string()?;
                    self.any(depth + 1)?;
                }
                Ok(())
            }
            117 => {
                for _ in 0..self.count()? {
                    self.any(depth + 1)?;
                }
                Ok(())
            }
            // undefined and buffers: never written by our editors, refused by `read` anyway
            _ => bad(),
        }
    }
    fn id(&mut self) -> R<()> {
        self.var()?;
        self.var()?;
        Ok(())
    }
    fn block(&mut self) -> R<()> {
        let info = self.u8()?;
        match info {
            0 | 10 => {
                self.var()?;
                return Ok(());
            }
            _ => {}
        }
        let copies = info & 0b1100_0000 != 0;
        if info & 0x80 != 0 {
            self.id()?;
        }
        if info & 0x40 != 0 {
            self.id()?;
        }
        if !copies {
            if self.var()? == 1 {
                self.string()?;
            } else {
                self.id()?;
            }
            if info & 0x20 != 0 {
                self.string()?;
            }
        }
        match info & 0b1111 {
            1 => {
                self.var()?;
                Ok(())
            }
            4 => self.string(),
            7 => match self.u8()? {
                0..=2 => Ok(()),
                _ => bad(),
            },
            8 => {
                for _ in 0..self.count()? {
                    self.any(0)?;
                }
                Ok(())
            }
            _ => bad(),
        }
    }
}

/// `Ok` when `bytes` is a well-formed update of the shapes we accept, within bounds; nothing is allocated.
pub fn scan(bytes: &[u8]) -> R<()> {
    let mut c = Cur { b: bytes, at: 0 };
    for _ in 0..c.count()? {
        let blocks = c.count()?;
        c.var()?; // client
        c.var()?; // first clock
        for _ in 0..blocks {
            c.block()?;
        }
    }
    // the delete set: per client, (clock, len) ranges
    for _ in 0..c.count()? {
        c.var()?;
        for _ in 0..c.count()? {
            c.var()?;
            c.var()?;
        }
    }
    if c.left() == 0 { Ok(()) } else { bad() }
}
