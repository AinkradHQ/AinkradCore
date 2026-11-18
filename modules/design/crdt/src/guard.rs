// TODO(#298): once `design_doc::apply_remote` (its guard) is on development, call it from `Replica::apply_remote` and
// drop the duplicated nesting/pending rules here. This copy uses the corrected rule: a reference is allowed below the
// replica's state or inside the update's own insertions, and Skip blocks are refused.
//! A bounded structural scan of a yrs v1 update, run on the raw bytes BEFORE yrs decodes them.
//!
//! Why: yrs decodes (and later drops and encodes) nested `Any` values recursively, so a crafted update can overflow
//! the stack, which aborts the process (`catch_unwind` cannot help); its decoders can panic on malformed input; it
//! reserves memory from lengths read off the wire; deleting or collecting a chain of nested shared types recurses once
//! per level (a 20 000-deep chain of maps in ONE update aborts the process); and an update that depends on blocks the
//! replica does not have is parked as "pending", after which a later overlapping update reads freed memory.
//!
//! This scan allocates in proportion to the update's own size, recurses to at most `MAX_DEPTH`, checks every declared
//! count against the bytes that are left (an item takes at least one byte), and accepts only the content kinds this
//! document uses: deleted ranges, GC, strings (text), `Any`, and Map/Text types. Embeds, formats, JSON, binaries,
//! sub-documents, XML, arrays, weak types and Skip blocks are refused: our editors never write them. A client id
//! appears once per update; clocks and run lengths stay inside `u32`. The scan is deliberately stricter than yrs; an
//! honest client's update always passes (tests build real ones).
//!
//! It also collects what the update depends on (`Facts`):
//! - `check_known`: refuse, BEFORE yrs integrates anything, an update that starts past the replica's state vector,
//!   references blocks it does not have, or deletes beyond known state (`Refused::Pending`: the peer must resync, the
//!   Core closes with 4412; not a violation, nothing stored).
//! - `resolve_types`: the nesting depth of every shared type the update creates, found through the update's own items
//!   and the replica's index of earlier ones, so a deep chain is refused without yrs ever walking it. Shapes allowed:
//!   root `nodes` -> node map (depth 1) -> `props` map or `text` (depth 2); nothing deeper, no type under any other
//!   root.

use std::collections::{HashMap, HashSet};

use crate::Refused;

/// Nesting of one `Any` value (the model's validators accept far less).
pub const MAX_DEPTH: usize = 24;
/// Deepest shared-type nesting: root -> node map (1) -> props map / text (2).
pub const MAX_TYPE_DEPTH: u8 = 2;
const MAX_CLOCK: u64 = u32::MAX as u64;

/// `(client, clock)`.
pub type ItemId = (u64, u64);

/// Where a shared type sits.
#[derive(Debug, Clone, Copy)]
enum Dep {
    /// Directly under a named root; `true` for `nodes`, the only root that may hold types.
    Root(bool),
    /// Under the branch created by this item.
    Parent(ItemId),
    /// Beside this item (it is an origin or right origin: yrs copies the parent from it).
    Sibling(ItemId),
}

#[derive(Debug)]
struct TypeItem {
    id: ItemId,
    dep: Dep,
}

type R<T> = Result<T, Refused>;

fn bad<T>() -> R<T> {
    Err(Refused::Malformed)
}

/// What an update needs the receiving replica to already have, and the shared types it creates.
#[derive(Debug, Default)]
pub struct Facts {
    /// `(client, first clock, end clock)` of each client's run of blocks (one run per client).
    runs: Vec<(u64, u64, u64)>,
    /// `(client, clock)` of every origin, right origin and parent id.
    refs: Vec<ItemId>,
    /// `(client, clock, len)` of every deleted range.
    dels: Vec<(u64, u64, u64)>,
    types: Vec<TypeItem>,
}

impl Facts {
    /// `Ok` when every run starts at or below `known(client)` (its next clock in the replica) and every reference and
    /// deletion lies below what the replica has plus what this update itself adds. O(update).
    pub fn check_known(&self, known: impl Fn(u64) -> u64) -> Result<(), Refused> {
        let own: HashMap<u64, u64> = self.runs.iter().map(|r| (r.0, r.2)).collect();
        let have = |c: u64| known(c).max(own.get(&c).copied().unwrap_or(0));
        if self.runs.iter().any(|&(c, start, _)| start > known(c))
            || self.refs.iter().any(|&(c, k)| k >= have(c))
            || self
                .dels
                .iter()
                .any(|&(c, k, n)| k.saturating_add(n) > have(c))
        {
            return Err(Refused::Pending);
        }
        Ok(())
    }

    /// The depth of every shared type this update creates, resolved against `index` (the replica's earlier ones).
    /// `known(client)` is the replica's next clock for that client.
    ///
    /// Trimmed like yrs does: a block below the replica's clock is already held, yrs silently drops it and nests
    /// whatever follows under the REAL item. Such a block is ignored here (never counted, never used as a parent or
    /// origin) and an id below the clock is looked up in the replica's index only, so a resent block cannot be
    /// mislabelled to hide how deep the real chain is.
    ///
    /// `strict` (a peer's update): a type whose place cannot be found, or deeper than `MAX_TYPE_DEPTH`, is refused.
    /// Not strict (bytes this process wrote itself): unresolved ones count as depth 1, nothing is refused.
    /// Iterative, so the chain a hostile update builds is never walked recursively.
    pub fn resolve_types(
        &self,
        index: &HashMap<ItemId, u8>,
        known: &dyn Fn(u64) -> u64,
        strict: bool,
    ) -> R<Vec<(ItemId, u8)>> {
        let held = |id: &ItemId| id.1 < known(id.0);
        let fresh: Vec<&TypeItem> = self.types.iter().filter(|t| !held(&t.id)).collect();
        let pos: HashMap<ItemId, usize> =
            fresh.iter().enumerate().map(|(i, t)| (t.id, i)).collect();
        let mut memo: HashMap<ItemId, u8> = HashMap::new();
        for start in 0..fresh.len() {
            if memo.contains_key(&fresh[start].id) {
                continue;
            }
            let mut stack = vec![start];
            let mut on: HashSet<usize> = HashSet::from([start]);
            while let Some(&top) = stack.last() {
                let t = fresh[top];
                let (target, add) = match t.dep {
                    Dep::Root(true) => (None, 1u8),
                    Dep::Root(false) => return bad(),
                    Dep::Parent(p) => (Some(p), 1),
                    Dep::Sibling(s) => (Some(s), 0),
                };
                let depth = match target {
                    None => add,
                    Some(id) if held(&id) => match index.get(&id) {
                        Some(d) => d.saturating_add(add),
                        None if strict => return bad(),
                        None => 1,
                    },
                    Some(id) => match memo.get(&id) {
                        Some(d) => d.saturating_add(add),
                        None => match pos.get(&id) {
                            Some(&i) => {
                                if !on.insert(i) {
                                    return bad(); // a cycle
                                }
                                stack.push(i);
                                continue;
                            }
                            None if strict => return bad(),
                            None => 1,
                        },
                    },
                };
                if strict && depth > MAX_TYPE_DEPTH {
                    return bad();
                }
                memo.insert(t.id, depth.min(MAX_TYPE_DEPTH + 1));
                on.remove(&top);
                stack.pop();
            }
        }
        Ok(memo.into_iter().collect())
    }
}

struct Cur<'a> {
    b: &'a [u8],
    at: usize,
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
    /// A string; its length in UTF-16 units (a block's length), and it must be UTF-8.
    fn text(&mut self) -> R<u64> {
        let n = self.var()?;
        let start = self.at;
        self.skip(n)?;
        let s = std::str::from_utf8(&self.b[start..self.at]).map_err(|_| Refused::Malformed)?;
        Ok(s.encode_utf16().count() as u64)
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
    /// A client id: yrs holds it in 53 bits (a larger one trips an assertion in debug builds).
    fn client(&mut self) -> R<u64> {
        let c = self.var()?;
        if c >= 1 << 53 { bad() } else { Ok(c) }
    }
    fn id(&mut self, f: &mut Facts) -> R<ItemId> {
        let c = self.client()?;
        let k = self.var()?;
        f.refs.push((c, k));
        Ok((c, k))
    }
    /// A run or range length: a clock never leaves `u32`.
    fn len(&mut self) -> R<u64> {
        let n = self.var()?;
        if n == 0 || n > MAX_CLOCK {
            bad()
        } else {
            Ok(n)
        }
    }
    /// One block starting at `clock`; its length in clock units.
    fn block(&mut self, f: &mut Facts, client: u64, clock: u64) -> R<u64> {
        let info = self.u8()?;
        // Skip (10) leaves a gap the replica would have to fill later: never written by an honest peer, refused.
        if info == 10 {
            return bad();
        }
        if info == 0 {
            return self.len();
        }
        let (mut origin, mut right) = (None, None);
        if info & 0x80 != 0 {
            origin = Some(self.id(f)?);
        }
        if info & 0x40 != 0 {
            right = Some(self.id(f)?);
        }
        let dep = if let Some(o) = origin.or(right) {
            Dep::Sibling(o)
        } else {
            let dep = if self.var()? == 1 {
                let n = self.var()?;
                let start = self.at;
                self.skip(n)?;
                Dep::Root(&self.b[start..self.at] == b"nodes")
            } else {
                Dep::Parent(self.id(f)?)
            };
            if info & 0x20 != 0 {
                self.string()?;
            }
            dep
        };
        match info & 0b1111 {
            1 => self.len(),
            4 => self.text(),
            7 => match self.u8()? {
                1 | 2 => {
                    f.types.push(TypeItem {
                        id: (client, clock),
                        dep,
                    });
                    Ok(1)
                }
                _ => bad(),
            },
            8 => {
                let n = self.count()?;
                for _ in 0..n {
                    self.any(0)?;
                }
                if n == 0 { bad() } else { Ok(n) }
            }
            _ => bad(),
        }
    }
}

/// `Ok` when `bytes` is a well-formed update of the shapes we accept, within bounds, with what it depends on.
/// Memory is proportional to the update's own size.
pub fn scan_facts(bytes: &[u8]) -> R<Facts> {
    let mut c = Cur { b: bytes, at: 0 };
    let mut f = Facts::default();
    let mut seen = HashSet::new();
    for _ in 0..c.count()? {
        let blocks = c.count()?;
        let client = c.client()?;
        // one run per client: a second would restart the clock and make every check above meaningless
        if !seen.insert(client) {
            return bad();
        }
        let start = c.var()?;
        let mut end = start;
        for _ in 0..blocks {
            end = end.saturating_add(c.block(&mut f, client, end)?);
            if end > MAX_CLOCK {
                return bad();
            }
        }
        if start > MAX_CLOCK || end == start {
            return bad();
        }
        f.runs.push((client, start, end));
    }
    // the delete set: per client, (clock, len) ranges
    for _ in 0..c.count()? {
        let client = c.client()?;
        for _ in 0..c.count()? {
            let clock = c.var()?;
            let len = c.len()?;
            if clock.saturating_add(len) > MAX_CLOCK {
                return bad();
            }
            f.dels.push((client, clock, len));
        }
    }
    if c.left() == 0 { Ok(f) } else { bad() }
}

/// `scan_facts` without the dependencies, for tests and callers that only need the shape checked.
pub fn scan(bytes: &[u8]) -> R<()> {
    scan_facts(bytes).map(drop)
}
