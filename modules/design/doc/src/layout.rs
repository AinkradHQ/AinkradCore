//! The T1 layout as a gate on remote bytes. yrs integrates, deletes and garbage-collects nested shared types
//! recursively, so a chain of nested maps inside ONE update (refused at read time, but integrated and then deleted
//! first) overflows the stack inside `apply_update`: an abort, which no `catch_unwind` stops. Content on the list
//! side of a map branch is invisible to key-based reads. So before yrs sees an update, every block in it is parsed
//! here (lib0 v1, structure only) and placed in the layout:
//!
//! ```text
//! root "nodes"   key -> node map | deleted                 root "meta" / "tokens"   key -> value | deleted
//! node map       "props" -> props map, "text" -> text, other keys -> value | deleted
//! props map      key -> value | deleted                    text      list of plain strings | deleted
//! ```
//!
//! Anything else is refused: another root, a nested type anywhere else (so nesting depth is at most 2), list-side
//! content in a map, text that is not a plain string, JSON/binary/embed/format/subdoc content, skip blocks, empty
//! blocks, and a client run whose clocks would pass `u32::MAX`. A block's place comes from its explicit parent, or
//! from its origin (yrs copies parent and key from it), looked up in the update itself or in `Shadow`: what this
//! replica already holds, learned from every committed update.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use yrs::{ClientID, StateVector};

use crate::MAX_JSON_DEPTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Node,
    Props,
    Text,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Parent {
    Nodes,
    Meta,
    Tokens,
    Type(Kind),
    /// Under a garbage-collected item: yrs garbage-collects the new block too.
    Gone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Place {
    parent: Parent,
    key: Option<Arc<str>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Content {
    Deleted,
    Str,
    Value,
    Map,
    Text,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pref {
    Root(Arc<str>),
    Id(u64, u32),
}

#[derive(Debug)]
struct Block {
    client: u64,
    clock: u32,
    len: u32,
    /// `None` = a GC block.
    item: Option<Item>,
}

#[derive(Debug)]
struct Item {
    origin: Option<(u64, u32)>,
    right: Option<(u64, u32)>,
    parent: Option<Pref>,
    key: Option<Arc<str>>,
    content: Content,
}

/// What this replica holds: for every block range, its place (`None` = GC), and the kind of every nested type.
#[derive(Default)]
pub(crate) struct Shadow {
    items: HashMap<u64, BTreeMap<u32, (u32, Option<Place>)>>,
    types: HashMap<(u64, u32), Kind>,
}

impl Shadow {
    fn place(&self, (client, clock): (u64, u32)) -> Option<Option<Place>> {
        let (_, (end, p)) = self.items.get(&client)?.range(..=clock).next_back()?;
        (clock < *end).then(|| p.clone())
    }

    /// Check `update` against the layout; on success, return what it would add. `have` is the replica's state
    /// vector: like yrs, every block (or block part) below it is already held and is skipped, and an id below it is
    /// looked up only in the shadow, never in what the update claims (a resent block relabelled as something else
    /// must not become a parent).
    pub(crate) fn check(&self, update: &[u8], have: &StateVector) -> Result<Learned, String> {
        let blocks = parse(update).ok_or("malformed update")?;
        let mut new = Learned::default();
        let mut todo: Vec<&Block> = blocks.iter().collect();
        // a block's origin or parent may be a later block of the same update: resolve until no progress
        while !todo.is_empty() {
            let before = todo.len();
            let mut i = 0;
            while i < todo.len() {
                match self.resolve(&mut new, todo[i], have)? {
                    Some(()) => {
                        todo.swap_remove(i);
                    }
                    None => i += 1,
                }
            }
            if todo.len() == before {
                return Err("a block refers to something this replica does not hold".into());
            }
        }
        Ok(new)
    }

    /// Place one block; `Ok(None)` = depends on a block of this update not placed yet.
    fn resolve(
        &self,
        new: &mut Learned,
        b: &Block,
        have: &StateVector,
    ) -> Result<Option<()>, String> {
        let held = |c: u64| have.get(&ClientID::new(c));
        let end = b.clock + b.len;
        let start = b.clock.max(held(b.client));
        if start >= end {
            return Ok(Some(())); // already held: yrs drops it
        }
        let range = (b.client, start, end);
        let Some(it) = &b.item else {
            new.record(range, None, None);
            return Ok(Some(()));
        };
        let below = |id: (u64, u32)| id.1 < held(id.0);
        let lookup = |new: &Learned, id: (u64, u32)| {
            if below(id) {
                self.place(id)
            } else {
                new.place(id)
            }
        };
        if start > b.clock {
            // yrs integrates the rest of a partly held block after its own held part: same place as that part
            let place = match self.place((b.client, start - 1)) {
                Some(Some(p)) => p,
                Some(None) => Place {
                    parent: Parent::Gone,
                    key: None,
                },
                None => return Err("a partly held block this replica cannot place".into()),
            };
            let made = allowed(&place, it.content)?;
            if made.is_some() {
                return Err("a nested type cannot be split".into());
            }
            new.record(range, Some(place), None);
            return Ok(Some(()));
        }
        let place = match (&it.parent, it.origin.or(it.right)) {
            (Some(Pref::Root(r)), _) => {
                let parent = match &**r {
                    "nodes" => Parent::Nodes,
                    "meta" => Parent::Meta,
                    "tokens" => Parent::Tokens,
                    _ => return Err(format!("unknown root {r:?}")),
                };
                Place {
                    parent,
                    key: it.key.clone(),
                }
            }
            (Some(Pref::Id(c, k)), _) => {
                let types = if below((*c, *k)) {
                    &self.types
                } else {
                    &new.types
                };
                let kind = match types.get(&(*c, *k)) {
                    Some(kind) => *kind,
                    None if lookup(new, (*c, *k)).is_some() => {
                        return Err("parent is not a nested type".into());
                    }
                    None => return Ok(None),
                };
                Place {
                    parent: Parent::Type(kind),
                    key: it.key.clone(),
                }
            }
            (None, Some(o)) => match lookup(new, o) {
                Some(Some(p)) => p,
                Some(None) => Place {
                    parent: Parent::Gone,
                    key: None,
                },
                None => return Ok(None),
            },
            (None, None) => return Err("block without a parent".into()),
        };
        let made = allowed(&place, it.content)?;
        new.record(range, Some(place), made);
        Ok(Some(()))
    }

    pub(crate) fn learn(&mut self, l: Learned) {
        for (client, runs) in l.index {
            self.items.entry(client).or_default().extend(runs);
        }
        self.types.extend(l.types);
    }
}

/// What a checked update adds to the shadow.
#[derive(Default)]
pub(crate) struct Learned {
    index: HashMap<u64, BTreeMap<u32, (u32, Option<Place>)>>,
    types: HashMap<(u64, u32), Kind>,
}

impl Learned {
    fn record(
        &mut self,
        (client, start, end): (u64, u32, u32),
        place: Option<Place>,
        made: Option<Kind>,
    ) {
        self.index
            .entry(client)
            .or_default()
            .insert(start, (end, place));
        if let Some(k) = made {
            self.types.insert((client, start), k);
        }
    }

    fn place(&self, (client, clock): (u64, u32)) -> Option<Option<Place>> {
        let (_, (end, p)) = self.index.get(&client)?.range(..=clock).next_back()?;
        (clock < *end).then(|| p.clone())
    }
}

/// The layout rule for one block; returns the kind of nested type it creates.
fn allowed(p: &Place, c: Content) -> Result<Option<Kind>, String> {
    use Content::*;
    let keyed = p.key.is_some();
    let ok = |made| Ok(made);
    match (&p.parent, c) {
        (Parent::Gone, Map | Text) => Err("nested type under a removed block".into()),
        (Parent::Gone, _) => ok(None),
        (_, Deleted) => ok(None),
        (Parent::Type(Kind::Text), _) if keyed => Err("keyed content in a text".into()),
        (Parent::Type(Kind::Text), Str) => ok(None),
        (Parent::Type(Kind::Text), _) => Err("text holds plain strings only".into()),
        (_, _) if !keyed => Err("list-side content in a map".into()),
        (Parent::Nodes, Map) => ok(Some(Kind::Node)),
        (Parent::Type(Kind::Node), Map) if p.key.as_deref() == Some("props") => {
            ok(Some(Kind::Props))
        }
        (Parent::Type(Kind::Node), Text) if p.key.as_deref() == Some("text") => {
            ok(Some(Kind::Text))
        }
        (Parent::Nodes, _) => Err("a node must be a map".into()),
        (Parent::Meta | Parent::Tokens | Parent::Type(Kind::Node | Kind::Props), Value) => ok(None),
        _ => Err("nested type or content not allowed here".into()),
    }
}

// ---- lib0 v1, structure only -------------------------------------------------------------------------------------

struct R<'a>(&'a [u8], usize);

impl R<'_> {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.0.get(self.1)?;
        self.1 += 1;
        Some(b)
    }
    fn var(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    fn var32(&mut self) -> Option<u32> {
        u32::try_from(self.var()?).ok()
    }
    /// A signed varint (lib0: sign in bit 6 of the first byte); only skipped.
    fn ivar(&mut self) -> Option<()> {
        loop {
            if self.u8()? & 0x80 == 0 {
                return Some(());
            }
        }
    }
    fn bytes(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.1.checked_add(n)?;
        let s = self.0.get(self.1..end)?;
        self.1 = end;
        Some(s)
    }
    fn string(&mut self) -> Option<&str> {
        let n = usize::try_from(self.var()?).ok()?;
        std::str::from_utf8(self.bytes(n)?).ok()
    }
    fn id(&mut self) -> Option<(u64, u32)> {
        Some((self.var()?, self.var32()?))
    }
    fn any(&mut self, depth: usize) -> Option<()> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        match self.u8()? {
            120 | 121 | 126 | 127 => {}
            125 => self.ivar()?,
            124 => {
                self.bytes(4)?;
            }
            123 | 122 => {
                self.bytes(8)?;
            }
            119 => {
                self.string()?;
            }
            116 => {
                let n = usize::try_from(self.var()?).ok()?;
                self.bytes(n)?;
            }
            118 => {
                for _ in 0..self.count()? {
                    self.string()?;
                    self.any(depth + 1)?;
                }
            }
            117 => {
                for _ in 0..self.count()? {
                    self.any(depth + 1)?;
                }
            }
            _ => return None,
        }
        Some(())
    }
    /// A count of elements, each at least one byte.
    fn count(&mut self) -> Option<usize> {
        let n = usize::try_from(self.var()?).ok()?;
        (n <= self.0.len() - self.1).then_some(n)
    }
}

/// Every block of a v1 update, or `None` when it is malformed or holds something the layout never needs.
fn parse(bytes: &[u8]) -> Option<Vec<Block>> {
    let mut r = R(bytes, 0);
    let mut out = vec![];
    for _ in 0..r.count()? {
        let n = r.count()?;
        let client = r.var()?;
        let mut clock = r.var32()?;
        for _ in 0..n {
            let info = r.u8()?;
            let (len, item) = match info {
                0 => (r.var32()?, None),
                _ if info & 0x0f == 10 || info & 0x0f == 0 => return None, // skip, or GC with flags
                _ => {
                    let origin = if info & 0x80 != 0 {
                        Some(r.id()?)
                    } else {
                        None
                    };
                    let right = if info & 0x40 != 0 {
                        Some(r.id()?)
                    } else {
                        None
                    };
                    let (parent, key) = if origin.is_none() && right.is_none() {
                        let parent = if r.var()? == 1 {
                            Pref::Root(r.string()?.into())
                        } else {
                            let (c, k) = r.id()?;
                            Pref::Id(c, k)
                        };
                        let key = if info & 0x20 != 0 {
                            Some(Arc::from(r.string()?))
                        } else {
                            None
                        };
                        (Some(parent), key)
                    } else {
                        (None, None)
                    };
                    let (len, content) = match info & 0x0f {
                        1 => (r.var32()?, Content::Deleted),
                        4 => (
                            u32::try_from(r.string()?.encode_utf16().count()).ok()?,
                            Content::Str,
                        ),
                        7 => match r.u8()? {
                            1 => (1, Content::Map),
                            2 => (1, Content::Text),
                            _ => return None,
                        },
                        8 => {
                            let n = r.count()?;
                            for _ in 0..n {
                                r.any(0)?;
                            }
                            (u32::try_from(n).ok()?, Content::Value)
                        }
                        // JSON, binary, embed, format, subdoc: never written by the layout
                        _ => return None,
                    };
                    (
                        len,
                        Some(Item {
                            origin,
                            right,
                            parent,
                            key,
                            content,
                        }),
                    )
                }
            };
            if len == 0 {
                return None;
            }
            let end = clock.checked_add(len)?;
            out.push(Block {
                client,
                clock,
                len,
                item,
            });
            clock = end;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One client, one GC block of `len` at `clock`, empty delete set.
    fn gc(clock: u32, len: u32) -> Vec<u8> {
        let mut u = vec![1, 1, 1];
        let mut var = |mut v: u64| loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                u.push(b);
                break;
            }
            u.push(b | 0x80);
        };
        var(u64::from(clock));
        var(0);
        var(u64::from(len));
        u.push(0);
        u
    }

    #[test]
    fn a_client_run_may_not_pass_u32_max() {
        assert!(parse(&gc(u32::MAX - 5, 5)).is_some());
        assert!(parse(&gc(u32::MAX - 5, 6)).is_none());
        assert!(parse(&gc(0, 0)).is_none(), "empty block");
    }
}
