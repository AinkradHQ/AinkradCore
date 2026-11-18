//! Defence in depth for remote updates, independent of how `layout` parses bytes. Every remote update is first
//! applied to a trial copy of the replica on a thread with a 1 GiB stack (a virtual reservation), and the copy's
//! actual structure is then checked by a flat walk: only the three roots, no list-side content in a map, node maps
//! under `nodes` holding plain values plus `props` (plain values) and `text` (plain strings, no formatting, no
//! embeds). Whatever an encoding trick makes yrs do (deep recursion while integrating, deleting or collecting), it
//! happens on that stack, and a copy that fails the walk is dropped there too. The real replica then applies the
//! update, also on a big stack (`big_stack`).
//!
//! Cost: the copy is built once from a full encode of the replica, then kept in step with deltas (the replica's
//! changes since the copy's state vector, which include our own edits) plus the remote update itself. Per remote
//! update: two thread spawns, the delta encode, one extra apply and a walk over the whole document. Since V1-05 the
//! Core's replica runs it too (`gate`), so the Core trial-applies every device update before it touches its replica.

use yrs::types::text::{Diff, YChange};
use yrs::updates::decoder::Decode;
use yrs::{Any, Doc, Map, MapRef, Out, ReadTxn, StateVector, Text, Transact, Update};

use crate::gate::Refused;

/// The stack for the trial and for applying remote updates to the replica.
#[cfg(not(fuzzing))]
pub(crate) const BIG_STACK: usize = 1 << 30;
/// Tried when the 1 GiB reservation cannot be made (a tight address space or ulimit); still far above the default.
#[cfg(not(fuzzing))]
pub(crate) const FALLBACK_STACK: usize = 1 << 28;

pub(crate) struct Trial {
    doc: Doc,
    pub(crate) sv: StateVector,
}

/// Under the fuzzer `f` runs inline instead, on the fuzz target's 512 KB stack: AddressSanitizer never frees its
/// per-thread records, so two threads per update ran the fuzzer out of memory, and inline the fuzzer also proves the
/// layout gate alone keeps yrs from recursing deeply (any miss would abort the run).
#[cfg(fuzzing)]
pub(crate) fn big_stack<T: Send>(f: impl FnOnce() -> T + Send) -> Result<T, Refused> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| Refused::Malformed)
}

/// Run `f` on a thread with `BIG_STACK` (`FALLBACK_STACK` when that cannot be reserved) and wait for it: `Busy` when
/// no thread could start (`f` did not run), `Malformed` when `f` panicked.
#[cfg(not(fuzzing))]
pub(crate) fn big_stack<T: Send>(f: impl FnOnce() -> T + Send) -> Result<T, Refused> {
    big_stack_of(&[BIG_STACK, FALLBACK_STACK], f)
}

/// `big_stack` with the stack sizes to try, in order (a failed spawn consumes `f`, so it waits in a slot).
#[cfg(not(fuzzing))]
pub(crate) fn big_stack_of<T: Send>(
    sizes: &[usize],
    f: impl FnOnce() -> T + Send,
) -> Result<T, Refused> {
    let slot = std::sync::Mutex::new(Some(f));
    let run = || {
        let f = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        f.map(|f| f())
    };
    std::thread::scope(|s| {
        for &size in sizes {
            if let Ok(h) = std::thread::Builder::new()
                .stack_size(size)
                .spawn_scoped(s, run)
            {
                return h
                    .join()
                    .map_err(|_| Refused::Malformed)?
                    .ok_or(Refused::Busy);
            }
        }
        Err(Refused::Busy)
    })
}

/// Bring the trial (or a new one built from `base` = the replica's full state) up to date with `base`, apply
/// `update`, and walk it. `Err` = the update is refused (the trial was dropped on the big stack), or `Busy`.
pub(crate) fn run(trial: Option<Trial>, base: Vec<u8>, update: &[u8]) -> Result<Trial, Refused> {
    big_stack(move || {
        let doc = trial.map(|t| t.doc).unwrap_or_else(|| {
            let d = crate::new_ydoc();
            for root in ["nodes", "meta", "tokens"] {
                d.get_or_insert_map(root);
            }
            d
        });
        {
            let mut t = doc.transact_mut();
            // `base` is our own replica's encoding; the remote bytes go through the guarded decoder
            t.apply_update(Update::decode_v1(&base).ok()?).ok()?;
            let (u, _) = crate::decode::update(update).ok()?;
            t.apply_update(u).ok()?;
        }
        let ok = walk(&doc);
        let sv = doc.transact().state_vector();
        ok.then_some(Trial { doc, sv })
        // a refused copy is dropped here, on the big stack
    })?
    .ok_or(Refused::Malformed)
}

/// The layout, checked on the copy's live structure. Flat: the layout's depth is fixed at 2.
pub(crate) fn walk(doc: &Doc) -> bool {
    let txn = doc.transact();
    let plain = |m: &MapRef| m.as_ref().len() == 0; // nothing on the list side of a map
    for (name, root) in txn.root_refs() {
        let Out::YMap(root) = root else { return false };
        if !plain(&root) {
            return false;
        }
        for (_, v) in root.iter(&txn) {
            let ok = match (name, v) {
                ("meta" | "tokens", Out::Any(_)) => true,
                ("nodes", Out::YMap(node)) => plain(&node) && node_ok(&txn, &node),
                _ => false,
            };
            if !ok {
                return false;
            }
        }
    }
    true
}

fn node_ok<T: ReadTxn>(txn: &T, node: &MapRef) -> bool {
    node.iter(txn).all(|(k, v)| match (k, v) {
        ("props", Out::YMap(p)) => {
            p.as_ref().len() == 0 && p.iter(txn).all(|(_, v)| matches!(v, Out::Any(_)))
        }
        ("text", Out::YText(t)) => {
            t.diff(txn, YChange::identity)
                .into_iter()
                .all(|d: Diff<YChange>| {
                    matches!(d.insert, Out::Any(Any::String(_))) && d.attributes.is_none()
                })
        }
        (_, Out::Any(_)) => true,
        _ => false,
    })
}
