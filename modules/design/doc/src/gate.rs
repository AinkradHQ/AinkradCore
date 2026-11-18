//! The one gate every remote update passes before yrs integrates it (V1-05). The App engine (`Live`) and the Core's
//! replica (`Replica`) both go through it, so a peer's bytes meet the same defences on either side of the socket.
//!
//! SECURITY MODEL
//! - Remote bytes are hostile. yrs recurses over nested values and nested shared types (decode, integrate, delete,
//!   gc, encode, drop), so a crafted update can overflow the stack, which aborts the process; its decoders panic on
//!   some input; it reserves memory from lengths on the wire; and it parks an update it cannot place yet as
//!   "pending", where a later overlapping update reads freed memory. None of that may be reachable from a peer.
//! - `admit` runs every check before anything reaches the replica, each layer on its own parser, so a trick that
//!   fools one parser still meets the next (where `design-crdt` and the engine overlapped, both layers are kept):
//!   1. `guard::scan_facts`, the raw bytes: bounded nesting (`MAX_JSON_DEPTH`), every count against the bytes left,
//!      only our content kinds (no `undefined`, buffer, embed, format, JSON, subdoc, XML, skip), one run per client,
//!      client ids in 53 bits, clocks in `u32`, no empty run, no trailing bytes.
//!   2. `Facts::check_known`, the dependencies as the raw bytes state them: nothing past this replica's state
//!      (`Refused::Pending`: the peer resyncs, nothing was touched).
//!   3. `layout::Shadow::check`, the T1 layout: every block placed exactly (roots `nodes`/`meta`/`tokens`, node map,
//!      its `props` map and `text`; nothing deeper, no list-side content in a map, plain strings in a text), held
//!      blocks looked up only in what this replica committed. This replaces `design-crdt`'s shared-type depth count
//!      (`resolve_types`): the layout is the stricter rule, and the count refused an honest full state (a node
//!      re-added after a delete has a deleted item as its origin, which the count could not place).
//!   4. `decode::update`, yrs's own decoder with every `Any` depth- and length-capped, a client listed twice and skip
//!      blocks refused, panics caught.
//!   5. `no_gap`, the dependencies again, as yrs decoded them (`Refused::Pending`).
//!   6. `trial::run`, the update applied to a trial copy on a big stack and the copy's live structure walked.
//! - Then the owner integrates (`integrate`, on `trial::big_stack`): a panic inside yrs is caught and reported, never
//!   unwound through an open transaction, and whether yrs parked anything as pending is reported too. The engine
//!   resets its replica on a panic (`Error::Reset`); the Core poisons and rebuilds its replica from storage, and also
//!   refuses anything left pending and validates what the update touched (`Replica::verify`).
//! - Every committed update, local or remote, is placed in the shadow (`watch`), so the gate always knows what the
//!   replica holds. An update the shadow cannot place is counted (`misses`); later updates building on it are then
//!   refused (fail closed).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use yrs::{ClientID, Doc, ID, ReadTxn, StateVector, Transact, TransactionMut, Update};

use crate::{decode, guard, layout, trial};

/// Why a remote update was refused. Fixed text only: nothing a peer sent is echoed back beyond the model's clipped
/// paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    TooLarge,
    Malformed,
    /// It builds on state this replica does not have: the peer must resync. Refused before anything was integrated,
    /// so the replica is untouched; not a violation.
    Pending,
    /// Out of schema; the first violation (`path: message`).
    Invalid(String),
    ClockTooHigh,
    TooManyNodes,
    /// An earlier refusal left this replica unusable: rebuild it.
    Poisoned,
    /// No thread could be started for the update (nothing was integrated).
    Busy,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("update too large"),
            Self::Malformed => f.write_str("update is not valid"),
            Self::Pending => f.write_str("update does not follow this replica's state; resync"),
            Self::Invalid(m) => write!(f, "update refused: {m}"),
            Self::ClockTooHigh => f.write_str("move clock too far ahead"),
            Self::TooManyNodes => f.write_str("too many nodes"),
            Self::Poisoned => f.write_str("replica must be rebuilt"),
            Self::Busy => f.write_str("no thread available"),
        }
    }
}

impl std::error::Error for Refused {}

/// What `integrate` did.
pub(crate) struct Integrated {
    /// The update this transaction made (what the Core stores and relays).
    pub(crate) diff: Vec<u8>,
    /// yrs kept part of it as pending (`no_gap` makes this unreachable for remote bytes).
    pub(crate) pending: bool,
}

pub(crate) enum Failed {
    /// yrs returned an error.
    Refused(String),
    /// yrs panicked: the replica may be half-integrated.
    Panicked,
}

pub(crate) struct Gate {
    /// What the replica holds, placed in the T1 layout.
    pub(crate) shadow: Arc<Mutex<layout::Shadow>>,
    misses: Arc<AtomicU64>,
    /// The trial copy remote updates are tried on first.
    trial: Option<trial::Trial>,
}

impl Gate {
    /// Gate `doc`: every committed update is placed in the shadow, then handed to `then` (the engine's outbox).
    pub(crate) fn watch(
        doc: &Doc,
        then: impl Fn(&TransactionMut, &[u8]) + Send + Sync + 'static,
    ) -> Gate {
        let shadow: Arc<Mutex<layout::Shadow>> = Arc::default();
        let misses: Arc<AtomicU64> = Arc::default();
        let (sh, m) = (shadow.clone(), misses.clone());
        doc.observe_update_v1("gate", move |txn, e| {
            {
                let mut sh = sh.lock().unwrap_or_else(|e| e.into_inner());
                match sh.check(&e.update, txn.before_state()) {
                    Ok(l) => sh.learn(l),
                    Err(err) => {
                        m.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "design-doc: the layout shadow could not place a committed update: {err}"
                        );
                    }
                }
            }
            then(txn, &e.update);
        })
        .expect("a fresh doc has no transaction open");
        Gate {
            shadow,
            misses,
            trial: None,
        }
    }

    /// Committed updates the shadow could not place (0 in a healthy replica).
    pub(crate) fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// The trial copy holds an update the replica did not take: rebuild it from the replica next time.
    pub(crate) fn drop_trial(&mut self) {
        self.trial = None;
    }

    /// Every check before `update` may be integrated into `doc` (see the module docs). Nothing is written to `doc`.
    /// The caller has checked the size cap.
    pub(crate) fn admit(&mut self, doc: &Doc, update: &[u8]) -> Result<Update, Refused> {
        let have = doc.transact().state_vector();
        let facts = guard::scan_facts(update)?;
        facts.check_known(|c| u64::from(have.get(&ClientID::new(c))))?;
        self.shadow
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .check(update, &have)
            .map_err(|_| Refused::Malformed)?;
        let (u, refs) = decode::update(update).map_err(|_| Refused::Malformed)?;
        no_gap(&have, &u, &refs)?;
        let since = self
            .trial
            .as_ref()
            .map_or_else(StateVector::default, |t| t.sv.clone());
        let base = doc.transact().encode_state_as_update_v1(&since);
        self.trial = Some(trial::run(self.trial.take(), base, update)?);
        Ok(u)
    }
}

/// Refuse a remote update that yrs would have to keep as "pending": one whose blocks for some client start past
/// what this replica has, that refers to a block (origin, parent) neither this replica nor the update holds, or
/// that deletes beyond both. The Core relays updates in order and a diff starts at our state vector, so an honest
/// update never needs pending; the peer answers this refusal with a resync. yrs's pending path is where the
/// use-after-free and the re-encode panics live (fuzz target `apply`, `fuzz/regressions/*`), so remote bytes never
/// reach it.
fn no_gap(have: &StateVector, u: &Update, refs: &[ID]) -> Result<(), Refused> {
    // what the update itself inserts (one contiguous run per client: a client listed twice is refused at decode)
    let ins = u.insertions(true);
    let held = |id: &ID| id.clock < have.get(&id.client) || ins.contains(id);
    let deletable = |c: &ClientID, r: &std::ops::Range<u32>| {
        let from = r.start.max(have.get(c));
        from >= r.end || (ins.contains(&ID::new(*c, from)) && ins.contains(&ID::new(*c, r.end - 1)))
    };
    if u.state_vector_lower()
        .iter()
        .any(|(c, lower)| *lower > have.get(c))
        || !refs.iter().all(held)
        || u.delete_set()
            .iter()
            .any(|(c, rs)| rs.iter().any(|r| !deletable(c, r)))
    {
        return Err(Refused::Pending);
    }
    Ok(())
}

/// Apply `u` with `origin`, in one transaction. A panic inside yrs is `Failed::Panicked`; the caller resets or
/// poisons. Run it on `trial::big_stack` for remote bytes.
pub(crate) fn integrate(doc: &Doc, u: Update, origin: &str) -> Result<Integrated, Failed> {
    // A panic while integrating must not unwind through the open transaction: its drop commits, and a second panic
    // there would abort. The inner catch ends the first panic before the transaction drops; the outer one catches a
    // panic in that commit, in the encode or in the probe.
    let mut panicked = false;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut txn = doc.transact_mut_with(origin);
        let r = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| txn.apply_update(u)))
        {
            Ok(r) => r.map_err(|e| Failed::Refused(e.to_string())),
            Err(_) => {
                panicked = true;
                Err(Failed::Panicked)
            }
        };
        let r = r.map(|()| Integrated {
            pending: txn.store().pending_update().is_some() || txn.store().pending_ds().is_some(),
            diff: txn.encode_update_v1(),
        });
        drop(txn);
        // Probe: yrs keeps updates it cannot integrate yet as "pending" and re-encodes them later, which panics for
        // some it accepted. Do that now, so a bad pending update fails here, attributed to this update, and not on
        // the user's next edit or sync. Cheap: only the pending part is encoded.
        if !panicked {
            let t = doc.transact();
            if t.has_missing_updates() {
                let _ = t.encode_state_as_update_v1(&t.state_vector());
            }
        }
        r
    }));
    match r {
        Ok(r) if !panicked => r,
        _ => Err(Failed::Panicked),
    }
}
