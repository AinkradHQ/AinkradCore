//! The Core's document (V1-03, from `design-crdt`; on the shared `gate` since V1-05): the single place a device's
//! update is accepted before it is persisted or broadcast.
//!
//! SECURITY MODEL
//! - A peer's update bytes are hostile. `Replica::apply_remote` is the only way they enter a replica that is served to
//!   others, and it either returns the exact diff that was integrated (to persist and broadcast) or refuses.
//! - Refused means a protocol violation: the caller drops the peer and discards the replica (`poisoned`), then rebuilds
//!   it from storage. It is never "skip this update and carry on": an honest client cannot send any of these, and a
//!   skipped update would let replicas drift. Two refusals leave the replica untouched and unpoisoned: `Pending`
//!   (the peer resyncs) and `Busy` (no thread), and so does every refusal from `gate::admit`.
//! - Order of checks: size cap (`MAX_PEER_UPDATE_BYTES`) -> `gate::admit` (raw scan, dependencies twice, the T1
//!   layout, guarded decode, the trial copy; see `gate`) -> integrate on a big stack (a panic = invalid) -> nothing
//!   left pending -> no foreign root types or sub-documents -> every node the update touched is read strictly (`read`)
//!   and validated by the model crate (`design_model::validate`) -> clock cap -> node and token budgets. Only touched
//!   nodes are checked, found through yrs deep observers on the three roots, so this last part costs the size of the
//!   update; the trial walk in `gate` costs the size of the document.
//! - The cycle rule: parent, clock and previous parent are ONE register (`move`), so concurrent moves never mix their
//!   halves; `order` is another, so a rebalance never undoes a concurrent move. `design_model::tree::forest` reads any
//!   cycle two concurrent moves leave and reverts the loser to its previous parent.
//! - A clock more than `MAX_CLOCK_JUMP` above the highest in the document is refused (a hostile `u64::MAX` would make
//!   that node lose every cycle for ever). The cap depends on replica state, which is why the Core is the only
//!   validator: clients apply what the Core accepted, in the Core's order.
//! - Not here: authentication, rate limits, per-connection byte budgets (the Core's sync endpoint), and the whole
//!   document byte budget (it counts stored bytes, which only the store knows).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use design_model::limits::{MAX_CLOCK_JUMP, MAX_NODES, MAX_TOKENS};
use design_model::validate;
use yrs::types::DeepObservable as _;
use yrs::types::map::MapRef;
use yrs::updates::decoder::Decode;
use yrs::{Doc, Map as _, ReadTxn, StateVector, Transact, Update};

use crate::edit::Editor;
use crate::gate::{self, Gate, Refused};
use crate::{Model, read, trial};

/// The most bytes one update from a device may have (T14). The engine's outbox stays under it.
pub const MAX_PEER_UPDATE_BYTES: usize = 1 << 20;
const ROOTS: [&str; 3] = ["nodes", "meta", "tokens"];
/// The origin of a remote integrate (no undo manager here; it only labels the transaction).
const REMOTE: &str = "remote";

/// What `encode_update_v1` returns for a transaction that changed nothing.
const EMPTY_UPDATE: [u8; 2] = [0, 0];

#[derive(Default)]
struct Dirty {
    nodes: BTreeSet<String>,
    nodes_map: bool,
    /// An event deeper than root -> node -> props/text: a nested shared type that must not exist.
    too_deep: bool,
    meta: bool,
    tokens: bool,
}

pub struct Replica {
    doc: Doc,
    nodes: MapRef,
    meta: MapRef,
    tokens: MapRef,
    dirty: Arc<Mutex<Dirty>>,
    /// The highest move clock in the document.
    top_clock: u64,
    poisoned: bool,
    gate: Gate,
}

impl Default for Replica {
    fn default() -> Self {
        Self::new()
    }
}

impl Replica {
    pub fn new() -> Self {
        let doc = crate::new_ydoc();
        let (nodes, meta, tokens) = (
            doc.get_or_insert_map("nodes"),
            doc.get_or_insert_map("meta"),
            doc.get_or_insert_map("tokens"),
        );
        let dirty = Arc::new(Mutex::new(Dirty::default()));
        let d = dirty.clone();
        nodes.observe_deep("dirty", move |txn, events| {
            let mut d = d.lock().unwrap_or_else(|e| e.into_inner());
            for e in events.iter() {
                let path = e.path();
                if path.len() > 2 {
                    d.too_deep = true;
                }
                if let yrs::types::Event::Map(m) = e
                    && path.is_empty()
                {
                    d.nodes_map = true;
                    d.nodes.extend(m.keys(txn).keys().map(|k| k.to_string()));
                } else if let Some(yrs::types::PathSegment::Key(id)) = path.front() {
                    d.nodes.insert(id.to_string());
                }
            }
        });
        for (m, pick) in [
            (&meta, (|d: &mut Dirty| d.meta = true) as fn(&mut Dirty)),
            (&tokens, |d: &mut Dirty| d.tokens = true),
        ] {
            let d = dirty.clone();
            m.observe_deep("dirty", move |_, _| {
                pick(&mut d.lock().unwrap_or_else(|e| e.into_inner()))
            });
        }
        let gate = Gate::watch(&doc, |_, _| {});
        Self {
            doc,
            nodes,
            meta,
            tokens,
            dirty,
            top_clock: 0,
            poisoned: false,
            gate,
        }
    }

    /// Rebuild from stored bytes (a snapshot, then the log). Stored updates passed `apply_remote` when they were
    /// written, so they are integrated as they are; a stored document that does not read back strictly is an error.
    pub fn from_stored<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> Result<Self, Refused> {
        let mut r = Self::new();
        for p in parts {
            r.apply_trusted(p)?;
        }
        r.top_clock = r.read()?.nodes.values().map(|n| n.clock).max().unwrap_or(0);
        Ok(r)
    }

    /// Integrate bytes from a source this process already trusts (the Core's own broadcast, on a client; the store).
    /// Still scanned structurally first (cheap), then integrated on a big stack like every remote update
    /// (`gate::integrate` also turns a yrs panic into an error). Crate-private: a caller outside takes
    /// `apply_remote`, which verifies.
    pub(crate) fn apply_trusted(&mut self, update: &[u8]) -> Result<(), Refused> {
        crate::guard::scan(update)?;
        let doc = self.doc.clone();
        trial::big_stack(|| {
            let u = Update::decode_v1(update).map_err(|_| Refused::Malformed)?;
            gate::integrate(&doc, u, REMOTE)
                .map(|_| ())
                .map_err(|_| Refused::Malformed)
        })?
    }

    /// True once an update was refused after it was integrated, or the owner could not rebuild: the content must not
    /// be served to anyone. Rebuild the replica from storage.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// The gate. `Ok(None)`: valid, but nothing in it was new. `Ok(Some(diff))`: what was integrated, to persist and
    /// broadcast. `Err`: see the module docs; `Pending` and `Busy` leave the replica untouched, anything refused after
    /// integration poisons it.
    pub fn apply_remote(&mut self, update: &[u8]) -> Result<Option<Vec<u8>>, Refused> {
        if self.poisoned {
            return Err(Refused::Poisoned);
        }
        if update.len() > MAX_PEER_UPDATE_BYTES {
            return Err(Refused::TooLarge);
        }
        // Before yrs integrates a byte into this replica: every layer of the shared gate.
        let doc = self.doc.clone();
        let u = self.gate.admit(&doc, update)?;
        *self.dirty.lock().unwrap_or_else(|e| e.into_inner()) = Dirty::default();
        // From here the document may hold unverified content until `verify` passes.
        self.poisoned = true;
        // Integrate and verify on a thread with a big stack, so even a structure the gate missed cannot overflow the
        // Core's stack (yrs recurses over nested types in delete and gc).
        match trial::big_stack(|| self.integrate_and_verify(u)).and_then(|r| r) {
            Ok(diff) => {
                self.poisoned = false;
                Ok((diff != EMPTY_UPDATE).then_some(diff))
            }
            Err(e) => {
                self.gate.drop_trial(); // it holds the update
                if e == Refused::Busy {
                    self.poisoned = false; // the thread never started: nothing was integrated
                }
                Err(e)
            }
        }
    }

    /// Runs on the big-stack thread: integrate the update, then check what it did to the document.
    fn integrate_and_verify(&mut self, u: Update) -> Result<Vec<u8>, Refused> {
        let i = gate::integrate(&self.doc, u, REMOTE).map_err(|_| Refused::Malformed)?;
        // the gate makes a parked (pending) update unreachable; if it ever happens yrs holds it and the replica is
        // poisoned for good (a violation, not a resync: the owner rebuilds it)
        if i.pending {
            return Err(Refused::Malformed);
        }
        self.verify()?;
        Ok(i.diff)
    }

    /// Drop this replica on a big-stack thread (a replica that took a hostile update is dropped, never trusted).
    pub fn discard(self) {
        let cell = Mutex::new(Some(self));
        let ok = trial::big_stack(|| drop(cell.lock().unwrap_or_else(|e| e.into_inner()).take()))
            .is_ok();
        if !ok {
            // could not drop it safely: leak it rather than risk the stack
            std::mem::forget(cell.lock().unwrap_or_else(|e| e.into_inner()).take());
        }
    }

    fn verify(&mut self) -> Result<(), Refused> {
        let dirty = std::mem::take(&mut *self.dirty.lock().unwrap_or_else(|e| e.into_inner()));
        let txn = self.doc.transact();
        if txn.root_refs().any(|(n, _)| !ROOTS.contains(&n)) || txn.subdocs().next().is_some() {
            return Err(Refused::Invalid("foreign root type".into()));
        }
        let invalid = |m: String| Refused::Invalid(m);
        if dirty.too_deep {
            return Err(invalid("shared types nested too deeply".into()));
        }
        // A map holds keyed entries only: an item in its list part is invisible to every read, and would be stored.
        for m in [&self.nodes, &self.meta, &self.tokens] {
            if read::branch_len(m) != 0 {
                return Err(invalid("list item in a root map".into()));
            }
        }
        let cap = self.top_clock.saturating_add(MAX_CLOCK_JUMP);
        let mut top = self.top_clock;
        for id in &dirty.nodes {
            let Some(n) = read::node(&txn, &self.nodes, id).map_err(invalid)? else {
                continue;
            };
            let mut vs = vec![];
            validate::node(id, &n, &mut vs);
            if let Some(v) = vs.first() {
                return Err(invalid(format!("{}: {}", v.path, v.msg)));
            }
            if n.clock > cap {
                return Err(Refused::ClockTooHigh);
            }
            top = top.max(n.clock);
        }
        if dirty.nodes_map && self.nodes.len(&txn) as usize > MAX_NODES {
            return Err(Refused::TooManyNodes);
        }
        if dirty.meta {
            let m = read::meta(&txn, &self.meta).map_err(invalid)?;
            if m.system
                .as_deref()
                .is_some_and(|s| !design_model::ids::is_doc_id(s))
            {
                return Err(invalid("meta.system: bad design-system doc id".into()));
            }
        }
        if dirty.tokens {
            let t = read::tokens(&txn, &self.tokens).map_err(invalid)?;
            if t.len() > MAX_TOKENS {
                return Err(invalid("too many tokens".into()));
            }
            for (name, tok) in &t {
                if !design_model::ids::is_token_name(name) {
                    return Err(invalid("tokens: bad token name".into()));
                }
                validate::token(tok).map_err(|m| invalid(format!("tokens: {m}")))?;
            }
        }
        self.top_clock = top;
        Ok(())
    }

    /// The whole document as the model reads it (strict; an error means the stored shape is corrupt).
    pub fn read(&self) -> Result<Model, Refused> {
        let txn = self.doc.transact();
        read::all(&txn, &self.nodes, &self.meta, &self.tokens).map_err(Refused::Invalid)
    }

    /// The full state as one update (a snapshot, or a new peer's first message).
    pub fn state(&self) -> Vec<u8> {
        self.doc
            .transact()
            .encode_state_as_update_v1(&StateVector::default())
    }

    pub fn top_clock(&self) -> u64 {
        self.top_clock
    }

    /// Local edits (a client's gestures, the Core's own typed ops): one transaction, returned as update bytes. Local
    /// edits are not validated here; what a client sends is validated by the Core on arrival.
    pub fn edit<R>(&mut self, f: impl FnOnce(&mut Editor<'_, '_>) -> R) -> (R, Vec<u8>) {
        let mut txn = self.doc.transact_mut();
        let r = f(&mut Editor::new(
            &mut txn,
            &self.nodes,
            &self.meta,
            &self.tokens,
            &mut self.top_clock,
        ));
        let bytes = txn.encode_update_v1();
        drop(txn); // commits: the gate's shadow learns the edit
        (r, bytes)
    }

    /// Refuse every later update: the owner could not rebuild this replica after a failure.
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    /// The raw yrs document, for tests that forge hostile updates.
    #[doc(hidden)]
    pub fn raw(&self) -> &Doc {
        &self.doc
    }
}
