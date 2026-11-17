//! The Design CRDT: a yrs document (T1) and the single gate every remote update passes before it is persisted or
//! broadcast (V1-03).
//!
//! SECURITY MODEL
//! - A peer's update bytes are hostile. `Replica::apply_remote` is the only way they enter a replica that is served to
//!   others, and it either returns the exact diff that was integrated (to persist and broadcast) or refuses.
//! - Refused means a protocol violation: the caller drops the peer and discards the replica (`poisoned`), then rebuilds
//!   it from storage. It is never "skip this update and carry on": an honest client cannot send any of these, and a
//!   skipped update would let replicas drift.
//! - Order of checks: size cap (before decoding) -> decode -> integrate -> no pending (missing dependencies) -> no
//!   foreign root types or sub-documents -> every node the update touched is read strictly (`read`) and validated by
//!   the model crate (`design_model::validate`) -> clock cap -> node and token budgets. Only touched nodes are checked,
//!   found through yrs deep observers on the three roots, so a check costs the size of the update, not of the document.
//! - The cycle rule: parent, clock and previous parent are ONE register (`move`), so concurrent moves never mix their
//!   halves; `order` is another, so a rebalance never undoes a concurrent move. `design_model::tree::forest` reads any
//!   cycle two concurrent moves leave and reverts the loser to its previous parent.
//! - A clock more than `MAX_CLOCK_JUMP` above the highest in the document is refused (a hostile `u64::MAX` would make
//!   that node lose every cycle for ever). The cap depends on replica state, which is why the Core is the only
//!   validator: clients apply what the Core accepted, in the Core's order.
//! - Not here: authentication, rate limits, per-connection byte budgets (the Core's sync endpoint), and the whole
//!   document byte budget (it counts stored bytes, which only the store knows).

mod edit;
mod read;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use design_model::limits::{MAX_CLOCK_JUMP, MAX_NODES, MAX_TOKENS};
use design_model::validate;
pub use design_model::{Doc as Model, NodeType};
pub use edit::Editor;
use yrs::types::DeepObservable as _;
use yrs::types::map::MapRef;
use yrs::updates::decoder::Decode;
use yrs::{Doc, Map as _, ReadTxn, StateVector, Transact, Update};

/// The most bytes one update may have (T14).
pub const MAX_UPDATE_BYTES: usize = 1 << 20;
const ROOTS: [&str; 3] = ["nodes", "meta", "tokens"];
/// What `encode_update_v1` returns for a transaction that changed nothing.
const EMPTY_UPDATE: [u8; 2] = [0, 0];

/// Why an update was refused. Fixed text only: nothing a peer sent is echoed back beyond the model's clipped paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    TooLarge,
    Malformed,
    /// It builds on state this replica does not have.
    Pending,
    /// Out of schema; the first violation (`path: message`).
    Invalid(String),
    ClockTooHigh,
    TooManyNodes,
    /// An earlier refusal left this replica unusable: rebuild it.
    Poisoned,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => f.write_str("update too large"),
            Self::Malformed => f.write_str("update is not valid"),
            Self::Pending => f.write_str("update depends on state the document does not have"),
            Self::Invalid(m) => write!(f, "update refused: {m}"),
            Self::ClockTooHigh => f.write_str("move clock too far ahead"),
            Self::TooManyNodes => f.write_str("too many nodes"),
            Self::Poisoned => f.write_str("replica must be rebuilt"),
        }
    }
}

impl std::error::Error for Refused {}

#[derive(Default)]
struct Dirty {
    nodes: BTreeSet<String>,
    nodes_map: bool,
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
}

impl Default for Replica {
    fn default() -> Self {
        Self::new()
    }
}

impl Replica {
    pub fn new() -> Self {
        let doc = Doc::new();
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
                if let yrs::types::Event::Map(m) = e
                    && e.path().is_empty()
                {
                    d.nodes_map = true;
                    d.nodes.extend(m.keys(txn).keys().map(|k| k.to_string()));
                } else if let Some(yrs::types::PathSegment::Key(id)) = e.path().front() {
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
        Self {
            doc,
            nodes,
            meta,
            tokens,
            dirty,
            top_clock: 0,
            poisoned: false,
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
    pub fn apply_trusted(&mut self, update: &[u8]) -> Result<(), Refused> {
        let u = Update::decode_v1(update).map_err(|_| Refused::Malformed)?;
        self.doc
            .transact_mut()
            .apply_update(u)
            .map_err(|_| Refused::Malformed)
    }

    /// The gate. `Ok(None)`: valid, but nothing in it was new. `Ok(Some(diff))`: what was integrated, to persist and
    /// broadcast. `Err`: a protocol violation; the replica is poisoned (see the module docs).
    pub fn apply_remote(&mut self, update: &[u8]) -> Result<Option<Vec<u8>>, Refused> {
        if self.poisoned {
            return Err(Refused::Poisoned);
        }
        if update.len() > MAX_UPDATE_BYTES {
            return Err(Refused::TooLarge);
        }
        let u = Update::decode_v1(update).map_err(|_| Refused::Malformed)?;
        *self.dirty.lock().unwrap_or_else(|e| e.into_inner()) = Dirty::default();
        // From here the document may hold unverified content until `verify` passes.
        self.poisoned = true;
        let (diff, pending) = {
            let mut txn = self.doc.transact_mut();
            txn.apply_update(u).map_err(|_| Refused::Malformed)?;
            let pending =
                txn.store().pending_update().is_some() || txn.store().pending_ds().is_some();
            (txn.encode_update_v1(), pending)
        };
        if pending {
            return Err(Refused::Pending);
        }
        self.verify()?;
        self.poisoned = false;
        Ok((diff != EMPTY_UPDATE).then_some(diff))
    }

    fn verify(&mut self) -> Result<(), Refused> {
        let dirty = std::mem::take(&mut *self.dirty.lock().unwrap_or_else(|e| e.into_inner()));
        let txn = self.doc.transact();
        if txn.root_refs().any(|(n, _)| !ROOTS.contains(&n)) || txn.subdocs().next().is_some() {
            return Err(Refused::Invalid("foreign root type".into()));
        }
        let invalid = |m: String| Refused::Invalid(m);
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
