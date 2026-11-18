//! The design document (T1, T3), the single doc crate since V1-05: one `yrs::Doc` layout,
//!
//! ```text
//! nodes:  Map<id, Map{type, order, move: {p, c, f}, name, props: Map, text?: Text}>
//! meta:   Map{system, version}
//! tokens: Map<name, {kind, day, night}>          (system docs only)
//! ```
//!
//! (`read` documents the node entry; `move` is ONE register for parent, clock and previous parent, so concurrent
//! moves never tear and a losing crossing move is reverted), shared by two owners:
//!
//! - [`Live`], the App engine's document (V2-02): read out as a `design_model::Doc`, edited only through typed
//!   [`Op`]s that the model's validators check first (all-or-nothing, one transaction, one undo step), with sync bytes
//!   in/out (yrs update v1) and presence (yrs awareness). A node that does not read strictly is skipped and the
//!   model's resolver bounds the rest. A panic inside yrs resets the replica (`Error::Reset`) instead of aborting.
//! - [`Replica`], the Core's document (V1-03, from `design-crdt`): the one place a device's update is accepted,
//!   validated and turned into the diff the Core stores and relays; a refusal poisons it and the owner rebuilds it.
//!
//! SECURITY MODEL: both owners take remote bytes only through `gate` (its module docs list every layer and why).
//! The Core additionally validates every node an update touched with the model crate, caps move clocks and the node
//! and token budgets (`Replica::verify`); clients apply what the Core accepted, in the Core's order.

use std::sync::{Arc, Mutex};

use design_model::limits::{MAX_DOC_BYTES, MAX_NODES, MAX_TOKENS};
use design_model::{Doc, Meta, Token};
use serde_json::Value;
use yrs::undo::{Options as UndoOptions, UndoManager};
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;
use yrs::{Any, Doc as YDoc, Map, MapRef, Origin, Out, ReadTxn, StateVector, Transact};

mod decode;
mod edit;
mod gate;
pub mod guard;
#[cfg(test)]
mod followup_tests;
#[cfg(test)]
mod layered_tests;
mod layout;
mod ops;
mod presence;
mod read;
mod replica;
#[cfg(test)]
mod reset_tests;
mod trial;

pub use design_model::{Doc as Model, NodeType};
pub use edit::Editor;
pub use gate::Refused;
pub use ops::{MAX_GESTURE_OPS, MAX_OPS, MAX_OPS_BYTES, Op, parse_ops};
pub use presence::{ClockFn, MAX_PEERS, MAX_PRESENCE_BYTES, PEER_TTL_MS, Presence};
pub use replica::{MAX_PEER_UPDATE_BYTES, Replica};

/// What the engine accepts from the Core: one relayed update or a full state (the document cap plus framing room).
/// What a device may SEND is smaller, `MAX_PEER_UPDATE_BYTES`: the Core refuses more, so the engine's outbox and its
/// batches stay under that.
pub const MAX_UPDATE_BYTES: usize = MAX_DOC_BYTES + (1 << 20);
/// `Any` nesting anywhere in an update and in what is read back (the validators accept far less). One value for every
/// layer: `design-crdt` scanned to 24 and read props to 16, the engine decoded to 32; V1-05 keeps the strictest.
pub const MAX_JSON_DEPTH: usize = 16;

/// Every replica, trial copy and peer counts text in UTF-16 units, like Yjs and every JS client (the yrs default counts
/// UTF-8 bytes, and `read` compares a text's length with its strings).
pub(crate) fn new_ydoc() -> YDoc {
    YDoc::with_options(yrs::Options {
        offset_kind: yrs::OffsetKind::Utf16,
        ..yrs::Options::default()
    })
}

const LOCAL: &str = "local";
const REMOTE: &str = "remote";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    /// Bytes that do not decode, or yrs refused them.
    Malformed(String),
    /// An op the validators refused; nothing was written.
    Refused(String),
    /// yrs failed on a remote update; the replica was replaced by a fresh one holding only the unsent local edits.
    /// Resync from the Core (send the state vector, apply the full diff).
    Reset,
    /// `MAX_RESETS` resets within `RESET_WINDOW_MS`: remote updates are no longer applied (no resync loop). Local
    /// edits still work and still go out; close the design and open it again.
    Halted,
    /// No thread could be started for the update: nothing changed, retry later (not a reset).
    Busy,
}

/// The reset breaker: this many resets within the window halts remote updates.
pub const MAX_RESETS: usize = 3;
pub const RESET_WINDOW_MS: u64 = 60_000;

pub struct Live {
    presence: Presence,
    nodes: MapRef,
    meta: MapRef,
    tokens: MapRef,
    undo: UndoManager<()>,
    outbox: Arc<Mutex<Vec<Vec<u8>>>>,
    /// Every remote update passes it (`gate`); it sees every committed one.
    gate: gate::Gate,
    /// When the last resets happened (ms, the presence clock), for the breaker.
    resets: Vec<u64>,
    halted: bool,
}

impl Default for Live {
    fn default() -> Self {
        Self::new()
    }
}

impl Live {
    pub fn new() -> Live {
        Live::with_clock(std::sync::Arc::new(presence::system_clock))
    }

    /// `clock` = milliseconds for presence expiry and the reset breaker (tests pass a fake one).
    pub fn with_clock(clock: presence::ClockFn) -> Live {
        Live::build(clock, Arc::default())
    }

    fn build(clock: presence::ClockFn, outbox: Arc<Mutex<Vec<Vec<u8>>>>) -> Live {
        let doc = new_ydoc();
        let nodes = doc.get_or_insert_map("nodes");
        let meta = doc.get_or_insert_map("meta");
        let tokens = doc.get_or_insert_map("tokens");
        let ob = outbox.clone();
        let remote = Origin::from(REMOTE);
        // Everything this replica did (edits, undo, redo) goes out; what came in does not echo back. Everything
        // committed, either way, is placed in the gate's shadow layout.
        let gate = gate::Gate::watch(&doc, move |txn, update| {
            if txn.origin() != Some(&remote)
                && let Ok(mut o) = ob.lock()
            {
                o.push(update.to_vec());
            }
        });
        let mut undo = UndoManager::with_options(UndoOptions::default());
        undo.expand_scope(&doc, &nodes);
        undo.expand_scope(&doc, &meta);
        undo.include_origin(Origin::from(LOCAL));
        Live {
            presence: Presence::new(doc, clock),
            nodes,
            meta,
            tokens,
            undo,
            outbox,
            gate,
            resets: vec![],
            halted: false,
        }
    }

    fn doc(&self) -> &YDoc {
        self.presence.doc()
    }

    /// A remote update (v1) from the Core relay, through every layer of `gate`. Not undoable here, never echoed to
    /// the outbox. A refusal leaves the replica as it was (`Malformed`; the text says "resync" when the update only
    /// builds on state this replica lacks), except `Reset`.
    pub fn apply_remote(&mut self, update: &[u8]) -> Result<(), Error> {
        if update.len() > MAX_UPDATE_BYTES {
            return Err(Error::TooLarge);
        }
        if self.halted {
            return Err(Error::Halted);
        }
        let doc = self.doc().clone();
        let u = self.gate.admit(&doc, update).map_err(|r| match r {
            Refused::TooLarge => Error::TooLarge,
            r => Error::Malformed(r.to_string()),
        })?;
        // the real apply on a big stack too, so nothing yrs does with remote content recurses on ours. Pending is
        // tolerated here: `no_gap` keeps remote bytes out of it, and after a reset the engine's own unsent edits sit
        // pending until the resync (`reset`).
        let r = match trial::big_stack(|| gate::integrate(&doc, u, REMOTE)) {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(gate::Failed::Refused(m))) => Err(Error::Malformed(m)),
            Err(Refused::Busy) => Err(Error::Busy), // the thread never started: nothing was integrated
            Ok(Err(gate::Failed::Panicked)) | Err(_) => Err(Error::Reset),
        };
        if r.is_err() {
            self.gate.drop_trial(); // it holds the update; rebuild from the replica next time
        }
        if r == Err(Error::Reset) {
            self.reset();
        }
        r
    }

    pub fn state_vector(&self) -> Vec<u8> {
        self.doc().transact().state_vector().encode_v1()
    }

    /// Everything this replica has that a peer at state vector `sv` lacks (empty `sv` = the full state).
    pub fn diff(&mut self, sv: &[u8]) -> Result<Vec<u8>, Error> {
        let sv = if sv.is_empty() {
            StateVector::default()
        } else {
            decode::caught(|| StateVector::decode_v1(sv))?
        };
        // yrs re-decodes pending (not yet integrable) remote updates here and panics on some it accepted earlier
        self.recover(|l| Ok(l.doc().transact().encode_state_as_update_v1(&sv)))
    }

    /// Replace a replica yrs left inconsistent by a fresh one. The unsent local edits survive: the fresh replica
    /// keeps the same outbox (they still go out) and holds them as its own content (pending until the resync brings
    /// what they build on). The undo history and presence peers do not survive. The old document is leaked, not
    /// dropped: a panic may have left it half-integrated, and dropping such a yrs store is a known use-after-free;
    /// the breaker bounds the leak to `MAX_RESETS` documents per window.
    pub(crate) fn reset(&mut self) {
        let clock = self.presence.clock();
        let now = clock();
        let mut resets = std::mem::take(&mut self.resets);
        resets.retain(|t| now.saturating_sub(*t) < RESET_WINDOW_MS);
        resets.push(now);
        let queued = self
            .outbox
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let mut fresh = Live::build(clock, self.outbox.clone());
        for q in &queued {
            if let Ok((u, _)) = decode::update(q) {
                let _ = gate::integrate(fresh.doc(), u, REMOTE);
            }
        }
        fresh.halted = self.halted || resets.len() >= MAX_RESETS;
        fresh.resets = resets;
        std::mem::forget(std::mem::replace(self, fresh));
    }

    /// Run `f`; a panic inside yrs resets the replica (`Error::Reset`) instead of reaching the caller.
    pub(crate) fn recover<T>(
        &mut self,
        f: impl FnOnce(&mut Live) -> Result<T, Error>,
    ) -> Result<T, Error> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(self))) {
            Ok(r) => r,
            Err(_) => {
                self.reset();
                Err(Error::Reset)
            }
        }
    }

    /// Local updates not yet sent, merged into one update of at most `MAX_PEER_UPDATE_BYTES` (what the Core takes;
    /// empty when there are none). More pending than that: the oldest that fit, the rest wait for the next call.
    /// `take` = drain what is returned.
    pub fn outbox(&self, take: bool) -> Vec<u8> {
        self.outbox_under(take, MAX_PEER_UPDATE_BYTES)
    }

    pub(crate) fn outbox_under(&self, take: bool, cap: usize) -> Vec<u8> {
        let mut o = self.outbox.lock().unwrap_or_else(|e| e.into_inner());
        if o.is_empty() {
            return vec![];
        }
        // the oldest updates whose sizes add up to `cap`. One over the cap on its own never goes out (the relay
        // refuses it): it stays queued, with an error, instead of being retried forever by the caller.
        let (mut n, mut sum) = (0, 0);
        while n < o.len() && sum + o[n].len() <= cap {
            sum += o[n].len();
            n += 1;
        }
        if n == 0 {
            eprintln!("design-doc: the oldest unsent update is over {cap} bytes and is not sent");
            return vec![];
        }
        match yrs::merge_updates_v1(o[..n].iter().map(Vec::as_slice)) {
            Ok(merged) if n == 1 || merged.len() <= cap => {
                if take {
                    o.drain(..n);
                }
                merged
            }
            // never send bytes that are not one update: fall back to the oldest one, the rest stay queued
            _ if take => o.remove(0),
            _ => o[0].clone(),
        }
    }

    /// `false` also when yrs failed and the replica was reset (the next sync call reports it).
    pub fn undo(&mut self) -> bool {
        self.undo_checked().unwrap_or(false)
    }

    pub fn redo(&mut self) -> bool {
        self.redo_checked().unwrap_or(false)
    }

    /// Like `undo`, but says why nothing happened: `TooLarge` when the undo would make an update over
    /// `MAX_PEER_UPDATE_BYTES` (it is reverted, the document is as it was).
    pub fn undo_checked(&mut self) -> Result<bool, Error> {
        self.step(false, MAX_PEER_UPDATE_BYTES)
    }

    pub fn redo_checked(&mut self) -> Result<bool, Error> {
        self.step(true, MAX_PEER_UPDATE_BYTES)
    }

    /// One undo or redo, held to the same size budget as an edit (`commit`): what it wrote must fit `cap`, else the
    /// opposite step puts the content back and `TooLarge` is returned. Both steps went out as local updates (the
    /// peers' clocks must stay gapless), so the outbox tail is replaced by one small diff from the state before.
    pub(crate) fn step(&mut self, redo: bool, cap: usize) -> Result<bool, Error> {
        self.recover(|l| {
            let sv = l.doc().transact().state_vector();
            let queued = |l: &Live| l.outbox.lock().unwrap_or_else(|e| e.into_inner()).len();
            let before = queued(l);
            let did = if redo {
                l.undo.redo_blocking()
            } else {
                l.undo.undo_blocking()
            };
            let big = l.outbox.lock().unwrap_or_else(|e| e.into_inner())[before..]
                .iter()
                .any(|u| u.len() > cap);
            if !did || !big {
                return Ok(did);
            }
            if redo {
                l.undo.undo_blocking();
            } else {
                l.undo.redo_blocking();
            }
            let net = l.doc().transact().encode_state_as_update_v1(&sv);
            let mut o = l.outbox.lock().unwrap_or_else(|e| e.into_inner());
            o.truncate(before);
            o.push(net);
            Err(Error::TooLarge)
        })
    }

    #[cfg(test)]
    pub(crate) fn state_vector_struct(&self) -> StateVector {
        self.doc().transact().state_vector()
    }

    /// Committed updates the layout shadow could not place since this replica was made (0 in a healthy replica).
    pub fn shadow_misses(&self) -> u64 {
        self.gate.misses()
    }

    pub fn presence(&mut self) -> &mut Presence {
        &mut self.presence
    }

    /// The document as the model reads it. A node that does not read strictly (`read::node_out`), a malformed token
    /// and malformed meta fields are left out.
    pub fn read(&self) -> Doc {
        let txn = self.doc().transact();
        let mut doc = Doc::default();
        for (id, v) in self.nodes.iter(&txn).take(MAX_NODES) {
            if let Ok(n) = read::node_out(&txn, v) {
                doc.nodes.insert(id.to_string(), n);
            }
        }
        doc.meta = Meta {
            system: match self.meta.get(&txn, "system") {
                Some(Out::Any(Any::String(s))) => Some(s.to_string()),
                _ => None,
            },
            version: match self.meta.get(&txn, "version") {
                Some(Out::Any(a)) => read::clock(&a)
                    .ok()
                    .and_then(|v| u32::try_from(v).ok())
                    .unwrap_or(0),
                _ => 0,
            },
        };
        for (name, v) in self.tokens.iter(&txn).take(MAX_TOKENS) {
            let Out::Any(a) = v else { continue };
            if let Some(t) = read::json(&a, 0)
                .ok()
                .and_then(|j| serde_json::from_value::<Token>(j).ok())
            {
                doc.tokens.insert(name.to_string(), t);
            }
        }
        doc
    }
}

/// JSON -> `Any` (the value already passed the validators, so its depth is small).
fn json_any(v: &Value) -> Any {
    serde_json::from_value(v.clone()).unwrap_or(Any::Null)
}
