//! The document actor: one live `design_doc::Replica` per open design, shared by every socket and, later, AI ops.
//!
//! SECURITY MODEL (read with `design_doc`'s: its `gate` and `replica` modules)
//! - Reaching a doc takes a signed device request with the module scope (`admin`): the route is not in `ROUTE_SCOPES`,
//!   so it keeps the deny-by-default module scope. Revocation and a scope change cut the socket within the backstop
//!   (`ws.rs`). Every peer may write: there is no read-only socket in this story.
//! - Nothing a peer sends is trusted. An update goes through `Replica::apply_remote`, the same gate the App engine runs
//!   (raw-byte scan, dependencies, the T1 layout, guarded decode, a trial copy; then schema, clock and node budgets via
//!   the model crate), BEFORE it is stored or shown to anyone. A refusal is a protocol violation: the
//!   socket is closed with a code and the replica is rebuilt from storage, so no half-applied update survives.
//! - Persist, then broadcast: the diff that was integrated is written to `design_updates` in a write transaction, and
//!   only after the commit is it sent to the other peers and acknowledged to the sender. A crash loses nothing that
//!   was acknowledged. The stored and broadcast bytes are the DIFF the replica produced, never the peer's own bytes.
//! - The log is bounded: compaction at `compact_updates` updates or `compact_bytes` bytes folds it into
//!   `design_docs.snapshot`; the whole document (snapshot + log) is capped at the model's `MAX_DOC_BYTES`.
//! - Presence is relayed, stamped by the Core with the sender's identity (a peer cannot speak as another), rate-capped,
//!   never stored.
//! - One actor per doc, one lock: updates are applied and persisted one at a time, in the order the lock is taken.
//!   The lock is held across the database write on purpose (ordering and rollback beat parallelism here).
//! - Known limits: an archived doc refuses writes at the next update, it does not close idle sockets; unloading an idle
//!   doc is a timer after the last peer leaves.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use design_doc::{Live, Refused, Replica};
use design_model::limits::MAX_DOC_BYTES;
use sqlx::{Row, SqlitePool};
use tokio::sync::{Mutex, broadcast};

/// The `from` of an update the Core made itself (no socket has this connection id, so every socket gets it).
pub const CORE: u64 = u64::MAX;
pub const UPDATE_RATE: f64 = 50.0;
pub const BYTE_RATE: f64 = 4.0 * 1024.0 * 1024.0;
pub const PRESENCE_RATE: f64 = 20.0;
pub(crate) const MAX_VERSIONS: i64 = 200;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub idle: Duration,
    pub compact_updates: i64,
    pub compact_bytes: usize,
    pub update_rate: f64,
    /// Sockets one device may hold open at once.
    pub max_per_device: usize,
    /// Documents loaded at once (idle ones are evicted first; past it a new one is refused).
    pub max_docs: usize,
    /// An `auto` version at most this often per doc.
    pub auto_secs: i64,
    /// All `auto` versions of a doc together stay under this (full snapshots are outside the doc budget otherwise);
    /// the newest is always kept.
    pub auto_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(600),
            compact_updates: 500,
            compact_bytes: 1 << 20,
            update_rate: UPDATE_RATE,
            max_per_device: 8,
            max_docs: 64,
            auto_secs: 600,
            auto_bytes: MAX_DOC_BYTES,
        }
    }
}

/// What goes to every socket of a doc.
#[derive(Clone)]
pub enum Out {
    Update {
        seq: i64,
        from: u64,
        bytes: Arc<Vec<u8>>,
    },
    Presence {
        from: u64,
        json: Arc<String>,
    },
    Left {
        conn: u64,
    },
}

/// What `persist` did.
enum Stored {
    Yes,
    Gone(bool),
}

#[derive(Debug)]
pub enum Refusal {
    /// A protocol violation by the peer.
    Violation(Refused),
    DocFull,
    /// The update builds on state the document lacks: the client resyncs (a fresh connection, snapshot first).
    Resync,
    Archived,
    /// A person took the design over between the check in `edit` and the write (#327): an AI origin is refused.
    Paused,
    /// Storage failed; the peer did nothing wrong.
    Store,
}

/// Why a Core-side edit did not happen.
#[derive(Debug)]
pub enum EditError {
    /// The edit itself is not valid (a fixed sentence naming the op); nothing was written.
    Refused(String),
    TooLarge,
    /// A person took over: the AI may not write until they resume.
    Paused,
    Archived,
    DocFull,
    Store,
}

// `Live` sits in `State` behind the actor's lock, held across awaits: it must be `Send` (yrs `sync` feature; no `Rc`).
const _: fn() = || {
    fn send<T: Send>() {}
    send::<Live>();
    send::<Replica>();
};

struct State {
    replica: Replica,
    /// A `design_doc` replica kept level with `replica`, built on the first Core-side edit (`edit`): the typed ops
    /// run on it, its update goes through `replica`'s gate like any peer's. `None` = build it again on demand.
    live: Option<Live>,
    last_seq: i64,
    snapshot_seq: i64,
    log_updates: i64,
    log_bytes: usize,
    snapshot_bytes: usize,
}

pub struct Actor {
    pub id: String,
    pool: SqlitePool,
    limits: Limits,
    state: Mutex<State>,
    tx: broadcast::Sender<Out>,
    presence: StdMutex<HashMap<u64, Arc<String>>>,
}

/// What a joining socket is sent first, then it follows `rx`.
pub struct Joined {
    pub rx: broadcast::Receiver<Out>,
    pub head: i64,
    pub backlog: Backlog,
    pub presence: Vec<Arc<String>>,
}

pub enum Backlog {
    /// The log after the client's cursor, oldest first.
    Updates(Vec<(i64, Vec<u8>)>),
    /// Everything (no cursor, or it is older than the compacted log, or from the future).
    Snapshot(Vec<u8>),
}

async fn load(pool: &SqlitePool, id: &str) -> Result<State, sqlx::Error> {
    let r = sqlx::query("SELECT snapshot, snapshot_seq FROM design_docs WHERE id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    let snap: Option<Vec<u8>> = r.try_get("snapshot")?;
    let snapshot_seq: i64 = r.try_get("snapshot_seq")?;
    let rows =
        sqlx::query("SELECT seq, data FROM design_updates WHERE doc = ? AND seq > ? ORDER BY seq")
            .bind(id)
            .bind(snapshot_seq)
            .fetch_all(pool)
            .await?;
    let logs: Vec<(i64, Vec<u8>)> = rows
        .iter()
        .map(|r| Ok((r.try_get("seq")?, r.try_get("data")?)))
        .collect::<Result<_, sqlx::Error>>()?;
    let parts = snap
        .iter()
        .map(Vec::as_slice)
        .chain(logs.iter().map(|(_, d)| d.as_slice()));
    let replica = Replica::from_stored(parts).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    Ok(State {
        replica,
        live: None,
        last_seq: logs.last().map_or(snapshot_seq, |l| l.0),
        snapshot_seq,
        log_updates: logs.len() as i64,
        log_bytes: logs.iter().map(|l| l.1.len()).sum(),
        snapshot_bytes: snap.map_or(0, |s| s.len()),
    })
}

impl Actor {
    async fn open(pool: SqlitePool, id: &str, limits: Limits) -> Result<Arc<Actor>, sqlx::Error> {
        let state = load(&pool, id).await?;
        Ok(Arc::new(Actor {
            id: id.to_owned(),
            pool,
            limits,
            state: Mutex::new(state),
            tx: broadcast::channel(256).0,
            presence: StdMutex::default(),
        }))
    }

    /// Subscribe and read the backlog under the lock, so nothing falls between the two.
    pub async fn join(&self, after: Option<i64>) -> Result<Joined, sqlx::Error> {
        let mut st = self.state.lock().await;
        // Never serve a replica that may hold unverified content: rebuild it from storage or refuse the join.
        if st.replica.is_poisoned() {
            self.rebuild(&mut st).await;
            if st.replica.is_poisoned() {
                return Err(sqlx::Error::Protocol("replica unavailable".into()));
            }
        }
        let rx = self.tx.subscribe();
        let backlog = match after {
            Some(n) if n >= st.snapshot_seq && n <= st.last_seq => {
                let rows = sqlx::query(
                    "SELECT seq, data FROM design_updates WHERE doc = ? AND seq > ? ORDER BY seq",
                )
                .bind(&self.id)
                .bind(n)
                .fetch_all(&self.pool)
                .await?;
                Backlog::Updates(
                    rows.iter()
                        .map(|r| Ok((r.try_get("seq")?, r.try_get("data")?)))
                        .collect::<Result<_, sqlx::Error>>()?,
                )
            }
            _ => Backlog::Snapshot(st.replica.state()),
        };
        let presence = self
            .presence
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        Ok(Joined {
            rx,
            head: st.last_seq,
            backlog,
            presence,
        })
    }

    /// The gate. `Ok(seq)` is the sequence number the update is stored under (or the current head when it added
    /// nothing); it is only returned once the update is committed and has been sent to the other peers.
    pub async fn submit(&self, conn: u64, origin: &str, bytes: &[u8]) -> Result<i64, Refusal> {
        let mut st = self.state.lock().await;
        self.submit_locked(&mut st, conn, origin, bytes).await
    }

    async fn submit_locked(
        &self,
        st: &mut State,
        conn: u64,
        origin: &str,
        bytes: &[u8],
    ) -> Result<i64, Refusal> {
        if st.replica.is_poisoned() {
            self.rebuild(st).await;
            if st.replica.is_poisoned() {
                return Err(Refusal::Store);
            }
        }
        let diff = match st.replica.apply_remote(bytes) {
            Ok(None) => return Ok(st.last_seq),
            Ok(Some(d)) => d,
            // Refused before yrs integrated anything: the replica is untouched, nothing was stored.
            Err(Refused::Pending) => return Err(Refusal::Resync),
            // the replica could not be rebuilt earlier: not the peer's doing
            Err(Refused::Poisoned | Refused::Busy) => return Err(Refusal::Store),
            Err(e) => {
                // a refusal before integration leaves the replica as it was; only a poisoned one is rebuilt
                if st.replica.is_poisoned() {
                    self.rebuild(st).await;
                }
                return Err(Refusal::Violation(e));
            }
        };
        if st.snapshot_bytes + st.log_bytes + diff.len() > MAX_DOC_BYTES {
            self.rebuild(st).await;
            return Err(Refusal::DocFull);
        }
        let seq = st.last_seq + 1;
        match self.persist(seq, origin, &diff).await {
            Ok(Stored::Yes) => {}
            Ok(Stored::Gone(paused)) => {
                self.rebuild(st).await;
                return Err(if paused {
                    Refusal::Paused
                } else {
                    Refusal::Archived
                });
            }
            Err(e) => {
                tracing::error!(error = %e, doc = %self.id, "design update not stored");
                self.rebuild(st).await;
                return Err(Refusal::Store);
            }
        }
        // keep the typed-ops replica level with what was stored (an edit's own update is already in it)
        if conn != CORE
            && let Some(l) = st.live.as_mut()
            && l.apply_remote(&diff).is_err()
        {
            st.live = None;
        }
        st.last_seq = seq;
        st.log_updates += 1;
        st.log_bytes += diff.len();
        // No receiver is fine: nobody else is connected.
        let _ = self.tx.send(Out::Update {
            seq,
            from: conn,
            bytes: Arc::new(diff),
        });
        if (st.log_updates >= self.limits.compact_updates
            || st.log_bytes >= self.limits.compact_bytes)
            && let Err(e) = self.compact(&mut st).await
        {
            tracing::error!(error = %e, doc = %self.id, "design compaction failed");
        }
        Ok(seq)
    }

    /// `Gone(paused)`: nothing was written; the doc is archived, or (`paused`) a person took it over and `origin` is
    /// the AI's. The flag is checked in the same statement that touches the row, so a take-over is never raced (#327).
    async fn persist(&self, seq: i64, origin: &str, diff: &[u8]) -> Result<Stored, sqlx::Error> {
        let mut tx = ainkrad_core_server::store::begin_write(&self.pool).await?;
        let touched = sqlx::query(
            "UPDATE design_docs SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE id = ? AND state = 'active' AND (ai_paused = 0 OR ? NOT LIKE 'session:%')",
        )
        .bind(&self.id)
        .bind(origin)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if touched == 0 {
            let paused: Option<i64> = sqlx::query_scalar(
                "SELECT ai_paused FROM design_docs WHERE id = ? AND state = 'active'",
            )
            .bind(&self.id)
            .fetch_optional(&mut *tx)
            .await?;
            return Ok(Stored::Gone(paused == Some(1)));
        }
        sqlx::query("INSERT INTO design_updates (doc, seq, data, origin) VALUES (?, ?, ?, ?)")
            .bind(&self.id)
            .bind(seq)
            .bind(diff)
            .bind(origin)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Stored::Yes)
    }

    /// Fold the log into the snapshot; add an `auto` version when none is recent (T14), pruning the oldest autos
    /// past the per-doc cap. One transaction: either all of it or none.
    async fn compact(&self, st: &mut State) -> Result<(), sqlx::Error> {
        let snap = st.replica.state();
        let mut vid = [0u8; 8];
        getrandom::fill(&mut vid).expect("the system random source");
        let vid = format!(
            "dv_{}",
            vid.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        let mut tx = ainkrad_core_server::store::begin_write(&self.pool).await?;
        sqlx::query("UPDATE design_docs SET snapshot = ?, snapshot_seq = ? WHERE id = ?")
            .bind(&snap)
            .bind(st.last_seq)
            .bind(&self.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM design_updates WHERE doc = ? AND seq <= ?")
            .bind(&self.id)
            .bind(st.last_seq)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO design_versions (id, doc, kind, state, origin) \
             SELECT ?, ?, 'auto', ?, 'system' WHERE NOT EXISTS (SELECT 1 FROM design_versions \
             WHERE doc = ? AND kind = 'auto' AND created_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?))",
        )
        .bind(&vid)
        .bind(&self.id)
        .bind(&snap)
        .bind(&self.id)
        .bind(format!("-{} seconds", self.limits.auto_secs))
        .execute(&mut *tx)
        .await?;
        // Auto versions are full snapshots: keep the newest, then as many as fit the count and byte budgets.
        let autos: Vec<(String, i64)> = sqlx::query_as(
            "SELECT id, length(state) FROM design_versions WHERE doc = ? AND kind = 'auto' ORDER BY rowid DESC",
        )
        .bind(&self.id)
        .fetch_all(&mut *tx)
        .await?;
        let mut total = 0usize;
        for (n, (vid, len)) in autos.iter().enumerate() {
            total += *len as usize;
            if n > 0 && (n as i64 >= MAX_VERSIONS || total > self.limits.auto_bytes) {
                sqlx::query("DELETE FROM design_versions WHERE id = ?")
                    .bind(vid)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        st.snapshot_bytes = snap.len();
        st.snapshot_seq = st.last_seq;
        st.log_updates = 0;
        st.log_bytes = 0;
        Ok(())
    }

    /// Throw the replica away and rebuild it from what is stored (after a refusal or a failed write).
    async fn rebuild(&self, st: &mut State) {
        match load(&self.pool, &self.id).await {
            Ok(fresh) => {
                // the old replica may hold a hostile structure: drop it on a big-stack thread, never here
                let old = std::mem::replace(st, fresh);
                old.replica.discard();
            }
            // Cannot trust the replica and cannot rebuild it: every later update is refused as `Poisoned`
            // (`apply_remote` stays poisoned) until the actor is unloaded.
            Err(e) => {
                tracing::error!(error = %e, doc = %self.id, "design replica not rebuilt");
                st.replica.poison();
                st.live = None;
            }
        }
    }

    /// A Core-side edit (`designApply`, a restore): `f` edits a `design_doc` replica of the document; whatever it
    /// wrote goes through the same gate, persist and broadcast as a peer's update (sent as `CORE`, so every socket
    /// gets it). All or nothing: `f` is expected to refuse before it writes (`Live::apply_ops` does), and a refusal
    /// anywhere after that drops the replica, so nothing half-done is kept. An `origin` of `session:...` is the AI's:
    /// a design a person took over (`ai_paused`) refuses it.
    pub async fn edit<R>(
        &self,
        origin: &str,
        f: impl FnOnce(&mut Live) -> Result<R, EditError>,
    ) -> Result<(R, i64), EditError> {
        let mut st = self.state.lock().await;
        let row: Option<(String, i64)> =
            sqlx::query_as("SELECT state, ai_paused FROM design_docs WHERE id = ?")
                .bind(&self.id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| EditError::Store)?;
        match row {
            Some((s, _)) if s != "active" => return Err(EditError::Archived),
            Some((_, 1)) if origin.starts_with("session:") => return Err(EditError::Paused),
            Some(_) => {}
            None => return Err(EditError::Store),
        }
        if st.replica.is_poisoned() {
            self.rebuild(&mut st).await;
            if st.replica.is_poisoned() {
                return Err(EditError::Store);
            }
        }
        if st.live.is_none() {
            let mut l = Live::new();
            l.apply_remote(&st.replica.state())
                .map_err(|_| EditError::Store)?;
            st.live = Some(l);
        }
        let Some(live) = st.live.as_mut() else {
            return Err(EditError::Store);
        };
        let out = match f(live) {
            Ok(o) => o,
            Err(e) => {
                // a refusal wrote nothing; anything else may have left the replica half-way (a yrs reset)
                if !matches!(e, EditError::Refused(_) | EditError::TooLarge) {
                    st.live = None;
                }
                return Err(e);
            }
        };
        let bytes = live.outbox(true);
        // #331: the engine's outbox holds at most `MAX_PEER_UPDATE_BYTES` per send. An edit that does not fit whole
        // (the oldest update is over it, or more is queued than one update takes) is refused, never half-sent.
        if live.outbox_stuck() || !live.outbox(false).is_empty() {
            st.live = None;
            return Err(EditError::TooLarge);
        }
        if bytes.is_empty() {
            return Ok((out, st.last_seq));
        }
        match self.submit_locked(&mut st, CORE, origin, &bytes).await {
            Ok(seq) => Ok((out, seq)),
            Err(r) => {
                st.live = None;
                Err(match r {
                    Refusal::Violation(Refused::TooLarge) => EditError::TooLarge,
                    Refusal::DocFull => EditError::DocFull,
                    Refusal::Archived => EditError::Archived,
                    Refusal::Paused => EditError::Paused,
                    other => {
                        tracing::error!(?other, doc = %self.id, "design edit refused by the gate");
                        EditError::Store
                    }
                })
            }
        }
    }

    /// The document as the model reads it, and its whole state encoding, taken together under the lock.
    pub async fn view(&self) -> Result<(design_model::Doc, Vec<u8>), EditError> {
        let st = self.state.lock().await;
        let model = st.replica.read().map_err(|_| EditError::Store)?;
        Ok((model, st.replica.state()))
    }

    pub fn set_presence(&self, conn: u64, json: Arc<String>) {
        self.presence
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(conn, json.clone());
        let _ = self.tx.send(Out::Presence { from: conn, json });
    }
}

/// One document's place in the registry. `pins` counts the sockets holding it (and a load in progress); it is only
/// raised under the registry lock, so a doc is never evicted or unloaded while a socket is joining it.
struct Slot {
    cell: tokio::sync::OnceCell<Arc<Actor>>,
    pins: AtomicUsize,
}

/// A socket's hold on a doc: counts against its device, and on drop removes its presence and starts the unload timer.
pub struct Lease {
    pub actor: Arc<Actor>,
    pub conn: u64,
    reg: Arc<Registry>,
    slot: Arc<Slot>,
    device: String,
}

impl Lease {
    /// Updates per second one socket may send (burst twice that).
    pub fn rate(&self) -> f64 {
        self.reg.limits.update_rate
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.reg.release_device(&self.device);
        self.actor
            .presence
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.conn);
        let _ = self.actor.tx.send(Out::Left { conn: self.conn });
        if self.slot.pins.fetch_sub(1, Ordering::AcqRel) == 1 {
            let (reg, slot, id) = (self.reg.clone(), self.slot.clone(), self.actor.id.clone());
            tokio::spawn(async move {
                tokio::time::sleep(reg.limits.idle).await;
                let mut docs = reg.docs.lock().unwrap_or_else(|e| e.into_inner());
                // Pins only rise under this lock, so a doc someone just joined is kept.
                if slot.pins.load(Ordering::Acquire) == 0
                    && docs.get(&id).is_some_and(|s| Arc::ptr_eq(s, &slot))
                {
                    docs.remove(&id);
                }
            });
        }
    }
}

/// Why a socket could not open.
#[derive(Debug)]
pub enum OpenError {
    /// The device holds too many sockets.
    Device,
    /// Too many documents are loaded and none is idle.
    Busy,
    Store(sqlx::Error),
}

#[derive(Default)]
pub struct Registry {
    docs: StdMutex<HashMap<String, Arc<Slot>>>,
    devices: StdMutex<HashMap<String, usize>>,
    conns: AtomicU64,
    pub limits: Limits,
}

impl Registry {
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    fn release_device(&self, device: &str) {
        let mut d = self.devices.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = d.get_mut(device) {
            *n -= 1;
            if *n == 0 {
                d.remove(device);
            }
        }
    }

    /// The doc's actor, loaded on first use. The registry lock is held only to find or create the slot, never while a
    /// doc loads; two sockets opening the same doc share one load (`OnceCell`).
    pub async fn open(
        self: &Arc<Self>,
        pool: &SqlitePool,
        id: &str,
        device: &str,
    ) -> Result<Lease, OpenError> {
        {
            let mut d = self.devices.lock().unwrap_or_else(|e| e.into_inner());
            let n = d.entry(device.to_owned()).or_insert(0);
            if *n >= self.limits.max_per_device {
                return Err(OpenError::Device);
            }
            *n += 1;
        }
        let slot = {
            let mut docs = self.docs.lock().unwrap_or_else(|e| e.into_inner());
            if !docs.contains_key(id) && docs.len() >= self.limits.max_docs {
                docs.retain(|_, s| s.pins.load(Ordering::Acquire) > 0);
                if docs.len() >= self.limits.max_docs {
                    drop(docs);
                    self.release_device(device);
                    return Err(OpenError::Busy);
                }
            }
            let s = docs.entry(id.to_owned()).or_insert_with(|| {
                Arc::new(Slot {
                    cell: tokio::sync::OnceCell::new(),
                    pins: AtomicUsize::new(0),
                })
            });
            s.pins.fetch_add(1, Ordering::AcqRel);
            s.clone()
        };
        match slot
            .cell
            .get_or_try_init(|| Actor::open(pool.clone(), id, self.limits))
            .await
        {
            Ok(actor) => Ok(Lease {
                actor: actor.clone(),
                conn: self.conns.fetch_add(1, Ordering::Relaxed),
                reg: self.clone(),
                slot,
                device: device.to_owned(),
            }),
            Err(e) => {
                self.release_device(device);
                let mut docs = self.docs.lock().unwrap_or_else(|e| e.into_inner());
                if slot.pins.fetch_sub(1, Ordering::AcqRel) == 1
                    && docs.get(id).is_some_and(|s| Arc::ptr_eq(s, &slot))
                {
                    docs.remove(id);
                }
                Err(OpenError::Store(e))
            }
        }
    }

    pub async fn loaded(&self) -> usize {
        self.docs.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}
