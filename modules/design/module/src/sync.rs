//! The document actor: one live `design_crdt::Replica` per open design, shared by every socket and, later, AI ops.
//!
//! SECURITY MODEL (read with `design_crdt`'s)
//! - Reaching a doc takes a signed device request with the module scope (`admin`): the route is not in `ROUTE_SCOPES`,
//!   so it keeps the deny-by-default module scope. Revocation and a scope change cut the socket within the backstop
//!   (`ws.rs`). Every peer may write: there is no read-only socket in this story.
//! - Nothing a peer sends is trusted. An update goes through `Replica::apply_remote` (size, decode, schema, clock and
//!   node budgets, via the model crate) BEFORE it is stored or shown to anyone. A refusal is a protocol violation: the
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use design_crdt::{Refused, Replica};
use design_model::limits::MAX_DOC_BYTES;
use sqlx::{Row, SqlitePool};
use tokio::sync::{Mutex, broadcast};

pub const UPDATE_RATE: f64 = 50.0;
pub const BYTE_RATE: f64 = 4.0 * 1024.0 * 1024.0;
pub const PRESENCE_RATE: f64 = 20.0;
const MAX_VERSIONS: i64 = 200;
const AUTO_VERSION_SECS: i64 = 600;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub idle: Duration,
    pub compact_updates: i64,
    pub compact_bytes: usize,
    pub update_rate: f64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(600),
            compact_updates: 500,
            compact_bytes: 1 << 20,
            update_rate: UPDATE_RATE,
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

#[derive(Debug)]
pub enum Refusal {
    /// A protocol violation by the peer.
    Violation(Refused),
    DocFull,
    Archived,
    /// Storage failed; the peer did nothing wrong.
    Store,
}

struct State {
    replica: Replica,
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
    peers: AtomicUsize,
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
            peers: AtomicUsize::new(0),
            presence: StdMutex::default(),
        }))
    }

    /// Subscribe and read the backlog under the lock, so nothing falls between the two.
    pub async fn join(&self, after: Option<i64>) -> Result<Joined, sqlx::Error> {
        let st = self.state.lock().await;
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
        let diff = match st.replica.apply_remote(bytes) {
            Ok(None) => return Ok(st.last_seq),
            Ok(Some(d)) => d,
            Err(e) => {
                self.rebuild(&mut st).await;
                return Err(Refusal::Violation(e));
            }
        };
        if st.snapshot_bytes + st.log_bytes + diff.len() > MAX_DOC_BYTES {
            self.rebuild(&mut st).await;
            return Err(Refusal::DocFull);
        }
        let seq = st.last_seq + 1;
        match self.persist(seq, origin, &diff).await {
            Ok(true) => {}
            Ok(false) => {
                self.rebuild(&mut st).await;
                return Err(Refusal::Archived);
            }
            Err(e) => {
                tracing::error!(error = %e, doc = %self.id, "design update not stored");
                self.rebuild(&mut st).await;
                return Err(Refusal::Store);
            }
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

    /// `false`: the doc is not active any more (nothing was written).
    async fn persist(&self, seq: i64, origin: &str, diff: &[u8]) -> Result<bool, sqlx::Error> {
        let mut tx = ainkrad_core_server::store::begin_write(&self.pool).await?;
        let touched = sqlx::query(
            "UPDATE design_docs SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE id = ? AND state = 'active'",
        )
        .bind(&self.id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if touched == 0 {
            return Ok(false);
        }
        sqlx::query("INSERT INTO design_updates (doc, seq, data, origin) VALUES (?, ?, ?, ?)")
            .bind(&self.id)
            .bind(seq)
            .bind(diff)
            .bind(origin)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
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
        .bind(format!("-{AUTO_VERSION_SECS} seconds"))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM design_versions WHERE id IN (SELECT id FROM design_versions WHERE doc = ? \
             AND kind = 'auto' ORDER BY created_at LIMIT max(0, (SELECT count(*) FROM design_versions \
             WHERE doc = ?) - ?))",
        )
        .bind(&self.id)
        .bind(&self.id)
        .bind(MAX_VERSIONS)
        .execute(&mut *tx)
        .await?;
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
            Ok(fresh) => *st = fresh,
            // Cannot trust the replica and cannot rebuild it: every later update is refused as `Poisoned`
            // (`apply_remote` stays poisoned) until the actor is unloaded.
            Err(e) => {
                tracing::error!(error = %e, doc = %self.id, "design replica not rebuilt");
                st.replica.poison();
            }
        }
    }

    pub fn set_presence(&self, conn: u64, json: Arc<String>) {
        self.presence
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(conn, json.clone());
        let _ = self.tx.send(Out::Presence { from: conn, json });
    }
}

/// A socket's hold on a doc: counts it as a peer, and on drop removes its presence and starts the unload timer.
pub struct Lease {
    pub actor: Arc<Actor>,
    pub conn: u64,
    reg: Arc<Registry>,
}

impl Lease {
    /// Updates per second one socket may send (burst twice that).
    pub fn rate(&self) -> f64 {
        self.reg.limits.update_rate
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.actor
            .presence
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.conn);
        let _ = self.actor.tx.send(Out::Left { conn: self.conn });
        if self.actor.peers.fetch_sub(1, Ordering::AcqRel) == 1 {
            let (reg, actor) = (self.reg.clone(), self.actor.clone());
            tokio::spawn(async move {
                tokio::time::sleep(reg.limits.idle).await;
                let mut docs = reg.docs.lock().await;
                // Under the registry lock `open` counts a new peer in, so a doc someone just joined is kept.
                if actor.peers.load(Ordering::Acquire) == 0
                    && docs.get(&actor.id).is_some_and(|a| Arc::ptr_eq(a, &actor))
                {
                    docs.remove(&actor.id);
                }
            });
        }
    }
}

#[derive(Default)]
pub struct Registry {
    docs: Mutex<HashMap<String, Arc<Actor>>>,
    conns: std::sync::atomic::AtomicU64,
    pub limits: Limits,
}

impl Registry {
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    /// The doc's actor, loaded on first use. ponytail: one lock for the map, held while a doc loads; per-doc
    /// loading if opening many big docs at once ever shows up.
    pub async fn open(self: &Arc<Self>, pool: &SqlitePool, id: &str) -> Result<Lease, sqlx::Error> {
        let mut docs = self.docs.lock().await;
        let actor = match docs.get(id) {
            Some(a) => a.clone(),
            None => {
                let a = Actor::open(pool.clone(), id, self.limits).await?;
                docs.insert(id.to_owned(), a.clone());
                a
            }
        };
        actor.peers.fetch_add(1, Ordering::AcqRel);
        Ok(Lease {
            actor,
            conn: self.conns.fetch_add(1, Ordering::Relaxed),
            reg: self.clone(),
        })
    }

    pub async fn loaded(&self) -> usize {
        self.docs.lock().await.len()
    }
}
