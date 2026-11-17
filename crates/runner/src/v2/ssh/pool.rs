//! The connection pool of the `ssh` driver: what a connection is keyed by, who holds it, and the
//! sweeper that closes it when idle.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use ainkrad_proto::v2::SshHop;
use russh::client::Handle;
use russh::keys::{HashAlg, PrivateKey};

use super::{POOL_MAX, SshDriver, Verify};

/// A verified, authenticated chain. `_jumps` stay open for as long as `handle` runs over them.
pub(super) struct Conn {
    pub(super) handle: Handle<Verify>,
    pub(super) _jumps: Vec<Handle<Verify>>,
    /// The host key each hop presented, in chain order: re-checked against the pins on every use.
    pub(super) host_keys: Vec<String>,
    pub(super) used: Mutex<Instant>,
    /// Ops running on it: the sweeper never closes it under one.
    pub(super) busy: AtomicUsize,
}

/// A pooled connection held by one op (counted busy while held).
pub(super) struct InUse(pub(super) Arc<Conn>);

impl InUse {
    /// Call with the pool lock held, so the sweeper cannot close it in between.
    pub(super) fn new(conn: Arc<Conn>) -> Self {
        conn.busy.fetch_add(1, SeqCst);
        Self(conn)
    }
}

impl Drop for InUse {
    fn drop(&mut self) {
        *self.0.used.lock().unwrap() = Instant::now();
        self.0.busy.fetch_sub(1, SeqCst);
    }
}

/// What a connection is for: the chain's addresses and the fingerprint of every hop's key.
#[derive(Clone, PartialEq, Eq, Hash)]
pub(super) struct PoolKey {
    chain: Vec<(String, String, u16)>,
    keys: Vec<String>,
}

pub(super) type Pool = Arc<Mutex<HashMap<PoolKey, Arc<Conn>>>>;

pub(super) fn pool_key(chain: &[&SshHop], keys: &[PrivateKey]) -> PoolKey {
    PoolKey {
        chain: (chain.iter())
            .map(|h| (h.user.clone(), h.host.clone(), h.port))
            .collect(),
        keys: keys.iter().map(fingerprint).collect(),
    }
}

fn fingerprint(key: &PrivateKey) -> String {
    key.public_key().fingerprint(HashAlg::Sha256).to_string()
}

/// Every hop presented a key, and each is still pinned.
pub(super) fn pins_hold(presented: &[String], chain: &[&SshHop]) -> bool {
    presented.len() == chain.len()
        && (presented.iter().zip(chain)).all(|(k, h)| h.pinned_keys.contains(k))
}

impl SshDriver {
    pub(super) fn pooled(&self, name: &PoolKey, chain: &[&SshHop]) -> Option<InUse> {
        let mut pool = self.pool.lock().unwrap();
        let idle = self.idle;
        pool.retain(|_, c| {
            !c.handle.is_closed()
                && (c.busy.load(SeqCst) > 0 || c.used.lock().unwrap().elapsed() < idle)
        });
        let conn = pool.get(name)?;
        // Every hop's pins must still list the key it presented when the chain was dialled.
        if !pins_hold(&conn.host_keys, chain) {
            pool.remove(name);
            return None;
        }
        Some(InUse::new(Arc::clone(conn)))
    }

    pub(super) fn pool_put(&self, name: PoolKey, conn: Arc<Conn>) -> InUse {
        let mut pool = self.pool.lock().unwrap();
        if pool.len() >= POOL_MAX
            && let Some(oldest) = pool
                .iter()
                .min_by_key(|(_, c)| *c.used.lock().unwrap())
                .map(|(k, _)| k.clone())
        {
            pool.remove(&oldest);
        }
        let held = InUse::new(Arc::clone(&conn));
        let sweeper = sweep(
            Arc::downgrade(&self.pool),
            name.clone(),
            Arc::downgrade(&conn),
            self.idle,
        );
        pool.insert(name, conn);
        tokio::spawn(sweeper);
        held
    }
}

/// Closes `conn` (by dropping it from the pool) once it has been idle for `idle` with no op on it.
async fn sweep(
    pool: Weak<Mutex<HashMap<PoolKey, Arc<Conn>>>>,
    name: PoolKey,
    conn: Weak<Conn>,
    idle: Duration,
) {
    loop {
        let Some(c) = conn.upgrade() else { return };
        let left = match c.busy.load(SeqCst) {
            0 => idle.saturating_sub(c.used.lock().unwrap().elapsed()),
            _ => idle,
        };
        drop(c);
        if !left.is_zero() {
            tokio::time::sleep(left).await;
            continue;
        }
        let (Some(pool), Some(c)) = (pool.upgrade(), conn.upgrade()) else {
            return;
        };
        let mut pool = pool.lock().unwrap();
        if !pool.get(&name).is_some_and(|p| Arc::ptr_eq(p, &c)) {
            return;
        }
        if c.busy.load(SeqCst) == 0 {
            pool.remove(&name);
            return;
        }
    }
}
