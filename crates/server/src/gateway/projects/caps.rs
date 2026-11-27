//! In-flight caps (review fix, PR #338): places held per project and per client address, given
//! back when the exchange or the WebSocket is over.

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// In-flight counts by key; a key goes once its count is back to 0.
pub(super) type Counts<K> = Arc<Mutex<HashMap<K, usize>>>;

/// One in-flight place under a key, given back on drop.
pub(super) struct Held<K: Hash + Eq> {
    counts: Counts<K>,
    key: K,
}

impl<K: Hash + Eq> Drop for Held<K> {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(n) = counts.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

/// A place under `key`, if fewer than `cap` are held.
pub(super) fn hold<K: Hash + Eq + Clone>(
    counts: &Counts<K>,
    key: K,
    cap: usize,
) -> Option<Held<K>> {
    let mut c = counts.lock().unwrap_or_else(|p| p.into_inner());
    let n = c.entry(key.clone()).or_default();
    if *n >= cap {
        return None;
    }
    *n += 1;
    Some(Held {
        counts: Arc::clone(counts),
        key,
    })
}

/// A request's places: its project's and its client's. Kept until the exchange (or the
/// WebSocket) is over.
pub(crate) struct Permit {
    pub(super) _project: Held<i64>,
    pub(super) _client: Option<Held<IpAddr>>,
}
