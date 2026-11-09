//! Refusals counted in memory instead of audited one row each (review M4: the audit log is
//! permanent, so what an abuser can repeat must not grow it per request). A key counts within a
//! window; [`Refusals::note`] says whether a refusal is the first of its key in that window, so a
//! caller can record a transition once and only count the repeats. The table is bounded: past
//! [`KEYS_MAX`] keys the oldest window goes first. Nothing here touches the database.

use std::collections::HashMap;
use std::sync::Mutex;

/// Keys tracked at most.
pub const KEYS_MAX: usize = 4096;
/// How long a key's count runs before it starts again.
pub const WINDOW: i64 = 600;

#[derive(Debug, Clone, Copy)]
struct Count {
    n: u64,
    start: i64,
}

#[derive(Default)]
pub struct Refusals(Mutex<HashMap<String, Count>>);

impl Refusals {
    /// Counts one refusal under `key`; `true` when it is the first of its window.
    pub fn note(&self, key: &str, now: i64) -> bool {
        let mut all = self.0.lock().unwrap();
        if let Some(c) = all.get_mut(key) {
            if now - c.start < WINDOW {
                c.n += 1;
                return false;
            }
            *c = Count { n: 1, start: now };
            return true;
        }
        if all.len() >= KEYS_MAX {
            // ponytail: a linear scan, only when full; an ordered index if that ever shows.
            let oldest = all
                .iter()
                .min_by_key(|(_, c)| c.start)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                all.remove(&k);
            }
        }
        all.insert(key.to_owned(), Count { n: 1, start: now });
        true
    }

    /// How many refusals `key` has in its current window.
    pub fn count(&self, key: &str) -> u64 {
        self.0.lock().unwrap().get(key).map_or(0, |c| c.n)
    }

    /// How many keys are tracked.
    pub fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_of_a_window_then_counted_and_bounded() {
        let r = Refusals::default();
        assert!(r.note("a", 0));
        assert!(!r.note("a", 1));
        assert_eq!(r.count("a"), 2);
        assert!(r.note("a", WINDOW), "a new window");
        for i in 0..KEYS_MAX * 2 {
            r.note(&format!("k{i}"), 10);
        }
        assert_eq!(r.len(), KEYS_MAX);
    }
}
