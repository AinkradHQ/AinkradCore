//! Failures per address in this process (handshake spec §11; security review M2, N2): counted
//! and checked under one lock, so concurrent requests cannot all slip under the limit, and
//! anything past it is refused without touching the database. The persisted lockout
//! (`store::gov::limits`) carries the lock across restarts; this only gates the work and the
//! writes.
//!
//! - The host's own socket (`ip:local`) is never refused here: an attacker cannot lock the
//!   operator out of `bootstrap`/`recover`.
//! - A full table evicts its least recently touched address rather than refusing a new one.
//! - IPv6 is keyed by /64 (`api::v1::gate::address`), and one /48 holds at most
//!   `PER_PREFIX_MAX` keys; past that its addresses share the /48's key, so one prefix cannot
//!   fill the table.
//! - An evaluation slot (`reserve`) is given back by `release`; one never given back (a request
//!   dropped mid-way) lapses after `SLOT_SECS`.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::store::gov::ADDRESS;

/// The host's own socket's address key.
pub const LOCAL: &str = "ip:local";
/// Addresses tracked at most.
pub const ADDRESSES_MAX: usize = 65_536;
/// `/64` keys of one IPv6 `/48` tracked at most before they share the `/48`'s key.
pub const PER_PREFIX_MAX: usize = 1_024;
/// A slot older than this is no longer in flight (the request deadline is 30 s).
pub const SLOT_SECS: i64 = 60;

#[derive(Debug)]
struct Slot {
    fails: i64,
    start: i64,
    /// When each evaluation in flight started.
    inflight: Vec<i64>,
    touched: i64,
}

#[derive(Default)]
struct Table {
    slots: HashMap<String, Slot>,
    /// `/48` key → how many `/64` keys under it are tracked.
    prefixes: HashMap<String, usize>,
}

/// `ip:a:b:c::/48` of an `ip:a:b:c:d::/64` key.
fn prefix48(key: &str) -> Option<String> {
    let rest = key.strip_prefix("ip:")?.strip_suffix("::/64")?;
    let parts: Vec<&str> = rest.split(':').collect();
    (parts.len() == 4).then(|| format!("ip:{}:{}:{}::/48", parts[0], parts[1], parts[2]))
}

impl Table {
    fn key(&self, addr: &str) -> String {
        match prefix48(addr) {
            Some(p)
                if !self.slots.contains_key(addr)
                    && self.prefixes.get(&p).copied().unwrap_or(0) >= PER_PREFIX_MAX =>
            {
                p
            }
            _ => addr.to_owned(),
        }
    }

    fn remove(&mut self, key: &str) {
        if self.slots.remove(key).is_some()
            && let Some(p) = prefix48(key)
            && let Some(n) = self.prefixes.get_mut(&p)
        {
            *n -= 1;
            if *n == 0 {
                self.prefixes.remove(&p);
            }
        }
    }

    fn slot(&mut self, addr: &str, now: i64) -> &mut Slot {
        let key = self.key(addr);
        if !self.slots.contains_key(&key) {
            if self.slots.len() >= ADDRESSES_MAX {
                // ponytail: a linear scan, only when the table is full; an ordered index if
                // that ever shows.
                let oldest = self
                    .slots
                    .iter()
                    .min_by_key(|(_, s)| s.touched)
                    .map(|(k, _)| k.clone());
                if let Some(k) = oldest {
                    self.remove(&k);
                }
            }
            if let Some(p) = prefix48(&key) {
                *self.prefixes.entry(p).or_default() += 1;
            }
        }
        let slot = self.slots.entry(key).or_insert(Slot {
            fails: 0,
            start: now,
            inflight: Vec::new(),
            touched: now,
        });
        if now - slot.start >= ADDRESS.window {
            (slot.fails, slot.start) = (0, now);
        }
        slot.inflight.retain(|t| now - t < SLOT_SECS);
        slot.touched = now;
        slot
    }
}

#[derive(Default)]
pub struct AddressFailures {
    table: Mutex<Table>,
}

impl AddressFailures {
    /// Counts one failure from `addr`; `false` when the address is at its budget already (the
    /// caller refuses with 429 and writes nothing). Always `true` for the host's socket.
    pub fn count(&self, addr: &str, now: i64) -> bool {
        if addr == LOCAL {
            return true;
        }
        let mut table = self.table.lock().unwrap();
        let s = table.slot(addr, now);
        let ok = s.fails < ADDRESS.threshold;
        s.fails += i64::from(ok);
        ok
    }

    /// Takes one evaluation slot for `addr` (a pairing claim): `false` when its failures plus
    /// the claims in flight reach the budget. Give it back with `release`. Always `true` for
    /// the host's socket.
    pub fn reserve(&self, addr: &str, now: i64) -> bool {
        if addr == LOCAL {
            return true;
        }
        let mut table = self.table.lock().unwrap();
        let s = table.slot(addr, now);
        let ok = s.fails + (s.inflight.len() as i64) < ADDRESS.threshold;
        if ok {
            s.inflight.push(now);
        }
        ok
    }

    /// Gives back a slot from `reserve`, counting it as a failure when `failed`.
    pub fn release(&self, addr: &str, failed: bool, now: i64) {
        if addr == LOCAL {
            return;
        }
        let mut table = self.table.lock().unwrap();
        let s = table.slot(addr, now);
        if !s.inflight.is_empty() {
            s.inflight.remove(0);
        }
        s.fails += i64::from(failed);
    }

    /// How many addresses are tracked.
    pub fn len(&self) -> usize {
        self.table.lock().unwrap().slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The global wrong-claim budget (§7.4): 20 wrong pairing claims from anywhere within 5
/// minutes burn every live pairing. A claim in flight holds a slot, so concurrent guesses cannot
/// overrun it (review M2); a slot lapses after `SLOT_SECS` even if never given back (N1). The
/// host's socket does not take part (`api::v1::pair`). In memory: a restart starts it again.
#[derive(Default)]
pub struct PairBudget {
    /// (wrong claims in the window, window start, when each claim in flight started).
    slot: Mutex<(i64, i64, Vec<i64>)>,
}

pub const PAIR_BUDGET: i64 = 20;
pub const PAIR_WINDOW: i64 = 300;

impl PairBudget {
    fn fresh(s: &mut (i64, i64, Vec<i64>), now: i64) {
        if now - s.1 >= PAIR_WINDOW {
            (s.0, s.1) = (0, now);
        }
        s.2.retain(|t| now - t < SLOT_SECS);
    }

    /// Takes a slot for one claim; `false` when the wrong claims and the claims in flight
    /// reach the budget.
    pub fn reserve(&self, now: i64) -> bool {
        let mut s = self.slot.lock().unwrap();
        Self::fresh(&mut s, now);
        let ok = s.0 + (s.2.len() as i64) < PAIR_BUDGET;
        if ok {
            s.2.push(now);
        }
        ok
    }

    /// Gives the slot back; a `wrong` claim counts. `true` when that spends the budget: the
    /// caller burns every live pairing, and the budget starts again.
    pub fn release(&self, wrong: bool, now: i64) -> bool {
        let mut s = self.slot.lock().unwrap();
        Self::fresh(&mut s, now);
        if !s.2.is_empty() {
            s.2.remove(0);
        }
        s.0 += i64::from(wrong);
        let spent = s.0 >= PAIR_BUDGET;
        if spent {
            (s.0, s.1) = (0, now);
        }
        spent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counted_and_reserved_under_one_lock() {
        let f = AddressFailures::default();
        for _ in 0..20 {
            assert!(f.count("ip:a", 0));
        }
        assert!(!f.count("ip:a", 1), "at the budget");
        assert!(f.count("ip:b", 1), "per address");
        assert!(f.count("ip:a", 600), "a new window");
        for _ in 0..19 {
            assert!(f.reserve("ip:c", 0));
        }
        assert!(f.count("ip:c", 0));
        assert!(!f.reserve("ip:c", 0), "19 in flight + 1 failure");
        f.release("ip:c", false, 0);
        assert!(f.reserve("ip:c", 0), "a slot came back");
        // Slots never given back lapse.
        for _ in 0..20 {
            f.reserve("ip:d", 100);
        }
        assert!(!f.reserve("ip:d", 100));
        assert!(f.reserve("ip:d", 100 + SLOT_SECS), "dropped slots lapsed");
        // The host's socket is never refused.
        for _ in 0..100 {
            assert!(f.count(LOCAL, 0) && f.reserve(LOCAL, 0));
        }
    }

    /// N2: one /48 cannot fill the table, a full table evicts rather than refuses, and the
    /// host's socket always gets through.
    #[test]
    fn a_full_table_evicts_and_one_prefix_cannot_fill_it() {
        let f = AddressFailures::default();
        for i in 0..65_536u32 {
            f.count(&format!("ip:2001:db8:1:{i:x}::/64"), 0);
        }
        assert_eq!(f.len(), PER_PREFIX_MAX + 1, "the rest share the /48's key");
        for i in 0..(ADDRESSES_MAX - f.len()) as u32 {
            f.count(
                &format!("ip:10.{}.{}.{}", i >> 16, (i >> 8) & 255, i & 255),
                1,
            );
        }
        assert_eq!(f.len(), ADDRESSES_MAX);
        assert!(
            f.count("ip:192.0.2.1", 2),
            "a new address gets through a full table"
        );
        assert!(f.reserve("ip:192.0.2.2", 2));
        assert_eq!(f.len(), ADDRESSES_MAX, "by evicting the oldest");
        assert!(f.count(LOCAL, 2) && f.reserve(LOCAL, 2));
    }
}
