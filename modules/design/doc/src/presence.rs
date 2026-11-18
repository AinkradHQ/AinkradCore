//! Presence (D7, T3): yrs awareness. The local state is a small JSON object (cursor, selection, label); remote states
//! are capped in count and size and must be JSON objects, or the whole update is refused. Peers not heard from for
//! `PEER_TTL_MS` expire, and the table is rebuilt when expired entries pile up. Never stored (T3).

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::Value;
use yrs::Doc as YDoc;
use yrs::sync::Awareness;
use yrs::sync::awareness::AwarenessUpdate;
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;

use crate::Error;

pub const MAX_PRESENCE_BYTES: usize = 4096;
pub const MAX_PEERS: usize = 64;
/// A peer that sent nothing for this long is gone (T13's AI presence lives 30 s).
pub const PEER_TTL_MS: u64 = 30_000;
/// Entries (live and expired) kept before the table is rebuilt from the live ones.
const MAX_ENTRIES: usize = 16 * MAX_PEERS;

/// Milliseconds since some epoch.
pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

pub(crate) fn system_clock() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub struct Presence {
    aw: Awareness,
    clock: ClockFn,
}

fn object(s: &str) -> bool {
    s.len() <= MAX_PRESENCE_BYTES
        && (s == "null" || serde_json::from_str::<Value>(s).is_ok_and(|v| v.is_object()))
}

fn awareness(doc: YDoc, clock: &ClockFn) -> Awareness {
    let c = clock.clone();
    Awareness::with_clock(doc, move || c())
}

impl Presence {
    pub(crate) fn new(doc: YDoc, clock: ClockFn) -> Presence {
        Presence {
            aw: awareness(doc, &clock),
            clock,
        }
    }

    pub(crate) fn doc(&self) -> &YDoc {
        self.aw.doc()
    }

    pub(crate) fn clock(&self) -> ClockFn {
        self.clock.clone()
    }

    /// Set this replica's state: a JSON object of at most `MAX_PRESENCE_BYTES`.
    pub fn set_local(&mut self, json: &str) -> Result<(), Error> {
        if json.len() > MAX_PRESENCE_BYTES {
            return Err(Error::TooLarge);
        }
        if json == "null" || !object(json) {
            return Err(Error::Refused("presence must be a JSON object".into()));
        }
        self.aw.set_local_state_raw(json);
        Ok(())
    }

    /// This replica's awareness update (to send), empty when no local state was set.
    pub fn encode_local(&self) -> Vec<u8> {
        if self.aw.local_state_raw().is_none() {
            return vec![];
        }
        self.aw
            .update_with_clients([self.aw.client_id()])
            .map(|u| u.encode_v1())
            .unwrap_or_default()
    }

    /// Remote peers with a state, not expired.
    fn live(&self) -> Vec<yrs::ClientID> {
        let (me, now) = (self.aw.client_id(), (self.clock)());
        self.aw
            .iter()
            .filter(|(id, st)| {
                *id != me && st.data.is_some() && now.saturating_sub(st.last_updated) <= PEER_TTL_MS
            })
            .map(|(id, _)| id)
            .collect()
    }

    /// Clear expired peers; rebuild the table from the live ones once expired entries pile up.
    fn expire(&mut self) {
        let live = self.live();
        let me = self.aw.client_id();
        let stale: Vec<_> = self
            .aw
            .iter()
            .filter(|(id, st)| *id != me && st.data.is_some() && !live.contains(id))
            .map(|(id, _)| id)
            .collect();
        for id in stale {
            self.aw.remove_state(id);
        }
        if self.aw.iter().count() > MAX_ENTRIES {
            let keep = self.aw.update_with_clients(live).ok();
            let local = self.aw.local_state_raw();
            let mut fresh = awareness(self.aw.doc().clone(), &self.clock);
            if let Some(u) = keep {
                let _ = fresh.apply_update(u);
            }
            if let Some(l) = local {
                fresh.set_local_state_raw(l);
            }
            self.aw = fresh;
        }
    }

    /// A relayed awareness update. Our own client id in it is ignored.
    pub fn apply(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > MAX_PEERS * (MAX_PRESENCE_BYTES + 32) {
            return Err(Error::TooLarge);
        }
        let mut u = crate::decode::caught(|| AwarenessUpdate::decode_v1(bytes))?;
        u.clients.remove(&self.aw.client_id());
        if u.clients.len() > MAX_PEERS || !u.clients.values().all(|e| object(&e.json)) {
            return Err(Error::Refused("presence update out of bounds".into()));
        }
        self.expire();
        let live = self.live();
        let new = u.clients.keys().filter(|id| !live.contains(id)).count();
        if live.len() + new > 4 * MAX_PEERS {
            return Err(Error::Refused("too many peers".into()));
        }
        self.aw
            .apply_update(u)
            .map_err(|e| Error::Malformed(e.to_string()))
    }

    /// Live remote peers' states: `{"<client id>": {...}}`, at most `MAX_PEERS`.
    pub fn peers(&self) -> Value {
        let live = self.live();
        let m: BTreeMap<String, Value> = self
            .aw
            .iter()
            .filter(|(id, _)| live.contains(id))
            .filter_map(|(id, st)| {
                let v: Value = serde_json::from_str(st.data.as_deref()?).ok()?;
                v.is_object().then(|| (id.get().to_string(), v))
            })
            .take(MAX_PEERS)
            .collect();
        serde_json::to_value(m).unwrap_or(Value::Null)
    }
}
