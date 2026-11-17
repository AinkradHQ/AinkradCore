//! Presence (D7, T3): yrs awareness. The local state is a small JSON object (cursor, selection, label); remote states
//! are capped in count and size and must be JSON objects, or the whole update is refused. Never stored (T3).

use std::collections::BTreeMap;

use serde_json::Value;
use yrs::Doc as YDoc;
use yrs::sync::Awareness;
use yrs::sync::awareness::AwarenessUpdate;
use yrs::updates::decoder::Decode;
use yrs::updates::encoder::Encode;

use crate::Error;

pub const MAX_PRESENCE_BYTES: usize = 4096;
pub const MAX_PEERS: usize = 64;

pub struct Presence {
    aw: Awareness,
}

fn object(s: &str) -> bool {
    s.len() <= MAX_PRESENCE_BYTES
        && (s == "null" || serde_json::from_str::<Value>(s).is_ok_and(|v| v.is_object()))
}

impl Presence {
    pub(crate) fn new(doc: YDoc) -> Presence {
        Presence {
            aw: Awareness::new(doc),
        }
    }

    pub(crate) fn doc(&self) -> &YDoc {
        self.aw.doc()
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

    /// A relayed awareness update. Our own client id in it is ignored.
    pub fn apply(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > MAX_PEERS * (MAX_PRESENCE_BYTES + 32) {
            return Err(Error::TooLarge);
        }
        let mut u = crate::decode(|| AwarenessUpdate::decode_v1(bytes))?;
        u.clients.remove(&self.aw.client_id());
        if u.clients.len() > MAX_PEERS || !u.clients.values().all(|e| object(&e.json)) {
            return Err(Error::Refused("presence update out of bounds".into()));
        }
        let known = self.aw.iter().count();
        if known + u.clients.len() > 4 * MAX_PEERS {
            return Err(Error::Refused("too many peers".into()));
        }
        self.aw
            .apply_update(u)
            .map_err(|e| Error::Malformed(e.to_string()))
    }

    /// Remote peers' states: `{"<client id>": {...}}`, at most `MAX_PEERS`.
    pub fn peers(&self) -> Value {
        let me = self.aw.client_id();
        let m: BTreeMap<String, Value> = self
            .aw
            .iter()
            .filter(|(id, _)| *id != me)
            .filter_map(|(id, st)| {
                let v: Value = serde_json::from_str(st.data.as_deref()?).ok()?;
                v.is_object().then(|| (id.get().to_string(), v))
            })
            .take(MAX_PEERS)
            .collect();
        serde_json::to_value(m).unwrap_or(Value::Null)
    }
}
