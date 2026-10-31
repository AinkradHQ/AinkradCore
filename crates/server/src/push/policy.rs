//! What a notification may carry and who gets it (E2-12.3): ids, never secrets or terminal
//! content; one merged push for a burst; a ceiling per device. Everything a module's
//! [`super::Classifier`] hands over goes through [`clean`] before it reaches a provider.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use serde_json::{Map, Value};

use super::Notification;
use crate::store::gov::PushTarget;
use crate::store::redact;

const MAX_TITLE: usize = 80;
const MAX_BODY: usize = 200;
const MAX_ID: usize = 64;

fn id_like(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

fn trimmed(text: &str, max: usize) -> String {
    ainkrad_proto::redact::Redactor::new()
        .text(text)
        .chars()
        .take(max)
        .collect()
}

/// The notification as it may leave the Core. `data` keeps only what an app needs to open the
/// right screen: integers, booleans and short id-like strings, under keys that are not named
/// like a secret and whose value no secret pattern masks. Terminal output, free text and
/// anything that looks like a credential is dropped, not masked. Title and body are redacted
/// and cut short.
pub fn clean(mut n: Notification) -> Notification {
    n.title = trimmed(&n.title, MAX_TITLE);
    n.body = trimmed(&n.body, MAX_BODY);
    let mut kept = Map::new();
    if let Value::Object(map) = &n.data {
        for (key, value) in map {
            let plain = match value {
                Value::Number(x) => x.is_i64() || x.is_u64(),
                Value::Bool(_) => true,
                Value::String(s) => id_like(s),
                _ => false,
            };
            let mut probe = Value::Object(Map::from_iter([(key.clone(), value.clone())]));
            redact::json(&mut probe);
            let untouched = probe[key] == *value;
            if plain && id_like(key) && !redact::secret_name(key) && untouched {
                kept.insert(key.clone(), value.clone());
            }
        }
    }
    n.data = Value::Object(kept);
    n
}

/// Whether a device may be sent a notification that needs scope `needs`: it holds that scope or
/// `admin`. A `read` device is told nothing about an approval.
pub fn may_receive(to: &PushTarget, needs: &str) -> bool {
    to.scopes.iter().any(|s| s == needs || s == "admin")
}

/// Merges notifications with the same `collapse` key into one (the first's title, a count in
/// `data`, the last one's ids); the others pass through in order.
pub fn coalesce(all: Vec<Notification>) -> Vec<Notification> {
    let mut out: Vec<Notification> = Vec::with_capacity(all.len());
    let mut seen: HashMap<String, (usize, u64)> = HashMap::new();
    for n in all {
        let Some(key) = n.collapse.clone() else {
            out.push(n);
            continue;
        };
        match seen.get_mut(&key) {
            Some((at, count)) => {
                *count += 1;
                let mut merged = n;
                merged.title = out[*at].title.clone();
                merged.body = format!("{count} new");
                if let Value::Object(map) = &mut merged.data {
                    map.insert("count".to_owned(), (*count).into());
                }
                out[*at] = merged;
            }
            None => {
                seen.insert(key, (out.len(), 1));
                out.push(n);
            }
        }
    }
    out
}

/// At most [`Limiter::MAX`] pushes per device in any [`Limiter::WINDOW`] seconds; per process,
/// so a restart forgets (the cost is one more burst).
#[derive(Default)]
pub struct Limiter(Mutex<HashMap<(i64, String), VecDeque<i64>>>);

impl Limiter {
    pub const MAX: usize = 10;
    pub const WINDOW: i64 = 60;

    /// Whether `device` may be pushed at `now` (unix seconds); counts it when it may. Each
    /// module has a budget of its own (`bucket`), so one cannot use up the platform's or another's.
    pub fn allow(&self, device: i64, bucket: &str, now: i64) -> bool {
        let mut all = self.0.lock().unwrap();
        let sent = all.entry((device, bucket.to_owned())).or_default();
        while sent.front().is_some_and(|t| now - t >= Self::WINDOW) {
            sent.pop_front();
        }
        if sent.len() >= Self::MAX {
            return false;
        }
        sent.push_back(now);
        true
    }
}
