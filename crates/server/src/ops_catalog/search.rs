//! `ainkrad.search`'s ranking (E1.4): word match over an operation's id, group, path and summary.

use serde_json::{Value, json};

use super::{Catalogue, Op, render};

const DEFAULT_LIMIT: usize = 8;
const MAX_LIMIT: usize = 20;
/// The answer stays under this many bytes.
pub const MAX_ANSWER: usize = 8 * 1024;

/// Lower-case words; `listAgentSessions` is `list agent sessions`.
fn words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in s.chars() {
        if (!c.is_alphanumeric() || (c.is_uppercase() && prev_lower)) && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        if c.is_alphanumeric() {
            cur.extend(c.to_lowercase());
        }
        prev_lower = c.is_lowercase();
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn score(op: &Op, query: &[String]) -> u32 {
    let fields = [
        (words(&op.id), 3),
        (words(&format!("{} {}", op.group, op.path)), 2),
        (words(&op.summary), 1),
    ];
    query
        .iter()
        .map(|q| {
            fields
                .iter()
                .map(|(ws, weight)| {
                    if ws.iter().any(|w| w == q) {
                        *weight * 2
                    } else if q.len() >= 3 && ws.iter().any(|w| w.starts_with(q.as_str())) {
                        *weight
                    } else {
                        0
                    }
                })
                .max()
                .unwrap_or(0)
        })
        .sum()
}

/// The answer to a search: up to `limit` (8 by default, 20 at most) definitions of the operations
/// that match `query` and whose scope is among `scopes`. No match gives no definitions and the
/// groups the session can reach, so the model can ask again with a better word.
pub fn search(cat: &Catalogue, scopes: &[String], query: &str, limit: Option<usize>) -> Value {
    let q = words(query);
    let limit = limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let usable: Vec<&Op> = cat
        .ops
        .values()
        .filter(|o| scopes.contains(&o.scope))
        .collect();
    let mut hits: Vec<(u32, &Op)> = usable
        .iter()
        .map(|o| (score(o, &q), *o))
        .filter(|(s, _)| *s > 0)
        .collect();
    hits.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id)));
    let mut defs = Vec::new();
    let mut size = 0;
    for (_, o) in hits.into_iter().take(limit) {
        let d = json!({"op": o.id, "group": o.group, "risk": o.risk.as_str(), "def": render(o)});
        size += d.to_string().len();
        if size > MAX_ANSWER - 512 {
            break;
        }
        defs.push(d);
    }
    let mut out = json!({"defs": defs});
    if defs.is_empty() {
        let mut groups: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
        for o in &usable {
            groups.entry(&o.group).or_default().push(&o.id);
        }
        out["groups"] = json!(groups);
    }
    out
}
