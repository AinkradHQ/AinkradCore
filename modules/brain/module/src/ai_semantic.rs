//! Meaning-based ranking for `brainAiSearch`: the query is embedded (as a `query:`) on the one
//! background worker (bounded wait), scored against the vectors of the memory records of the rooms
//! the session may see and has open, and fused with the keyword hits. Records only: sources are not
//! searched by meaning for AI retrieval (plan B2, "Search fixes"). Nothing here ever looks at a room
//! the caller did not pass in. Vectors a record lacks are queued for the worker, never computed
//! inline; on a timeout, a model that is off or any error the caller keeps the keyword hits.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use ainkrad_core_server::api::App;
use brain_model::merge::DEMOTE_SQL;
use brain_model::semantic::{EMBED_CHARS, Q_MEMORY_MARGIN, within_margin};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::Brain;
use crate::access::Visible;
use crate::ai::{AiHit, CONTESTS_KIND, LIST_BODY, record_of};
use crate::rooms::RoomAccess;
use crate::semantic::service::similar;

/// How long a search waits for the worker to embed the question.
pub(crate) const WAIT: Duration = Duration::from_secs(2);
/// ponytail: newest records per room; an index of vectors if rooms outgrow this. A room with more
/// makes the search `complete: false`.
const MAX_RECORDS: i64 = 500;
/// Candidates one search may queue for embedding.
const MAX_QUEUE: usize = 200;
const RRF_K: f32 = 60.0;

/// Whether meaning ranking is on: the setting and a loaded model.
pub(crate) async fn available(app: &App, b: &Brain) -> bool {
    b.embedder().is_some() && crate::suggest::enabled(app, b).await
}

/// The text a record is embedded as (cut on a char boundary).
pub(crate) fn embed_text(body: &str) -> String {
    let mut end = body.len().min(EMBED_CHARS);
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    body[..end].to_owned()
}

/// The vector key of a record: the hash of its normalised body (`body_norm`; the body itself while
/// that column is still empty), so a fact worded twice shares one vector.
pub(crate) fn record_hash(norm_or_body: &str) -> String {
    let d = Sha256::digest(norm_or_body.as_bytes());
    format!(
        "rec:{}",
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

impl Brain {
    /// Queues the vectors of just-saved records, `(body_norm, body)` each, so a search finds them
    /// without waiting. Returns at once; a no-op while the model is off.
    pub(crate) fn queue_record_vectors(&self, records: &[(Option<String>, String)]) {
        let pairs: Vec<(String, String)> = records
            .iter()
            .map(|(n, body)| (record_hash(n.as_deref().unwrap_or(body)), embed_text(body)))
            .collect();
        if !pairs.is_empty() {
            self.queue_embed(pairs);
        }
    }
}

struct Cand {
    room: usize,
    id: String,
    hash: String,
    /// `DEMOTE_SQL`: a stale `project-state`/`task` ranks after the fresh ones, a contested record
    /// after everything (B4-02).
    demote: i64,
}

/// The best `limit` hits by meaning, best first, and whether `MAX_RECORDS` cut a room; `None` when
/// meaning cannot answer now.
pub(crate) async fn rank(
    app: &App,
    b: &Brain,
    q: &str,
    open: &[(Visible, RoomAccess)],
    limit: usize,
) -> Option<(Vec<AiHit>, bool)> {
    if !available(app, b).await {
        return None;
    }
    let qv = b.embed_query(q, WAIT).await?;
    let mut cands: Vec<Cand> = vec![];
    let mut rec_text: HashMap<String, String> = HashMap::new();
    let mut capped = false;
    for (i, (_, a)) in open.iter().enumerate() {
        let total: i64 = sqlx::query_scalar("SELECT count(*) FROM memory")
            .fetch_one(a.pool())
            .await
            .ok()?;
        capped |= total > MAX_RECORDS;
        let recs = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id, body, body_norm, {DEMOTE_SQL} AS demote FROM memory ORDER BY created_at DESC, id LIMIT {MAX_RECORDS}"
        )))
        .bind(crate::ai::stale_cutoff(app, &open[i].0.id).await)
        .fetch_all(a.pool())
        .await
        .ok()?;
        for r in recs {
            let body: String = r.try_get("body").ok()?;
            let norm: Option<String> = r.try_get("body_norm").ok()?;
            let hash = record_hash(norm.as_deref().unwrap_or(&body));
            rec_text.insert(hash.clone(), embed_text(&body));
            cands.push(Cand {
                room: i,
                id: r.try_get("id").ok()?,
                demote: r.try_get::<i64, _>("demote").ok()?,
                hash,
            });
        }
    }
    let hashes: Vec<String> = cands.iter().map(|c| c.hash.clone()).collect();
    let have = b.vectors_for(&hashes).await.ok()?;
    // What has no vector yet goes to the worker; this search ranks what it has.
    let mut queue: Vec<(String, String)> = vec![];
    let mut seen = HashSet::new();
    for c in cands.iter().filter(|c| !have.contains_key(&c.hash)) {
        if queue.len() >= MAX_QUEUE || !seen.insert(c.hash.clone()) {
            continue;
        }
        queue.extend(rec_text.get(&c.hash).map(|t| (c.hash.clone(), t.clone())));
    }
    if !queue.is_empty() {
        b.queue_embed(queue);
    }
    let scored: Vec<(String, Vec<f32>)> = cands
        .iter()
        .enumerate()
        .filter_map(|(i, c)| have.get(&c.hash).map(|v| (i.to_string(), v.clone())))
        .collect();
    let mut top = similar(&qv, &scored, limit);
    let keep = within_margin(
        &top.iter().map(|t| t.1).collect::<Vec<_>>(),
        Q_MEMORY_MARGIN,
    );
    top.truncate(keep);
    // Stale project state and tasks after the fresh ones, contested records last, each group still
    // best first (stable).
    top.sort_by_key(|t| cands[t.0.parse::<usize>().unwrap_or(0)].demote);
    let mut hits = vec![];
    for (i, _) in top {
        let c = &cands[i.parse::<usize>().ok()?];
        let (v, a) = &open[c.room];
        let r = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id, type, body, tags, source_ids, created_at, origin, contests, {CONTESTS_KIND} FROM memory WHERE id = ?"
        )))
        .bind(&c.id)
        .fetch_optional(a.pool())
        .await
        .ok()?;
        let Some(r) = r else { continue };
        let rec = record_of(&v.id, &r, LIST_BODY).ok()?;
        hits.push(AiHit {
            room: v.id.clone(),
            kind: "record".to_owned(),
            id: rec.id,
            started_at: rec.created_at,
            text: rec.text,
            demote: c.demote,
        });
    }
    Some((hits, capped))
}

/// Reciprocal-rank fusion of two best-first lists; a hit in both keeps the keyword text (it has the
/// matched words marked). Best first, at most `limit`.
pub(crate) fn fuse(keyword: Vec<AiHit>, meaning: Vec<AiHit>, limit: usize) -> Vec<AiHit> {
    let key = |h: &AiHit| (h.room.clone(), h.kind.clone(), h.id.clone());
    let mut score: HashMap<(String, String, String), f32> = HashMap::new();
    for list in [&keyword, &meaning] {
        for (rank, h) in list.iter().enumerate() {
            *score.entry(key(h)).or_default() += 1.0 / (RRF_K + rank as f32 + 1.0);
        }
    }
    let mut seen = HashSet::new();
    let mut all: Vec<AiHit> = keyword
        .into_iter()
        .chain(meaning)
        .filter(|h| seen.insert(key(h)))
        .collect();
    // Fused best first, but never above the demotion: contested stays last (B4-02).
    all.sort_by(|a, b| {
        a.demote
            .cmp(&b.demote)
            .then(score[&key(b)].total_cmp(&score[&key(a)]))
    });
    all.truncate(limit);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(id: &str) -> AiHit {
        AiHit {
            room: "r".into(),
            kind: "record".into(),
            id: id.into(),
            started_at: String::new(),
            text: id.into(),
            demote: 0,
        }
    }

    #[test]
    fn a_hit_in_both_lists_beats_one_in_a_single_list() {
        let out = fuse(vec![h("a"), h("b")], vec![h("c"), h("b")], 10);
        let ids: Vec<&str> = out.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, ["b", "a", "c"]);
        assert_eq!(fuse(vec![h("a"), h("b")], vec![], 1).len(), 1);
    }

    #[test]
    fn a_contested_hit_stays_last_after_fusion() {
        let contested = AiHit {
            demote: 2,
            ..h("x")
        };
        let out = fuse(vec![contested.clone(), h("a")], vec![contested, h("c")], 10);
        let ids: Vec<&str> = out.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, ["a", "c", "x"]);
    }
}
