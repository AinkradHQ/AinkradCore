//! Meaning-based ranking for `brainAiSearch`: the query is embedded on the one background worker
//! (bounded wait), scored against the vectors of the records and sources of the rooms the session
//! may see and has open, and fused with the keyword hits. Nothing here ever looks at a room the
//! caller did not pass in. Vectors a record or source lacks are queued for the worker, never
//! computed inline; on a timeout, a model that is off or any error the caller keeps the keyword hits.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use ainkrad_core::untrusted::wrap;
use ainkrad_core_server::api::App;
use brain_model::semantic::EMBED_CHARS;
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::Brain;
use crate::access::Visible;
use crate::ai::{AiHit, LIST_BODY, cut, record_of};
use crate::rooms::RoomAccess;
use crate::semantic::service::similar;

/// How long a search waits for the worker to embed the question.
pub(crate) const WAIT: Duration = Duration::from_secs(2);
/// Below this cosine a candidate is not "about" the query at all.
const MIN_SCORE: f32 = 0.35;
/// ponytail: newest records and the first sources per room; an index of vectors if rooms outgrow this.
const MAX_RECORDS: i64 = 500;
const MAX_SOURCES: i64 = 2000;
/// Candidates one search may queue for embedding.
const MAX_QUEUE: usize = 200;
const RRF_K: f32 = 60.0;

/// Whether meaning ranking is on: the setting and a loaded model.
pub(crate) async fn available(app: &App, b: &Brain) -> bool {
    b.embedder().is_some() && crate::suggest::enabled(app, b).await
}

fn embed_text(title: &str, text: &str) -> String {
    let mut end = text.len().min(EMBED_CHARS);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{title}\n{}", &text[..end])
}

fn record_hash(text: &str) -> String {
    let d = Sha256::digest(text.as_bytes());
    format!(
        "rec:{}",
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

struct Cand {
    room: usize,
    record: bool,
    id: String,
    hash: String,
}

/// The best `limit` hits by meaning, best first; `None` when meaning cannot answer now.
pub(crate) async fn rank(
    app: &App,
    b: &Brain,
    q: &str,
    open: &[(Visible, RoomAccess)],
    limit: usize,
) -> Option<Vec<AiHit>> {
    if !available(app, b).await {
        return None;
    }
    let qv = b.embed_query(q, WAIT).await?;
    let mut cands: Vec<Cand> = vec![];
    let mut rec_text: HashMap<String, String> = HashMap::new();
    for (i, (_, a)) in open.iter().enumerate() {
        let recs = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id, body FROM records WHERE status = 'accepted' ORDER BY created_at DESC, id LIMIT {MAX_RECORDS}"
        )))
        .fetch_all(a.pool())
        .await
        .ok()?;
        for r in recs {
            let text = embed_text("", &r.try_get::<String, _>("body").ok()?);
            let hash = record_hash(&text);
            rec_text.insert(hash.clone(), text);
            cands.push(Cand {
                room: i,
                record: true,
                id: r.try_get("id").ok()?,
                hash,
            });
        }
        let srcs = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT item_id, content_hash FROM sources ORDER BY item_id LIMIT {MAX_SOURCES}"
        )))
        .fetch_all(a.pool())
        .await
        .ok()?;
        for r in srcs {
            cands.push(Cand {
                room: i,
                record: false,
                id: r.try_get("item_id").ok()?,
                hash: r.try_get("content_hash").ok()?,
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
        let text = if c.record {
            rec_text.get(&c.hash).cloned()
        } else {
            let r = sqlx::query("SELECT title, text FROM sources WHERE item_id = ?")
                .bind(&c.id)
                .fetch_optional(open[c.room].1.pool())
                .await
                .ok()?;
            match r {
                Some(r) => Some(embed_text(
                    &r.try_get::<String, _>("title").ok()?,
                    &r.try_get::<String, _>("text").ok()?,
                )),
                None => None,
            }
        };
        queue.extend(text.map(|t| (c.hash.clone(), t)));
    }
    if !queue.is_empty() {
        b.queue_embed(queue);
    }
    let scored: Vec<(String, Vec<f32>)> = cands
        .iter()
        .enumerate()
        .filter_map(|(i, c)| have.get(&c.hash).map(|v| (i.to_string(), v.clone())))
        .collect();
    let mut hits = vec![];
    for (i, score) in similar(&qv, &scored, limit) {
        if score < MIN_SCORE {
            break;
        }
        let c = &cands[i.parse::<usize>().ok()?];
        let (v, a) = &open[c.room];
        if c.record {
            let r = sqlx::query(
                "SELECT id, type, body, tags, source_ids, created_at FROM records WHERE id = ?",
            )
            .bind(&c.id)
            .fetch_one(a.pool())
            .await
            .ok()?;
            let rec = record_of(&v.id, &r, LIST_BODY).ok()?;
            hits.push(AiHit {
                room: v.id.clone(),
                kind: "record".to_owned(),
                id: rec.id,
                started_at: r.try_get("created_at").ok()?,
                text: rec.text,
            });
        } else {
            let r = sqlx::query("SELECT title, text, started_at FROM sources WHERE item_id = ?")
                .bind(&c.id)
                .fetch_one(a.pool())
                .await
                .ok()?;
            let title: String = r.try_get("title").ok()?;
            let body: String = r.try_get("text").ok()?;
            hits.push(AiHit {
                room: v.id.clone(),
                kind: "source".to_owned(),
                text: wrap(
                    &format!("source {} | {title}", c.id),
                    &cut(&body, LIST_BODY).0,
                ),
                id: c.id.clone(),
                started_at: r.try_get("started_at").ok()?,
            });
        }
    }
    Some(hits)
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
    all.sort_by(|a, b| score[&key(b)].total_cmp(&score[&key(a)]));
    all.truncate(limit);
    all
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(id: &str) -> AiHit {
        AiHit {
            room: "r".into(),
            kind: "source".into(),
            id: id.into(),
            started_at: String::new(),
            text: id.into(),
        }
    }

    #[test]
    fn a_hit_in_both_lists_beats_one_in_a_single_list() {
        let out = fuse(vec![h("a"), h("b")], vec![h("c"), h("b")], 10);
        let ids: Vec<&str> = out.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, ["b", "a", "c"]);
        assert_eq!(fuse(vec![h("a"), h("b")], vec![], 1).len(), 1);
    }
}
