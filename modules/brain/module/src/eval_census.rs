//! The Brain junk census (B1-02): how much of a real room is noise, duplicate or stale, by record
//! type and source kind. Runs on a READ-ONLY COPY of a Core home (never the live dir), on a scratch
//! copy of each room file migrated to this binary's schema (so it also proves the migrations on
//! real rows). Output is counts only: no body, title, path or id leaves the copy.
//! Driven by `examples/brain_census.rs`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use ainkrad_core_server::ops::config::Home;
use brain_model::admit::{Admission, Band, Candidate, Cited, admit};
use brain_model::merge::{Q_MERGE_COSINE, is_stale};
use brain_model::semantic::dot;
use serde::Serialize;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::eval::{brain_key, check_copy};
use crate::{cipher, files};

/// A cited source's text is read up to this many characters for the grounding check.
const CITED_CHARS: i64 = 20_000;
/// A source shorter than this many characters carries nothing worth distilling.
const TINY_CHARS: i64 = 40;

#[derive(Serialize, Default, Clone)]
pub struct Share {
    pub total: usize,
    /// Admission rejects the record's body (any hard or soft reject).
    pub noise: usize,
    /// Admission calls it borderline.
    pub borderline: usize,
    /// The same normalised body as an earlier record of the room.
    pub exact_duplicate: usize,
    /// A stored vector at or above `Q_MERGE_COSINE` to an earlier record of the same type.
    pub near_duplicate: usize,
    /// A task or project-state not seen within the room's review days.
    pub stale: usize,
}

#[derive(Serialize, Default)]
pub struct SourceShare {
    pub total: usize,
    pub tiny: usize,
    /// The same text as an earlier source (different hash: another device or run).
    pub same_text: usize,
    /// Older than the room's review days.
    pub old: usize,
    /// Already compacted or a pointer: no text left.
    pub no_text: usize,
}

#[derive(Serialize, Default)]
pub struct RoomCensus {
    pub room: String,
    pub review_days: i64,
    pub records_by_type: BTreeMap<String, Share>,
    /// Reject reasons, counted once per record per reason.
    pub reject_reasons: BTreeMap<String, usize>,
    pub sources_by_kind: BTreeMap<String, SourceShare>,
    /// Records with a stored vector / without: near-duplicates only count the first.
    pub with_vector: usize,
    pub without_vector: usize,
    pub failure: Option<String>,
}

fn decode(b: &[u8]) -> Vec<f32> {
    b.as_chunks::<4>()
        .0
        .iter()
        .map(|c| f32::from_le_bytes(*c))
        .collect()
}

/// Every stored vector, by content hash (any model: a copy holds one).
async fn vectors(root: &Path, key: &[u8; 32]) -> HashMap<String, Vec<f32>> {
    let path = files::vectors_path(root);
    if !path.is_file() {
        return HashMap::new();
    }
    let Ok(pool) = cipher::open_read_only(&path, key).await else {
        return HashMap::new();
    };
    let rows = sqlx::query("SELECT content_hash, vec FROM vectors")
        .fetch_all(&pool)
        .await
        .unwrap_or_default();
    pool.close().await;
    rows.iter()
        .filter_map(|r| {
            Some((
                r.try_get("content_hash").ok()?,
                decode(&r.try_get::<Vec<u8>, _>("vec").ok()?),
            ))
        })
        .collect()
}

async fn census_room(
    pool: &SqlitePool,
    room: &str,
    review_days: i64,
    vecs: &HashMap<String, Vec<f32>>,
    now: &str,
) -> Result<RoomCensus, sqlx::Error> {
    let mut c = RoomCensus {
        room: room.to_owned(),
        review_days,
        ..Default::default()
    };
    let cutoff: String =
        sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', ?, '-' || ? || ' days')")
            .bind(now)
            .bind(review_days)
            .fetch_one(pool)
            .await?;
    let records = sqlx::query(
        "SELECT id, type, body, coalesce(body_norm, lower(trim(body))) AS norm, \
                coalesce(last_seen_at, created_at) AS seen \
         FROM records WHERE status = 'accepted' AND archived_at IS NULL ORDER BY created_at, id",
    )
    .fetch_all(pool)
    .await?;
    let mut seen_norm: HashSet<String> = HashSet::new();
    // Earlier records' vectors per type, for the near-duplicate test.
    let mut earlier: HashMap<String, Vec<&Vec<f32>>> = HashMap::new();
    for r in &records {
        let (id, kind, body, norm, seen): (String, String, String, String, String) = (
            r.try_get("id")?,
            r.try_get("type")?,
            r.try_get("body")?,
            r.try_get("norm")?,
            r.try_get("seen")?,
        );
        let texts: Vec<String> = sqlx::query_scalar(
            "SELECT substr(s.text, 1, ?) FROM record_sources rs JOIN sources s ON s.item_id = rs.source WHERE rs.record = ? AND s.pointer = 0",
        )
        .bind(CITED_CHARS)
        .bind(&id)
        .fetch_all(pool)
        .await?;
        let cited: Vec<Cited> = texts
            .iter()
            .map(|t| Cited::new(t, t.contains("User:")))
            .collect();
        let a: Admission = admit(
            &Candidate {
                body: &body,
                kind: &kind,
                durable: None,
                confidence: None,
            },
            &cited,
            &[],
        );
        let s = c.records_by_type.entry(kind.clone()).or_default();
        s.total += 1;
        match a.band {
            Band::Reject => {
                s.noise += 1;
                let mut codes: Vec<&str> = a.reasons.iter().map(|x| x.code()).collect();
                codes.dedup();
                for code in codes {
                    *c.reject_reasons.entry(code.to_owned()).or_default() += 1;
                }
            }
            Band::Borderline => s.borderline += 1,
            Band::Admit => {}
        }
        if !seen_norm.insert(norm.clone()) {
            s.exact_duplicate += 1;
        }
        if is_stale(&kind, &seen, &cutoff) {
            s.stale += 1;
        }
        match vecs.get(&crate::ai_semantic::record_hash(&norm)) {
            Some(v) => {
                c.with_vector += 1;
                let list = earlier.entry(kind.clone()).or_default();
                if list.iter().any(|e| dot(e, v) >= Q_MERGE_COSINE) {
                    c.records_by_type.entry(kind).or_default().near_duplicate += 1;
                } else {
                    list.push(v);
                }
            }
            None => c.without_vector += 1,
        }
    }
    let srcs = sqlx::query(
        "SELECT source_kind, length(text) AS n, started_at, pointer, compacted_at IS NOT NULL AS gone, \
                lower(trim(text)) AS norm FROM sources ORDER BY started_at, item_id",
    )
    .fetch_all(pool)
    .await?;
    let mut seen_text: HashSet<String> = HashSet::new();
    for r in &srcs {
        let kind: String = r.try_get("source_kind")?;
        let s = c.sources_by_kind.entry(kind).or_default();
        s.total += 1;
        let (gone, pointer): (i64, i64) = (r.try_get("gone")?, r.try_get("pointer")?);
        if gone == 1 || pointer == 1 {
            s.no_text += 1;
            continue;
        }
        if r.try_get::<i64, _>("n")? < TINY_CHARS {
            s.tiny += 1;
        }
        if !seen_text.insert(r.try_get("norm")?) {
            s.same_text += 1;
        }
        if r.try_get::<String, _>("started_at")? < cutoff {
            s.old += 1;
        }
    }
    Ok(c)
}

/// The census of every active room of a copy of a Core home. `scratch` is where each room file is
/// copied and migrated; it is emptied after each room.
pub async fn run(home: &Path, out: &Path) -> Result<Vec<RoomCensus>, Box<dyn std::error::Error>> {
    check_copy(home, out)?;
    let h = Home(home.to_path_buf());
    let key = brain_key(&h).await?;
    let root = h.0.join("brain");
    let core = SqlitePoolOptions::new()
        .connect_with(SqliteConnectOptions::new().filename(h.db()).read_only(true))
        .await?;
    let rooms: Vec<(String, i64)> = sqlx::query_as(
        "SELECT id, review_days FROM brain_rooms WHERE state = 'active' ORDER BY id",
    )
    .fetch_all(&core)
    .await?;
    let now: String = sqlx::query_scalar("SELECT strftime('%Y-%m-%dT%H:%M:%SZ','now')")
        .fetch_one(&core)
        .await?;
    core.close().await;
    let vecs = vectors(&root, &key).await;
    let scratch = out.join(".scratch");
    std::fs::create_dir_all(&scratch)?;
    let mut all = vec![];
    for (room, days) in rooms {
        let src = files::room_path(&root, &room);
        let dst = scratch.join(format!("{room}-canon.db"));
        let one = async {
            std::fs::copy(&src, &dst).map_err(|e| format!("copy: {e}"))?;
            let pool = files::open_migrated(&dst, &key, false, files::CANON)
                .await
                .map_err(|e| e.to_string())?;
            let r = census_room(&pool, &room, days, &vecs, &now)
                .await
                .map_err(|e| e.to_string());
            pool.close().await;
            r
        }
        .await;
        let _ = std::fs::remove_file(&dst);
        all.push(one.unwrap_or_else(|e| RoomCensus {
            room: room.clone(),
            failure: Some(e.chars().take(160).collect()),
            ..Default::default()
        }));
    }
    let _ = std::fs::remove_dir_all(&scratch);
    Ok(all)
}
