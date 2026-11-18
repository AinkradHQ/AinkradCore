//! Merge-on-save (B4-01): a candidate fact the memory already holds reinforces that fact instead of
//! adding a row. The decision is the pure `brain_model::merge::decide`; this file loads what it
//! needs (stored and candidate vectors) and writes the reinforcement. The caller writes it inside
//! one change set, so Undo puts the old support, `last_seen_at` and citations back.

use std::collections::HashMap;

use ainkrad_core_server::api::App;
use brain_model::merge::{Decision, Known, decide};
use brain_model::semantic::normalized;
use sqlx::{SqliteConnection, SqlitePool};

use crate::Brain;
use crate::ai_semantic::{embed_text, record_hash};
use crate::changes::ChangeSet;

/// ponytail: the newest memory records per room are compared by meaning; an index of vectors if
/// rooms outgrow this. Exact matches look at every record.
const MAX_COMPARED: i64 = 2000;

/// Unit vectors for one save: the stored ones of the room's records (by record hash) and one per
/// candidate. Empty when the model is off or fails: only the exact and `same_as` tiers then work.
#[derive(Default)]
pub(crate) struct Prepared {
    cand: Vec<Option<Vec<f32>>>,
    stored: HashMap<String, Vec<f32>>,
}

/// `bodies` are the candidates' bodies as they will be stored (redacted, trimmed).
pub(crate) async fn prepare(
    app: &App,
    b: &Brain,
    pool: &SqlitePool,
    bodies: &[String],
) -> Prepared {
    if !crate::ai_semantic::available(app, b).await {
        return Prepared::default();
    }
    let run = async {
        let rows: Vec<(Option<String>, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
            "SELECT body_norm, body FROM memory ORDER BY created_at DESC, id LIMIT {MAX_COMPARED}"
        )))
        .fetch_all(pool)
        .await
        .ok()?;
        let hashes: Vec<String> = rows
            .iter()
            .map(|(n, body)| record_hash(n.as_deref().unwrap_or(body)))
            .collect();
        let stored = b
            .vectors_for(&hashes)
            .await
            .ok()?
            .into_iter()
            .map(|(h, v)| (h, normalized(v)))
            .collect();
        let pairs: Vec<(String, String)> = bodies
            .iter()
            .map(|t| {
                (
                    record_hash(&brain_model::merge::body_norm(t)),
                    embed_text(t),
                )
            })
            .collect();
        let cand = b
            .embed_texts(&pairs)
            .await
            .ok()?
            .into_iter()
            .map(|v| Some(normalized(v)))
            .collect();
        Some(Prepared { cand, stored })
    };
    run.await.unwrap_or_default()
}

impl Prepared {
    /// The unit vector of candidate `i`, when there is one.
    pub(crate) fn candidate(&self, i: usize) -> Option<&[f32]> {
        self.cand.get(i)?.as_deref()
    }
}

struct Row {
    id: String,
    kind: String,
    norm: String,
    vec: Option<Vec<f32>>,
}

/// The facts in force in the room (the `memory` view) as the decision sees them, kept current as a
/// batch saves, so a fact worded twice in one answer merges with itself.
pub(crate) struct Memory(Vec<Row>);

impl Memory {
    pub(crate) async fn load(
        conn: &mut SqliteConnection,
        prep: &Prepared,
    ) -> Result<Self, sqlx::Error> {
        let rows: Vec<(String, String, String, Option<String>)> =
            sqlx::query_as("SELECT id, type, body, body_norm FROM memory")
                .fetch_all(conn)
                .await?;
        Ok(Self(
            rows.into_iter()
                .map(|(id, kind, body, norm)| Row {
                    vec: prep
                        .stored
                        .get(&record_hash(norm.as_deref().unwrap_or(&body)))
                        .cloned(),
                    norm: norm.unwrap_or_else(|| brain_model::merge::body_norm(&body)),
                    id,
                    kind,
                })
                .collect(),
        ))
    }

    pub(crate) fn decide(
        &self,
        kind: &str,
        norm: &str,
        vec: Option<&[f32]>,
        same_as: Option<&str>,
    ) -> Decision {
        let known: Vec<Known> = self
            .0
            .iter()
            .map(|r| Known {
                id: &r.id,
                kind: &r.kind,
                norm: &r.norm,
                vec: r.vec.as_deref(),
            })
            .collect();
        decide(kind, norm, vec, same_as, &known)
    }

    /// A record saved in memory in this batch.
    pub(crate) fn add(&mut self, id: &str, kind: &str, norm: &str, vec: Option<&[f32]>) {
        self.0.push(Row {
            id: id.to_owned(),
            kind: kind.to_owned(),
            norm: norm.to_owned(),
            vec: vec.map(<[f32]>::to_vec),
        });
    }
}

/// Reinforces record `id`: support + 1, `last_seen_at` = `now`, and each of `sources` it does not
/// cite yet appended to its citations. The row is touched in `cs` first, so Undo can restore it.
pub async fn reinforce(
    conn: &mut SqliteConnection,
    cs: &mut ChangeSet,
    id: &str,
    sources: &[String],
    now: &str,
) -> Result<(), sqlx::Error> {
    cs.touch(conn, id).await?;
    sqlx::query("UPDATE records SET support = support + 1, last_seen_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(&mut *conn)
        .await?;
    let mut next: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(position) + 1, 0) FROM record_sources WHERE record = ?",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    for s in sources {
        let added = sqlx::query(
            "INSERT OR IGNORE INTO record_sources (record, source, position) VALUES (?, ?, ?)",
        )
        .bind(id)
        .bind(s)
        .bind(next)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        next += i64::from(added > 0);
    }
    Ok(())
}
