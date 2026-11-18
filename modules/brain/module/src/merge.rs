//! Merge-on-save (B4-01): a candidate fact the memory already holds reinforces that fact instead of
//! adding a row. The decision is the pure `brain_model::merge::decide`; this file loads what it
//! needs (stored and candidate vectors) and writes the reinforcement. The caller writes it inside
//! one change set, so Undo puts the old support, `last_seen_at` and citations back.

use std::collections::{HashMap, HashSet};

use ainkrad_core_server::api::App;
use brain_model::merge::{Decision, Grounding, Known, decide, may_supersede};
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
    try_prepare(app, b, pool, bodies).await.unwrap_or_default()
}

/// As `prepare`, but None when the model is off or fails (a re-distil must not archive on exact
/// matches alone, B6-01).
pub(crate) async fn try_prepare(
    app: &App,
    b: &Brain,
    pool: &SqlitePool,
    bodies: &[String],
) -> Option<Prepared> {
    if !crate::ai_semantic::available(app, b).await {
        return None;
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
    run.await
}

impl Prepared {
    /// No candidates, and the stored vectors of every one of `preps` (the memory of a whole run).
    pub(crate) fn stored_of(preps: &[Prepared]) -> Self {
        Self {
            cand: vec![],
            stored: preps
                .iter()
                .flat_map(|p| p.stored.iter().map(|(k, v)| (k.clone(), v.clone())))
                .collect(),
        }
    }

    #[cfg(test)]
    pub(crate) fn of(cand: Vec<Option<Vec<f32>>>, stored: HashMap<String, Vec<f32>>) -> Self {
        Self { cand, stored }
    }

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

/// The uncontested facts in force in the room (the `memory` view; a contested record is never
/// reinforced, B4-02 round 4) as the decision sees them, kept current as a
/// batch saves, so a fact worded twice in one answer merges with itself.
pub(crate) struct Memory(Vec<Row>);

impl Memory {
    pub(crate) async fn load(
        conn: &mut SqliteConnection,
        prep: &Prepared,
    ) -> Result<Self, sqlx::Error> {
        let rows: Vec<(String, String, String, Option<String>)> =
            sqlx::query_as("SELECT id, type, body, body_norm FROM memory WHERE contests IS NULL")
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

    /// The facts without a stored vector: no candidate can match them by meaning.
    pub(crate) fn unvectored(&self) -> Vec<String> {
        self.0
            .iter()
            .filter(|r| r.vec.is_none())
            .map(|r| r.id.clone())
            .collect()
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

    /// A record that left memory in this batch (superseded), so later candidates cannot merge into it.
    pub(crate) fn remove(&mut self, id: &str) {
        self.0.retain(|r| r.id != id);
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

/// Where a transcript source came from: its path is this plus the AI session id.
pub(crate) const SESSION_PATH: &str = "core://ai-session/";

/// Reinforces record `id`: `last_seen_at` = `now`, each of `sources` it does not cite yet appended
/// to its citations (each stamped with the distil `run` that cited it), then its support recounted
/// (`recount`), never incremented. A citation from a session in `loaded_by` (the sessions the Brain
/// gave `id` to, `brain_session_loaded`) is kept but marked `echo`: it is the record said back, not a
/// new origin. The row is touched in `cs` first, so Undo can restore it.
pub async fn reinforce(
    conn: &mut SqliteConnection,
    cs: &mut ChangeSet,
    id: &str,
    sources: &[String],
    run: &str,
    loaded_by: &HashSet<String>,
    now: &str,
) -> Result<(), sqlx::Error> {
    cs.touch(conn, id).await?;
    sqlx::query("UPDATE records SET last_seen_at = ? WHERE id = ?")
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
        let path: Option<String> = sqlx::query_scalar("SELECT path FROM sources WHERE item_id = ?")
            .bind(s)
            .fetch_optional(&mut *conn)
            .await?;
        let echo = path
            .as_deref()
            .and_then(|p| p.strip_prefix(SESSION_PATH))
            .is_some_and(|session| loaded_by.contains(session));
        let added = sqlx::query(
            "INSERT OR IGNORE INTO record_sources (record, source, position, run, echo) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(s)
        .bind(next)
        .bind(run)
        .bind(i64::from(echo))
        .execute(&mut *conn)
        .await?
        .rows_affected();
        next += i64::from(added > 0);
    }
    recount(conn, id).await
}

/// Sets record `id`'s support to the number of distinct origins that cite it (at least 1): an
/// origin is one AI session or one document (`sources.device` + `path`), so one source saying a
/// fact twice, or one session cut into several parts, counts once. `echo` citations do not count. A
/// cited source that is gone counts as its own origin. The same expression backfills `canon_0010`.
pub async fn recount(conn: &mut SqliteConnection, id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE records SET support = max(1, (\
             SELECT count(DISTINCT coalesce(s.device || char(10) || s.path, rs.source)) \
             FROM record_sources rs LEFT JOIN sources s ON s.item_id = rs.source \
             WHERE rs.record = records.id AND rs.echo = 0)) \
         WHERE id = ?",
    )
    .bind(id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// What a `replaces` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replace {
    /// `old` left memory, `new` took its place.
    Superseded,
    /// The evidence was too weak: `old` stays in force and `new.contests` names it, for room tidy
    /// (B9-01) to reconcile. Never an Inbox item: saving stays automatic.
    Contested,
    /// No such target in memory, or `old == new`: nothing written.
    Ignored,
}

/// Supersedes memory record `old` with `new` (B4-02), in `cs`, so Undo restores both rows. `old` keeps
/// its row as history: `superseded_by` = `new` and `valid_to` = the moment `new` became true (the
/// `memory` view filters on `valid_to`, so setting it is what removes `old` from memory); `new` gets
/// `supersedes` = `old` and that moment as `valid_from`. The moment is the earliest source `new` cites,
/// else `now`, never before `old` began.
///
/// Security model: a true record is never retired on weak evidence (`may_supersede`): `new` must be
/// of `old`'s kind and `g` must say it is grounded in one user turn (or, for a task or project
/// state, in one cited Jira or GitHub item), so an assistant turn, a tool result or a document cannot
/// retire a record of any kind. Without that, `old` stays in force and `new` is marked as contesting
/// it. Ignored: an `old` that is not in memory (unknown, archived, already superseded), or `old ==
/// new`. `new` must be saved and cited already.
pub async fn supersede(
    conn: &mut SqliteConnection,
    cs: &mut ChangeSet,
    old: &str,
    new: &str,
    g: Grounding,
    now: &str,
) -> Result<Replace, sqlx::Error> {
    if old == new {
        return Ok(Replace::Ignored);
    }
    let target: Option<(String, String)> =
        sqlx::query_as("SELECT type, coalesce(valid_from, created_at) FROM memory WHERE id = ?")
            .bind(old)
            .fetch_optional(&mut *conn)
            .await?;
    let Some((kind, began)) = target else {
        return Ok(Replace::Ignored);
    };
    let new_kind: Option<String> = sqlx::query_scalar("SELECT type FROM records WHERE id = ?")
        .bind(new)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(new_kind) = new_kind else {
        return Ok(Replace::Ignored);
    };
    if !may_supersede(&new_kind, &kind, g) {
        cs.touch(conn, new).await?;
        sqlx::query("UPDATE records SET contests = ? WHERE id = ?")
            .bind(old)
            .bind(new)
            .execute(&mut *conn)
            .await?;
        return Ok(Replace::Contested);
    }
    let first_source: Option<String> = sqlx::query_scalar(
        "SELECT min(s.started_at) FROM record_sources rs JOIN sources s ON s.item_id = rs.source WHERE rs.record = ?",
    )
    .bind(new)
    .fetch_one(&mut *conn)
    .await?;
    let at = first_source.unwrap_or_else(|| now.to_owned()).max(began);
    cs.touch(conn, old).await?;
    cs.touch(conn, new).await?;
    sqlx::query("UPDATE records SET valid_to = ?, superseded_by = ? WHERE id = ?")
        .bind(&at)
        .bind(new)
        .bind(old)
        .execute(&mut *conn)
        .await?;
    sqlx::query("UPDATE records SET valid_from = ?, supersedes = ? WHERE id = ?")
        .bind(&at)
        .bind(old)
        .bind(new)
        .execute(&mut *conn)
        .await?;
    Ok(Replace::Superseded)
}
