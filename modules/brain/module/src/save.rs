//! The save step of the pipeline (B3-03): candidates that passed `may_store`, admission and the judge
//! are merged (B4-01) or inserted, the dropped ones are logged, and all of it is ONE change set in
//! ONE transaction, so a single Undo puts the room back as it was before the distil.
//!
//! Security model: bodies are redacted before they are stored or logged. A dropped candidate's text
//! is kept only under the `bodies` key of its `admit.dropped` audit row (the 30-day purge of
//! `changes::purge_room` clears exactly that key), next to counts and reason codes that stay.

use std::collections::BTreeMap;

use ainkrad_proto::redact::Redactor;
use brain_model::merge::{Decision, body_norm};
use serde_json::json;
use sqlx::SqlitePool;

use crate::answer::Candidate;
use crate::changes::ChangeSet;
use crate::distil::{DistilledBy, auto_ok, log_op};
use crate::judge::Dropped;
use crate::merge::{Memory, Prepared, reinforce};
use crate::{policy, rand_id};

/// What one save did.
#[derive(Debug, PartialEq)]
pub(crate) struct Saved {
    /// Rows added (accepted into memory or waiting in the Inbox).
    pub saved: i64,
    /// Of those, accepted straight into memory.
    pub accepted: i64,
    /// Existing facts that were repeated instead of getting a new row.
    pub reinforced: i64,
    /// Candidates dropped before the save (not records; logged in `admit.dropped`).
    pub dropped: i64,
    /// The change set, when anything changed.
    pub change: Option<String>,
}

/// Writes `out` into the room as `records` with their op-log and outbox rows, in one transaction;
/// kinds the room auto-accepts go straight to `accepted`. A candidate the memory already holds
/// (B4-01) reinforces that record instead of adding a row. `dropped` is logged as one
/// `admit.dropped` audit row, and the distil's parked judge state (`distil.pending`) is removed in
/// the same transaction, so a rerun can never save twice. One change set: "Saved N · reinforced M ·
/// dropped K". `ai` marks a proposal from an AI session (`ai_propose.rs`): its rows get
/// `origin = 'ai'` and its change set is of kind `ai`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn store_candidates(
    pool: &SqlitePool,
    distil: &str,
    out: &[Candidate],
    dropped: &[Dropped],
    policy: &policy::Policy,
    by: &DistilledBy,
    now: &str,
    prep: &Prepared,
    ai: bool,
) -> Result<Saved, sqlx::Error> {
    let redactor = Redactor::new();
    let (mut n, mut accepted, mut reinforced) = (0, 0, 0);
    let mut tx = pool.begin().await?;
    let mut cs = ChangeSet::new(if ai { "ai" } else { "distil" }, now);
    let mut memory = Memory::load(&mut tx, prep).await?;
    for (i, c) in out.iter().enumerate() {
        let body = redactor.text(c.body.trim());
        let norm = body_norm(&body);
        let same_as = c.same_as.as_deref();
        if let Decision::Reinforce { id, .. } =
            memory.decide(&c.kind, &norm, prep.candidate(i), same_as)
        {
            reinforce(&mut tx, &mut cs, &id, &c.sources, now).await?;
            reinforced += 1;
            continue;
        }
        let id = rand_id("rec-");
        cs.touch(&mut tx, &id).await?;
        let auto_ok = auto_ok(c, policy);
        sqlx::query(
            "INSERT INTO records (id, type, status, body, tags, source_ids, created_at, reviewed_at, decided_by, distil, provider, account, tool, body_norm, last_seen_at, origin) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&c.kind)
        .bind(if auto_ok { "accepted" } else { "candidate" })
        .bind(&body)
        .bind(json!(c.tags).to_string())
        .bind(json!(c.sources).to_string())
        .bind(now)
        .bind(auto_ok.then_some(now))
        .bind(auto_ok.then_some("auto"))
        .bind(distil)
        .bind(&by.provider)
        .bind(&by.account)
        .bind(&by.tool)
        .bind(&norm)
        .bind(now)
        .bind(if ai { "ai" } else { "distil" })
        .execute(&mut *tx)
        .await?;
        for (pos, s) in c.sources.iter().enumerate() {
            sqlx::query(
                "INSERT OR IGNORE INTO record_sources (record, source, position) VALUES (?, ?, ?)",
            )
            .bind(&id)
            .bind(s)
            .bind(pos as i64)
            .execute(&mut *tx)
            .await?;
        }
        if auto_ok {
            memory.add(&id, &c.kind, &norm, prep.candidate(i));
        }
        log_op(
            &mut tx,
            if auto_ok {
                "record.accepted"
            } else {
                "record.candidate"
            },
            &id,
            now,
        )
        .await?;
        n += 1;
        accepted += i64::from(auto_ok);
    }
    let k = i64::try_from(dropped.len()).unwrap_or(i64::MAX);
    if !dropped.is_empty() {
        let mut reasons: BTreeMap<&str, i64> = BTreeMap::new();
        for r in dropped.iter().flat_map(|d| &d.reasons) {
            *reasons.entry(r.as_str()).or_default() += 1;
        }
        sqlx::query("INSERT INTO room_audit (action, detail, at) VALUES ('admit.dropped', ?, ?)")
            .bind(
                json!({"distil": distil, "count": k, "reasons": reasons, "bodies": dropped})
                    .to_string(),
            )
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "DELETE FROM room_audit WHERE action = 'distil.pending' \
         AND json_extract(detail, '$.distil') = ?",
    )
    .bind(distil)
    .execute(&mut *tx)
    .await?;
    let summary = format!("Saved {n} · reinforced {reinforced} · dropped {k}");
    let change = cs
        .commit(
            &mut tx,
            &summary,
            json!({"saved": n, "reinforced": reinforced, "dropped": k}),
        )
        .await?;
    tx.commit().await?;
    Ok(Saved {
        saved: n,
        accepted,
        reinforced,
        dropped: k,
        change,
    })
}

#[cfg(test)]
#[path = "save_tests.rs"]
mod tests;
