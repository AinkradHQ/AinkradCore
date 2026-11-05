//! What a session's gateway was last given (KAN-435 G5): its ceiling and the price snapshot of its
//! grant, kept on the session row. The Core prices a request from its book and, when the book has
//! lost the model, from the snapshot the gateway enforced; and it tops the ceiling up, or stops the
//! session, when the gateway has too little left to admit a turn.

use ainkrad_proto::v2::{Ceiling, ModelPrice};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;

use super::super::prices::{Price, Rates};

#[derive(Serialize, Deserialize)]
struct Snap {
    model: String,
    input: i64,
    output: i64,
    cache: i64,
    priced_at: String,
}

fn db(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn un(n: i64) -> u64 {
    if n == i64::MAX {
        u64::MAX
    } else {
        u64::try_from(n).unwrap_or(0)
    }
}

/// The grant's prices as rates, by model; none for a snapshot that does not read.
pub(super) fn snapshot_rates(json: Option<&str>) -> Vec<(String, Rates)> {
    let snaps: Vec<Snap> = json
        .and_then(|j| serde_json::from_str(j).ok())
        .unwrap_or_default();
    snaps
        .into_iter()
        .map(|s| {
            let rates = Rates {
                input: s.input,
                output: s.output,
                cache: s.cache,
                priced_at: s.priced_at,
            };
            (s.model, rates)
        })
        .collect()
}

/// Keeps what the gateway of `session` was granted: its ceiling and the prices it enforces.
pub async fn save_grant(
    pool: &SqlitePool,
    session: &str,
    ceiling: Ceiling,
    book: &[Price],
) -> Result<(), sqlx::Error> {
    let snaps: Vec<Snap> = book
        .iter()
        .map(|p| Snap {
            model: p.model.clone(),
            input: p.input_per_mtok_micro,
            output: p.output_per_mtok_micro,
            cache: p.cache_per_mtok_micro,
            priced_at: p.priced_at.clone(),
        })
        .collect();
    sqlx::query(
        "UPDATE core_agent_sessions SET gw_ceiling_tokens = ?, gw_ceiling_usd = ?, gw_prices = ? \
         WHERE id = ?",
    )
    .bind(db(ceiling.tokens))
    .bind(db(ceiling.usd_micros))
    .bind(serde_json::to_string(&snaps).expect("prices serialize"))
    .bind(session)
    .execute(pool)
    .await
    .map(drop)
}

/// The gateway of `session` has been given `ceiling` (an absolute total for its instance).
pub async fn set_ceiling(
    pool: &SqlitePool,
    session: &str,
    ceiling: Ceiling,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE core_agent_sessions SET gw_ceiling_tokens = ?, gw_ceiling_usd = ? WHERE id = ?",
    )
    .bind(db(ceiling.tokens))
    .bind(db(ceiling.usd_micros))
    .bind(session)
    .execute(pool)
    .await
    .map(drop)
}

/// The ceiling and prices the gateway of `session` runs with, if it was granted any.
pub async fn granted(
    pool: &SqlitePool,
    session: &str,
) -> Result<Option<(Ceiling, Vec<ModelPrice>)>, sqlx::Error> {
    let row: Option<(Option<i64>, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT gw_ceiling_tokens, gw_ceiling_usd, gw_prices FROM core_agent_sessions WHERE id = ?",
    )
    .bind(session)
    .fetch_optional(pool)
    .await?;
    let Some((Some(tokens), Some(usd), json)) = row else {
        return Ok(None);
    };
    let prices = snapshot_rates(json.as_deref())
        .into_iter()
        .map(|(model, r)| {
            let n = |v: i64| u64::try_from(v).unwrap_or(0);
            ModelPrice {
                model,
                input: n(r.input),
                output: n(r.output),
                cache_read: n(r.cache),
                cache_write: n(r.cache),
            }
        })
        .collect();
    let ceiling = Ceiling {
        tokens: un(tokens),
        usd_micros: un(usd),
    };
    Ok(Some((ceiling, prices)))
}

/// What the ledger holds for `session` under `epoch` (one gateway instance, spent from 0): tokens
/// as a ceiling counts them, and micro-dollars (an unpriced event counts 0).
pub async fn spent_in_epoch(
    pool: &SqlitePool,
    session: &str,
    epoch: i64,
) -> Result<(u64, u64), sqlx::Error> {
    let (tokens, usd): (i64, i64) = sqlx::query_as(
        "SELECT coalesce(sum(input_tokens + output_tokens + cache_tokens), 0), \
         coalesce(sum(cost_usd_micros), 0) FROM core_cost_events WHERE session = ? AND epoch = ?",
    )
    .bind(session)
    .bind(epoch)
    .fetch_one(pool)
    .await?;
    let n = |v: i64| u64::try_from(v).unwrap_or(0);
    Ok((n(tokens), n(usd)))
}

/// What the next `agent.read` acknowledges: the cursor, once a report of the session's current
/// epoch has moved it there. After a resume (epoch = `resumes`) it is 0 until then: a runner that
/// lost its state numbers again from 1, and acknowledging the old cursor would drop its new reports
/// unrecorded. A runner that kept its state loses nothing by it: its old reports stay held, and
/// the Core takes them first.
pub async fn ack_after(pool: &SqlitePool, session: &str) -> Result<u64, sqlx::Error> {
    let n: Option<i64> = sqlx::query_scalar(
        "SELECT iif(gw_epoch < resumes, 0, gw_seq) FROM core_agent_sessions WHERE id = ?",
    )
    .bind(session)
    .fetch_optional(pool)
    .await?;
    Ok(u64::try_from(n.unwrap_or(0)).unwrap_or(0))
}

/// The cursor of `session`: the newest report recorded and the epoch it was made under.
pub async fn cursor(pool: &SqlitePool, session: &str) -> Result<(i64, i64), sqlx::Error> {
    let row: Option<(i64, i64)> =
        sqlx::query_as("SELECT gw_epoch, gw_seq FROM core_agent_sessions WHERE id = ?")
            .bind(session)
            .fetch_optional(pool)
            .await?;
    Ok(row.unwrap_or((0, 0)))
}
