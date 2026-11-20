//! The Decisions cost cap (§2.3): each provider call is one row in the cost ledger
//! (`store::costs::record_in`, subject `agent` = `decisions:<consumer>`), and the day's spend is the
//! sum of those rows since UTC midnight. At `decisions.daily_usd_micros` there is no provider until
//! the next UTC day: every consumer uses its fallback.
//!
//! The ledger's harness column is a closed set; Google's own harness, `agy`, is the one a Google
//! model's rows carry, and the `decisions:` session says what the row really is.

use sqlx::sqlite::SqlitePool;

use crate::store::{self, costs};

/// The ledger session of a consumer's calls: `decisions:<consumer>`.
pub fn subject(consumer: &str) -> String {
    format!("decisions:{consumer}")
}

/// Micro-dollars for `tokens` input tokens at `price` micro-dollars per million, rounded up so a
/// call is never free.
pub fn cost_micros(tokens: u64, price_per_mtok: i64) -> i64 {
    let n = u128::from(tokens) * u128::try_from(price_per_mtok.max(0)).unwrap_or(0);
    i64::try_from(n.div_ceil(1_000_000)).unwrap_or(i64::MAX)
}

/// What the Decisions service spent since `now`'s UTC midnight, in micro-dollars.
pub async fn spent_today(pool: &SqlitePool, now: &str) -> Result<i64, sqlx::Error> {
    let midnight = format!("{}T00:00:00.000Z", now.get(..10).unwrap_or("1970-01-01"));
    sqlx::query_scalar(
        "SELECT COALESCE(SUM(cost_usd_micros), 0) FROM core_cost_events \
         WHERE session LIKE 'decisions:%' AND occurred_at >= ?",
    )
    .bind(midnight)
    .fetch_one(pool)
    .await
}

/// Whether the day's spend has reached `cap` (a cap of 0 is always reached).
pub async fn cap_reached(pool: &SqlitePool, now: &str, cap: i64) -> Result<bool, sqlx::Error> {
    Ok(spent_today(pool, now).await? >= cap)
}

/// One provider call's ledger row.
pub struct Charge<'a> {
    pub consumer: &'a str,
    pub account: i64,
    pub model: &'a str,
    pub input_tokens: u64,
    pub usd_micros: i64,
}

/// Records `c` in the ledger. A failure is the caller's to log, never a reason to drop an answer
/// it already has.
pub async fn record(pool: &SqlitePool, c: &Charge<'_>, now: &str) -> Result<(), String> {
    let session = subject(c.consumer);
    let key = crate::auth::crypto::random_id("dc_");
    let cost = costs::NewCost {
        session: &session,
        epoch: 0,
        account_id: Some(c.account),
        legacy_account_id: None,
        provider: "google",
        harness: "agy",
        model: c.model,
        input_tokens: i64::try_from(c.input_tokens).unwrap_or(i64::MAX),
        output_tokens: 0,
        cache_tokens: 0,
        reported_usd_micros: Some(c.usd_micros),
        approximate: false,
        subjects: &[("agent", session.as_str())],
        idempotency_key: &key,
        occurred_at: now,
    };
    let mut tx = store::begin_write(pool).await.map_err(|e| e.to_string())?;
    costs::record_in(&mut tx, &cost, now)
        .await
        .map_err(|_| "the ledger refused the row".to_owned())?;
    tx.commit().await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_costs_its_tokens_at_the_price_rounded_up() {
        // 100_000 micro-dollars per million tokens is $0.10 / M.
        assert_eq!(cost_micros(1_000_000, 100_000), 100_000);
        assert_eq!(cost_micros(812, 100_000), 82);
        assert_eq!(cost_micros(1, 100_000), 1);
        assert_eq!(cost_micros(0, 100_000), 0);
        assert_eq!(cost_micros(500, -5), 0);
        assert_eq!(subject("heavy_job"), "decisions:heavy_job");
    }
}
