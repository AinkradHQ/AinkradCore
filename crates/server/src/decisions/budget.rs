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

/// The calls in flight and what they have reserved (E15 security review M11, M12). The Core's
/// service shares one ([`Gate::shared`]); a test service gets its own.
pub struct Gate {
    /// At most this many provider calls at once; another one falls back (`overloaded`).
    pub calls: tokio::sync::Semaphore,
    /// Micro-dollars reserved by calls in flight: counted with the day's spend before a call.
    reserved: tokio::sync::Mutex<i64>,
}

/// Provider calls in flight at once.
pub const MAX_IN_FLIGHT: usize = 3;
/// The prompt's fixed text, in tokens, on top of what a call carries.
const PROMPT_TOKENS: u64 = 200;

impl Gate {
    pub fn new() -> Self {
        Self {
            calls: tokio::sync::Semaphore::new(MAX_IN_FLIGHT),
            reserved: tokio::sync::Mutex::new(0),
        }
    }

    /// The process's one gate.
    pub fn shared() -> std::sync::Arc<Gate> {
        static G: std::sync::LazyLock<std::sync::Arc<Gate>> =
            std::sync::LazyLock::new(|| std::sync::Arc::new(Gate::new()));
        std::sync::Arc::clone(&G)
    }

    /// Reserves `usd` before a call: `false` when the day's spend plus every reservation in flight
    /// plus this one passes `cap` (a cap of 0 always does). Checked and taken under one lock, so
    /// parallel calls cannot all pass the check before any charge lands.
    pub async fn reserve(&self, pool: &SqlitePool, now: &str, cap: i64, usd: i64) -> bool {
        let mut held = self.reserved.lock().await;
        let spent = spent_today(pool, now).await.unwrap_or(i64::MAX);
        let total = spent.saturating_add(*held).saturating_add(usd);
        if cap <= 0 || total > cap {
            return false;
        }
        *held += usd;
        true
    }

    /// Ends a reservation of `usd` (its charge is now in the ledger, or was never owed).
    pub async fn release(&self, usd: i64) {
        let mut held = self.reserved.lock().await;
        *held = (*held - usd).max(0);
    }
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

/// The input tokens a call of `bytes` request text is estimated at (bytes / 4, plus the prompt).
pub fn estimate_tokens(bytes: usize) -> u64 {
    u64::try_from(bytes / 4).unwrap_or(u64::MAX).saturating_add(PROMPT_TOKENS)
}

/// One provider call's ledger row.
pub struct Charge<'a> {
    pub consumer: &'a str,
    /// The account billed; `None` for a failed call's estimate (no account answered).
    pub account: Option<i64>,
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
        account_id: c.account,
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
        assert_eq!(estimate_tokens(0), 200);
        assert_eq!(estimate_tokens(400), 300);
    }
}
