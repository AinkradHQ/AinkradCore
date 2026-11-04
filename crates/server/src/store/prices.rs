//! Prices (KAN-449; design `2026-11-02-ai-provider-accounts` §7, §12 decision 2): what a million tokens
//! of a provider's model cost, in millionths of a dollar, and when the price was read. There is no
//! built-in rate card: a price nobody set is unknown, and a cost event that needs it is `unpriced`.
//!
//! A price is versioned, never edited: a new price is a new row and an event keeps the rates that
//! priced it (`core_cost_events.rate_*`), so a later price never re-prices history. The newest row of
//! the price book wins; a user provider definition's own `models` list is the fallback when the book
//! has none (its cache rate is the input rate: a definition has no cache price). Changing a price
//! needs a step-up (the route's, `DESTRUCTIVE`): it changes what every later turn costs.

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::providers;
use super::secrets::Error;

/// A price above this many micro-dollars per million tokens is a typo, not a price.
pub const MAX_PRICE: i64 = 1_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Price {
    pub provider: String,
    pub model: String,
    pub version: i64,
    pub input_per_mtok_micro: i64,
    pub output_per_mtok_micro: i64,
    pub cache_per_mtok_micro: i64,
    /// When the provider's list price was read.
    pub priced_at: String,
    pub created_at: String,
}

/// The rates that priced an event, and when they were read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rates {
    pub input: i64,
    pub output: i64,
    pub cache: i64,
    pub priced_at: String,
}

impl Rates {
    /// Micro-dollars for the tokens, rounded half up; `None` only on overflow (a typo-sized count).
    pub fn cost(&self, input: i64, output: i64, cache: i64) -> Option<i64> {
        let sum = i128::from(input) * i128::from(self.input)
            + i128::from(output) * i128::from(self.output)
            + i128::from(cache) * i128::from(self.cache);
        i64::try_from((sum + 500_000) / 1_000_000).ok()
    }
}

fn refused<T>(message: &str) -> Result<T, Error> {
    Err(Error::Refused {
        code: "bad_request",
        message: message.to_owned(),
    })
}

/// A model id: 1 to 80 of `[A-Za-z0-9._:/-]` (a definition's own rule).
pub fn valid_model(s: &str) -> bool {
    (1..=80).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}

fn price(r: SqliteRow) -> Result<Price, sqlx::Error> {
    Ok(Price {
        provider: r.try_get("provider")?,
        model: r.try_get("model")?,
        version: r.try_get("version")?,
        input_per_mtok_micro: r.try_get("input_per_mtok_micro")?,
        output_per_mtok_micro: r.try_get("output_per_mtok_micro")?,
        cache_per_mtok_micro: r.try_get("cache_per_mtok_micro")?,
        priced_at: r.try_get("priced_at")?,
        created_at: r.try_get("created_at")?,
    })
}

const COLUMNS: &str = "provider, model, version, input_per_mtok_micro, output_per_mtok_micro, \
    cache_per_mtok_micro, priced_at, created_at";

/// Stores the next version of the price of `provider`'s `model`, in force from now on, and
/// appends `price.set`. `rates` is `[input, output, cache]`, micro-dollars per million tokens.
#[allow(clippy::too_many_arguments)]
pub async fn set(
    pool: &SqlitePool,
    provider: &str,
    model: &str,
    rates: [i64; 3],
    priced_at: &str,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Price, Error> {
    if !valid_model(model) || !(1..=32).contains(&provider.len()) {
        return refused("a price names a provider and a model of [A-Za-z0-9._:/-]");
    }
    if rates.iter().any(|r| !(0..=MAX_PRICE).contains(r)) {
        return refused("a price is 0 to 1000000000 micro-dollars per million tokens");
    }
    if priced_at.len() > 40 || !priced_at.ends_with('Z') {
        return refused("priced_at is a UTC timestamp, like 2026-11-02T00:00:00Z");
    }
    let mut tx = super::begin_write(pool).await?;
    // The provider must exist (a built-in or a definition), so a typo does not park a price.
    providers::get_in(&mut tx, provider).await?;
    let sql = format!(
        "INSERT INTO core_prices (provider, model, version, input_per_mtok_micro, \
         output_per_mtok_micro, cache_per_mtok_micro, priced_at, created_at) VALUES (?1, ?2, \
         (SELECT coalesce(max(version), 0) + 1 FROM core_prices WHERE provider = ?1 AND model = ?2), \
         ?3, ?4, ?5, ?6, ?7) RETURNING {COLUMNS}"
    );
    let p = match sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(provider)
        .bind(model)
        .bind(rates[0])
        .bind(rates[1])
        .bind(rates[2])
        .bind(priced_at)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
    {
        Ok(r) => price(r)?,
        // `priced_at` is not a date SQLite reads: the CHECK says so.
        Err(sqlx::Error::Database(e)) if e.is_check_violation() => {
            return refused("priced_at is not a valid timestamp");
        }
        Err(e) => return Err(e.into()),
    };
    let event = NewAuditEvent {
        actor,
        action: "price.set".to_owned(),
        entity: None,
        details: json!({"provider": provider, "model": model, "version": p.version,
                        "input": rates[0], "output": rates[1], "cache": rates[2],
                        "priced_at": priced_at, "by_device": by_device})
        .to_string(),
    };
    super::audit::append(&mut tx, &event).await?;
    tx.commit().await?;
    Ok(p)
}

/// The newest price of every provider and model, by provider then model.
pub async fn list(pool: &SqlitePool) -> Result<Vec<Price>, sqlx::Error> {
    let sql = format!(
        "SELECT {COLUMNS} FROM core_prices p WHERE version = (SELECT max(version) FROM core_prices q \
         WHERE q.provider = p.provider AND q.model = p.model) ORDER BY provider, model"
    );
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(price)
        .collect()
}

/// The rates in force for `provider`'s `model`, or `None` when nobody set a price.
pub async fn rates_in(
    conn: &mut SqliteConnection,
    provider: &str,
    model: &str,
) -> Result<Option<Rates>, sqlx::Error> {
    let booked: Option<SqliteRow> = sqlx::query(
        "SELECT input_per_mtok_micro, output_per_mtok_micro, cache_per_mtok_micro, priced_at \
         FROM core_prices WHERE provider = ? AND model = ? ORDER BY version DESC LIMIT 1",
    )
    .bind(provider)
    .bind(model)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(r) = booked {
        return Ok(Some(Rates {
            input: r.try_get("input_per_mtok_micro")?,
            output: r.try_get("output_per_mtok_micro")?,
            cache: r.try_get("cache_per_mtok_micro")?,
            priced_at: r.try_get("priced_at")?,
        }));
    }
    // A user definition's own list, read as of its newest version; a built-in has none.
    let Ok(def) = providers::get_in(conn, provider).await else {
        return Ok(None);
    };
    let (Some(m), Some(at)) = (def.models.iter().find(|m| m.id == model), def.priced_at) else {
        return Ok(None);
    };
    Ok(Some(Rates {
        input: m.input_per_mtok_micro,
        output: m.output_per_mtok_micro,
        cache: m.input_per_mtok_micro,
        priced_at: at,
    }))
}
