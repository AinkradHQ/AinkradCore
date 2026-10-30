//! The cost ledger's dollars (E7.3, #15). A cost event is priced from the harness's own report
//! (Claude's `total_cost_usd`, OpenCode's session cost) when there is one, else from the latest
//! version of its harness and model's price (`set_price`), else not at all: its cost stays
//! NULL and `priced = 0`, never 0, and its run counts as unpriced. A harness billed by
//! subscription (`set_billing`) is recorded in tokens only. There is no built-in rate card: a
//! price nobody set is unknown, and says so.
//!
//! Not ported (S7: they read the run table, `Run` and `Usage`): `Price::cost_of`, `billing_in`,
//! `price_in` (pricing one cost event as it is recorded), `unpriced`, `cost_report` and
//! `cost_json`, and re-costing past events (`set_price_from` with `past`, `recost_in`).

use ainkrad_core::audit::AuditActor;
use serde_json::{Value, json};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

use crate::domain::gov::{Billing, PriceId};
use crate::domain::org::Harness;
use crate::store::audit::{Event, append};
use crate::store::org::text;

/// One version of a harness and model's price, in millionths of a dollar per million tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Price {
    pub id: PriceId,
    pub harness: Harness,
    pub model: String,
    pub version: i64,
    pub input_micros_per_mtok: i64,
    pub output_micros_per_mtok: i64,
    pub cache_micros_per_mtok: i64,
}

macro_rules! price_columns {
    () => {
        "id, harness, model, version, input_micros_per_mtok, output_micros_per_mtok, \
         cache_micros_per_mtok"
    };
}

fn price(row: SqliteRow) -> Result<Price, Error> {
    Ok(Price {
        id: PriceId(row.try_get("id")?),
        harness: text(&row, "harness")?,
        model: row.try_get("model")?,
        version: row.try_get("version")?,
        input_micros_per_mtok: row.try_get("input_micros_per_mtok")?,
        output_micros_per_mtok: row.try_get("output_micros_per_mtok")?,
        cache_micros_per_mtok: row.try_get("cache_micros_per_mtok")?,
    })
}

async fn record(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    details: Value,
) -> Result<(), Error> {
    append(conn, Event::new(actor, action).details(details)).await
}

/// Stores the next version of `harness` and `model`'s price per million tokens (input, output,
/// cache, in millionths of a dollar), from `now` on, and appends `price.set` by `actor`. Earlier
/// cost events keep the version that priced them.
pub async fn set_price(
    pool: &SqlitePool,
    harness: Harness,
    model: &str,
    rates: [i64; 3],
    actor: AuditActor,
    now: &str,
) -> Result<Price, Error> {
    set_price_from(pool, harness, model, rates, false, actor, now)
        .await
        .map(|(p, _)| p)
}

/// `set_price`; the monolith's `past` also priced the metered cost events of the harness and
/// model that had no dollars yet. That needs the run table (S7): until then `past` is refused
/// (`Error::InvalidArgument`), and the events re-costed are always 0.
pub async fn set_price_from(
    pool: &SqlitePool,
    harness: Harness,
    model: &str,
    [input, output, cache]: [i64; 3],
    past: bool,
    actor: AuditActor,
    now: &str,
) -> Result<(Price, u64), Error> {
    let model = model.trim();
    if model.is_empty() || input < 0 || output < 0 || cache < 0 {
        let why = "a price needs a model and rates of 0 or more";
        return Err(Error::InvalidArgument(why.to_owned()));
    }
    if past {
        let why = "pricing past runs needs the run engine, which is not built yet";
        return Err(Error::InvalidArgument(why.to_owned()));
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let p = sqlx::query(concat!(
        "INSERT INTO citadel_prices (harness, model, version, input_micros_per_mtok, \
         output_micros_per_mtok, cache_micros_per_mtok, created_at) VALUES (?1, ?2, \
         (SELECT coalesce(max(version), 0) + 1 FROM citadel_prices WHERE harness = ?1 \
          AND model = ?2), ?3, ?4, ?5, ?6) RETURNING ",
        price_columns!()
    ))
    .bind(harness.as_str())
    .bind(model)
    .bind(input)
    .bind(output)
    .bind(cache)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .and_then(price)?;
    let details = json!({"price": p.id.0, "harness": harness.as_str(), "model": model,
                         "version": p.version, "input": input, "output": output,
                         "cache": cache, "apply_from": "now", "recosted": 0});
    record(&mut tx, actor, "price.set", details).await?;
    tx.commit().await?;
    Ok((p, 0))
}

/// The latest version of every harness and model's price.
pub async fn list_prices(pool: impl sqlx::SqliteExecutor<'_>) -> Result<Vec<Price>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        price_columns!(),
        " FROM citadel_prices p WHERE version = (SELECT max(version) FROM citadel_prices q \
         WHERE q.harness = p.harness AND q.model = p.model) ORDER BY harness, model"
    ))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(price)
    .collect()
}

/// Every version of `harness` and `model`'s price, newest first, each with when it took effect.
pub async fn price_history(
    pool: impl sqlx::SqliteExecutor<'_>,
    harness: Harness,
    model: &str,
) -> Result<Vec<(Price, String)>, Error> {
    let rows = sqlx::query(concat!(
        "SELECT ",
        price_columns!(),
        ", created_at FROM citadel_prices WHERE harness = ? AND model = ? ORDER BY version DESC"
    ))
    .bind(harness.as_str())
    .bind(model.trim())
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let at: String = row.try_get("created_at")?;
            Ok((price(row)?, at))
        })
        .collect()
}

/// Sets how `harness` is paid for, from the next cost event on, and appends `billing.set`. A
/// run with an account is billed as its account instead (E15.1); this is a new account's default.
pub async fn set_billing(
    pool: &SqlitePool,
    harness: Harness,
    billing: Billing,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    sqlx::query(
        "INSERT INTO citadel_harness_billing (harness, billing) VALUES (?, ?) \
         ON CONFLICT (harness) DO UPDATE SET billing = excluded.billing",
    )
    .bind(harness.as_str())
    .bind(billing.as_str())
    .execute(&mut *tx)
    .await?;
    let details = json!({"harness": harness.as_str(), "billing": billing.as_str()});
    record(&mut tx, actor, "billing.set", details).await?;
    tx.commit().await
}

/// How `harness` is paid for when a run has no account; metered unless set otherwise.
pub async fn harness_billing(
    pool: impl sqlx::SqliteExecutor<'_>,
    harness: Harness,
) -> Result<Billing, Error> {
    let billing: Option<String> =
        sqlx::query_scalar("SELECT billing FROM citadel_harness_billing WHERE harness = ?")
            .bind(harness.as_str())
            .fetch_optional(pool)
            .await?;
    Ok(match billing.as_deref() {
        Some("subscription") => Billing::Subscription,
        _ => Billing::Metered,
    })
}
