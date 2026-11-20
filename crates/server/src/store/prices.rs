//! Prices (KAN-449; design `2026-11-02-ai-provider-accounts` §7, §12 decision 2): what a million tokens
//! of a provider's model cost, in millionths of a dollar, and when the price was read. There is no
//! built-in rate card but the release's list prices of the known models ([`SHIPPED`], N35 K1): a
//! price nobody set (and no shipped one) is unknown, and a cost event that needs it is `unpriced`.
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

/// The provider list prices this release ships, as `(provider, model, input, output, cache read)`
/// in micro-dollars per million tokens (standard tier, text, short context). A price someone set
/// (`set`) always wins over these. Anthropic read 2026-11-11; OpenAI
/// (developers.openai.com/api/docs/pricing) and Gemini (aistudio.google.com/docs/pricing) read
/// 2026-11-19. Gemini rows whose price rises on 2026-12-01 or 2027-01-01 carry the higher, scheduled
/// price (an over-estimate is safe for a ceiling). A long-context rate is not a row: the default
/// ([`default_rates`]) covers it. Re-read them when a provider changes its list ([`shipped_at`]).
pub const SHIPPED: &[(&str, &str, i64, i64, i64)] = &[
    (
        "anthropic",
        "claude-opus-5-5",
        4_000_000,
        20_000_000,
        200_000,
    ),
    (
        "anthropic",
        "claude-sonnet-5-5",
        2_000_000,
        10_000_000,
        100_000,
    ),
    ("anthropic", "claude-haiku-5-5", 100_000, 500_000, 10_000),
    ("openai", "gpt-6.2-astra", 8_000_000, 40_000_000, 400_000),
    ("openai", "gpt-6.2-sol", 2_000_000, 10_000_000, 100_000),
    ("openai", "gpt-6-astra", 10_000_000, 50_000_000, 1_000_000),
    ("openai", "gpt-6.1-sol", 2_000_000, 10_000_000, 100_000),
    ("openai", "gpt-6.1-terra", 1_000_000, 5_000_000, 50_000),
    ("openai", "gpt-6-luna", 100_000, 500_000, 10_000),
    ("openai", "gpt-6-sol", 2_000_000, 10_000_000, 200_000),
    ("openai", "gpt-5.6-sol", 4_000_000, 20_000_000, 400_000),
    ("openai", "gpt-5.6-terra", 2_000_000, 12_000_000, 200_000),
    ("openai", "gpt-5.6-luna", 200_000, 1_200_000, 20_000),
    ("openai", "gpt-5.5", 5_000_000, 30_000_000, 500_000),
    ("openai", "gpt-5.5-pro", 30_000_000, 180_000_000, 30_000_000),
    ("openai", "gpt-5.4", 2_500_000, 15_000_000, 250_000),
    ("openai", "gpt-5.4-pro", 30_000_000, 180_000_000, 30_000_000),
    ("openai", "gpt-5.4-mini", 750_000, 4_500_000, 75_000),
    ("openai", "gpt-5.4-nano", 200_000, 1_250_000, 20_000),
    ("openai", "gpt-5.3-codex", 1_750_000, 14_000_000, 175_000),
    ("openai", "gpt-5.2", 1_750_000, 14_000_000, 175_000),
    ("openai", "gpt-5.1", 1_250_000, 10_000_000, 125_000),
    ("openai", "gpt-5", 1_250_000, 10_000_000, 125_000),
    ("openai", "gpt-5-mini", 250_000, 2_000_000, 25_000),
    ("openai", "gpt-5-nano", 50_000, 400_000, 5_000),
    ("openai", "gpt-4.1", 2_000_000, 8_000_000, 500_000),
    ("openai", "gpt-4.1-mini", 400_000, 1_600_000, 100_000),
    ("openai", "gpt-4o", 2_500_000, 10_000_000, 1_250_000),
    ("openai", "gpt-4o-mini", 150_000, 600_000, 75_000),
    ("openai", "o3", 2_000_000, 8_000_000, 500_000),
    ("google", "gemini-4-carbon", 4_000_000, 20_000_000, 200_000),
    ("google", "gemini-4-argon", 4_000_000, 20_000_000, 200_000),
    ("google", "gemini-4-neon", 3_000_000, 15_000_000, 150_000),
    ("google", "gemini-4-hydrogen", 1_500_000, 7_500_000, 75_000),
    ("google", "gemini-3.8-flash", 1_500_000, 7_500_000, 150_000),
    ("google", "gemini-3.6-flash", 1_500_000, 7_500_000, 150_000),
    (
        "google",
        "gemini-3.5-flash-lite",
        300_000,
        2_500_000,
        30_000,
    ),
    (
        "google",
        "gemini-3.1-pro-preview",
        2_000_000,
        12_000_000,
        200_000,
    ),
    (
        "google",
        "gemini-3.1-flash-lite",
        250_000,
        1_500_000,
        25_000,
    ),
    (
        "google",
        "gemini-3-flash-preview",
        500_000,
        3_000_000,
        50_000,
    ),
    ("google", "gemini-2.5-pro", 1_250_000, 10_000_000, 125_000),
    ("google", "gemini-2.5-flash", 300_000, 2_500_000, 30_000),
    ("google", "gemini-2.5-flash-lite", 100_000, 400_000, 10_000),
];

/// When a shipped provider's list was read.
fn shipped_at(provider: &str) -> &'static str {
    match provider {
        "anthropic" => "2026-11-11T00:00:00Z",
        _ => "2026-11-19T00:00:00Z",
    }
}

/// The highest list price of each built-in provider's models, long context included, as
/// `(provider, input, output)` in micro-dollars per million tokens: OpenAI gpt-5.5-pro and
/// gpt-5.4-pro above 272k ($60/$270), Anthropic Opus ($15/$75), Google's gemini-4 from 2026-12-01
/// ($4/$20; Pro above 200k is $4/$18). Read 2026-11-19. Raise a row when a provider lists more.
const MAX_LIST: [(&str, i64, i64); 3] = [
    ("openai", 60_000_000, 270_000_000),
    ("anthropic", 15_000_000, 75_000_000),
    ("google", 4_000_000, 20_000_000),
];

/// The flagged default rates `[input, output, cache]` of a model of a built-in provider that the
/// book and [`SHIPPED`] do not know, so a user's own model id never hard-fails. It is the
/// provider's [`MAX_LIST`] (cache read priced as input), at or above any real price, so a dollar
/// ceiling can only be over-counted. A provider with no row gets the highest of all.
fn default_rates(provider: &str) -> [i64; 3] {
    let (_, i, o) = MAX_LIST
        .iter()
        .find(|r| r.0 == provider)
        .copied()
        .unwrap_or(MAX_LIST[0]);
    [i, o, i]
}

/// The flagged default's `priced_at`: the epoch, which no real price has. The default lives in the
/// session's grant book only (so its cost events carry the flag as their rates' `priced_at`); the
/// Core's price book never holds it.
const DEFAULT_PRICED_AT: &str = "1970-01-01T00:00:00Z";

/// The flagged default price of `model`, for the grant's book.
pub fn default_price(provider: &str, model: &str) -> Price {
    let [input, output, cache] = default_rates(provider);
    Price {
        provider: provider.to_owned(),
        model: model.to_owned(),
        version: 0,
        input_per_mtok_micro: input,
        output_per_mtok_micro: output,
        cache_per_mtok_micro: cache,
        priced_at: DEFAULT_PRICED_AT.to_owned(),
        created_at: String::new(),
    }
}

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

/// The prices a gateway session of `provider` runs with: the price book's newest rows, and the
/// priced models of a user definition that the book does not have (its cache rate is its input
/// rate). The one source for the grant and for the allocator's one-turn room, so they cannot
/// disagree.
pub fn book_of(all: Vec<Price>, provider: &str, def: &providers::Definition) -> Vec<Price> {
    let mut book: Vec<Price> = all.into_iter().filter(|p| p.provider == provider).collect();
    let fallback: Vec<Price> = def
        .models
        .iter()
        .filter(|m| !book.iter().any(|p| p.model == m.id))
        .filter_map(|m| {
            let at = def.priced_at.as_ref().filter(|_| !def.builtin)?;
            Some(Price {
                provider: provider.to_owned(),
                model: m.id.clone(),
                version: 0,
                input_per_mtok_micro: m.input_per_mtok_micro,
                output_per_mtok_micro: m.output_per_mtok_micro,
                cache_per_mtok_micro: m.input_per_mtok_micro,
                priced_at: at.clone(),
                created_at: String::new(),
            })
        })
        .collect();
    book.extend(fallback);
    book
}

/// A book as the gateway's grant carries it.
pub fn model_prices(book: &[Price]) -> Vec<ainkrad_proto::v2::ModelPrice> {
    let rate = |n: i64| u64::try_from(n).unwrap_or(0);
    book.iter()
        .map(|p| ainkrad_proto::v2::ModelPrice {
            model: p.model.clone(),
            input: rate(p.input_per_mtok_micro),
            output: rate(p.output_per_mtok_micro),
            cache_read: rate(p.cache_per_mtok_micro),
            cache_write: rate(p.cache_per_mtok_micro),
        })
        .collect()
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
        return refused(
            "a price names a provider and a model of [A-Za-z0-9._:/-], exactly as the provider \
             names it: the gateway grants and compares model ids as they are and resolves no alias",
        );
    }
    if let Some(why) = super::provider_rules::model_problem(model) {
        return refused(why);
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

/// The newest price of every provider and model, by provider then model: the set ones, then the
/// shipped ones no one has set (version 0).
pub async fn list(pool: &SqlitePool) -> Result<Vec<Price>, sqlx::Error> {
    let mut all = booked(pool).await?;
    for &(provider, model, i, o, c) in SHIPPED {
        if !all
            .iter()
            .any(|p| p.provider == provider && p.model == model)
        {
            all.push(Price {
                provider: provider.to_owned(),
                model: model.to_owned(),
                version: 0,
                input_per_mtok_micro: i,
                output_per_mtok_micro: o,
                cache_per_mtok_micro: c,
                priced_at: shipped_at(provider).to_owned(),
                created_at: String::new(),
            });
        }
    }
    all.sort_by(|a, b| (&a.provider, &a.model).cmp(&(&b.provider, &b.model)));
    Ok(all)
}

async fn booked(pool: &SqlitePool) -> Result<Vec<Price>, sqlx::Error> {
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
    if let Some(&(_, _, input, output, cache)) = SHIPPED
        .iter()
        .find(|(p, m, ..)| *p == provider && *m == model)
    {
        return Ok(Some(Rates {
            input,
            output,
            cache,
            priced_at: shipped_at(provider).to_owned(),
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

#[cfg(test)]
mod shipped_tests {
    use super::*;

    #[test]
    fn the_default_is_at_or_above_every_shipped_and_documented_list_price() {
        for p in ["anthropic", "openai", "google"] {
            assert!(SHIPPED.iter().any(|s| s.0 == p), "{p}");
        }
        assert!(SHIPPED.iter().all(|s| s.2 > 0 && s.4 <= s.2));
        for &(p, m, i, o, c) in SHIPPED {
            let [di, d_o, dc] = default_rates(p);
            assert!(di >= i && d_o >= o && dc >= c, "{p}/{m}");
        }
        // The documented maxima (long context included): gpt-5.5-pro 60/270, Opus 4 15/75, gemini-4 4/20.
        for (p, i, o) in [
            ("openai", 60, 270),
            ("anthropic", 15, 75),
            ("google", 4, 20),
        ] {
            let [di, d_o, _] = default_rates(p);
            assert!(di >= i * 1_000_000 && d_o >= o * 1_000_000, "{p}");
        }
        let d = default_price("google", "gemini-next");
        assert_eq!(d.priced_at, "1970-01-01T00:00:00Z");
    }
}
