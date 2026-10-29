//! The cost ledger's dollars (E7.3, #15). A cost event is priced from the harness's own report
//! (Claude's `total_cost_usd`, OpenCode's session cost) when there is one, else from the latest
//! version of its harness and model's price (`set_price`), else not at all: its cost stays
//! NULL and `priced = 0`, never 0, and its run counts as unpriced. A harness billed by
//! subscription (`set_billing`) is recorded in tokens only. There is no built-in rate card: a
//! price nobody set is unknown, and says so.

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use ainkrad_core::exec::{Run, Usage};
use ainkrad_core::gov::{Billing, PriceId};
use ainkrad_core::org::{CompanyId, Harness};
use ainkrad_core::work::SprintId;
use serde_json::{Value, json};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row, SqliteConnection};

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

impl Price {
    /// What `u`'s tokens cost at this price, in millionths of a dollar, rounded half up.
    pub fn cost_of(&self, u: &Usage) -> i64 {
        let micros = i128::from(u.input_tokens) * i128::from(self.input_micros_per_mtok)
            + i128::from(u.output_tokens) * i128::from(self.output_micros_per_mtok)
            + i128::from(u.cache_tokens) * i128::from(self.cache_micros_per_mtok);
        i64::try_from((micros + 500_000) / 1_000_000).unwrap_or(i64::MAX)
    }
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

async fn append(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    details: Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: None,
        company_id: None,
        run_id: None,
        details: details.to_string(),
    };
    crate::store::audit::append(&mut *conn, &event)
        .await
        .map(drop)
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

/// `set_price`; with `past`, also prices the metered cost events of the harness and model that
/// have no dollars yet (a run's model is the one it used, else its agent's) at the new version,
/// in the same transaction: those events and their runs gain their dollars, the budgets'
/// dollar counters are recounted, and `price.set` says how many events (`recosted`). Events
/// that already have dollars keep them. Returns the price and the events re-costed.
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
    let mut tx = crate::store::begin_write(pool).await?;
    let p = sqlx::query(concat!(
        "INSERT INTO prices (harness, model, version, input_micros_per_mtok, \
         output_micros_per_mtok, cache_micros_per_mtok, created_at) VALUES (?1, ?2, \
         (SELECT coalesce(max(version), 0) + 1 FROM prices WHERE harness = ?1 AND model = ?2), \
         ?3, ?4, ?5, ?6) RETURNING ",
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
    let recosted = match past {
        true => recost_in(&mut tx, &p).await?,
        false => 0,
    };
    let details = json!({"price": p.id.0, "harness": harness.as_str(), "model": model,
                         "version": p.version, "input": input, "output": output,
                         "cache": cache, "apply_from": if past { "past" } else { "now" },
                         "recosted": recosted});
    append(&mut tx, actor, "price.set", details).await?;
    tx.commit().await?;
    Ok((p, recosted))
}

/// SQL: the model a run `r` (of agent `a`) works with.
macro_rules! run_model {
    () => {
        "coalesce(r.model_used, a.model)"
    };
}

async fn recost_in(conn: &mut SqliteConnection, p: &Price) -> Result<u64, Error> {
    let events = sqlx::query(concat!(
        "UPDATE cost_events SET priced = 1, price_id = ?1, cost_usd_micros = \
         (input_tokens * ?2 + output_tokens * ?3 + cache_tokens * ?4 + 500000) / 1000000 \
         WHERE priced = 0 AND billing = 'metered' AND run_id IN (SELECT r.id FROM runs r \
             JOIN agents a ON a.id = r.agent_id WHERE r.harness = ?5 AND ",
        run_model!(),
        " = ?6)"
    ))
    .bind(p.id.0)
    .bind(p.input_micros_per_mtok)
    .bind(p.output_micros_per_mtok)
    .bind(p.cache_micros_per_mtok)
    .bind(p.harness.as_str())
    .bind(&p.model)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    if events > 0 {
        // A run is priced once every one of its events is.
        sqlx::query(
            "UPDATE runs SET priced = 1, cost_usd_micros = (SELECT sum(cost_usd_micros) \
             FROM cost_events WHERE run_id = runs.id) WHERE priced = 0 AND harness = ?1 \
             AND coalesce(model_used, (SELECT model FROM agents WHERE id = runs.agent_id)) = ?2 \
             AND EXISTS (SELECT 1 FROM cost_events WHERE run_id = runs.id) \
             AND NOT EXISTS (SELECT 1 FROM cost_events WHERE run_id = runs.id AND priced = 0)",
        )
        .bind(p.harness.as_str())
        .bind(&p.model)
        .execute(&mut *conn)
        .await?;
        // ponytail: recounts every budget; scope it to the affected agents if this gets slow.
        super::budgets::recompute_in(conn, None).await?;
    }
    Ok(events)
}

/// A harness and model with metered spend that has no dollars, per account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpriced {
    pub harness: Harness,
    pub model: String,
    pub account_id: Option<i64>,
    pub runs: i64,
    pub tokens: i64,
}

/// The company's metered cost events with no dollars (no price when they were recorded), grouped
/// by harness, model and account, most tokens first. A price set since, from now on only, leaves
/// them here; `set_price_from` with `past` prices them.
pub async fn unpriced(pool: &SqlitePool, company: CompanyId) -> Result<Vec<Unpriced>, Error> {
    let rows = sqlx::query(concat!(
        "SELECT r.harness, ",
        run_model!(),
        " AS model, c.account_id, count(DISTINCT c.run_id) AS runs, \
         sum(c.input_tokens + c.output_tokens + c.cache_tokens) AS tokens \
         FROM cost_events c JOIN runs r ON r.id = c.run_id JOIN agents a ON a.id = c.agent_id \
         WHERE a.company_id = ? AND c.priced = 0 AND c.billing = 'metered' \
         GROUP BY r.harness, model, c.account_id ORDER BY tokens DESC, r.harness, model"
    ))
    .bind(company.0)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(Unpriced {
                harness: text(&row, "harness")?,
                model: row.try_get("model")?,
                account_id: row.try_get("account_id")?,
                runs: row.try_get("runs")?,
                tokens: row.try_get("tokens")?,
            })
        })
        .collect()
}

/// The latest version of every harness and model's price.
pub async fn list_prices(pool: &SqlitePool) -> Result<Vec<Price>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        price_columns!(),
        " FROM prices p WHERE version = (SELECT max(version) FROM prices q \
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
    pool: &SqlitePool,
    harness: Harness,
    model: &str,
) -> Result<Vec<(Price, String)>, Error> {
    let rows = sqlx::query(concat!(
        "SELECT ",
        price_columns!(),
        ", created_at FROM prices WHERE harness = ? AND model = ? ORDER BY version DESC"
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
    let mut tx = crate::store::begin_write(pool).await?;
    sqlx::query(
        "INSERT INTO harness_billing (harness, billing) VALUES (?, ?) \
         ON CONFLICT (harness) DO UPDATE SET billing = excluded.billing",
    )
    .bind(harness.as_str())
    .bind(billing.as_str())
    .execute(&mut *tx)
    .await?;
    let details = json!({"harness": harness.as_str(), "billing": billing.as_str()});
    append(&mut tx, actor, "billing.set", details).await?;
    tx.commit().await
}

/// How `harness` is paid for when a run has no account; metered unless set otherwise.
pub async fn harness_billing(pool: &SqlitePool, harness: Harness) -> Result<Billing, Error> {
    let billing: Option<String> =
        sqlx::query_scalar("SELECT billing FROM harness_billing WHERE harness = ?")
            .bind(harness.as_str())
            .fetch_optional(pool)
            .await?;
    Ok(match billing.as_deref() {
        Some("subscription") => Billing::Subscription,
        _ => Billing::Metered,
    })
}

/// How `run` is paid for: as its account (E15.1); with none, as its harness; metered unless
/// set otherwise.
pub(crate) async fn billing_in(conn: &mut SqliteConnection, run: &Run) -> Result<Billing, Error> {
    let billing: Option<String> = sqlx::query_scalar(
        "SELECT coalesce((SELECT a.billing FROM runs r JOIN accounts a ON a.id = r.account_id \
             WHERE r.id = ?1), (SELECT billing FROM harness_billing WHERE harness = ?2))",
    )
    .bind(run.id.0)
    .bind(run.harness.as_str())
    .fetch_one(&mut *conn)
    .await?;
    Ok(match billing.as_deref() {
        Some("subscription") => Billing::Subscription,
        _ => Billing::Metered,
    })
}

/// How a cost event of `run` is billed and what its `delta` tokens cost: `(billing, cost,
/// price)`. Subscription: no dollars. Metered: `reported` (the harness's cost of the run so
/// far, less what the ledger holds for it already, never below 0) when given; else the latest
/// price of the run's harness and the model it works with (its agent's, unless it fell back,
/// E15.3); else unknown (`None`).
pub(crate) async fn price_in(
    conn: &mut SqliteConnection,
    run: &Run,
    delta: &Usage,
    reported: Option<i64>,
) -> Result<(Billing, Option<i64>, Option<PriceId>), Error> {
    if billing_in(conn, run).await? == Billing::Subscription {
        return Ok((Billing::Subscription, None, None));
    }
    if let Some(reported) = reported {
        return Ok((Billing::Metered, Some(reported.max(0)), None));
    }
    let latest = sqlx::query(concat!(
        "SELECT ",
        price_columns!(),
        " FROM prices WHERE harness = ?1 AND model = coalesce(\
             (SELECT model_used FROM runs WHERE id = ?3), (SELECT model FROM agents WHERE id = ?2)) \
         ORDER BY version DESC LIMIT 1"
    ))
    .bind(run.harness.as_str())
    .bind(run.agent_id.0)
    .bind(run.id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(price)
    .transpose()?;
    Ok(match latest {
        Some(p) => (Billing::Metered, Some(p.cost_of(delta)), Some(p.id)),
        None => (Billing::Metered, None, None),
    })
}

/// Whose runs a cost report covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CostScope {
    Company(CompanyId),
    /// The runs on the sprint's issues (as they are now).
    Sprint(SprintId),
    /// The runs on the requirement's issues (E15.10).
    Requirement(ainkrad_core::work::RequirementId),
}

/// The runs that used tokens in a scope, and what they cost. Dollars are the priced runs'
/// only: an unpriced run is counted, with its tokens, never as $0.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CostReport {
    pub runs: i64,
    /// Metered runs whose every token is priced; `cost_usd_micros` is theirs.
    pub priced_runs: i64,
    pub unpriced_runs: i64,
    pub subscription_runs: i64,
    pub cost_usd_micros: i64,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub unpriced_tokens: i64,
    pub subscription_tokens: i64,
}

/// The cost report of `scope`; see `CostReport`.
pub async fn cost_report(pool: &SqlitePool, scope: CostScope) -> Result<CostReport, Error> {
    let (company, sprint, requirement) = match scope {
        CostScope::Company(c) => (Some(c.0), None, None),
        CostScope::Sprint(s) => (None, Some(s.0), None),
        CostScope::Requirement(r) => (None, None, Some(r.0)),
    };
    let row = sqlx::query(
        "WITH r AS (SELECT r.*, r.input_tokens + r.output_tokens + r.cache_tokens AS tokens, \
             EXISTS (SELECT 1 FROM cost_events c WHERE c.run_id = r.id \
                 AND c.billing = 'subscription') AS sub \
             FROM runs r JOIN agents a ON a.id = r.agent_id \
             WHERE (?1 IS NULL OR a.company_id = ?1) \
             AND (?2 IS NULL OR r.issue_id IN (SELECT id FROM issues WHERE sprint_id = ?2)) \
             AND (?3 IS NULL OR r.issue_id IN (SELECT id FROM issues WHERE requirement_id = ?3)) \
             AND EXISTS (SELECT 1 FROM cost_events c WHERE c.run_id = r.id)) \
         SELECT count(*) AS runs, \
             coalesce(sum(NOT sub AND priced = 1), 0) AS priced_runs, \
             coalesce(sum(NOT sub AND priced = 0), 0) AS unpriced_runs, \
             coalesce(sum(sub), 0) AS subscription_runs, \
             coalesce(sum(iif(NOT sub AND priced = 1, cost_usd_micros, 0)), 0) AS cost, \
             coalesce(sum(input_tokens), 0) AS input, coalesce(sum(output_tokens), 0) AS output, \
             coalesce(sum(cache_tokens), 0) AS cache, \
             coalesce(sum(iif(NOT sub AND priced = 0, tokens, 0)), 0) AS unpriced_tokens, \
             coalesce(sum(iif(sub, tokens, 0)), 0) AS subscription_tokens FROM r",
    )
    .bind(company)
    .bind(sprint)
    .bind(requirement)
    .fetch_one(pool)
    .await?;
    Ok(CostReport {
        runs: row.try_get("runs")?,
        priced_runs: row.try_get("priced_runs")?,
        unpriced_runs: row.try_get("unpriced_runs")?,
        subscription_runs: row.try_get("subscription_runs")?,
        cost_usd_micros: row.try_get("cost")?,
        input_tokens: row.try_get("input")?,
        output_tokens: row.try_get("output")?,
        cache_tokens: row.try_get("cache")?,
        unpriced_tokens: row.try_get("unpriced_tokens")?,
        subscription_tokens: row.try_get("subscription_tokens")?,
    })
}

/// The report as JSON, with dollars as a decimal string (exact) and the unpriced runs named
/// as such: `"unpriced": "3 runs"`.
pub fn cost_json(r: &CostReport) -> Value {
    let usd = format!(
        "{}.{:06}",
        r.cost_usd_micros / 1_000_000,
        r.cost_usd_micros % 1_000_000
    );
    json!({"runs": r.runs, "priced_runs": r.priced_runs, "cost_usd": usd,
           "cost_usd_micros": r.cost_usd_micros,
           "unpriced": format!("{} runs", r.unpriced_runs), "unpriced_runs": r.unpriced_runs,
           "unpriced_tokens": r.unpriced_tokens, "subscription_runs": r.subscription_runs,
           "subscription_tokens": r.subscription_tokens,
           "tokens": {"input": r.input_tokens, "output": r.output_tokens,
                      "cache": r.cache_tokens}})
}
