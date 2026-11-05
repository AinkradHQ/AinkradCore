//! The cost ledger (KAN-449; design `2026-11-02-ai-provider-accounts` §7, §11b item 2, §12d): usage
//! and cost per ATTEMPT, keyed by session, epoch and account, with the model and harness, the cost
//! basis and whether the turn was cut short. Moved here from Citadel's `citadel_cost_events`.
//!
//! - **A row is a delta.** One attempt's tokens, never a running total (a runner restarts its meter
//!   each run), so a restart or a failover cannot lose or double a turn. A retried report with the
//!   same `idempotency_key` is a no-op that answers the first row; the same key with a different
//!   payload is a `conflict`.
//! - **Insert-only.** The database refuses an update or a delete. A correction (the provider's bill
//!   differs from the estimate) is a new `billing_corrected` row holding the difference, so a sum
//!   over the ledger is always the corrected total.
//! - **Cost basis.** The provider's own report wins (`provider_reported`); else the list price in
//!   force (`list_price`, with the rates kept on the row); else the event is `unpriced` with a NULL
//!   cost, never 0, and the totals say how many events were unpriced.
//! - **Subjects.** Who an event counts against (agent, company, department, project, sprint, issue)
//!   is what the caller attributes it to, as opaque ids; the account and every pool it was in are
//!   added here. The budget engine (KAN-448) reads them; nothing here knows a Citadel table.
//! - **Callers.** The run engine and Citadel record through [`record_in`]; no HTTP route writes the
//!   ledger, so a device cannot forge a cost.

use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::budgets::guard::{self, Guard};
use super::prices;
use super::secrets::Error;

pub const HARNESSES: [&str; 4] = ["claude", "codex", "opencode", "agy"];
/// The subject kinds a caller may attribute an event to; `account` and `pool` are added here.
pub const CALLER_SUBJECTS: [&str; 6] = [
    "agent",
    "company",
    "department",
    "project",
    "sprint",
    "issue",
];
const MAX_SUBJECTS: usize = 16;

/// An attempt's usage to record. `account_id` is a Core account; `legacy_account_id` is the id of
/// Citadel's own account store until that store moves into Core.
#[derive(Debug, Clone, Copy)]
pub struct NewCost<'a> {
    pub session: &'a str,
    pub epoch: i64,
    pub account_id: Option<i64>,
    pub legacy_account_id: Option<i64>,
    pub provider: &'a str,
    pub harness: &'a str,
    pub model: &'a str,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    /// What the provider itself reported for the attempt, micro-dollars.
    pub reported_usd_micros: Option<i64>,
    /// The turn was interrupted: the tokens are the meter's last reading.
    pub approximate: bool,
    /// `(kind, id)` of [`CALLER_SUBJECTS`]; ids are 1 to 64 of `[A-Za-z0-9._:-]`.
    pub subjects: &'a [(&'a str, &'a str)],
    pub idempotency_key: &'a str,
    /// When the usage happened (not when it was recorded).
    pub occurred_at: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostEvent {
    pub id: i64,
    pub session: String,
    pub epoch: i64,
    pub account_id: Option<i64>,
    pub legacy_account_id: Option<i64>,
    pub provider: String,
    pub harness: String,
    pub model: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cache_tokens: i64,
    pub cost_usd_micros: Option<i64>,
    /// `list_price`, `provider_reported`, `billing_corrected` or `unpriced`.
    pub basis: String,
    pub approximate: bool,
    pub priced_at: Option<String>,
    pub corrects_id: Option<i64>,
    pub occurred_at: String,
}

/// What [`record_in`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    pub event: CostEvent,
    /// The key was already recorded: nothing was written, `event` is the first row.
    pub duplicate: bool,
    /// What the budgets said once the event was counted (nothing for a duplicate).
    pub guard: Guard,
}

/// The ledger's totals: events, tokens, priced dollars, and how many events have no price.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Totals {
    pub events: i64,
    pub tokens: i64,
    pub cost_usd_micros: i64,
    pub unpriced: i64,
}

pub fn valid_subject_id(s: &str) -> bool {
    super::pools::valid_agent(s)
}

fn refused<T>(message: impl Into<String>) -> Result<T, Error> {
    Err(Error::Refused {
        code: "bad_request",
        message: message.into(),
    })
}

macro_rules! columns {
    () => {
        "id, session, epoch, account_id, legacy_account_id, provider, harness, model, \
         input_tokens, output_tokens, cache_tokens, cost_usd_micros, basis, approximate, \
         priced_at, corrects_id, occurred_at"
    };
}

pub(crate) fn event(r: &SqliteRow) -> Result<CostEvent, sqlx::Error> {
    Ok(CostEvent {
        id: r.try_get("id")?,
        session: r.try_get("session")?,
        epoch: r.try_get("epoch")?,
        account_id: r.try_get("account_id")?,
        legacy_account_id: r.try_get("legacy_account_id")?,
        provider: r.try_get("provider")?,
        harness: r.try_get("harness")?,
        model: r.try_get("model")?,
        input_tokens: r.try_get("input_tokens")?,
        output_tokens: r.try_get("output_tokens")?,
        cache_tokens: r.try_get("cache_tokens")?,
        cost_usd_micros: r.try_get("cost_usd_micros")?,
        basis: r.try_get("basis")?,
        approximate: r.try_get::<i64, _>("approximate")? == 1,
        priced_at: r.try_get("priced_at")?,
        corrects_id: r.try_get("corrects_id")?,
        occurred_at: r.try_get("occurred_at")?,
    })
}

fn check(c: &NewCost<'_>) -> Result<(), Error> {
    if c.session.is_empty()
        || c.session.len() > 64
        || c.idempotency_key.is_empty()
        || c.idempotency_key.len() > 128
    {
        return refused("a session is 1 to 64 characters and a key 1 to 128");
    }
    if c.account_id.is_some() && c.legacy_account_id.is_some() {
        return refused("an event names a Core account or a legacy account, not both");
    }
    if !HARNESSES.contains(&c.harness) {
        return refused(format!("harness is one of {}", HARNESSES.join(", ")));
    }
    if !(1..=32).contains(&c.provider.len()) || !prices::valid_model(c.model) {
        return refused("a cost names a provider and a model of [A-Za-z0-9._:/-]");
    }
    let counts = [c.epoch, c.input_tokens, c.output_tokens, c.cache_tokens];
    if counts.iter().any(|n| *n < 0) || c.reported_usd_micros.is_some_and(|n| n < 0) {
        return refused("an epoch, a token count and a reported cost are 0 or more");
    }
    if c.subjects.len() > MAX_SUBJECTS
        || c.subjects
            .iter()
            .any(|(k, id)| !CALLER_SUBJECTS.contains(k) || !valid_subject_id(id))
    {
        return refused(format!(
            "at most {MAX_SUBJECTS} subjects, each of {} with an id of 1 to 64 of [A-Za-z0-9._:-]",
            CALLER_SUBJECTS.join(", ")
        ));
    }
    Ok(())
}

/// Records one attempt's usage in the caller's transaction (so a budget counter, when KAN-448's
/// engine runs there, moves with it). Idempotent by `idempotency_key`.
pub async fn record_in(
    conn: &mut SqliteConnection,
    c: &NewCost<'_>,
    now: &str,
) -> Result<Recorded, Error> {
    record_priced_in(conn, c, Pricing::Book, now).await
}

/// Where a cost comes from when the provider reported none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pricing {
    /// The Core's price book (then a user definition's own list).
    Book,
    /// The caller's own rates (a module's price book, which has not moved into the Core's yet).
    Own(prices::Rates),
    /// Nobody prices it: a harness billed by subscription records tokens only.
    Unpriced,
}

/// [`record_in`] with the caller saying how an unreported cost is priced.
pub async fn record_priced_in(
    conn: &mut SqliteConnection,
    c: &NewCost<'_>,
    pricing: Pricing,
    now: &str,
) -> Result<Recorded, Error> {
    check(c)?;
    if let Some(r) = sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM core_cost_events WHERE idempotency_key = ?"
    ))
    .bind(c.idempotency_key)
    .fetch_optional(&mut *conn)
    .await?
    {
        let first = event(&r)?;
        let same = first.session == c.session
            && first.epoch == c.epoch
            && first.account_id == c.account_id
            && first.legacy_account_id == c.legacy_account_id
            && first.provider == c.provider
            && first.harness == c.harness
            && first.model == c.model
            && (first.input_tokens, first.output_tokens, first.cache_tokens)
                == (c.input_tokens, c.output_tokens, c.cache_tokens);
        if !same {
            return Err(Error::Refused {
                code: "conflict",
                message: "that idempotency key recorded a different event".to_owned(),
            });
        }
        return Ok(Recorded {
            event: first,
            duplicate: true,
            guard: Guard::default(),
        });
    }
    let rates = match (c.reported_usd_micros, pricing) {
        (Some(_), _) | (None, Pricing::Unpriced) => None,
        (None, Pricing::Own(r)) => Some(r),
        (None, Pricing::Book) => prices::rates_in(conn, c.provider, c.model).await?,
    };
    let (cost, basis, rates) = match (c.reported_usd_micros, rates) {
        (Some(usd), _) => (Some(usd), "provider_reported", None),
        (None, Some(r)) => match r.cost(c.input_tokens, c.output_tokens, c.cache_tokens) {
            Some(usd) => (Some(usd), "list_price", Some(r)),
            None => return refused("those token counts overflow a cost"),
        },
        (None, None) => (None, "unpriced", None),
    };
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO core_cost_events (session, epoch, account_id, legacy_account_id, provider, \
         harness, model, input_tokens, output_tokens, cache_tokens, cost_usd_micros, basis, \
         approximate, rate_input, rate_output, rate_cache, priced_at, idempotency_key, \
         occurred_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(c.session)
    .bind(c.epoch)
    .bind(c.account_id)
    .bind(c.legacy_account_id)
    .bind(c.provider)
    .bind(c.harness)
    .bind(c.model)
    .bind(c.input_tokens)
    .bind(c.output_tokens)
    .bind(c.cache_tokens)
    .bind(cost)
    .bind(basis)
    .bind(c.approximate)
    .bind(rates.as_ref().map(|r| r.input))
    .bind(rates.as_ref().map(|r| r.output))
    .bind(rates.as_ref().map(|r| r.cache))
    .bind(rates.as_ref().map(|r| r.priced_at.as_str()))
    .bind(c.idempotency_key)
    .bind(c.occurred_at)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;
    add_subjects(conn, id, c.account_id, c.subjects).await?;
    // What counts against a budget is what the gateway counts against a ceiling: the one definition
    // (`ceiling_tokens`), so what the gateway refuses and what the ledger holds cannot drift. The
    // counts are checked non-negative above; the sum saturates instead of overflowing.
    let count = |n: i64| u64::try_from(n).unwrap_or(0);
    let tokens = i64::try_from(ainkrad_proto::v2::ceiling_tokens(
        count(c.input_tokens),
        count(c.output_tokens),
        count(c.cache_tokens),
        0,
    ))
    .unwrap_or(i64::MAX);
    guard::apply_in(
        conn,
        id,
        c.session,
        tokens,
        cost.unwrap_or(0),
        c.occurred_at,
    )
    .await?;
    let guard = guard::check_in(conn, id, c.occurred_at, now).await?;
    let r = sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM core_cost_events WHERE id = ?"
    ))
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(Recorded {
        event: event(&r)?,
        duplicate: false,
        guard,
    })
}

async fn add_subjects(
    conn: &mut SqliteConnection,
    id: i64,
    account: Option<i64>,
    subjects: &[(&str, &str)],
) -> Result<(), sqlx::Error> {
    for (kind, subject) in subjects {
        sqlx::query(
            "INSERT OR IGNORE INTO core_cost_subjects (event_id, kind, subject_id) VALUES (?, ?, ?)",
        )
        .bind(id)
        .bind(kind)
        .bind(subject)
        .execute(&mut *conn)
        .await?;
    }
    if let Some(a) = account {
        sqlx::query(
            "INSERT INTO core_cost_subjects (event_id, kind, subject_id) VALUES (?1, 'account', ?2)",
        )
        .bind(id)
        .bind(a.to_string())
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "INSERT INTO core_cost_subjects (event_id, kind, subject_id) \
             SELECT ?1, 'pool', CAST(pool_id AS TEXT) FROM core_pool_members WHERE account_id = ?2",
        )
        .bind(id)
        .bind(a)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Records that the provider's bill puts event `id` (and any earlier correction of it) at
/// `corrected_usd_micros` in all: a new `billing_corrected` row of the difference, counted against
/// the same account and subjects, so the ledger sums to the corrected cost. `None` when it already
/// does, or the key was used. The correction counts in the period of the event it corrects.
pub async fn correct_in(
    conn: &mut SqliteConnection,
    id: i64,
    corrected_usd_micros: i64,
    idempotency_key: &str,
    now: &str,
) -> Result<Option<Recorded>, Error> {
    if corrected_usd_micros < 0 || idempotency_key.is_empty() || idempotency_key.len() > 128 {
        return refused("a corrected cost is 0 or more, with a key of 1 to 128 characters");
    }
    let Some(r) = sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM core_cost_events WHERE id = ? AND corrects_id IS NULL"
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Err(Error::Refused {
            code: "not_found",
            message: "no such cost event (a correction is of an original)".to_owned(),
        });
    };
    let o = event(&r)?;
    let so_far: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(cost_usd_micros), 0) FROM core_cost_events \
         WHERE id = ?1 OR corrects_id = ?1",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    let delta = corrected_usd_micros - so_far;
    if delta == 0 {
        return Ok(None);
    }
    let new: Option<i64> = sqlx::query_scalar(
        "INSERT INTO core_cost_events (session, epoch, account_id, legacy_account_id, provider, \
         harness, model, input_tokens, output_tokens, cache_tokens, cost_usd_micros, basis, \
         approximate, corrects_id, idempotency_key, occurred_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, 'billing_corrected', 0, ?, ?, ?, ?) \
         ON CONFLICT (idempotency_key) DO NOTHING RETURNING id",
    )
    .bind(&o.session)
    .bind(o.epoch)
    .bind(o.account_id)
    .bind(o.legacy_account_id)
    .bind(&o.provider)
    .bind(&o.harness)
    .bind(&o.model)
    .bind(delta)
    .bind(id)
    .bind(idempotency_key)
    .bind(&o.occurred_at)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(new) = new else {
        return Ok(None);
    };
    sqlx::query(
        "INSERT INTO core_cost_subjects (event_id, kind, subject_id) \
         SELECT ?1, kind, subject_id FROM core_cost_subjects WHERE event_id = ?2",
    )
    .bind(new)
    .bind(id)
    .execute(&mut *conn)
    .await?;
    guard::apply_in(conn, new, &o.session, 0, delta, &o.occurred_at).await?;
    let guard = guard::check_in(conn, new, &o.occurred_at, now).await?;
    let r = sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM core_cost_events WHERE id = ?"
    ))
    .bind(new)
    .fetch_one(&mut *conn)
    .await?;
    Ok(Some(Recorded {
        event: event(&r)?,
        duplicate: false,
        guard,
    }))
}

/// The newest events first, of one session and/or one account, at most `limit`.
pub async fn list(
    pool: &SqlitePool,
    session: Option<&str>,
    account: Option<i64>,
    limit: i64,
) -> Result<Vec<CostEvent>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM core_cost_events WHERE (?1 IS NULL OR session = ?1) \
         AND (?2 IS NULL OR account_id = ?2) ORDER BY id DESC LIMIT ?3"
    ))
    .bind(session)
    .bind(account)
    .bind(limit)
    .fetch_all(pool)
    .await?
    .iter()
    .map(event)
    .collect()
}

/// The whole ledger's totals (corrections included in the dollars).
pub async fn totals(conn: &mut SqliteConnection) -> Result<Totals, sqlx::Error> {
    let (events, tokens, cost, unpriced): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(sum(input_tokens + output_tokens + cache_tokens), 0), \
         coalesce(sum(cost_usd_micros), 0), coalesce(sum(basis = 'unpriced'), 0) \
         FROM core_cost_events",
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(Totals {
        events,
        tokens,
        cost_usd_micros: cost,
        unpriced,
    })
}

/// What a session has recorded: input, output and cache tokens, and the dollars (corrections
/// included; unpriced events count 0).
pub async fn session_totals(
    conn: &mut SqliteConnection,
    session: &str,
) -> Result<[i64; 4], sqlx::Error> {
    let (i, o, c, usd): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT coalesce(sum(input_tokens), 0), coalesce(sum(output_tokens), 0), \
         coalesce(sum(cache_tokens), 0), coalesce(sum(cost_usd_micros), 0) \
         FROM core_cost_events WHERE session = ?",
    )
    .bind(session)
    .fetch_one(&mut *conn)
    .await?;
    Ok([i, o, c, usd])
}

/// The dollars of everything a session recorded (corrections included), or `None` when any of its
/// events is unpriced: a session is priced once every one of its events is.
pub async fn session_cost(
    conn: &mut SqliteConnection,
    session: &str,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT iif(NOT EXISTS (SELECT 1 FROM core_cost_events WHERE session = ?1 \
         AND basis = 'unpriced'), (SELECT coalesce(sum(cost_usd_micros), 0) FROM core_cost_events \
         WHERE session = ?1), NULL)",
    )
    .bind(session)
    .fetch_one(&mut *conn)
    .await
}

/// [`record_in`] in its own write transaction.
pub async fn record(pool: &SqlitePool, c: &NewCost<'_>, now: &str) -> Result<Recorded, Error> {
    let mut tx = super::begin_write(pool).await?;
    let r = record_in(&mut tx, c, now).await?;
    tx.commit().await?;
    Ok(r)
}
