//! The budget engine (KAN-448; design `2026-11-02-ai-provider-accounts` §7, §11b item 3, §12d). Moved
//! here from Citadel's E7.2: a limit per subject (account, pool, agent, company, department, project,
//! sprint, issue) over a calendar period (UTC day, week from Monday, month, or all time), a warning at
//! `warn_at_percent`, and with `hard_stop` a stop at the cap.
//!
//! - **One counter.** Spend is kept per budget and period in `core_budget_spend`, moved by
//!   [`guard::apply_in`] in the transaction that records the cost event, so admission and the mid-run
//!   check read one row and never sum the ledger. [`set`] counts the period's spend from the ledger, so a
//!   budget set mid-period sees what was spent already; [`recompute`] repairs the counters.
//! - **Subjects are opaque.** The Core knows no Citadel table. Whoever records a cost names what it
//!   counts against (`store::costs`), and a budget names the same pair. The Core adds the account and
//!   its pools itself. A module removes its own subject's budgets with [`remove`], not by cascade.
//! - **Company binding.** `company` is the owner a budget belongs to (for a company budget, itself), so
//!   a route can be filtered by it (KAN-294).
//! - **What it does** is in [`guard`]: the mid-run check after each event, the atomic reserve for a new
//!   session, the raise an approved overrun makes, and the alerts (audit rows, so they are events on the
//!   bus). Changing a limit needs a step-up (the route's); every change is audited.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Row, SqliteConnection};

use super::secrets::Error;

pub mod guard;

pub const KINDS: [&str; 8] = [
    "account",
    "pool",
    "agent",
    "company",
    "department",
    "project",
    "sprint",
    "issue",
];
pub const PERIODS: [&str; 4] = ["day", "week", "month", "total"];
/// A budget's warning threshold when it names none.
pub const DEFAULT_WARN: i64 = 80;
const MAX_BUDGETS: i64 = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Budget {
    pub id: i64,
    pub kind: String,
    pub subject: String,
    pub company: Option<String>,
    pub period: String,
    pub token_cap: i64,
    pub usd_cap_micros: Option<i64>,
    pub warn_at_percent: i64,
    pub hard_stop: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// A budget to create, or whose caps to change.
#[derive(Debug, Clone, Copy)]
pub struct NewBudget<'a> {
    pub kind: &'a str,
    pub subject: &'a str,
    /// The owner's company binding; a company budget's is its subject.
    pub company: Option<&'a str>,
    pub period: &'a str,
    /// Tokens per period; 0 with a dollar cap is a dollars-only budget.
    pub token_cap: i64,
    pub usd_cap_micros: Option<i64>,
    pub warn_at_percent: Option<i64>,
    pub hard_stop: bool,
}

/// A budget as it stands in the period containing some moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    pub budget: Budget,
    /// `2026-10-22`, `2026-10-19` (a week's Monday), `2026-10` or `total`.
    pub period_key: String,
    pub spent: i64,
    /// Tokens added for the period by approved overruns.
    pub raised: i64,
    pub usd_spent: i64,
    pub raised_usd: i64,
    /// Tokens and dollars held by sessions that reserved them and have not spent them yet.
    pub held: i64,
    pub held_usd: i64,
}

impl Standing {
    /// A dollar cap with no token cap: only the dollars count.
    pub fn dollars_only(&self) -> bool {
        self.budget.token_cap == 0 && self.budget.usd_cap_micros.is_some()
    }

    /// Tokens left: the cap plus the raises, less the spend; 0 or less is exhausted. A dollars-only
    /// budget has no token limit.
    pub fn left(&self) -> i64 {
        match self.dollars_only() {
            true => i64::MAX,
            false => self.budget.token_cap + self.raised - self.spent,
        }
    }

    /// Dollars (millionths) left, when the budget has a dollar cap.
    pub fn usd_left(&self) -> Option<i64> {
        Some(self.budget.usd_cap_micros? + self.raised_usd - self.usd_spent)
    }

    /// Nothing left in tokens or in dollars (the holds of sessions not counted: they are not spent).
    pub fn exhausted(&self) -> bool {
        self.left() <= 0 || self.usd_left().is_some_and(|l| l <= 0)
    }

    /// Whether a session may still take `tokens` and `usd` out of it, holds counted.
    pub fn has_room(&self, tokens: i64, usd: i64) -> bool {
        let t = self.left().saturating_sub(self.held) >= tokens && self.left() > 0;
        let d = self
            .usd_left()
            .is_none_or(|l| l - self.held_usd >= usd && l > 0);
        t && d
    }
}

pub(crate) fn refused<T>(code: &'static str, message: &str) -> Result<T, Error> {
    Err(Error::Refused {
        code,
        message: message.to_owned(),
    })
}

/// A subject or company id: 1 to 64 of `[A-Za-z0-9._:-]`.
pub fn valid_id(s: &str) -> bool {
    super::costs::valid_subject_id(s)
}

/// SQL: the key of budget `b`'s period that contains the time `$t` (an SQL expression).
macro_rules! period_key {
    ($t:literal) => {
        concat!(
            "CASE b.period WHEN 'day' THEN date(",
            $t,
            ") WHEN 'week' THEN date(",
            $t,
            ", '-6 days', 'weekday 1') WHEN 'month' THEN strftime('%Y-%m', ",
            $t,
            ") ELSE 'total' END"
        )
    };
}
pub(crate) use period_key;

/// SQL: a pool's budget only counts what happened at or after the pool was created (`$t`, an SQL
/// expression), so a pool that reuses a deleted pool's id inherits none of its history. Both sides are
/// compared as instants (`julianday`), not as text; a pool that is gone counts nothing.
macro_rules! pool_gate {
    ($t:literal) => {
        concat!(
            "(b.subject_kind <> 'pool' OR julianday(",
            $t,
            ") >= julianday((SELECT p.created_at FROM core_pools p \
             WHERE CAST(p.id AS TEXT) = b.subject_id)))"
        )
    };
}
pub(crate) use pool_gate;

macro_rules! columns {
    () => {
        "b.id, b.subject_kind, b.subject_id, b.company, b.period, b.token_cap, b.usd_cap_micros, \
         b.warn_at_percent, b.hard_stop, b.created_at, b.updated_at"
    };
}
pub(crate) use columns;

pub(crate) fn budget(r: &SqliteRow) -> Result<Budget, sqlx::Error> {
    Ok(Budget {
        id: r.try_get("id")?,
        kind: r.try_get("subject_kind")?,
        subject: r.try_get("subject_id")?,
        company: r.try_get("company")?,
        period: r.try_get("period")?,
        token_cap: r.try_get("token_cap")?,
        usd_cap_micros: r.try_get("usd_cap_micros")?,
        warn_at_percent: r.try_get("warn_at_percent")?,
        hard_stop: r.try_get::<i64, _>("hard_stop")? == 1,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

pub(crate) fn standing(r: &SqliteRow) -> Result<Standing, sqlx::Error> {
    Ok(Standing {
        budget: budget(r)?,
        period_key: r.try_get("period_key")?,
        spent: r.try_get("spent")?,
        raised: r.try_get("raised")?,
        usd_spent: r.try_get("usd_spent")?,
        raised_usd: r.try_get("raised_usd")?,
        held: r.try_get("held")?,
        held_usd: r.try_get("held_usd")?,
    })
}

/// SQL: a budget `b` with its standing in the period containing `?now` (`?1`); `?2` is a session whose
/// own holds are not counted. Append a `WHERE`.
macro_rules! standing_sql {
    () => {
        concat!(
            "SELECT ",
            columns!(),
            ", ",
            period_key!("?1"),
            " AS period_key, coalesce(s.tokens, 0) AS spent, coalesce(s.raised, 0) AS raised, \
             coalesce(s.usd_micros, 0) AS usd_spent, coalesce(s.raised_usd_micros, 0) AS raised_usd, \
             coalesce((SELECT sum(h.tokens) FROM core_budget_holds h WHERE h.budget_id = b.id \
                 AND h.period_key = ",
            period_key!("?1"),
            " AND julianday(h.expires_at) > julianday(?1) AND h.session <> ?2), 0) AS held, \
             coalesce((SELECT sum(h.usd_micros) FROM core_budget_holds h WHERE h.budget_id = b.id \
                 AND h.period_key = ",
            period_key!("?1"),
            " AND julianday(h.expires_at) > julianday(?1) AND h.session <> ?2), 0) AS held_usd \
             FROM core_budgets b LEFT JOIN core_budget_spend s ON s.budget_id = b.id \
             AND s.period_key = ",
            period_key!("?1"),
        )
    };
}
pub(crate) use standing_sql;

pub(crate) async fn audit_in(
    conn: &mut SqliteConnection,
    actor: AuditActor,
    action: &str,
    id: i64,
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = NewAuditEvent {
        actor,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "budget".to_owned(),
            id,
        }),
        details: details.to_string(),
    };
    super::audit::append(conn, &event).await?;
    Ok(())
}

/// The budget `id`.
pub async fn get(pool: &SqlitePool, id: i64) -> Result<Option<Budget>, sqlx::Error> {
    sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM core_budgets b WHERE b.id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?
    .as_ref()
    .map(budget)
    .transpose()
}

/// Every budget with its standing in the period containing `now`, by id; of one kind, one subject
/// and/or one company when given.
pub async fn list(
    pool: &SqlitePool,
    kind: Option<&str>,
    subject: Option<&str>,
    company: Option<&str>,
    now: &str,
) -> Result<Vec<Standing>, sqlx::Error> {
    sqlx::query(concat!(
        standing_sql!(),
        " WHERE (?3 IS NULL OR b.subject_kind = ?3) AND (?4 IS NULL OR b.subject_id = ?4) \
         AND (?5 IS NULL OR b.company = ?5) ORDER BY b.id"
    ))
    .bind(now)
    .bind("")
    .bind(kind)
    .bind(subject)
    .bind(company)
    .fetch_all(pool)
    .await?
    .iter()
    .map(standing)
    .collect()
}

/// One budget with its standing in the period `period_key` names (the period containing `now` for a
/// `total` budget).
pub async fn standing_for(
    pool: &SqlitePool,
    id: i64,
    period_key: &str,
    now: &str,
) -> Result<Option<Standing>, sqlx::Error> {
    let Some(b) = get(pool, id).await? else {
        return Ok(None);
    };
    let at = match b.period.as_str() {
        "month" => format!("{period_key}-01"),
        "total" => now.to_owned(),
        _ => period_key.to_owned(),
    };
    standing_of(pool, id, &at).await
}

/// One budget with its standing in the period containing `now`.
pub async fn standing_of(
    pool: &SqlitePool,
    id: i64,
    now: &str,
) -> Result<Option<Standing>, sqlx::Error> {
    sqlx::query(concat!(standing_sql!(), " WHERE b.id = ?3"))
        .bind(now)
        .bind("")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .as_ref()
        .map(standing)
        .transpose()
}

fn check(b: &NewBudget<'_>) -> Result<Option<String>, Error> {
    if !KINDS.contains(&b.kind) || !PERIODS.contains(&b.period) || !valid_id(b.subject) {
        return refused(
            "bad_request",
            "a budget names a kind, a subject of 1 to 64 of [A-Za-z0-9._:-] and a period of day, week, month or total",
        );
    }
    if b.token_cap == 0 && b.usd_cap_micros.is_none() {
        return refused(
            "bad_request",
            "a budget with no token cap needs a dollar cap",
        );
    }
    if b.token_cap < 0
        || b.usd_cap_micros.is_some_and(|c| c < 0)
        || b.warn_at_percent.is_some_and(|w| !(1..=100).contains(&w))
    {
        return refused(
            "bad_request",
            "a budget needs a cap of 0 or more tokens (and dollars) and a warning at 1-100%",
        );
    }
    // A company budget is its own company binding; any other subject may carry one.
    let company = match (b.kind, b.company) {
        ("company", Some(c)) if c != b.subject => {
            return refused("bad_request", "a company budget's company is its subject");
        }
        ("company", _) => Some(b.subject.to_owned()),
        (_, Some(c)) if !valid_id(c) => {
            return refused("bad_request", "a company is 1 to 64 of [A-Za-z0-9._:-]");
        }
        (_, c) => c.map(str::to_owned),
    };
    Ok(company)
}

/// Creates the budget for its subject and period, or changes the caps, warning, hard stop and company
/// of the one there, and appends `budget.created` or `budget.set`; then counts the period's spend from
/// the ledger. One write transaction. An account or pool subject must exist.
pub async fn set(
    pool: &SqlitePool,
    b: &NewBudget<'_>,
    by_device: &str,
    actor: AuditActor,
    now: &str,
) -> Result<Budget, Error> {
    let company = check(b)?;
    let mut tx = super::begin_write(pool).await?;
    let owned = match b.kind {
        "account" => Some("core_accounts"),
        "pool" => Some("core_pools"),
        _ => None,
    };
    if let Some(table) = owned {
        let exists: i64 = sqlx::query_scalar(match table {
            "core_accounts" => "SELECT count(*) FROM core_accounts WHERE CAST(id AS TEXT) = ?",
            _ => "SELECT count(*) FROM core_pools WHERE CAST(id AS TEXT) = ?",
        })
        .bind(b.subject)
        .fetch_one(&mut *tx)
        .await?;
        if exists == 0 {
            return refused("not_found", "no such account or pool");
        }
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM core_budgets")
        .fetch_one(&mut *tx)
        .await?;
    let existed: Option<(i64, i64, Option<i64>)> = sqlx::query_as(
        "SELECT id, token_cap, usd_cap_micros FROM core_budgets \
         WHERE subject_kind = ? AND subject_id = ? AND period = ?",
    )
    .bind(b.kind)
    .bind(b.subject)
    .bind(b.period)
    .fetch_optional(&mut *tx)
    .await?;
    if existed.is_none() && count >= MAX_BUDGETS {
        return refused("limit_reached", "that is the most budgets there may be");
    }
    let warn = b.warn_at_percent.unwrap_or(DEFAULT_WARN);
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO core_budgets (subject_kind, subject_id, company, period, token_cap, \
         usd_cap_micros, warn_at_percent, hard_stop, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (subject_kind, subject_id, period) DO UPDATE SET company = excluded.company, \
         token_cap = excluded.token_cap, usd_cap_micros = excluded.usd_cap_micros, \
         warn_at_percent = excluded.warn_at_percent, hard_stop = excluded.hard_stop, \
         updated_at = excluded.updated_at RETURNING id",
    )
    .bind(b.kind)
    .bind(b.subject)
    .bind(&company)
    .bind(b.period)
    .bind(b.token_cap)
    .bind(b.usd_cap_micros)
    .bind(warn)
    .bind(b.hard_stop)
    .bind(now)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;
    guard::recompute_in(&mut tx, Some(id)).await?;
    // A cap that grew re-arms the exhaustion alert, so the next time it runs out is heard.
    if existed.is_some_and(|(_, tokens, usd)| {
        b.token_cap > tokens
            || match (usd, b.usd_cap_micros) {
                (Some(_), None) => true,
                (Some(old), Some(new)) => new > old,
                _ => false,
            }
    }) {
        sqlx::query("UPDATE core_budget_spend SET exhausted_at = NULL WHERE budget_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    let details = json!({"kind": b.kind, "subject": b.subject, "company": company,
                         "period": b.period, "token_cap": b.token_cap,
                         "usd_cap_micros": b.usd_cap_micros, "warn_at_percent": warn,
                         "hard_stop": b.hard_stop, "by_device": by_device});
    let action = if existed.is_some() {
        "budget.set"
    } else {
        "budget.created"
    };
    audit_in(&mut tx, actor, action, id, details).await?;
    let r = sqlx::query(concat!(
        "SELECT ",
        columns!(),
        " FROM core_budgets b WHERE b.id = ?"
    ))
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    let out = budget(&r)?;
    tx.commit().await?;
    Ok(out)
}

/// Deletes the budget (its counters and holds go with it) and appends `budget.deleted`; `false` when
/// there is no such budget.
pub async fn remove(
    pool: &SqlitePool,
    id: i64,
    by_device: &str,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = super::begin_write(pool).await?;
    let gone = sqlx::query(concat!(
        "DELETE FROM core_budgets WHERE id = ? RETURNING ",
        "id, subject_kind, subject_id, company, period, token_cap, usd_cap_micros, warn_at_percent, \
         hard_stop, created_at, updated_at"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(r) = gone else {
        return Ok(false);
    };
    let b = budget(&r)?;
    let details = json!({"kind": b.kind, "subject": b.subject, "company": b.company,
                         "period": b.period, "token_cap": b.token_cap, "by_device": by_device});
    audit_in(&mut tx, actor, "budget.deleted", id, details).await?;
    tx.commit().await?;
    Ok(true)
}

/// Deletes every budget of one subject (all its periods) in the caller's transaction, each audited as
/// `budget.deleted`: what a module calls when it deletes the subject, since a subject is opaque text and
/// no foreign key cascades. A subject id a module may reuse must not keep another's budget.
pub async fn remove_subject_in(
    conn: &mut SqliteConnection,
    kind: &str,
    subject: &str,
    by_device: &str,
    actor: AuditActor,
) -> Result<u64, Error> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM core_budgets WHERE subject_kind = ? AND subject_id = ? ORDER BY id",
    )
    .bind(kind)
    .bind(subject)
    .fetch_all(&mut *conn)
    .await?;
    delete_in(conn, &ids, by_device, actor).await
}

/// Deletes every budget bound to `company` (its own and those of everything it owns), as
/// [`remove_subject_in`] does.
pub async fn remove_company_in(
    conn: &mut SqliteConnection,
    company: &str,
    by_device: &str,
    actor: AuditActor,
) -> Result<u64, Error> {
    let ids: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM core_budgets WHERE company = ? ORDER BY id")
            .bind(company)
            .fetch_all(&mut *conn)
            .await?;
    delete_in(conn, &ids, by_device, actor).await
}

async fn delete_in(
    conn: &mut SqliteConnection,
    ids: &[i64],
    by_device: &str,
    actor: AuditActor,
) -> Result<u64, Error> {
    for id in ids {
        let r = sqlx::query(concat!(
            "DELETE FROM core_budgets WHERE id = ? RETURNING ",
            "id, subject_kind, subject_id, company, period, token_cap, usd_cap_micros, \
             warn_at_percent, hard_stop, created_at, updated_at"
        ))
        .bind(id)
        .fetch_one(&mut *conn)
        .await?;
        let b = budget(&r)?;
        let details = json!({"kind": b.kind, "subject": b.subject, "company": b.company,
                             "period": b.period, "token_cap": b.token_cap, "by_device": by_device});
        audit_in(conn, actor, "budget.deleted", *id, details).await?;
    }
    Ok(ids.len() as u64)
}

/// The company binding of budget `id`: no row when there is no such budget, a NULL when it has none.
pub async fn company_of(pool: &SqlitePool, id: i64) -> Result<Option<Option<String>>, sqlx::Error> {
    sqlx::query_scalar("SELECT company FROM core_budgets WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
}

/// Rebuilds every budget's spend counters from the ledger, keeping the raises and the alerts already
/// sent, and appends `budget.recomputed`. For repair: [`guard::apply_in`] keeps them in step.
pub async fn recompute(pool: &SqlitePool, actor: AuditActor) -> Result<u64, Error> {
    let mut tx = super::begin_write(pool).await?;
    let counters = guard::recompute_in(&mut tx, None).await?;
    let event = NewAuditEvent {
        actor,
        action: "budget.recomputed".to_owned(),
        entity: None,
        details: json!({"counters": counters}).to_string(),
    };
    super::audit::append(&mut tx, &event).await?;
    tx.commit().await?;
    Ok(counters)
}
