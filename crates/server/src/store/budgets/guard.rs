//! What budgets do (KAN-448; Citadel's E7.2 `budgets/guard.rs`, made subject-generic), all from the spend
//! counters:
//!
//! - **Counting** ([`apply_in`]): one cost event moves the counter of every budget whose subject it
//!   counts against, in the same transaction that records it. [`recompute_in`] rebuilds them.
//! - **Mid-run** ([`check_in`], called by `store::costs::record_in`): after each event, a budget that
//!   reached its warning threshold sends one `budget.warning` per period and one that ran out sends one
//!   `budget.exhausted` (audit rows: they are events on the bus). The answer says which hard-stop
//!   budgets are exhausted NOW, so whoever runs the session stops it. The Core stops nothing itself: it
//!   has no caller that records costs yet (AP-10).
//! - **Admission** ([`reserve_in`]): a new session takes what it may spend from every hard-stop budget
//!   that applies, in the write transaction that checked the headroom, so two sessions cannot both
//!   take the last of it. A denial names the budgets that said no; the module that asked decides what
//!   to do (Citadel opens its `budget_overrun` approval). A hold shrinks as the session's cost is
//!   recorded, goes with [`release_in`], and lapses at its expiry if the session died unreleased.
//! - **Raising** ([`raise_in`]): an approved overrun adds tokens or dollars to one period.

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::SqliteConnection;

use super::{Error, Standing, audit_in, columns, period_key, refused, standing, standing_sql};

/// What the mid-run check found after one cost event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Guard {
    /// Budgets that reached their warning threshold for this period for the first time.
    pub warned: Vec<Standing>,
    /// Budgets that ran out for this period for the first time.
    pub newly_exhausted: Vec<Standing>,
    /// Every hard-stop budget that has nothing left now: the session must stop.
    pub stop: Vec<Standing>,
}

/// The result of [`reserve_in`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reservation {
    Granted,
    /// The hard-stop budgets with too little left for what was asked.
    Denied(Vec<Standing>),
}

/// Moves the counter of every budget the event `event_id` counts against by its tokens and dollars,
/// in the period containing `at`; and shrinks `session`'s holds by the same.
pub async fn apply_in(
    conn: &mut SqliteConnection,
    event_id: i64,
    session: &str,
    tokens: i64,
    usd: i64,
    at: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(concat!(
        "INSERT INTO core_budget_spend (budget_id, period_key, tokens, usd_micros) \
         SELECT b.id, ",
        period_key!("?2"),
        ", ?3, ?4 FROM core_budgets b WHERE EXISTS (SELECT 1 FROM core_cost_subjects s \
         WHERE s.event_id = ?1 AND s.kind = b.subject_kind AND s.subject_id = b.subject_id) \
         ON CONFLICT (budget_id, period_key) DO UPDATE SET tokens = tokens + excluded.tokens, \
         usd_micros = usd_micros + excluded.usd_micros"
    ))
    .bind(event_id)
    .bind(at)
    .bind(tokens)
    .bind(usd)
    .execute(&mut *conn)
    .await?;
    if tokens > 0 || usd > 0 {
        sqlx::query(
            "UPDATE core_budget_holds SET tokens = max(0, tokens - ?2), \
             usd_micros = max(0, usd_micros - ?3) WHERE session = ?1",
        )
        .bind(session)
        .bind(tokens)
        .bind(usd)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Recounts the spend of budget `only` (every budget with `None`) from the ledger; the raises and the
/// alerts already sent stay. Returns how many counters hold spend.
pub async fn recompute_in(
    conn: &mut SqliteConnection,
    only: Option<i64>,
) -> Result<u64, sqlx::Error> {
    sqlx::query(
        "UPDATE core_budget_spend SET tokens = 0, usd_micros = 0 WHERE ?1 IS NULL OR budget_id = ?1",
    )
    .bind(only)
    .execute(&mut *conn)
    .await?;
    sqlx::query(concat!(
        "INSERT INTO core_budget_spend (budget_id, period_key, tokens, usd_micros) \
         SELECT b.id, ",
        period_key!("e.occurred_at"),
        " AS key, sum(e.input_tokens + e.output_tokens + e.cache_tokens), \
         coalesce(sum(e.cost_usd_micros), 0) FROM core_budgets b \
         JOIN core_cost_subjects s ON s.kind = b.subject_kind AND s.subject_id = b.subject_id \
         JOIN core_cost_events e ON e.id = s.event_id \
         WHERE (?1 IS NULL OR b.id = ?1) \
         AND (b.subject_kind <> 'pool' OR e.occurred_at >= \
              (SELECT created_at FROM core_pools WHERE CAST(id AS TEXT) = b.subject_id)) \
         GROUP BY b.id, key \
         ON CONFLICT (budget_id, period_key) DO UPDATE SET tokens = excluded.tokens, \
         usd_micros = excluded.usd_micros"
    ))
    .bind(only)
    .execute(&mut *conn)
    .await
    .map(|r| r.rows_affected())
}

/// Every budget that the event `event_id` counts against, in the period containing `at`.
async fn standings_of_event(
    conn: &mut SqliteConnection,
    event_id: i64,
    at: &str,
) -> Result<Vec<Standing>, sqlx::Error> {
    sqlx::query(concat!(
        standing_sql!(),
        " WHERE EXISTS (SELECT 1 FROM core_cost_subjects c WHERE c.event_id = ?3 \
         AND c.kind = b.subject_kind AND c.subject_id = b.subject_id) ORDER BY b.id"
    ))
    .bind(at)
    .bind("")
    .bind(event_id)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(standing)
    .collect()
}

/// The mid-run check after the event `event_id` (at `at`) was counted: sends the alerts that are due
/// and answers which hard-stop budgets are exhausted. Alerts go once per budget and period.
pub async fn check_in(
    conn: &mut SqliteConnection,
    event_id: i64,
    at: &str,
    now: &str,
) -> Result<Guard, Error> {
    let mut out = Guard::default();
    for s in standings_of_event(conn, event_id, at).await? {
        let warn = s.budget.warn_at_percent;
        let tokens = !s.dollars_only() && s.spent * 100 >= (s.budget.token_cap + s.raised) * warn;
        let usd = s
            .budget
            .usd_cap_micros
            .is_some_and(|c| s.usd_spent * 100 >= (c + s.raised_usd) * warn);
        if (tokens || usd) && first(conn, &s, "warned_at", now).await? {
            let d = json!({"kind": s.budget.kind, "subject": s.budget.subject,
                           "period": s.budget.period, "period_key": s.period_key, "spent": s.spent,
                           "usd_spent": s.usd_spent, "token_cap": s.budget.token_cap,
                           "usd_cap_micros": s.budget.usd_cap_micros, "warn_at_percent": warn});
            audit_in(conn, AuditActor::System, "budget.warning", s.budget.id, d).await?;
            out.warned.push(s.clone());
        }
        if s.exhausted() {
            if first(conn, &s, "exhausted_at", now).await? {
                let d = json!({"kind": s.budget.kind, "subject": s.budget.subject,
                               "period": s.budget.period, "period_key": s.period_key,
                               "spent": s.spent, "usd_spent": s.usd_spent,
                               "hard_stop": s.budget.hard_stop});
                audit_in(conn, AuditActor::System, "budget.exhausted", s.budget.id, d).await?;
                out.newly_exhausted.push(s.clone());
            }
            if s.budget.hard_stop {
                out.stop.push(s);
            }
        }
    }
    Ok(out)
}

/// Stamps `column` (`warned_at` or `exhausted_at`) of the budget's counter for its period; true the
/// first time, so an alert goes once.
async fn first(
    conn: &mut SqliteConnection,
    s: &Standing,
    column: &str,
    now: &str,
) -> Result<bool, sqlx::Error> {
    let sql = match column {
        "warned_at" => {
            "UPDATE core_budget_spend SET warned_at = ?3 WHERE budget_id = ?1 AND period_key = ?2 \
             AND warned_at IS NULL"
        }
        _ => {
            "UPDATE core_budget_spend SET exhausted_at = ?3 WHERE budget_id = ?1 AND period_key = ?2 \
             AND exhausted_at IS NULL"
        }
    };
    Ok(sqlx::query(sql)
        .bind(s.budget.id)
        .bind(&s.period_key)
        .bind(now)
        .execute(&mut *conn)
        .await?
        .rows_affected()
        > 0)
}

/// Reserves what a new `session` may spend (`tokens` and `usd` micro-dollars) against every hard-stop
/// budget the subjects name, `ttl_secs` long. Atomic when the caller holds a write transaction
/// (`begin_write`): the headroom is read and the holds written with nothing between. A session that
/// reserves again (a resume) replaces its own hold and is not counted against itself.
pub async fn reserve_in(
    conn: &mut SqliteConnection,
    session: &str,
    subjects: &[(&str, &str)],
    tokens: i64,
    usd: i64,
    ttl_secs: i64,
    now: &str,
) -> Result<Reservation, Error> {
    if session.is_empty()
        || session.len() > 64
        || tokens < 0
        || usd < 0
        || !(1..=7 * 24 * 3600).contains(&ttl_secs)
        || subjects.len() > 16
        || subjects
            .iter()
            .any(|(k, id)| !super::KINDS.contains(k) || !super::valid_id(id))
    {
        return refused(
            "bad_request",
            "a reservation is a session of 1 to 64 characters, amounts of 0 or more, a ttl of up to a week and at most 16 valid subjects",
        );
    }
    sqlx::query("DELETE FROM core_budget_holds WHERE julianday(expires_at) <= julianday(?)")
        .bind(now)
        .execute(&mut *conn)
        .await?;
    let mut all: Vec<Standing> = Vec::new();
    for (kind, id) in subjects {
        let found = sqlx::query(concat!(
            standing_sql!(),
            " WHERE b.subject_kind = ?3 AND b.subject_id = ?4 AND b.hard_stop = 1 ORDER BY b.id"
        ))
        .bind(now)
        .bind(session)
        .bind(kind)
        .bind(id)
        .fetch_all(&mut *conn)
        .await?;
        for r in &found {
            all.push(standing(r)?);
        }
    }
    let blocked: Vec<Standing> = all
        .iter()
        .filter(|s| !s.has_room(tokens, usd))
        .cloned()
        .collect();
    if !blocked.is_empty() {
        return Ok(Reservation::Denied(blocked));
    }
    for s in &all {
        sqlx::query(
            "INSERT INTO core_budget_holds (session, budget_id, period_key, tokens, usd_micros, \
             expires_at, created_at) VALUES (?1, ?2, ?3, ?4, ?5, strftime('%Y-%m-%dT%H:%M:%fZ', ?7, ?6), ?7) \
             ON CONFLICT (session, budget_id) DO UPDATE SET period_key = excluded.period_key, \
             tokens = excluded.tokens, usd_micros = excluded.usd_micros, \
             expires_at = excluded.expires_at",
        )
        .bind(session)
        .bind(s.budget.id)
        .bind(&s.period_key)
        .bind(tokens)
        .bind(usd)
        .bind(format!("+{ttl_secs} seconds"))
        .bind(now)
        .execute(&mut *conn)
        .await?;
    }
    Ok(Reservation::Granted)
}

/// Drops `session`'s holds (it ended). Returns how many.
pub async fn release_in(conn: &mut SqliteConnection, session: &str) -> Result<u64, sqlx::Error> {
    sqlx::query("DELETE FROM core_budget_holds WHERE session = ?")
        .bind(session)
        .execute(&mut *conn)
        .await
        .map(|r| r.rows_affected())
}

/// An approved overrun: the budget's period `period_key` gets `tokens` (or `usd_micros`) more, its
/// exhaustion alert is cleared so the next one is heard, and `budget.raised` is appended by `actor`.
/// `period_key` must be a period the budget has (the one that ran out).
pub async fn raise_in(
    conn: &mut SqliteConnection,
    budget_id: i64,
    period_key: &str,
    tokens: i64,
    usd_micros: i64,
    by_device: &str,
    actor: AuditActor,
) -> Result<(), Error> {
    let key_ok = period_key == "total"
        || ((4..=10).contains(&period_key.len())
            && period_key.bytes().all(|b| b.is_ascii_digit() || b == b'-'));
    if tokens < 0 || usd_micros < 0 || (tokens == 0 && usd_micros == 0) || !key_ok {
        return refused(
            "bad_request",
            "a raise is tokens or dollars of 1 or more, for a period key like 2026-10-22, 2026-10 or total",
        );
    }
    let exists: i64 = sqlx::query_scalar("SELECT count(*) FROM core_budgets WHERE id = ?")
        .bind(budget_id)
        .fetch_one(&mut *conn)
        .await?;
    if exists == 0 {
        return refused("not_found", "no such budget");
    }
    sqlx::query(
        "INSERT INTO core_budget_spend (budget_id, period_key, raised, raised_usd_micros) \
         VALUES (?1, ?2, ?3, ?4) ON CONFLICT (budget_id, period_key) DO UPDATE SET \
         raised = raised + excluded.raised, \
         raised_usd_micros = raised_usd_micros + excluded.raised_usd_micros, exhausted_at = NULL",
    )
    .bind(budget_id)
    .bind(period_key)
    .bind(tokens)
    .bind(usd_micros)
    .execute(&mut *conn)
    .await?;
    let d = json!({"period_key": period_key, "tokens": tokens, "usd_micros": usd_micros,
                   "by_device": by_device});
    audit_in(conn, actor, "budget.raised", budget_id, d).await?;
    Ok(())
}
