//! Copies Citadel's budgets and cost ledger into the Core's (KAN-450; design
//! `2026-11-02-ai-provider-accounts` §12d), so the Core engine and ledger start with what Citadel
//! already had. Run by `ainkrad-core-citadel citadel ledger-to-core [--dry-run]`.
//!
//! - **Source untouched.** The `citadel_cost_events`, `citadel_budgets` and `citadel_budget_spend` rows
//!   are only read; they stay as they are until a later migration drops the tables, so the copy can
//!   be re-run and the old code can be put back. (The Core's ledger is insert-only: what was copied
//!   stays there; the old tables, not the Core's rows, are what a rollback goes back to.)
//! - **Idempotent.** An event is copied once, by its idempotency key (the same key the run engine
//!   uses, so a repeated report after the move is still a no-op); a budget once, by (kind, subject,
//!   period). Running it again copies only what is new.
//! - **Verified before it counts.** One write transaction: copy, rebuild the spend counters from the
//!   copied ledger, then compare events, tokens, priced dollars, unpriced events, budgets and the
//!   spend counters against the source. Any difference is an error and nothing is written; `--dry-run`
//!   does the same and rolls back.
//! - **Ids.** Budget ids change (the Core numbers its own), so a pending `budget_overrun` approval
//!   has its payload's budget id rewritten to the new one.
//!
//! Subscription events keep their tokens and no dollars (`unpriced`): the Core ledger does not
//! record a billing mode (decision: API-key accounts only).

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::budgets::guard;
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, SqliteConnection};

use crate::store::audit::{Event, append};

/// What the ledger and the budgets hold, counted the same way on both sides.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counts {
    pub events: i64,
    pub tokens: i64,
    pub usd_micros: i64,
    pub unpriced: i64,
    pub budgets: i64,
    pub spend_tokens: i64,
    pub spend_usd_micros: i64,
    pub raised: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migrated {
    /// Citadel's tables.
    pub source: Counts,
    /// The Core's rows that came from them (by key).
    pub core: Counts,
    pub events_copied: u64,
    pub budgets_copied: u64,
    pub approvals_rewritten: u64,
    /// Rolled back after verifying (`--dry-run`).
    pub dry_run: bool,
}

async fn source_counts(conn: &mut SqliteConnection) -> Result<Counts, Error> {
    let (events, tokens, usd, unpriced): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(sum(input_tokens + output_tokens + cache_tokens), 0), \
         coalesce(sum(cost_usd_micros), 0), coalesce(sum(cost_usd_micros IS NULL), 0) \
         FROM citadel_cost_events",
    )
    .fetch_one(&mut *conn)
    .await?;
    let budgets: i64 = sqlx::query_scalar("SELECT count(*) FROM citadel_budgets")
        .fetch_one(&mut *conn)
        .await?;
    let (st, su, raised): (i64, i64, i64) = sqlx::query_as(
        "SELECT coalesce(sum(tokens), 0), coalesce(sum(usd_micros), 0), \
         coalesce(sum(raised) + sum(raised_usd_micros), 0) FROM citadel_budget_spend",
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(Counts {
        events,
        tokens,
        usd_micros: usd,
        unpriced,
        budgets,
        spend_tokens: st,
        spend_usd_micros: su,
        raised,
    })
}

/// The Core's side: only rows that came from Citadel's (the events by key, the budgets by subject).
async fn core_counts(conn: &mut SqliteConnection) -> Result<Counts, Error> {
    let (events, tokens, usd, unpriced): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(sum(input_tokens + output_tokens + cache_tokens), 0), \
         coalesce(sum(cost_usd_micros), 0), coalesce(sum(cost_usd_micros IS NULL), 0) \
         FROM core_cost_events WHERE idempotency_key IN \
         (SELECT idempotency_key FROM citadel_cost_events)",
    )
    .fetch_one(&mut *conn)
    .await?;
    const MAPPED: &str = "FROM core_budgets c JOIN citadel_budgets b ON c.subject_kind = b.scope \
         AND c.subject_id = CAST(b.scope_id AS TEXT) AND c.period = b.period";
    let budgets: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) {MAPPED}")))
        .fetch_one(&mut *conn)
        .await?;
    let (st, su, raised): (i64, i64, i64) = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT coalesce(sum(s.tokens), 0), coalesce(sum(s.usd_micros), 0), \
         coalesce(sum(s.raised) + sum(s.raised_usd_micros), 0) \
         FROM core_budget_spend s WHERE s.budget_id IN (SELECT c.id {MAPPED})"
    )))
    .fetch_one(&mut *conn)
    .await?;
    Ok(Counts {
        events,
        tokens,
        usd_micros: usd,
        unpriced,
        budgets,
        spend_tokens: st,
        spend_usd_micros: su,
        raised,
    })
}

/// Copies, verifies and (unless `dry_run`) commits. See the module doc.
pub async fn migrate_to_core(pool: &SqlitePool, dry_run: bool) -> Result<Migrated, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let source = source_counts(&mut tx).await?;

    // Budgets first, so the copied events' spend lands on them.
    let budgets_copied = sqlx::query(
        "INSERT INTO core_budgets (user_id, subject_kind, subject_id, company, period, token_cap, \
         usd_cap_micros, warn_at_percent, hard_stop, created_at, updated_at) \
         SELECT b.user_id, b.scope, CAST(b.scope_id AS TEXT), CAST(coalesce(b.company_id, \
         (SELECT company_id FROM citadel_departments WHERE id = b.department_id), \
         (SELECT company_id FROM citadel_projects WHERE id = b.project_id), \
         (SELECT company_id FROM citadel_agents WHERE id = b.agent_id), \
         (SELECT p.company_id FROM citadel_sprints sp JOIN citadel_projects p ON p.id = sp.project_id \
             WHERE sp.id = b.sprint_id), \
         (SELECT p.company_id FROM citadel_issues i JOIN citadel_projects p ON p.id = i.project_id \
             WHERE i.id = b.issue_id)) AS TEXT), \
         b.period, b.token_cap, b.usd_cap_micros, b.warn_at_percent, b.hard_stop, b.created_at, \
         b.created_at FROM citadel_budgets b WHERE true ORDER BY b.id \
         ON CONFLICT (subject_kind, subject_id, period) DO NOTHING",
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    // What an approved overrun added, and the warnings already sent, carry over; the counters are
    // recounted from the ledger below.
    sqlx::query(
        "INSERT INTO core_budget_spend (budget_id, period_key, raised, raised_usd_micros, warned_at) \
         SELECT c.id, s.period_key, s.raised, s.raised_usd_micros, s.warned_at \
         FROM citadel_budget_spend s JOIN citadel_budgets b ON b.id = s.budget_id \
         JOIN core_budgets c ON c.subject_kind = b.scope AND c.subject_id = CAST(b.scope_id AS TEXT) \
         AND c.period = b.period WHERE true \
         ON CONFLICT (budget_id, period_key) DO UPDATE SET raised = excluded.raised, \
         raised_usd_micros = excluded.raised_usd_micros, \
         warned_at = coalesce(core_budget_spend.warned_at, excluded.warned_at)",
    )
    .execute(&mut *tx)
    .await?;

    let events_copied = sqlx::query(
        "WITH s AS (SELECT e.*, coalesce(r.harness, a.harness) AS hz, \
             substr(coalesce(nullif(r.model_used, ''), nullif(a.model, ''), 'unknown'), 1, 80) AS mz, \
             CASE WHEN e.cost_usd_micros IS NULL THEN 'unpriced' \
                  WHEN p.id IS NOT NULL THEN 'list_price' ELSE 'provider_reported' END AS bz, \
             p.input_micros_per_mtok AS pi, p.output_micros_per_mtok AS po, \
             p.cache_micros_per_mtok AS pc, p.created_at AS pa \
             FROM citadel_cost_events e JOIN citadel_agents a ON a.id = e.agent_id \
             LEFT JOIN citadel_runs r ON r.id = e.run_id LEFT JOIN citadel_prices p ON p.id = e.price_id \
             WHERE e.idempotency_key NOT IN (SELECT idempotency_key FROM core_cost_events)) \
         INSERT INTO core_cost_events (user_id, session, epoch, legacy_account_id, provider, harness, \
             model, input_tokens, output_tokens, cache_tokens, cost_usd_micros, basis, approximate, \
             rate_input, rate_output, rate_cache, priced_at, idempotency_key, occurred_at, created_at) \
         SELECT user_id, 'run:' || run_id, 0, account_id, \
             CASE hz WHEN 'claude' THEN 'anthropic' WHEN 'codex' THEN 'openai' \
                     WHEN 'agy' THEN 'google' ELSE hz END, \
             hz, mz, input_tokens, output_tokens, cache_tokens, cost_usd_micros, bz, 0, \
             iif(bz = 'list_price', pi, NULL), iif(bz = 'list_price', po, NULL), \
             iif(bz = 'list_price', pc, NULL), iif(bz = 'list_price', pa, NULL), \
             idempotency_key, created_at, created_at FROM s ORDER BY id",
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();
    // What each copied event counted against, as the run engine names it.
    for sql in [
        "SELECT x.id, 'agent', CAST(e.agent_id AS TEXT) FROM citadel_cost_events e \
         JOIN core_cost_events x ON x.idempotency_key = e.idempotency_key",
        "SELECT x.id, 'company', CAST(a.company_id AS TEXT) FROM citadel_cost_events e \
         JOIN citadel_agents a ON a.id = e.agent_id \
         JOIN core_cost_events x ON x.idempotency_key = e.idempotency_key",
        "SELECT x.id, 'department', CAST(t.department_id AS TEXT) FROM citadel_cost_events e \
         JOIN citadel_team_memberships m ON m.agent_id = e.agent_id \
         JOIN citadel_teams t ON t.id = m.team_id \
         JOIN core_cost_events x ON x.idempotency_key = e.idempotency_key",
        "SELECT x.id, 'issue', CAST(e.issue_id AS TEXT) FROM citadel_cost_events e \
         JOIN core_cost_events x ON x.idempotency_key = e.idempotency_key WHERE e.issue_id IS NOT NULL",
        "SELECT x.id, 'project', CAST(i.project_id AS TEXT) FROM citadel_cost_events e \
         JOIN citadel_issues i ON i.id = e.issue_id \
         JOIN core_cost_events x ON x.idempotency_key = e.idempotency_key \
         WHERE i.project_id IS NOT NULL",
        "SELECT x.id, 'sprint', CAST(i.sprint_id AS TEXT) FROM citadel_cost_events e \
         JOIN citadel_issues i ON i.id = e.issue_id \
         JOIN core_cost_events x ON x.idempotency_key = e.idempotency_key \
         WHERE i.sprint_id IS NOT NULL",
    ] {
        let sql =
            format!("INSERT OR IGNORE INTO core_cost_subjects (event_id, kind, subject_id) {sql}");
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&mut *tx)
            .await?;
    }
    guard::recompute_in(&mut tx, None).await?;

    // A pending overrun approval names its budget by id; the id is the Core's now.
    let pending: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT a.id, json_extract(a.payload, '$.budget'), c.id FROM citadel_approvals a \
         JOIN citadel_budgets b ON b.id = json_extract(a.payload, '$.budget') \
         JOIN core_budgets c ON c.subject_kind = b.scope AND c.subject_id = CAST(b.scope_id AS TEXT) \
         AND c.period = b.period WHERE a.kind = 'budget_overrun' AND a.status = 'pending' ORDER BY a.id",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut approvals_rewritten = 0;
    for (approval, old, new) in pending {
        if old != new {
            sqlx::query("UPDATE citadel_approvals SET payload = json_set(payload, '$.budget', ?) WHERE id = ?")
                .bind(new)
                .bind(approval)
                .execute(&mut *tx)
                .await?;
            approvals_rewritten += 1;
        }
    }

    let core = core_counts(&mut tx).await?;
    if source != core {
        // Dropping `tx` rolls everything back.
        return Err(Error::Protocol(format!(
            "the copy does not match its source, nothing was written: source {source:?}, core {core:?}"
        )));
    }
    let done = Migrated {
        source,
        core,
        events_copied,
        budgets_copied,
        approvals_rewritten,
        dry_run,
    };
    if dry_run {
        return Ok(done);
    }
    let event = Event::new(AuditActor::System, "ledger.migrated").details(json!({
        "events": done.events_copied, "budgets": done.budgets_copied,
        "tokens": done.source.tokens, "usd_micros": done.source.usd_micros,
        "approvals_rewritten": done.approvals_rewritten}));
    append(&mut tx, event).await?;
    tx.commit().await?;
    Ok(done)
}

/// The admin command: `citadel ledger-to-core [--dry-run]`.
pub async fn command(pool: &SqlitePool, args: &[&str]) -> Result<String, String> {
    let dry_run = match args {
        [] => false,
        ["--dry-run"] => true,
        _ => return Err("usage: citadel ledger-to-core [--dry-run]".to_owned()),
    };
    let m = migrate_to_core(pool, dry_run)
        .await
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{}: {} events and {} budgets copied ({} tokens, {} micro-dollars, {} unpriced events, \
         {} approvals re-pointed); verified equal to the source",
        if dry_run {
            "dry run, rolled back"
        } else {
            "ledger moved"
        },
        m.events_copied,
        m.budgets_copied,
        m.source.tokens,
        m.source.usd_micros,
        m.source.unpriced,
        m.approvals_rewritten
    ))
}
