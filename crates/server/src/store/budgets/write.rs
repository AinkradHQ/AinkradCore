//! Writing budgets: set, remove, recompute.

use super::*;

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
    let mut tx = super::super::begin_write(pool).await?;
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
    let mut tx = super::super::begin_write(pool).await?;
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
    let mut tx = super::super::begin_write(pool).await?;
    let counters = guard::recompute_in(&mut tx, None).await?;
    let event = NewAuditEvent {
        actor,
        action: "budget.recomputed".to_owned(),
        entity: None,
        details: json!({"counters": counters}).to_string(),
    };
    super::super::audit::append(&mut tx, &event).await?;
    tx.commit().await?;
    Ok(counters)
}
