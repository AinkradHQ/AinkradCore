//! Admission: whether a run may start, wakes for budget warnings, and raising a budget after an
//! approved overrun.

use super::*;

/// Whether a run of `agent` (of `company`) on `issue` may start at `now`: no hard-stop budget that
/// applies is exhausted. Each exhausted one gets a `budget_overrun` approval for its period unless it
/// has one already (whatever its status), with `budget.exhausted` appended.
pub(crate) async fn admit_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    company: CompanyId,
    issue: Option<IssueId>,
    now: &str,
) -> Result<bool, Error> {
    let exhausted: Vec<Standing> = standings_in(conn, agent, issue, now, true)
        .await?
        .into_iter()
        .filter(|s| s.exhausted())
        .collect();
    for s in &exhausted {
        let asked: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM citadel_approvals WHERE kind = 'budget_overrun' \
             AND json_extract(payload, '$.core_budget') = 1 \
             AND json_extract(payload, '$.budget') = ? AND json_extract(payload, '$.period') = ?)",
        )
        .bind(s.budget.id.0)
        .bind(&s.period_key)
        .fetch_one(&mut *conn)
        .await?;
        if asked {
            continue;
        }
        let (scope, scope_id) = scope_parts(s.budget.scope);
        // Dollars when they are what ran out; the decider's raise is in that unit.
        let usd = s.left() > 0;
        let summary = match usd {
            true => format!(
                "{scope} {scope_id} {} budget exhausted: {} of {} micro-dollars spent",
                s.budget.period.as_str(),
                s.usd_spent,
                s.budget.usd_cap_micros.unwrap_or(0) + s.raised_usd
            ),
            false => format!(
                "{scope} {scope_id} {} budget exhausted: {} of {} tokens spent",
                s.budget.period.as_str(),
                s.spent,
                s.budget.token_cap + s.raised
            ),
        };
        let payload = json!({"budget": s.budget.id.0, "period": s.period_key, "scope": scope,
                             "scope_id": scope_id, "token_cap": s.budget.token_cap,
                             "spent": s.spent, "raised": s.raised,
                             "unit": if usd { "usd_micros" } else { "tokens" },
                             "usd_cap_micros": s.budget.usd_cap_micros,
                             "usd_spent": s.usd_spent, "summary": summary,
                             "core_budget": true});
        let new = crate::domain::gov::NewApproval {
            company_id: company,
            kind: crate::domain::gov::ApprovalKind::BudgetOverrun,
            issue_id: issue,
            sprint_id: None,
            agent_id: None,
            requested_by: agent,
            payload: payload.to_string(),
        };
        let a = open_approval_in(conn, &new, None, now).await?;
        let details = json!({"approval": a.id.0, "period": s.period_key, "spent": s.spent,
                             "blocked_agent": agent.0, "budget": s.budget.id.0});
        let event = Event::new(AuditActor::System, "budget.exhausted")
            .entity("budget", s.budget.id.0)
            .company(company.0)
            .details(details);
        append(conn, event).await?;
    }
    Ok(exhausted.is_empty())
}

/// After a cost event by `agent` on `issue`: the product owner of the issue's team is woken, once per
/// budget and period (the key says which), for each budget the Core warned (`Guard::warned`; the Core
/// appended the `budget.warning` row).
pub(crate) async fn wake_for_warnings(
    conn: &mut SqliteConnection,
    warned: &[cb::Standing],
    issue: Option<IssueId>,
) -> Result<(), Error> {
    if warned.is_empty() {
        return Ok(());
    }
    // The Core appended its own `budget.warning`; Citadel's row carries the company, as it always did.
    for s in warned {
        let mut event = Event::new(AuditActor::System, "budget.warning")
            .entity("budget", s.budget.id)
            .details(json!({"period": s.period_key, "spent": s.spent,
                            "token_cap": s.budget.token_cap}));
        if let Some(c) = s.budget.company.as_deref().and_then(|c| c.parse().ok()) {
            event = event.company(c);
        }
        append(conn, event).await?;
    }
    let po: Option<i64> = sqlx::query_scalar(
        "SELECT m.agent_id FROM citadel_issues i JOIN citadel_projects p ON p.id = i.project_id \
         JOIN citadel_team_memberships m ON m.team_id = p.team_id \
         AND m.team_role = 'product_owner' WHERE i.id = ?",
    )
    .bind(issue.map(|i| i.0))
    .fetch_optional(&mut *conn)
    .await?;
    let Some(po) = po else {
        return Ok(());
    };
    for s in warned {
        let wake = crate::store::exec::NewWakeRequest {
            agent_id: AgentId(po),
            issue_id: issue,
            source: crate::domain::work::WakeSource::Escalation,
            reason: format!(
                "a budget reached {}% of its cap ({} of {} tokens)",
                s.budget.warn_at_percent, s.spent, s.budget.token_cap
            ),
            idempotency_key: format!("budget:{}:{}:warning", s.budget.id, s.period_key),
            not_before: None,
        };
        crate::store::exec::enqueue_in(conn, &wake, 1).await?;
    }
    Ok(())
}

/// What an approved `budget_overrun` does, inside the deciding transaction: its budget's period (from
/// the payload) gets `raise` more tokens (or dollars), and the raise is audited by `by`.
pub(crate) async fn raise_in(
    conn: &mut SqliteConnection,
    a: &Approval,
    raise: i64,
    by: UserId,
) -> Result<(), Error> {
    let payload: serde_json::Value = serde_json::from_str(&a.payload).unwrap_or_default();
    let (Some(id), Some(period)) = (payload["budget"].as_i64(), payload["period"].as_str()) else {
        return Err(Error::InvalidArgument(format!(
            "approval {} names no budget period",
            a.id.0
        )));
    };
    // Only an approval the adapter opened names a Core budget id (an old Citadel id would hit another
    // budget), and only one of the approval's own company.
    let company: Option<Option<String>> =
        sqlx::query_scalar("SELECT company FROM core_budgets WHERE id = ?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    // The adapter writes `true`; the copy marks a re-pointed approval with SQL's `1`.
    let marked = payload["core_budget"].as_bool() == Some(true)
        || payload["core_budget"].as_i64() == Some(1);
    if !marked || company.flatten().as_deref() != Some(a.company_id.0.to_string().as_str()) {
        return Err(Error::InvalidArgument(format!(
            "approval {} does not name one of its company's budgets",
            a.id.0
        )));
    }
    // A budget that ran out of dollars is raised in dollars (millionths), else in tokens.
    let usd = payload["unit"].as_str() == Some("usd_micros");
    let (tokens, dollars) = if usd { (0, raise) } else { (raise, 0) };
    engine::raise_in(conn, id, period, tokens, dollars, DEVICE, user_actor(by))
        .await
        .map_err(map)?;
    let unit = if usd { "usd_micros" } else { "tokens" };
    let details = json!({"approval": a.id.0, "period": period, "raise": raise, "unit": unit});
    let event = Event::new(user_actor(by), "budget.raised")
        .entity("budget", id)
        .company(a.company_id.0)
        .details(details);
    append(conn, event).await
}
