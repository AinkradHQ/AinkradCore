//! Budgets (E7.2) as Citadel sees them: an ADAPTER over the Core's budget engine (KAN-448; moved by
//! KAN-450). The Core owns the limits, the spend counters, the warnings and the reserve; Citadel keeps
//! agents, companies, projects and work, and this file maps them in and out:
//!
//! - a [`BudgetScope`] is a Core `(kind, subject)` pair (the entity's id as text), and a budget is
//!   bound to its company (`scope_company`), which is what the company routes filter by;
//! - what a run counts against is its agent, the agent's company and departments (through its
//!   teams), and its issue, the issue's project and its sprint ([`subjects_in`]); `reconcile`
//!   names them when it records a cost, and admission and the mid-run cap read them back;
//! - admission still opens one `budget_overrun` approval per exhausted budget and period
//!   (approvals are Citadel's), and an approved one raises the Core budget's period;
//! - deleting an entity deletes its budgets, because a subject is opaque to the Core and no foreign
//!   key cascades (`drop_budgets_of`, `drop_company_budgets`): Citadel ids can be reused.
//!
//! The old `citadel_budgets` and `citadel_budget_spend` tables are no longer read or written; they
//! stay, frozen, as the source of `store::gov::migrate_core` until a later migration drops them.

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::budgets::{self as cb, guard as engine};
use ainkrad_core_server::store::secrets::Error as CoreError;
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use sqlx::{Error, SqliteConnection};

use crate::domain::gov::{Approval, Budget, BudgetId, BudgetPeriod, BudgetScope, NewBudget};
use crate::domain::org::{AgentId, CompanyId, DepartmentId};
use crate::domain::work::{IssueId, ProjectId, SprintId, UserId};
use crate::store::audit::{Event, append};
use crate::store::gov::{open_approval_in, user_actor};

/// What the Core's audit rows say made the change.
const DEVICE: &str = "citadel";

/// SQL: the company budget `?` belongs to (a row of NULL when it has none); no row when there is no
/// such budget, or it is not one of Citadel's. The seam's `OWNERS` row for `budgets` is this.
pub const BUDGET_COMPANY: &str = concat!(
    "SELECT CAST(company AS INTEGER) FROM core_budgets WHERE id = ? AND subject_kind IN ",
    "('company', 'department', 'project', 'agent', 'sprint', 'issue')"
);

/// (kind, its id) of a scope: the Core's pair, the id as text.
pub fn scope_parts(s: BudgetScope) -> (&'static str, i64) {
    match s {
        BudgetScope::Company(id) => ("company", id.0),
        BudgetScope::Department(id) => ("department", id.0),
        BudgetScope::Project(id) => ("project", id.0),
        BudgetScope::Agent(id) => ("agent", id.0),
        BudgetScope::Sprint(id) => ("sprint", id.0),
        BudgetScope::Issue(id) => ("issue", id.0),
    }
}

fn scope_of(kind: &str, subject: &str) -> Option<BudgetScope> {
    let id: i64 = subject.parse().ok()?;
    Some(match kind {
        "company" => BudgetScope::Company(CompanyId(id)),
        "department" => BudgetScope::Department(DepartmentId(id)),
        "project" => BudgetScope::Project(ProjectId(id)),
        "agent" => BudgetScope::Agent(AgentId(id)),
        "sprint" => BudgetScope::Sprint(SprintId(id)),
        "issue" => BudgetScope::Issue(IssueId(id)),
        _ => return None,
    })
}

fn map(e: CoreError) -> Error {
    match e {
        CoreError::Db(e) => e,
        CoreError::Refused { message, .. } => Error::InvalidArgument(message),
    }
}

fn budget(b: cb::Budget) -> Result<Budget, Error> {
    let scope =
        scope_of(&b.kind, &b.subject).ok_or_else(|| Error::ColumnNotFound("scope".into()))?;
    let period: BudgetPeriod = b
        .period
        .parse()
        .map_err(|_| Error::ColumnNotFound("period".into()))?;
    Ok(Budget {
        id: BudgetId(b.id),
        scope,
        period,
        token_cap: b.token_cap,
        usd_cap_micros: b.usd_cap_micros,
        warn_at_percent: u8::try_from(b.warn_at_percent).unwrap_or(80),
        hard_stop: b.hard_stop,
    })
}

/// A budget as it stands in the period containing some moment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    pub budget: Budget,
    /// `2026-10-22`, `2026-10-19` (a week's Monday), `2026-10` or `total`.
    pub period_key: String,
    /// Tokens spent in the period.
    pub spent: i64,
    /// Tokens added for the period by approved overruns.
    pub raised: i64,
    /// Priced dollars (millionths) spent in the period, and added by approved overruns.
    pub usd_spent: i64,
    pub raised_usd: i64,
}

impl Standing {
    /// A dollar cap with no token cap (`token_cap` 0): only the dollars count.
    pub fn dollars_only(&self) -> bool {
        self.budget.token_cap == 0 && self.budget.usd_cap_micros.is_some()
    }

    /// Tokens left: the cap plus the raises, less the spend; 0 or less is exhausted. A
    /// dollars-only budget has no token limit (`i64::MAX`).
    pub fn left(&self) -> i64 {
        match self.dollars_only() {
            true => i64::MAX,
            false => self.budget.token_cap + self.raised - self.spent,
        }
    }

    /// Dollars (millionths) left, when the budget has a dollar cap; 0 or less is exhausted.
    pub fn usd_left(&self) -> Option<i64> {
        let cap = self.budget.usd_cap_micros?;
        Some(cap + self.raised_usd - self.usd_spent)
    }

    /// Nothing left in tokens or in dollars.
    pub fn exhausted(&self) -> bool {
        self.left() <= 0 || self.usd_left().is_some_and(|l| l <= 0)
    }
}

fn standing(s: cb::Standing) -> Result<Standing, Error> {
    Ok(Standing {
        period_key: s.period_key,
        spent: s.spent,
        raised: s.raised,
        usd_spent: s.usd_spent,
        raised_usd: s.raised_usd,
        budget: budget(s.budget)?,
    })
}

fn now() -> String {
    ainkrad_core_server::scheduler::Clock::now(&ainkrad_core_server::scheduler::SystemClock)
}

pub async fn get_budget(pool: &SqlitePool, id: BudgetId) -> Result<Option<Budget>, Error> {
    match cb::get(pool, id.0).await? {
        Some(b) if scope_of(&b.kind, &b.subject).is_some() => Ok(Some(budget(b)?)),
        _ => Ok(None),
    }
}

/// Every budget on `scope`, one per period.
pub async fn list_budgets(pool: &SqlitePool, scope: BudgetScope) -> Result<Vec<Budget>, Error> {
    let (kind, id) = scope_parts(scope);
    cb::list(pool, Some(kind), Some(&id.to_string()), None, &now())
        .await?
        .into_iter()
        .map(|s| budget(s.budget))
        .collect()
}

/// Every budget of the company, as it stands in the period containing `now`, by id.
pub async fn company_budgets(
    pool: &SqlitePool,
    company: CompanyId,
    now: &str,
) -> Result<Vec<Standing>, Error> {
    // A Core account or pool budget may carry the company binding too; it is not Citadel's to show.
    cb::list(pool, None, None, Some(&company.0.to_string()), now)
        .await?
        .into_iter()
        .filter(|s| scope_of(&s.budget.kind, &s.budget.subject).is_some())
        .map(standing)
        .collect()
}

/// Creates the budget for its scope and period, or changes the cap, warning threshold and hard stop of
/// the one there, and audits it (the Core's `budget.created` / `budget.set`); then the Core counts its
/// spend from the ledger, so a budget set mid-period sees what was spent already.
pub async fn set_budget(
    pool: &SqlitePool,
    b: &NewBudget,
    actor: AuditActor,
) -> Result<Budget, Error> {
    write_budget(pool, b, actor, true)
        .await
        .map(|b| b.expect("an upsert always writes"))
}

/// `set_budget` that only creates: `None` when its scope already has a budget for the period.
pub async fn add_budget(
    pool: &SqlitePool,
    b: &NewBudget,
    actor: AuditActor,
) -> Result<Option<Budget>, Error> {
    write_budget(pool, b, actor, false).await
}

async fn write_budget(
    pool: &SqlitePool,
    b: &NewBudget,
    actor: AuditActor,
    replace: bool,
) -> Result<Option<Budget>, Error> {
    if b.token_cap < 0
        || b.usd_cap_micros.is_some_and(|c| c < 0)
        || !(1..=100).contains(&b.warn_at_percent)
    {
        let why = "a budget needs a cap of 0 or more tokens (and dollars) and a warning at 1-100%";
        return Err(Error::InvalidArgument(why.to_owned()));
    }
    let (kind, id) = scope_parts(b.scope);
    let subject = id.to_string();
    // The Core cannot see Citadel's tables: the entity must exist here, and its company is the binding.
    let Some(company) = scope_company(pool, &b.scope).await? else {
        return Err(Error::InvalidArgument(format!("no such {kind} {id}")));
    };
    let now = now();
    if !replace {
        let taken = cb::list(pool, Some(kind), Some(&subject), None, &now)
            .await?
            .iter()
            .any(|s| s.budget.period == b.period.as_str());
        // ponytail: check then write; two racing creates both succeed as a set. A create is an admin's click.
        if taken {
            return Ok(None);
        }
    }
    let company_id = company;
    let company = company.to_string();
    let new = cb::NewBudget {
        kind,
        subject: &subject,
        company: Some(&company),
        period: b.period.as_str(),
        token_cap: b.token_cap,
        usd_cap_micros: b.usd_cap_micros,
        warn_at_percent: Some(i64::from(b.warn_at_percent)),
        hard_stop: b.hard_stop,
    };
    let set = cb::set(pool, &new, DEVICE, actor, &now)
        .await
        .map_err(map)?;
    // The Core audited the change; Citadel's own row keeps the company's activity as it was.
    let details = json!({"scope": kind, "scope_id": id, "period": b.period.as_str(),
                         "token_cap": b.token_cap, "usd_cap_micros": b.usd_cap_micros,
                         "warn_at_percent": b.warn_at_percent, "hard_stop": b.hard_stop});
    let action = if replace {
        "budget.set"
    } else {
        "budget.created"
    };
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let event = Event::new(actor, action)
        .entity("budget", set.id)
        .company(company_id)
        .details(details);
    append(&mut tx, event).await?;
    tx.commit().await?;
    Ok(Some(budget(set)?))
}

/// Deletes the budget (its spend counters go with it) and audits it; `false` when there is no such
/// budget (or it is not Citadel's).
pub async fn remove_budget(
    pool: &SqlitePool,
    id: BudgetId,
    actor: AuditActor,
) -> Result<bool, Error> {
    let Some(gone) = get_budget(pool, id).await? else {
        return Ok(false);
    };
    let company = scope_company(pool, &gone.scope).await?;
    if !cb::remove(pool, id.0, DEVICE, actor).await.map_err(map)? {
        return Ok(false);
    }
    let (kind, scope_id) = scope_parts(gone.scope);
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let mut event = Event::new(actor, "budget.deleted")
        .entity("budget", id.0)
        .details(
            json!({"scope": kind, "scope_id": scope_id, "period": gone.period.as_str(),
                        "token_cap": gone.token_cap}),
        );
    if let Some(c) = company {
        event = event.company(c);
    }
    append(&mut tx, event).await?;
    tx.commit().await?;
    Ok(true)
}

/// Rebuilds every budget's spend counters from the ledger, keeping the raises and warnings, and
/// audits it. For repair: the Core keeps them in step. Returns how many counters hold spend.
pub async fn recompute_budget_spend(pool: &SqlitePool, actor: AuditActor) -> Result<u64, Error> {
    let counters = cb::recompute(pool, actor).await.map_err(map)?;
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let event = Event::new(actor, "budget.recomputed").details(json!({"counters": counters}));
    append(&mut tx, event).await?;
    tx.commit().await?;
    Ok(counters)
}

/// Deletes the budgets of the entity `scope` names (every period), inside the caller's transaction:
/// the deletion's own cascade, which a Core table cannot do.
pub async fn drop_budgets_of(
    conn: &mut SqliteConnection,
    scope: BudgetScope,
    actor: AuditActor,
) -> Result<u64, Error> {
    let (kind, id) = scope_parts(scope);
    cb::remove_subject_in(conn, kind, &id.to_string(), DEVICE, actor)
        .await
        .map_err(map)
}

/// Deletes every budget of the company and of everything in it (they are all bound to it).
pub async fn drop_company_budgets(
    conn: &mut SqliteConnection,
    company: CompanyId,
    actor: AuditActor,
) -> Result<u64, Error> {
    cb::remove_company_in(conn, &company.0.to_string(), DEVICE, actor)
        .await
        .map_err(map)
}

/// What a run of `agent` on `issue` counts against, as the Core names a subject: the agent, its
/// company and departments (through its teams), the issue, its project and its sprint.
pub async fn subjects_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    issue: Option<IssueId>,
) -> Result<Vec<(String, String)>, Error> {
    let mut out = vec![("agent".to_owned(), agent.0.to_string())];
    let company: Option<i64> =
        sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
            .bind(agent.0)
            .fetch_optional(&mut *conn)
            .await?;
    if let Some(c) = company {
        out.push(("company".to_owned(), c.to_string()));
    }
    let departments: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT t.department_id FROM citadel_team_memberships m \
         JOIN citadel_teams t ON t.id = m.team_id WHERE m.agent_id = ? ORDER BY 1",
    )
    .bind(agent.0)
    .fetch_all(&mut *conn)
    .await?;
    out.extend(
        departments
            .into_iter()
            .map(|d| ("department".to_owned(), d.to_string())),
    );
    if let Some(issue) = issue {
        out.push(("issue".to_owned(), issue.0.to_string()));
        let row: Option<(Option<i64>, Option<i64>)> =
            sqlx::query_as("SELECT project_id, sprint_id FROM citadel_issues WHERE id = ?")
                .bind(issue.0)
                .fetch_optional(&mut *conn)
                .await?;
        if let Some((project, sprint)) = row {
            out.extend(project.map(|p| ("project".to_owned(), p.to_string())));
            out.extend(sprint.map(|s| ("sprint".to_owned(), s.to_string())));
        }
    }
    Ok(out)
}

/// Every budget that applies to a run of `agent` on `issue`, as it stands in the period containing
/// `now`; only hard-stop ones with `hard_only`.
pub async fn standings_in(
    conn: &mut SqliteConnection,
    agent: AgentId,
    issue: Option<IssueId>,
    now: &str,
    hard_only: bool,
) -> Result<Vec<Standing>, Error> {
    let owned = subjects_in(conn, agent, issue).await?;
    let subjects: Vec<(&str, &str)> = owned
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    engine::standings_for(conn, &subjects, now, "", hard_only)
        .await?
        .into_iter()
        .map(standing)
        .collect()
}

/// [`standings_in`] on a connection of the pool.
pub async fn standings(
    pool: &SqlitePool,
    agent: AgentId,
    issue: Option<IssueId>,
    now: &str,
    hard_only: bool,
) -> Result<Vec<Standing>, Error> {
    let mut conn = pool.acquire().await?;
    standings_in(&mut conn, agent, issue, now, hard_only).await
}

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

/// A new budget's warning threshold when none is given: the `budget.warn_percent` setting
/// (E15.17).
// ponytail: server-wide until the Core settings store has company/project scopes; the monolith
// read the company that owns `scope`.
pub async fn default_warn_percent(pool: &SqlitePool, _scope: &BudgetScope) -> Result<u8, Error> {
    let warn = crate::settings::value(pool, "budget.warn_percent").await?;
    Ok(warn as u8)
}

/// The company owning what `scope` names; `None` when it names nothing.
pub async fn scope_company(
    pool: impl sqlx::SqliteExecutor<'_>,
    scope: &BudgetScope,
) -> Result<Option<i64>, Error> {
    let (sql, id) = match scope {
        BudgetScope::Company(c) => ("SELECT id FROM citadel_companies WHERE id = ?", c.0),
        BudgetScope::Department(d) => (
            "SELECT company_id FROM citadel_departments WHERE id = ?",
            d.0,
        ),
        BudgetScope::Project(p) => ("SELECT company_id FROM citadel_projects WHERE id = ?", p.0),
        BudgetScope::Agent(a) => ("SELECT company_id FROM citadel_agents WHERE id = ?", a.0),
        BudgetScope::Sprint(s) => (
            "SELECT p.company_id FROM citadel_sprints s JOIN citadel_projects p \
             ON p.id = s.project_id WHERE s.id = ?",
            s.0,
        ),
        BudgetScope::Issue(i) => (
            "SELECT p.company_id FROM citadel_issues i JOIN citadel_projects p \
             ON p.id = i.project_id WHERE i.id = ?",
            i.0,
        ),
    };
    sqlx::query_scalar(sql).bind(id).fetch_optional(pool).await
}

#[cfg(any(test, feature = "test-support"))]
mod raw;
#[cfg(any(test, feature = "test-support"))]
pub use raw::*;
