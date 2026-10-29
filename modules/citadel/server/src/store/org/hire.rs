//! The hire gate (E6.4): every new agent starts `pending_approval`, with a `hire_agent` approval
//! about it, and runs only once a human approves it (`gov::decide_approval` calls
//! `hire_decided_in`; a trigger refuses any other activation, and dispatch runs active agents
//! only). Rejecting terminates it. The one exception is a company's first CEO, which the admin
//! bootstraps active (`bootstrap_ceo`): someone has to take the first intake.

use citadel_core::audit::AuditActor;
use citadel_core::gov::{Approval, ApprovalKind, ApprovalStatus, NewApproval};
use citadel_core::org::{AgentProfile, AgentStatus, Effort, OrgRole, Sandbox, TeamRole};
use serde_json::{Value, json};
use sqlx::SqliteConnection;

use super::*;
use crate::store::gov::open_approval_in;

/// Inserts `a` with `status` inside the caller's transaction.
async fn insert_agent(
    conn: &mut SqliteConnection,
    a: &NewAgent,
    status: AgentStatus,
) -> Result<Agent, Error> {
    sqlx::query(concat!(
        "INSERT INTO agents (company_id, name, role, org_role, reports_to, harness, model, \
         runner_tags, status, palette_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ",
        palette_pick!(),
        ") RETURNING ",
        agent_columns!()
    ))
    .bind(a.company_id.0)
    .bind(&a.name)
    .bind(&a.role)
    .bind(a.org_role.as_str())
    .bind(a.reports_to.map(|r| r.0))
    .bind(a.harness.as_str())
    .bind(&a.model)
    .bind(Json(&a.runner_tags))
    .bind(status.as_str())
    .fetch_one(&mut *conn)
    .await
    .and_then(agent)
}

/// What a hire brings besides its seat in the org: a profile, a team seat and a palette, all
/// applied when the hire is approved (kept in the approval's payload as `extras`).
#[derive(Debug, Clone, Default)]
pub struct HireExtras {
    pub profile: AgentProfile,
    /// A seat on a team of the company, given when the hire is approved.
    pub team: Option<(TeamId, TeamRole)>,
    pub palette_id: Option<String>,
}

impl HireExtras {
    fn is_default(&self) -> bool {
        self.profile == AgentProfile::default() && self.team.is_none() && self.palette_id.is_none()
    }

    fn to_json(&self) -> Value {
        let p = &self.profile;
        json!({"description": p.description, "effort": p.effort.map(|e| e.as_str()),
               "sandbox": p.sandbox.map(|s| s.as_str()), "instructions": p.instructions,
               "guidelines": p.guidelines, "team_id": self.team.map(|t| t.0.0),
               "team_role": self.team.map(|t| t.1.as_str()), "palette_id": self.palette_id})
    }
}

/// Adds `a` as `pending_approval` (whatever its `status`) with a `hire_agent` approval about it,
/// requested by `requested_by` (an agent of the company), or by the new agent itself when a
/// human adds it, and appends `agent.hire_requested` by `actor`, in one `BEGIN IMMEDIATE`
/// transaction, the approval opened at `now`. The approval's payload holds the role, org role, harness, model, runner tags
/// and `justification`.
pub async fn hire_agent(
    pool: &SqlitePool,
    a: &NewAgent,
    requested_by: Option<AgentId>,
    justification: &str,
    actor: AuditActor,
    now: &str,
) -> Result<(Agent, Approval), OrgError> {
    let extras = HireExtras::default();
    hire_agent_with(pool, a, requested_by, justification, &extras, actor, now).await
}

/// `hire_agent` with `extras`, checked now (a bad profile or palette is `InvalidArgument`, a team
/// of another company `OtherCompany`, one that is gone `NotFound`, a taken product owner or lead
/// seat `SeatTaken`) and applied when the hire is approved.
pub async fn hire_agent_with(
    pool: &SqlitePool,
    a: &NewAgent,
    requested_by: Option<AgentId>,
    justification: &str,
    extras: &HireExtras,
    actor: AuditActor,
    now: &str,
) -> Result<(Agent, Approval), OrgError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let hired = hire_in(&mut tx, a, requested_by, justification, extras, actor, now).await?;
    tx.commit().await?;
    Ok(hired)
}

/// `hire_agent` inside the caller's transaction.
pub(crate) async fn hire_agent_in(
    tx: &mut SqliteConnection,
    a: &NewAgent,
    requested_by: Option<AgentId>,
    justification: &str,
    actor: AuditActor,
    now: &str,
) -> Result<(Agent, Approval), OrgError> {
    let extras = HireExtras::default();
    hire_in(tx, a, requested_by, justification, &extras, actor, now).await
}

async fn check_extras(
    tx: &mut SqliteConnection,
    company: CompanyId,
    e: &HireExtras,
) -> Result<(), OrgError> {
    if let Some(why) = e.profile.invalid() {
        return Err(Error::InvalidArgument(why).into());
    }
    if let Some(p) = &e.palette_id {
        let known: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM avatar_palettes WHERE id = ?)")
                .bind(p)
                .fetch_one(&mut *tx)
                .await?;
        if !known {
            return Err(Error::InvalidArgument(format!("no palette {p:?}")).into());
        }
    }
    if let Some((team, role)) = e.team {
        let of: i64 = sqlx::query_scalar(
            "SELECT d.company_id FROM teams t JOIN departments d ON d.id = t.department_id \
             WHERE t.id = ?",
        )
        .bind(team.0)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(OrgError::NotFound)?;
        if of != company.0 {
            return Err(OrgError::OtherCompany);
        }
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM team_memberships WHERE team_id = ? AND team_role = ?)",
        )
        .bind(team.0)
        .bind(role.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if taken && role != TeamRole::Member {
            return Err(OrgError::SeatTaken);
        }
    }
    Ok(())
}

async fn hire_in(
    tx: &mut SqliteConnection,
    a: &NewAgent,
    requested_by: Option<AgentId>,
    justification: &str,
    extras: &HireExtras,
    actor: AuditActor,
    now: &str,
) -> Result<(Agent, Approval), OrgError> {
    if let Some(why) = citadel_core::org::invalid_runner_tags(&a.runner_tags) {
        return Err(Error::InvalidArgument(why).into());
    }
    check_extras(tx, a.company_id, extras).await?;
    if a.name.trim().is_empty() || justification.trim().is_empty() {
        let why = "a hire needs a name and a justification".to_owned();
        return Err(Error::InvalidArgument(why).into());
    }
    if let Some(by) = requested_by {
        let theirs: Option<i64> = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
            .bind(by.0)
            .fetch_optional(&mut *tx)
            .await?;
        match theirs {
            None => return Err(OrgError::NotFound),
            Some(c) if c != a.company_id.0 => return Err(OrgError::OtherCompany),
            Some(_) => {}
        }
    }
    let hired = insert_agent(tx, a, AgentStatus::PendingApproval).await?;
    let mut payload = json!({"name": hired.name, "role": hired.role,
                         "org_role": hired.org_role.as_str(), "harness": hired.harness.as_str(),
                         "model": hired.model, "runner_tags": hired.runner_tags,
                         "justification": justification.trim(),
                         "requested_by": requested_by.map(|r| r.0)});
    if !extras.is_default() {
        payload["extras"] = extras.to_json();
    }
    let new = NewApproval {
        company_id: a.company_id,
        kind: ApprovalKind::HireAgent,
        issue_id: None,
        sprint_id: None,
        agent_id: Some(hired.id),
        requested_by: requested_by.unwrap_or(hired.id),
        payload: payload.to_string(),
    };
    let approval = open_approval_in(tx, &new, None, now).await?;
    let id = approval.id.0;
    let details = json!({"approval": id, "role": hired.role, "requested_by":
                         requested_by.map(|r| r.0)});
    let entity = ("agent", hired.id.0);
    append_org_event(
        tx,
        a.company_id,
        actor,
        "agent.hire_requested",
        entity,
        details,
    )
    .await?;
    Ok((hired, approval))
}

/// Adds the company's first CEO, active from the start, and appends `agent.bootstrapped` by
/// `actor`. Anything else (another org role, or a company that has a CEO) is
/// `OrgError::NotBootstrap`: it goes through `hire_agent`.
pub async fn bootstrap_ceo(
    pool: &SqlitePool,
    a: &NewAgent,
    actor: AuditActor,
) -> Result<Agent, OrgError> {
    if a.org_role != OrgRole::Ceo {
        return Err(OrgError::NotBootstrap);
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let has_ceo: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM agents WHERE company_id = ? AND org_role = 'ceo')",
    )
    .bind(a.company_id.0)
    .fetch_one(&mut *tx)
    .await?;
    if has_ceo {
        return Err(OrgError::NotBootstrap);
    }
    let ceo = insert_agent(&mut tx, a, AgentStatus::Active).await?;
    let entity = ("agent", ceo.id.0);
    let details = json!({"org_role": "ceo"});
    append_org_event(
        &mut tx,
        a.company_id,
        actor,
        "agent.bootstrapped",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(ceo)
}

/// What a decided `hire_agent` does, inside the deciding transaction: approved, its agent
/// becomes active (`agent.hired`); rejected or expired, terminated (`agent.hire_rejected`,
/// `agent.hire_expired`); by `by`. An agent no longer pending (or gone) is left as it is.
pub(crate) async fn hire_decided_in(
    conn: &mut SqliteConnection,
    a: &Approval,
    by: AuditActor,
) -> Result<(), Error> {
    let Some(agent) = a.agent_id else {
        return Ok(());
    };
    let (status, action) = match a.status {
        ApprovalStatus::Approved => (AgentStatus::Active, "agent.hired"),
        ApprovalStatus::Expired => (AgentStatus::Terminated, "agent.hire_expired"),
        _ => (AgentStatus::Terminated, "agent.hire_rejected"),
    };
    let changed =
        sqlx::query("UPDATE agents SET status = ? WHERE id = ? AND status = 'pending_approval'")
            .bind(status.as_str())
            .bind(agent.0)
            .execute(&mut *conn)
            .await
            .map(affected)?;
    if changed {
        let mut details = json!({"approval": a.id.0, "reply": a.reply});
        if a.status == ApprovalStatus::Approved {
            details["extras"] = apply_extras_in(conn, a, agent, by).await?;
        }
        let entity = ("agent", agent.0);
        append_org_event(conn, a.company_id, by, action, entity, details).await?;
    }
    Ok(())
}

/// Gives the just-hired `agent` the profile, palette and team seat its approval's payload
/// carries; `null` when it carries none. A seat that can no longer be had (the team's product
/// owner or lead seat was filled meanwhile) is skipped and named in the result, never a failure
/// of the decision.
async fn apply_extras_in(
    conn: &mut SqliteConnection,
    a: &Approval,
    agent: AgentId,
    by: AuditActor,
) -> Result<Value, Error> {
    let payload: Value = serde_json::from_str(&a.payload).unwrap_or(Value::Null);
    let Some(e) = payload.get("extras") else {
        return Ok(Value::Null);
    };
    let text = |k: &str| e[k].as_str().map(str::to_owned);
    let guidelines: Vec<String> =
        serde_json::from_value(e["guidelines"].clone()).unwrap_or_default();
    sqlx::query(
        "UPDATE agents SET description = ?, effort = ?, sandbox = ?, instructions = ?, \
         guidelines = ?, palette_id = coalesce(?, palette_id) WHERE id = ?",
    )
    .bind(text("description").unwrap_or_default())
    .bind(
        text("effort")
            .and_then(|v| v.parse::<Effort>().ok())
            .map(Effort::as_str),
    )
    .bind(
        text("sandbox")
            .and_then(|v| v.parse::<Sandbox>().ok())
            .map(Sandbox::as_str),
    )
    .bind(text("instructions").unwrap_or_default())
    .bind(Json(&guidelines))
    .bind(text("palette_id"))
    .bind(agent.0)
    .execute(&mut *conn)
    .await?;
    let mut applied = e.clone();
    let seat = e["team_id"]
        .as_i64()
        .zip(text("team_role").and_then(|r| r.parse().ok()));
    if let Some((team, role)) = seat
        && let Err(why) = seat_member_in(conn, TeamId(team), agent, role, None, by).await
    {
        applied["seat_skipped"] = json!(why.to_string());
    }
    Ok(applied)
}
