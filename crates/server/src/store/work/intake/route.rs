//! Routing an intake request (`route_intake`): see the parent module.

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::{NewWakeRequest, WakeSource};
use ainkrad_core::org::{AgentId, DepartmentId, TeamId};
use ainkrad_core::work::{Actor, IssueKind, IssueState, IssueTransition, NewIssue, NextActor};
use serde_json::json;
use sqlx::SqliteConnection;

use super::*;

/// The team that owns a new project in `department` (`team`, default its first), and its
/// product owner.
async fn owner_of(
    conn: &mut SqliteConnection,
    company: CompanyId,
    department: DepartmentId,
    team: Option<TeamId>,
) -> Result<(TeamId, AgentId), IntakeError> {
    let in_company: Option<bool> =
        sqlx::query_scalar("SELECT company_id = ? FROM departments WHERE id = ?")
            .bind(company.0)
            .bind(department.0)
            .fetch_optional(&mut *conn)
            .await?;
    if in_company != Some(true) {
        return Err(IntakeError::Elsewhere);
    }
    let team: Option<i64> = match team {
        Some(t) => sqlx::query_scalar("SELECT id FROM teams WHERE id = ? AND department_id = ?")
            .bind(t.0)
            .bind(department.0)
            .fetch_optional(&mut *conn)
            .await?
            .map(Some)
            .ok_or(IntakeError::Elsewhere)?,
        None => {
            sqlx::query_scalar("SELECT min(id) FROM teams WHERE department_id = ?")
                .bind(department.0)
                .fetch_one(&mut *conn)
                .await?
        }
    };
    let team = TeamId(team.ok_or(IntakeError::NoTeam(department))?);
    product_owner(conn, team).await
}

/// The team's product owner.
async fn product_owner(
    conn: &mut SqliteConnection,
    team: TeamId,
) -> Result<(TeamId, AgentId), IntakeError> {
    let po: Option<i64> = sqlx::query_scalar(
        "SELECT agent_id FROM team_memberships WHERE team_id = ? AND team_role = 'product_owner'",
    )
    .bind(team.0)
    .fetch_optional(&mut *conn)
    .await?;
    Ok((team, AgentId(po.ok_or(IntakeError::NoProductOwner(team))?)))
}

/// An existing project a request may go to: the company's, not its intake project, not named
/// by an earlier route; and the product owner of its team.
async fn existing(
    conn: &mut SqliteConnection,
    company: CompanyId,
    id: ProjectId,
    earlier: &[Routed],
) -> Result<(Project, AgentId), IntakeError> {
    let project = sqlx::query(concat!(
        "SELECT ",
        project_columns!(),
        " FROM projects WHERE id = ? AND company_id = ? AND intake = 0"
    ))
    .bind(id.0)
    .bind(company.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(super::super::project)
    .transpose()?
    .filter(|_| earlier.iter().all(|r| r.project.id != id))
    .ok_or(IntakeError::NotRoutable(id))?;
    let team = project.team_id.ok_or(IntakeError::ProjectNoTeam(id))?;
    let (_, po) = product_owner(conn, team).await?;
    Ok((project, po))
}

/// Routes the open intake request as its next actor `by` (the CEO, or the admin with no CEO),
/// in one `BEGIN IMMEDIATE` transaction: per route, a new project owned by the team (its spec
/// the request) or an existing project of the company (untouched), and in it a kickoff issue
/// carrying the request's requirement, waiting on and waking the team's product owner (flagged
/// cross-department when the request has several routes); then the request is closed (`done`)
/// by `by` and `intake.routed` appended with what was routed.
pub async fn route_intake(
    pool: &SqlitePool,
    intake: IssueId,
    by: Actor,
    routes: &[Route],
) -> Result<Vec<Routed>, IntakeError> {
    if !(1..=MAX_ROUTES).contains(&routes.len()) {
        return Err(IntakeError::Routes(routes.len()));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let request = super::super::issues::issue_in(&mut tx, intake)
        .await?
        .ok_or(IntakeError::NotFound)?;
    let (company, is_intake): (i64, bool) =
        sqlx::query_as("SELECT company_id, intake FROM projects WHERE id = ?")
            .bind(request.project_id.0)
            .fetch_one(&mut *tx)
            .await?;
    let company = CompanyId(company);
    if !is_intake {
        return Err(IntakeError::NotIntake);
    }
    if request.state.is_terminal() {
        return Err(IntakeError::Closed);
    }
    if request.next_actor != Some(by.into()) {
        return Err(IntakeError::NotYours);
    }
    let audit_by = match by {
        Actor::Agent(a) => AuditActor::Agent(a),
        Actor::Human(u) => AuditActor::User(u),
    };
    let keys: Vec<&str> = routes
        .iter()
        .filter_map(|r| match r {
            Route::New { key, .. } => Some(key.as_str()),
            Route::Existing(_) => None,
        })
        .collect();
    check_keys(&mut tx, company, &keys).await?;
    let spec = format!("{}\n\n{}", request.title, request.body);
    let mut routed: Vec<Routed> = vec![];
    for r in routes {
        let (project, po, created) = match r {
            Route::Existing(id) => {
                let (project, po) = existing(&mut tx, company, *id, &routed).await?;
                (project, po, false)
            }
            Route::New {
                department,
                team,
                name,
                key,
                mode,
            } => {
                let (team, po) = owner_of(&mut tx, company, *department, *team).await?;
                let project = sqlx::query(concat!(
                    "INSERT INTO projects (company_id, team_id, name, key, mode, \
                     sprint_approval, spec, requirement_id) VALUES (?, ?, ?, ?, ?, 'owner', ?, \
                     (SELECT requirement_id FROM issues WHERE id = ?)) RETURNING ",
                    project_columns!()
                ))
                .bind(company.0)
                .bind(team.0)
                .bind(name)
                .bind(key)
                .bind(mode.as_str())
                .bind(spec.trim())
                .bind(intake.0)
                .fetch_one(&mut *tx)
                .await
                .and_then(super::super::project)?;
                (project, po, true)
            }
        };
        let kickoff = NewIssue {
            project_id: project.id,
            epic_id: None,
            parent_id: None,
            kind: IssueKind::Task,
            title: format!(
                "Kick off {}",
                if created {
                    &project.name
                } else {
                    &request.title
                }
            ),
            body: format!(
                "Routed from intake request: {}\n\n{}",
                request.title, request.body
            ),
            state: IssueState::Todo,
            owner: Some(Actor::Agent(po)),
            next_actor: Some(NextActor::Agent(po)),
            points: None,
            sprint_id: None,
        };
        let mut kickoff = create_issue_in(&mut tx, &kickoff).await?;
        // An existing project's own requirement (if any) is not this one: link it here.
        if kickoff.requirement_id != request.requirement_id {
            sqlx::query("UPDATE issues SET requirement_id = ? WHERE id = ?")
                .bind(request.requirement_id.map(|q| q.0))
                .bind(kickoff.id.0)
                .execute(&mut *tx)
                .await?;
            kickoff.requirement_id = request.requirement_id;
        }
        if routes.len() > 1 {
            // Several departments share the request: its questions may cross them (E6.3).
            sqlx::query("UPDATE issues SET cross_department = 1 WHERE id = ?")
                .bind(kickoff.id.0)
                .execute(&mut *tx)
                .await?;
        }
        let wake = NewWakeRequest {
            agent_id: po,
            issue_id: Some(kickoff.id),
            source: WakeSource::Assignment,
            reason: if created {
                format!("new project {} routed to your team", project.key)
            } else {
                format!("request routed to your project {}", project.key)
            },
            idempotency_key: format!("intake:{}:project:{}", intake.0, project.id.0),
            not_before: None,
        };
        enqueue_in(&mut tx, &wake, 1).await?;
        routed.push(Routed {
            project,
            created,
            kickoff,
            product_owner: po,
        });
    }
    let first = &routed[0];
    super::super::hand_off_in(
        &mut tx,
        intake,
        first.product_owner,
        first.kickoff.id,
        audit_by,
    )
    .await?;
    if request.state != IssueState::InProgress {
        transition_issue_in(&mut tx, intake, &IssueTransition::Start, audit_by).await?;
    }
    transition_issue_in(&mut tx, intake, &IssueTransition::Done, audit_by).await?;
    let created: Vec<_> = routed
        .iter()
        .map(|r| {
            json!({"project": r.project.id.0, "key": r.project.key, "created": r.created,
                   "team": r.project.team_id.map(|t| t.0), "kickoff": r.kickoff.id.0,
                   "product_owner": r.product_owner.0})
        })
        .collect();
    let details = json!({"routes": created});
    append_org_event(
        &mut tx,
        company,
        audit_by,
        "intake.routed",
        ("issue", intake.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(routed)
}
