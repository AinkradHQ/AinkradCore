//! A whole plan in one call (E15.18 step 2, decision #59): `apply_plan` files a requirement's
//! epics and tasks (estimates, assignees, repos) and puts them in a sprint, in one `begin_write`
//! transaction. Every item is tried; any that is invalid rolls everything back and every
//! problem comes back together, by its place in the plan (`epics[1].tasks[2]: …`). Each item is
//! audited as its own step would be (`epic.created`, `issue.created`, `issue.repos_set`,
//! `sprint.planned`, `issue.sprint_set`), and the whole as `plan.applied`.
//!
//! Idempotent by a client key: the first result is stored (`plan_applies`) and returned again
//! for the same requirement and key, with nothing filed twice.

use ainkrad_core::audit::AuditActor;
use serde_json::{Value, json};
use sqlx::{Error, SqlitePool};

use super::*;
use crate::domain::work::{EpicId, NewSprint, RequirementState, SprintId};
use crate::store::work::{SprintError, add_to_sprint_in, plan_sprint_in, set_issue_repos_in};

/// A task of the plan: `PlannedTask`'s fields, the repos it touches (names; none is the
/// project's primary repo) and whether it joins the plan's sprint.
pub struct ApplyTask<'a> {
    pub task: PlannedTask<'a>,
    pub repos: Vec<String>,
    pub sprint: bool,
}

/// An epic of the plan: a new one in `project` called `title`, or an existing one.
pub enum ApplyEpic<'a> {
    New {
        project: ProjectId,
        title: &'a str,
        tasks: Vec<ApplyTask<'a>>,
    },
    Existing {
        epic: EpicId,
        tasks: Vec<ApplyTask<'a>>,
    },
}

/// The sprint the plan's tasks join: a planned one, or a new one. `New` reuses the project's
/// planned sprint when it has one open for issues (not waiting on its commit), so plans for
/// one project fill one sprint; only without one is a sprint planned.
pub enum ApplySprint {
    Existing(SprintId),
    New(NewSprint),
}

/// The project's oldest planned sprint whose commit is not waiting on an approval.
async fn open_planned_in(
    conn: &mut sqlx::SqliteConnection,
    project: ProjectId,
) -> Result<Option<SprintId>, Error> {
    let id: Option<i64> = sqlx::query_scalar(
        "SELECT s.id FROM citadel_sprints s WHERE s.project_id = ? AND s.state = 'planned' \
         AND NOT EXISTS (SELECT 1 FROM citadel_approvals a WHERE a.sprint_id = s.id \
             AND a.kind = 'sprint_commit' AND a.status = 'pending') \
         ORDER BY s.id LIMIT 1",
    )
    .bind(project.0)
    .fetch_optional(conn)
    .await?;
    Ok(id.map(SprintId))
}

/// Why nothing was filed.
#[derive(Debug)]
pub enum ApplyError {
    /// The requirement, its planner or its state refused the whole plan.
    Refused(RequirementError),
    /// These items are invalid, each with its place in the plan.
    Invalid(Vec<String>),
}

impl From<Error> for ApplyError {
    fn from(e: Error) -> Self {
        Self::Refused(RequirementError::Db(e))
    }
}

/// An item's failure: in words for the agent, or a real database failure that ends the call.
fn item(at: &str, e: RequirementError) -> Result<String, ApplyError> {
    match e {
        RequirementError::Db(Error::Protocol(why)) => Ok(format!("{at}: {why}")),
        RequirementError::Db(e) => Err(e.into()),
        e => Ok(format!("{at}: {e}")),
    }
}

fn sprint_item(at: &str, e: SprintError) -> Result<String, ApplyError> {
    match e {
        SprintError::Db(e) => item(at, RequirementError::Db(e)),
        e => Ok(format!("{at}: {e}")),
    }
}

/// Applies `epics` and `sprint` to requirement `id` as planner `by`; see the module docs. The
/// result: `{requirement_id, key, epics, tasks, sprint_id, problems}` (`problems`: what still
/// keeps the plan from being complete), plus `replayed: true` for a repeated key.
pub async fn apply_plan(
    pool: &SqlitePool,
    id: RequirementId,
    by: AgentId,
    key: Option<&str>,
    epics: &[ApplyEpic<'_>],
    sprint: Option<&ApplySprint>,
) -> Result<Value, ApplyError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(ApplyError::Refused(RequirementError::NotFound))?;
    if !plans_in(&mut tx, &r, by).await? {
        return Err(ApplyError::Refused(RequirementError::NotPlanner));
    }
    if let Some(key) = key {
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT result FROM citadel_plan_applies WHERE requirement_id = ? AND client_key = ?",
        )
        .bind(id.0)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(stored) = stored {
            let mut v: Value = serde_json::from_str(&stored).unwrap_or_default();
            v["replayed"] = Value::Bool(true);
            return Ok(v);
        }
    }
    if !matches!(
        r.state,
        RequirementState::Planning | RequirementState::InProgress
    ) {
        return Err(ApplyError::Refused(RequirementError::State(r.state)));
    }
    // An agent acts as `system` in the Core's audit; its id rides in the details (see
    // `audit_actor`), which the sprint and issue steps (S4a's) do not carry.
    let actor = AuditActor::System;
    let mut problems = vec![];
    let sprint_id = match sprint {
        None => None,
        Some(ApplySprint::Existing(s)) => Some(*s),
        Some(ApplySprint::New(s)) => match open_planned_in(&mut tx, s.project_id).await? {
            Some(open) => Some(open),
            None => match plan_sprint_in(&mut tx, s, actor).await {
                Ok(s) => Some(s.id),
                Err(e) => {
                    problems.push(sprint_item("sprint", e)?);
                    None
                }
            },
        },
    };
    let (mut epic_ids, mut task_ids) = (vec![], vec![]);
    for (i, e) in epics.iter().enumerate() {
        let at = format!("epics[{i}]");
        let (epic, tasks) = match e {
            ApplyEpic::New {
                project,
                title,
                tasks,
            } => match add_epic_in(&mut tx, &r, *project, title, by).await {
                Ok(epic) => {
                    epic_ids.push(epic.0);
                    (epic, tasks)
                }
                Err(e) => {
                    problems.push(item(&at, e)?);
                    continue;
                }
            },
            ApplyEpic::Existing { epic, tasks } => (*epic, tasks),
        };
        for (j, t) in tasks.iter().enumerate() {
            let at = format!("{at}.tasks[{j}]");
            let planned = PlannedTask {
                epic: Some(epic),
                ..t.task
            };
            let issue = match add_task_in(&mut tx, &r, &planned, by).await {
                Ok(issue) => issue.id,
                Err(e) => {
                    problems.push(item(&at, e)?);
                    continue;
                }
            };
            task_ids.push(issue.0);
            if !t.repos.is_empty()
                && let Err(e) = set_issue_repos_in(&mut tx, issue, &t.repos, actor).await
            {
                problems.push(item(&format!("{at}.repos"), RequirementError::Db(e))?);
            }
            if let (Some(s), true) = (sprint_id, t.sprint)
                && let Err(e) = add_to_sprint_in(&mut tx, s, issue, actor).await
            {
                problems.push(sprint_item(&format!("{at}.sprint"), e)?);
            }
        }
    }
    if !problems.is_empty() {
        return Err(ApplyError::Invalid(problems));
    }
    let out = json!({"requirement_id": id.0, "key": r.key(), "epics": epic_ids,
                     "tasks": task_ids, "sprint_id": sprint_id.map(|s| s.0),
                     "problems": plan_problems_in(&mut tx, id).await?});
    if let Some(key) = key {
        sqlx::query(
            "INSERT INTO citadel_plan_applies (requirement_id, client_key, agent_id, result) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(id.0)
        .bind(key)
        .bind(by.0)
        .bind(out.to_string())
        .execute(&mut *tx)
        .await?;
    }
    let details = json!({"key": key, "epics": out["epics"], "tasks": out["tasks"],
                         "sprint": out["sprint_id"]});
    let entity = ("requirement", id.0);
    let details = by_agent(details, by);
    append_org_event(
        &mut tx,
        r.company_id,
        actor,
        "plan.applied",
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(out)
}
