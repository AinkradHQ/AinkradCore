//! Skills for a run (E4.3): publishing a new version, and resolving what a run is given.
//!
//! A skill is a name within a company; each publish adds the next version and never edits
//! an old one. The latest version of a name is the skill: its attachment decides who gets
//! it, so moving a skill to another role is a publish too. There is no pinning to an older
//! version: rolling back is publishing the old body again. A role matches an agent's role
//! exactly (case-sensitive).

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::exec::RunId;
use citadel_core::gov::{RunSkills, fit_skills};
use citadel_core::settings::{Key, Scope};

use super::*;
use crate::store::audit;

/// Stores `body` as the next version of the company's skill `name` (1 for a new name),
/// attached at `attach`, and audits `skill.published` by `actor`, in one transaction. A blank
/// name or body, a body over the company's `skills.max_bytes` setting, or a department or
/// project not of the company is `Error::InvalidArgument`.
pub async fn publish_skill(
    pool: &SqlitePool,
    company_id: CompanyId,
    name: &str,
    body: &str,
    attach: &SkillAttach,
    actor: AuditActor,
) -> Result<Skill, Error> {
    let invalid = |why: String| Err(Error::InvalidArgument(why));
    if name.trim().is_empty() || body.trim().is_empty() {
        return invalid("a skill needs a name and a body".to_owned());
    }
    if let SkillAttach::Role(role) = attach
        && role.trim().is_empty()
    {
        return invalid("a role skill needs a role".to_owned());
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let at = Scope::Company(company_id);
    let max = crate::store::settings::value_in(&mut tx, Key::SkillMaxBytes, at).await?;
    if body.len() as i64 > max {
        let why = format!(
            "the skill body is {} bytes; skills.max_bytes is {max}",
            body.len()
        );
        return invalid(why);
    }
    let target = match attach {
        SkillAttach::Project(p) => Some((
            "project",
            "SELECT company_id FROM projects WHERE id = ?",
            p.0,
        )),
        SkillAttach::Department(d) => Some((
            "department",
            "SELECT company_id FROM departments WHERE id = ?",
            d.0,
        )),
        _ => None,
    };
    if let Some((what, sql, id)) = target {
        let owner: Option<i64> = sqlx::query_scalar(sql)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        if owner != Some(company_id.0) {
            return invalid(format!("no {what} {id} in company {}", company_id.0));
        }
    }
    let published = publish_skill_in(&mut tx, company_id, name, body, attach, actor).await?;
    tx.commit().await?;
    Ok(published)
}

/// `publish_skill` inside the caller's transaction.
pub(crate) async fn publish_skill_in(
    tx: &mut sqlx::SqliteConnection,
    company_id: CompanyId,
    name: &str,
    body: &str,
    attach: &SkillAttach,
    actor: AuditActor,
) -> Result<Skill, Error> {
    let (scope, department, role, project) = attach_columns(attach);
    let published = sqlx::query(concat!(
        "INSERT INTO skills (company_id, name, version, body, attach_scope, department_id, \
         role, project_id) VALUES (?1, ?2, (SELECT coalesce(max(version), 0) + 1 FROM skills \
         WHERE company_id = ?1 AND name = ?2), ?3, ?4, ?5, ?6, ?7) RETURNING ",
        skill_columns!()
    ))
    .bind(company_id.0)
    .bind(name)
    .bind(body)
    .bind(scope)
    .bind(department)
    .bind(role)
    .bind(project)
    .fetch_one(&mut *tx)
    .await
    .and_then(skill)?;
    let details: String = sqlx::query_scalar("SELECT json_object('name', ?, 'version', ?)")
        .bind(name)
        .bind(published.version)
        .fetch_one(&mut *tx)
        .await?;
    audit::append(
        &mut *tx,
        &NewAuditEvent {
            actor,
            action: "skill.published".to_owned(),
            entity: Some(AuditEntity {
                kind: "skill".to_owned(),
                id: published.id.0,
            }),
            company_id: Some(company_id),
            run_id: None,
            details,
        },
    )
    .await?;
    Ok(published)
}

/// The latest version of every skill attached to the run's company, to a department the
/// run's agent is in (through its teams), to the agent's role, or to the run's issue's
/// project; only skills of the agent's own company are considered. Fitted to
/// the run's project's `skills.budget_bytes` setting (E15.17) by `fit_skills`: highest precedence first, the overflow listed in
/// `dropped`. A missing run is `Error::RowNotFound`.
pub async fn skills_for_run(pool: &SqlitePool, run: RunId) -> Result<RunSkills, Error> {
    let mut tx = pool.begin().await?;
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM runs WHERE id = ?)")
        .bind(run.0)
        .fetch_one(&mut *tx)
        .await?;
    if !exists {
        return Err(Error::RowNotFound);
    }
    let skills = sqlx::query(concat!(
        "WITH ctx (run_agent, run_company, run_role, run_project) AS (SELECT r.agent_id, \
             a.company_id, a.role, i.project_id \
             FROM runs r JOIN agents a ON a.id = r.agent_id \
             LEFT JOIN issues i ON i.id = r.issue_id WHERE r.id = ?1) \
         SELECT ",
        skill_columns!(),
        " FROM skills s, ctx WHERE s.company_id = run_company \
         AND s.version = (SELECT max(v.version) FROM skills v \
             WHERE v.company_id = s.company_id AND v.name = s.name) \
         AND (s.attach_scope = 'company' \
             OR (s.attach_scope = 'role' AND s.role = run_role) \
             OR (s.attach_scope = 'project' AND s.project_id = run_project) \
             OR (s.attach_scope = 'department' AND s.department_id IN \
                 (SELECT t.department_id FROM team_memberships m \
                  JOIN teams t ON t.id = m.team_id WHERE m.agent_id = run_agent))) \
         ORDER BY s.name"
    ))
    .bind(run.0)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .map(skill)
    .collect::<Result<Vec<_>, _>>()?;
    let at = crate::store::settings::scope_of_run_in(&mut tx, run).await?;
    let budget = crate::store::settings::value_in(&mut tx, Key::SkillBudgetBytes, at).await?;
    tx.commit().await?;
    Ok(fit_skills(skills, budget as usize))
}

/// The latest version of every skill the agent's runs are given, before the per-run budget
/// (`skills_for_run`): attached to its company, its role, a department of its teams, or a
/// project of its teams; by name. `None`: no such agent.
pub async fn skills_for_agent(
    pool: &SqlitePool,
    agent: AgentId,
) -> Result<Option<Vec<Skill>>, Error> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM agents WHERE id = ?)")
        .bind(agent.0)
        .fetch_one(pool)
        .await?;
    if !exists {
        return Ok(None);
    }
    sqlx::query(concat!(
        "WITH ctx (me, my_company, my_role) AS (SELECT id, company_id, role FROM agents \
             WHERE id = ?1), \
         mine (team) AS (SELECT team_id FROM team_memberships WHERE agent_id = ?1) \
         SELECT ",
        skill_columns!(),
        " FROM skills s, ctx WHERE s.company_id = my_company \
         AND s.version = (SELECT max(v.version) FROM skills v \
             WHERE v.company_id = s.company_id AND v.name = s.name) \
         AND (s.attach_scope = 'company' \
             OR (s.attach_scope = 'role' AND s.role = my_role) \
             OR (s.attach_scope = 'project' AND s.project_id IN \
                 (SELECT id FROM projects WHERE team_id IN (SELECT team FROM mine))) \
             OR (s.attach_scope = 'department' AND s.department_id IN \
                 (SELECT t.department_id FROM teams t WHERE t.id IN (SELECT team FROM mine)))) \
         ORDER BY s.name"
    ))
    .bind(agent.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(skill)
    .collect::<Result<Vec<_>, _>>()
    .map(Some)
}
