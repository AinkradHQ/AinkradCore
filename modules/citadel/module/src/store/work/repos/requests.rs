//! Which repos an issue touches (E15.16): set while planning (`set_issue_repos`), or asked for
//! by its agent mid-task (`request_repo`) and decided by the project's team lead or a human
//! (`decide_repo`, decision #55). The lead is woken with the request, the asker with the answer.

use super::*;
use crate::domain::work::Actor;

/// The issue's project, company and key.
async fn issue_at(
    conn: &mut SqliteConnection,
    issue: IssueId,
) -> Result<(ProjectId, i64, String), Error> {
    let found: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT p.id, p.company_id, p.key || '-' || i.number FROM citadel_issues i \
         JOIN citadel_projects p ON p.id = i.project_id WHERE i.id = ?",
    )
    .bind(issue.0)
    .fetch_optional(&mut *conn)
    .await?;
    let (project, company, key) = found.ok_or_else(|| invalid("no such issue"))?;
    Ok((ProjectId(project), company, key))
}

/// Wakes `agent` on `issue` once per `key`.
// S7: the wake queue is the run engine's; the request's lead and the answer's asker are woken
// (source `comment`) from there. Nothing is enqueued until it exists.
async fn wake(
    _conn: &mut SqliteConnection,
    _agent: AgentId,
    _issue: IssueId,
    _reason: String,
    _key: String,
) -> Result<(), Error> {
    Ok(())
}

/// Sets the repos `issue` touches to `names` (its project's repos), replacing those approved
/// before; empty goes back to the primary repo. The repos it touches now.
pub async fn set_issue_repos(
    pool: &SqlitePool,
    issue: IssueId,
    names: &[String],
    actor: AuditActor,
) -> Result<Vec<Repo>, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let now = set_issue_repos_in(&mut tx, issue, names, actor).await?;
    tx.commit().await?;
    Ok(now)
}

/// `set_issue_repos` inside the caller's transaction.
pub async fn set_issue_repos_in(
    tx: &mut SqliteConnection,
    issue: IssueId,
    names: &[String],
    actor: AuditActor,
) -> Result<Vec<Repo>, Error> {
    let (project, company, _) = issue_at(&mut *tx, issue).await?;
    let mut ids = vec![];
    for name in names {
        let r = repo_named(&mut *tx, project, name).await?;
        ids.push(
            r.ok_or_else(|| invalid(format!("the project has no repo {name:?}")))?
                .id,
        );
    }
    sqlx::query("DELETE FROM citadel_issue_repos WHERE issue_id = ? AND state = 'approved'")
        .bind(issue.0)
        .execute(&mut *tx)
        .await?;
    for id in ids {
        sqlx::query(
            "INSERT INTO citadel_issue_repos (issue_id, repo_id) VALUES (?, ?) ON CONFLICT \
             (issue_id, repo_id) DO UPDATE SET state = 'approved'",
        )
        .bind(issue.0)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    let entity = ("issue", issue.0);
    append(
        &mut *tx,
        company,
        actor,
        "issue.repos_set",
        entity,
        json!({"repos": names}),
    )
    .await?;
    issue_repos_in(tx, issue).await
}

/// `agent`, working on `issue`, asks for the project's repo `name` too, saying `why`. The
/// project's team lead is woken to decide (`decide_repo`); without one it waits for the admin.
/// Refused for a repo the issue already touches.
pub async fn request_repo(
    pool: &SqlitePool,
    issue: IssueId,
    name: &str,
    agent: AgentId,
    why: &str,
) -> Result<(), Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let (project, company, key) = issue_at(&mut tx, issue).await?;
    let r = repo_named(&mut tx, project, name)
        .await?
        .ok_or_else(|| invalid(format!("the project has no repo {name:?}")))?;
    if issue_repos_in(&mut tx, issue)
        .await?
        .iter()
        .any(|t| t.id == r.id)
    {
        return Err(invalid(format!("{key} already touches {name}")));
    }
    sqlx::query(
        "INSERT INTO citadel_issue_repos (issue_id, repo_id, state, requested_by_agent_id, reason) \
         VALUES (?, ?, 'requested', ?, ?) ON CONFLICT (issue_id, repo_id) DO UPDATE SET \
         state = 'requested', requested_by_agent_id = excluded.requested_by_agent_id, \
         reason = excluded.reason",
    )
    .bind(issue.0)
    .bind(r.id)
    .bind(agent.0)
    .bind(why)
    .execute(&mut *tx)
    .await?;
    let said = format!("Asks for repo {name} on {key}: {why}");
    note(&mut tx, issue, &said).await?;
    // The Core's audit actor has no agent kind: the agent acts as `system`, its id in the details.
    let details = json!({"repo": name, "reason": why, "agent_id": agent.0});
    append(
        &mut tx,
        company,
        AuditActor::System,
        "issue.repo_requested",
        ("issue", issue.0),
        details,
    )
    .await?;
    let lead: Option<i64> = sqlx::query_scalar(
        "SELECT a.id FROM citadel_projects p JOIN citadel_team_memberships m ON m.team_id = p.team_id \
         AND m.team_role = 'team_lead' JOIN citadel_agents a ON a.id = m.agent_id \
         WHERE p.id = ? AND a.status = 'active' AND a.id <> ? ORDER BY a.id LIMIT 1",
    )
    .bind(project.0)
    .bind(agent.0)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(lead) = lead {
        let reason = format!("{said}. Decide it with decide_repo.");
        wake(
            &mut tx,
            AgentId(lead),
            issue,
            reason,
            format!("repo-request:{}:{name}", issue.0),
        )
        .await?;
    }
    tx.commit().await
}

/// Approves or rejects the pending request for repo `name` on `issue`, as `by` (a human, or the
/// project's active team lead who did not ask; the Core's audit has no agent actor, so an agent
/// acts as `system` with its id in the details), with `reply`. Approved, the issue touches it
/// from its next run on, beside the repos it touched; the asker is woken with the answer.
pub async fn decide_repo(
    pool: &SqlitePool,
    issue: IssueId,
    name: &str,
    approve: bool,
    by: Actor,
    reply: Option<&str>,
) -> Result<(), Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let (project, company, key) = issue_at(&mut tx, issue).await?;
    let r = repo_named(&mut tx, project, name)
        .await?
        .ok_or_else(|| invalid(format!("the project has no repo {name:?}")))?;
    let asked: Option<Option<i64>> = sqlx::query_scalar(
        "SELECT requested_by_agent_id FROM citadel_issue_repos WHERE issue_id = ? AND repo_id = ? \
         AND state = 'requested'",
    )
    .bind(issue.0)
    .bind(r.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(asker) = asked else {
        return Err(invalid(format!("nobody asked for {name} on {key}")));
    };
    match by {
        Actor::Human(_) => {}
        Actor::Agent(a) if Some(a.0) != asker => {
            let lead: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM citadel_projects p JOIN citadel_team_memberships m \
                 ON m.team_id = p.team_id AND m.team_role = 'team_lead' JOIN citadel_agents a \
                 ON a.id = m.agent_id WHERE p.id = ? AND a.id = ? AND a.status = 'active')",
            )
            .bind(project.0)
            .bind(a.0)
            .fetch_one(&mut *tx)
            .await?;
            if !lead {
                return Err(invalid(
                    "only the project's team lead, or a human, decides it",
                ));
            }
        }
        Actor::Agent(_) => return Err(invalid("you do not decide your own request")),
    }
    if approve {
        // The repos it touched so far stay: the primary, when none was approved.
        let before = issue_repos_in(&mut tx, issue).await?;
        for t in before {
            sqlx::query(
                "INSERT OR IGNORE INTO citadel_issue_repos (issue_id, repo_id) VALUES (?, ?)",
            )
            .bind(issue.0)
            .bind(t.id)
            .execute(&mut *tx)
            .await?;
        }
    }
    let state = if approve { "approved" } else { "rejected" };
    sqlx::query(
        "UPDATE citadel_issue_repos SET state = ?, reason = ? WHERE issue_id = ? AND repo_id = ?",
    )
    .bind(state)
    .bind(reply)
    .bind(issue.0)
    .bind(r.id)
    .execute(&mut *tx)
    .await?;
    let said = format!(
        "Repo {name} {state} for {key}{}",
        reply.map(|r| format!(": {r}")).unwrap_or_default()
    );
    note(&mut tx, issue, &said).await?;
    let mut details = json!({"repo": name, "approved": approve, "reply": reply});
    let actor = match by {
        Actor::Human(u) => super::super::core_user(u),
        Actor::Agent(a) => {
            details["agent_id"] = json!(a.0);
            AuditActor::System
        }
    };
    let action = format!("issue.repo_{state}");
    append(
        &mut tx,
        company,
        actor,
        &action,
        ("issue", issue.0),
        details,
    )
    .await?;
    if let Some(asker) = asker {
        let reason = match approve {
            true => format!("{said}. Your next run has its worktree."),
            false => said,
        };
        wake(
            &mut tx,
            AgentId(asker),
            issue,
            reason,
            format!("repo-decided:{}:{name}", issue.0),
        )
        .await?;
    }
    tx.commit().await
}

/// The issue's requests for more repos still waiting: (repo name, asker, why).
pub async fn repo_requests(
    pool: &SqlitePool,
    issue: IssueId,
) -> Result<Vec<(String, Option<AgentId>, Option<String>)>, Error> {
    let rows: Vec<(String, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT r.name, x.requested_by_agent_id, x.reason FROM citadel_issue_repos x \
         JOIN citadel_project_repos r ON r.id = x.repo_id WHERE x.issue_id = ? AND x.state = 'requested' \
         ORDER BY r.position, r.id",
    )
    .bind(issue.0)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(n, a, w)| (n, a.map(AgentId), w))
        .collect())
}
