//! What a decided `pr_merge` or `workflow_push` approval does to its PR and issue (E9.3, #103).

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::{Error, SqliteConnection};

use super::user_actor;
use crate::domain::gov::{Approval, ApprovalStatus};
use crate::domain::org::AgentId;
use crate::domain::work::{Actor, IssueState, IssueTransition, UserId};
use crate::store::audit::{Event, append};

pub(crate) async fn merge_decided_in(
    conn: &mut SqliteConnection,
    a: &Approval,
    by: UserId,
) -> Result<(), Error> {
    let Some(issue) = a.issue_id else {
        return Ok(());
    };
    let Some(i) = crate::store::work::issue_in(conn, issue).await? else {
        return Ok(());
    };
    let payload: serde_json::Value = serde_json::from_str(&a.payload).unwrap_or_default();
    let Some(number) = payload["pr"].as_i64() else {
        return Ok(());
    };
    let repo: Option<i64> = match payload["repo_id"].as_i64() {
        Some(r) => {
            sqlx::query_scalar(
                "SELECT repo_id FROM citadel_issue_prs WHERE issue_id = ? AND repo_id = ? \
                 AND number = ? AND state = 'open'",
            )
            .bind(issue.0)
            .bind(r)
            .bind(number)
            .fetch_optional(&mut *conn)
            .await?
        }
        None => {
            sqlx::query_scalar(
                "SELECT repo_id FROM citadel_issue_prs WHERE issue_id = ? AND number = ? \
                 AND state = 'open'",
            )
            .bind(issue.0)
            .bind(number)
            .fetch_optional(&mut *conn)
            .await?
        }
    };
    let Some(repo) = repo else {
        return Ok(());
    };
    match a.status {
        ApprovalStatus::Approved => {
            sqlx::query(
                "UPDATE citadel_issue_prs SET state = 'merging', \
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
                 WHERE issue_id = ? AND repo_id = ?",
            )
            .bind(issue.0)
            .bind(repo)
            .execute(&mut *conn)
            .await?;
            let company: i64 =
                sqlx::query_scalar("SELECT company_id FROM citadel_projects WHERE id = ?")
                    .bind(i.project_id.0)
                    .fetch_one(&mut *conn)
                    .await?;
            let details = json!({"repo_id": repo, "number": number, "approval": a.id.0});
            let ev = Event::new(user_actor(by), "issue.pr_merging")
                .entity("issue", i.id.0)
                .company(company)
                .details(details);
            append(conn, ev).await?;
        }
        ApprovalStatus::Rejected => {
            let author: Option<i64> = sqlx::query_scalar(
                "SELECT author_agent_id FROM citadel_issue_prs WHERE issue_id = ? AND repo_id = ?",
            )
            .bind(issue.0)
            .bind(repo)
            .fetch_optional(&mut *conn)
            .await?
            .flatten();
            let dev = author.map(AgentId).or(match i.owner {
                Some(Actor::Agent(d)) => Some(d),
                _ => None,
            });
            if i.state == IssueState::InReview
                && let Some(dev) = dev
            {
                let back = IssueTransition::RequestChanges {
                    assignee: Actor::Agent(dev),
                };
                let _ = crate::store::work::transition_issue_in(conn, issue, &back, user_actor(by))
                    .await;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) async fn workflow_decided_in(
    conn: &mut SqliteConnection,
    a: &Approval,
) -> Result<(), Error> {
    let Some(issue) = a.issue_id else {
        return Ok(());
    };
    let Some(i) = crate::store::work::issue_in(conn, issue).await? else {
        return Ok(());
    };
    let payload: serde_json::Value = serde_json::from_str(&a.payload).unwrap_or_default();
    let Some(repo) = payload["repo_id"].as_i64() else {
        return Ok(());
    };
    let sha = payload["head_sha"].as_str().unwrap_or("");
    let branch = payload["branch"].as_str().unwrap_or("?");
    let files = &payload["files"];
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_projects WHERE id = ?")
        .bind(i.project_id.0)
        .fetch_one(&mut *conn)
        .await?;
    let actor = a.decided_by.map_or(AuditActor::System, user_actor);
    match a.status {
        ApprovalStatus::Approved => {
            sqlx::query(
                "UPDATE citadel_issue_prs SET push_held = NULL, last_error = NULL, \
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
                 WHERE issue_id = ? AND repo_id = ? AND push_held = ?",
            )
            .bind(issue.0)
            .bind(repo)
            .bind(sha)
            .execute(&mut *conn)
            .await?;
            let details = json!({
                "repo_id": repo,
                "branch": branch,
                "head_sha": sha,
                "files": files,
                "approval": a.id.0,
            });
            let ev = Event::new(actor, "issue.workflow_push_approved")
                .entity("issue", i.id.0)
                .company(company)
                .details(details);
            append(conn, ev).await?;
        }
        ApprovalStatus::Rejected => {
            let list = files
                .as_array()
                .map(|f| {
                    f.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default();
            let body = format!(
                "Workflow push of `{branch}` (`{sha}`) rejected ({list}): revert the workflow \
                 file change on the branch so the server can push it."
            );
            let key = format!("workflow-push-rejected:{}", a.id.0);
            sqlx::query(
                "INSERT INTO citadel_comments (issue_id, author_agent_id, body, idempotency_key) \
                 VALUES (?, ?, ?, ?) ON CONFLICT (issue_id, idempotency_key) DO NOTHING",
            )
            .bind(issue.0)
            .bind(a.requested_by.0)
            .bind(&body)
            .bind(&key)
            .execute(&mut *conn)
            .await?;
            let details = json!({
                "repo_id": repo,
                "branch": branch,
                "head_sha": sha,
                "files": files,
                "approval": a.id.0,
                "reply": a.reply,
            });
            let ev = Event::new(actor, "issue.workflow_push_rejected")
                .entity("issue", i.id.0)
                .company(company)
                .details(details);
            append(conn, ev).await?;
        }
        _ => {}
    }
    Ok(())
}
