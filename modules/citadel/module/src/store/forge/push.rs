//! What a run's branch push said (#103), from its transcript (`branch_pushed`, `push_failed`;
//! runner protocol 1.23), stored once per chunk, so all of this happens once per run and branch.
//!
//! A failed push is commented on the issue with the remote's reason (the agent reads it with
//! the issue's newest comments), and its PR request, if any, says `push rejected: <reason>`.
//! A refusal that retrying cannot fix (`permanent`: a token without the `workflow` scope, a
//! protected branch, no permission) holds the request (`push_held`): later runs no longer
//! re-arm it, and the forge poller opens it quietly once the branch is on the forge. One refused
//! for changing workflow files also opens a `workflow_push` approval for a human, who pushes the
//! branch with credentials that may (`workflow_decided_in`). A later push that goes through
//! lifts the hold.

use crate::domain::gov::{ApprovalKind, NewApproval};
use serde_json::Value;

use super::*;
use crate::domain::org::CompanyId;
use crate::store::gov::open_approval_in;

/// The most of a push's reason kept on the PR row and in comments, in chars.
const REASON_MAX: usize = 600;

/// A token refused a change to workflow files (GitHub: "… without `workflow` scope").
pub fn workflow_refusal(reason: &str) -> bool {
    let r = reason.to_lowercase();
    r.contains("workflow") && (r.contains("scope") || r.contains("permission"))
}

/// A refusal another push of the same branch would get again.
pub fn permanent_refusal(reason: &str) -> bool {
    let r = reason.to_lowercase();
    workflow_refusal(reason)
        || [
            "protected branch",
            "gh006",
            "permission",
            "not allowed",
            "denied",
            "403",
        ]
        .iter()
        .any(|w| r.contains(w))
}

fn cap(s: &str) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    match s.char_indices().nth(REASON_MAX) {
        Some((at, _)) => format!("{}…", &s[..at]),
        None => s,
    }
}

/// The head the issue's branch in `repo` was last pushed at by a run (1.28), `None` before its
/// first confirmed push.
pub async fn pushed_head(
    pool: &SqlitePool,
    issue: IssueId,
    repo: i64,
) -> Result<Option<String>, Error> {
    sqlx::query_scalar(
        "SELECT sha FROM citadel_issue_pushed_heads WHERE issue_id = ? AND repo_id = ?",
    )
    .bind(issue.0)
    .bind(repo)
    .fetch_optional(pool)
    .await
}

/// Who reported a push: the issue the run works on and its agent, and the run (S7 reads them off
/// the run when it ingests the transcript chunk).
#[derive(Debug, Clone, Copy)]
pub struct PushReporter {
    pub issue: IssueId,
    pub agent: AgentId,
    pub run: Option<i64>,
}

/// Records a `branch_pushed` or `push_failed` chunk of a run (`by`) at `now`; anything else is
/// left alone.
pub async fn push_reported(
    pool: &SqlitePool,
    by: PushReporter,
    payload: &Value,
    now: &str,
) -> Result<(), Error> {
    let kind = payload["type"].as_str().unwrap_or("");
    if !matches!(kind, "branch_pushed" | "push_failed") {
        return Ok(());
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let PushReporter { issue, agent, run } = by;
    let company: Option<i64> = sqlx::query_scalar(
        "SELECT p.company_id FROM citadel_issues i JOIN citadel_projects p ON p.id = i.project_id \
         WHERE i.id = ?",
    )
    .bind(issue.0)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(company) = company else {
        return Ok(());
    };
    let agent = agent.0;
    let repos = crate::store::work::issue_repos_in(&mut tx, issue).await?;
    let repo = match payload["repo"].as_str() {
        Some(name) => repos.into_iter().find(|r| r.name == name),
        None => repos.into_iter().next(),
    };
    let branch = payload["branch"].as_str().unwrap_or("?");
    if kind == "branch_pushed" {
        // It is on the forge now: a held request may open, an unpushed one need not wait, and
        // a requested one is due at once (`pushed_sha`, `due_prs`).
        if let Some(repo) = repo {
            let sha = payload["sha"].as_str().unwrap_or("");
            // The branch's head now, whatever the PR's state: the next push leases on it (1.28).
            sqlx::query(
                "INSERT INTO citadel_issue_pushed_heads (issue_id, repo_id, sha) VALUES (?, ?, ?) \
                 ON CONFLICT (issue_id, repo_id) DO UPDATE SET sha = excluded.sha",
            )
            .bind(issue.0)
            .bind(repo.id)
            .bind(sha)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE citadel_issue_prs SET push_held = NULL, unpushed_at = NULL, pushed_sha = ? \
                 WHERE issue_id = ? AND repo_id = ? AND state = 'requested'",
            )
            .bind(sha)
            .bind(issue.0)
            .bind(repo.id)
            .execute(&mut *tx)
            .await?;
        }
        return tx.commit().await;
    }
    let reason = cap(payload["reason"].as_str().unwrap_or("no reason given"));
    let files: Vec<&str> = payload["workflow_files"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let permanent = permanent_refusal(&reason);
    let workflow = workflow_refusal(&reason);
    let mut said = format!("Pushing {branch} failed: {reason}");
    if let Some(repo) = &repo {
        let error = format!("push rejected: {reason}");
        // A workflow refusal is held under the head, which is what its approval releases
        // (`workflow_decided_in`); any other refusal for good is held under its reason.
        let sha = payload["sha"].as_str();
        let hold = match (workflow, sha) {
            (true, Some(sha)) => Some(sha),
            _ => permanent.then_some(reason.as_str()),
        };
        // A refusal for good holds the request; after any other, the poller's next attempt finds
        // the branch missing and waits for a later run's push, keeping this error
        // (`pr_unpushed`), so nobody is woken over it.
        sqlx::query(
            "UPDATE citadel_issue_prs SET last_error = ?, push_held = coalesce(?, push_held), \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE issue_id = ? AND repo_id = ? AND state = 'requested'",
        )
        .bind(&error)
        .bind(hold)
        .bind(issue.0)
        .bind(repo.id)
        .execute(&mut *tx)
        .await?;
    }
    if workflow {
        let sha = payload["sha"].as_str();
        let listed = match files.is_empty() {
            true => "workflow files".to_owned(),
            false => files.join(", "),
        };
        // One approval per head waiting: a later run refused for the same commit adds none.
        let open: Option<i64> = sqlx::query_scalar(
            "SELECT id FROM citadel_approvals WHERE kind = 'workflow_push' AND status = 'pending' \
             AND issue_id = ? AND json_extract(payload, '$.branch') = ? \
             AND json_extract(payload, '$.head_sha') IS ?",
        )
        .bind(issue.0)
        .bind(branch)
        .bind(sha)
        .fetch_optional(&mut *tx)
        .await?;
        let id = match open {
            Some(id) => id,
            None => {
                let repo_path = repo
                    .as_ref()
                    .map(|r| r.forge.as_ref().map_or(r.url.clone(), |f| f.repo.clone()));
                let summary = format!(
                    "Push {branch} by hand: the forge token may not change {listed}. From the \
                     issue's worktree on the runner, with credentials that have the workflow \
                     scope: git push origin {branch}:{branch}; then approve, and the PR opens. \
                     Reject to have the agent drop the workflow change."
                );
                let payload = json!({"summary": summary, "run": run, "branch": branch,
                    "head_sha": sha, "repo": repo_path, "repo_id": repo.as_ref().map(|r| r.id),
                    "files": files, "rejection": reason});
                let new = NewApproval {
                    company_id: CompanyId(company),
                    kind: ApprovalKind::WorkflowPush,
                    issue_id: Some(issue),
                    sprint_id: None,
                    agent_id: None,
                    requested_by: AgentId(agent),
                    payload: payload.to_string(),
                };
                open_approval_in(&mut tx, &new, None, now).await?.id.0
            }
        };
        said = format!(
            "{said}\nThe forge token may not change workflow files ({listed}), so a human \
             pushes this branch: workflow_push approval {id} waits for that, and the PR opens \
             once the branch is on the forge. To push it yourself instead, drop the workflow \
             change from the branch."
        );
    } else if permanent {
        said = format!(
            "{said}\nRetrying will not help: a human must fix the permission (or the branch \
             must change). The PR request waits until the branch is on the forge."
        );
    }
    note(&mut tx, issue, &said).await?;
    let details = json!({"branch": branch, "repo": repo.as_ref().map(|r| r.id), "run": run,
                         "reason": reason, "permanent": permanent, "workflow": workflow});
    let by = AuditActor::System;
    append(
        &mut tx,
        company,
        by,
        "pr.push_failed",
        ("issue", issue.0),
        details,
    )
    .await?;
    tx.commit().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tells_permanent_and_workflow_refusals_apart() {
        let wrk3 = "refs/heads/feat/wrk-3 rejected: refusing to allow a Personal Access Token \
                    to create or update workflow `.github/workflows/images.yml` without \
                    `workflow` scope";
        assert!(workflow_refusal(wrk3) && permanent_refusal(wrk3));
        let gh006 = "remote: error: GH006: Protected branch update failed";
        assert!(!workflow_refusal(gh006) && permanent_refusal(gh006));
        let net = "fatal: unable to access 'https://github.com/o/r.git/': Could not resolve host";
        assert!(!permanent_refusal(net));
    }
}
