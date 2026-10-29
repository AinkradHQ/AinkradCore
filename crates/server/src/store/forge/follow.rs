//! What the forge poller saw, recorded: each change goes on the PR row, as a comment on the
//! issue (written as the admin, who speaks for the forge) and in the audit log (by the system),
//! in one transaction. A change that needs the issue's agent (failing checks, a refused PR, a
//! PR closed unmerged) wakes the issue's next actor when it is an agent.

use ainkrad_core::exec::{NewWakeRequest, WakeSource};
use ainkrad_core::work::{IssueState, IssueTransition, NextActor};
use ainkrad_providers::Checks;

use super::*;
use crate::store::exec::{ESCALATION_USER, enqueue_in};
use crate::store::org::product_owner_in;
use crate::store::work::{IssueTransitionError, issue_in, transition_issue_in};

/// The issue's company, and its PR on `repo` as it is now.
async fn current(
    conn: &mut SqliteConnection,
    issue: IssueId,
    repo: i64,
) -> Result<(i64, IssuePr), Error> {
    let company: i64 = sqlx::query_scalar(
        "SELECT p.company_id FROM issues i JOIN projects p ON p.id = i.project_id WHERE i.id = ?",
    )
    .bind(issue.0)
    .fetch_one(&mut *conn)
    .await?;
    let pr = issue_prs(&mut *conn, issue)
        .await?
        .into_iter()
        .find(|p| p.repo_id == repo)
        .ok_or(Error::RowNotFound)?;
    Ok((company, pr))
}

/// How comments name `pr`: `PR #3`, or `<repo> PR #3` when its issue has PRs on several repos.
pub(crate) async fn pr_label(conn: &mut SqliteConnection, pr: &IssuePr) -> Result<String, Error> {
    let n = pr.number.unwrap_or(0);
    if issue_prs(&mut *conn, pr.issue_id).await?.len() < 2 {
        return Ok(format!("PR #{n}"));
    }
    let name: String = sqlx::query_scalar("SELECT name FROM project_repos WHERE id = ?")
        .bind(pr.repo_id)
        .fetch_one(&mut *conn)
        .await?;
    Ok(format!("{name} PR #{n}"))
}

/// A comment on the issue, from the forge (written as the admin).
pub(crate) async fn note(
    conn: &mut SqliteConnection,
    issue: IssueId,
    body: &str,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO comments (issue_id, author_user_id, body) VALUES (?, ?, ?)")
        .bind(issue.0)
        .bind(ESCALATION_USER.0)
        .bind(body)
        .execute(&mut *conn)
        .await
        .map(drop)
}

/// Wakes the issue's next actor, if an agent, once per `key`.
async fn wake_next(
    conn: &mut SqliteConnection,
    issue: IssueId,
    reason: String,
    key: String,
) -> Result<(), Error> {
    let Some(i) = issue_in(conn, issue).await? else {
        return Ok(());
    };
    if let Some(NextActor::Agent(agent_id)) = i.next_actor {
        let wake = NewWakeRequest {
            agent_id,
            issue_id: Some(issue),
            source: WakeSource::Comment,
            reason,
            idempotency_key: key,
            not_before: None,
        };
        enqueue_in(conn, &wake, 1).await?;
    }
    Ok(())
}

/// The requested PR is open on the forge as `number` at `url`, on head `sha`.
pub async fn pr_opened(
    pool: &SqlitePool,
    (issue, repo): (IssueId, i64),
    number: u64,
    url: &str,
    sha: &str,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let (company, pr) = current(&mut tx, issue, repo).await?;
    if pr.phase != PrPhase::Requested {
        return Ok(());
    }
    sqlx::query(
        "UPDATE issue_prs SET state = 'open', number = ?, url = ?, head_sha = ?, \
         last_error = NULL, unpushed_at = NULL, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
         WHERE issue_id = ? AND repo_id = ?",
    )
    .bind(number as i64)
    .bind(url)
    .bind(sha)
    .bind(issue.0)
    .bind(repo)
    .execute(&mut *tx)
    .await?;
    let opened = IssuePr {
        number: Some(number),
        ..pr.clone()
    };
    let said = format!("{} opened: {url}", pr_label(&mut tx, &opened).await?);
    note(&mut tx, issue, &said).await?;
    let details = json!({"repo": repo, "number": number, "url": url, "head": pr.head, "sha": sha});
    let entity = ("issue", issue.0);
    let system = AuditActor::System;
    append(&mut tx, company, system, "pr.opened", entity, details).await?;
    tx.commit().await
}

/// The forge refused what the poller asked (`why`, never holding a token). Recorded, commented
/// and the issue's agent woken only when the reason changes, so a retry every poll is quiet.
pub async fn pr_refused(
    pool: &SqlitePool,
    (issue, repo): (IssueId, i64),
    why: &str,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let (company, pr) = current(&mut tx, issue, repo).await?;
    if pr.last_error.as_deref() == Some(why) {
        return Ok(());
    }
    sqlx::query("UPDATE issue_prs SET last_error = ? WHERE issue_id = ? AND repo_id = ?")
        .bind(why)
        .bind(issue.0)
        .bind(repo)
        .execute(&mut *tx)
        .await?;
    let what = match pr.phase {
        PrPhase::Requested => format!("Opening the PR of {} failed", pr.head),
        _ => format!("{} on the forge", pr_label(&mut tx, &pr).await?),
    };
    note(&mut tx, issue, &format!("{what}: {why}")).await?;
    let details = json!({"repo": repo, "phase": pr.phase.as_str(), "error": why});
    let entity = ("issue", issue.0);
    let seq = append(
        &mut tx,
        company,
        AuditActor::System,
        "pr.error",
        entity,
        details,
    )
    .await?;
    let key = format!("pr:{}:audit:{seq}", issue.0);
    wake_next(&mut tx, issue, format!("{what}: {why}"), key).await?;
    tx.commit().await
}

/// Opening the requested PR found its head branch not on the forge (never pushed: the run
/// that asked died before its push, or committed nothing). Reported like `pr_refused` (once),
/// and the request waits for a later run on the issue to end, whose push lets it open
/// (`due_prs`), instead of being retried every poll. A request whose run's push was refused
/// (`push_reported`) keeps that reason, already said, and wakes nobody.
pub async fn pr_unpushed(
    pool: &SqlitePool,
    (issue, repo): (IssueId, i64),
    why: &str,
) -> Result<(), Error> {
    let error: Option<Option<String>> = sqlx::query_scalar(
        "UPDATE issue_prs SET unpushed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
         WHERE issue_id = ? AND repo_id = ? AND state = 'requested' RETURNING last_error",
    )
    .bind(issue.0)
    .bind(repo)
    .fetch_optional(pool)
    .await?;
    if error
        .flatten()
        .is_some_and(|e| e.starts_with("push rejected: "))
    {
        return Ok(());
    }
    let why = format!("{why}; it opens once a run on this issue pushes the branch");
    pr_refused(pool, (issue, repo), &why).await
}

/// The open PR's head is `sha` and its checks say `checks` (`failed` names the failures);
/// `partial` says what they are made of when the token cannot read every check
/// (`PrStatus::note`). Only a change is recorded; checks turning to success or failure are
/// commented, a failure wakes the issue's agent, a new `partial` is commented once. An issue in
/// review with its checks passed (or none) wakes its reviewer, once per head.
pub async fn pr_followed(
    pool: &SqlitePool,
    (issue, repo): (IssueId, i64),
    sha: &str,
    (checks, failed): (Checks, &[String]),
    partial: Option<&str>,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let (company, pr) = current(&mut tx, issue, repo).await?;
    let same = pr.head_sha.as_deref() == Some(sha) && pr.checks == checks.as_str();
    let noted = pr.checks_note.as_deref() != partial;
    // Its QA reviewer is woken once per head that is ready for review (E9.3).
    let reviewing = issue_in(&mut tx, issue)
        .await?
        .is_some_and(|i| i.state == IssueState::InReview);
    // With PRs on several repos, once every one of them is.
    let ready =
        |p: &IssuePr| p.phase == PrPhase::Open && matches!(p.checks.as_str(), "success" | "none");
    let others = issue_prs(&mut *tx, issue).await?;
    let others_ready = others
        .iter()
        .filter(|p| p.repo_id != repo && p.phase.is_live())
        .all(ready);
    if reviewing && matches!(checks, Checks::Success | Checks::None) && others_ready {
        let label = pr_label(&mut tx, &pr).await?;
        let why = match partial {
            Some(partial) => format!(
                "{label} is ready for review ({} checks; {partial})",
                checks.as_str()
            ),
            None => format!("{label} is ready for review ({} checks)", checks.as_str()),
        };
        let key = format!("pr:{}:{repo}:review:{sha}", issue.0);
        wake_next(&mut tx, issue, why, key).await?;
    }
    if same && !noted && pr.last_error.is_none() {
        return tx.commit().await;
    }
    sqlx::query(
        "UPDATE issue_prs SET head_sha = ?, checks = ?, checks_note = ?, last_error = NULL, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE issue_id = ? AND repo_id = ?",
    )
    .bind(sha)
    .bind(checks.as_str())
    .bind(partial)
    .bind(issue.0)
    .bind(repo)
    .execute(&mut *tx)
    .await?;
    if noted && let Some(partial) = partial {
        let label = pr_label(&mut tx, &pr).await?;
        note(&mut tx, issue, &format!("{label}: {partial}.")).await?;
    }
    if !same {
        let n = pr.number.unwrap_or(0);
        let label = pr_label(&mut tx, &pr).await?;
        let short = &sha[..sha.len().min(12)];
        let said = match checks {
            Checks::Success => Some(format!("{label}: checks passed on {short}.")),
            Checks::Failure => Some(format!(
                "{label}: checks failed on {short}: {}.",
                failed.join(", ")
            )),
            Checks::Pending | Checks::None => None,
        };
        if let Some(said) = &said {
            note(&mut tx, issue, said).await?;
        }
        let details = json!({"repo": repo, "number": n, "sha": sha, "checks": checks.as_str(),
                             "failed": failed});
        let entity = ("issue", issue.0);
        append(
            &mut tx,
            company,
            AuditActor::System,
            "pr.checks",
            entity,
            details,
        )
        .await?;
        if let (Checks::Failure, Some(said)) = (checks, said) {
            let key = format!("pr:{}:{repo}:checks:{sha}:failure", issue.0);
            wake_next(&mut tx, issue, said, key).await?;
        }
    }
    tx.commit().await
}

pub async fn issue_title(pool: &SqlitePool, issue: IssueId) -> Result<String, Error> {
    sqlx::query_scalar("SELECT title FROM issues WHERE id = ?")
        .bind(issue.0)
        .fetch_one(pool)
        .await
}

/// Audits the deletion of the head branch `branch` of the merged PR `(issue, repo)`: `Ok` when it
/// is gone, `Err` with why it is kept. The merge stands either way.
pub async fn pr_branch_deleted(
    pool: &SqlitePool,
    (issue, repo): (IssueId, i64),
    branch: &str,
    outcome: Result<(), String>,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let (company, _) = current(&mut tx, issue, repo).await?;
    let (action, details) = match outcome {
        Ok(()) => ("pr.branch_deleted", json!({"repo": repo, "branch": branch})),
        Err(why) => (
            "pr.branch_kept",
            json!({"repo": repo, "branch": branch, "why": why}),
        ),
    };
    let entity = ("issue", issue.0);
    append(
        &mut tx,
        company,
        AuditActor::System,
        action,
        entity,
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The PR was merged (`merged`) or closed without merging, on the forge. An issue in review is
/// done once every PR of it is merged.
pub async fn pr_finished(
    pool: &SqlitePool,
    (issue, repo): (IssueId, i64),
    merged: bool,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let (company, pr) = current(&mut tx, issue, repo).await?;
    if !pr.phase.is_live() {
        return Ok(());
    }
    let phase = if merged {
        PrPhase::Merged
    } else {
        PrPhase::Closed
    };
    sqlx::query(
        "UPDATE issue_prs SET state = ?, last_error = NULL, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE issue_id = ? AND repo_id = ?",
    )
    .bind(phase.as_str())
    .bind(issue.0)
    .bind(repo)
    .execute(&mut *tx)
    .await?;
    let n = pr.number.unwrap_or(0);
    let said = format!("{} {}.", pr_label(&mut tx, &pr).await?, phase.as_str());
    note(&mut tx, issue, &said).await?;
    let details = json!({"repo": repo, "number": n, "sha": pr.head_sha});
    let entity = ("issue", issue.0);
    let action = format!("pr.{}", phase.as_str());
    append(
        &mut tx,
        company,
        AuditActor::System,
        &action,
        entity,
        details,
    )
    .await?;
    if !merged {
        wake_next(
            &mut tx,
            issue,
            said.clone(),
            format!("pr:{}:{repo}:closed:{n}", issue.0),
        )
        .await?;
    } else if issue_in(&mut tx, issue)
        .await?
        .is_some_and(|i| i.state == IssueState::InReview)
        && issue_prs(&mut *tx, issue)
            .await?
            .iter()
            .all(|p| p.phase == PrPhase::Merged)
    {
        // Merged is done (E9.3); with PRs on several repos, once every one is (E15.16).
        let done = IssueTransition::Approve;
        match transition_issue_in(&mut tx, issue, &done, AuditActor::System).await {
            Ok(_) => {}
            Err(IssueTransitionError::Db(e)) => return Err(e),
            Err(e) => return Err(Error::Protocol(e.to_string())),
        }
    }
    // The product owner runs on every merge, not on the next poll (R7a).
    if merged && let Some(po) = product_owner_in(&mut tx, issue).await? {
        let wake = NewWakeRequest {
            agent_id: po,
            issue_id: Some(issue),
            source: WakeSource::Comment,
            reason: said.clone(),
            idempotency_key: format!("pr:{}:{repo}:merged:{n}", issue.0),
            not_before: None,
        };
        enqueue_in(&mut tx, &wake, 1).await?;
    }
    tx.commit().await
}
