//! The done flow (E9.3, decision #16): agent done → QA agent verifies → the owner approves the
//! merge → merged → done.
//!
//! - `submit_for_qa`: a developer's `done` on an issue with a live PR moves it to `in_review`,
//!   waiting on the project's QA agent (a team member whose role is QA), else its team lead,
//!   else the admin. The reviewer is woken; once the PR is open (`pr_opened`) it is woken again.
//! - `qa_verdict`: the reviewer passes it (the PR must be open, its checks not failing or
//!   running; checks the forge token cannot read (`checks_note`) count as what it could read,
//!   commit statuses or Actions runs, and the approval's summary says so), which opens a
//!   `pr_merge` approval and hands the issue to the admin; or fails it
//!   with notes, which go back to the PR's author as a comment, with the issue.
//! - `merge_decided_in` (`store::gov::approvals`, from the step-up `decide-forge` route): approved at the
//!   head every PR had when QA passed it, the PR is `merging` and the poller
//!   merges it (`pr_merged`, then the issue is done); rejected, the issue goes back to the
//!   author with the reply.
//! - `pr_merge_refused`: the forge would not merge it (conflict, moved head): the PR is open
//!   again and the issue goes back to its author.
//!
//! Multi-repo issues (E15.16): the issue goes to QA with every PR it has; a pass needs each one
//! open with its checks passed, and opens one `pr_merge` approval covering all of them. Approved,
//! they merge one at a time in the project's repo order (#54), and the issue is done once every
//! one is merged. When a merge fails after an earlier one merged (#53), the merging stops, the
//! merged PRs are left alone, the rest are open again, a new `pr_merge` approval for them is
//! opened with the reason, and the issue stays in review.

use std::fmt;

use crate::domain::gov::{Approval, ApprovalKind, NewApproval};
use crate::domain::org::CompanyId;
use crate::domain::work::{Actor, IssueState, IssueTransition, NextActor};

use super::*;
use crate::store::gov::open_approval_in;
use crate::store::org::ESCALATION_USER;
use crate::store::work::{IssueTransitionError, transition_issue_in};

/// Why the done flow refused a step.
#[derive(Debug)]
pub enum DoneError {
    /// The issue, its PR or the reviewer is not where the step needs them.
    Refused(String),
    Transition(IssueTransitionError),
    Db(Error),
}

impl From<Error> for DoneError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl From<IssueTransitionError> for DoneError {
    fn from(e: IssueTransitionError) -> Self {
        match e {
            IssueTransitionError::Db(e) => Self::Db(e),
            e => Self::Transition(e),
        }
    }
}

impl fmt::Display for DoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(why) => f.write_str(why),
            Self::Transition(e) => e.fmt(f),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DoneError {}

/// Who verifies `dev`'s work on the project: an active member of its team whose role is QA,
/// else its active team lead, never `dev`; else the admin.
async fn qa_reviewer_in(
    conn: &mut SqliteConnection,
    project: ProjectId,
    dev: AgentId,
) -> Result<Actor, Error> {
    let found: Option<i64> = sqlx::query_scalar(
        "SELECT a.id FROM citadel_projects p JOIN citadel_team_memberships m ON m.team_id = p.team_id \
         JOIN citadel_agents a ON a.id = m.agent_id WHERE p.id = ? AND a.id <> ? \
         AND a.status = 'active' AND (lower(a.role) = 'qa' OR m.team_role = 'team_lead') \
         ORDER BY lower(a.role) = 'qa' DESC, a.id LIMIT 1",
    )
    .bind(project.0)
    .bind(dev.0)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(found.map_or(Actor::Human(ESCALATION_USER), |a| Actor::Agent(AgentId(a))))
}

/// The issue's company and every PR of it, when one of them is live.
async fn live_prs(
    conn: &mut SqliteConnection,
    issue: IssueId,
) -> Result<Option<(i64, Vec<IssuePr>)>, Error> {
    let prs = issue_prs(&mut *conn, issue).await?;
    if !prs.iter().any(|p| p.phase.is_live()) {
        return Ok(None);
    }
    let company: i64 = sqlx::query_scalar(
        "SELECT p.company_id FROM citadel_issues i JOIN citadel_projects p ON p.id = i.project_id WHERE i.id = ?",
    )
    .bind(issue.0)
    .fetch_one(&mut *conn)
    .await?;
    Ok(Some((company, prs)))
}

/// Sends the issue back to `author`, if any, as `by`; an illegal move is left alone.
async fn back_to(
    conn: &mut SqliteConnection,
    issue: IssueId,
    author: Option<AgentId>,
    by: AuditActor,
) -> Result<(), Error> {
    let Some(author) = author else {
        return Ok(());
    };
    let back = IssueTransition::RequestChanges {
        assignee: Actor::Agent(author),
    };
    match transition_issue_in(conn, issue, &back, by).await {
        Ok(_) | Err(IssueTransitionError::Illegal(_)) => Ok(()),
        Err(IssueTransitionError::Db(e)) => Err(e),
        Err(e) => Err(Error::Protocol(e.to_string())),
    }
}

/// `dev`'s `done` on an issue with a live PR: `in_review`, waiting on its QA reviewer, with a
/// comment saying so; `None` when the issue has no live PR (a plain `done` applies).
pub async fn submit_for_qa(
    pool: &SqlitePool,
    issue: IssueId,
    dev: AgentId,
) -> Result<Option<crate::domain::work::Issue>, DoneError> {
    submit_in(pool, issue, dev, false).await
}

/// An agent's `done` over MCP: `submit_for_qa`, but only on evidence the forge produced, and a
/// refusal otherwise (`DoneError::Refused`). Never moves an issue to `done`: that happens when the
/// owner-approved PR is merged. The evidence (B-M3), checked in the transaction that moves the
/// issue, is `evidence_problem`: every live PR opened on the forge by this agent, fresh, with
/// checks neither failing nor running and everything pushed. A comment, a claim or a PR the agent
/// merely asked for are not evidence.
pub async fn submit_with_evidence(
    pool: &SqlitePool,
    issue: IssueId,
    dev: AgentId,
) -> Result<crate::domain::work::Issue, DoneError> {
    submit_in(pool, issue, dev, true)
        .await?
        .ok_or_else(|| DoneError::Refused(NO_EVIDENCE.to_owned()))
}

const NO_EVIDENCE: &str = "done needs a pull request opened on the forge for this issue; \
    without one, use submit_for_review";

/// How old the poller's last word on a PR may be (minutes) before it is not evidence: the poll
/// runs every minute, so ten is a poller that has stopped.
const EVIDENCE_MAX_AGE_MIN: f64 = 10.0;

/// Why the live `prs` of `issue` are not evidence of `dev`'s finished work, if they are not. The
/// forge poller's rows are the only source, so each is checked for what makes it untrustworthy:
/// not opened on the forge (number, URL, head), authored by another agent, a poll that failed or
/// went quiet (`last_error`, an old `updated_at`), checks failing or still running (`none`, a
/// forge with no checks, passes: QA then judges it), a head that is not the head pushed, a refused
/// push, commits made after the last push, or an approved repo of the issue with no PR.
async fn evidence_problem(
    conn: &mut SqliteConnection,
    issue: IssueId,
    dev: AgentId,
    prs: &[IssuePr],
) -> Result<Option<String>, Error> {
    let missing: Option<String> = sqlx::query_scalar(
        "SELECT r.name FROM citadel_issue_repos ir JOIN citadel_project_repos r ON r.id = ir.repo_id \
         WHERE ir.issue_id = ?1 AND ir.state = 'approved' AND NOT EXISTS (SELECT 1 FROM \
         citadel_issue_prs p WHERE p.issue_id = ?1 AND p.repo_id = ir.repo_id \
         AND p.state <> 'closed') LIMIT 1",
    )
    .bind(issue.0)
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(repo) = missing {
        return Ok(Some(format!(
            "the repo {repo} of this issue has no pull request"
        )));
    }
    for pr in prs.iter().filter(|p| p.phase.is_live()) {
        let (unpushed, pushed_sha, age): (bool, Option<String>, f64) = sqlx::query_as(
            "SELECT unpushed_at IS NOT NULL, pushed_sha, \
             (julianday('now') - julianday(updated_at)) * 1440.0 \
             FROM citadel_issue_prs WHERE issue_id = ? AND repo_id = ?",
        )
        .bind(issue.0)
        .bind(pr.repo_id)
        .fetch_one(&mut *conn)
        .await?;
        let head = &pr.head;
        let problem = if pr.phase == PrPhase::Requested
            || pr.number.is_none()
            || pr.url.is_none()
            || pr.head_sha.is_none()
        {
            "is not opened on the forge yet"
        } else if pr.author != Some(dev) {
            "was not opened by you"
        } else if pr.last_error.is_some() {
            "failed its last forge sync"
        } else if !(age <= EVIDENCE_MAX_AGE_MIN) {
            "has not been seen on the forge lately"
        } else if pr.checks == "failure" {
            "has failing checks"
        } else if pr.checks == "pending" {
            "has checks still running"
        } else if pushed_sha.is_some() && pushed_sha != pr.head_sha {
            "is not at the head that was pushed"
        } else if pr.push_held.is_some() || unpushed {
            "has work that is not pushed"
        } else {
            continue;
        };
        return Ok(Some(format!("the PR of {head} {problem}")));
    }
    Ok(None)
}

async fn submit_in(
    pool: &SqlitePool,
    issue: IssueId,
    dev: AgentId,
    evidence: bool,
) -> Result<Option<crate::domain::work::Issue>, DoneError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let Some((_, prs)) = live_prs(&mut tx, issue).await? else {
        return Ok(None);
    };
    if evidence && let Some(why) = evidence_problem(&mut tx, issue, dev, &prs).await? {
        return Err(DoneError::Refused(why));
    }
    let project: i64 = sqlx::query_scalar("SELECT project_id FROM citadel_issues WHERE id = ?")
        .bind(issue.0)
        .fetch_one(&mut *tx)
        .await?;
    let reviewer = qa_reviewer_in(&mut tx, ProjectId(project), dev).await?;
    let step = IssueTransition::SubmitForReview { reviewer };
    let moved = transition_issue_in(&mut tx, issue, &step, AuditActor::System).await?;
    let mut texts = vec![];
    for pr in prs.iter().filter(|p| p.phase.is_live()) {
        texts.push(match (pr.number, &pr.url) {
            (Some(_), Some(url)) => format!("{} ({url})", pr_label(&mut tx, pr).await?),
            _ => format!("the PR of {} (opens once its branch is pushed)", pr.head),
        });
    }
    note(
        &mut tx,
        issue,
        &format!("Done; ready for QA: {}.", texts.join(", ")),
    )
    .await?;
    tx.commit().await?;
    Ok(Some(moved))
}

/// The QA reviewer's verdict on the issue it reviews (`in_review`, waiting on `qa`): pass
/// opens a `pr_merge` approval at `now` covering every PR still to merge and hands the issue to
/// the admin; fail sends it back to the PR's author with `notes`. Both comment the notes as the
/// reviewer. The approval, on a pass.
pub async fn qa_verdict(
    pool: &SqlitePool,
    issue: IssueId,
    qa: AgentId,
    pass: bool,
    notes: &str,
    now: &str,
) -> Result<Option<Approval>, DoneError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let i = crate::store::work::issue_in(&mut tx, issue)
        .await?
        .ok_or_else(|| DoneError::Refused("no such issue".to_owned()))?;
    if i.state != IssueState::InReview || i.next_actor != Some(NextActor::Agent(qa)) {
        let why = "you can only give a verdict on an issue in review that waits on you";
        return Err(DoneError::Refused(why.to_owned()));
    }
    let (company, prs) = live_prs(&mut tx, issue)
        .await?
        .ok_or_else(|| DoneError::Refused("the issue has no open PR".to_owned()))?;
    sqlx::query("INSERT INTO citadel_comments (issue_id, author_agent_id, body) VALUES (?, ?, ?)")
        .bind(issue.0)
        .bind(qa.0)
        .bind(format!(
            "QA {}: {notes}",
            if pass { "passed" } else { "failed" }
        ))
        .execute(&mut *tx)
        .await?;
    let by = AuditActor::System;
    let live: Vec<&IssuePr> = prs.iter().filter(|p| p.phase.is_live()).collect();
    if !pass {
        let author = live.iter().find_map(|p| p.author).ok_or_else(|| {
            DoneError::Refused("the PR has no author to send it back to".to_owned())
        })?;
        back_to(&mut tx, issue, Some(author), by).await?;
        let details = json!({"pass": false, "notes": notes});
        append(
            &mut tx,
            company,
            by,
            "qa.verdict",
            ("issue", issue.0),
            details,
        )
        .await?;
        tx.commit().await?;
        return Ok(None);
    }
    let mut listed = vec![];
    for pr in &live {
        let label = pr_label(&mut tx, pr).await?;
        let repo: String =
            sqlx::query_scalar("SELECT name FROM citadel_project_repos WHERE id = ?")
                .bind(pr.repo_id)
                .fetch_one(&mut *tx)
                .await?;
        let (Some(n), PrPhase::Open) = (pr.number, pr.phase) else {
            let which = if live.len() > 1 {
                format!("the {repo} PR")
            } else {
                "the PR".to_owned()
            };
            let why = format!("{which} is not open yet; you are woken when it is");
            return Err(DoneError::Refused(why));
        };
        if pr.checks == "failure" || pr.checks == "pending" {
            let why = format!(
                "{label}'s checks are {}; pass it once they succeed",
                pr.checks
            );
            return Err(DoneError::Refused(why));
        }
        listed.push((
            label,
            json!({"repo": repo, "repo_id": pr.repo_id, "pr": n, "url": pr.url,
                                   "head_sha": pr.head_sha, "checks_note": pr.checks_note}),
        ));
    }
    let first = live[0];
    let mut summary = match listed.as_slice() {
        [(label, _)] => format!("Merge {label}: {}", first.title),
        _ => {
            let labels: Vec<&str> = listed.iter().map(|(l, _)| l.as_str()).collect();
            format!(
                "Merge {} PRs ({}): {}",
                listed.len(),
                labels.join(", "),
                first.title
            )
        }
    };
    // Checks the token could not read pass as what it could read; the approver is told.
    if let Some(partial) = live.iter().find_map(|p| p.checks_note.as_deref()) {
        summary = format!("{summary} [{partial}]");
    }
    let payload = json!({"summary": summary, "pr": first.number, "url": first.url,
                         "head_sha": first.head_sha, "qa_notes": notes,
                         "prs": listed.into_iter().map(|(_, v)| v).collect::<Vec<_>>()});
    let approval = merge_approval(&mut tx, (company, issue, qa), payload, now).await?;
    let to_owner = IssueTransition::Reassign {
        next: NextActor::Human(ESCALATION_USER),
    };
    transition_issue_in(&mut tx, issue, &to_owner, by).await?;
    let details = json!({"pass": true, "notes": notes, "approval": approval.id.0});
    append(
        &mut tx,
        company,
        by,
        "qa.verdict",
        ("issue", issue.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(Some(approval))
}

/// Opens a `pr_merge` approval on the issue, requested by `by`.
async fn merge_approval(
    conn: &mut SqliteConnection,
    (company, issue, by): (i64, IssueId, AgentId),
    payload: serde_json::Value,
    now: &str,
) -> Result<Approval, Error> {
    let new = NewApproval {
        company_id: CompanyId(company),
        kind: ApprovalKind::PrMerge,
        issue_id: Some(issue),
        sprint_id: None,
        agent_id: None,
        requested_by: by,
        payload: payload.to_string(),
    };
    open_approval_in(conn, &new, None, now).await
}

/// Citadel merged the issue's PR on `repo`: merged, commented, audited, and the issue done once
/// every PR of it is.
pub async fn pr_merged(pool: &SqlitePool, at: (IssueId, i64)) -> Result<(), Error> {
    pr_finished(pool, at, true).await
}

/// The forge would not merge the approved PR on `repo` (`why`): it is open again, and so is
/// every other PR of the issue still waiting to merge. With none of them merged yet, the issue
/// goes back to its author with the reason. After one merged (#53), the merged ones are left
/// alone, a new `pr_merge` approval for the rest is opened at `now` with the reason, and the
/// issue stays in review with the admin.
pub async fn pr_merge_refused(
    pool: &SqlitePool,
    (issue, repo): (IssueId, i64),
    why: &str,
    now: &str,
) -> Result<(), Error> {
    let why = &super::untrusted(why, 300);
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let Some((company, prs)) = live_prs(&mut tx, issue).await? else {
        return Ok(());
    };
    // Only a PR being merged can be refused a merge: one that is merged (an overlapping pass
    // merged it first), open or closed stays as it is, and never flips back to open.
    let Some(pr) = prs
        .iter()
        .find(|p| p.repo_id == repo && p.phase == PrPhase::Merging)
    else {
        return Ok(());
    };
    sqlx::query(
        "UPDATE citadel_issue_prs SET state = 'open', last_error = ? \
         WHERE issue_id = ? AND repo_id = ? AND state = 'merging'",
    )
    .bind(why)
    .bind(issue.0)
    .bind(repo)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE citadel_issue_prs SET state = 'open' WHERE issue_id = ? AND state = 'merging'",
    )
    .bind(issue.0)
    .execute(&mut *tx)
    .await?;
    let label = pr_label(&mut tx, pr).await?;
    note(&mut tx, issue, &format!("Merging {label} failed: {why}")).await?;
    let merged: Vec<&IssuePr> = prs.iter().filter(|p| p.phase == PrPhase::Merged).collect();
    let n = pr.number.unwrap_or(0);
    let details = json!({"repo": repo, "number": n, "error": why, "partial": !merged.is_empty()});
    let system = AuditActor::System;
    append(
        &mut tx,
        company,
        system,
        "pr.merge_failed",
        ("issue", issue.0),
        details,
    )
    .await?;
    if merged.is_empty() {
        back_to(&mut tx, issue, pr.author, system).await?;
        return tx.commit().await;
    }
    let previous: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT id, requested_by_agent_id, payload FROM citadel_approvals WHERE issue_id = ? \
         AND kind = 'pr_merge' ORDER BY id DESC LIMIT 1",
    )
    .bind(issue.0)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((id, requester, payload)) = previous {
        let mut payload: serde_json::Value = serde_json::from_str(&payload).unwrap_or_default();
        let mut left = vec![];
        for p in prs.iter().filter(|p| p.phase != PrPhase::Merged) {
            left.push(pr_label(&mut tx, p).await?);
        }
        payload["summary"] = format!(
            "Merge the rest ({}) after {label} failed: {why}",
            left.join(", ")
        )
        .into();
        // The new approval covers what is left, at the heads the poller saw last: a head the
        // first approval named may be gone, and a merged PR is not open to merge again.
        let rest: Vec<&IssuePr> = prs.iter().filter(|p| p.phase != PrPhase::Merged).collect();
        payload["prs"] = rest
            .iter()
            .map(|p| {
                json!({"repo_id": p.repo_id, "pr": p.number, "url": p.url,
                       "head_sha": p.head_sha, "checks_note": p.checks_note})
            })
            .collect();
        if let Some(first) = rest.first() {
            payload["pr"] = json!(first.number);
            payload["url"] = json!(first.url);
            payload["head_sha"] = json!(first.head_sha);
        }
        payload["reopened_from"] = id.into();
        payload["reason"] = why.as_str().into();
        let at = (company, issue, AgentId(requester));
        let reopened = merge_approval(&mut tx, at, payload, now).await?;
        let details = json!({"approval": reopened.id.0, "reopened_from": id, "reason": why});
        append(
            &mut tx,
            company,
            system,
            "approval.reopened",
            ("issue", issue.0),
            details,
        )
        .await?;
    }
    tx.commit().await
}
