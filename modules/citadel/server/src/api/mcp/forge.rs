//! The forge tools (E9): `open_pr` asks for the run's issue's pull request; it is opened on the
//! project's forge once the run ends and its branch is pushed, and followed from there. The
//! done flow (E9.3): `done` with a PR goes to QA (`done`), whose `qa_verdict` passes it to a
//! merge approval or fails it back to the developer.

use citadel_core::auth::RunScope;
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use citadel_core::work::{Issue, IssueId};

use super::args::{MAX_TEXT, MAX_TITLE, Result, ToolError, required, text};
use super::tools::target;
use crate::api::App;
use crate::store::forge::submit_for_qa;
use crate::store::forge::{DoneError, IssuePr, PrError, qa_verdict as verdict, request_pr};

/// The PR as an agent sees it.
pub(super) fn pr_json(pr: &IssuePr) -> Value {
    json!({"repo_id": pr.repo_id, "state": pr.phase.as_str(), "number": pr.number, "url": pr.url, "head": pr.head,
           "base": pr.base, "checks": pr.checks, "checks_note": pr.checks_note,
           "last_error": pr.last_error})
}

pub(super) async fn open_pr(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let issue = target(app, scope, None).await?;
    let title = required(args, "title", MAX_TITLE)?;
    let body = text(args, "body", MAX_TEXT)?.unwrap_or_default();
    let repo = text(args, "repo", MAX_TITLE)?;
    match request_pr(&app.pool, issue.id, repo, scope.agent_id, (title, body)).await {
        Ok(pr) => {
            let mut v = pr_json(&pr);
            v["note"] = "The PR is opened from your branch once this run ends and the branch is \
                         pushed; commit your work before you finish. Its number, URL and checks \
                         come back as comments on the issue."
                .into();
            Ok(v)
        }
        Err(PrError::Db(e)) => Err(e.into()),
        Err(e) => Err(ToolError::Refused(e.to_string())),
    }
}

fn done_error(e: DoneError) -> ToolError {
    match e {
        DoneError::Db(e) => e.into(),
        e => ToolError::Refused(e.to_string()),
    }
}

/// The run's agent's `done` on `issue`: with a live PR, `in_review` with its QA reviewer;
/// `None` without one.
pub(super) async fn done(app: &App, scope: RunScope, issue: IssueId) -> Result<Option<Issue>> {
    submit_for_qa(&app.pool, issue, scope.agent_id)
        .await
        .map_err(done_error)
}

/// The QA reviewer's verdict on the issue it reviews: pass (a `pr_merge` approval for the
/// owner) or fail (back to the developer with the notes).
pub(super) async fn qa_verdict(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let issue = target(app, scope, None).await?;
    let pass = match required(args, "verdict", MAX_TITLE)? {
        "pass" => true,
        "fail" => false,
        _ => {
            return Err(ToolError::Invalid(
                "verdict must be pass or fail".to_owned(),
            ));
        }
    };
    let notes = required(args, "notes", MAX_TEXT)?;
    let now = app.clock.now();
    let approval = verdict(&app.pool, issue.id, scope.agent_id, pass, notes, &now)
        .await
        .map_err(done_error)?;
    Ok(match approval {
        Some(a) => json!({"verdict": "pass", "approval_id": a.id.0,
                          "note": "The merge waits on the owner's approval."}),
        None => json!({"verdict": "fail", "note": "The issue is back with its developer."}),
    })
}
