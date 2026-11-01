//! The read tools: `get_issue`, `get_context`, `list_backlog` and `get_approval`. Every text they return is
//! size-capped, and comments come a page at a time, so one call cannot flood the agent's context.

use ainkrad_proto::redact::Redactor;
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{Result, ToolError, clip, int, text};
use super::plan::planned_project;
use super::tools::{next_actor, summary, target};
use crate::domain::gov::{ApprovalId, KnowledgeEntry};
use crate::domain::org::AgentId;
use crate::domain::work::{Actor, BacklogFilter, EpicId, LabelId, UserId};
use crate::store::exec::RunScope;
use crate::store::gov::{get_approval as stored_approval, project_knowledge};
use crate::store::work::{
    MAX_BACKLOG_PAGE, backlog_page, get_issue as stored_issue, get_project, issue_key,
    list_blockers, list_comments, list_issues, project_profile, project_spec,
};
use ainkrad_core_server::api::App;

/// The most of an issue body returned.
const MAX_BODY: usize = 20 * 1024;
/// The most of each comment or reply returned.
const MAX_ENTRY: usize = 4 * 1024;
/// Comments per page by default, and at most.
const PAGE: i64 = 20;
const MAX_PAGE: i64 = 50;

fn author(a: Actor) -> Value {
    match a {
        Actor::Agent(id) => json!({"agent": id.0}),
        Actor::Human(id) => json!({"user": id.0}),
    }
}

/// The issue (default: the run's own) or one of its subtasks, a page of its comments, its
/// blockers and subtasks.
pub(super) async fn get_issue(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
    red: &Redactor,
) -> Result<Value> {
    let issue = target(app, scope, int(args, "issue_id")?).await?;
    let after = int(args, "comments_after")?;
    let before = int(args, "comments_before")?;
    let limit = int(args, "limit")?.unwrap_or(PAGE);
    if !(1..=MAX_PAGE).contains(&limit) {
        return Err(ToolError::Invalid(format!("limit must be 1 to {MAX_PAGE}")));
    }
    let pool = &app.pool;
    // ponytail: reads every comment and filters; a keyset query when issues get long threads.
    let all = list_comments(pool, issue.id).await?;
    // Forward from comments_after; otherwise the newest page (before comments_before), so a long
    // thread never hides the latest instructions behind its oldest comments.
    let (page, next_after, older_before) = if let Some(after) = after {
        let mut page: Vec<_> = all.into_iter().filter(|c| c.id.0 > after).collect();
        let more = page.len() as i64 > limit;
        page.truncate(limit as usize);
        let next = more.then(|| page.last().map(|c| c.id.0)).flatten();
        (page, next, None)
    } else {
        let mut page: Vec<_> = all
            .into_iter()
            .filter(|c| before.is_none_or(|b| c.id.0 < b))
            .collect();
        let older = page.len() as i64 > limit;
        let page = page.split_off(page.len().saturating_sub(limit as usize));
        let older = older.then(|| page.first().map(|c| c.id.0)).flatten();
        (page, None, older)
    };
    let comments: Vec<Value> = page
        .iter()
        .map(|c| {
            let (body, truncated) = clip(&red.text(&c.body), MAX_ENTRY);
            json!({"id": c.id.0, "author": author(c.author), "body": body, "truncated": truncated})
        })
        .collect();
    let mut blockers = vec![];
    for id in list_blockers(pool, issue.id).await? {
        if let Some(b) = stored_issue(pool, id).await? {
            blockers.push(summary(app, &b).await?);
        }
    }
    let mut subtasks = vec![];
    for s in list_issues(pool, issue.project_id).await? {
        if s.parent_id == Some(issue.id) {
            subtasks.push(summary(app, &s).await?);
        }
    }
    let (body, body_truncated) = clip(&red.text(&issue.body), MAX_BODY);
    Ok(json!({
        "id": issue.id.0,
        "key": issue_key(pool, issue.id).await?,
        "kind": issue.kind.as_str(),
        "title": issue.title,
        "body": body,
        "body_truncated": body_truncated,
        "state": issue.state.as_str(),
        "next_actor": next_actor(&issue.next_actor),
        "you": {"agent": scope.agent_id.0},
        "parent_id": issue.parent_id.map(|p| p.0),
        "comments": comments,
        "next_comments_after": next_after,
        "older_comments_before": older_before,
        "blockers": blockers,
        "subtasks": subtasks,
    }))
}

/// The run's project (with its spec), its profile and its accepted knowledge fitted to the
/// budget (with what was left out).
pub(super) async fn get_context(app: &App, scope: RunScope) -> Result<Value> {
    let pool = &app.pool;
    let (mut project, mut profile) = (Value::Null, Value::Null);
    let mut knowledge = crate::domain::gov::RunKnowledge::default();
    if let Some(own) = scope.issue_id
        && let Some(issue) = stored_issue(pool, own).await?
    {
        if let Some(p) = get_project(pool, issue.project_id).await? {
            let spec = project_spec(pool, p.id).await?.unwrap_or_default();
            let (spec, spec_truncated) = clip(&spec, MAX_BODY);
            project = json!({"id": p.id.0, "key": p.key, "name": p.name, "mode": p.mode.as_str(),
                             "sprint_approval": p.sprint_approval.as_str(), "spec": spec,
                             "spec_truncated": spec_truncated});
        }
        if let Some(p) = project_profile(pool, issue.project_id).await? {
            profile = serde_json::to_value(&p.profile).unwrap_or_default();
        }
        knowledge = project_knowledge(pool, issue.project_id).await?;
    }
    let entry =
        |k: &KnowledgeEntry| json!({"id": k.id.0, "kind": k.kind.as_str(), "title": k.title});
    Ok(json!({
        "project": project,
        "profile": profile,
        "knowledge": knowledge.entries.iter().map(|k| {
            let mut v = entry(k);
            v["body"] = k.body.clone().into();
            v
        }).collect::<Vec<_>>(),
        "dropped_knowledge": knowledge.dropped.iter().map(entry).collect::<Vec<_>>(),
    }))
}

/// A page of a project's backlog (default: the run's issue's project), filtered, by rank. Only
/// for the product owner or team lead of the project's team, or the company's CEO or CTO.
pub(super) async fn list_backlog(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let pool = &app.pool;
    let project_id = planned_project(app, scope, int(args, "project_id")?).await?;
    let parsed =
        |key: &str| -> Result<Option<String>> { Ok(text(args, key, 32)?.map(str::to_owned)) };
    let bad = |key: &str| ToolError::Invalid(format!("unknown {key}"));
    let assignee = match (
        int(args, "assignee_agent_id")?,
        int(args, "assignee_user_id")?,
    ) {
        (Some(_), Some(_)) => {
            let why = "give assignee_agent_id or assignee_user_id, not both".to_owned();
            return Err(ToolError::Invalid(why));
        }
        (Some(a), None) => Some(Actor::Agent(AgentId(a))),
        (None, Some(u)) => Some(Actor::Human(UserId(u))),
        (None, None) => None,
    };
    let filter = BacklogFilter {
        epic_id: int(args, "epic_id")?.map(EpicId),
        label_id: int(args, "label_id")?.map(LabelId),
        kind: parsed("kind")?
            .map(|k| k.parse().map_err(|_| bad("kind")))
            .transpose()?,
        state: parsed("state")?
            .map(|s| s.parse().map_err(|_| bad("state")))
            .transpose()?,
        assignee,
    };
    let offset = int(args, "offset")?.unwrap_or(0);
    let limit = int(args, "limit")?.unwrap_or(PAGE);
    let max = i64::from(MAX_BACKLOG_PAGE);
    if offset < 0 || !(1..=max).contains(&limit) {
        let why = format!("offset must be 0 or more and limit 1 to {max}");
        return Err(ToolError::Invalid(why));
    }
    let page = backlog_page(pool, project_id, &filter, offset as u32, limit as u32).await?;
    // A full page may have more after it; the next one is empty if not.
    let more = page.len() as i64 == limit;
    let mut issues = vec![];
    for i in &page {
        issues.push(json!({
            "id": i.id.0,
            "key": issue_key(pool, i.id).await?,
            "kind": i.kind.as_str(),
            "title": i.title,
            "state": i.state.as_str(),
            "points": i.points,
            "epic_id": i.epic_id.map(|e| e.0),
            "owner": i.owner.map(author),
            "next_actor": next_actor(&i.next_actor),
        }));
    }
    Ok(json!({"issues": issues, "next_offset": more.then_some(offset + limit)}))
}

/// An approval the run's agent asked for: its kind, status, the decider's reply (or why it
/// expired), its deadline and subjects. Anyone else's gets the same answer as a missing one.
pub(super) async fn get_approval(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let id = int(args, "approval_id")?
        .ok_or_else(|| ToolError::Invalid("approval_id is required".to_owned()))?;
    let a = stored_approval(&app.pool, ApprovalId(id))
        .await?
        .filter(|a| a.company_id == scope.company_id && a.requested_by == scope.agent_id)
        .ok_or_else(|| ToolError::Refused(format!("no approval {id} of yours")))?;
    Ok(
        json!({"approval_id": a.id.0, "kind": a.kind.as_str(), "status": a.status.as_str(),
              "reply": a.reply.as_deref().map(|r| clip(r, MAX_ENTRY).0),
              "expires_at": a.expires_at, "issue_id": a.issue_id.map(|i| i.0)}),
    )
}
