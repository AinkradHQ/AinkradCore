//! The write tools. Each is a thin call into the store, as the run's agent, on the run's issue
//! or one of its subtasks; the store's own rules (next actor, blockers, cycles) still apply.

use citadel_core::audit::AuditActor;
use citadel_core::auth::RunScope;
use citadel_core::gov::{ApprovalKind, KnowledgeEntryId, KnowledgeKind, NewApproval};
use citadel_core::org::AgentId;
use citadel_core::work::{
    Actor, BlockerLink, IssueId, IssueKind, IssueState, IssueTransition, NewComment, NewIssue,
    NextActor, UserId,
};
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{MAX_TEXT, MAX_TITLE, Result, ToolError, int, required, text};
use super::tools::{company_issue, next_actor, target};
use crate::api::App;
use crate::store::exec::{EmptyDone, done_evidence, get_run, refuse_empty_done};
use crate::store::gov::{
    KnowledgeError, Proposal, decide_knowledge, get_knowledge_entry, open_approval, propose,
};
use crate::store::org::{get_agent, user_exists};
use crate::store::work::{
    BlockerError, IssueTransitionError, add_blocker, create_comment, create_issue, issue_key,
    list_blockers, plan_hold, transition_issue,
};

/// The user a new blocker waits on when the agent names no one: the admin.
const ADMIN: UserId = UserId(1);

pub(super) async fn comment(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let issue = target(app, scope, int(args, "issue_id")?).await?;
    let new = NewComment {
        issue_id: issue.id,
        author: Actor::Agent(scope.agent_id),
        body: required(args, "body", MAX_TEXT)?.to_owned(),
        run_id: Some(scope.run_id),
        idempotency_key: text(args, "idempotency_key", MAX_TITLE)?.map(str::to_owned),
    };
    let c = create_comment(&app.pool, &new).await?;
    Ok(json!({"comment_id": c.id.0, "issue_id": c.issue_id.0}))
}

/// A person the agent names (`<prefix>_agent_id` or `<prefix>_user_id`, at most one): an
/// agent of its own company, or a user; `None` when neither is given.
async fn person(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
    prefix: &str,
) -> Result<Option<Actor>> {
    let agent = int(args, &format!("{prefix}_agent_id"))?;
    let user = int(args, &format!("{prefix}_user_id"))?;
    match (agent, user) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(ToolError::Invalid(format!(
            "give {prefix}_agent_id or {prefix}_user_id, not both"
        ))),
        (Some(id), None) => match get_agent(&app.pool, AgentId(id)).await? {
            Some(a) if a.company_id == scope.company_id => Ok(Some(Actor::Agent(a.id))),
            _ => Err(ToolError::Refused(format!("no agent {id} in this company"))),
        },
        (None, Some(id)) if user_exists(&app.pool, UserId(id)).await? => {
            Ok(Some(Actor::Human(UserId(id))))
        }
        (None, Some(id)) => Err(ToolError::Refused(format!("no user {id}"))),
    }
}

/// Links `blocker` before `blocked`; an existing link is fine.
async fn link(app: &App, blocker: i64, blocked: i64) -> Result<()> {
    let pool = &app.pool;
    let blocked = citadel_core::work::IssueId(blocked);
    if blocker == blocked.0 {
        return Err(ToolError::Refused(
            "an issue cannot block itself".to_owned(),
        ));
    }
    if list_blockers(pool, blocked)
        .await?
        .iter()
        .any(|b| b.0 == blocker)
    {
        return Ok(());
    }
    let link = BlockerLink {
        blocker: citadel_core::work::IssueId(blocker),
        blocked,
    };
    match add_blocker(pool, link).await {
        Ok(()) => Ok(()),
        Err(BlockerError::Cycle) => Err(ToolError::Refused(
            "that link would make a blocker cycle".to_owned(),
        )),
        Err(BlockerError::Db(e)) => Err(e.into()),
    }
}

/// Moves the issue, only while the agent is its next actor. `done` on an issue with a PR goes to
/// its QA reviewer instead (`in_review`, E9.3).
pub(super) async fn transition(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let issue = target(app, scope, int(args, "issue_id")?).await?;
    let me = NextActor::Agent(scope.agent_id);
    if issue.next_actor.as_ref() != Some(&me) {
        return Err(ToolError::Refused(format!(
            "you are not this issue's next actor (it waits on {})",
            next_actor(&issue.next_actor)
        )));
    }
    let step = match required(args, "transition", MAX_TITLE)? {
        "start" => {
            if let Some(why) = plan_hold(&app.pool, issue.id, scope.agent_id).await? {
                return Err(ToolError::Refused(why));
            }
            IssueTransition::Start
        }
        "submit_for_review" => match person(app, scope, args, "reviewer").await? {
            Some(Actor::Agent(a)) if a == scope.agent_id => {
                return Err(ToolError::Refused(
                    "you cannot review your own issue".to_owned(),
                ));
            }
            Some(reviewer) => IssueTransition::SubmitForReview { reviewer },
            None => {
                return Err(ToolError::Invalid(
                    "submit_for_review needs reviewer_agent_id or reviewer_user_id".to_owned(),
                ));
            }
        },
        "block" => {
            if let Some(blocker) = int(args, "blocker_issue_id")? {
                company_issue(app, scope, blocker).await?;
                link(app, blocker, issue.id.0).await?;
            }
            IssueTransition::Block
        }
        "done" => IssueTransition::Done,
        other => {
            return Err(ToolError::Invalid(format!(
                "transition {other:?} is not one of start, submit_for_review, block, done"
            )));
        }
    };
    let actor = AuditActor::Agent(scope.agent_id);
    // Only a done the issue's state allows is judged; any other is refused below, as illegal.
    if step == IssueTransition::Done && issue.state == IssueState::InProgress {
        empty_done(app, scope, issue.id).await?;
    }
    // With a PR, done goes to QA first (E9.3).
    let reviewed = match step {
        IssueTransition::Done => super::forge::done(app, scope, issue.id).await?,
        _ => None,
    };
    let moved = match reviewed {
        Some(moved) => moved,
        None => match transition_issue(&app.pool, issue.id, &step, actor).await {
            Ok(moved) => moved,
            Err(IssueTransitionError::Db(e)) => return Err(e.into()),
            Err(e) => return Err(ToolError::Refused(e.to_string())),
        },
    };
    Ok(
        json!({"issue_id": moved.id.0, "key": issue_key(&app.pool, moved.id).await?,
              "state": moved.state.as_str(), "next_actor": next_actor(&moved.next_actor)}),
    )
}

/// Refuses a done with nothing to show for it (E15.7, pain #3): no diff from any run of the
/// issue or from this run, no PR, no comment from this run. The agent is told why; its second
/// empty done on the issue escalates it up the chain.
async fn empty_done(app: &App, scope: RunScope, issue: IssueId) -> Result<()> {
    let pool = &app.pool;
    if done_evidence(pool, issue, scope.run_id).await? {
        return Ok(());
    }
    let run = get_run(pool, scope.run_id)
        .await?
        .ok_or_else(|| ToolError::Refused("your run is gone".to_owned()))?;
    let why = "done refused: nothing shows this work was done (no change in the issue's \
               worktree, no PR, and no comment from this run)";
    match refuse_empty_done(pool, issue, &run, &app.clock.now()).await {
        Ok(EmptyDone::Refused) => Err(ToolError::Refused(format!(
            "{why}. Make and save the change, or comment what you did and why no change was \
             needed, then try again. A second empty done escalates the issue."
        ))),
        Ok(EmptyDone::Escalated(to)) => Err(ToolError::Refused(format!(
            "{why}, a second time: the issue was escalated to {}. Stop working on it.",
            next_actor(&Some(to))
        ))),
        Err(IssueTransitionError::Db(e)) => Err(e.into()),
        Err(e) => Err(ToolError::Refused(e.to_string())),
    }
}

/// A subtask of the run's issue, owned by and waiting on the agent.
pub(super) async fn create_subtask(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let parent = target(app, scope, None).await?;
    let me = scope.agent_id;
    let new = NewIssue {
        project_id: parent.project_id,
        epic_id: parent.epic_id,
        parent_id: Some(parent.id),
        kind: IssueKind::Subtask,
        title: required(args, "title", MAX_TITLE)?.to_owned(),
        body: text(args, "body", MAX_TEXT)?.unwrap_or_default().to_owned(),
        state: IssueState::Todo,
        owner: Some(Actor::Agent(me)),
        next_actor: Some(NextActor::Agent(me)),
        points: None,
        sprint_id: parent.sprint_id,
    };
    let created = create_issue(&app.pool, &new).await?;
    Ok(json!({"issue_id": created.id.0, "key": issue_key(&app.pool, created.id).await?}))
}

/// Links an existing issue, or a new task, as a blocker of the run's issue (or a subtask).
pub(super) async fn report_blocker(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let blocked = target(app, scope, int(args, "issue_id")?).await?;
    let blocker = match int(args, "blocker_issue_id")? {
        Some(id) => company_issue(app, scope, id).await?,
        None => {
            let title = required(args, "title", MAX_TITLE)
                .map_err(|_| ToolError::Invalid("give blocker_issue_id, or a title".to_owned()))?;
            let assignee = person(app, scope, args, "assignee").await?;
            let new = NewIssue {
                project_id: blocked.project_id,
                epic_id: None,
                parent_id: None,
                kind: IssueKind::Task,
                title: title.to_owned(),
                body: text(args, "body", MAX_TEXT)?.unwrap_or_default().to_owned(),
                state: IssueState::Todo,
                owner: None,
                next_actor: Some(assignee.unwrap_or(Actor::Human(ADMIN)).into()),
                points: None,
                sprint_id: None,
            };
            create_issue(&app.pool, &new).await?
        }
    };
    link(app, blocker.id.0, blocked.id.0).await?;
    Ok(json!({"blocker_issue_id": blocker.id.0,
              "blocker_key": issue_key(&app.pool, blocker.id).await?,
              "blocked_issue_id": blocked.id.0}))
}

pub(super) async fn request_approval(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
) -> Result<Value> {
    let issue = target(app, scope, int(args, "issue_id")?).await?;
    let kind = match required(args, "kind", MAX_TITLE)?.parse::<ApprovalKind>() {
        Ok(ApprovalKind::SprintCommit | ApprovalKind::HireAgent | ApprovalKind::WorkflowPush)
        | Err(_) => {
            return Err(ToolError::Invalid(
                "kind must be pr_merge, permission_escalation or budget_overrun (a hire is \
                 request_hire)"
                    .to_owned(),
            ));
        }
        Ok(kind) => kind,
    };
    let payload = json!({"summary": required(args, "summary", MAX_TEXT)?,
                         "details": text(args, "details", MAX_TEXT)?,
                         "run": scope.run_id.0});
    let new = NewApproval {
        company_id: scope.company_id,
        kind,
        issue_id: Some(issue.id),
        sprint_id: None,
        agent_id: None,
        requested_by: scope.agent_id,
        payload: payload.to_string(),
    };
    let a = open_approval(&app.pool, &new, &app.clock.now()).await?;
    Ok(json!({"approval_id": a.id.0, "status": a.status.as_str(), "expires_at": a.expires_at}))
}

/// Proposes an entry for the run's project; a `state` entry with `target: "spec"` proposes a
/// new project spec (its body).
pub(super) async fn propose_knowledge(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
) -> Result<Value> {
    let issue = target(app, scope, None).await?;
    let kind = required(args, "kind", MAX_TITLE)?
        .parse::<KnowledgeKind>()
        .map_err(|_| {
            ToolError::Invalid("kind must be decision, landmine, state or retro".to_owned())
        })?;
    let (spec, profile_field) = match text(args, "target", MAX_TITLE)? {
        None => (false, None),
        Some("spec") => (true, None),
        Some(t) => match t.strip_prefix("profile.") {
            Some(field) => (false, Some(field.to_owned())),
            None => {
                let why = "target must be spec or profile.<field>".to_owned();
                return Err(ToolError::Invalid(why));
            }
        },
    };
    let p = Proposal {
        project: issue.project_id,
        kind,
        title: required(args, "title", MAX_TITLE)?.to_owned(),
        body: required(args, "body", MAX_TEXT)?.to_owned(),
        spec,
        profile_field,
        rationale: text(args, "rationale", MAX_TITLE)?.map(str::to_owned),
    };
    let k = propose(&app.pool, &p, scope.agent_id)
        .await
        .map_err(knowledge_error)?;
    Ok(json!({"knowledge_entry_id": k.id.0, "status": k.status.as_str()}))
}

/// Accepts or rejects a pending proposal of the run's project, as its team lead.
pub(super) async fn review_knowledge(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
) -> Result<Value> {
    let issue = target(app, scope, None).await?;
    let id = int(args, "entry_id")?
        .ok_or_else(|| ToolError::Invalid("entry_id is required".to_owned()))?;
    let accept = match required(args, "verdict", MAX_TITLE)? {
        "accept" => true,
        "reject" => false,
        _ => {
            return Err(ToolError::Invalid(
                "verdict must be accept or reject".to_owned(),
            ));
        }
    };
    let reason = text(args, "reason", MAX_TEXT)?;
    // Another project's entry looks like none.
    match get_knowledge_entry(&app.pool, KnowledgeEntryId(id)).await? {
        Some(k) if k.project_id == issue.project_id => {}
        _ => return Err(ToolError::Refused(format!("no entry {id} in your project"))),
    }
    let by = AuditActor::Agent(scope.agent_id);
    let k = decide_knowledge(&app.pool, KnowledgeEntryId(id), accept, by, reason)
        .await
        .map_err(knowledge_error)?;
    Ok(
        json!({"knowledge_entry_id": k.id.0, "status": k.status.as_str(),
              "spec_applied": accept && k.targets_spec}),
    )
}

fn knowledge_error(e: KnowledgeError) -> ToolError {
    match e {
        KnowledgeError::Db(e) => e.into(),
        KnowledgeError::Invalid(why) => ToolError::Invalid(why),
        e => ToolError::Refused(e.to_string()),
    }
}
