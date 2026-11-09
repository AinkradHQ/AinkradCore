//! An issue's comment thread, which is how the admin chats with an agent
//! (`store::work::post_comment`), and its activity (the audit rows about it).

use ainkrad_core::audit::{AuditActor, AuditSeq};
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ADMIN, ApiError, ApiResult};
use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::util::{issue, rule};
use crate::api::model::work::Comment;
use crate::api::scope::Acting;
use crate::api::types::{Timestamp, ts};
use crate::domain::org::AgentId;
use crate::domain::work::{IssueId, UserId};
use crate::store::work;

#[utoipa::path(get, path = "/issues/{id}/comments", operation_id = "listComments",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")),
    responses((status = 200, description = "The issue's thread, oldest first", body = Vec<Comment>)))]
pub async fn list_comments(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<Comment>> {
    let i = issue(&app, id).await?;
    let all = work::list_comments(&app.pool, i.id).await?;
    Ok(Json(all.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewComment {
    pub body: String,
    /// Makes a retry safe: the same key on the same issue posts (and wakes) once.
    pub idempotency_key: Option<String>,
    /// The agent to wake (one of the issue's company). Absent: the first agent the body
    /// mentions (`@agent:<id>`, or `@<name>`, any case), else the agent working a `todo` or
    /// `in_progress` issue (its owner), else its next actor. An open question on the issue is
    /// answered by the comment and wakes its asker either way.
    pub wake_agent_id: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Posted {
    pub comment: Comment,
    /// The agent the comment woke (see `NewComment.wake_agent_id`).
    pub woke_agent_id: Option<i64>,
}

#[utoipa::path(post, path = "/issues/{id}/comments", operation_id = "postComment",
    tag = "issues", params(("id" = i64, Path, description = "Issue id")), request_body = NewComment,
    responses((status = 200, description = "The comment, and the agent it woke", body = Posted)))]
pub async fn post_comment(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Json(c): Json<NewComment>,
) -> ApiResult<Posted> {
    let key = c.idempotency_key.as_deref();
    let wake = c.wake_agent_id.map(AgentId);
    let by = UserId(ADMIN.0);
    let (comment, woke) = work::post_comment(&app.pool, IssueId(id), by, &c.body, key, wake)
        .await
        .map_err(rule)?
        .ok_or_else(|| ApiError::not_found(format!("no issue {id}")))?;
    Ok(Json(Posted {
        comment: comment.into(),
        woke_agent_id: woke.map(|a| a.0),
    }))
}

/// Which page of an issue's activity.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ActivityQuery {
    /// Only rows with a `seq` below this (the previous page's `next_before`).
    pub before: Option<i64>,
    /// At most this many (default and most 100).
    pub limit: Option<u32>,
}

/// Who did it: a person (`user`, with `user_id`) or the system (an agent's act is the system's,
/// its id in `details.agent_id`).
#[derive(Debug, Serialize, ToSchema)]
pub struct ActivityActor {
    pub kind: String,
    pub user_id: Option<i64>,
}

/// One audit row about an issue.
#[derive(Debug, Serialize, ToSchema)]
pub struct ActivityEntry {
    pub seq: i64,
    pub at: Timestamp,
    /// The action without the module's prefix: `issue.created`.
    pub action: String,
    pub actor: ActivityActor,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ActivityPage {
    pub items: Vec<ActivityEntry>,
    /// Continue with `before=` this for older rows; absent on the last page.
    pub next_before: Option<i64>,
}

#[utoipa::path(get, path = "/issues/{id}/activity", operation_id = "listIssueActivity",
    tag = "issues", params(("id" = i64, Path, description = "Issue id"), ActivityQuery),
    responses((status = 200, description = "What was done to the issue (the audit rows about it: \
        created, moved, estimated, labelled, edited, every state change), newest first; \
        `next_before` continues with older rows (API minor 18)", body = ActivityPage)))]
pub async fn activity(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
    Query(q): Query<ActivityQuery>,
) -> ApiResult<ActivityPage> {
    let i = issue(&app, id).await?;
    let limit = q.limit.unwrap_or(100).clamp(1, 100);
    let mut rows = ainkrad_core_server::store::audit::page(
        &app.pool,
        q.before.map(AuditSeq),
        Some("citadel.issue."),
        Some(("issue", Some(i.id.0))),
        None,
        limit + 1,
    )
    .await?;
    let more = rows.len() > limit as usize;
    rows.truncate(limit as usize);
    let next_before = more.then(|| rows.last().map(|e| e.seq.0)).flatten();
    let items = rows
        .into_iter()
        .map(|e| {
            let (kind, user_id) = match e.actor {
                AuditActor::User(u) => ("user", Some(u.0)),
                AuditActor::System => ("system", None),
            };
            ActivityEntry {
                seq: e.seq.0,
                at: ts(&e.at),
                action: e
                    .action
                    .strip_prefix("citadel.")
                    .unwrap_or(&e.action)
                    .to_owned(),
                actor: ActivityActor {
                    kind: kind.to_owned(),
                    user_id,
                },
                details: safe_details(&e.details),
            }
        })
        .collect();
    Ok(Json(ActivityPage { items, next_before }))
}

/// The keys of an audit row's details a `read` device may see (F-07): ids, counters and states.
/// Free text, URLs and error messages (a PR url, a failure reason) are dropped, the full row is
/// the admin-only audit.
const SAFE_KEYS: &[&str] = &[
    "from",
    "to",
    "state",
    "transition",
    "points",
    "priority",
    "label_id",
    "epic_id",
    "sprint_id",
    "comment_id",
    "blocker_id",
    "agent_id",
    "run_id",
    "project_id",
    "issue_id",
    "number",
];

pub(super) fn safe_details(raw: &str) -> serde_json::Value {
    use serde_json::Value;
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw) else {
        return Value::Null;
    };
    let kept = map
        .into_iter()
        .filter(|(k, v)| {
            SAFE_KEYS.contains(&k.as_str())
                && match v {
                    Value::Number(_) | Value::Bool(_) => true,
                    Value::String(s) => s.len() <= 32,
                    _ => false,
                }
        })
        .collect();
    Value::Object(kept)
}

#[cfg(test)]
mod safe_tests {
    use super::safe_details;

    #[test]
    fn free_text_and_urls_are_dropped() {
        let d = safe_details(
            r#"{"to":"done","points":2,"url":"https://x/pr/1","error":"boom","note":{"a":1}}"#,
        );
        assert_eq!(d, serde_json::json!({"to": "done", "points": 2}));
        assert_eq!(safe_details("not json"), serde_json::Value::Null);
    }
}
