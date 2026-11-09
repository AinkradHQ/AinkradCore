//! A requirement's thread (E15.11, pain #9, screen 12): read it as one timeline of messages,
//! agent question cards (answered ones as receipts), approval and artifact cards, and post in it. A post
//! answers the newest open question unless it names another or clears the target (#44), and the
//! answer goes to the agent that asked, not the CEO; a post to the owner wakes the owner.

use citadel_core::gov::ArtifactKind;
use citadel_core::work::{QuestionId, RequirementId};
use ainkrad_proto::redact::Redactor;
use axum::Json;
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::artifacts::Artifact;
use super::model::{Approval, Comment};
use super::types::{QuestionState, Timestamp, opt_ts, ts};
use super::{ADMIN, ApiError, ApiResult};
use crate::api::App;
use crate::store::artifacts::{self, ArtifactError, NewArtifact};
use crate::store::work::{self, HubError, Posted, To};

/// An agent's question for the admin: a card while open, a receipt once answered.
#[derive(Debug, Serialize, ToSchema)]
pub struct Question {
    pub id: i64,
    pub requirement_id: Option<i64>,
    /// The asker's issue, where the answer goes.
    pub issue_id: i64,
    pub issue_key: String,
    pub asked_by_agent_id: i64,
    pub run_id: Option<i64>,
    pub question: String,
    pub options: Vec<String>,
    pub state: QuestionState,
    pub answer: Option<String>,
    /// `requirement` or `issue`: where it was answered.
    pub answered_in: Option<String>,
    pub created_at: Timestamp,
    pub answered_at: Option<Timestamp>,
}

pub(super) fn question(q: work::Question, issue_key: String) -> Question {
    Question {
        id: q.id.0,
        requirement_id: q.requirement_id.map(|r| r.0),
        issue_id: q.issue_id.0,
        issue_key,
        asked_by_agent_id: q.agent_id.0,
        run_id: q.run_id.map(|r| r.0),
        question: q.question,
        options: q.options,
        state: q.state.into(),
        answer: q.answer,
        answered_in: q.answered_in,
        created_at: ts(&q.created_at),
        answered_at: opt_ts(q.answered_at.as_deref()),
    }
}

/// One item of a requirement's thread.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ThreadItem {
    Message {
        comment: Comment,
        at: Timestamp,
    },
    Question {
        question: Question,
    },
    Approval {
        approval: Approval,
        at: Timestamp,
    },
    /// Published on the requirement's issues (E15.12); opens on the artifacts screen.
    Artifact {
        artifact: super::artifacts::Artifact,
    },
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Thread {
    pub requirement_id: i64,
    /// Who a message to the owner wakes: the CEO, then the product owner (#45).
    pub owner_agent_id: Option<i64>,
    /// What a post answers unless it says otherwise: the newest open question (#44).
    pub to_question_id: Option<i64>,
    pub items: Vec<ThreadItem>,
}

#[utoipa::path(get, path = "/api/v1/requirements/{id}/thread", operation_id = "getRequirementThread",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "The thread, oldest first, and what a post answers",
        body = Thread)))]
pub async fn get(State(app): State<App>, Path(id): Path<i64>) -> ApiResult<Thread> {
    let r = work::get_requirement(&app.pool, RequirementId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no requirement {id}")))?;
    let all = work::requirement_thread(&app.pool, r.id)
        .await?
        .unwrap_or_default();
    let mut to = None;
    let items = all
        .into_iter()
        .map(|item| match item {
            work::ThreadItem::Message { comment, at } => ThreadItem::Message {
                comment: comment.into(),
                at: ts(&at),
            },
            work::ThreadItem::Question {
                question: q,
                issue_key,
            } => {
                if q.state == citadel_core::work::QuestionState::Open {
                    to = Some(q.id.0);
                }
                ThreadItem::Question {
                    question: question(q, issue_key),
                }
            }
            work::ThreadItem::Approval { approval, at } => ThreadItem::Approval {
                approval: approval.into(),
                at: ts(&at),
            },
            work::ThreadItem::Artifact { artifact } => ThreadItem::Artifact {
                artifact: artifact.into(),
            },
        })
        .collect();
    Ok(Json(Thread {
        requirement_id: id,
        owner_agent_id: r.owner_agent_id.map(|a| a.0),
        to_question_id: to,
        items,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ThreadPost {
    pub body: String,
    /// The question it answers; absent: the newest open one, unless `to_owner`.
    pub question_id: Option<i64>,
    /// The target cleared: a message to the owner even with questions open.
    #[serde(default)]
    pub to_owner: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ThreadPosted {
    /// The question it answered, now a receipt; its asker was woken on its issue.
    pub answered: Option<Question>,
    /// The thread comment, when it went to the owner.
    pub comment_id: Option<i64>,
    pub woke_agent_id: Option<i64>,
    pub woke_issue_id: Option<i64>,
}

#[utoipa::path(post, path = "/api/v1/requirements/{id}/thread", operation_id = "postToRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    request_body = ThreadPost,
    responses((status = 200, description = "What the post did: the question it answered and the \
        agent woken with the answer, or the message to the owner", body = ThreadPosted)))]
pub async fn post(
    State(app): State<App>,
    Path(id): Path<i64>,
    Json(p): Json<ThreadPost>,
) -> ApiResult<ThreadPosted> {
    let to = match (p.question_id, p.to_owner) {
        (Some(_), true) => {
            return Err(ApiError::bad_request(
                "give question_id or to_owner, not both",
            ));
        }
        (Some(q), false) => To::Question(QuestionId(q)),
        (None, true) => To::Owner,
        (None, false) => To::Auto,
    };
    let posted = work::post_to_requirement(&app.pool, RequirementId(id), ADMIN, &p.body, to)
        .await
        .map_err(|e| match e {
            HubError::NotFound => ApiError::not_found(e.to_string()),
            HubError::Db(sqlx::Error::InvalidArgument(why)) => ApiError::bad_request(why),
            HubError::Db(e) => e.into(),
            e => ApiError::conflict(e.to_string()),
        })?;
    Ok(Json(match posted {
        Posted::Answered(q) => {
            let key = work::issue_key(&app.pool, q.issue_id)
                .await?
                .unwrap_or_default();
            ThreadPosted {
                woke_agent_id: Some(q.agent_id.0),
                woke_issue_id: Some(q.issue_id.0),
                answered: Some(question(*q, key)),
                comment_id: None,
            }
        }
        Posted::ToOwner(c, woke) => ThreadPosted {
            answered: None,
            comment_id: Some(c.0),
            woke_agent_id: woke.map(|(a, _)| a.0),
            woke_issue_id: woke.map(|(_, i)| i.0),
        },
    }))
}

#[utoipa::path(post, path = "/api/v1/requirements/{id}/attachments/{name}",
    operation_id = "attachToRequirement", tag = "requirements",
    params(("id" = i64, Path, description = "Requirement id"),
        ("name" = String, Path, description = "The file's name, its type by its extension (the \
            artifact allowlist)")),
    request_body(description = "The file itself, at most artifact.max_file_bytes",
        content(("application/octet-stream"))),
    responses(
        (status = 200, description = "The attachment: an artifact of the requirement's thread \
            (shown in it as a card), a text file redacted of every key shape first; audited as \
            `artifact.published` by the admin", body = Artifact),
        (status = 409, description = "The company's artifact storage is full \
            (artifact.company_quota_bytes)", body = super::types::ErrorBody),
        (status = 413, description = "Over artifact.max_file_bytes", body = super::types::ErrorBody),
        (status = 415, description = "A type outside the allowlist", body = super::types::ErrorBody)))]
pub async fn attach(
    State(app): State<App>,
    Path((id, name)): Path<(i64, String)>,
    body: Body,
) -> ApiResult<Artifact> {
    let r = work::get_requirement(&app.pool, RequirementId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no requirement {id}")))?;
    let new = NewArtifact {
        company: r.company_id,
        issue: r.intake_issue_id,
        requirement: Some(r.id),
        run: None,
        agent: None,
        name,
        kind: ArtifactKind::File,
        user: Some(ADMIN),
    };
    let (_, _, max) = artifacts::artifact_usage(&app.pool, r.company_id).await?;
    let too_large = |size: String| {
        let why = format!(
            "rejected: {size} is over the {max}-byte limit per file \
                           (artifact.max_file_bytes)"
        );
        ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large", why)
    };
    // Read no more than the limit (and one byte past it, so the store refuses it as over).
    let Ok(bytes) = axum::body::to_bytes(body, max as usize + 1).await else {
        let why = format!("rejected: over the {max}-byte limit per file (artifact.max_file_bytes)");
        artifacts::record_refusal(&app.pool, &new, &why).await?;
        return Err(too_large("the file".to_owned()));
    };
    let published =
        artifacts::publish_artifact(&app.pool, &app.artifacts, &new, &bytes, &Redactor::new())
            .await;
    match published {
        Ok(a) => Ok(Json(a.into())),
        Err(ArtifactError::Db(e)) => Err(e.into()),
        Err(e) => {
            let why = e.to_string();
            artifacts::record_refusal(&app.pool, &new, &why).await?;
            Err(match e {
                ArtifactError::TooLarge { size, .. } => too_large(format!("{size} bytes")),
                ArtifactError::TypeNotAllowed(_) => ApiError::new(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "unsupported_media_type",
                    why,
                ),
                ArtifactError::OverQuota { .. } => ApiError::conflict(why),
                ArtifactError::Io(_) => {
                    ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", why)
                }
                _ => ApiError::bad_request(why),
            })
        }
    }
}
