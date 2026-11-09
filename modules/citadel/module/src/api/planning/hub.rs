//! A requirement's thread (E15.11, pain #9, screen 12): read it as one timeline of messages,
//! agent question cards (answered ones as receipts), approval and artifact cards, and post in it.
//! A post answers the newest open question unless it names another or clears the target (#44),
//! and the answer goes to the agent that asked, not the CEO; a post to the owner reaches the
//! owner.
//!
//! Not here: attaching a file to the requirement (`attachToRequirement`) needs the artifact
//! store's publish path (S5).

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::api::model::planning::{Question, Thread, ThreadItem, question};
use crate::api::scope::Acting;
use crate::domain::org::CompanyId;
use crate::domain::work::{QuestionId, QuestionState, RequirementId};
use crate::store::org;
use crate::store::work::{self, HubError, Posted, To};

#[utoipa::path(get, path = "/requirements/{id}/thread", operation_id = "getRequirementThread",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    responses((status = 200, description = "The thread, oldest first, and what a post answers",
        body = Thread)))]
pub async fn get(State(app): State<App>, _: Acting, Path(id): Path<i64>) -> ApiResult<Thread> {
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
                at: crate::api::types::ts(&at),
            },
            work::ThreadItem::Question {
                question: q,
                issue_key,
            } => {
                if q.state == QuestionState::Open {
                    to = Some(q.id.0);
                }
                ThreadItem::Question {
                    question: question(q, issue_key),
                }
            }
            work::ThreadItem::Approval { approval, at } => ThreadItem::Approval {
                approval: approval.into(),
                at: crate::api::types::ts(&at),
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
    /// The question it answered, now a receipt; its asker is the one to hear it.
    pub answered: Option<Question>,
    /// The thread comment, when it went to the owner.
    pub comment_id: Option<i64>,
    pub woke_agent_id: Option<i64>,
    pub woke_issue_id: Option<i64>,
}

#[utoipa::path(post, path = "/requirements/{id}/thread", operation_id = "postToRequirement",
    tag = "requirements", params(("id" = i64, Path, description = "Requirement id")),
    request_body = ThreadPost,
    responses((status = 200, description = "What the post did: the question it answered and the \
        agent it reaches with the answer, or the message to the owner", body = ThreadPosted)))]
pub async fn post(
    State(app): State<App>,
    _: Acting,
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
    let admin = crate::domain::work::UserId(ainkrad_core_server::api::v1::ADMIN.0);
    let posted = work::post_to_requirement(&app.pool, RequirementId(id), admin, &p.body, to)
        .await
        .map_err(|e| match e {
            HubError::NotFound => ApiError::not_found(e.to_string()),
            HubError::Db(sqlx::Error::Protocol(why)) => ApiError::bad_request(why),
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

#[utoipa::path(get, path = "/companies/{id}/questions", operation_id = "listOpenQuestions",
    tag = "reads", params(("id" = i64, Path, description = "Company id")),
    responses((status = 200, description = "Its agents' open questions for the admin, across \
        requirements, oldest first (E15.11)", body = Vec<Question>)))]
pub async fn open_questions(
    State(app): State<App>,
    _: Acting,
    Path(id): Path<i64>,
) -> ApiResult<Vec<Question>> {
    let c = org::get_company(&app.pool, CompanyId(id))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no company {id}")))?;
    let mut out = vec![];
    for q in work::open_questions(&app.pool, c.id).await? {
        let key = work::issue_key(&app.pool, q.issue_id)
            .await?
            .unwrap_or_default();
        out.push(question(q, key));
    }
    Ok(Json(out))
}
