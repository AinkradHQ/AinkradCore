//! A requirement's thread as the client shows it (E15.11, screen 12): one timeline of the
//! messages in it (its intake issue's comments), the agents' questions (cards; answered ones are
//! receipts), the approvals about it or its issues and the artifacts published on them (cards),
//! oldest first.

use citadel_core::gov::Approval;

use crate::store::artifacts::{Artifact, ArtifactFilter, list_artifacts};
use citadel_core::work::Comment;

use super::*;
use crate::store::gov::get_approval;

#[derive(Debug, Clone, PartialEq)]
pub enum ThreadItem {
    Message {
        comment: Comment,
        at: String,
    },
    Question {
        question: Question,
        issue_key: String,
    },
    Approval {
        approval: Approval,
        at: String,
    },
    /// An artifact published on the requirement's issues (E15.12).
    Artifact {
        artifact: Artifact,
    },
}

impl ThreadItem {
    pub fn at(&self) -> &str {
        match self {
            Self::Message { at, .. } | Self::Approval { at, .. } => at,
            Self::Question { question, .. } => &question.created_at,
            Self::Artifact { artifact } => &artifact.created_at,
        }
    }
}

/// The requirement's thread; `None` when there is no such requirement.
pub async fn requirement_thread(
    pool: &SqlitePool,
    id: RequirementId,
) -> Result<Option<Vec<ThreadItem>>, Error> {
    let Some(r) = get_requirement(pool, id).await? else {
        return Ok(None);
    };
    let mut items = vec![];
    if let Some(thread) = r.intake_issue_id {
        // A question asked from the thread's own issue shows once, as its card.
        let at: Vec<(i64, String)> = sqlx::query_as(
            "SELECT id, created_at FROM comments WHERE issue_id = ? AND id NOT IN \
             (SELECT question_comment_id FROM questions WHERE question_comment_id IS NOT NULL \
              UNION SELECT answer_comment_id FROM questions WHERE answer_comment_id IS NOT NULL)",
        )
        .bind(thread.0)
        .fetch_all(pool)
        .await?;
        for c in list_comments(pool, thread).await? {
            if let Some((_, at)) = at.iter().find(|(id, _)| *id == c.id.0) {
                items.push(ThreadItem::Message {
                    at: at.clone(),
                    comment: c,
                });
            }
        }
    }
    for q in list_questions(pool, Some(id), None, false).await? {
        let issue_key = issue_key(pool, q.issue_id).await?.unwrap_or_default();
        items.push(ThreadItem::Question {
            question: q,
            issue_key,
        });
    }
    let approvals: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, created_at FROM approvals WHERE requirement_id = ?1 \
         OR issue_id IN (SELECT id FROM issues WHERE requirement_id = ?1) ORDER BY id",
    )
    .bind(id.0)
    .fetch_all(pool)
    .await?;
    for (a, at) in approvals {
        if let Some(approval) = get_approval(pool, citadel_core::gov::ApprovalId(a)).await? {
            items.push(ThreadItem::Approval { approval, at });
        }
    }
    let published = ArtifactFilter {
        requirement: Some(id),
        ..ArtifactFilter::default()
    };
    // ponytail: the newest 200; a long-lived requirement's thread pages them later.
    for artifact in list_artifacts(pool, &published, None, 200).await? {
        items.push(ThreadItem::Artifact { artifact });
    }
    items.sort_by(|a, b| a.at().cmp(b.at()));
    Ok(Some(items))
}

/// The company's open questions across its requirements (and issues serving none), oldest
/// first (E15.11): what waits on the admin's answer.
pub async fn open_questions(pool: &SqlitePool, company: CompanyId) -> Result<Vec<Question>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        question_columns!(),
        " FROM questions WHERE state = 'open' \
         AND agent_id IN (SELECT id FROM agents WHERE company_id = ?) ORDER BY id"
    ))
    .bind(company.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(question)
    .collect()
}
