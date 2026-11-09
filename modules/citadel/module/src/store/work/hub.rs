//! The requirement conversation hub (E15.11, pain #9, decisions #39, #44, #45): one thread per
//! requirement, its intake issue's comments, between the admin and its owner (the CEO, then the
//! product owner it was handed to; the CEO can still post).
//!
//! - Any agent working on one of the requirement's issues asks the admin with `ask_human`: a
//!   question card in the requirement's thread, and the agent's comment on its own issue, which
//!   now waits on the admin (next actor user 1). Its run should end there.
//! - The admin's answer goes to the agent that asked, never through the CEO: posted in the
//!   requirement's thread (to the newest open question unless another is named, or the owner when
//!   the target is cleared, #44) or on the asker's issue, it becomes the admin's comment there,
//!   the issue waits on the asker again, and the asker is woken with it. The card collapses to a
//!   receipt; answered in either place, it is answered in both.
//! - A message to the owner is a comment in the thread that wakes the owner on its issue.
//!
//! Every step is audited (`question.asked`, `question.answered`, `requirement.message`), so the
//! client's event stream carries it and a new question is pushed.

use crate::domain::work::WakeSource;
use crate::store::exec::{NewWakeRequest, enqueue_in};
use std::fmt;

use ainkrad_core::audit::AuditActor;
use serde_json::json;
use sqlx::sqlite::SqliteRow;
use sqlx::{Error, Row, SqliteConnection, SqlitePool};

use super::intake::INTAKE_FALLBACK_USER;
use super::requirements::{by_agent, event_in, plans_in, requirement_in, user_audit};
use crate::domain::org::{AgentId, CompanyId};
use crate::domain::work::{
    CommentId, IssueId, IssueTransition, NextActor, QuestionId, QuestionState, RequirementId,
    RunId, UserId,
};
use crate::store::org::text;
use crate::store::work::{issue_in, transition_issue_in};

/// Who a question leaves its issue waiting on.
pub const ANSWERER: UserId = INTAKE_FALLBACK_USER;
/// The most options a question offers.
pub const MAX_OPTIONS: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: QuestionId,
    pub requirement_id: Option<RequirementId>,
    pub issue_id: IssueId,
    pub agent_id: AgentId,
    pub run_id: Option<RunId>,
    pub question: String,
    pub options: Vec<String>,
    pub state: QuestionState,
    pub answer: Option<String>,
    pub answered_by: Option<UserId>,
    /// `requirement` or `issue`.
    pub answered_in: Option<String>,
    pub question_comment_id: Option<CommentId>,
    pub answer_comment_id: Option<CommentId>,
    pub created_at: String,
    pub answered_at: Option<String>,
}

macro_rules! question_columns {
    () => {
        "id, requirement_id, issue_id, agent_id, run_id, question, options, state, answer, \
         answered_by_user_id, answered_in, question_comment_id, answer_comment_id, created_at, \
         answered_at"
    };
}

fn question(row: SqliteRow) -> Result<Question, Error> {
    let id = |c: &str| -> Result<Option<i64>, Error> { row.try_get(c) };
    let options: String = row.try_get("options")?;
    Ok(Question {
        id: QuestionId(row.try_get("id")?),
        requirement_id: id("requirement_id")?.map(RequirementId),
        issue_id: IssueId(row.try_get("issue_id")?),
        agent_id: AgentId(row.try_get("agent_id")?),
        run_id: id("run_id")?.map(RunId),
        question: row.try_get("question")?,
        options: serde_json::from_str(&options).unwrap_or_default(),
        state: text(&row, "state")?,
        answer: row.try_get("answer")?,
        answered_by: id("answered_by_user_id")?.map(UserId),
        answered_in: row.try_get("answered_in")?,
        question_comment_id: id("question_comment_id")?.map(CommentId),
        answer_comment_id: id("answer_comment_id")?.map(CommentId),
        created_at: row.try_get("created_at")?,
        answered_at: row.try_get("answered_at")?,
    })
}

async fn question_in(
    conn: &mut SqliteConnection,
    id: QuestionId,
) -> Result<Option<Question>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        question_columns!(),
        " FROM citadel_questions WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(question)
    .transpose()
}

pub async fn get_question(pool: &SqlitePool, id: QuestionId) -> Result<Option<Question>, Error> {
    let mut conn = pool.acquire().await?;
    question_in(&mut conn, id).await
}

/// Questions about the requirement (or the issue), oldest first; `open` only, or all.
pub async fn list_questions(
    pool: &SqlitePool,
    requirement: Option<RequirementId>,
    issue: Option<IssueId>,
    open: bool,
) -> Result<Vec<Question>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        question_columns!(),
        " FROM citadel_questions WHERE (?1 IS NULL OR requirement_id = ?1) \
         AND (?2 IS NULL OR issue_id = ?2) AND (NOT ?3 OR state = 'open') ORDER BY id"
    ))
    .bind(requirement.map(|r| r.0))
    .bind(issue.map(|i| i.0))
    .bind(open)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(question)
    .collect()
}

/// Why a hub write was refused.
#[derive(Debug)]
pub enum HubError {
    NotFound,
    /// The question was answered or cancelled already.
    Closed(QuestionState),
    /// The question is another requirement's.
    Elsewhere,
    /// The issue is closed: nobody would be woken with the answer.
    IssueClosed,
    /// Only the requirement's owner, its planners, or the CEO post in its thread.
    NotAllowed,
    Db(Error),
}

impl From<Error> for HubError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for HubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no such requirement, issue or question"),
            Self::Closed(s) => write!(f, "the question is {} already", s.as_str()),
            Self::Elsewhere => f.write_str("the question is not this requirement's"),
            Self::IssueClosed => f.write_str("the issue is closed"),
            Self::NotAllowed => f.write_str(
                "only the requirement's owner, its planners or the CEO post in its thread",
            ),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for HubError {}

/// Appends `action` about the question, in its issue's company.
async fn question_event_in(
    conn: &mut SqliteConnection,
    q: &Question,
    actor: AuditActor,
    action: &str,
    details: serde_json::Value,
) -> Result<(), Error> {
    let company: i64 = sqlx::query_scalar(
        "SELECT p.company_id FROM citadel_issues i JOIN citadel_projects p ON p.id = i.project_id WHERE i.id = ?",
    )
    .bind(q.issue_id.0)
    .fetch_one(&mut *conn)
    .await?;
    let entity = ("question", q.id.0);
    let company = CompanyId(company);
    super::requirements::append_org_event(conn, company, actor, action, entity, details).await
}

/// `agent` (in `run`) asks the admin `text`, with `options`, from `issue`; see the module docs.
pub async fn ask_human(
    pool: &SqlitePool,
    agent: AgentId,
    run: Option<RunId>,
    issue: IssueId,
    text: &str,
    options: &[String],
) -> Result<Question, HubError> {
    if text.trim().is_empty() {
        return Err(Error::Protocol("a question needs a text".to_owned()).into());
    }
    if options.len() > MAX_OPTIONS || options.iter().any(|o| o.trim().is_empty()) {
        let why = format!("1 to {MAX_OPTIONS} options, none blank");
        return Err(Error::Protocol(why).into());
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let i = issue_in(&mut tx, issue).await?.ok_or(HubError::NotFound)?;
    if i.state.is_terminal() {
        return Err(HubError::IssueClosed);
    }
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO citadel_questions (requirement_id, issue_id, agent_id, run_id, question, options) \
         VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(i.requirement_id.map(|r| r.0))
    .bind(issue.0)
    .bind(agent.0)
    .bind(run.map(|r| r.0))
    .bind(text.trim())
    .bind(serde_json::to_string(options).expect("strings"))
    .fetch_one(&mut *tx)
    .await?;
    let mut body = format!("Question for you: {}", text.trim());
    if !options.is_empty() {
        body.push_str(&format!("\nOptions: {}", options.join(" / ")));
    }
    let comment: i64 = sqlx::query_scalar(
        "INSERT INTO citadel_comments (issue_id, author_agent_id, body, run_id, idempotency_key) \
         VALUES (?, ?, ?, ?, ?) RETURNING id",
    )
    .bind(issue.0)
    .bind(agent.0)
    .bind(&body)
    .bind(run.map(|r| r.0))
    .bind(format!("question:{id}"))
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE citadel_questions SET question_comment_id = ? WHERE id = ?")
        .bind(comment)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    // An agent acts as `system` in the Core's audit; its id rides in the details.
    let by = AuditActor::System;
    if i.next_actor == Some(NextActor::Agent(agent)) {
        let wait = IssueTransition::Reassign {
            next: NextActor::Human(ANSWERER),
        };
        // ponytail: a state the machine will not reassign in leaves the issue as it is; the
        // question still stands and is answered the same way.
        let _ = transition_issue_in(&mut tx, issue, &wait, by).await;
    }
    let q = question_in(&mut tx, QuestionId(id))
        .await?
        .ok_or(Error::RowNotFound)?;
    let details = json!({"requirement": q.requirement_id.map(|r| r.0), "issue": issue.0,
                         "agent": agent.0, "run": run.map(|r| r.0), "question": q.question,
                         "options": q.options});
    let details = by_agent(details, agent);
    question_event_in(&mut tx, &q, by, "question.asked", details).await?;
    tx.commit().await?;
    Ok(q)
}

/// Answers the open question `q` as `by` with `answer`, given in `place` (`requirement` or
/// `issue`; for `issue`, `comment` is the admin's comment that answered it, else one is posted on
/// the asker's issue): the issue waits on the asker again, the asker is woken with the answer.
pub(crate) async fn answer_in(
    conn: &mut SqliteConnection,
    q: &Question,
    by: UserId,
    answer: &str,
    place: &str,
    comment: Option<i64>,
) -> Result<(), Error> {
    let comment =
        match comment {
            Some(c) => c,
            None => sqlx::query_scalar(
                "INSERT INTO citadel_comments (issue_id, author_user_id, body, idempotency_key) \
                 VALUES (?, ?, ?, ?) RETURNING id",
            )
            .bind(q.issue_id.0)
            .bind(by.0)
            .bind(answer)
            .bind(format!("answer:{}", q.id.0))
            .fetch_one(&mut *conn)
            .await?,
        };
    sqlx::query(
        "UPDATE citadel_questions SET state = 'answered', answer = ?, answered_by_user_id = ?, \
         answered_in = ?, answer_comment_id = ?, \
         answered_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
    )
    .bind(answer)
    .bind(by.0)
    .bind(place)
    .bind(comment)
    .bind(q.id.0)
    .execute(&mut *conn)
    .await?;
    // The answer's wake first: the reassignment's own folds into it, so the run is told the
    // answer.
    let wake = NewWakeRequest {
        agent_id: q.agent_id,
        issue_id: Some(q.issue_id),
        source: WakeSource::Comment,
        reason: format!("your question was answered: {answer}"),
        idempotency_key: format!("answer:{}", q.id.0),
        not_before: None,
    };
    enqueue_in(conn, &wake, 1).await?;
    let actor = user_audit(by);
    if let Some(i) = issue_in(conn, q.issue_id).await?
        && !i.state.is_terminal()
        && i.next_actor == Some(NextActor::Human(ANSWERER))
    {
        let back = IssueTransition::Reassign {
            next: NextActor::Agent(q.agent_id),
        };
        let _ = transition_issue_in(conn, q.issue_id, &back, actor).await;
    }
    let details = json!({"requirement": q.requirement_id.map(|r| r.0), "issue": q.issue_id.0,
                         "agent": q.agent_id.0, "in": place, "comment": comment});
    question_event_in(conn, q, actor, "question.answered", details).await
}

/// Where a post in a requirement's thread goes (#44).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum To {
    /// The newest open question, else the owner.
    Auto,
    Question(QuestionId),
    /// The owner, even with questions open (the target cleared).
    Owner,
}

/// What a post did: the question it answered, or the owner's comment and wake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Posted {
    Answered(Box<Question>),
    /// The thread comment, and who it woke on which issue (none without an owner).
    ToOwner(CommentId, Option<(AgentId, IssueId)>),
}

/// The admin `by` posts `body` in the requirement's thread, to `to`; see the module docs.
pub async fn post_to_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    by: UserId,
    body: &str,
    to: To,
) -> Result<Posted, HubError> {
    if body.trim().is_empty() {
        return Err(Error::Protocol("a message needs a body".to_owned()).into());
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(HubError::NotFound)?;
    let target = match to {
        To::Owner => None,
        To::Question(q) => Some(q),
        To::Auto => sqlx::query_scalar::<_, Option<i64>>(
            "SELECT max(id) FROM citadel_questions WHERE requirement_id = ? AND state = 'open'",
        )
        .bind(id.0)
        .fetch_one(&mut *tx)
        .await?
        .map(QuestionId),
    };
    let posted = match target {
        Some(qid) => {
            let q = question_in(&mut tx, qid).await?.ok_or(HubError::NotFound)?;
            if q.requirement_id != Some(id) {
                return Err(HubError::Elsewhere);
            }
            if q.state != QuestionState::Open {
                return Err(HubError::Closed(q.state));
            }
            answer_in(&mut tx, &q, by, body.trim(), "requirement", None).await?;
            let q = question_in(&mut tx, qid).await?.ok_or(Error::RowNotFound)?;
            Posted::Answered(Box::new(q))
        }
        None => {
            let thread = r.intake_issue_id.ok_or(HubError::NotFound)?;
            let comment: i64 = sqlx::query_scalar(
                "INSERT INTO citadel_comments (issue_id, author_user_id, body) VALUES (?, ?, ?) \
                 RETURNING id",
            )
            .bind(thread.0)
            .bind(by.0)
            .bind(body.trim())
            .fetch_one(&mut *tx)
            .await?;
            let woke = match (r.owner_agent_id, r.owner_issue_id) {
                (Some(agent), Some(issue)) => {
                    let wake = NewWakeRequest {
                        agent_id: agent,
                        issue_id: Some(issue),
                        source: WakeSource::Comment,
                        reason: format!("{} thread: {}", r.key(), body.trim()),
                        idempotency_key: format!("thread:{comment}"),
                        not_before: None,
                    };
                    enqueue_in(&mut tx, &wake, 1).await?;
                    Some((agent, issue))
                }
                _ => None,
            };
            let details = json!({"comment": comment, "to": woke.map(|(a, _)| a.0)});
            let actor = user_audit(by);
            event_in(&mut tx, &r, actor, "requirement.message", details).await?;
            Posted::ToOwner(CommentId(comment), woke)
        }
    };
    tx.commit().await?;
    Ok(posted)
}

/// `agent` posts `body` in the requirement's thread, from `run`: its owner, a planner of it, or
/// the company's CEO (#45: the CEO can still post after the hand-off).
pub async fn agent_post_to_requirement(
    pool: &SqlitePool,
    id: RequirementId,
    agent: AgentId,
    run: Option<RunId>,
    body: &str,
) -> Result<CommentId, HubError> {
    if body.trim().is_empty() {
        return Err(Error::Protocol("a message needs a body".to_owned()).into());
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let r = requirement_in(&mut tx, id)
        .await?
        .ok_or(HubError::NotFound)?;
    let allowed = r.owner_agent_id == Some(agent) || plans_in(&mut tx, &r, agent).await?;
    if !allowed {
        return Err(HubError::NotAllowed);
    }
    let thread = r.intake_issue_id.ok_or(HubError::NotFound)?;
    let comment: i64 = sqlx::query_scalar(
        "INSERT INTO citadel_comments (issue_id, author_agent_id, body, run_id) VALUES (?, ?, ?, ?) \
         RETURNING id",
    )
    .bind(thread.0)
    .bind(agent.0)
    .bind(body.trim())
    .bind(run.map(|r| r.0))
    .fetch_one(&mut *tx)
    .await?;
    let details = json!({"comment": comment, "agent": agent.0});
    let details = by_agent(details, agent);
    event_in(
        &mut tx,
        &r,
        AuditActor::System,
        "requirement.message",
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(CommentId(comment))
}

/// The admin's comment `comment` on `issue` answers the issue's newest open question, if any
/// (answering in the issue thread clears the requirement's card too); the asker, or `None`.
pub(crate) async fn answer_from_issue_in(
    conn: &mut SqliteConnection,
    issue: IssueId,
    by: UserId,
    body: &str,
    comment: i64,
) -> Result<Option<AgentId>, Error> {
    let open = sqlx::query(concat!(
        "SELECT ",
        question_columns!(),
        " FROM citadel_questions WHERE issue_id = ? AND state = 'open' ORDER BY id DESC LIMIT 1"
    ))
    .bind(issue.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(question)
    .transpose()?;
    let Some(q) = open else {
        return Ok(None);
    };
    answer_in(conn, &q, by, body, "issue", Some(comment)).await?;
    Ok(Some(q.agent_id))
}

mod thread;
pub use thread::*;
