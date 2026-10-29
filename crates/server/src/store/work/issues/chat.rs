//! A person's writes on issues from the app (E10.1): a new issue or epic, audited, and a comment that
//! wakes the issue's agent — "chat with an agent" (E11.6) is an issue's comment thread, the
//! way Paperclip kept a conversation on an issue. No separate conversation table: a chat
//! about something new starts as a new issue assigned to the agent.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::exec::{NewWakeRequest, WakeSource};
use ainkrad_core::org::CompanyId;
use ainkrad_core::work::Epic;
use serde_json::json;
use sqlx::SqliteConnection;

use super::checkout::append_issue_event;
use super::*;
use crate::store::exec::enqueue_in;

/// Creates the issue as `actor` and appends `issue.created`, in one transaction, with
/// `create_issue`'s rules.
pub async fn create_issue_by(
    pool: &SqlitePool,
    i: &NewIssue,
    actor: AuditActor,
) -> Result<Issue, Error> {
    if !matches!(i.state, IssueState::Backlog | IssueState::Todo) {
        return Err(Error::InvalidArgument(format!(
            "a new issue starts in backlog or todo, not {}",
            i.state.as_str()
        )));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let created = create_issue_in(&mut tx, i).await?;
    let details = json!({"title": created.title}).to_string();
    append_issue_event(&mut tx, &created, actor, "issue.created", None, details).await?;
    tx.commit().await?;
    Ok(created)
}

/// Creates an `open` epic in the project as `actor` and appends `epic.created`, in one
/// transaction; `None` when there is no such project.
pub async fn create_epic_by(
    pool: &SqlitePool,
    project: ProjectId,
    title: &str,
    actor: AuditActor,
) -> Result<Option<Epic>, Error> {
    if title.trim().is_empty() {
        return Err(Error::InvalidArgument("an epic needs a title".to_owned()));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    let company: Option<i64> = sqlx::query_scalar("SELECT company_id FROM projects WHERE id = ?")
        .bind(project.0)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(company) = company else {
        return Ok(None);
    };
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO epics (project_id, title, requirement_id) VALUES (?1, ?2, \
         (SELECT requirement_id FROM projects WHERE id = ?1)) RETURNING id",
    )
    .bind(project.0)
    .bind(title.trim())
    .fetch_one(&mut *tx)
    .await?;
    let event = NewAuditEvent {
        actor,
        action: "epic.created".to_owned(),
        entity: Some(AuditEntity {
            kind: "epic".to_owned(),
            id,
        }),
        company_id: Some(CompanyId(company)),
        run_id: None,
        details: json!({"project": project.0, "title": title.trim()}).to_string(),
    };
    crate::store::audit::append(&mut *tx, &event).await?;
    tx.commit().await?;
    crate::store::work::get_epic(pool, EpicId(id)).await
}

/// The most of a comment its wake's reason quotes, in chars.
const QUOTE_MAX: usize = 300;

/// The agent a person's comment on `i` wakes, when nobody names one: the first agent of the
/// issue's company it mentions (`@agent:<id>`, or `@<name>`, any case), else, on a `todo` or
/// `in_progress` issue, its agent owner (who works it, not a reviewer it went past), else its
/// agent next actor, else its agent owner; none on a closed issue.
async fn chat_agent(
    conn: &mut SqliteConnection,
    i: &Issue,
    body: &str,
) -> Result<Option<AgentId>, Error> {
    if i.state.is_terminal() {
        return Ok(None);
    }
    if let Some(a) = mentioned(conn, i.project_id, body).await? {
        return Ok(Some(a));
    }
    let owner = match i.owner {
        Some(Actor::Agent(a)) => Some(a),
        _ => None,
    };
    let next = match i.next_actor {
        Some(NextActor::Agent(a)) => Some(a),
        _ => None,
    };
    Ok(match i.state {
        IssueState::Todo | IssueState::InProgress => owner.or(next),
        _ => next.or(owner),
    })
}

/// The agent of the project's company that `body` mentions first: `@agent:<id>` or
/// `@<name>` (case-insensitive, not followed by a letter, digit, `_` or `-`).
async fn mentioned(
    conn: &mut SqliteConnection,
    project: ProjectId,
    body: &str,
) -> Result<Option<AgentId>, Error> {
    if !body.contains('@') {
        return Ok(None);
    }
    let agents: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, name FROM agents WHERE company_id = \
         (SELECT company_id FROM projects WHERE id = ?) ORDER BY id",
    )
    .bind(project.0)
    .fetch_all(&mut *conn)
    .await?;
    let text = body.to_lowercase();
    let at = |handle: &str| {
        text.match_indices(handle).map(|(at, _)| at).find(|&at| {
            let after = text[at + handle.len()..].chars().next();
            !after.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-')
        })
    };
    Ok(agents
        .iter()
        .flat_map(|(id, name)| {
            let named = format!("@{}", name.trim().to_lowercase());
            let by_id = at(&format!("@agent:{id}"));
            let by_name = (named.len() > 1).then(|| at(&named)).flatten();
            [by_id, by_name].into_iter().flatten().map(|pos| (pos, *id))
        })
        .min()
        .map(|(_, id)| AgentId(id)))
}

/// `body` on one line, cut to `QUOTE_MAX` chars with an ellipsis.
fn quote(body: &str) -> String {
    let line = body.split_whitespace().collect::<Vec<_>>().join(" ");
    match line.char_indices().nth(QUOTE_MAX) {
        Some((at, _)) => format!("{}…", &line[..at]),
        None => line,
    }
}

/// `by`'s comment on the issue, once per `key` (a repeat returns the first, and wakes no
/// one again), with `issue.commented`, and a `comment` wake whose reason quotes it, in one
/// transaction. It wakes `wake` when given (an agent of the issue's company), else the agent
/// `chat_agent` picks: one it mentions, else the issue's working agent. With a question open on
/// the issue, the comment answers it instead, and wakes the agent that asked (E15.11). The
/// comment and the agent woken; `None` when there is no such issue.
pub async fn post_comment(
    pool: &SqlitePool,
    issue: IssueId,
    by: UserId,
    body: &str,
    key: Option<&str>,
    wake: Option<AgentId>,
) -> Result<Option<(Comment, Option<AgentId>)>, Error> {
    if body.trim().is_empty() {
        return Err(Error::InvalidArgument("a comment needs a body".to_owned()));
    }
    let mut tx = crate::store::begin_write(pool).await?;
    if let Some(agent) = wake {
        let same: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM agents a JOIN projects p ON p.company_id = a.company_id \
             JOIN issues i ON i.project_id = p.id WHERE a.id = ? AND i.id = ?)",
        )
        .bind(agent.0)
        .bind(issue.0)
        .fetch_one(&mut *tx)
        .await?;
        if !same && issue_in(&mut tx, issue).await?.is_some() {
            let why = format!("no agent {} in the issue's company", agent.0);
            return Err(Error::InvalidArgument(why));
        }
    }
    let Some((id, woke)) = post_comment_in(&mut tx, issue, by, body, key, wake).await? else {
        return Ok(None);
    };
    tx.commit().await?;
    let c = get_comment(pool, CommentId(id))
        .await?
        .ok_or(Error::RowNotFound)?;
    Ok(Some((c, woke)))
}

/// `post_comment` inside the caller's transaction: the comment's id and the agent woken. `to`
/// wakes that agent rather than the issue's (a message to a run that ended goes to the run's
/// agent); an open question is still answered by it.
pub(crate) async fn post_comment_in(
    conn: &mut SqliteConnection,
    issue: IssueId,
    by: UserId,
    body: &str,
    key: Option<&str>,
    to: Option<AgentId>,
) -> Result<Option<(i64, Option<AgentId>)>, Error> {
    let Some(i) = issue_in(conn, issue).await? else {
        return Ok(None);
    };
    let inserted: Option<i64> = sqlx::query_scalar(
        "INSERT INTO comments (issue_id, author_user_id, body, idempotency_key) \
         VALUES (?, ?, ?, ?) ON CONFLICT (issue_id, idempotency_key) DO NOTHING RETURNING id",
    )
    .bind(issue.0)
    .bind(by.0)
    .bind(body)
    .bind(key)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(id) = inserted else {
        let id = sqlx::query_scalar(
            "SELECT id FROM comments WHERE issue_id = ? AND idempotency_key = ?",
        )
        .bind(issue.0)
        .bind(key)
        .fetch_one(&mut *conn)
        .await?;
        return Ok(Some((id, None)));
    };
    let details = json!({"comment": id}).to_string();
    let actor = AuditActor::User(by);
    append_issue_event(conn, &i, actor, "issue.commented", None, details).await?;
    // An open question on the issue is answered by it, and its asker woken (E15.11).
    let asker = crate::store::work::answer_from_issue_in(conn, issue, by, body, id).await?;
    let woke = match (asker, to) {
        (Some(a), _) | (None, Some(a)) => Some(a),
        (None, None) => chat_agent(conn, &i, body).await?,
    };
    if let (None, Some(agent_id)) = (asker, woke) {
        let wake = NewWakeRequest {
            agent_id,
            issue_id: Some(issue),
            source: WakeSource::Comment,
            reason: format!("comment: \"{}\"", quote(body)),
            idempotency_key: format!("comment:{id}"),
            not_before: None,
        };
        enqueue_in(conn, &wake, 1).await?;
    }
    Ok(Some((id, woke)))
}
