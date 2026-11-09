//! The admin's messages to a run (1.19): to the live run, given to its harness as its next turn
//! and marked delivered by the runner's `user_message` chunk; or, the run not live (or ended
//! before taking it), a comment on its issue that wakes the run's agent.

use citadel_core::audit::AuditActor;
use citadel_core::work::UserId;
use serde_json::json;
use sqlx::SqliteConnection;

use super::controls::{control_in, record};
use super::*;
use crate::store::work::post_comment_in;

/// Where a message to a run went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Delivery {
    /// To the live run, as its harness's next turn: the message's id.
    Run(i64),
    /// A comment on the run's issue (the run is not live), waking the run's agent.
    Comment(i64),
}

/// Why a message was not taken.
#[derive(Debug)]
pub enum MessageError {
    NotFound,
    /// The run is not live and has no issue to comment on.
    NoIssue,
    Db(Error),
}

impl From<Error> for MessageError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("run not found"),
            Self::NoIssue => f.write_str("the run has ended and has no issue to comment on"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

/// `by`'s message to the run, once per `key`: to the live run, else a comment on its issue.
pub async fn message_run(
    pool: &SqlitePool,
    run: RunId,
    by: UserId,
    body: &str,
    key: Option<&str>,
    now: &str,
) -> Result<Delivery, MessageError> {
    if body.trim().is_empty() {
        return Err(Error::InvalidArgument("a message needs a body".to_owned()).into());
    }
    let mut tx = crate::store::begin_write(pool).await?;
    check_time(&mut tx, now).await?;
    let current = run_in(&mut tx, run).await?.ok_or(MessageError::NotFound)?;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(current.agent_id.0)
        .fetch_one(&mut *tx)
        .await?;
    let (delivery, fresh) = match (current.state.is_terminal(), current.issue_id) {
        (false, _) => {
            let (id, fresh) = control_in(&mut tx, run, "message", body, key, now).await?;
            (Delivery::Run(id), fresh)
        }
        (true, Some(issue)) => {
            let key = key.map(|k| format!("run-message:{}:{k}", run.0));
            let seen: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM comments WHERE issue_id = ? AND idempotency_key = ?)",
            )
            .bind(issue.0)
            .bind(&key)
            .fetch_one(&mut *tx)
            .await?;
            let to = Some(current.agent_id);
            let posted = post_comment_in(&mut tx, issue, by, body, key.as_deref(), to).await?;
            (
                Delivery::Comment(posted.ok_or(MessageError::NotFound)?.0),
                !seen,
            )
        }
        (true, None) => return Err(MessageError::NoIssue),
    };
    if !fresh {
        return Ok(delivery);
    }
    let details = match delivery {
        Delivery::Run(id) => json!({"message": id}),
        Delivery::Comment(id) => json!({"comment": id}),
    };
    let actor = AuditActor::User(by);
    record(
        &mut tx,
        actor,
        "run.messaged",
        ("run", run.0),
        company,
        Some(run),
        details,
    )
    .await?;
    tx.commit().await?;
    signal_wakes();
    Ok(delivery)
}

/// The messages the run ended before taking, as comments on its issue by their author (the
/// admin) waking its agent; inside the run's terminal transition.
pub(super) async fn undelivered_in(conn: &mut SqliteConnection, r: &Run) -> Result<(), Error> {
    let Some(issue) = r.issue_id else {
        return Ok(());
    };
    let pending: Vec<(i64, String)> = sqlx::query_as(
        "SELECT id, body FROM run_controls WHERE run_id = ? AND kind = 'message' \
         AND delivered_at IS NULL AND comment_id IS NULL ORDER BY id",
    )
    .bind(r.id.0)
    .fetch_all(&mut *conn)
    .await?;
    for (id, body) in pending {
        let key = format!("run-message:{id}");
        let by = ESCALATION_USER;
        let to = Some(r.agent_id);
        let Some((comment, _)) = post_comment_in(conn, issue, by, &body, Some(&key), to).await?
        else {
            continue;
        };
        sqlx::query("UPDATE run_controls SET comment_id = ? WHERE id = ?")
            .bind(comment)
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Marks message `id` of `run` given to its harness (its `user_message` chunk).
pub(super) async fn delivered_in(
    conn: &mut SqliteConnection,
    run: RunId,
    id: i64,
    now: &str,
) -> Result<(), Error> {
    sqlx::query(
        "UPDATE run_controls SET delivered_at = ? WHERE id = ? AND run_id = ? \
         AND kind = 'message' AND delivered_at IS NULL",
    )
    .bind(now)
    .bind(id)
    .bind(run.0)
    .execute(&mut *conn)
    .await
    .map(drop)
}
