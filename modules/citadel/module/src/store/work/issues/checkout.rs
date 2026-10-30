//! Issue checkout (E2.3), the data half: the checkout columns of `citadel_issues`
//! (`checkout_run_id`, `checked_out_at`) and their release, plus the audit helper every issue
//! write uses.
//!
//! Not here (S7, the run engine): `checkout_issue` and `CheckoutError`. The claim joins the
//! run's table (a live run, its agent) and the kanban WIP check, and the run table is the run
//! slice's. A holder whose run has ended no longer holds the issue; that check is S7's too.

use ainkrad_core::audit::AuditActor;
use serde_json::{Value, json};
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit::{self, Event};

/// The issue, read inside the caller's transaction.
pub(crate) async fn issue_in(
    conn: &mut SqliteConnection,
    id: IssueId,
) -> Result<Option<Issue>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        issue_columns!(),
        " FROM citadel_issues WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(&mut *conn)
    .await?
    .map(issue)
    .transpose()
}

/// Releases `issue` if `run` holds it, appending `issue.released` by `actor`; `false` when
/// the run did not hold it. State, owner and next actor are left as they are: moving the
/// issue on is a transition (E2.4). A run's terminal transition releases what it holds by
/// itself (E2.6).
pub async fn release_issue(
    pool: &SqlitePool,
    issue_id: IssueId,
    run_id: RunId,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let released = release_in(&mut tx, issue_id, run_id, actor).await?;
    tx.commit().await?;
    Ok(released)
}

/// Releases every issue `run` holds, inside the caller's transaction; the run is ending.
pub(crate) async fn release_held_in(
    conn: &mut SqliteConnection,
    run_id: RunId,
    actor: AuditActor,
) -> Result<(), Error> {
    let held: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM citadel_issues WHERE checkout_run_id = ?")
            .bind(run_id.0)
            .fetch_all(&mut *conn)
            .await?;
    for id in held {
        release_in(conn, IssueId(id), run_id, actor).await?;
    }
    Ok(())
}

/// `release_issue` inside the caller's transaction.
async fn release_in(
    conn: &mut SqliteConnection,
    issue_id: IssueId,
    run_id: RunId,
    actor: AuditActor,
) -> Result<bool, Error> {
    let released = sqlx::query(concat!(
        "UPDATE citadel_issues SET checkout_run_id = NULL, checked_out_at = NULL \
         WHERE id = ? AND checkout_run_id = ? RETURNING ",
        issue_columns!()
    ))
    .bind(issue_id.0)
    .bind(run_id.0)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = released else {
        return Ok(false);
    };
    let after = issue(row)?;
    append_issue_event(
        conn,
        &after,
        actor,
        "issue.released",
        Some(run_id),
        "{}".to_owned(),
    )
    .await?;
    Ok(true)
}

/// Appends an event about `issue`, attributed to its project's company; `details` is the JSON
/// text of the row's details.
pub(crate) async fn append_issue_event(
    conn: &mut SqliteConnection,
    issue: &Issue,
    actor: AuditActor,
    action: &str,
    run_id: Option<RunId>,
    details: String,
) -> Result<i64, Error> {
    let company_id: i64 =
        sqlx::query_scalar("SELECT company_id FROM citadel_projects WHERE id = ?")
            .bind(issue.project_id.0)
            .fetch_one(&mut *conn)
            .await?;
    let details: Value = serde_json::from_str(&details).unwrap_or_else(|_| json!({}));
    let mut event = Event::new(actor, action)
        .entity("issue", issue.id.0)
        .company(company_id)
        .details(details);
    if let Some(run) = run_id {
        event = event.run(run.0);
    }
    audit::append_seq(conn, event).await
}
