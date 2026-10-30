//! A project's cumulative flow (API minor 18): how many of its issues were in each state at the
//! end of each day, from the state history every issue keeps (`issue_state_history`).

use crate::domain::work::{IssueState, ProjectId};
use sqlx::{Error, SqlitePool};

/// The states, in board order.
pub const STATES: [IssueState; 7] = [
    IssueState::Backlog,
    IssueState::Todo,
    IssueState::InProgress,
    IssueState::InReview,
    IssueState::Blocked,
    IssueState::Done,
    IssueState::Cancelled,
];

/// For each day from `since` to `until` (`YYYY-MM-DD`, inclusive), oldest first, the issues in
/// each of [`STATES`] at the day's end, in that order; an issue counts from the day it was
/// created.
pub async fn cumulative_flow(
    pool: &SqlitePool,
    project: ProjectId,
    since: &str,
    until: &str,
) -> Result<Vec<(String, [i64; 7])>, Error> {
    let rows: Vec<(String, String, i64)> = sqlx::query_as(
        "WITH RECURSIVE d (day) AS (SELECT date(?2) UNION ALL \
             SELECT date(day, '+1 day') FROM d WHERE day < date(?3)), \
         last AS (SELECT d.day, h.to_state, \
             row_number() OVER (PARTITION BY d.day, h.issue_id ORDER BY h.at DESC, h.id DESC) AS rn \
             FROM d JOIN citadel_issue_state_history h ON date(h.at) <= d.day \
             JOIN citadel_issues i ON i.id = h.issue_id AND i.project_id = ?1) \
         SELECT day, to_state, count(*) FROM last WHERE rn = 1 GROUP BY day, to_state",
    )
    .bind(project.0)
    .bind(since)
    .bind(until)
    .fetch_all(pool)
    .await?;
    let days: Vec<String> = sqlx::query_scalar(
        "WITH RECURSIVE d (day) AS (SELECT date(?1) UNION ALL \
             SELECT date(day, '+1 day') FROM d WHERE day < date(?2)) SELECT day FROM d",
    )
    .bind(since)
    .bind(until)
    .fetch_all(pool)
    .await?;
    Ok(days
        .into_iter()
        .map(|day| {
            let mut counts = [0; 7];
            for (_, state, n) in rows.iter().filter(|r| r.0 == day) {
                if let Some(i) = STATES.iter().position(|s| s.as_str() == state) {
                    counts[i] = *n;
                }
            }
            (day, counts)
        })
        .collect())
}
