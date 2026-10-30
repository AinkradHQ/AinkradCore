//! Sprint metrics (E5.2): committed and completed points, capacity, velocity and the
//! burndown, from the sprint's frozen numbers and the issues' state history
//! (`issue_state_history`, written by triggers on every state change); and flow metrics
//! (E5.3): cycle and lead times, from the same history.
//!
//! Points are read as the issues carry them now: re-pointing an issue after the fact changes
//! the burndown it is in, not the committed and completed numbers frozen at start and close.

use crate::domain::work::{FlowMetrics, SprintReport, Velocity};
use serde_json::{Value, json};

use super::*;

/// The sprint's report as of `now` (ISO-8601); `None` when there is no such sprint.
pub async fn sprint_report(
    pool: &SqlitePool,
    id: SprintId,
    now: &str,
) -> Result<Option<SprintReport>, Error> {
    let Some(row) = sqlx::query(
        "SELECT s.state, s.starts_on, s.ends_on, s.committed_points, \
         CASE s.state WHEN 'closed' THEN s.completed_points \
             ELSE (SELECT coalesce(sum(points), 0) FROM citadel_issues \
                   WHERE sprint_id = s.id AND state = 'done') END AS completed, \
         (SELECT sum(m.capacity) FROM citadel_team_memberships m JOIN citadel_projects p \
             ON p.team_id = m.team_id WHERE p.id = s.project_id) AS capacity \
         FROM citadel_sprints s WHERE s.id = ?",
    )
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    let committed: Option<u32> = row.try_get("committed_points")?;
    let burndown = match committed {
        Some(points) => burndown(pool, id, &row, points, now).await?,
        None => vec![],
    };
    Ok(Some(SprintReport {
        sprint_id: id,
        state: text(&row, "state")?,
        committed,
        completed: row.try_get("completed")?,
        capacity: row.try_get("capacity")?,
        burndown,
    }))
}

/// The report as JSON, as the MCP tools and the admin CLI show it.
pub fn report_json(r: &SprintReport) -> Value {
    let burndown: Vec<Value> = r
        .burndown
        .iter()
        .map(|(day, left)| json!({"day": day, "left": left}))
        .collect();
    json!({"sprint_id": r.sprint_id.0, "state": r.state.as_str(), "committed": r.committed,
           "completed": r.completed, "capacity": r.capacity, "burndown": burndown})
}

/// Points left at the end of each day from the start date to the end date or `now`'s date,
/// whichever is earlier: committed less the points of the sprint's issues that were done
/// then (the last state they reached by that day's end).
async fn burndown(
    pool: &SqlitePool,
    id: SprintId,
    sprint: &SqliteRow,
    committed: u32,
    now: &str,
) -> Result<Vec<(String, u32)>, Error> {
    let starts: Option<String> = sprint.try_get("starts_on")?;
    let ends: Option<String> = sprint.try_get("ends_on")?;
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "WITH RECURSIVE last(d) AS (SELECT min(date(?2), date(?3))), \
         days(d) AS (SELECT date(?1) WHERE date(?1) <= (SELECT d FROM last) \
             UNION ALL SELECT date(d, '+1 day') FROM days WHERE d < (SELECT d FROM last)) \
         SELECT d, max(?4 - coalesce((SELECT sum(i.points) FROM citadel_issues i \
             WHERE i.sprint_id = ?5 AND (SELECT h.to_state FROM citadel_issue_state_history h \
                 WHERE h.issue_id = i.id AND h.at < date(d, '+1 day') \
                 ORDER BY h.at DESC, h.id DESC LIMIT 1) = 'done'), 0), 0) \
         FROM days ORDER BY d",
    )
    .bind(starts)
    .bind(ends)
    .bind(now)
    .bind(committed)
    .bind(id.0)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(day, left)| (day, left as u32))
        .collect())
}

/// Committed and completed points of the project's last `n` closed sprints, and the mean
/// completed.
pub async fn velocity(pool: &SqlitePool, project: ProjectId, n: u32) -> Result<Velocity, Error> {
    let rows: Vec<(i64, u32, u32)> = sqlx::query_as(
        "SELECT id, coalesce(committed_points, 0), coalesce(completed_points, 0) FROM citadel_sprints \
         WHERE project_id = ? AND state = 'closed' ORDER BY id DESC LIMIT ?",
    )
    .bind(project.0)
    .bind(n)
    .fetch_all(pool)
    .await?;
    let total: u32 = rows.iter().map(|r| r.2).sum();
    let average = match rows.len() {
        0 => 0.0,
        len => f64::from(total) / len as f64,
    };
    Ok(Velocity {
        sprints: rows
            .into_iter()
            .map(|(id, committed, completed)| (SprintId(id), committed, completed))
            .collect(),
        average,
    })
}

/// Cycle and lead times of the project's top-level issues that are done now and were last
/// done in `[from, to)` (ISO-8601), by when they were done.
pub async fn flow_metrics(
    pool: &SqlitePool,
    project: ProjectId,
    from: &str,
    to: &str,
) -> Result<FlowMetrics, Error> {
    let rows: Vec<(i64, Option<i64>, i64)> = sqlx::query_as(
        "WITH t AS (SELECT i.id, \
             (SELECT min(at) FROM citadel_issue_state_history WHERE issue_id = i.id) AS created, \
             (SELECT min(at) FROM citadel_issue_state_history WHERE issue_id = i.id \
                 AND to_state = 'in_progress') AS started, \
             (SELECT max(at) FROM citadel_issue_state_history WHERE issue_id = i.id \
                 AND to_state = 'done') AS done \
             FROM citadel_issues i WHERE i.project_id = ?1 AND i.state = 'done' AND i.parent_id IS NULL) \
         SELECT id, CAST(round((julianday(done) - julianday(started)) * 86400) AS INTEGER), \
             CAST(round((julianday(done) - julianday(created)) * 86400) AS INTEGER) \
         FROM t WHERE julianday(done) >= julianday(?2) AND julianday(done) < julianday(?3) \
         ORDER BY done, id",
    )
    .bind(project.0)
    .bind(from)
    .bind(to)
    .fetch_all(pool)
    .await?;
    let mean = |v: Vec<i64>| {
        let n = v.len() as f64;
        (n > 0.0).then(|| v.into_iter().sum::<i64>() as f64 / n)
    };
    Ok(FlowMetrics {
        mean_cycle_secs: mean(rows.iter().filter_map(|r| r.1).collect()),
        mean_lead_secs: mean(rows.iter().map(|r| r.2).collect()),
        issues: rows
            .into_iter()
            .map(|(id, cycle, lead)| (IssueId(id), cycle, lead))
            .collect(),
    })
}
