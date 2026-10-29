//! Backlog (E5.1): ordering, epic and label assignment and estimates (each audited), the
//! filtered, paged backlog listing, and who may plan it.
//!
//! An issue's place is its `rank` within the project, ascending, ties by id. A move puts the
//! issue halfway between its new neighbours; when they are too close for that (or tied), the
//! project is renumbered 1, 2, 3, … in its current order first, so the order stays total.

use citadel_core::audit::AuditActor;
use citadel_core::work::{BacklogFilter, Position};
use sqlx::SqliteConnection;

use super::checkout::{append_issue_event, issue_in};
use super::*;

/// The most a backlog page holds.
pub const MAX_BACKLOG_PAGE: u32 = 200;

/// Moves the issue to `to` in its project's order and appends `issue.moved` by `actor`, in
/// one `BEGIN IMMEDIATE` transaction. A missing issue or anchor is `Error::RowNotFound`; an
/// anchor in another project, or the issue itself, is `Error::InvalidArgument`.
pub async fn move_issue(
    pool: &SqlitePool,
    id: IssueId,
    to: Position,
    actor: AuditActor,
) -> Result<Issue, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let current = issue_in(&mut tx, id).await?.ok_or(Error::RowNotFound)?;
    if let Position::Before(anchor) | Position::After(anchor) = to {
        if anchor == id {
            let why = "an issue cannot move next to itself".to_owned();
            return Err(Error::InvalidArgument(why));
        }
        let a = issue_in(&mut tx, anchor).await?.ok_or(Error::RowNotFound)?;
        if a.project_id != current.project_id {
            let why = format!("issue {} is in another project", anchor.0);
            return Err(Error::InvalidArgument(why));
        }
    }
    let rank = match free_rank(&mut tx, &current, to).await? {
        Some(rank) => rank,
        None => {
            renumber(&mut tx, current.project_id).await?;
            free_rank(&mut tx, &current, to)
                .await?
                .expect("renumbered ranks are 1 apart")
        }
    };
    let row = sqlx::query(concat!(
        "UPDATE issues SET rank = ? WHERE id = ? RETURNING ",
        issue_columns!()
    ))
    .bind(rank)
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await?;
    let moved = issue(row)?;
    let details = serde_json::json!({"to": format!("{to:?}"), "rank": rank}).to_string();
    append_issue_event(&mut tx, &moved, actor, "issue.moved", None, details).await?;
    tx.commit().await?;
    Ok(moved)
}

/// Bumps the issue (`priority`: to the top of its backlog, flagged so its wakes are dispatched
/// first) or clears the flag, leaving its place; appends `issue.priority_set` by `actor`, in one
/// `BEGIN IMMEDIATE` transaction. `None`: no such issue. The `priority_level` follows: set, it is
/// at least `high`; cleared, `high` and `urgent` fall to `none`.
pub async fn set_issue_priority(
    pool: &SqlitePool,
    id: IssueId,
    priority: bool,
    actor: AuditActor,
) -> Result<Option<Issue>, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(current) = issue_in(&mut tx, id).await? else {
        return Ok(None);
    };
    let mut rank = current.rank;
    if priority {
        rank = match free_rank(&mut tx, &current, Position::Top).await? {
            Some(rank) => rank,
            None => {
                renumber(&mut tx, current.project_id).await?;
                free_rank(&mut tx, &current, Position::Top)
                    .await?
                    .expect("renumbered ranks are 1 apart")
            }
        };
    }
    let row = sqlx::query(concat!(
        "UPDATE issues SET rank = ?1, priority = ?2, priority_level = CASE \
         WHEN ?2 THEN (CASE WHEN priority_level IN ('high', 'urgent') THEN priority_level \
             ELSE 'high' END) \
         WHEN priority_level IN ('high', 'urgent') THEN 'none' ELSE priority_level END \
         WHERE id = ?3 RETURNING ",
        issue_columns!()
    ))
    .bind(rank)
    .bind(priority)
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await?;
    let set = issue(row)?;
    let details = serde_json::json!({"priority": priority, "rank": rank}).to_string();
    append_issue_event(&mut tx, &set, actor, "issue.priority_set", None, details).await?;
    tx.commit().await?;
    Ok(Some(set))
}

/// A rank strictly between the issue's new neighbours at `to`; `None` when they are too
/// close (or tied) for one.
async fn free_rank(
    conn: &mut SqliteConnection,
    issue: &Issue,
    to: Position,
) -> Result<Option<f64>, Error> {
    // The neighbour before (`<`, descending) or after (`>`, ascending) the (rank, id) of
    // `anchor`, or the first / last issue, leaving out the one being moved.
    async fn next_to(
        conn: &mut SqliteConnection,
        issue: &Issue,
        anchor: Option<IssueId>,
        before: bool,
    ) -> Result<Option<f64>, Error> {
        let sql = if before {
            "SELECT rank FROM issues WHERE project_id = ?1 AND id <> ?2 AND (?3 IS NULL \
             OR (rank, id) < (SELECT rank, id FROM issues WHERE id = ?3)) \
             ORDER BY rank DESC, id DESC LIMIT 1"
        } else {
            "SELECT rank FROM issues WHERE project_id = ?1 AND id <> ?2 AND (?3 IS NULL \
             OR (rank, id) > (SELECT rank, id FROM issues WHERE id = ?3)) \
             ORDER BY rank, id LIMIT 1"
        };
        sqlx::query_scalar(sql)
            .bind(issue.project_id.0)
            .bind(issue.id.0)
            .bind(anchor.map(|a| a.0))
            .fetch_optional(&mut *conn)
            .await
    }
    let rank_of =
        |a: IssueId| sqlx::query_scalar::<_, f64>("SELECT rank FROM issues WHERE id = ?").bind(a.0);
    let (lo, hi) = match to {
        Position::Top => (None, next_to(conn, issue, None, false).await?),
        Position::Bottom => (next_to(conn, issue, None, true).await?, None),
        Position::Before(a) => (
            next_to(conn, issue, Some(a), true).await?,
            Some(rank_of(a).fetch_one(&mut *conn).await?),
        ),
        Position::After(a) => (
            Some(rank_of(a).fetch_one(&mut *conn).await?),
            next_to(conn, issue, Some(a), false).await?,
        ),
    };
    Ok(match (lo, hi) {
        (None, None) => Some(1.0),
        (None, Some(hi)) => Some(hi - 1.0),
        (Some(lo), None) => Some(lo + 1.0),
        (Some(lo), Some(hi)) => {
            let mid = lo + (hi - lo) / 2.0;
            (lo < mid && mid < hi).then_some(mid)
        }
    })
}

/// Ranks the project's issues 1, 2, 3, … in their current order.
async fn renumber(conn: &mut SqliteConnection, project: ProjectId) -> Result<(), Error> {
    sqlx::query(
        "UPDATE issues SET rank = r.n FROM (SELECT id, row_number() OVER (ORDER BY rank, id) AS n \
         FROM issues WHERE project_id = ?) AS r WHERE issues.id = r.id",
    )
    .bind(project.0)
    .execute(&mut *conn)
    .await
    .map(drop)
}

/// Puts the issue in `epic` (or none) and appends `issue.epic_set` by `actor`; `false` when
/// there is no such issue. An epic of another project is `Error::Database` (trigger).
pub async fn set_issue_epic(
    pool: &SqlitePool,
    id: IssueId,
    epic: Option<EpicId>,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let row = sqlx::query(concat!(
        "UPDATE issues SET epic_id = ? WHERE id = ? RETURNING ",
        issue_columns!()
    ))
    .bind(epic.map(|e| e.0))
    .bind(id.0)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let updated = issue(row)?;
    let details = serde_json::json!({"epic": epic.map(|e| e.0)}).to_string();
    append_issue_event(&mut tx, &updated, actor, "issue.epic_set", None, details).await?;
    tx.commit().await?;
    Ok(true)
}

/// Sets the issue's story points (`None` clears them) and appends `issue.estimated` by
/// `actor`, in one `BEGIN IMMEDIATE` transaction. A missing issue is `NotFound`; a closed one
/// is `IssueClosed`; one in a sprint whose commit waits on its approval is
/// `AwaitingApproval`: the approval holds its points (a trigger refuses every other path).
/// Points frozen at a sprint's start and close stay.
pub async fn estimate_issue(
    pool: &SqlitePool,
    id: IssueId,
    points: Option<u32>,
    actor: AuditActor,
) -> Result<Issue, SprintError> {
    let mut tx = crate::store::begin_write(pool).await?;
    let current = issue_in(&mut tx, id).await?.ok_or(SprintError::NotFound)?;
    if current.state.is_terminal() {
        return Err(SprintError::IssueClosed(current.state));
    }
    if let Some(sprint) = current.sprint_id {
        super::sprints::not_awaiting(&mut tx, sprint).await?;
    }
    let row = sqlx::query(concat!(
        "UPDATE issues SET points = ? WHERE id = ? RETURNING ",
        issue_columns!()
    ))
    .bind(points)
    .bind(id.0)
    .fetch_one(&mut *tx)
    .await?;
    let estimated = issue(row)?;
    let details = serde_json::json!({"from": current.points, "to": points}).to_string();
    append_issue_event(&mut tx, &estimated, actor, "issue.estimated", None, details).await?;
    tx.commit().await?;
    Ok(estimated)
}

/// A page of the project's backlog (open top-level issues in no sprint) matching `filter`, by
/// rank: up to `limit` (at most `MAX_BACKLOG_PAGE`) issues after skipping `offset`.
pub async fn backlog_page(
    pool: &SqlitePool,
    project_id: ProjectId,
    filter: &BacklogFilter,
    offset: u32,
    limit: u32,
) -> Result<Vec<Issue>, Error> {
    let (owner_agent, owner_user) = actor_columns(filter.assignee);
    sqlx::query(concat!(
        "SELECT ",
        issue_columns!(),
        " FROM issues WHERE project_id = ?1 AND sprint_id IS NULL AND parent_id IS NULL \
         AND state NOT IN ('done', 'cancelled') \
         AND (?2 IS NULL OR epic_id = ?2) \
         AND (?3 IS NULL OR EXISTS (SELECT 1 FROM issue_labels l \
             WHERE l.issue_id = issues.id AND l.label_id = ?3)) \
         AND (?4 IS NULL OR kind = ?4) AND (?5 IS NULL OR state = ?5) \
         AND (?6 IS NULL OR owner_agent_id = ?6) AND (?7 IS NULL OR owner_user_id = ?7) \
         ORDER BY rank, id LIMIT ?8 OFFSET ?9"
    ))
    .bind(project_id.0)
    .bind(filter.epic_id.map(|e| e.0))
    .bind(filter.label_id.map(|l| l.0))
    .bind(filter.kind.map(|k| k.as_str()))
    .bind(filter.state.map(|s| s.as_str()))
    .bind(owner_agent)
    .bind(owner_user)
    .bind(limit.min(MAX_BACKLOG_PAGE))
    .bind(offset)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(issue)
    .collect()
}

/// Attaches the label to the issue and appends `issue.labeled` by `actor`; attaching it
/// again changes and audits nothing. A missing issue is `Error::RowNotFound`; a label of
/// another project is `Error::Database` (trigger).
pub async fn add_issue_label(
    pool: &SqlitePool,
    issue_id: IssueId,
    label_id: LabelId,
    actor: AuditActor,
) -> Result<(), Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let i = issue_in(&mut tx, issue_id)
        .await?
        .ok_or(Error::RowNotFound)?;
    let added = sqlx::query(
        "INSERT INTO issue_labels (issue_id, label_id) VALUES (?, ?) ON CONFLICT DO NOTHING",
    )
    .bind(issue_id.0)
    .bind(label_id.0)
    .execute(&mut *tx)
    .await
    .map(affected)?;
    if added {
        let details = serde_json::json!({"label": label_id.0}).to_string();
        append_issue_event(&mut tx, &i, actor, "issue.labeled", None, details).await?;
    }
    tx.commit().await
}

/// Detaches the label and appends `issue.unlabeled` by `actor`; `false` when it was not
/// attached.
pub async fn remove_issue_label(
    pool: &SqlitePool,
    issue_id: IssueId,
    label_id: LabelId,
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let removed = sqlx::query("DELETE FROM issue_labels WHERE issue_id = ? AND label_id = ?")
        .bind(issue_id.0)
        .bind(label_id.0)
        .execute(&mut *tx)
        .await
        .map(affected)?;
    if removed && let Some(i) = issue_in(&mut tx, issue_id).await? {
        let details = serde_json::json!({"label": label_id.0}).to_string();
        append_issue_event(&mut tx, &i, actor, "issue.unlabeled", None, details).await?;
    }
    tx.commit().await?;
    Ok(removed)
}

/// Whether the agent may read the project's whole backlog (E5.1): the product owner or team
/// lead of the project's owning team, or the CEO or CTO of the project's company.
pub async fn may_read_backlog(
    pool: &SqlitePool,
    agent: AgentId,
    project: ProjectId,
) -> Result<bool, Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM projects p \
         JOIN agents a ON a.id = ?2 AND a.company_id = p.company_id WHERE p.id = ?1 \
         AND (a.org_role IN ('ceo', 'cto') OR EXISTS (SELECT 1 FROM team_memberships m \
             WHERE m.team_id = p.team_id AND m.agent_id = a.id \
             AND m.team_role IN ('product_owner', 'team_lead'))))",
    )
    .bind(project.0)
    .bind(agent.0)
    .fetch_one(pool)
    .await
}

/// Whether the agent is a member (any role) of the project's owning team.
pub async fn on_project_team(
    pool: &SqlitePool,
    agent: AgentId,
    project: ProjectId,
) -> Result<bool, Error> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM projects p JOIN team_memberships m \
         ON m.team_id = p.team_id WHERE p.id = ? AND m.agent_id = ?)",
    )
    .bind(project.0)
    .bind(agent.0)
    .fetch_one(pool)
    .await
}
