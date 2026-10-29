//! A requirement's tree (E15.10, pain #10: "done vs remaining, live, without asking"): its epics
//! and their tasks with state, assignee, points, time and tokens; % done by points; a burndown;
//! an ETA from its own pace; what it has cost so far; and the plan's diff since its approved
//! version (scope added or removed after approval, never silent).
//!
//! Numbers are the plan's: its tasks (top-level issues under its epics, cancelled ones left out),
//! with the points they carry now. Other issues of the requirement (the kickoff, a request filed
//! with no epic) are listed apart and count for nothing.

use std::collections::HashSet;

use ainkrad_core::work::aggregate::{eta_days, left, percent};
use ainkrad_core::work::{EpicId, IssueState};
use serde_json::Value;

use super::*;
use crate::store::gov::{CostReport, CostScope, cost_report};

#[derive(Debug, Clone, PartialEq)]
pub struct TreeTask {
    pub id: IssueId,
    pub key: String,
    pub title: String,
    pub state: IssueState,
    pub epic_id: Option<EpicId>,
    /// Its owner, else the agent it waits on.
    pub assignee: Option<Actor>,
    pub points: Option<u32>,
    pub sprint_id: Option<SprintId>,
    /// Seconds its ended runs took.
    pub time_secs: i64,
    pub tokens: i64,
    pub prs: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TreeEpic {
    pub id: EpicId,
    pub project_id: ProjectId,
    pub title: String,
    pub status: String,
    pub points: u32,
    pub done_points: u32,
    pub tasks: Vec<TreeTask>,
}

/// A task as a plan version holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTaskRef {
    pub id: i64,
    pub key: String,
    pub title: String,
    pub points: Option<i64>,
}

/// The plan now against its approved version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanDiff {
    pub version: i64,
    pub approved_at: String,
    pub approved_by: String,
    pub added: Vec<PlannedTaskRef>,
    pub removed: Vec<PlannedTaskRef>,
    pub points_approved: i64,
    pub points_now: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequirementTree {
    pub requirement: Requirement,
    pub epics: Vec<TreeEpic>,
    /// Its issues outside the plan (no epic): the kickoff, the intake request.
    pub other: Vec<TreeTask>,
    pub points: u32,
    pub done_points: u32,
    /// Done points over all points, rounded; 0 with no points. Leaf product tasks only.
    pub percent_done: u32,
    pub tasks: u32,
    pub done_tasks: u32,
    /// `(day, left, scope)` at the end of each day, from its plan's approval (or its creation) to
    /// today: the scope of that day, not today's.
    pub burndown: Vec<(String, u32, u32)>,
    /// Done points per day since that start (at least one day).
    pub points_per_day: f64,
    /// When the rest is done at that pace (`YYYY-MM-DD`); today once all is done; `None` before
    /// anything is done or before three days of data.
    pub eta: Option<String>,
    pub cost: CostReport,
    pub diff: Option<PlanDiff>,
}

fn refs(tasks: &Value) -> Vec<PlannedTaskRef> {
    tasks
        .as_array()
        .into_iter()
        .flatten()
        .map(|t| PlannedTaskRef {
            id: t["id"].as_i64().unwrap_or_default(),
            key: t["key"].as_str().unwrap_or_default().to_owned(),
            title: t["title"].as_str().unwrap_or_default().to_owned(),
            points: t["points"].as_i64(),
        })
        .collect()
}

/// The plan's diff against its approved version; `None` before one.
pub async fn plan_diff(pool: &SqlitePool, r: &Requirement) -> Result<Option<PlanDiff>, Error> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT tasks, approved_at, approved_by FROM requirement_plans \
         WHERE requirement_id = ? AND version = ?",
    )
    .bind(r.id.0)
    .bind(r.plan_version)
    .fetch_optional(pool)
    .await?;
    let Some((approved, approved_at, approved_by)) = row else {
        return Ok(None);
    };
    let approved = refs(&serde_json::from_str(&approved).unwrap_or_default());
    let mut conn = pool.acquire().await?;
    let now = refs(&Value::from(plan_tasks_in(&mut conn, r.id).await?));
    let ids = |v: &[PlannedTaskRef]| v.iter().map(|t| t.id).collect::<HashSet<_>>();
    let (was, is) = (ids(&approved), ids(&now));
    let sum = |v: &[PlannedTaskRef]| v.iter().filter_map(|t| t.points).sum();
    Ok(Some(PlanDiff {
        version: r.plan_version,
        approved_at,
        approved_by,
        points_approved: sum(&approved),
        points_now: sum(&now),
        added: now
            .iter()
            .filter(|t| !was.contains(&t.id))
            .cloned()
            .collect(),
        removed: approved
            .into_iter()
            .filter(|t| !is.contains(&t.id))
            .collect(),
    }))
}

/// The requirement's top-level issues, by epic then rank.
async fn tasks(pool: &SqlitePool, r: RequirementId) -> Result<Vec<TreeTask>, Error> {
    let rows = sqlx::query(
        "SELECT i.id, p.key || '-' || i.number AS key, i.title, i.state, i.epic_id, \
         i.owner_agent_id, i.owner_user_id, i.next_agent_id, i.points, i.sprint_id, \
         (SELECT coalesce(sum(CAST(round((julianday(ended_at) - julianday(started_at)) \
             * 86400) AS INTEGER)), 0) FROM runs WHERE issue_id = i.id AND ended_at IS NOT NULL \
             AND started_at IS NOT NULL) AS time_secs, \
         (SELECT coalesce(sum(input_tokens + output_tokens + cache_tokens), 0) FROM runs \
             WHERE issue_id = i.id) AS tokens, \
         (SELECT count(*) FROM issue_prs WHERE issue_id = i.id) AS prs \
         FROM issues i JOIN projects p ON p.id = i.project_id \
         WHERE i.requirement_id = ? AND i.parent_id IS NULL \
         ORDER BY i.epic_id IS NULL, i.epic_id, i.rank, i.id",
    )
    .bind(r.0)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let id = |c: &str| -> Result<Option<i64>, Error> { row.try_get(c) };
            let assignee = match (id("owner_agent_id")?, id("owner_user_id")?) {
                (Some(a), _) => Some(Actor::Agent(AgentId(a))),
                (_, Some(u)) => Some(Actor::Human(UserId(u))),
                _ => id("next_agent_id")?.map(|a| Actor::Agent(AgentId(a))),
            };
            Ok(TreeTask {
                id: IssueId(row.try_get("id")?),
                key: row.try_get("key")?,
                title: row.try_get("title")?,
                state: text(&row, "state")?,
                epic_id: id("epic_id")?.map(EpicId),
                assignee,
                points: row.try_get("points")?,
                sprint_id: id("sprint_id")?.map(SprintId),
                time_secs: row.try_get("time_secs")?,
                tokens: row.try_get("tokens")?,
                prs: row.try_get("prs")?,
            })
        })
        .collect()
}

/// The issues that count as product progress (alias `i`, requirement `?1`): leaf tasks of an epic
/// (a task with live subtasks counts through them), not cancelled, not labelled docs.
macro_rules! leaf {
    () => {
        "i.requirement_id = ?1 AND i.state <> 'cancelled' \
    AND coalesce(i.epic_id, (SELECT pp.epic_id FROM issues pp WHERE pp.id = i.parent_id)) IS NOT NULL \
    AND NOT EXISTS (SELECT 1 FROM issues c WHERE c.parent_id = i.id AND c.state <> 'cancelled') \
    AND NOT EXISTS (SELECT 1 FROM issue_labels il JOIN labels l ON l.id = il.label_id \
        WHERE il.issue_id = i.id AND lower(l.name) IN ('doc', 'docs', 'documentation'))"
    };
}

/// `(epic, points, done)` of each leaf product task.
async fn leaves(pool: &SqlitePool, r: RequirementId) -> Result<Vec<(i64, u32, bool)>, Error> {
    let rows: Vec<(i64, Option<u32>, String)> = sqlx::query_as(concat!(
        "SELECT coalesce(i.epic_id, (SELECT pp.epic_id FROM issues pp WHERE pp.id = i.parent_id)), \
         i.points, i.state FROM issues i WHERE ",
        leaf!()
    ))
    .bind(r.0)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(e, p, s)| (e, p.unwrap_or(0), s == "done"))
        .collect())
}

/// `(day, left, scope)` at the end of each day from `start` to `now`'s date. The scope of a day
/// is the leaf tasks created by then, so adding work later does not rewrite earlier days; `left`
/// is that scope less the points done by then (the last state each reached by that day's end).
async fn burndown(
    pool: &SqlitePool,
    r: RequirementId,
    start: &str,
    now: &str,
) -> Result<Vec<(String, u32, u32)>, Error> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(concat!(
        "WITH RECURSIVE days(d) AS (SELECT date(?2) WHERE date(?2) <= date(?3) \
             UNION ALL SELECT date(d, '+1 day') FROM days WHERE d < date(?3)) \
         SELECT d, \
             coalesce((SELECT sum(i.points) FROM issues i WHERE ",
        leaf!(),
        " \
                 AND i.created_at < date(d, '+1 day')), 0), \
             coalesce((SELECT sum(i.points) FROM issues i WHERE ",
        leaf!(),
        " \
                 AND i.created_at < date(d, '+1 day') \
                 AND (SELECT h.to_state FROM issue_state_history h \
                     WHERE h.issue_id = i.id AND h.at < date(d, '+1 day') \
                     ORDER BY h.at DESC, h.id DESC LIMIT 1) = 'done'), 0) \
         FROM days ORDER BY d"
    ))
    .bind(r.0)
    .bind(start)
    .bind(now)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(d, scope, done)| (d, left(scope as u32, done as u32), scope as u32))
        .collect())
}

/// The requirement's tree as of `now` (ISO-8601); `None` when there is no such requirement.
pub async fn requirement_tree(
    pool: &SqlitePool,
    id: RequirementId,
    now: &str,
) -> Result<Option<RequirementTree>, Error> {
    let Some(r) = get_requirement(pool, id).await? else {
        return Ok(None);
    };
    let epic_rows: Vec<(i64, i64, String, String)> = sqlx::query_as(
        "SELECT id, project_id, title, status FROM epics WHERE requirement_id = ? ORDER BY id",
    )
    .bind(id.0)
    .fetch_all(pool)
    .await?;
    let mut all = tasks(pool, id).await?;
    let leaf = leaves(pool, id).await?;
    let mut epics = vec![];
    for (eid, project, title, status) in epic_rows {
        let (mine, rest): (Vec<_>, Vec<_>) = all
            .into_iter()
            .partition(|t| t.epic_id == Some(EpicId(eid)));
        all = rest;
        let (points, done_points) = leaf
            .iter()
            .filter(|l| l.0 == eid)
            .fold((0, 0), |(p, d), l| (p + l.1, d + if l.2 { l.1 } else { 0 }));
        epics.push(TreeEpic {
            id: EpicId(eid),
            project_id: ProjectId(project),
            title,
            status,
            points,
            done_points,
            tasks: mine,
        });
    }
    let points: u32 = epics.iter().map(|e| e.points).sum();
    let done_points: u32 = epics.iter().map(|e| e.done_points).sum();
    let done_tasks = leaf.iter().filter(|l| l.2).count() as u32;
    let tasks = leaf.len() as u32;
    let start: String = sqlx::query_scalar(
        "SELECT coalesce((SELECT min(approved_at) FROM requirement_plans \
         WHERE requirement_id = ?1), (SELECT created_at FROM requirements WHERE id = ?1))",
    )
    .bind(id.0)
    .fetch_one(pool)
    .await?;
    let (days, today): (f64, String) =
        sqlx::query_as("SELECT julianday(?2) - julianday(?1), date(?2)")
            .bind(&start)
            .bind(now)
            .fetch_one(pool)
            .await?;
    let points_per_day = f64::from(done_points) / days.max(1.0);
    let rest = points - done_points;
    let eta = if rest == 0 && points > 0 {
        Some(today)
    } else {
        match eta_days(rest, done_points, days) {
            Some(ahead) => Some(
                sqlx::query_scalar("SELECT date(?, '+' || ? || ' days')")
                    .bind(now)
                    .bind(ahead)
                    .fetch_one(pool)
                    .await?,
            ),
            None => None,
        }
    };
    Ok(Some(RequirementTree {
        burndown: burndown(pool, id, &start, now).await?,
        cost: cost_report(pool, CostScope::Requirement(id)).await?,
        diff: plan_diff(pool, &r).await?,
        requirement: r,
        epics,
        other: all,
        percent_done: percent(done_points, points),
        points,
        done_points,
        tasks,
        done_tasks,
        points_per_day,
        eta,
    }))
}
