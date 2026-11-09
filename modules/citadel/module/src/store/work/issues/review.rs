//! Sprint review and retro (E5.5). Closing a sprint stores its review on it (`review_in`,
//! called by `close_sprint` in its transaction); the product owner or team lead proposes retro
//! items (`propose_retro`): knowledge entries that stay `proposed`, linked to the sprint, until
//! E8 accepts or rejects them. Nothing here accepts anything.

use crate::domain::gov::{KnowledgeEntry, KnowledgeEntryId, KnowledgeKind};
use crate::domain::work::{Sprint, SprintState};
use ainkrad_core::audit::AuditActor;
use serde_json::{Value, json};
use sqlx::SqliteConnection;

use super::sprints::{append_sprint_event, sprint_in};
use super::*;
use crate::store::gov::get_knowledge_entry;

/// The review of the active sprint `s` as it closes, read before its open issues move out
/// (to `carry_to`, or the backlog): committed and completed points, the carried issues, the
/// completed points against the mean of the project's last `sprint.velocity_window` (a
/// setting, E15.17) closed sprints,
/// and from the audit log since it started, the issues that were blocked and the loop-breaker
/// escalations on its issues.
pub(super) async fn review_in(
    conn: &mut SqliteConnection,
    s: &Sprint,
    carry_to: Option<SprintId>,
) -> Result<Value, Error> {
    let (committed, completed, started): (u32, u32, i64) = sqlx::query_as(
        "SELECT coalesce(committed_points, 0), \
         (SELECT coalesce(sum(points), 0) FROM citadel_issues WHERE sprint_id = ?1 AND state = 'done'), \
         coalesce((SELECT max(seq) FROM audit_events WHERE action = 'citadel.sprint.started' \
             AND entity_kind = 'sprint' AND entity_id = ?1), 0) \
         FROM citadel_sprints WHERE id = ?1",
    )
    .bind(s.id.0)
    .fetch_one(&mut *conn)
    .await?;
    let carried: Vec<(i64, String, String, Option<u32>, String)> = sqlx::query_as(
        "SELECT i.id, p.key || '-' || i.number, i.title, i.points, i.state FROM citadel_issues i \
         JOIN citadel_projects p ON p.id = i.project_id WHERE i.sprint_id = ? \
         AND i.state NOT IN ('done', 'cancelled') ORDER BY i.id",
    )
    .bind(s.id.0)
    .fetch_all(&mut *conn)
    .await?;
    // ponytail: server-wide until the Core settings store has company/project scopes.
    let window = crate::settings::handle()
        .get_in(conn, "sprint.velocity_window")
        .await
        .map_err(|e| Error::Configuration(e.to_string().into()))?;
    let previous: Vec<u32> = sqlx::query_scalar(
        "SELECT coalesce(completed_points, 0) FROM citadel_sprints WHERE project_id = ? \
         AND state = 'closed' AND id <> ? ORDER BY id DESC LIMIT ?",
    )
    .bind(s.project_id.0)
    .bind(s.id.0)
    .bind(window)
    .fetch_all(&mut *conn)
    .await?;
    let mean = (!previous.is_empty())
        .then(|| previous.iter().map(|&p| f64::from(p)).sum::<f64>() / previous.len() as f64);
    // The sprint's issues: in it now, before the open ones are carried out.
    let blocked: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT i.id, p.key || '-' || i.number, count(*) FROM audit_events e \
         JOIN citadel_issues i ON i.id = e.entity_id JOIN citadel_projects p ON p.id = i.project_id \
         WHERE e.seq > ?1 AND e.entity_kind = 'issue' AND e.action = 'citadel.issue.blocked' \
         AND i.sprint_id = ?2 GROUP BY i.id ORDER BY i.id",
    )
    .bind(started)
    .bind(s.id.0)
    .fetch_all(&mut *conn)
    .await?;
    let escalated: Vec<(i64, String, i64)> = sqlx::query_as(
        "SELECT i.id, p.key || '-' || i.number, count(*) FROM audit_events e \
         JOIN citadel_issues i ON i.id = json_extract(e.details, '$.issue') \
         JOIN citadel_projects p ON p.id = i.project_id \
         WHERE e.seq > ?1 AND e.action = 'citadel.loop_breaker.tripped' AND i.sprint_id = ?2 \
         GROUP BY i.id ORDER BY i.id",
    )
    .bind(started)
    .bind(s.id.0)
    .fetch_all(&mut *conn)
    .await?;
    let counted = |rows: Vec<(i64, String, i64)>| -> Vec<Value> {
        rows.into_iter()
            .map(|(id, key, times)| json!({"issue": id, "key": key, "times": times}))
            .collect()
    };
    let carried: Vec<Value> = carried
        .into_iter()
        .map(|(id, key, title, points, state)| {
            json!({"issue": id, "key": key, "title": title, "points": points, "state": state})
        })
        .collect();
    Ok(json!({
        "committed": committed,
        "completed": completed,
        "carried": carried,
        "carried_to": carry_to.map(|c| c.0),
        "velocity": {"previous_mean": mean, "delta": mean.map(|m| f64::from(completed) - m),
                     "sprints": previous.len()},
        "blocked": counted(blocked),
        "escalated": counted(escalated),
    }))
}

/// The review stored when the sprint closed; `None` before that, or with no such sprint.
pub async fn sprint_review(pool: &SqlitePool, sprint: SprintId) -> Result<Option<Value>, Error> {
    let review: Option<Option<String>> =
        sqlx::query_scalar("SELECT review FROM citadel_sprints WHERE id = ?")
            .bind(sprint.0)
            .fetch_optional(pool)
            .await?;
    review
        .flatten()
        .map(|r| serde_json::from_str(&r).map_err(|e| Error::Decode(Box::new(e))))
        .transpose()
}

/// A retro item: a decision, landmine or retro note learned in the sprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetroItem {
    pub kind: KnowledgeKind,
    pub title: String,
    pub body: String,
}

/// Proposes `items` from the closed sprint as knowledge entries of its project, `proposed` by
/// `by` and linked to the sprint, and appends `sprint.retro_proposed`, in one `BEGIN
/// IMMEDIATE` transaction. A `state` item is `Error::InvalidArgument`: state is not learned.
pub async fn propose_retro(
    pool: &SqlitePool,
    sprint: SprintId,
    items: &[RetroItem],
    by: AgentId,
) -> Result<Vec<KnowledgeEntry>, SprintError> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let s = sprint_in(&mut tx, sprint).await?;
    if s.state != SprintState::Closed {
        return Err(SprintError::State(s.state));
    }
    let mut ids = vec![];
    for item in items {
        if item.kind == KnowledgeKind::State {
            let why = "a retro item is a decision, landmine or retro".to_owned();
            return Err(Error::InvalidArgument(why).into());
        }
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO citadel_knowledge_entries (project_id, kind, title, body, status, \
             proposed_by_agent_id) VALUES (?, ?, ?, ?, 'proposed', ?) RETURNING id",
        )
        .bind(s.project_id.0)
        .bind(item.kind.as_str())
        .bind(&item.title)
        .bind(&item.body)
        .bind(by.0)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO citadel_sprint_retro_items (entry_id, sprint_id) VALUES (?, ?)")
            .bind(id)
            .bind(sprint.0)
            .execute(&mut *tx)
            .await?;
        ids.push(id);
    }
    let details = json!({"entries": ids, "agent_id": by.0});
    append_sprint_event(
        &mut tx,
        &s,
        AuditActor::System,
        "sprint.retro_proposed",
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(entries(pool, ids).await?)
}

/// The knowledge entries proposed from the sprint, oldest first.
pub async fn retro_items(
    pool: &SqlitePool,
    sprint: SprintId,
) -> Result<Vec<KnowledgeEntry>, Error> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT entry_id FROM citadel_sprint_retro_items WHERE sprint_id = ? ORDER BY entry_id",
    )
    .bind(sprint.0)
    .fetch_all(pool)
    .await?;
    entries(pool, ids).await
}

async fn entries(pool: &SqlitePool, ids: Vec<i64>) -> Result<Vec<KnowledgeEntry>, Error> {
    let mut found = vec![];
    for id in ids {
        if let Some(k) = get_knowledge_entry(pool, KnowledgeEntryId(id)).await? {
            found.push(k);
        }
    }
    Ok(found)
}
