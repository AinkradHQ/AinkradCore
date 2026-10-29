//! Runs that end without acting (pain: an agent reads its issue, writes a summary and ends
//! its turn `success`, while the issue still waits on it).
//!
//! A run that succeeds but made no state-changing Citadel call (any tool but the reads and a
//! bare comment, `NOT_ACTING`; a refused one counts, e.g. a verdict while checks still run:
//! the agent tried, and its refusal is its answer), and whose issue did not change while it
//! ran, while that issue, open, still waits on its agent, is no progress: its terminal reason becomes `ended_without_action`, and in the same transaction its agent is
//! woken again at once with a nudge quoting its last words, up to `run.max_no_action_rewakes`
//! times in a row; the next one escalates the issue up the chain (team lead, product owner,
//! the admin) with the reason. Audited as `run.ended_without_action`.
//!
//! Never a loop: the count is per (issue, agent), of such runs since the agent's last run that
//! acted and since the issue last changed (`issues.updated_at`: state or next actor), and an
//! escalation moves the issue off the agent.

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::exec::{NewWakeRequest, WakeSource};
use ainkrad_core::org::CompanyId;
use ainkrad_core::settings::Key;
use ainkrad_core::work::NextActor;
use serde_json::json;
use sqlx::SqliteConnection;

use super::prompt::cut;
use super::*;
use crate::store::audit;
use crate::store::org::escalation_target_in;
use crate::store::settings::{run_scope_in, value_in};
use crate::store::work::{IssueTransitionError, reassign_in};

/// A succeeded run's terminal reason when it ended without acting.
pub const ENDED_WITHOUT_ACTION: &str = "ended_without_action";

/// The Citadel tools that change nothing (reads), and a comment, which hands nothing off: a
/// run whose only calls are these did not act.
// ponytail: a deny-list, so a new tool counts as acting until it is listed here.
const NOT_ACTING: &[&str] = &[
    "mcp.get_issue",
    "mcp.get_context",
    "mcp.list_backlog",
    "mcp.org_chart",
    "mcp.search_tools",
    "mcp.describe_tool",
    "mcp.get_approval",
    "mcp.sprint_report",
    "mcp.comment",
    "mcp.unknown_tool",
];

/// The most of the run's last words the nudge quotes, in chars.
const LAST_WORDS_MAX: usize = 300;

/// Inside the succeeded run `r`'s terminal transition, at `now`: when it ended without acting,
/// marks it, nudges its agent or escalates the issue, audits it, and returns its new terminal
/// reason; `None` when it acted (or had no open issue waiting on its agent).
pub(super) async fn no_action_in(
    conn: &mut SqliteConnection,
    r: &Run,
    now: &str,
) -> Result<Option<String>, IssueTransitionError> {
    let Some(issue) = r.issue_id else {
        return Ok(None);
    };
    let waits: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM issues WHERE id = ? AND next_agent_id = ? \
         AND state NOT IN ('done', 'cancelled'))",
    )
    .bind(issue.0)
    .bind(r.agent_id.0)
    .fetch_one(&mut *conn)
    .await?;
    if !waits {
        return Ok(None);
    }
    // Its own call, or the issue changing (state, next actor) while it ran: by the agent's
    // hand outside the tools, or by anyone else, whose change wakes it afresh anyway.
    let acted: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM audit_events WHERE run_id = ?1 AND action LIKE 'mcp.%' \
             AND action NOT IN (SELECT value FROM json_each(?2))) \
         OR EXISTS (SELECT 1 FROM issues i JOIN runs r ON r.id = ?1 WHERE i.id = ?3 \
             AND julianday(i.updated_at) >= julianday(r.started_at))",
    )
    .bind(r.id.0)
    .bind(json!(NOT_ACTING).to_string())
    .bind(issue.0)
    .fetch_one(&mut *conn)
    .await?;
    if acted {
        return Ok(None);
    }
    // This agent's runs on the issue that ended so, since its last run that acted and since
    // the issue last changed.
    let before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM runs WHERE agent_id = ?1 AND issue_id = ?2 AND id < ?3 \
         AND state = 'succeeded' AND terminal_reason = ?4 \
         AND id > coalesce((SELECT max(id) FROM runs WHERE agent_id = ?1 AND issue_id = ?2 \
             AND id < ?3 AND state = 'succeeded' AND terminal_reason IS NOT ?4), 0) \
         AND ((SELECT updated_at FROM issues WHERE id = ?2) IS NULL \
             OR julianday(ended_at) > julianday((SELECT updated_at FROM issues WHERE id = ?2)))",
    )
    .bind(r.agent_id.0)
    .bind(issue.0)
    .bind(r.id.0)
    .bind(ENDED_WITHOUT_ACTION)
    .fetch_one(&mut *conn)
    .await?;
    let at = run_scope_in(conn, Some(issue), r.agent_id).await?;
    let max = value_in(conn, Key::MaxNoActionRewakes, at).await?;
    let last: Option<String> = sqlx::query_scalar(
        "SELECT json_extract(payload, '$.text') FROM run_events WHERE run_id = ? \
         AND kind = 'assistant_text' ORDER BY seq DESC LIMIT 1",
    )
    .bind(r.id.0)
    .fetch_optional(&mut *conn)
    .await?
    .flatten();
    let last = cut(last.as_deref().unwrap_or("(nothing)"), LAST_WORDS_MAX);
    sqlx::query("UPDATE runs SET terminal_reason = ? WHERE id = ?")
        .bind(ENDED_WITHOUT_ACTION)
        .bind(r.id.0)
        .execute(&mut *conn)
        .await?;
    let (action, escalated_to) = if before < max {
        let wake = NewWakeRequest {
            agent_id: r.agent_id,
            issue_id: Some(issue),
            source: WakeSource::Retry,
            reason: format!(
                "your last run ended without acting: \"{last}\"; act now with the citadel \
                 tools, or ask_human"
            ),
            idempotency_key: format!("no-action:run:{}", r.id.0),
            not_before: None,
        };
        enqueue_in(conn, &wake, 1).await?;
        ("rewake", None)
    } else {
        let to = escalation_target_in(conn, issue, r.agent_id).await?;
        // Queued first, so the reassignment's own wake folds into it and the reason survives.
        if let NextActor::Agent(a) = to {
            let wake = NewWakeRequest {
                agent_id: a,
                issue_id: Some(issue),
                source: WakeSource::Escalation,
                reason: format!(
                    "agent {} ended {} runs in a row without acting on it; last said: \
                     \"{last}\"",
                    r.agent_id.0,
                    before + 1
                ),
                idempotency_key: format!("no-action:run:{}", r.id.0),
                not_before: None,
            };
            enqueue_in(conn, &wake, 1).await?;
        }
        let by = AuditActor::System;
        reassign_in(conn, issue, to.clone(), by, WakeSource::Escalation).await?;
        ("escalate", Some(super::breaker::actor_text(&to)))
    };
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(r.agent_id.0)
        .fetch_one(&mut *conn)
        .await?;
    let event = NewAuditEvent {
        actor: AuditActor::System,
        action: format!("run.{ENDED_WITHOUT_ACTION}"),
        entity: Some(AuditEntity {
            kind: "issue".to_owned(),
            id: issue.0,
        }),
        company_id: Some(CompanyId(company)),
        run_id: Some(r.id),
        details: json!({"agent": r.agent_id.0, "run": r.id.0, "in_a_row": before + 1,
            "max_rewakes": max, "action": action, "escalated_to": escalated_to,
            "last_text": last, "at": now})
        .to_string(),
    };
    audit::append(&mut *conn, &event).await?;
    Ok(Some(ENDED_WITHOUT_ACTION.to_owned()))
}
