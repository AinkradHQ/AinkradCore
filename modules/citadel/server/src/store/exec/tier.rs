//! Which tier a task runs on (E15.5, pain #1: small jobs burning big-model tokens). A project's
//! routing rules match an issue by label (`label:chore`) or kind (`kind:subtask`) and name its
//! tier; a project with no rules of its own uses `DEFAULT_RULES`. With no rule matching, its
//! points decide: at most `routing.small_max_points` is small, at least
//! `routing.large_min_points` large, anything else (or unestimated) standard. A run starts on
//! its agent's model for that tier (`store::org::set_tiers`), then its usual chain.

use citadel_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use citadel_core::org::{CompanyId, Tier};
use citadel_core::settings::{Key, Scope};
use citadel_core::work::{IssueKind, ProjectId};
use serde_json::json;
use sqlx::SqliteConnection;

use super::*;
use crate::store::audit;
use crate::store::settings::value_in;

/// The rules of a project that has none set: chores and docs are small.
pub const DEFAULT_RULES: &[(&str, Tier)] =
    &[("label:chore", Tier::Small), ("label:docs", Tier::Small)];

/// Whether `rule` is `label:<name>` or `kind:<issue kind>`.
fn rule_ok(rule: &str) -> bool {
    match rule.split_once(':') {
        Some(("label", name)) => !name.trim().is_empty(),
        Some(("kind", kind)) => kind.parse::<IssueKind>().is_ok(),
        _ => false,
    }
}

/// Replaces the project's routing rules with `rules` (empty: back to `DEFAULT_RULES`) and
/// appends `project.tier_rules_set`; `false` when the project is gone. A rule that is not
/// `label:<name>` or `kind:<kind>`, or one given twice, is `InvalidArgument`.
pub async fn set_tier_rules(
    pool: &SqlitePool,
    project: ProjectId,
    rules: &[(String, Tier)],
    actor: AuditActor,
) -> Result<bool, Error> {
    let mut tx = crate::store::begin_write(pool).await?;
    let Some(company): Option<i64> =
        sqlx::query_scalar("SELECT company_id FROM projects WHERE id = ?")
            .bind(project.0)
            .fetch_optional(&mut *tx)
            .await?
    else {
        return Ok(false);
    };
    for (i, (rule, _)) in rules.iter().enumerate() {
        if !rule_ok(rule) || rules[..i].iter().any(|(r, _)| r == rule) {
            let why = format!("bad rule {rule:?}: label:<name> or kind:<kind>, once each");
            return Err(Error::InvalidArgument(why));
        }
    }
    sqlx::query("DELETE FROM tier_rules WHERE project_id = ?")
        .bind(project.0)
        .execute(&mut *tx)
        .await?;
    for (rule, tier) in rules {
        sqlx::query("INSERT INTO tier_rules (project_id, rule, tier) VALUES (?, ?, ?)")
            .bind(project.0)
            .bind(rule)
            .bind(tier.as_str())
            .execute(&mut *tx)
            .await?;
    }
    let set: serde_json::Map<String, serde_json::Value> = rules
        .iter()
        .map(|(r, t)| (r.clone(), t.as_str().into()))
        .collect();
    let event = NewAuditEvent {
        actor,
        action: "project.tier_rules_set".to_owned(),
        entity: Some(AuditEntity {
            kind: "project".to_owned(),
            id: project.0,
        }),
        company_id: Some(CompanyId(company)),
        run_id: None,
        details: json!({ "rules": set }).to_string(),
    };
    audit::append(&mut *tx, &event).await?;
    tx.commit().await?;
    Ok(true)
}

/// The project's routing rules, and whether they are `DEFAULT_RULES` (none set).
pub async fn list_tier_rules(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<(Vec<(String, Tier)>, bool), Error> {
    rules_in(&mut *pool.acquire().await?, project).await
}

async fn rules_in(
    conn: &mut SqliteConnection,
    project: ProjectId,
) -> Result<(Vec<(String, Tier)>, bool), Error> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT rule, tier FROM tier_rules WHERE project_id = ? ORDER BY rule")
            .bind(project.0)
            .fetch_all(&mut *conn)
            .await?;
    if rows.is_empty() {
        let defaults = DEFAULT_RULES.iter().map(|(r, t)| ((*r).to_owned(), *t));
        return Ok((defaults.collect(), true));
    }
    rows.into_iter()
        .map(|(rule, tier)| {
            let tier = tier.parse().map_err(|e| Error::Decode(Box::new(e)))?;
            Ok((rule, tier))
        })
        .collect::<Result<_, Error>>()
        .map(|rules| (rules, false))
}

/// The tier of a task on `issue` (standard with none). A matching rule wins over points; of
/// several matching rules, the largest tier, as a big task on a small model costs more than
/// the reverse.
pub(crate) async fn task_tier_in(
    conn: &mut SqliteConnection,
    issue: Option<IssueId>,
) -> Result<Tier, Error> {
    let Some(issue) = issue else {
        return Ok(Tier::Standard);
    };
    let Some((project, kind, points)): Option<(i64, String, Option<i64>)> =
        sqlx::query_as("SELECT project_id, kind, points FROM issues WHERE id = ?")
            .bind(issue.0)
            .fetch_optional(&mut *conn)
            .await?
    else {
        return Ok(Tier::Standard);
    };
    let labels: Vec<String> = sqlx::query_scalar(
        "SELECT lower(l.name) FROM issue_labels il JOIN labels l ON l.id = il.label_id \
         WHERE il.issue_id = ?",
    )
    .bind(issue.0)
    .fetch_all(&mut *conn)
    .await?;
    let project = ProjectId(project);
    let (rules, _) = rules_in(conn, project).await?;
    let matched = rules
        .iter()
        .filter(|(rule, _)| match rule.split_once(':') {
            Some(("label", name)) => labels.contains(&name.trim().to_lowercase()),
            Some(("kind", k)) => *k == kind,
            _ => false,
        })
        .map(|(_, tier)| *tier)
        .max_by_key(|t| match t {
            Tier::Small => 0,
            Tier::Standard => 1,
            Tier::Large => 2,
        });
    if let Some(tier) = matched {
        return Ok(tier);
    }
    let Some(points) = points else {
        return Ok(Tier::Standard);
    };
    let at = Scope::Project(project);
    if points <= value_in(conn, Key::RoutingSmallMaxPoints, at).await? {
        return Ok(Tier::Small);
    }
    if points >= value_in(conn, Key::RoutingLargeMinPoints, at).await? {
        return Ok(Tier::Large);
    }
    Ok(Tier::Standard)
}

/// The session a new `run` continues, when it may (E15.5, fresh context): every run starts a
/// new harness session unless `run.resume_unfinished` is 1 for its project and its agent's
/// previous run on the issue, on the same harness, ended unfinished (failed, timed out or
/// lost; never at its token cap, which would spend the same tokens again) with a session to
/// resume. Within a run, a dropped turn resumes regardless (E15.4).
pub async fn resume_session(pool: &SqlitePool, run: &Run) -> Result<Option<String>, Error> {
    let Some(issue) = run.issue_id else {
        return Ok(None);
    };
    let mut conn = pool.acquire().await?;
    let at = crate::store::settings::run_scope_in(&mut conn, Some(issue), run.agent_id).await?;
    if value_in(&mut conn, Key::ResumeUnfinished, at).await? == 0 {
        return Ok(None);
    }
    let previous: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT iif(terminal_reason = 'token_cap', 'token_cap', state), session_id, harness \
         FROM runs WHERE agent_id = ? AND issue_id = ? AND id < ? ORDER BY id DESC LIMIT 1",
    )
    .bind(run.agent_id.0)
    .bind(issue.0)
    .bind(run.id.0)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(match previous {
        Some((state, session, harness))
            if matches!(state.as_str(), "failed" | "timed_out" | "runner_lost")
                && harness == run.harness.as_str() =>
        {
            session
        }
        _ => None,
    })
}
