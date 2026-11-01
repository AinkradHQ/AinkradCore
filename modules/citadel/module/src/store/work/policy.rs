//! Project permission policies (E3.10): the harness policy a project's runs start with.

use crate::domain::work::{IssueId, ProjectId};
use ainkrad_core::audit::AuditActor;
use ainkrad_proto::runner::{PermissionMode, Policy};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::types::Json;
use sqlx::{Error, Row};

/// Sets the project's harness permission policy (E3.10) as `actor` and audits
/// `project.policy_set` (mode, allowlist, sandboxed) in one `BEGIN IMMEDIATE` transaction;
/// `false` when there is no such project. `sandboxed` mode without `sandboxed` runs, or an
/// empty allowlist entry, is `Error::InvalidArgument`. The entries keep the runner's rules
/// (`ainkrad_proto::runner::allows`): a tool name or `<tool>:<command prefix>`, matching a
/// command with shell operators only when every part of a plain chain matches on its own.
pub async fn set_project_policy(
    pool: &SqlitePool,
    project_id: ProjectId,
    policy: &Policy,
    actor: AuditActor,
) -> Result<bool, Error> {
    if policy.mode == PermissionMode::Sandboxed && !policy.sandboxed {
        let why = "the sandboxed mode needs sandboxed runs".to_owned();
        return Err(Error::InvalidArgument(why));
    }
    if policy.allow.iter().any(|entry| entry.trim().is_empty()) {
        return Err(Error::InvalidArgument(
            "an empty allowlist entry".to_owned(),
        ));
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let company: Option<i64> = sqlx::query_scalar(
        "UPDATE citadel_projects SET permission_mode = ?, allowed_tools = ?, sandboxed = ? WHERE id = ? \
         RETURNING company_id",
    )
    .bind(policy.mode.as_str())
    .bind(Json(&policy.allow))
    .bind(policy.sandboxed)
    .bind(project_id.0)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(company) = company else {
        return Ok(false);
    };
    let details = serde_json::json!({
        "mode": policy.mode.as_str(), "allow": policy.allow, "sandboxed": policy.sandboxed,
    });
    super::append(
        &mut tx,
        company,
        actor,
        "project.policy_set",
        ("project", project_id.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// The policy of the issue's project; the default (ask) when the issue is gone.
pub async fn issue_policy(pool: &SqlitePool, issue: IssueId) -> Result<Policy, Error> {
    let row = sqlx::query(
        "SELECT p.permission_mode, p.allowed_tools, p.sandboxed FROM citadel_issues i \
         JOIN citadel_projects p ON p.id = i.project_id WHERE i.id = ?",
    )
    .bind(issue.0)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(policy).transpose()?.unwrap_or_default())
}

/// The project's policy; `None` when there is no such project.
pub async fn project_policy(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<Option<Policy>, Error> {
    sqlx::query(
        "SELECT permission_mode, allowed_tools, sandboxed FROM citadel_projects WHERE id = ?",
    )
    .bind(project.0)
    .fetch_optional(pool)
    .await?
    .map(policy)
    .transpose()
}

fn policy(row: SqliteRow) -> Result<Policy, Error> {
    let mode: String = row.try_get("permission_mode")?;
    Ok(Policy {
        mode: mode.parse().map_err(|e: String| Error::Decode(e.into()))?,
        allow: row.try_get::<Json<Vec<String>>, _>("allowed_tools")?.0,
        sandboxed: row.try_get("sandboxed")?,
        ..Default::default()
    })
}
