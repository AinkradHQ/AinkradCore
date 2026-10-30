//! Project profiles (E15.13): read with the project's approval policy and permission mode,
//! changed a field at a time (`ProfilePatch`), every change audited as `project.profile_set`
//! with the fields it changed. What a run is given of it is `run_profile`.

use ainkrad_core::audit::AuditActor;
use ainkrad_proto::runner::PermissionMode;
use serde_json::{Value, json};
use sqlx::types::Json;
use sqlx::{Error, Row, SqliteConnection, SqlitePool};

use super::requirements::append_org_event;
use crate::domain::org::CompanyId;
use crate::domain::work::{ProjectId, SprintApproval};
use crate::profile::{Fitted, Policies, Profile, ProfilePatch, fit};
use crate::store::org::{affected, text};
use crate::store::work::{Repo, list_repos};

/// A project's profile and the project settings shown with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectProfile {
    pub project_id: ProjectId,
    pub profile: Profile,
    pub sprint_approval: SprintApproval,
    pub permission_mode: PermissionMode,
    /// When the profile was last changed; `None` while it never was.
    pub updated_at: Option<String>,
}

impl ProjectProfile {
    pub fn policies(&self) -> Policies {
        Policies {
            sprint_approval: self.sprint_approval.as_str(),
            permission_mode: self.permission_mode.as_str(),
        }
    }
}

pub(crate) async fn profile_in(
    conn: &mut SqliteConnection,
    project: ProjectId,
) -> Result<Option<ProjectProfile>, Error> {
    let Some(row) = sqlx::query(
        "SELECT p.sprint_approval, p.permission_mode, f.profile, f.updated_at FROM citadel_projects p \
         LEFT JOIN citadel_project_profiles f ON f.project_id = p.id WHERE p.id = ?",
    )
    .bind(project.0)
    .fetch_optional(&mut *conn)
    .await?
    else {
        return Ok(None);
    };
    let profile = match row.try_get::<Option<Json<Profile>>, _>("profile")? {
        Some(Json(p)) => p.with_rules(),
        None => Profile::default(),
    };
    let mode: String = row.try_get("permission_mode")?;
    Ok(Some(ProjectProfile {
        project_id: project,
        profile,
        sprint_approval: text(&row, "sprint_approval")?,
        permission_mode: mode.parse().map_err(|e: String| Error::Decode(e.into()))?,
        updated_at: row.try_get("updated_at")?,
    }))
}

/// The project's profile; `None` when there is no such project.
pub async fn project_profile(
    pool: &SqlitePool,
    project: ProjectId,
) -> Result<Option<ProjectProfile>, Error> {
    profile_in(&mut *pool.acquire().await?, project).await
}

/// Applies `patch` to the project's profile (and its approval policy and permission mode) as
/// `actor`, in one `BEGIN IMMEDIATE` transaction; `None` when there is no such project. A value
/// the profile cannot hold, or the sandboxed mode on a project without sandboxed runs, is
/// `Error::Protocol`.
pub async fn update_profile(
    pool: &SqlitePool,
    project: ProjectId,
    patch: &ProfilePatch,
    actor: AuditActor,
) -> Result<Option<ProjectProfile>, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let updated = update_profile_in(&mut tx, project, patch, actor, json!({})).await?;
    tx.commit().await?;
    Ok(updated)
}

/// `update_profile` inside the caller's transaction; `details` go into the audit event.
pub(crate) async fn update_profile_in(
    conn: &mut SqliteConnection,
    project: ProjectId,
    patch: &ProfilePatch,
    actor: AuditActor,
    mut details: Value,
) -> Result<Option<ProjectProfile>, Error> {
    let Some(mut current) = profile_in(conn, project).await? else {
        return Ok(None);
    };
    let mut changed = patch.apply(&mut current.profile);
    if let Some(why) = current.profile.problem() {
        return Err(Error::Protocol(why));
    }
    if let Some(a) = patch.sprint_approval.map(SprintApproval::from)
        && a != current.sprint_approval
    {
        sqlx::query("UPDATE citadel_projects SET sprint_approval = ? WHERE id = ?")
            .bind(a.as_str())
            .bind(project.0)
            .execute(&mut *conn)
            .await?;
        changed.push("sprint_approval");
    }
    if let Some(mode) = patch.permission_mode.map(PermissionMode::from)
        && mode != current.permission_mode
    {
        sqlx::query(
            "UPDATE citadel_projects SET permission_mode = ? WHERE id = ? \
             AND (? <> 'sandboxed' OR sandboxed = 1)",
        )
        .bind(mode.as_str())
        .bind(project.0)
        .bind(mode.as_str())
        .execute(&mut *conn)
        .await
        .map(affected)?
        .then_some(())
        .ok_or_else(|| Error::Protocol("the sandboxed mode needs sandboxed runs".to_owned()))?;
        changed.push("permission_mode");
    }
    if changed.is_empty() {
        return Ok(Some(current));
    }
    sqlx::query(
        "INSERT INTO citadel_project_profiles (project_id, profile) VALUES (?, ?) \
         ON CONFLICT (project_id) DO UPDATE SET profile = excluded.profile, \
         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
    )
    .bind(project.0)
    .bind(Json(&current.profile))
    .execute(&mut *conn)
    .await?;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_projects WHERE id = ?")
        .bind(project.0)
        .fetch_one(&mut *conn)
        .await?;
    // The new values, so the profile's history shows what each change set.
    let given = serde_json::to_value(patch).unwrap_or_default();
    let values: serde_json::Map<String, Value> = changed
        .iter()
        .filter_map(|f| Some(((*f).to_owned(), given.get(*f)?.clone())))
        .collect();
    details["fields"] = json!(changed);
    details["values"] = Value::Object(values);
    let entity = ("project", project.0);
    let action = "project.profile_set";
    append_org_event(conn, CompanyId(company), actor, action, entity, details).await?;
    profile_in(conn, project).await
}

/// One step of a profile's history: a change (`project.profile_set`) or an agent's proposal of
/// one being made or decided (`knowledge.proposed|accepted|rejected`), as audited.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileStep {
    pub seq: i64,
    pub at: String,
    pub actor: AuditActor,
    pub action: String,
    /// What was audited: the fields changed and their new values, or the proposal's field,
    /// reason and knowledge entry.
    pub details: Value,
}

/// The project's profile history, newest first: `limit` steps before audit `seq` `before`.
pub async fn profile_history(
    pool: &SqlitePool,
    project: ProjectId,
    before: Option<i64>,
    limit: u32,
) -> Result<Vec<ProfileStep>, Error> {
    let rows: Vec<(i64, String, String, Option<i64>, String, String)> = sqlx::query_as(
        "SELECT seq, at, actor_kind, actor_id, action, details FROM audit_events \
         WHERE ((entity_kind = 'project' AND entity_id = ?1 \
                 AND action = 'citadel.project.profile_set') \
             OR (entity_kind = 'knowledge_entry' AND entity_id IN (SELECT id FROM \
                 citadel_knowledge_entries WHERE project_id = ?1 AND target LIKE 'profile.%'))) \
         AND (?2 IS NULL OR seq < ?2) ORDER BY seq DESC LIMIT ?3",
    )
    .bind(project.0)
    .bind(before)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|(seq, at, kind, id, action, details)| {
            let actor = AuditActor::from_parts(&kind, id)
                .ok_or_else(|| Error::Decode(format!("bad actor `{kind}`").into()))?;
            let details = serde_json::from_str(&details).unwrap_or(Value::Null);
            // The module's rows are `citadel.<action>`; a client sees the action itself.
            let action = action
                .strip_prefix("citadel.")
                .unwrap_or(&action)
                .to_owned();
            Ok(ProfileStep {
                seq,
                at,
                actor,
                action,
                details,
            })
        })
        .collect()
}

/// What a run on the project is given of its profile, fitted to its `profile.budget_bytes`, and
/// that budget.
pub async fn run_profile(pool: &SqlitePool, project: ProjectId) -> Result<(Fitted, u64), Error> {
    let Some(p) = project_profile(pool, project).await? else {
        return Ok((Fitted::default(), 0));
    };
    // ponytail: server-wide until the Core settings store has company/project scopes
    let budget = crate::settings::value(pool, "profile.budget_bytes").await? as u64;
    let repos = repos_section(&list_repos(pool, project).await?);
    let sections = p
        .profile
        .sections(repos.into_iter().collect(), &p.policies());
    Ok((fit(sections, budget as usize), budget))
}

/// The project's repos with their commands (E15.16), when it has any.
fn repos_section(repos: &[Repo]) -> Option<(&'static str, String)> {
    let mut out = String::new();
    for r in repos {
        let primary = if r.primary { " (primary)" } else { "" };
        out.push_str(&format!(
            "- {}{primary}: {}, base {}\n",
            r.name, r.url, r.default_branch
        ));
        let c = &r.commands;
        for (what, cmd) in [
            ("build", &c.build),
            ("test", &c.test),
            ("lint", &c.lint),
            ("format", &c.format),
        ] {
            if !cmd.trim().is_empty() {
                out.push_str(&format!("  - {what}: `{}`\n", cmd.trim()));
            }
        }
    }
    if repos.len() > 1 {
        out.push_str("An issue touching several repos has a worktree per repo, named after it.\n");
    }
    (!out.is_empty()).then_some(("repositories", out))
}
