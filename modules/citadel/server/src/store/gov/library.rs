//! Skills, knowledge entries and device keys; what a run is given of each in `skills` and
//! `knowledge`.

use citadel_core::gov::{
    DeviceKey, DeviceKeyId, KnowledgeEntry, KnowledgeEntryId, NewKnowledgeEntry, Skill,
    SkillAttach, SkillId,
};
use citadel_core::org::{AgentId, CompanyId, DepartmentId};
use citadel_core::work::{ProjectId, UserId};
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row};

use super::id_column;
use crate::store::key_hash;
use crate::store::org::{affected, text};

// --- skills -----------------------------------------------------------------

macro_rules! skill_columns {
    () => {
        "id, company_id, name, version, body, attach_scope, department_id, role, project_id"
    };
}

fn attach_columns(a: &SkillAttach) -> (&'static str, Option<i64>, Option<&str>, Option<i64>) {
    match a {
        SkillAttach::Company => ("company", None, None, None),
        SkillAttach::Department(id) => ("department", Some(id.0), None, None),
        SkillAttach::Role(role) => ("role", None, Some(role), None),
        SkillAttach::Project(id) => ("project", None, None, Some(id.0)),
    }
}

fn skill(row: SqliteRow) -> Result<Skill, Error> {
    let scope: String = row.try_get("attach_scope")?;
    let missing = |column: &str| Error::ColumnNotFound(column.to_owned());
    let attach = match scope.as_str() {
        "company" => SkillAttach::Company,
        "department" => SkillAttach::Department(DepartmentId(
            id_column(&row, "department_id")?.ok_or_else(|| missing("department_id"))?,
        )),
        "role" => SkillAttach::Role(
            row.try_get::<Option<String>, _>("role")?
                .ok_or_else(|| missing("role"))?,
        ),
        "project" => SkillAttach::Project(ProjectId(
            id_column(&row, "project_id")?.ok_or_else(|| missing("project_id"))?,
        )),
        _ => return Err(missing("attach_scope")),
    };
    Ok(Skill {
        id: SkillId(row.try_get("id")?),
        company_id: CompanyId(row.try_get("company_id")?),
        name: row.try_get("name")?,
        version: row.try_get("version")?,
        body: row.try_get("body")?,
        attach,
    })
}

mod skills;
pub use skills::*;

/// Test-only: skills are stored by `publish_skill`, which numbers the version and audits it.
/// A repeat (company, name, version) is a constraint error.
#[cfg(test)]
pub(crate) async fn create_skill(
    pool: &SqlitePool,
    s: &citadel_core::gov::NewSkill,
) -> Result<Skill, Error> {
    let (scope, department, role, project) = attach_columns(&s.attach);
    sqlx::query(concat!(
        "INSERT INTO skills (company_id, name, version, body, attach_scope, department_id, \
         role, project_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING ",
        skill_columns!()
    ))
    .bind(s.company_id.0)
    .bind(&s.name)
    .bind(s.version)
    .bind(&s.body)
    .bind(scope)
    .bind(department)
    .bind(role)
    .bind(project)
    .fetch_one(pool)
    .await
    .and_then(skill)
}

pub async fn get_skill(pool: &SqlitePool, id: SkillId) -> Result<Option<Skill>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        skill_columns!(),
        " FROM skills WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(skill)
    .transpose()
}

/// The company's skills by name, then version.
pub async fn list_skills(
    pool: impl sqlx::SqliteExecutor<'_>,
    company_id: CompanyId,
) -> Result<Vec<Skill>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        skill_columns!(),
        " FROM skills WHERE company_id = ? ORDER BY name, version"
    ))
    .bind(company_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(skill)
    .collect()
}

/// Test-only, like `create_skill`: a published version is never edited. Updates everything
/// but the company.
#[cfg(test)]
pub(crate) async fn update_skill(pool: &SqlitePool, s: &Skill) -> Result<bool, Error> {
    let (scope, department, role, project) = attach_columns(&s.attach);
    sqlx::query(
        "UPDATE skills SET name = ?, version = ?, body = ?, attach_scope = ?, \
         department_id = ?, role = ?, project_id = ? WHERE id = ?",
    )
    .bind(&s.name)
    .bind(s.version)
    .bind(&s.body)
    .bind(scope)
    .bind(department)
    .bind(role)
    .bind(project)
    .bind(s.id.0)
    .execute(pool)
    .await
    .map(affected)
}

pub async fn delete_skill(pool: &SqlitePool, id: SkillId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM skills WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

// --- knowledge entries ------------------------------------------------------

macro_rules! knowledge_columns {
    () => {
        "id, project_id, kind, title, body, status, proposed_by_agent_id, decided_by_user_id, \
         decided_by_agent_id, reason, target, rationale, retired_reason, supersedes_id"
    };
}

fn knowledge_entry(row: SqliteRow) -> Result<KnowledgeEntry, Error> {
    Ok(KnowledgeEntry {
        id: KnowledgeEntryId(row.try_get("id")?),
        project_id: ProjectId(row.try_get("project_id")?),
        kind: text(&row, "kind")?,
        title: row.try_get("title")?,
        body: row.try_get("body")?,
        status: text(&row, "status")?,
        proposed_by: id_column(&row, "proposed_by_agent_id")?.map(AgentId),
        decided_by: id_column(&row, "decided_by_user_id")?.map(UserId),
        decided_by_agent: id_column(&row, "decided_by_agent_id")?.map(AgentId),
        reason: row.try_get("reason")?,
        targets_spec: row.try_get::<Option<String>, _>("target")?.as_deref() == Some("spec"),
        profile_field: row
            .try_get::<Option<String>, _>("target")?
            .and_then(|t| t.strip_prefix("profile.").map(str::to_owned)),
        rationale: row.try_get("rationale")?,
        retired_reason: row.try_get("retired_reason")?,
        supersedes: id_column(&row, "supersedes_id")?.map(KnowledgeEntryId),
    })
}

pub async fn create_knowledge_entry(
    pool: &SqlitePool,
    k: &NewKnowledgeEntry,
) -> Result<KnowledgeEntry, Error> {
    sqlx::query(concat!(
        "INSERT INTO knowledge_entries (project_id, kind, title, body, status, \
         proposed_by_agent_id, decided_by_user_id) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING ",
        knowledge_columns!()
    ))
    .bind(k.project_id.0)
    .bind(k.kind.as_str())
    .bind(&k.title)
    .bind(&k.body)
    .bind(k.status.as_str())
    .bind(k.proposed_by.map(|a| a.0))
    .bind(k.decided_by.map(|u| u.0))
    .fetch_one(pool)
    .await
    .and_then(knowledge_entry)
}

pub async fn get_knowledge_entry(
    pool: &SqlitePool,
    id: KnowledgeEntryId,
) -> Result<Option<KnowledgeEntry>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        knowledge_columns!(),
        " FROM knowledge_entries WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(knowledge_entry)
    .transpose()
}

/// The project's entries, oldest first.
pub async fn list_knowledge_entries(
    pool: &SqlitePool,
    project_id: ProjectId,
) -> Result<Vec<KnowledgeEntry>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        knowledge_columns!(),
        " FROM knowledge_entries WHERE project_id = ? ORDER BY id"
    ))
    .bind(project_id.0)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(knowledge_entry)
    .collect()
}

/// Updates kind, text, status and decider; the project and proposer are fixed.
pub async fn update_knowledge_entry(pool: &SqlitePool, k: &KnowledgeEntry) -> Result<bool, Error> {
    sqlx::query(
        "UPDATE knowledge_entries SET kind = ?, title = ?, body = ?, status = ?, \
         decided_by_user_id = ? WHERE id = ?",
    )
    .bind(k.kind.as_str())
    .bind(&k.title)
    .bind(&k.body)
    .bind(k.status.as_str())
    .bind(k.decided_by.map(|u| u.0))
    .bind(k.id.0)
    .execute(pool)
    .await
    .map(affected)
}

pub async fn delete_knowledge_entry(
    pool: &SqlitePool,
    id: KnowledgeEntryId,
) -> Result<bool, Error> {
    sqlx::query("DELETE FROM knowledge_entries WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}

mod knowledge;
pub use knowledge::*;

// --- device keys ------------------------------------------------------------

macro_rules! device_key_columns {
    () => {
        "id, name, created_at, last_used_at, revoked_at"
    };
}

fn device_key(row: SqliteRow) -> Result<DeviceKey, Error> {
    Ok(DeviceKey {
        id: DeviceKeyId(row.try_get("id")?),
        name: row.try_get("name")?,
        created_at: row.try_get("created_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
    })
}

/// Stores only the SHA-256 of `key`.
pub async fn create_device_key(
    pool: &SqlitePool,
    name: &str,
    key: &str,
) -> Result<DeviceKey, Error> {
    sqlx::query(concat!(
        "INSERT INTO device_keys (name, key_hash) VALUES (?, ?) RETURNING ",
        device_key_columns!()
    ))
    .bind(name)
    .bind(key_hash(key))
    .fetch_one(pool)
    .await
    .and_then(device_key)
}

pub async fn get_device_key(
    pool: &SqlitePool,
    id: DeviceKeyId,
) -> Result<Option<DeviceKey>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        device_key_columns!(),
        " FROM device_keys WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(device_key)
    .transpose()
}

/// The device key matching `key`, revoked or not; the caller checks `revoked_at`.
pub async fn get_device_key_by_key(
    pool: &SqlitePool,
    key: &str,
) -> Result<Option<DeviceKey>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        device_key_columns!(),
        " FROM device_keys WHERE key_hash = ?"
    ))
    .bind(key_hash(key))
    .fetch_optional(pool)
    .await?
    .map(device_key)
    .transpose()
}

pub async fn list_device_keys(pool: &SqlitePool) -> Result<Vec<DeviceKey>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        device_key_columns!(),
        " FROM device_keys ORDER BY id"
    ))
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(device_key)
    .collect()
}

/// Renames, marks use, or revokes; the key itself never changes.
pub async fn update_device_key(pool: &SqlitePool, d: &DeviceKey) -> Result<bool, Error> {
    sqlx::query("UPDATE device_keys SET name = ?, last_used_at = ?, revoked_at = ? WHERE id = ?")
        .bind(&d.name)
        .bind(&d.last_used_at)
        .bind(&d.revoked_at)
        .bind(d.id.0)
        .execute(pool)
        .await
        .map(affected)
}

pub async fn delete_device_key(pool: &SqlitePool, id: DeviceKeyId) -> Result<bool, Error> {
    sqlx::query("DELETE FROM device_keys WHERE id = ?")
        .bind(id.0)
        .execute(pool)
        .await
        .map(affected)
}
