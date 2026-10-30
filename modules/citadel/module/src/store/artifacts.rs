//! Artifacts (E15.12, pain #13): what agents publish (reports, files, screenshots), stored by
//! the server and listed on their issue and requirement, so nobody opens an agent's
//! conversation to find them.
//!
//! - Content-addressed: a file is `blobs/<sha256[0..2]>/<sha256>` under the artifacts dir,
//!   written once however often it is published; each publish is a row saying where it came
//!   from.
//! - Refused, with the reason audited on the run (`artifact.refused`, decision #47): a name that
//!   is not a plain file name, a type outside the allowlist (`mime_of`), a file over
//!   `artifact.max_file_bytes`, or one that would take its company past
//!   `artifact.company_quota_bytes` (each distinct blob counted once per company).
//! - Served with its type, always as an attachment, never sniffed or run; only text and raster
//!   images are previewed (the serving routes need the Core to give the module an artifacts
//!   dir: not built yet).
//! - Redacted (E15.18): a text artifact (`ainkrad_proto::redact::is_text`) has every known
//!   secret of its run and every key shape replaced before it is checked, hashed and stored,
//!   so no secret reaches the blob or the database; the number of markers it holds is
//!   `redactions`. Any other type is stored as it is and marked `unscanned`.
//!
//! A publish by path is read by the run's runner from its worktree (`reads`). The Core's audit
//! actor is a user or the system: an agent's publish is audited as the system with `agent_id`
//! in the details.

use std::fmt;
use std::path::{Path, PathBuf};

use ainkrad_core::audit::AuditActor;
use ainkrad_proto::redact::Redactor;
use serde_json::json;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::{Error, Row};

use crate::domain::gov::{ArtifactId, ArtifactKind};
use crate::domain::org::{AgentId, CompanyId};
use crate::domain::work::{IssueId, RequirementId, RunId, UserId};
use crate::store::audit::{Event, append};
use crate::store::org::text;

mod reads;
pub use reads::*;

/// The types an artifact may have, by file extension; anything else is refused.
const TYPES: &[(&str, &str)] = &[
    ("md", "text/markdown"),
    ("markdown", "text/markdown"),
    ("txt", "text/plain"),
    ("log", "text/plain"),
    ("csv", "text/csv"),
    ("json", "application/json"),
    ("yaml", "application/yaml"),
    ("yml", "application/yaml"),
    ("diff", "text/x-diff"),
    ("patch", "text/x-diff"),
    ("html", "text/html"),
    ("htm", "text/html"),
    ("svg", "image/svg+xml"),
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("gif", "image/gif"),
    ("webp", "image/webp"),
    ("pdf", "application/pdf"),
    ("zip", "application/zip"),
];

/// The type of a file called `name`, by its extension; `None`: not allowed.
pub fn mime_of(name: &str) -> Option<&'static str> {
    let (_, ext) = name.rsplit_once('.')?;
    let ext = ext.to_ascii_lowercase();
    TYPES.iter().find(|(e, _)| *e == ext).map(|(_, m)| *m)
}

/// How a type is previewed: as text, as an image, or not at all (HTML, SVG, PDF and archives
/// can carry script or are opaque: download them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preview {
    Text,
    Image,
    None,
}

pub fn preview_of(mime: &str) -> Preview {
    match mime {
        "text/markdown" | "text/plain" | "text/csv" | "application/json" | "application/yaml"
        | "text/x-diff" => Preview::Text,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp" => Preview::Image,
        _ => Preview::None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub id: ArtifactId,
    pub company_id: CompanyId,
    pub issue_id: Option<IssueId>,
    pub requirement_id: Option<RequirementId>,
    pub run_id: Option<RunId>,
    pub agent_id: Option<AgentId>,
    pub name: String,
    pub kind: ArtifactKind,
    pub mime: String,
    pub size: i64,
    pub sha256: String,
    /// Secrets redacted from its content (markers in the stored text).
    pub redactions: i64,
    /// Stored as it is, never scanned for secrets: not text.
    pub unscanned: bool,
    pub created_at: String,
}

macro_rules! artifact_columns {
    () => {
        "id, company_id, issue_id, requirement_id, run_id, agent_id, name, kind, mime, size, \
         sha256, redactions, unscanned, created_at"
    };
}

fn artifact(row: SqliteRow) -> Result<Artifact, Error> {
    let id = |c: &str| -> Result<Option<i64>, Error> { row.try_get(c) };
    Ok(Artifact {
        id: ArtifactId(row.try_get("id")?),
        company_id: CompanyId(row.try_get("company_id")?),
        issue_id: id("issue_id")?.map(IssueId),
        requirement_id: id("requirement_id")?.map(RequirementId),
        run_id: id("run_id")?.map(RunId),
        agent_id: id("agent_id")?.map(AgentId),
        name: row.try_get("name")?,
        kind: text(&row, "kind")?,
        mime: row.try_get("mime")?,
        size: row.try_get("size")?,
        sha256: row.try_get("sha256")?,
        redactions: row.try_get("redactions")?,
        unscanned: row.try_get("unscanned")?,
        created_at: row.try_get("created_at")?,
    })
}

/// A publish: where it comes from, and what it is called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewArtifact {
    pub company: CompanyId,
    pub issue: Option<IssueId>,
    pub requirement: Option<RequirementId>,
    pub run: Option<RunId>,
    pub agent: Option<AgentId>,
    pub name: String,
    pub kind: ArtifactKind,
    /// The person who uploaded it (a thread attachment), audited as them.
    pub user: Option<UserId>,
}

/// Why a publish was refused, in words for the agent and the run's audit.
#[derive(Debug)]
pub enum ArtifactError {
    /// Not a plain file name: empty, too long, a path, or a control character.
    BadName,
    /// Its type is not in the allowlist.
    TypeNotAllowed(String),
    TooLarge {
        size: u64,
        max: u64,
    },
    OverQuota {
        used: u64,
        size: u64,
        quota: u64,
    },
    /// The file could not be read or written; the detail is logged.
    Io(String),
    Db(Error),
}

impl From<Error> for ArtifactError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadName => f.write_str(
                "rejected: the name must be a plain file name (no path), up to 200 bytes",
            ),
            Self::TypeNotAllowed(name) => write!(
                f,
                "rejected: type not allowed ({name}); allowed: {}",
                TYPES.iter().map(|(e, _)| *e).collect::<Vec<_>>().join(", ")
            ),
            Self::TooLarge { size, max } => write!(
                f,
                "rejected: {size} bytes is over the {max}-byte limit per file \
                 (artifact.max_file_bytes)"
            ),
            Self::OverQuota { used, size, quota } => write!(
                f,
                "rejected: the company's artifact storage is full ({used} of {quota} bytes \
                 used; this file needs {size}; artifact.company_quota_bytes)"
            ),
            Self::Io(_) => f.write_str("the artifact could not be stored; try again later"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ArtifactError {}

/// Where a blob lives under `root`.
pub fn blob_path(root: &Path, sha256: &str) -> PathBuf {
    root.join("blobs").join(&sha256[..2]).join(sha256)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Writes `bytes` (whose SHA-256 is `sha`) as its blob under `root`, unless it is there
/// already; written to a part file and renamed, so a blob is never seen half-written.
pub(crate) fn store_blob(root: &Path, sha: &str, bytes: &[u8]) -> Result<(), String> {
    let path = blob_path(root, sha);
    if path.exists() {
        return Ok(());
    }
    let io = |e: std::io::Error| format!("{}: {e}", path.display());
    let dir = path.parent().expect("a blob has a dir");
    std::fs::create_dir_all(dir).map_err(io)?;
    let part = dir.join(format!("{sha}.{}.part", std::process::id()));
    std::fs::write(&part, bytes).map_err(io)?;
    std::fs::rename(&part, &path).map_err(io)
}

/// Checks a publish of `size` bytes before anything is read or stored: its name, its type, and
/// the per-file limit. Its type.
pub async fn check_artifact(
    pool: &SqlitePool,
    new: &NewArtifact,
    size: u64,
) -> Result<&'static str, ArtifactError> {
    let name = &new.name;
    let plain = !name.trim().is_empty()
        && name.len() <= 200
        && !name.contains(['/', '\\'])
        && !name.starts_with('.')
        && !name.chars().any(char::is_control);
    if !plain {
        return Err(ArtifactError::BadName);
    }
    let mime = mime_of(name).ok_or_else(|| ArtifactError::TypeNotAllowed(name.clone()))?;
    // ponytail: server-wide until the Core settings store has company scopes.
    let max = crate::settings::value(pool, "artifact.max_file_bytes").await? as u64;
    if size > max {
        return Err(ArtifactError::TooLarge { size, max });
    }
    Ok(mime)
}

/// The company's artifact storage (each distinct blob once), its quota, and its per-file limit.
pub async fn artifact_usage(
    pool: &SqlitePool,
    company: CompanyId,
) -> Result<(u64, u64, u64), Error> {
    let used: i64 = sqlx::query_scalar(
        "SELECT coalesce(sum(size), 0) FROM (SELECT max(size) AS size FROM citadel_artifacts \
         WHERE company_id = ? GROUP BY sha256)",
    )
    .bind(company.0)
    .fetch_one(pool)
    .await?;
    let quota = crate::settings::value(pool, "artifact.company_quota_bytes").await?;
    let max = crate::settings::value(pool, "artifact.max_file_bytes").await?;
    Ok((used as u64, quota as u64, max as u64))
}

/// The audit actor of `new`, and the agent to name in the details.
fn actor_of(new: &NewArtifact) -> (AuditActor, Option<i64>) {
    match (new.user, new.agent) {
        (Some(u), _) => (crate::store::gov::user_actor(u), None),
        (None, Some(a)) => (AuditActor::System, Some(a.0)),
        (None, None) => (AuditActor::System, None),
    }
}

/// Stores `bytes` as `new` under `root`, a text file redacted with `secrets` (the run's known
/// secrets) first; see the module docs. Audited `artifact.published`.
pub async fn publish_artifact(
    pool: &SqlitePool,
    root: &Path,
    new: &NewArtifact,
    bytes: &[u8],
    secrets: &Redactor,
) -> Result<Artifact, ArtifactError> {
    let (bytes, redactions) = secrets.file(&new.name, bytes.to_vec());
    let bytes = bytes.as_slice();
    let size = bytes.len() as u64;
    let mime = check_artifact(pool, new, size).await?;
    let sha = sha256_hex(bytes);
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let (seen, used): (bool, i64) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM citadel_artifacts WHERE company_id = ?1 AND sha256 = ?2), \
         (SELECT coalesce(sum(size), 0) FROM (SELECT max(size) AS size FROM citadel_artifacts \
             WHERE company_id = ?1 GROUP BY sha256))",
    )
    .bind(new.company.0)
    .bind(&sha)
    .fetch_one(&mut *tx)
    .await?;
    let quota =
        crate::store::gov::setting_in(&mut tx, "artifact.company_quota_bytes").await? as u64;
    if !seen && used as u64 + size > quota {
        let used = used as u64;
        return Err(ArtifactError::OverQuota { used, size, quota });
    }
    store_blob(root, &sha, bytes).map_err(ArtifactError::Io)?;
    let a = sqlx::query(concat!(
        "INSERT INTO citadel_artifacts (company_id, issue_id, requirement_id, run_id, agent_id, \
         name, kind, mime, size, sha256, redactions, unscanned) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING ",
        artifact_columns!()
    ))
    .bind(new.company.0)
    .bind(new.issue.map(|i| i.0))
    .bind(new.requirement.map(|r| r.0))
    .bind(new.run.map(|r| r.0))
    .bind(new.agent.map(|a| a.0))
    .bind(new.name.trim())
    .bind(new.kind.as_str())
    .bind(mime)
    .bind(size as i64)
    .bind(&sha)
    .bind(redactions.unwrap_or(0) as i64)
    .bind(redactions.is_none())
    .fetch_one(&mut *tx)
    .await
    .and_then(artifact)?;
    let details = json!({"name": a.name, "kind": a.kind.as_str(), "mime": mime, "size": size,
                         "sha256": sha, "issue": a.issue_id.map(|i| i.0),
                         "requirement": a.requirement_id.map(|r| r.0), "new_blob": !seen,
                         "redactions": a.redactions, "unscanned": a.unscanned});
    audit_in(
        &mut tx,
        new,
        "artifact.published",
        ("artifact", a.id.0),
        details,
    )
    .await?;
    tx.commit().await?;
    Ok(a)
}

async fn audit_in(
    conn: &mut sqlx::SqliteConnection,
    new: &NewArtifact,
    action: &str,
    (kind, id): (&str, i64),
    mut details: serde_json::Value,
) -> Result<(), Error> {
    let (actor, agent) = actor_of(new);
    if let (Some(agent), Some(d)) = (agent, details.as_object_mut()) {
        d.insert("agent_id".to_owned(), json!(agent));
    }
    let mut event = Event::new(actor, action)
        .entity(kind, id)
        .company(new.company.0)
        .details(details);
    if let Some(run) = new.run {
        event = event.run(run.0);
    }
    append(conn, event).await
}

/// Records why a publish was refused, on its run and issue (`artifact.refused`, #47).
pub async fn record_refusal(pool: &SqlitePool, new: &NewArtifact, why: &str) -> Result<(), Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let entity = match new.issue {
        Some(i) => ("issue", i.0),
        None => ("company", new.company.0),
    };
    let details = json!({"name": new.name, "kind": new.kind.as_str(), "reason": why});
    audit_in(&mut tx, new, "artifact.refused", entity, details).await?;
    tx.commit().await
}

pub async fn get_artifact(
    pool: impl sqlx::SqliteExecutor<'_>,
    id: ArtifactId,
) -> Result<Option<Artifact>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        artifact_columns!(),
        " FROM citadel_artifacts WHERE id = ?"
    ))
    .bind(id.0)
    .fetch_optional(pool)
    .await?
    .map(artifact)
    .transpose()
}

/// Narrows a listing; a `None` field matches every artifact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactFilter {
    pub company: Option<CompanyId>,
    pub requirement: Option<RequirementId>,
    pub issue: Option<IssueId>,
    pub agent: Option<AgentId>,
    pub kind: Option<ArtifactKind>,
}

/// Artifacts matching `f`, newest first, `limit` of them before id `before` (when given).
pub async fn list_artifacts(
    pool: impl sqlx::SqliteExecutor<'_>,
    f: &ArtifactFilter,
    before: Option<i64>,
    limit: u32,
) -> Result<Vec<Artifact>, Error> {
    sqlx::query(concat!(
        "SELECT ",
        artifact_columns!(),
        " FROM citadel_artifacts WHERE (?1 IS NULL OR company_id = ?1) \
         AND (?2 IS NULL OR requirement_id = ?2) AND (?3 IS NULL OR issue_id = ?3) \
         AND (?4 IS NULL OR agent_id = ?4) AND (?5 IS NULL OR kind = ?5) \
         AND (?6 IS NULL OR id < ?6) ORDER BY id DESC LIMIT ?7"
    ))
    .bind(f.company.map(|c| c.0))
    .bind(f.requirement.map(|r| r.0))
    .bind(f.issue.map(|i| i.0))
    .bind(f.agent.map(|a| a.0))
    .bind(f.kind.map(|k| k.as_str()))
    .bind(before)
    .bind(limit)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(artifact)
    .collect()
}

#[cfg(test)]
mod tests;
