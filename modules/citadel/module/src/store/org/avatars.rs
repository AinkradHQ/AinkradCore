//! Agent avatars (decision #61): an agent is an animated figure the client draws, never a
//! letter. The server keeps only how it looks, and what it is doing:
//!
//! - Its appearance: the figure's version (`FIGURE_VERSIONS`) and one of the named palettes
//!   (`citadel_avatar_palettes`; the colours live in the client). A new agent is given one by
//!   `palette_pick!`; the admin may change it (`agent.appearance_set`).
//! - An optional uploaded image, shown instead of the figure; removing it
//!   (`agent.avatar_reset`) brings the figure back. NOT ported yet: storing and serving the
//!   image (`upload_avatar`, `avatar_image`) needs the content-addressed blob store of the
//!   artifacts slice (S5) and the Core's artifacts directory; `sniff` and `max_bytes` are here
//!   for it.
//! - Its activity (`activity`), which the client API maps to the figure's state. The run half
//!   of it (live run, first token, last run's end) needs the run engine (S7); until then only
//!   `waiting` is known.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::store::begin_write;
use serde_json::{Value, json};
use sqlx::{Error, SqlitePool};

use super::agent;
use super::chart::append_org_event;
use crate::domain::org::{Agent, AgentId, CompanyId};
use crate::store::artifacts::{blob_path, sha256_hex, store_blob};

/// The figure versions the client draws.
pub const FIGURE_VERSIONS: &[&str] = &["v1"];

/// The image type of `bytes` by their first bytes: PNG, JPEG or WebP, else `None`.
pub fn sniff(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// Why an avatar change or read failed.
#[derive(Debug)]
pub enum AvatarError {
    NoAgent(AgentId),
    /// No such company (a company logo, which follows the same rules).
    NoCompany(CompanyId),
    /// No such project (a project logo, which follows the same rules).
    NoProject(crate::domain::work::ProjectId),
    UnknownPalette(String),
    UnknownFigure(String),
    /// Not a PNG, JPEG or WebP by its first bytes.
    NotAnImage,
    TooLarge {
        size: u64,
        max: u64,
    },
    /// The image could not be read or written; the detail is logged.
    Io(String),
    Db(Error),
}

impl From<Error> for AvatarError {
    fn from(e: Error) -> Self {
        Self::Db(e)
    }
}

impl fmt::Display for AvatarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAgent(a) => write!(f, "no agent {}", a.0),
            Self::NoCompany(c) => write!(f, "no company {}", c.0),
            Self::NoProject(p) => write!(f, "no project {}", p.0),
            Self::UnknownPalette(p) => write!(f, "no palette {p:?} (see the palette list)"),
            Self::UnknownFigure(v) => write!(
                f,
                "no figure version {v:?}; known: {}",
                FIGURE_VERSIONS.join(", ")
            ),
            Self::NotAnImage => {
                f.write_str("rejected: an avatar must be a PNG, JPEG or WebP image")
            }
            Self::TooLarge { size, max } => write!(
                f,
                "rejected: {size} bytes is over the {max}-byte avatar limit (avatar.max_bytes)"
            ),
            Self::Io(_) => f.write_str("the avatar image could not be read or stored"),
            Self::Db(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for AvatarError {}

/// The palettes, in the design's order: `(id, name)`.
pub async fn list_palettes(pool: &SqlitePool) -> Result<Vec<(String, String)>, Error> {
    sqlx::query_as("SELECT id, name FROM citadel_avatar_palettes ORDER BY position")
        .fetch_all(pool)
        .await
}

/// A change to an agent's look; a `None` field is left as it is.
#[derive(Default)]
struct Change<'a> {
    palette: Option<&'a str>,
    figure_version: Option<&'a str>,
    /// `Some(None)` removes the image.
    image: Option<Option<&'a str>>,
}

/// Applies `c` to the agent, audited as `action`.
async fn change(
    pool: &SqlitePool,
    id: AgentId,
    c: Change<'_>,
    (action, details): (&str, Value),
    by: AuditActor,
) -> Result<Agent, AvatarError> {
    let mut tx = begin_write(pool).await?;
    let a = sqlx::query(concat!(
        "UPDATE citadel_agents SET palette_id = coalesce(?1, palette_id), \
         figure_version = coalesce(?2, figure_version), \
         avatar_sha256 = CASE WHEN ?3 THEN ?4 ELSE avatar_sha256 END WHERE id = ?5 RETURNING ",
        agent_columns!()
    ))
    .bind(c.palette)
    .bind(c.figure_version)
    .bind(c.image.is_some())
    .bind(c.image.flatten())
    .bind(id.0)
    .fetch_optional(&mut *tx)
    .await?
    .map(agent)
    .transpose()?
    .ok_or(AvatarError::NoAgent(id))?;
    append_org_event(&mut tx, a.company_id, by, action, ("agent", id.0), details).await?;
    tx.commit().await?;
    Ok(a)
}

/// Gives the agent `palette`, and `figure_version` when given.
pub async fn set_appearance(
    pool: &SqlitePool,
    agent: AgentId,
    palette: &str,
    figure_version: Option<&str>,
    by: AuditActor,
) -> Result<Agent, AvatarError> {
    if let Some(v) = figure_version.filter(|v| !FIGURE_VERSIONS.contains(v)) {
        return Err(AvatarError::UnknownFigure(v.to_owned()));
    }
    let known: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM citadel_avatar_palettes WHERE id = ?)")
            .bind(palette)
            .fetch_one(pool)
            .await?;
    if !known {
        return Err(AvatarError::UnknownPalette(palette.to_owned()));
    }
    let details = json!({"palette_id": palette, "figure_version": figure_version});
    let c = Change {
        palette: Some(palette),
        figure_version,
        ..Change::default()
    };
    change(pool, agent, c, ("agent.appearance_set", details), by).await
}

/// The largest upload the agent's company takes (`avatar.max_bytes`, server-wide).
pub async fn max_bytes(pool: &SqlitePool, agent: AgentId) -> Result<u64, AvatarError> {
    sqlx::query_scalar::<_, i64>("SELECT company_id FROM citadel_agents WHERE id = ?")
        .bind(agent.0)
        .fetch_optional(pool)
        .await?
        .ok_or(AvatarError::NoAgent(agent))?;
    // ponytail: server-wide until the Core settings store has company/project scopes
    Ok(crate::settings::value(pool, "avatar.max_bytes").await? as u64)
}

/// Gives the agent `bytes` as its avatar image, stored under `root` (the artifacts dir); see
/// the module docs for what is refused.
pub async fn upload_avatar(
    pool: &SqlitePool,
    root: &Path,
    agent: AgentId,
    bytes: &[u8],
    by: AuditActor,
) -> Result<Agent, AvatarError> {
    let (size, max) = (bytes.len() as u64, max_bytes(pool, agent).await?);
    if size > max {
        return Err(AvatarError::TooLarge { size, max });
    }
    let mime = sniff(bytes).ok_or(AvatarError::NotAnImage)?;
    let sha = sha256_hex(bytes);
    store_blob(root, &sha, bytes).map_err(|e| {
        tracing::error!(error = %e, "storing an avatar failed");
        AvatarError::Io(e)
    })?;
    let details = json!({"mime": mime, "size": size, "sha256": sha});
    let c = Change {
        image: Some(Some(&sha)),
        ..Change::default()
    };
    change(pool, agent, c, ("agent.avatar_set", details), by).await
}

/// Removes the agent's avatar image: its figure is shown again.
pub async fn reset_avatar(
    pool: &SqlitePool,
    agent: AgentId,
    by: AuditActor,
) -> Result<Agent, AvatarError> {
    let c = Change {
        image: Some(None),
        ..Change::default()
    };
    change(pool, agent, c, ("agent.avatar_reset", json!({})), by).await
}

/// An avatar image to serve (for the upload slice).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    pub mime: &'static str,
    pub sha256: String,
    pub bytes: Vec<u8>,
}

/// The agent's uploaded image (from `root`); `None` when it has none.
pub async fn avatar_image(
    pool: &SqlitePool,
    root: &Path,
    agent: AgentId,
) -> Result<Option<Image>, AvatarError> {
    let sha: Option<String> =
        sqlx::query_scalar("SELECT avatar_sha256 FROM citadel_agents WHERE id = ?")
            .bind(agent.0)
            .fetch_optional(pool)
            .await?
            .ok_or(AvatarError::NoAgent(agent))?;
    let Some(sha256) = sha else {
        return Ok(None);
    };
    let path = blob_path(root, &sha256);
    let bytes = tokio::fs::read(&path).await.map_err(|e| {
        tracing::error!(path = %path.display(), error = %e, "reading an avatar failed");
        AvatarError::Io(e.to_string())
    })?;
    let mime = sniff(&bytes).ok_or(AvatarError::NotAnImage)?;
    Ok(Some(Image {
        mime,
        sha256,
        bytes,
    }))
}

/// What an agent is doing, for its figure's state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Activity {
    /// It has an open question to the admin, or an approval it asked for is pending.
    pub waiting: bool,
    /// Its live run's state: `queued`, `claimed` or `running` (S7: always `None` for now).
    pub live: Option<String>,
    /// Its running run has produced its first token (S7).
    pub speaking: bool,
    /// Its last ended run failed (S7).
    pub failed: bool,
    /// Its last ended run succeeded within five minutes of now (S7).
    pub succeeded: bool,
}

/// The activity of the agents of `company`, or of `agent` alone: only `waiting`, which needs the
/// questions and approvals tables (the run half is the run engine's).
pub async fn activity(
    pool: &SqlitePool,
    company: Option<CompanyId>,
    agent: Option<AgentId>,
) -> Result<HashMap<AgentId, Activity>, Error> {
    let rows: Vec<(i64, bool)> = sqlx::query_as(
        "SELECT a.id, \
         EXISTS (SELECT 1 FROM citadel_questions q WHERE q.agent_id = a.id AND q.state = 'open') \
         OR EXISTS (SELECT 1 FROM citadel_approvals p WHERE p.requested_by_agent_id = a.id \
             AND p.status = 'pending') \
         FROM citadel_agents a WHERE (?1 IS NULL OR a.company_id = ?1) \
         AND (?2 IS NULL OR a.id = ?2)",
    )
    .bind(company.map(|c| c.0))
    .bind(agent.map(|a| a.0))
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, waiting)| {
            let activity = Activity {
                waiting,
                ..Activity::default()
            };
            (AgentId(id), activity)
        })
        .collect())
}
