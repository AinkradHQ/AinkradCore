//! Agent avatars (decision #61): an agent is an animated figure the client draws, never a
//! letter. The server keeps only how it looks, and what it is doing:
//!
//! - Its appearance: the figure's version (`FIGURE_VERSIONS`) and one of the named palettes
//!   (`avatar_palettes`; the colours live in the client). A new agent is given one by
//!   `palette_pick!` (stable, spread evenly within its company); the admin may change it
//!   (`agent.appearance_set`).
//! - An optional uploaded image, shown instead of the figure: stored content-addressed with the
//!   artifacts (`artifacts::store_blob`). It must be a PNG, JPEG or WebP by its first bytes
//!   (never SVG, never HTML) and at most `avatar.max_bytes` (`agent.avatar_set`); removing it
//!   (`agent.avatar_reset`) brings the figure back.
//! - Its activity (`activity`), which the client API maps to the figure's state.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use citadel_core::audit::AuditActor;
use citadel_core::org::{Agent, AgentId, CompanyId};
use citadel_core::settings::{Key, Scope};
use serde_json::{Value, json};
use sqlx::Error;
use sqlx::sqlite::SqlitePool;

use super::agent;
use super::service::append_org_event;
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
    /// No such project (a project logo).
    NoProject(citadel_core::work::ProjectId),
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
    sqlx::query_as("SELECT id, name FROM avatar_palettes ORDER BY position")
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
    let mut tx = crate::store::begin_write(pool).await?;
    let a = sqlx::query(concat!(
        "UPDATE agents SET palette_id = coalesce(?1, palette_id), \
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
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM avatar_palettes WHERE id = ?)")
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

/// The largest upload the agent's company takes (`avatar.max_bytes`).
pub async fn max_bytes(pool: &SqlitePool, agent: AgentId) -> Result<u64, AvatarError> {
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM agents WHERE id = ?")
        .bind(agent.0)
        .fetch_optional(pool)
        .await?
        .ok_or(AvatarError::NoAgent(agent))?;
    let at = Scope::Company(CompanyId(company));
    Ok(crate::store::settings::value(pool, Key::AvatarMaxBytes, at).await? as u64)
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

/// An avatar image to serve.
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
    let sha: Option<String> = sqlx::query_scalar("SELECT avatar_sha256 FROM agents WHERE id = ?")
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
    /// Its live run's state: `queued`, `claimed` or `running`.
    pub live: Option<String>,
    /// Its running run has produced its first token.
    pub speaking: bool,
    /// Its last ended run failed (failed, timed out, runner lost, or stalled).
    pub failed: bool,
    /// Its last ended run succeeded within `SUCCESS_SECS` of now.
    pub succeeded: bool,
}

/// How long a success shows.
pub const SUCCESS_SECS: i64 = 300;

/// An agent's id, whether it waits on a human, its live run's state and whether it has spoken,
/// its last ended run's state and reason, and whether that ended recently.
type ActivityRow = (
    i64,
    bool,
    Option<String>,
    Option<bool>,
    Option<String>,
    Option<String>,
    bool,
);

/// The activity of the agents of `company`, or of `agent` alone, at `now`.
pub async fn activity(
    pool: &SqlitePool,
    company: Option<CompanyId>,
    agent: Option<AgentId>,
    now: &str,
) -> Result<HashMap<AgentId, Activity>, Error> {
    let rows: Vec<ActivityRow> =
        sqlx::query_as(
            "SELECT a.id, \
             EXISTS (SELECT 1 FROM questions q WHERE q.agent_id = a.id AND q.state = 'open') \
             OR EXISTS (SELECT 1 FROM approvals p WHERE p.requested_by_agent_id = a.id \
                 AND p.status = 'pending'), \
             l.state, l.first_token_at IS NOT NULL, e.state, e.terminal_reason, \
             coalesce(e.ended_at >= strftime('%Y-%m-%dT%H:%M:%fZ', ?3, '-' || ?4 || ' seconds'), 0) \
             FROM agents a \
             LEFT JOIN runs l ON l.id = (SELECT max(id) FROM runs WHERE agent_id = a.id \
                 AND state IN ('queued', 'claimed', 'running')) \
             LEFT JOIN runs e ON e.id = (SELECT max(id) FROM runs WHERE agent_id = a.id \
                 AND ended_at IS NOT NULL) \
             WHERE (?1 IS NULL OR a.company_id = ?1) AND (?2 IS NULL OR a.id = ?2)",
        )
        .bind(company.map(|c| c.0))
        .bind(agent.map(|a| a.0))
        .bind(now)
        .bind(SUCCESS_SECS)
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(id, waiting, live, speaking, last, reason, recent)| {
            let last = last.as_deref();
            let failed = matches!(last, Some("failed" | "timed_out" | "runner_lost"))
                || reason.as_deref() == Some("stalled");
            let activity = Activity {
                waiting,
                live,
                speaking: speaking.unwrap_or(false),
                failed,
                succeeded: last == Some("succeeded") && recent,
            };
            (AgentId(id), activity)
        })
        .collect())
}
