//! `POST /api/v1/agent-sessions/{id}/attachments` (E4): a file for the session's next messages,
//! kept with the session in the Core (`store::attachments`) and written into the session's folder
//! on its runner when a message names it (`agents::attach`).

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use super::{BY, not_a_modules, one, owns_secrets, parse};
use crate::api::App;
use crate::api::v1::{ApiError, ApiResult, Caller};
use crate::store::agents as sessions;
use crate::store::attachments::{self as store, NewAttachment};
use ainkrad_proto::v2::{MAX_ATTACHMENT_BYTES, valid_attachment_name};

/// The largest upload body: a whole [`MAX_ATTACHMENT_BYTES`] file in base64, its name and JSON.
pub const UPLOAD_BODY: usize = 14 * 1024 * 1024;

/// The most attachments one message names.
pub const MAX_PER_MESSAGE: usize = 16;

#[derive(Deserialize, ToSchema)]
pub struct NewAgentAttachment {
    /// The file's name as the user knows it: 1 to 255 bytes, no `/`, `\` or control character,
    /// not `.` or `..`. The runner writes it as `<id>-<name>` with anything outside
    /// `[A-Za-z0-9._-]` made `_`.
    pub name: String,
    /// Its media type, as the client knows it (`image/png`); kept, never interpreted.
    pub content_type: Option<String>,
    /// The file, standard base64: 1 byte to 10 MiB once decoded.
    pub data: String,
}

#[derive(Serialize, ToSchema)]
pub struct AgentAttachment {
    /// `at_…`: name it in `sendAgentMessage`'s `attachments`.
    pub id: String,
    pub name: String,
    pub content_type: Option<String>,
    /// Bytes.
    pub size: u64,
    /// Hex SHA-256 of the file.
    pub sha256: String,
}

#[utoipa::path(post, path = "/api/v1/agent-sessions/{id}/attachments",
    operation_id = "addAgentAttachment", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    request_body = NewAgentAttachment,
    responses((status = 200, description = "Kept with the session (audited as \
        `agent.attachment_added`, its id and size only) until the session row goes or the session \
        has been over for 7 days. Name its id in `sendAgentMessage`'s `attachments`: the runner \
        then writes the file into the session's folder (`<folder>/.ainkrad/attachments/<id>-<name>`) \
        and the message ends with its path (`@<path>` for Claude Code). The caller needs the same \
        rights as for a message. 400 `bad_request` (not base64, empty, a bad `content_type`), \
        `bad_attachment_name`; 413 `attachment_too_large` (over 10 MiB), `attachments_full` (the \
        session's attachments would pass 100 MiB); 403 `forbidden_scope` (a session holding \
        secrets, not the caller's); 409 `module_owned`", body = AgentAttachment)))]
pub async fn add(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<AgentAttachment> {
    let s = one(&app, &me, &id).await?;
    not_a_modules(&s)?;
    owns_secrets(&s, &me)?;
    let b: NewAgentAttachment = parse(&body)?;
    if !valid_attachment_name(&b.name) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_attachment_name",
            "a name is 1 to 255 bytes with no slash, backslash or control character, not . or ..",
        ));
    }
    if (b.content_type.as_ref())
        .is_some_and(|t| t.is_empty() || t.len() > 255 || t.chars().any(char::is_control))
    {
        return Err(ApiError::bad_request(
            "content_type is 1 to 255 plain characters",
        ));
    }
    // Refused before decoding: a long base64 is a large file.
    if b.data.len() > MAX_ATTACHMENT_BYTES.div_ceil(3) * 4 {
        return Err(too_large());
    }
    let data = base64::engine::general_purpose::STANDARD
        .decode(&b.data)
        .map_err(|_| ApiError::bad_request("data is not standard base64"))?;
    if data.is_empty() {
        return Err(ApiError::bad_request("an attachment is at least one byte"));
    }
    if data.len() > MAX_ATTACHMENT_BYTES {
        return Err(too_large());
    }
    let sha256: String = Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let at = crate::auth::crypto::random_id("at_");
    let new = NewAttachment {
        id: &at,
        session: &s.id,
        name: &b.name,
        content_type: b.content_type.as_deref(),
        sha256: &sha256,
        data: &data,
        created_by: &me.device.id,
    };
    if !store::add(&app.pool, &new, &app.clock.now()).await? {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "attachments_full",
            "the session's attachments would pass 100 MiB",
        ));
    }
    let details = json!({"attachment": at, "bytes": data.len()});
    let action = "agent.attachment_added";
    sessions::action(&app.pool, &s, BY, action, None, details, &me.device.id).await?;
    Ok(Json(AgentAttachment {
        id: at,
        name: b.name,
        content_type: b.content_type,
        size: data.len() as u64,
        sha256,
    }))
}

fn too_large() -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "attachment_too_large",
        "an attachment is at most 10 MiB",
    )
}

/// The attachments a message names, checked: `at_…` ids, at most [`MAX_PER_MESSAGE`], each once,
/// every one held by session `session` (400 `unknown_attachment` otherwise: another session's
/// is no such attachment).
pub(super) async fn named(
    app: &App,
    session: &str,
    ids: Option<Vec<String>>,
) -> Result<Vec<String>, ApiError> {
    let mut ids = ids.unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    ids.retain(|id| seen.insert(id.clone()));
    if ids.len() > MAX_PER_MESSAGE {
        return Err(ApiError::bad_request(
            "a message names at most 16 attachments",
        ));
    }
    let bad = || {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "unknown_attachment",
            "the session has no such attachment",
        )
    };
    if !ids
        .iter()
        .all(|id| ainkrad_proto::v2::valid_attachment_id(id))
    {
        return Err(bad());
    }
    if !store::missing(&app.pool, session, &ids).await?.is_empty() {
        return Err(bad());
    }
    Ok(ids)
}
