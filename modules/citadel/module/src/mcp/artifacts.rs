//! `publish_artifact` and `get_artifact` (E15.12): an agent publishes a report or file of its
//! run, by content (standard base64), stored by the server on the run's issue and requirement
//! and listed in the requirement's thread. A refusal (name, type, size, the company's quota) is
//! recorded on the run with its reason and returned to the agent.
//!
//! Least privilege: the type allow-list, the per-file limit and the company's quota are the
//! store's (`check_artifact`), checked before the text is decoded; the name must be a plain file
//! name (no path); a run publishes at most `mcp.max_artifacts_per_run`; text is redacted of the
//! run token's shape on the way in; reads are limited to the run's own issue and requirement
//! of its own company. Publishing by a worktree path (the runner reads the file) is not ported:
//! the runner side of that handshake does not exist in the Core yet.

use ainkrad_proto::redact::Redactor;
use base64::Engine;
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{MAX_TITLE, Result, ToolError, clip, int, required, text};
use crate::domain::gov::ArtifactKind;
use crate::store::artifacts::{
    Artifact, ArtifactError, ArtifactFilter, NewArtifact, Preview, artifact_root, blob_path,
    check_artifact, get_artifact as read_stored, list_artifacts, preview_of,
    publish_artifact as publish, record_refusal,
};
use crate::store::exec::RunScope;
use crate::store::work::get_issue;
use ainkrad_core_server::api::App;

/// The longest base64 text taken: it must fit the route's body cap (256 KiB) with the rest of
/// the call.
const MAX_BASE64: usize = 240 * 1024;

/// Records the refusal on the run and turns it into the agent's answer.
async fn refuse(app: &App, new: &NewArtifact, why: String) -> ToolError {
    if let Err(e) = record_refusal(&app.pool, new, &why).await {
        tracing::error!(error = %e, "recording an artifact refusal failed");
    }
    ToolError::Refused(why)
}

fn stored(e: ArtifactError) -> std::result::Result<String, ToolError> {
    match e {
        ArtifactError::Db(e) => Err(e.into()),
        ArtifactError::Io(detail) => Err(ToolError::Failed(detail)),
        e => Ok(e.to_string()),
    }
}

pub(super) async fn publish_artifact(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
) -> Result<Value> {
    if args.contains_key("path") {
        return Err(ToolError::Invalid(
            "publishing by path is not available; give content (standard base64)".to_owned(),
        ));
    }
    let name = required(args, "name", MAX_TITLE)?.trim().to_owned();
    let kind = match text(args, "kind", 20)? {
        None => ArtifactKind::File,
        Some(k) => k.parse().map_err(|_| {
            ToolError::Invalid("kind is report, file, screenshot or other".to_owned())
        })?,
    };
    let issue = match scope.issue_id {
        Some(i) => get_issue(&app.pool, i).await?,
        None => None,
    };
    let new = NewArtifact {
        company: scope.company_id,
        issue: issue.as_ref().map(|i| i.id),
        requirement: issue.as_ref().and_then(|i| i.requirement_id),
        run: Some(scope.run_id),
        agent: Some(scope.agent_id),
        name,
        kind,
        user: None,
    };
    let max = crate::settings::value(&app.pool, "mcp.max_artifacts_per_run").await?;
    let published: i64 =
        sqlx::query_scalar("SELECT count(*) FROM citadel_artifacts WHERE run_id = ?")
            .bind(scope.run_id.0)
            .fetch_one(&app.pool)
            .await?;
    if published >= max {
        return Err(ToolError::Refused(format!(
            "this run has published its {max} artifacts (mcp.max_artifacts_per_run)"
        )));
    }
    let b64 = required(args, "content", MAX_BASE64)?;
    // Checked before decoding: what the text decodes to, at most.
    if let Err(e) = check_artifact(&app.pool, &new, (b64.len() / 4 * 3) as u64).await {
        let why = stored(e)?;
        return Err(refuse(app, &new, why).await);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| ToolError::Invalid("content is not standard base64".to_owned()))?;
    let root = artifact_root(&app.pool).await?;
    match publish(&app.pool, &root, &new, &bytes, &Redactor::new()).await {
        Ok(a) => Ok(
            json!({"artifact_id": a.id.0, "name": a.name, "kind": a.kind.as_str(),
                           "mime": a.mime, "size": a.size, "sha256": a.sha256,
                           "redactions": a.redactions, "unscanned": a.unscanned,
                           "requirement_id": a.requirement_id.map(|r| r.0)}),
        ),
        Err(e) => {
            let why = stored(e)?;
            Err(refuse(app, &new, why).await)
        }
    }
}

/// The most of an artifact's text returned.
const MAX_TEXT_READ: usize = 64 * 1024;
/// The most artifacts one listing returns.
const MAX_LISTED: u32 = 50;

fn meta(a: &Artifact) -> Value {
    json!({"artifact_id": a.id.0, "name": a.name, "kind": a.kind.as_str(), "mime": a.mime,
           "size": a.size, "sha256": a.sha256, "issue_id": a.issue_id.map(|i| i.0),
           "agent_id": a.agent_id.map(|i| i.0), "created_at": a.created_at})
}

/// `get_artifact {artifact_id?}`: an artifact published on the run's requirement (or issue): its
/// metadata and, for text, its content (capped). Without `artifact_id`, the requirement's
/// artifacts, newest first. Another requirement's or company's look like none.
pub(super) async fn get_artifact(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let own = match scope.issue_id {
        Some(i) => get_issue(&app.pool, i).await?,
        None => None,
    }
    .ok_or_else(|| ToolError::Refused("this run has no issue".to_owned()))?;
    let Some(id) = int(args, "artifact_id")? else {
        let f = ArtifactFilter {
            company: Some(scope.company_id),
            requirement: own.requirement_id,
            issue: own.requirement_id.is_none().then_some(own.id),
            ..Default::default()
        };
        let all = list_artifacts(&app.pool, &f, None, MAX_LISTED).await?;
        return Ok(json!({"artifacts": all.iter().map(meta).collect::<Vec<_>>()}));
    };
    let none = || ToolError::Refused(format!("no artifact {id} on your requirement"));
    let a = read_stored(&app.pool, crate::domain::gov::ArtifactId(id))
        .await?
        .filter(|a| {
            a.company_id == scope.company_id
                && (a.issue_id == Some(own.id)
                    || (own.requirement_id.is_some() && a.requirement_id == own.requirement_id))
        })
        .ok_or_else(none)?;
    let mut v = meta(&a);
    v["content"] = Value::Null;
    v["truncated"] = false.into();
    if preview_of(&a.mime) == Preview::Text {
        let bytes = std::fs::read(blob_path(&artifact_root(&app.pool).await?, &a.sha256))
            .map_err(|e| ToolError::Failed(e.to_string()))?;
        let (body, cut) = clip(&String::from_utf8_lossy(&bytes), MAX_TEXT_READ);
        v["content"] = body.into();
        v["truncated"] = cut.into();
    }
    Ok(v)
}
