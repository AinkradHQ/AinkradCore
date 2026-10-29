//! `publish_artifact` (E15.12, pain #13): an agent publishes a report, file or screenshot of its
//! run, by content (base64) or by a path in its worktree, which its runner reads. It is stored
//! by the server on the run's issue and requirement, listed in the requirement's thread and the
//! artifacts screen. A refusal (name, type, size, the company's quota) is recorded on the run
//! with its reason (decision #47) and returned to the agent.

use std::time::Duration;

use citadel_core::auth::RunScope;
use citadel_core::gov::ArtifactKind;
use ainkrad_proto::redact::Redactor;
use base64::Engine;
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{MAX_TITLE, Result, ToolError, clip, int, required, text};
use crate::api::App;
use crate::store::artifacts::{
    Artifact, ArtifactError, ArtifactFilter, NewArtifact, Preview, blob_path, check_artifact,
    get_artifact as read_stored, incoming_path, list_artifacts, preview_of,
    publish_artifact as publish, read_outcome, record_refusal, request_read, worktree_path_ok,
};
use crate::store::work::get_issue;

/// How long a publish by path waits for the runner to read the file.
const READ_WAIT: Duration = Duration::from_secs(60);
/// The longest base64 text taken: 12 MB of file (`artifact.max_file_bytes`'s bound).
const MAX_BASE64: usize = 16 * 1024 * 1024;

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

/// The bytes of `path` in the run's worktree, read by its runner, or why not.
async fn read_path(
    app: &App,
    scope: RunScope,
    path: &str,
    max: u64,
) -> std::result::Result<Vec<u8>, String> {
    if !worktree_path_ok(path) {
        return Err(format!(
            "rejected: {path:?} is not a plain relative path inside your worktree"
        ));
    }
    let read = request_read(&app.pool, scope.run_id, path, max)
        .await
        .map_err(|e| e.to_string())?;
    let deadline = tokio::time::Instant::now() + READ_WAIT;
    loop {
        let (state, error) = read_outcome(&app.pool, read)
            .await
            .map_err(|e| e.to_string())?;
        match state.as_str() {
            "done" => {
                let file = incoming_path(&app.artifacts, read);
                let bytes = std::fs::read(&file).map_err(|e| e.to_string());
                let _ = std::fs::remove_file(&file);
                return bytes;
            }
            "failed" => return Err(format!("rejected: {}", error.unwrap_or_default())),
            _ if tokio::time::Instant::now() >= deadline => {
                let why = "the runner did not read the file in 60 s".to_owned();
                let _ =
                    crate::store::artifacts::finish_read(&app.pool, read, Err(why.clone())).await;
                return Err(why);
            }
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

pub(super) async fn publish_artifact(
    app: &App,
    scope: RunScope,
    secrets: &Redactor,
    args: &JsonObject,
) -> Result<Value> {
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
    let content = text(args, "content", MAX_BASE64)?;
    let path = text(args, "path", 1024)?;
    let bytes = match (content, path) {
        (Some(b64), None) => {
            // Checked before decoding: what the text decodes to, at most.
            if let Err(e) = check_artifact(&app.pool, &new, (b64.len() / 4 * 3) as u64).await {
                let why = stored(e)?;
                return Err(refuse(app, &new, why).await);
            }
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|_| ToolError::Invalid("content is not standard base64".to_owned()))?
        }
        (None, Some(path)) => {
            let max = match check_artifact(&app.pool, &new, 0).await {
                Ok(_) => {
                    crate::store::artifacts::artifact_usage(&app.pool, new.company)
                        .await?
                        .2
                }
                Err(e) => {
                    let why = stored(e)?;
                    return Err(refuse(app, &new, why).await);
                }
            };
            match read_path(app, scope, path, max).await {
                Ok(bytes) => bytes,
                Err(why) => return Err(refuse(app, &new, why).await),
            }
        }
        _ => {
            return Err(ToolError::Invalid(
                "give content (base64) or path (in your worktree), one of them".to_owned(),
            ));
        }
    };
    match publish(&app.pool, &app.artifacts, &new, &bytes, secrets).await {
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
    let a = read_stored(&app.pool, citadel_core::gov::ArtifactId(id))
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
        let bytes = std::fs::read(blob_path(&app.artifacts, &a.sha256))
            .map_err(|e| ToolError::Failed(e.to_string()))?;
        let (body, cut) = clip(&String::from_utf8_lossy(&bytes), MAX_TEXT_READ);
        v["content"] = body.into();
        v["truncated"] = cut.into();
    }
    Ok(v)
}
