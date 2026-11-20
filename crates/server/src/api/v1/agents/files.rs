//! A session's folder (E14): `GET /agent-sessions/{id}/files` lists one level, `POST .../files/revert`
//! puts one file back as it was before the session's edits, `POST .../files/write` writes one.
//! All three are runner ops on the folder the runner recorded for the session (`session_folder`),
//! never a path from the client: the Core cleans the path (`folder_relative`: no `..`, nothing
//! outside the folder) and the runner walks it again, refusing a symlink anywhere on the way.
//!
//! A revert is built from the session's own recorded edits (the transcript's `tool_use` entries
//! carry `edit {changes: [{path, old, new}]}`), which the runner reverse-applies, newest first. It
//! works with no git and undoes only what the session did. What the record cannot reverse (a cut
//! text, a removal inside a file) falls back to the file's git `HEAD` copy, read with plumbing so
//! no filter or hook runs.

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use serde_json::{Value, json};

use super::types::{
    AgentFileRevert, AgentFileWrite, AgentFolderEntry, AgentFolderListing, FolderQuery,
};
use super::{
    AgentSession, ApiError, ApiResult, BY, Caller, Session, not_a_modules, one, owns_secrets,
    parse, session_folder, shown, store,
};
use crate::agents;
use crate::api::App;
use crate::workspace::adopt;
use crate::workspace::fs::{Plan, Tree};
use crate::workspace::sync::SyncError;
use crate::workspace::watch::{self, WatchState};
use ainkrad_proto::v2::{
    AgentFiles, AgentRevert, AgentWrite, Body, Command, MAX_REVERT_BYTES, MAX_WRITE_BYTES,
    OP_AGENT_FILES, OP_AGENT_REVERT, OP_AGENT_WRITE, Reply, RevertEdit, RevertResult,
    folder_relative,
};
use std::path::PathBuf;
use std::sync::Arc;

fn unsupported(session_runner_old: &str) -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "unsupported_command",
        format!("the runner is too old to {session_runner_old}"),
    )
}

/// `path` cleaned and relative to `folder`: 400 `bad_path` for `..`, a control character or a path
/// outside the folder.
fn relative(folder: &str, path: &str) -> Result<String, ApiError> {
    folder_relative(folder, path).ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_path",
            "a path inside the session's folder, with no `..`",
        )
    })
}

/// Paths the Core never reads or writes for a client: anything under `.git`.
fn guarded(rel: &str) -> bool {
    rel.split('/').any(|p| p.eq_ignore_ascii_case(".git"))
}

/// Sends `command` to `s`'s runner and returns its reply. A read (`proof` none) goes the read
/// path; a write needs the step-up's proof.
async fn call(
    app: &App,
    s: &Session,
    command: Command,
    me: Option<&Caller>,
) -> Result<Reply, ApiError> {
    let sent = match me {
        Some(me) => {
            let proof = app.hub.agent_elevation(me);
            app.hub.dispatch_elevated(&s.runner, command, proof)
        }
        None => app.hub.dispatch_agent_read(&s.runner, command),
    }
    .map_err(|e| super::super::runners::failed(&e))?;
    let answer = tokio::time::timeout(app.agents.config.answer, sent.outcome())
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "runner_timeout",
                "the runner did not answer in time",
            )
        })?
        .map_err(|e| super::super::runners::failed(&e))?;
    match answer {
        Body::Result(reply) => Ok(reply),
        _ => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "runner_failed",
            "an answer of another op",
        )),
    }
}

fn wrong_op() -> ApiError {
    ApiError::new(
        StatusCode::BAD_GATEWAY,
        "runner_failed",
        "an answer of another op",
    )
}

/// Where a session's files are: in the Core's workspace (`ws_path`, E15-2), or still only on its
/// runner (a legacy session, served by the old runner ops until 0.11).
enum Home {
    Ws {
        root: PathBuf,
        /// An overflow session: its runner's folder is the writer, so a write goes there first.
        overflow: Option<Arc<WatchState>>,
        is_overflow: bool,
    },
    Runner,
}

async fn home(app: &App, s: &Session) -> Result<Home, ApiError> {
    let Some(root) = adopt::ws_path(&app.pool, &s.id).await? else {
        return Ok(Home::Runner);
    };
    let is_overflow = adopt::is_overflow(&app.pool, &s.id).await?;
    let overflow = app.hub.sync.watches.get(&s.id).filter(|w| w.is_live());
    Ok(Home::Ws {
        root,
        overflow,
        is_overflow,
    })
}

/// A workspace I/O error as an API answer.
fn io_refusal(e: std::io::Error) -> ApiError {
    use std::io::ErrorKind::{InvalidInput, NotFound};
    match e.kind() {
        InvalidInput => ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_path",
            "a plain file inside the session's folder",
        ),
        NotFound => ApiError::new(
            StatusCode::CONFLICT,
            "session_folder_gone",
            "that is not in the session's folder",
        ),
        _ => ApiError::new(
            StatusCode::CONFLICT,
            "workspace_refused",
            format!("not done: {e}"),
        ),
    }
}

/// A sync failure as an API answer: a stale base is the 409 `conflict` of spec 4.6.
fn sync_refusal(e: SyncError) -> ApiError {
    let (status, code) = match e.code {
        "conflict" => (StatusCode::CONFLICT, "conflict"),
        "path_refused" => (StatusCode::BAD_REQUEST, "bad_path"),
        "runner_offline" | "runner_timeout" | "runner_busy" => {
            (StatusCode::CONFLICT, "runner_offline")
        }
        _ => (StatusCode::BAD_GATEWAY, "runner_failed"),
    };
    ApiError::new(status, code, e.why)
}

/// An overflow session writes through its runner; when that stream is down the write waits (409).
fn overflow_down() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "runner_offline",
        "the session runs on a runner that is not syncing now: try again in a moment",
    )
}

#[utoipa::path(get, path = "/api/v1/agent-sessions/{id}/files",
    operation_id = "listAgentSessionFiles", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`"), FolderQuery),
    responses((status = 200, description = "One level of the session's folder on its runner: \
        directories first, then by name, at most 500 (`truncated` says there were more); \
        `.git`, `node_modules` and the like are left out, a symbolic link is listed as a file and \
        never followed. Call again with `dir` for a folder's own entries. Read like the \
        transcript (a session holding secrets answers only to its creator or an admin). 400 \
        `bad_path` (`..`, outside the folder), 409 `session_folder_unknown`, `session_folder_gone`, \
        `unsupported_command` (a runner too old), `runner_offline`", body = AgentFolderListing)))]
pub async fn list(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Query(q): Query<FolderQuery>,
) -> ApiResult<AgentFolderListing> {
    let s = one(&app, &me, &id).await?;
    owns_secrets(&s, &me)?;
    // What a module's agent worked on is the module's `admin` read, like its transcript.
    if s.owner_module.is_some() && !me.device.scopes.iter().any(|x| x == "admin") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "forbidden_scope",
            "a module's session folder requires the admin scope",
        ));
    }
    if let Home::Ws { root, .. } = home(&app, &s).await? {
        // E15-2: the Core lists its own copy of the folder; no runner is asked.
        let dir = relative(&root.to_string_lossy(), q.dir.as_deref().unwrap_or(""))?;
        if guarded(&dir) {
            return Err(ApiError::bad_request("not under .git"));
        }
        let tree = Tree::open(&root).map_err(io_refusal)?;
        let (entries, truncated) = tree.list_folder(&dir).map_err(io_refusal)?;
        return Ok(Json(AgentFolderListing {
            dir,
            truncated,
            entries: entries
                .into_iter()
                .map(|e| AgentFolderEntry {
                    name: e.name,
                    dir: e.dir,
                    size: e.size,
                })
                .collect(),
        }));
    }
    let folder = session_folder(s.workspace.is_some(), &s.state, s.folder.as_deref())?;
    let dir = relative(&folder, q.dir.as_deref().unwrap_or(""))?;
    if !agents::offers(&app, &s.runner, OP_AGENT_FILES) {
        return Err(unsupported("list a session's folder"));
    }
    let cmd = Command::AgentFiles(AgentFiles {
        session: s.id.clone(),
        dir,
    });
    let Reply::AgentFiles(got) = call(&app, &s, cmd, None).await? else {
        return Err(wrong_op());
    };
    Ok(Json(AgentFolderListing {
        dir: got.dir,
        truncated: got.truncated,
        entries: got
            .entries
            .into_iter()
            .map(|e| AgentFolderEntry {
                name: e.name,
                dir: e.dir,
                size: e.size,
            })
            .collect(),
    }))
}

/// The recorded edits of `rel` (a path relative to `folder`) among the session's file-edit
/// entries, NEWEST FIRST, and whether the record cannot be reversed: an entry's text was cut
/// (`edit.truncated`), or the edits are more than one frame holds (then none are sent).
pub(crate) fn edits_of(entries: &[Value], folder: &str, rel: &str) -> (Vec<RevertEdit>, bool) {
    let mut edits = Vec::new();
    let mut cut = false;
    let mut bytes = 0;
    for e in entries {
        let truncated = e["edit"]["truncated"] == true;
        for c in e["edit"]["changes"].as_array().into_iter().flatten().rev() {
            let same = c["path"]
                .as_str()
                .and_then(|p| folder_relative(folder, p))
                .is_some_and(|p| p == rel);
            if !same {
                continue;
            }
            cut |= truncated;
            let (old, new) = (
                c["old"].as_str().unwrap_or_default(),
                c["new"].as_str().unwrap_or_default(),
            );
            bytes += old.len() + new.len();
            edits.push(RevertEdit {
                old: old.to_owned(),
                new: new.to_owned(),
            });
        }
    }
    match bytes >= MAX_REVERT_BYTES {
        true => (vec![], true),
        false => (edits, cut),
    }
}

fn session_files_refusal(why: &'static str, code: &'static str) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, code, why)
}

#[utoipa::path(post, path = "/api/v1/agent-sessions/{id}/files/revert",
    operation_id = "revertAgentFile", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    request_body = AgentFileRevert,
    responses((status = 200, description = "Puts the file back as it was before the session's \
        edits (audited as `agent.file_reverted`, the path and what was done). The session's \
        recorded edits of that file (its `tool_use` entries' `edit`) are reverse-applied on the \
        runner, newest first: no git needed, and only what the session did is undone; a file the \
        session created is deleted (restored from git `HEAD` instead when git tracks it). Edits \
        the record cannot reverse (a cut text, a removal inside the file) fall back to the file's \
        git `HEAD` copy. 409 `revert_conflict` when the file no longer holds the recorded text \
        (nothing is changed), `revert_impossible` (no usable record and git has no copy), \
        `session_folder_unknown`, `session_folder_gone`, `unsupported_command` (a runner too old), \
        `module_owned`; 400 `bad_path`", body = AgentSession)))]
pub async fn revert(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<AgentSession> {
    let s = one(&app, &me, &id).await?;
    let b: AgentFileRevert = parse(&body)?;
    not_a_modules(&s)?;
    owns_secrets(&s, &me)?;
    if let Home::Ws {
        root,
        overflow,
        is_overflow,
    } = home(&app, &s).await?
    {
        let rel = relative(&root.to_string_lossy(), &b.path)?;
        if rel.is_empty() || guarded(&rel) {
            return Err(ApiError::bad_request(
                "name a file of the folder, not under .git",
            ));
        }
        // The recorded edits name the paths the harness saw: its own folder as the runner reported it.
        let seen = s
            .folder
            .clone()
            .unwrap_or_else(|| root.to_string_lossy().into_owned());
        let entries = store::file_edits(&app.pool, &s.id).await?;
        let (edits, truncated) = edits_of(&entries, &seen, &rel);
        let tree = Tree::open(&root).map_err(io_refusal)?;
        let plan = tree
            .plan_revert(&root, &rel, &edits, truncated)
            .map_err(io_refusal)?;
        let result = match (plan, overflow) {
            (Plan::Refused(r), _) => r,
            (plan, None) if is_overflow => {
                let _ = plan;
                return Err(overflow_down());
            }
            (Plan::Write(bytes, r), None) => {
                tree.write(&rel, &bytes, None).map_err(io_refusal)?;
                r
            }
            (Plan::Delete, None) => {
                tree.remove(&rel).map_err(io_refusal)?;
                RevertResult::Deleted
            }
            (Plan::Write(bytes, r), Some(w)) => {
                watch::write_through(&app.hub, &w, &rel, &bytes, None)
                    .await
                    .map_err(sync_refusal)?;
                r
            }
            (Plan::Delete, Some(w)) => {
                watch::delete_through(&app.hub, &w, &rel)
                    .await
                    .map_err(sync_refusal)?;
                RevertResult::Deleted
            }
        };
        return finish_revert(&app, &me, &s, &id, &rel, result).await;
    }
    let folder = session_folder(s.workspace.is_some(), &s.state, s.folder.as_deref())?;
    let rel = relative(&folder, &b.path)?;
    if rel.is_empty() || guarded(&rel) {
        return Err(ApiError::bad_request(
            "name a file of the folder, not under .git",
        ));
    }
    if !agents::offers(&app, &s.runner, OP_AGENT_REVERT) {
        return Err(unsupported("revert a file"));
    }
    let entries = store::file_edits(&app.pool, &s.id).await?;
    let (edits, truncated) = edits_of(&entries, &folder, &rel);
    let cmd = Command::AgentRevert(AgentRevert {
        session: s.id.clone(),
        path: rel.clone(),
        edits,
        truncated,
    });
    let Reply::AgentRevert(done) = call(&app, &s, cmd, Some(&me)).await? else {
        return Err(wrong_op());
    };
    finish_revert(&app, &me, &s, &id, &rel, done.result).await
}

/// The answer to a revert, whoever did it: a refusal for what changed nothing, else the audit row
/// and the session.
async fn finish_revert(
    app: &App,
    me: &Caller,
    s: &Session,
    id: &str,
    rel: &str,
    result: RevertResult,
) -> ApiResult<AgentSession> {
    match result {
        RevertResult::Reverted | RevertResult::Deleted | RevertResult::Restored => {}
        RevertResult::Conflict => {
            return Err(session_files_refusal(
                "the file no longer holds what the session wrote; nothing was changed",
                "revert_conflict",
            ));
        }
        RevertResult::Impossible => {
            return Err(session_files_refusal(
                "the session's record cannot reverse this file and git has no copy of it",
                "revert_impossible",
            ));
        }
        RevertResult::Unknown => return Err(wrong_op()),
    }
    let details = json!({"path": rel, "result": result});
    let action = "agent.file_reverted";
    store::action(&app.pool, s, BY, action, None, details, &me.device.id).await?;
    shown(app, me, id).await
}

#[utoipa::path(post, path = "/api/v1/agent-sessions/{id}/files/write",
    operation_id = "writeAgentFile", tag = "agents",
    params(("id" = String, Path, description = "The session's id, `as_…`")),
    request_body = AgentFileWrite,
    responses((status = 200, description = "Writes `content` (at most 256 KiB) to the file `path` \
        of the session's folder on its runner, creating the folders on the way inside it \
        (audited as `agent.file_written`, the path and size, never the text). A symbolic link on \
        the way, `..` or a path outside the folder is refused, and so is anything under `.git`. \
        400 `bad_path`; 413 `file_too_large`; 409 `session_folder_unknown`, \
        `session_folder_gone`, `unsupported_command` (a runner too old), `module_owned`", body = AgentSession)))]
pub async fn write(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<AgentSession> {
    let s = one(&app, &me, &id).await?;
    let b: AgentFileWrite = parse(&body)?;
    not_a_modules(&s)?;
    owns_secrets(&s, &me)?;
    if b.content.len() > MAX_WRITE_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "file_too_large",
            "a file written here is at most 256 KiB",
        ));
    }
    if let Home::Ws {
        root,
        overflow,
        is_overflow,
    } = home(&app, &s).await?
    {
        let rel = relative(&root.to_string_lossy(), &b.path)?;
        if rel.is_empty() || guarded(&rel) {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "bad_path",
                "name a file of the folder, not under .git",
            ));
        }
        match overflow {
            Some(w) => watch::write_through(&app.hub, &w, &rel, b.content.as_bytes(), None)
                .await
                .map_err(sync_refusal)?,
            None if is_overflow => return Err(overflow_down()),
            None => Tree::open(&root)
                .and_then(|t| t.write(&rel, b.content.as_bytes(), None))
                .map_err(io_refusal)?,
        }
        let details = json!({"path": rel, "bytes": b.content.len()});
        store::action(
            &app.pool,
            &s,
            BY,
            "agent.file_written",
            None,
            details,
            &me.device.id,
        )
        .await?;
        return shown(&app, &me, &id).await;
    }
    let folder = session_folder(s.workspace.is_some(), &s.state, s.folder.as_deref())?;
    let rel = relative(&folder, &b.path)?;
    if rel.is_empty() || guarded(&rel) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_path",
            "name a file of the folder, not under .git",
        ));
    }
    if !agents::offers(&app, &s.runner, OP_AGENT_WRITE) {
        return Err(unsupported("write a file"));
    }
    let bytes = b.content.len();
    let cmd = Command::AgentWrite(AgentWrite {
        session: s.id.clone(),
        path: rel.clone(),
        content: b.content,
    });
    let Reply::AgentWrite(_) = call(&app, &s, cmd, Some(&me)).await? else {
        return Err(wrong_op());
    };
    let details = json!({"path": rel, "bytes": bytes});
    let action = "agent.file_written";
    store::action(&app.pool, &s, BY, action, None, details, &me.device.id).await?;
    shown(&app, &me, &id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(changes: Value, truncated: bool) -> Value {
        json!({"type": "tool_use", "edit": {"changes": changes, "truncated": truncated}})
    }

    #[test]
    fn a_files_edits_come_newest_first_and_are_matched_by_folder_relative_path() {
        let a = |p: &str, o: &str, n: &str| json!({"path": p, "old": o, "new": n});
        // The store gives entries newest first; a MultiEdit's own changes are in order.
        let entries = [
            entry(
                json!([a("/w/s/x.rs", "2", "3"), a("/w/s/y.rs", "q", "r")]),
                false,
            ),
            entry(json!([a("x.rs", "0", "1"), a("x.rs", "1", "2")]), false),
        ];
        let (edits, cut) = edits_of(&entries, "/w/s", "x.rs");
        let pairs: Vec<_> = edits
            .iter()
            .map(|e| (e.old.as_str(), e.new.as_str()))
            .collect();
        assert_eq!(pairs, [("2", "3"), ("1", "2"), ("0", "1")]);
        assert!(!cut);
    }

    #[test]
    fn a_cut_record_is_not_sent_and_says_so() {
        let big = "x".repeat(MAX_REVERT_BYTES);
        let c = json!([{"path": "a", "old": "", "new": big}]);
        let (edits, cut) = edits_of(&[entry(c, false)], "/w/s", "a");
        assert!(edits.is_empty() && cut);
        let c = json!([{"path": "a", "old": "1", "new": "2"}]);
        let (edits, cut) = edits_of(&[entry(c, true)], "/w/s", "a");
        assert_eq!(edits.len(), 1);
        assert!(cut);
    }

    #[test]
    fn paths_are_cleaned_and_git_is_guarded() {
        assert_eq!(relative("/w/s", "/w/s/a/b").unwrap(), "a/b");
        assert!(relative("/w/s", "../x").is_err());
        assert!(relative("/w/s", "/etc/passwd").is_err());
        assert!(guarded(".git/config") && guarded("a/.Git/x") && !guarded(".gitignore"));
    }
}
