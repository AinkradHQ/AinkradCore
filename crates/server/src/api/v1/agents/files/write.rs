//! A person's write into a session's files (E15-2): the Core's workspace copy, or written through
//! to an overflow session's runner.

use super::*;

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
