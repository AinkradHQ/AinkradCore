//! AI documents (E10-2, D-28): the `.md` files an AI session writes in its own folder become Lore notes,
//! linked to the session and its project, and a person's edit in Lore flows back to the file.
//!
//! How. A job (15 s) asks each running session's runner for the files it created or changed since its harness
//! started (`agent.docs list`; the runner scopes every path to the session's folder, see
//! `ainkrad-runner`'s `agent/docs.rs`). A file with no row is read and becomes a note in the session's project
//! (personal when it has none). A file whose sha-256 moved is read and written as the note's new head. A
//! person's save of a linked note marks it `dirty` and is written back at once (`kick`), or by the next pass.
//!
//! Safety. File text is outside data, stored as note text like any import. The Core sends the runner only
//! `agent.docs` (`Hub::dispatch_agent_docs`), only for sessions of its own table, and only paths the runner
//! accepts. A write names the sha-256 the file had when last synced, so it never overwrites a change it has
//! not seen.
//!
//! Both sides changed (a person saved while the session rewrote the file): the person wins. The file's text is
//! kept as a `conflict` version of the note, then the note is written over the file.
//!
//! At the end of a session the runner keeps the files it made or changed; the job imports those once more
//! (`lore_session_final` marks it done), so the last seconds are not lost.

use std::time::Duration;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiResult;
use ainkrad_core_server::jobs::{Done, JobHandler, Run};
use ainkrad_core_server::store::begin_write;
use ainkrad_proto::v2::{
    AgentDocs, Body, Command, DOCS_NO_FINAL, DocFile, DocsAction, DocsReply, OP_AGENT_DOCS, Reply,
};
use axum::Json;
use axum::extract::State;
use serde::Serialize;
use sqlx::{Row, SqliteConnection};
use std::sync::{Arc, OnceLock};
use utoipa::ToSchema;

use crate::save::{Snap, commit_text, load};
use crate::versions;

const WAIT: Duration = Duration::from_secs(20);
const SESSIONS_MAX: i64 = 20;
const TEXT_MAX: usize = 2_000_000;

/// A session whose folder is in the Core's workspace (E15-2) is read and written there directly:
/// no runner is asked. An overflow session's write goes to its runner first (`write_through`).
async fn local(app: &App, root: std::path::PathBuf, req: AgentDocs) -> Result<DocsReply, String> {
    use ainkrad_core_server::workspace::{adopt, docs, fs::Tree};
    let io = |e: std::io::Error| e.to_string();
    let path = || req.path.clone().ok_or_else(|| "a document path".to_owned());
    let tree = Tree::open(&root).map_err(io)?;
    match req.action {
        DocsAction::List => {
            let (session, ws) = (req.session.clone(), adopt::workspace());
            let files = tokio::task::spawn_blocking(move || docs::list(ws.root(), &session, &tree))
                .await
                .map_err(|e| e.to_string())?
                .map_err(io)?;
            Ok(DocsReply {
                files,
                ..Default::default()
            })
        }
        DocsAction::Read => {
            let (text, sha) = docs::read(&tree, &path()?).map_err(io)?;
            Ok(DocsReply {
                text: Some(text),
                sha256: Some(sha),
                ..Default::default()
            })
        }
        DocsAction::Write => {
            let ended: Option<String> =
                sqlx::query_scalar("SELECT state FROM core_agent_sessions WHERE id = ?")
                    .bind(&req.session)
                    .fetch_optional(&app.pool)
                    .await
                    .map_err(|e| e.to_string())?;
            if matches!(ended.as_deref(), Some("ended" | "lost")) {
                return Err("the session is over: its documents are not written".into());
            }
            let (rel, text) = (path()?, req.text.clone().ok_or("the text")?);
            let docs::Write::Put(bytes) =
                docs::plan_write(&tree, &rel, &text, req.base.as_deref()).map_err(io)?
            else {
                return Err("the file is not as it was last synced".into());
            };
            if adopt::is_overflow(&app.pool, &req.session)
                .await
                .map_err(|e| e.to_string())?
            {
                let w = app
                    .hub
                    .sync
                    .watches
                    .get(&req.session)
                    .filter(|w| w.is_live())
                    .ok_or("the session's runner is not syncing now")?;
                ainkrad_core_server::workspace::watch::write_through(
                    &app.hub, &w, &rel, &bytes, None,
                )
                .await
                .map_err(|e| e.to_string())?;
            } else {
                tree.write(&rel, &bytes, None).map_err(io)?;
            }
            Ok(DocsReply {
                sha256: Some(docs::sha256(&bytes)),
                ..Default::default()
            })
        }
    }
}

async fn call(app: &App, runner: &str, req: AgentDocs) -> Result<DocsReply, String> {
    let ws = ainkrad_core_server::workspace::adopt::ws_path(&app.pool, &req.session)
        .await
        .map_err(|e| e.to_string())?;
    if let Some(root) = ws {
        return local(app, root, req).await;
    }
    let online = app.hub.runners().get(runner).is_some_and(|r| {
        r.online
            && r.drivers
                .iter()
                .any(|d| d.commands.iter().any(|c| c == OP_AGENT_DOCS))
    });
    if !online {
        return Err("the runner does not serve documents".into());
    }
    let sent = app
        .hub
        .dispatch_agent_docs(runner, Command::AgentDocs(req))
        .map_err(|e| e.message)?;
    match tokio::time::timeout(WAIT, sent.outcome()).await {
        Ok(Ok(Body::Result(Reply::AgentDocs(r)))) => Ok(r),
        Ok(Ok(_)) => Err("the runner answered with something else".into()),
        Ok(Err(e)) => Err(e.message),
        Err(_) => Err("no answer in time".into()),
    }
}

fn req(session: &str, action: DocsAction, path: Option<&str>) -> AgentDocs {
    AgentDocs {
        session: session.to_owned(),
        action,
        path: path.map(str::to_owned),
        text: None,
        base: None,
    }
}

/// Marks a note linked to a session file as having a save the file has not got. `true` when it is linked.
pub(crate) async fn mark_dirty(
    conn: &mut SqliteConnection,
    note: &str,
) -> Result<bool, sqlx::Error> {
    let n = sqlx::query("UPDATE lore_session_docs SET dirty = dirty + 1 WHERE note = ?")
        .bind(note)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(n > 0)
}

/// Writes the note's text to its file now, in the background; a failure leaves it dirty for the job.
pub(crate) fn kick(app: &App, note: &str) {
    let (app, note) = (app.clone(), note.to_owned());
    tokio::spawn(async move {
        if let Err(e) = push(&app, &note).await {
            tracing::debug!(
                note,
                error = e,
                "writing a note back to its session file waits"
            );
        }
    });
}

/// Writes a dirty note's text over its session file (when the file is as last synced).
pub(crate) async fn push(app: &App, note: &str) -> Result<(), String> {
    let e = |e: sqlx::Error| e.to_string();
    let Some(r) = sqlx::query(
        "SELECT d.session, d.runner, d.path, d.file_hash, d.dirty, n.text \
         FROM lore_session_docs d JOIN lore_notes n ON n.id = d.note WHERE d.note = ? AND d.dirty > 0",
    )
    .bind(note)
    .fetch_optional(&app.pool)
    .await
    .map_err(e)?
    else {
        return Ok(());
    };
    let (session, runner, path, base, dirty, text): (String, String, String, String, i64, String) = (
        r.try_get("session").map_err(e)?,
        r.try_get("runner").map_err(e)?,
        r.try_get("path").map_err(e)?,
        r.try_get("file_hash").map_err(e)?,
        r.try_get("dirty").map_err(e)?,
        r.try_get("text").map_err(e)?,
    );
    let mut w = req(&session, DocsAction::Write, Some(&path));
    w.text = Some(text);
    w.base = Some(base);
    let sha = call(app, &runner, w).await?.sha256.ok_or("no sha-256")?;
    sqlx::query(
        "UPDATE lore_session_docs SET file_hash = ?, dirty = MAX(dirty - ?, 0) WHERE note = ?",
    )
    .bind(sha)
    .bind(dirty)
    .bind(note)
    .execute(&app.pool)
    .await
    .map_err(e)?;
    Ok(())
}

struct Sess {
    id: String,
    runner: String,
    project: Option<i64>,
}

/// One changed file of a session. `true` when a note changed.
async fn sync_file(app: &App, s: &Sess, f: &DocFile) -> Result<bool, String> {
    let db = |e: sqlx::Error| e.to_string();
    let refused = |_| "lore refused the text".to_owned();
    let who = format!("session:{}", s.id);
    let row = sqlx::query(
        "SELECT note, file_hash, dirty FROM lore_session_docs WHERE session = ? AND path = ?",
    )
    .bind(&s.id)
    .bind(&f.path)
    .fetch_optional(&app.pool)
    .await
    .map_err(db)?;
    let Some(row) = row else {
        let (text, sha) = read(app, s, &f.path).await?;
        let mut tx = begin_write(&app.pool).await.map_err(db)?;
        let project = match s.project {
            Some(p) => crate::notes::project_id(&mut tx, &p.to_string()).await.ok(),
            None => None,
        };
        let id = crate::notes::insert(&mut tx, project.as_deref(), &text, &who, "session")
            .await
            .map_err(refused)?;
        sqlx::query(
            "INSERT INTO lore_session_docs (note, session, runner, path, file_hash) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&s.id)
        .bind(&s.runner)
        .bind(&f.path)
        .bind(sha)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        return Ok(true);
    };
    let note: String = row.try_get("note").map_err(db)?;
    let hash: String = row.try_get("file_hash").map_err(db)?;
    let dirty: i64 = row.try_get("dirty").map_err(db)?;
    if hash == f.sha256 {
        if dirty > 0 {
            push(app, &note).await?;
        }
        return Ok(false);
    }
    // The file moved since the last sync.
    let (text, sha) = read(app, s, &f.path).await?;
    let mut tx = begin_write(&app.pool).await.map_err(db)?;
    let h = load(&mut tx, &note).await.map_err(refused)?;
    if dirty > 0 {
        // Both changed: the person wins; the file's text stays as a version.
        versions::keep(&mut tx, &note, h.rev, &text, "conflict", None, &who)
            .await
            .map_err(refused)?;
        sqlx::query("UPDATE lore_session_docs SET file_hash = ? WHERE note = ?")
            .bind(&sha)
            .bind(&note)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        push(app, &note).await?;
        return Ok(true);
    }
    if !h.trashed && text != h.text {
        commit_text(&mut tx, &h, &text, &who, "session", Snap::Always)
            .await
            .map_err(refused)?;
    }
    sqlx::query("UPDATE lore_session_docs SET file_hash = ? WHERE note = ?")
        .bind(&sha)
        .bind(&note)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    tx.commit().await.map_err(db)?;
    Ok(true)
}

async fn read(app: &App, s: &Sess, path: &str) -> Result<(String, String), String> {
    let r = call(app, &s.runner, req(&s.id, DocsAction::Read, Some(path))).await?;
    let text = r.text.ok_or("no text")?;
    if text.len() > TEXT_MAX {
        return Err("the document is too large".into());
    }
    Ok((text, r.sha256.ok_or("no sha-256")?))
}

async fn mark_final(app: &App, session: &str) {
    let _ = sqlx::query("INSERT OR IGNORE INTO lore_session_final (session) VALUES (?)")
        .bind(session)
        .execute(&app.pool)
        .await;
}

/// One pass over the running sessions. Returns the notes written.
pub(crate) async fn pass(app: &App) -> Result<usize, String> {
    // Running sessions, and sessions that ended in the last day whose kept files are not imported yet.
    let rows = sqlx::query(
        "SELECT id, runner, project_id, state FROM core_agent_sessions \
         WHERE state = 'running' \
            OR (state = 'ended' AND ended_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day') \
                AND id NOT IN (SELECT session FROM lore_session_final)) \
         ORDER BY (state = 'running') DESC, updated_at DESC LIMIT ?",
    )
    .bind(SESSIONS_MAX)
    .fetch_all(&app.pool)
    .await
    .map_err(|e| e.to_string())?;
    let mut n = 0;
    for r in rows {
        let s = Sess {
            id: r.try_get("id").map_err(|e| e.to_string())?,
            runner: r.try_get("runner").map_err(|e| e.to_string())?,
            project: r.try_get("project_id").map_err(|e| e.to_string())?,
        };
        let ended = r.try_get::<String, _>("state").map_err(|e| e.to_string())? == "ended";
        // A runner that is away or does not serve documents is skipped quietly (an ended session is asked again).
        let list = match call(app, &s.runner, req(&s.id, DocsAction::List, None)).await {
            Ok(l) => l,
            Err(e) if ended && e == DOCS_NO_FINAL => {
                mark_final(app, &s.id).await;
                continue;
            }
            Err(_) => continue,
        };
        let mut clean = true;
        for f in &list.files {
            match sync_file(app, &s, f).await {
                Ok(true) => n += 1,
                Ok(false) => {}
                Err(e) => {
                    clean = false;
                    tracing::debug!(
                        session = s.id,
                        error = e,
                        "a session document was not synced"
                    );
                }
            }
        }
        if ended && clean {
            mark_final(app, &s.id).await;
        }
    }
    Ok(n)
}

pub(crate) struct DocsJob(pub Arc<OnceLock<App>>);

impl JobHandler for DocsJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let app = self.0.get().ok_or("the lore module is not attached")?;
            if pass(app).await? == 0 {
                run.idle();
            }
            Ok(())
        })
    }
}

#[derive(Serialize, ToSchema)]
pub struct SessionDoc {
    /// The note.
    pub note: String,
    /// The AI session, `as_…`.
    pub session: String,
    /// The file, relative to the session's folder.
    pub path: String,
    pub title: String,
    /// The session's first prompt line, at most 80 characters; `null` when it has none.
    pub session_title: Option<String>,
    pub project: Option<String>,
    pub updated_at: String,
}

#[utoipa::path(get, path = "/session-docs", operation_id = "loreSessionDocs", tag = "lore",
    responses((status = 200, description = "The live notes imported from AI session files, newest change first (at most 200), each with its session and file path", body = Vec<SessionDoc>)))]
pub(crate) async fn list(State(app): State<App>) -> ApiResult<Vec<SessionDoc>> {
    let rows = sqlx::query(
        "SELECT d.note, d.session, d.path, n.title, n.project, n.updated_at, substr(s.prompt, 1, 200) AS prompt \
         FROM lore_session_docs d JOIN lore_notes n ON n.id = d.note \
         LEFT JOIN core_agent_sessions s ON s.id = d.session \
         WHERE n.trashed_at IS NULL ORDER BY n.updated_at DESC, d.note LIMIT 200",
    )
    .fetch_all(&app.pool)
    .await?;
    let out = rows
        .iter()
        .map(|r| {
            let prompt: Option<String> = r.try_get("prompt")?;
            let title = prompt
                .as_deref()
                .and_then(|p| p.lines().map(str::trim).find(|l| !l.is_empty()))
                .map(|l| l.chars().take(80).collect::<String>());
            Ok(SessionDoc {
                note: r.try_get("note")?,
                session: r.try_get("session")?,
                path: r.try_get("path")?,
                title: r.try_get("title")?,
                session_title: title,
                project: r.try_get("project")?,
                updated_at: r.try_get("updated_at")?,
            })
        })
        .collect::<Result<_, sqlx::Error>>()?;
    Ok(Json(out))
}
