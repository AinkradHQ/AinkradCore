//! The project's main working copy, `<ws>/p/<project>/main` (E15 §4.1): what a job with no session,
//! a run configuration or anything else that resolves the project folder works on. Made on first
//! need by cloning the Core's copies (the same copies a session's checkouts are cloned from), one
//! project at a time. One repo: `main` is its clone; several: `main/<repo>`, as a session's are.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use super::{Mirrors, key, refresh};
use crate::api::App;
use crate::store::projects as store;
use crate::workspace::paths::Workspace;

/// One materialisation per project at a time.
fn project_lock(project: i64) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>> = OnceLock::new();
    LOCKS
        .get_or_init(Mutex::default)
        .lock()
        .expect("locks")
        .entry(project)
        .or_default()
        .clone()
}

/// `<ws>/p/<project>/main`, cloned from the Core's copies if it is not there yet. `Err` says why it
/// cannot be made (no repo, no workspace, a copy that cannot be fetched).
pub async fn ensure_main(app: &App, project: i64) -> Result<PathBuf, String> {
    ensure_main_in(app, &crate::heavy::workspace(), project).await
}

pub(crate) async fn ensure_main_in(
    app: &App,
    ws: &Workspace,
    project: i64,
) -> Result<PathBuf, String> {
    let main = ws.project_main(project);
    let lock = project_lock(project);
    let _one = lock.lock().await;
    let mut conn = app.pool.acquire().await.map_err(|e| e.to_string())?;
    let repos = store::repos(&mut conn, project)
        .await
        .map_err(|e| e.to_string())?;
    drop(conn);
    if repos.is_empty() {
        return Err(format!(
            "project {project} has no repo, so it has no project folder: add a repo to the project"
        ));
    }
    if !ws.root().is_dir() {
        return Err(format!(
            "the Core's workspace {} does not exist, so the project folder cannot be made",
            ws.root().display()
        ));
    }
    let mirrors = app
        .mirrors
        .as_ref()
        .ok_or("this Core keeps no repo copies, so the project folder cannot be made")?;
    // ponytail: a repo added after `main` was made as a single clone lands inside it at
    // `main/<repo>`; re-lay the folder out when multi-repo projects use main for real.
    let nested = repos.len() > 1;
    for r in &repos {
        let dest = match nested {
            true => ws
                .project_repo(project, &r.name)
                .ok_or_else(|| format!("the repo name {} cannot be a folder name", r.name))?,
            false => main.clone(),
        };
        if dest.join(".git").exists() {
            continue;
        }
        let k = key(project, &r.remote_url);
        if mirrors.ready(r.id, &k).is_err() {
            let m = refresh(app, r.id)
                .await
                .map_err(|e| format!("the Core's copy of {} cannot be fetched: {e:?}", r.name))?;
            if m.state != "ready" {
                return Err(format!(
                    "the Core's copy of {} is not ready: {}",
                    r.name,
                    m.error.unwrap_or_else(|| m.state.clone())
                ));
            }
        }
        mirrors
            .clone_to(r.id, &k, &r.remote_url, &r.default_branch, &dest)
            .await
            .map_err(|why| format!("cloning {} into the project folder failed: {why}", r.name))?;
    }
    Ok(main)
}

impl Mirrors {
    /// Clones the copy of `repo` (made for `key`) at `branch` into `dest`, aside first so a failed
    /// clone leaves nothing, with `origin` set to the real `remote`. Holds the repo's lock, so no
    /// fetch or collection rewrites the copy meanwhile.
    async fn clone_to(
        &self,
        repo: i64,
        key: &str,
        remote: &str,
        branch: &str,
        dest: &Path,
    ) -> Result<(), String> {
        let _one = self.lock(repo).await;
        let src = self
            .ready(repo, key)
            .map_err(|_| "the Core's copy is not ready".to_owned())?;
        let parent = dest.parent().ok_or("the project folder has no parent")?;
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        let work = dest.with_extension("cloning");
        let _ = std::fs::remove_dir_all(&work);
        let w = work.to_str().ok_or("path is not UTF-8")?;
        let args = [
            "clone",
            "-q",
            "--no-hardlinks",
            "--branch",
            branch,
            "--",
            &src,
            w,
        ];
        // The source is the Core's own copy, a local path: only the file transport is allowed.
        let mut cmd = self.command(&args, None);
        cmd.env("GIT_ALLOW_PROTOCOL", "file");
        let made = async {
            self.run_command(cmd, None, self.timeout).await?;
            self.run(&["-C", w, "remote", "set-url", "origin", remote], None)
                .await?;
            std::fs::rename(&work, dest).map_err(|e| format!("{}: {e}", dest.display()))
        }
        .await;
        if made.is_err() {
            let _ = std::fs::remove_dir_all(&work);
        }
        made
    }
}
