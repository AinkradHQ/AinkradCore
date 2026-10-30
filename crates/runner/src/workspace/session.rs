//! Independent object stores per session generation; no shared writable mirror.
use super::*;
use crate::v2::agent::secrets::private_dir;
use ainkrad_proto::v2::valid_session_id;

impl Workspaces {
    pub fn session_path(&self, session: &str) -> Result<PathBuf, String> {
        if !valid_session_id(session) {
            return Err("invalid agent session id".into());
        }
        Ok(self.root.join("worktrees/sessions").join(session))
    }

    pub async fn prepare_session(
        &self,
        session: &str,
        generation: i64,
        requests: &[SessionWorkspace],
        helper: Option<&Path>,
    ) -> Result<PathBuf, String> {
        if generation < 0 || requests.is_empty() || requests.len() > 16 {
            return Err("invalid workspace generation or repository count".into());
        }
        let mut names = std::collections::HashSet::new();
        for r in requests {
            if let Some(why) = ainkrad_proto::runner::repo_url_problem(&r.repo) {
                return Err(why);
            }
            if !ainkrad_proto::runner::branch_name_ok(&r.reference)
                || !ainkrad_proto::runner::branch_name_ok(&r.branch)
            {
                return Err("invalid git ref".into());
            }
            if requests.len() > 1
                && (!safe_repo_name(&r.name) || !names.insert(r.name.to_ascii_lowercase()))
            {
                return Err("invalid or duplicate repository name".into());
            }
        }
        let _slot = self
            .prepares
            .acquire()
            .await
            .map_err(|_| "workspace service closed")?;
        let root = self.session_path(session)?.join(generation.to_string());
        if root.exists() {
            return Err("workspace generation already exists".into());
        }
        private_dir(&root).map_err(|e| e.to_string())?;
        let result = async {
            for r in requests {
                let path = if requests.len() == 1 {
                    root.clone()
                } else {
                    root.join(&r.name)
                };
                let path_str = path.to_str().ok_or("invalid workspace path")?;
                self.git_with_credentials(
                    &self.root,
                    &[
                        "clone",
                        "--no-checkout",
                        "--no-recurse-submodules",
                        "--template=",
                        "--depth=1",
                        "--single-branch",
                        "--branch",
                        &r.reference,
                        "--",
                        &r.repo,
                        path_str,
                    ],
                    helper,
                )
                .await
                .map_err(|_| "git clone failed (credentials or transport)".to_owned())?;
                // Only fresh, runner-created config is read. Never run git here after handoff.
                self.git(
                    &path,
                    &["checkout", "--no-recurse-submodules", "-B", &r.branch],
                )
                .await?;
            }
            Ok(root.clone())
        }
        .await;
        if result.is_err() {
            let _ = self.cleanup_session(session, generation).await;
        }
        result
    }

    /// Preserve commits, index, untracked and ignored WIP without interpreting agent config,
    /// hooks, alternates or `.git`. A stale teardown can only move its own generation.
    pub async fn cleanup_session(&self, session: &str, generation: i64) -> Result<(), String> {
        if generation < 0 {
            return Err("invalid generation".into());
        }
        let path = self.session_path(session)?.join(generation.to_string());
        if !path.exists() {
            return Ok(());
        }
        let saved = self.root.join("session-wip").join(session);
        private_dir(&saved).map_err(|e| e.to_string())?;
        std::fs::rename(&path, saved.join(generation.to_string())).map_err(|e| e.to_string())
    }

    /// Recovery retains sessions re-adopted by the driver; only unknown sessions are orphaned.
    pub fn recover_sessions(&self, adopted: &[String]) {
        let dir = self.root.join("worktrees/sessions");
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let session = entry.file_name().to_string_lossy().into_owned();
            if !valid_session_id(&session) || adopted.contains(&session) {
                continue;
            }
            let saved = self.root.join("session-wip").join(&session);
            if private_dir(saved.parent().expect("parent")).is_ok() && !saved.exists() {
                let _ = std::fs::rename(entry.path(), saved);
            }
        }
    }
}
