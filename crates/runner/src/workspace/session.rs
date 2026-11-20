//! Independent object stores per session generation; no shared writable mirror.
use super::*;
use crate::v2::agent::secrets::private_dir;
use ainkrad_proto::v2::valid_session_id;

/// `requests`, checked: 1 to 16 repos, real remotes and refs, unique safe names when several.
fn check_requests(requests: &[SessionWorkspace]) -> Result<(), String> {
    if requests.is_empty() || requests.len() > 16 {
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
    Ok(())
}

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
        if generation < 0 {
            return Err("invalid workspace generation or repository count".into());
        }
        let root = self.session_path(session)?.join(generation.to_string());
        check_requests(requests)?;
        let relay = self.relay_for(requests).await?;
        let _slot = self
            .prepares
            .acquire()
            .await
            .map_err(|_| "workspace service closed")?;
        if root.exists() {
            return Err("workspace generation already exists".into());
        }
        private_dir(&root).map_err(|e| e.to_string())?;
        let result = self
            .clone_each(requests, requests.len() > 1, &root, helper, relay.as_ref())
            .await;
        if result.is_err() {
            let _ = self.cleanup_session(session, generation).await;
        }
        result.map(|()| root)
    }

    /// A session's checkouts in its folder of the canonical workspace (`AgentStart::folder`): made
    /// once and kept, so a resume or a wake finds them as they were and the Core reads the same
    /// files. One repo: the folder is its clone; several: `<folder>/<name>`. A repo already there
    /// is reused as it is.
    pub async fn prepare_in_folder(
        &self,
        folder: &Path,
        requests: &[SessionWorkspace],
        helper: Option<&Path>,
    ) -> Result<PathBuf, String> {
        check_requests(requests)?;
        let _slot = self
            .prepares
            .acquire()
            .await
            .map_err(|_| "workspace service closed")?;
        let at = |r: &SessionWorkspace| match requests.len() {
            1 => folder.to_path_buf(),
            _ => folder.join(&r.name),
        };
        let missing: Vec<SessionWorkspace> = requests
            .iter()
            .filter(|r| !at(r).join(".git").exists())
            .cloned()
            .collect();
        if missing.is_empty() {
            return Ok(folder.to_path_buf());
        }
        let relay = self.relay_for(&missing).await?;
        // Group-shared with the Core (the unit's umask), not private: the Core reads this folder.
        std::fs::create_dir_all(folder).map_err(|e| format!("{}: {e}", folder.display()))?;
        self.clone_each(&missing, requests.len() > 1, folder, helper, relay.as_ref())
            .await?;
        Ok(folder.to_path_buf())
    }

    /// The loopback relay to the Core's copies these clones need, if any; started before anything
    /// is made on disk, so a runner that cannot reach the Core leaves nothing behind.
    async fn relay_for(
        &self,
        requests: &[SessionWorkspace],
    ) -> Result<Option<super::relay::Relay>, String> {
        let ids: Vec<i64> = requests.iter().filter_map(|r| r.mirror).collect();
        if ids.is_empty() {
            return Ok(None);
        }
        let up = self
            .mirror_upstream
            .lock()
            .expect("mirror upstream")
            .clone()
            .ok_or("this runner cannot clone from the Core")?;
        super::relay::Relay::start(up, ids)
            .await
            .map(Some)
            .map_err(|e| format!("relay: {e}"))
    }

    /// Clones every request into `root` (`root/<name>` when `nested`), through `relay` for the
    /// ones with a mirror.
    async fn clone_each(
        &self,
        requests: &[SessionWorkspace],
        nested: bool,
        root: &Path,
        helper: Option<&Path>,
        relay: Option<&super::relay::Relay>,
    ) -> Result<(), String> {
        for r in requests {
            let path = match nested {
                false => root.to_path_buf(),
                true => root.join(&r.name),
            };
            let path_str = path.to_str().ok_or("invalid workspace path")?;
            let source = match (r.mirror, relay) {
                (Some(id), Some(relay)) => Some(relay.url(id)),
                _ => None,
            };
            let clone = [
                "clone",
                "--no-checkout",
                "--no-recurse-submodules",
                "--template=",
                "--depth=1",
                "--single-branch",
                "--branch",
                &r.reference,
                "--",
                source.as_deref().unwrap_or(&r.repo),
                path_str,
            ];
            match source {
                Some(_) => self.git_relay(&self.root, &clone).await,
                None => self.git_with_credentials(&self.root, &clone, helper).await,
            }
            .map_err(|_| "git clone failed (credentials or transport)".to_owned())?;
            if source.is_some() {
                // The checkout pushes to the real remote; no trace of the relay stays in it.
                self.git(&path, &["remote", "set-url", "origin", &r.repo])
                    .await?;
            }
            // Only fresh, runner-created config is read. Never run git here after handoff.
            self.git(
                &path,
                &["checkout", "--no-recurse-submodules", "-B", &r.branch],
            )
            .await?;
        }
        Ok(())
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

    /// Deletes (never saves) every session workspace, live or saved, whose id starts with
    /// `prefix` and is not in `keep`: a project run's clone is only its helper's input (P5-05),
    /// so nothing of it is worth the `session-wip` a normal cleanup would leave.
    pub fn discard_sessions(&self, name: &str, prefix: bool, keep: &[String]) {
        for base in ["worktrees/sessions", "session-wip"] {
            let Ok(entries) = std::fs::read_dir(self.root.join(base)) else {
                continue;
            };
            for e in entries.flatten() {
                let entry_name = e.file_name().to_string_lossy().into_owned();
                if (if prefix {
                    entry_name.starts_with(name)
                } else {
                    entry_name == name
                }) && !keep.contains(&entry_name)
                {
                    let _ = std::fs::remove_dir_all(e.path());
                }
            }
        }
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
            // Per generation, so an earlier cleanup's saved dir never blocks the reap.
            if private_dir(&saved).is_ok()
                && let Ok(gens) = std::fs::read_dir(entry.path())
            {
                for g in gens.flatten() {
                    let _ = std::fs::rename(g.path(), saved.join(g.file_name()));
                }
                let _ = std::fs::remove_dir(entry.path());
            }
        }
    }
}
