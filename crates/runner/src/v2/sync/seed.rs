//! Seeding a project's cache with `git clone` from the Core's copy (`SyncManifest.seed`).

use std::path::Path;

use ainkrad_proto::runner::Workspace;
use ainkrad_proto::v2::{ErrorCode, RunClone, StreamError};

use super::{State, SyncDriver, invalid};

impl SyncDriver {
    /// Clones the Core's copy of the repo into the cache at its `base`, `.git` included, when the
    /// cache has none. A cache that already holds files only takes the `.git` folder.
    pub(super) async fn seed(
        &self,
        root: &Path,
        clone: &RunClone,
        project: i64,
        st: &mut State,
    ) -> Result<(), StreamError> {
        if root.join(".git").exists() {
            return Ok(());
        }
        let agents = self
            .clones
            .as_ref()
            .ok_or_else(|| invalid("this runner cannot clone from the Core"))?;
        let ws = Workspace {
            repo: clone.remote.clone(),
            base: clone.base.clone(),
            branch: clone.base.clone(),
            push: false,
            name: String::new(),
            also: Vec::new(),
            expected_head: None,
            mirror: Some(clone.mirror),
        };
        if let Some(why) = ws.problem() {
            return Err(invalid(why));
        }
        let session = format!("as_seed{project}");
        let moved = async {
            let dir = agents.run_workspace(&session, &ws).await?;
            let empty = std::fs::read_dir(root)
                .map_err(|e| e.to_string())?
                .next()
                .is_none();
            if empty {
                std::fs::remove_dir(root).map_err(|e| e.to_string())?;
                relocate(&dir, root).await
            } else {
                relocate(&dir.join(".git"), &root.join(".git")).await
            }
        }
        .await;
        agents.discard_run_workspace(&session);
        moved.map_err(|e| {
            StreamError::new(ErrorCode::Internal, format!("seeding the cache: {e}"))
        })?;
        // The cache is shared with jobs: git reads it sealed (E15 H1).
        let mut rev = ainkrad_sys::git::sealed(root);
        rev.args(["rev-parse", "HEAD"]).stdout(std::process::Stdio::piped());
        let head = tokio::process::Command::from(rev)
            .output()
            .await
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());
        st.saved.head = head;
        Ok(())
    }
}

/// Moves `src` to the absent `dst`; across filesystems (the agent work root is a temp folder) by copy.
async fn relocate(src: &Path, dst: &Path) -> Result<(), String> {
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    let copied = tokio::process::Command::new("cp")
        .arg("-a")
        .arg(src)
        .arg(dst)
        .status()
        .await
        .map_err(|e| e.to_string())?;
    copied
        .success()
        .then_some(())
        .ok_or_else(|| "copying the clone failed".to_owned())
}
