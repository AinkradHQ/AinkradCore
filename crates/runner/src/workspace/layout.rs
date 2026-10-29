//! Changing an issue's layout (E15.16) without losing a file.
//!
//! - A worktree whose repo the new layout still has is moved whole (`git worktree move`) to its
//!   new place, so everything in it stays: committed, uncommitted, untracked and git-ignored
//!   files alike. One going from the single layout to the multi-repo one becomes
//!   `issue-<id>/<repo name>`, its top-level files with it.
//! - A worktree whose repo the layout no longer has is retired as when idle: its uncommitted
//!   work saved on `refs/citadel/wip/<issue>` in its mirror.
//! - Loose files at the issue dir's top level (outside every worktree, from the multi-repo
//!   layout) stay at the top level: in the single layout that is the primary repo's worktree,
//!   where they show as untracked files. One whose name the repo already uses is moved to
//!   `<work_root>/preserved/issue-<id>/` instead; neither file is ever overwritten.
//!
//! Everything moved aside waits in `<work_root>/worktrees/.relayout/issue-<id>/` until the new
//! layout stands; a setup that fails leaves it there and the next one finishes the job.

use std::path::{Path, PathBuf};

use ainkrad_proto::runner::Workspace;

use super::Workspaces;

fn io(what: &Path, e: std::io::Error) -> String {
    format!("{}: {e}", what.display())
}

/// `dir`'s entries.
fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut all: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| Some(e.ok()?.path()))
        .collect();
    all.sort();
    all
}

impl Workspaces {
    fn stage(&self, issue: i64) -> PathBuf {
        self.root
            .join("worktrees/.relayout")
            .join(format!("issue-{issue}"))
    }

    /// Readies the issue dir for the worktrees `wanted` of `trees`: held worktrees moved or
    /// retired, loose files set aside when the issue dir is to become a worktree.
    pub(super) async fn relayout(
        &self,
        issue: i64,
        trees: &[Workspace],
        wanted: &[PathBuf],
        nested: bool,
    ) -> Result<(), String> {
        let (dir, stage) = (self.path(issue), self.stage(issue));
        let held = self.trees(issue);
        // Left aside by a relayout whose setup failed.
        let staged: Vec<PathBuf> = entries(&stage)
            .into_iter()
            .filter(|p| p.join(".git").is_file())
            .collect();
        let single_now = dir.join(".git").is_file();
        let changed = (nested && single_now) || held.iter().any(|t| !wanted.contains(t));
        if !changed && staged.is_empty() {
            return Ok(());
        }
        std::fs::create_dir_all(&stage).map_err(|e| io(&stage, e))?;
        let mut moved = vec![];
        for (n, tree) in held.iter().chain(&staged).enumerate() {
            if wanted.contains(tree) {
                continue;
            }
            let aside = match tree.starts_with(&stage) {
                true => tree.clone(),
                false => stage.join(format!("tree-{n}-{}", std::process::id())),
            };
            let to = self.wanted_at(tree, trees, wanted);
            match to {
                Some(to) if aside == *tree || self.move_tree(tree, &aside).await.is_ok() => {
                    moved.push((aside, to));
                }
                _ => self.retire_tree(issue, tree, false).await?,
            }
        }
        if !nested && dir.exists() {
            let loose = stage.join("loose");
            std::fs::create_dir_all(&loose).map_err(|e| io(&loose, e))?;
            for entry in entries(&dir) {
                let to = loose.join(entry.file_name().expect("an entry"));
                std::fs::rename(&entry, &to).map_err(|e| io(&entry, e))?;
            }
            std::fs::remove_dir(&dir).map_err(|e| io(&dir, e))?;
        }
        if nested {
            std::fs::create_dir_all(&dir).map_err(|e| io(&dir, e))?;
        }
        for (aside, to) in moved {
            self.move_tree(&aside, &to).await?;
        }
        Ok(())
    }

    /// Where `tree`'s repo goes in the new layout, if it is still there.
    fn wanted_at(&self, tree: &Path, trees: &[Workspace], wanted: &[PathBuf]) -> Option<PathBuf> {
        let real = |p: &Path| p.canonicalize().ok();
        let mirror = real(&Self::mirror_of(tree)?)?;
        trees
            .iter()
            .zip(wanted)
            .find(|(ws, _)| real(&self.mirror(&ws.repo)).as_ref() == Some(&mirror))
            .map(|(_, to)| to.clone())
    }

    /// `git worktree move from to`, under the repo's lock.
    async fn move_tree(&self, from: &Path, to: &Path) -> Result<(), String> {
        let mirror = Self::mirror_of(from).ok_or("not a worktree")?;
        let _repo = self.lock(&mirror).await;
        let utf8 = |p: &Path| p.to_str().map(str::to_owned).ok_or("path is not UTF-8");
        let (from, to) = (utf8(from)?, utf8(to)?);
        self.git(&mirror, &["worktree", "move", &from, &to])
            .await
            .map(drop)
    }

    /// Puts loose files set aside by `relayout` back at the issue dir's top level, or into the
    /// preserved folder when the name is taken.
    pub(super) fn restore_loose(&self, issue: i64) -> Result<(), String> {
        let (dir, stage) = (self.path(issue), self.stage(issue));
        let loose = stage.join("loose");
        for entry in entries(&loose) {
            let name = entry.file_name().expect("an entry").to_owned();
            let mut to = dir.join(&name);
            if std::fs::symlink_metadata(&to).is_ok() {
                let kept = self.root.join("preserved").join(format!("issue-{issue}"));
                std::fs::create_dir_all(&kept).map_err(|e| io(&kept, e))?;
                to = kept.join(&name);
                for n in 1.. {
                    if std::fs::symlink_metadata(&to).is_err() {
                        break;
                    }
                    to = kept.join(format!("{}.{n}", name.to_string_lossy()));
                }
                tracing::warn!(issue, file = %to.display(), "a loose file's name is taken; kept aside");
            }
            std::fs::rename(&entry, &to).map_err(|e| io(&entry, e))?;
        }
        // Only empty dirs go; anything left stays for the next setup.
        let _ = std::fs::remove_dir(&loose);
        let _ = std::fs::remove_dir(&stage);
        Ok(())
    }
}
