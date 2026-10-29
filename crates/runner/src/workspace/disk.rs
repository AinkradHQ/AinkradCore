//! Disk (E15.9, pain #8: 200 GB of worktrees after a day).
//!
//! - **Shared build caches**: every worktree of one repo builds into one cache,
//!   `<work_root>/caches/<repo>/`, through the variables its kind reads (`CacheRule`): Cargo's
//!   `CARGO_TARGET_DIR`, npm's and pnpm's stores, Gradle's home, and `CITADEL_DERIVED_DATA` for
//!   an Xcode or SwiftPM build to pass as `-derivedDataPath` (neither reads a variable).
//!   An issue of several repos (E15.16) runs one process for all of them, so a variable can
//!   name only one cache: each repo keeps its own build output there by a link where its tool
//!   looks by default (Cargo's `target`, kept out of git by the mirror's `info/exclude`), or by
//!   a variable suffixed with the repo's name (`CITADEL_DERIVED_DATA_<NAME>`,
//!   `CITADEL_BUILD_CACHE_<NAME>`). Content-addressed download stores (npm, pnpm, Gradle) are
//!   safe to share and keep one variable, the first such repo's.
//! - **Idle worktrees**: each worktree's last use is a marker file's time; one unused for
//!   `workspace.idle_secs` is removed (`retire`) and recreated from its branch on demand.
//! - **Cap**: past `disk_evict_percent` of `runner.disk_cap_bytes`, idle worktrees go oldest
//!   first, then the caches of repos with no worktree in use; a worktree in use never, and the
//!   mirrors (they hold every branch) never. Still over the cap: the report is `full`.
//!
//! Never losing work: a worktree's commits live on its branch in the mirror. Uncommitted
//! changes (git-ignored files aside) are committed to `refs/citadel/wip/<issue>` before it
//! goes, and put back as uncommitted changes when it is recreated; if that commit cannot be
//! made, the worktree stays. If they no longer apply onto the branch, the ref stays for a
//! person, and the run starts from the branch.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ainkrad_proto::runner::{DiskReport, RunnerLimits, Workspace, WorktreeDisk};

use super::{Workspaces, repo_name};

/// A build cache for repos of one kind: when a worktree holds `marker`, `var` points at
/// `dir` in its repo's cache. In a multi-repo issue, `link` (the tool's default dir in the
/// repo) is linked to it instead, and a cache that is not `shared` gets a per-repo variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheRule {
    pub marker: String,
    pub var: String,
    pub dir: String,
    pub link: Option<String>,
    /// Content-addressed: one repo's cache serves another's builds correctly.
    pub shared: bool,
}

impl CacheRule {
    pub fn defaults() -> Vec<Self> {
        [
            (
                "Cargo.toml",
                "CARGO_TARGET_DIR",
                "cargo-target",
                Some("target"),
                false,
            ),
            ("package.json", "npm_config_cache", "npm", None, true),
            (
                "package.json",
                "npm_config_store_dir",
                "pnpm-store",
                None,
                true,
            ),
            (
                "Package.swift",
                "CITADEL_DERIVED_DATA",
                "DerivedData",
                None,
                false,
            ),
            (
                "project.yml",
                "CITADEL_DERIVED_DATA",
                "DerivedData",
                None,
                false,
            ),
            ("build.gradle", "GRADLE_USER_HOME", "gradle", None, true),
            ("build.gradle.kts", "GRADLE_USER_HOME", "gradle", None, true),
        ]
        .map(|(marker, var, dir, link, shared)| Self {
            marker: marker.to_owned(),
            var: var.to_owned(),
            dir: dir.to_owned(),
            link: link.map(str::to_owned),
            shared,
        })
        .into()
    }
}

/// A repo name as an environment variable's suffix: `core-api` → `CORE_API`.
fn env_name(name: &str) -> String {
    name.chars()
        .map(|c| match c.is_ascii_alphanumeric() {
            true => c.to_ascii_uppercase(),
            false => '_',
        })
        .collect()
}

/// Bytes under `path`, symlinks not followed.
fn size(path: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    if !meta.is_dir() {
        return meta.len();
    }
    std::fs::read_dir(path)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|e| size(&e.path()))
        .sum()
}

/// The children of `dir`, by name.
fn children(dir: &Path) -> Vec<(String, PathBuf)> {
    let mut all: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|e| Some((e.file_name().into_string().ok()?, e.path())))
        .collect();
    all.sort();
    all
}

impl Workspaces {
    fn cache(&self, repo_name: &str) -> PathBuf {
        self.root.join("caches").join(repo_name)
    }

    fn marker(&self, issue: i64) -> PathBuf {
        self.root
            .join("worktrees/.used")
            .join(format!("issue-{issue}"))
    }

    /// Marks the issue's worktree used now.
    pub(super) fn touch(&self, issue: i64) {
        let marker = self.marker(issue);
        let touched = marker
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::File::create(&marker))
            .and_then(|f| f.set_modified(SystemTime::now()));
        if let Err(e) = touched {
            tracing::warn!(issue, error = %e, "cannot mark the worktree used");
        }
    }

    /// When the issue's worktree was last used: its marker, else the worktree's own time.
    fn used_at(&self, issue: i64) -> SystemTime {
        [self.marker(issue), self.path(issue)]
            .iter()
            .find_map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }

    fn in_use(&self, issue: i64) -> bool {
        self.in_use.lock().expect("in_use").contains_key(&issue)
    }

    /// The variables pointing the issue's build tools at its repos' shared caches; with several
    /// repos (E15.16), each repo's own (see the module doc).
    pub fn cache_env(&self, issue: i64, trees: &[Workspace]) -> Vec<(String, OsString)> {
        let nested = trees.len() > 1;
        let mut env: Vec<(String, OsString)> = vec![];
        let mut set = |var: String, value: PathBuf| {
            if !env.iter().any(|(v, _)| *v == var) {
                env.push((var, value.into()));
            }
        };
        for ws in trees {
            let (tree, cache) = (
                self.tree(issue, ws, nested),
                self.cache(&repo_name(&ws.repo)),
            );
            if let Err(e) = std::fs::create_dir_all(&cache) {
                tracing::warn!(error = %e, "cannot create the build cache");
                continue;
            }
            let suffix = |var: &str| match nested {
                true => format!("{var}_{}", env_name(&ws.name)),
                false => var.to_owned(),
            };
            set(suffix("CITADEL_BUILD_CACHE"), cache.clone());
            for rule in &self.cache_rules {
                if !tree.join(&rule.marker).exists() {
                    continue;
                }
                let dir = cache.join(&rule.dir);
                match (&rule.link, nested && !rule.shared) {
                    (_, false) => set(rule.var.clone(), dir),
                    (Some(link), true) => self.link_cache(ws, &tree, link, &dir),
                    (None, true) => set(suffix(&rule.var), dir),
                }
            }
        }
        env
    }

    /// Links `tree/link` to the repo's cache `dir`, kept out of git by the mirror's exclude
    /// file; a `link` already there (a real build dir) is left alone.
    fn link_cache(&self, ws: &Workspace, tree: &Path, link: &str, dir: &Path) {
        let exclude = self.mirror(&ws.repo).join("info/exclude");
        let line = format!("/{link}");
        let listed = std::fs::read_to_string(&exclude)
            .is_ok_and(|text| text.lines().any(|l| l.trim() == line));
        let linked = std::fs::create_dir_all(dir)
            .and_then(|()| match listed {
                true => Ok(()),
                false => {
                    std::fs::create_dir_all(exclude.parent().expect("info"))?;
                    let mut file = std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&exclude)?;
                    std::io::Write::write_all(&mut file, format!("\n{line}\n").as_bytes())
                }
            })
            .and_then(|()| match std::fs::symlink_metadata(tree.join(link)) {
                Ok(_) => Ok(()),
                Err(_) => std::os::unix::fs::symlink(dir, tree.join(link)),
            });
        if let Err(e) = linked {
            tracing::warn!(error = %e, link, "cannot link the repo's build cache");
        }
    }

    /// The mirror a worktree belongs to, from its `.git` file (`gitdir: <mirror>/worktrees/…`).
    pub(super) fn mirror_of(tree: &Path) -> Option<PathBuf> {
        let git = std::fs::read_to_string(tree.join(".git")).ok()?;
        let gitdir = PathBuf::from(git.trim().strip_prefix("gitdir: ")?);
        Some(gitdir.parent()?.parent()?.to_owned())
    }

    /// Removes the issue's worktrees (one per repo, E15.16) unless a run uses them, the
    /// uncommitted work of each first saved on `refs/citadel/wip/<issue>` in its repo's mirror;
    /// refused (what is left stays) when that cannot be saved.
    pub async fn retire(&self, issue: i64) -> Result<(), String> {
        if self.in_use(issue) {
            return Err("in use".to_owned());
        }
        for tree in self.trees(issue) {
            self.retire_tree(issue, &tree, true).await?;
        }
        // A multi-repo issue's dir, its worktrees gone; or a broken one.
        let dir = self.path(issue);
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        let _ = std::fs::remove_file(self.marker(issue));
        Ok(())
    }

    /// Removes one worktree of the issue, its uncommitted work saved first; with `idle`, refused
    /// once a run uses the issue (checked under the repo's lock, so a run starting meanwhile
    /// keeps it).
    pub(super) async fn retire_tree(
        &self,
        issue: i64,
        path: &Path,
        idle: bool,
    ) -> Result<(), String> {
        let path = path.to_owned();
        let mirror = Self::mirror_of(&path);
        let _repo = match &mirror {
            Some(mirror) => Some(self.lock(mirror).await),
            None => None,
        };
        if idle && self.in_use(issue) {
            return Err("in use".to_owned());
        }
        let removed = match (&mirror, path.to_str()) {
            (Some(mirror), Some(dir)) => {
                self.save_wip(issue, &path).await?;
                self.git(mirror, &["worktree", "remove", "--force", dir])
                    .await
            }
            _ => Err("not a worktree".to_owned()),
        };
        if let Err(why) = removed {
            tracing::warn!(issue, %why, "removing the worktree by hand");
            let _ = std::fs::remove_dir_all(&path);
            if let Some(mirror) = &mirror {
                let _ = self.git(mirror, &["worktree", "prune"]).await;
            }
        }
        Ok(())
    }

    /// Commits the worktree's uncommitted changes, if any, to `refs/citadel/wip/<issue>`
    /// without moving its branch.
    async fn save_wip(&self, issue: i64, tree: &Path) -> Result<(), String> {
        let dirty = self.git(tree, &["status", "--porcelain"]).await?;
        if dirty.trim().is_empty() {
            return Ok(());
        }
        self.git(tree, &["add", "-A"]).await?;
        let index = self.git(tree, &["write-tree"]).await?;
        let message = format!("citadel: work in progress on issue {issue}, kept on removal");
        let commit = [
            "-c",
            "user.name=Citadel runner",
            "-c",
            "user.email=runner@citadel.invalid",
            "commit-tree",
            index.trim(),
            "-p",
            "HEAD",
            "-m",
            &message,
        ];
        let sha = self.git(tree, &commit).await?;
        let wip = format!("refs/citadel/wip/{issue}");
        self.git(tree, &["update-ref", &wip, sha.trim()]).await?;
        tracing::info!(issue, sha = sha.trim(), "uncommitted work saved on {wip}");
        Ok(())
    }

    /// Puts the issue's saved work back into its new worktree as uncommitted changes and drops
    /// the ref; one that no longer applies stays on its ref.
    pub(super) async fn restore_wip(&self, issue: i64, mirror: &Path, tree: &Path) {
        let wip = format!("refs/citadel/wip/{issue}");
        let saved = ["rev-parse", "--verify", "--quiet", &wip];
        if self.git(mirror, &saved).await.is_err() {
            return;
        }
        match self.git(tree, &["cherry-pick", "--no-commit", &wip]).await {
            Ok(_) => {
                let _ = self.git(tree, &["reset", "-q"]).await;
                let _ = self.git(mirror, &["update-ref", "-d", &wip]).await;
                tracing::info!(issue, "uncommitted work restored from {wip}");
            }
            Err(why) => {
                let _ = self.git(tree, &["cherry-pick", "--abort"]).await;
                let _ = self.git(tree, &["reset", "--hard", "-q"]).await;
                tracing::warn!(issue, %why, "saved work no longer applies; it stays on {wip}");
            }
        }
    }

    /// Measures the work root as of `now`.
    async fn measure(&self, now: SystemTime, cap: u64) -> DiskReport {
        let root = self.root.clone();
        let sizes = tokio::task::spawn_blocking(move || {
            let mut by = (0, 0, 0, vec![]);
            for (name, path) in children(&root) {
                match name.as_str() {
                    "caches" => by.0 += size(&path),
                    "mirrors" => by.1 += size(&path),
                    "worktrees" => {
                        for (name, tree) in children(&path) {
                            let issue = name.strip_prefix("issue-").and_then(|n| n.parse().ok());
                            match issue {
                                Some(issue) => by.3.push((issue, size(&tree))),
                                None => by.2 += size(&tree),
                            }
                        }
                    }
                    _ => by.2 += size(&path),
                }
            }
            by
        });
        let (caches, mirrors, other, trees) = sizes.await.unwrap_or_default();
        let mut worktrees: Vec<WorktreeDisk> = trees
            .into_iter()
            .map(|(issue, bytes): (i64, u64)| WorktreeDisk {
                issue,
                bytes,
                active: self.in_use(issue),
                idle_secs: now
                    .duration_since(self.used_at(issue))
                    .unwrap_or_default()
                    .as_secs(),
            })
            .collect();
        worktrees.sort_by_key(|w| std::cmp::Reverse(w.idle_secs));
        let trees: u64 = worktrees.iter().map(|w| w.bytes).sum();
        let used = caches + mirrors + other + trees;
        DiskReport {
            used_bytes: used,
            cap_bytes: cap,
            caches_bytes: caches,
            mirrors_bytes: mirrors,
            full: used > cap,
            worktrees,
            removed: vec![],
        }
    }

    /// One clean-up pass at `now`: idle worktrees removed, then eviction down to the eviction
    /// threshold; the disk as it is left.
    pub async fn gc(&self, now: SystemTime, limits: &RunnerLimits) -> DiskReport {
        let mut removed = vec![];
        let idle = Duration::from_secs(limits.workspace_idle_secs);
        for issue in self.held() {
            let unused = now.duration_since(self.used_at(issue)).unwrap_or_default();
            if unused >= idle && !self.in_use(issue) && self.retire(issue).await.is_ok() {
                removed.push(issue);
            }
        }
        let cap = limits.disk_cap_bytes;
        let evict_at = (cap as u128 * u128::from(limits.disk_evict_percent) / 100) as u64;
        let mut report = self.measure(now, cap).await;
        while report.used_bytes > evict_at {
            let oldest = report.worktrees.iter().find(|w| !w.active).map(|w| w.issue);
            if let Some(issue) = oldest
                && self.retire(issue).await.is_ok()
            {
                tracing::info!(issue, "worktree evicted for room");
                removed.push(issue);
            } else if !self.evict_cache().await {
                break;
            }
            report = self.measure(now, cap).await;
        }
        report.removed = removed;
        report
    }

    /// Removes the least recently changed build cache of a repo with no worktree in use;
    /// `false` when there is none.
    async fn evict_cache(&self) -> bool {
        let busy: Vec<String> = self
            .in_use
            .lock()
            .expect("in_use")
            .keys()
            .flat_map(|i| self.trees(*i))
            .filter_map(|t| Self::mirror_of(&t))
            .filter_map(|m| Some(m.file_stem()?.to_str()?.to_owned()))
            .collect();
        let changed = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
        let mut caches: Vec<(Option<SystemTime>, PathBuf)> = children(&self.root.join("caches"))
            .into_iter()
            .filter(|(name, _)| !busy.contains(name))
            .map(|(_, path)| (changed(&path), path))
            .collect();
        caches.sort();
        let Some((_, oldest)) = caches.first() else {
            return false;
        };
        tracing::info!(cache = %oldest.display(), "build cache evicted for room");
        std::fs::remove_dir_all(oldest).is_ok()
    }
}

#[cfg(test)]
mod tests;
