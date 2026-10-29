//! Per-issue git worktrees (E3.7). Each repo is cloned once, bare, into
//! `<work_root>/mirrors/`; each issue gets a worktree `<work_root>/worktrees/issue-<id>` on
//! its branch `citadel/<KEY>-<n>`, cut from the project's default branch. A later run of
//! the same issue reuses that worktree as it was left; a broken one is rebuilt on its
//! branch. Worktrees go when the server says their issue is closed (`Prune`), or when idle or
//! evicted for room (`disk`, E15.9); either way uncommitted work is first saved on
//! `refs/citadel/wip/<issue>` in the mirror and put back when the worktree is recreated. A
//! branch is pushed back to the repo's origin on request (`push`, E9.1).
//!
//! Multi-repo issues (E15.16): an issue touching several repos gets one worktree per repo under
//! its issue dir, `issue-<id>/<repo name>`, all on its one branch; one touching a single repo
//! keeps the issue dir as its worktree. When an issue's layout changes (a repo approved
//! mid-task), its worktrees move to their new places with every file in them, and loose files
//! are kept (`layout`).
//!
//! Every git command on a repo holds that repo's async lock, so concurrent setups never race
//! for git's own lock files (Paperclip's "could not lock config file"). One runner process
//! per work root: the lock is in-process.
//!
//! git runs from a cleared environment: its global config is a runner-owned file
//! (`GIT_CONFIG_GLOBAL`, the system one is off), it never prompts (`GIT_TERMINAL_PROMPT=0`),
//! and credentials come only from the runner's `GIT_ASKPASS` program, never from a URL or
//! argv. Harness processes get the same config variables, so a harness's own `HOME`
//! override (agy) cannot point git at another config. A git failure is the run's failure,
//! with git's stderr tail.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use ainkrad_proto::runner::{RepoDiff, Workspace};
use tokio::process::Command;
use tokio::sync::OwnedMutexGuard;

pub struct Workspaces {
    root: PathBuf,
    /// git's `HOME`, holding its global config file `config`.
    git_home: PathBuf,
    /// The git executable.
    pub git: PathBuf,
    /// Answers git's username and password prompts; without it a repo that needs auth
    /// fails with a clear reason. It runs with the git home as `HOME`.
    pub askpass: Option<PathBuf>,
    locks: Mutex<HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>,
    /// Issue → runs using its worktree; `prune` leaves these alone.
    in_use: Mutex<HashMap<i64, u32>>,
    /// Build caches by the files that mark a repo's kind (E15.9): each one found in a worktree
    /// points its variable at the repo's shared cache on this runner.
    pub cache_rules: Vec<CacheRule>,
}

/// A repo URL as a plain file name: its mirror's and its build cache's.
fn repo_name(repo: &str) -> String {
    repo.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '_',
        })
        .collect()
}

/// The last `max` bytes of `text`, trimmed.
fn tail(text: &str, max: usize) -> &str {
    let text = text.trim();
    &text[text.ceil_char_boundary(text.len().saturating_sub(max))..]
}

/// Lines of a new file, for its diff: none for a binary one (a NUL in its first 8 KiB, as git
/// decides) or one over `NEW_FILE_MAX` bytes, which is not read.
fn new_lines(path: &Path) -> u64 {
    const NEW_FILE_MAX: u64 = 4 * 1024 * 1024;
    let small = std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() <= NEW_FILE_MAX);
    let Some(bytes) = small.then(|| std::fs::read(path).ok()).flatten() else {
        return 0;
    };
    if bytes[..bytes.len().min(8192)].contains(&0) {
        return 0;
    }
    let lines = bytes.iter().filter(|&&b| b == b'\n').count() as u64;
    lines + u64::from(bytes.last().is_some_and(|&b| b != b'\n'))
}

impl Workspaces {
    pub fn new(work_root: PathBuf, git_home: PathBuf) -> Self {
        Self {
            root: work_root,
            git_home,
            git: PathBuf::from("git"),
            askpass: None,
            locks: Mutex::default(),
            in_use: Mutex::default(),
            cache_rules: CacheRule::defaults(),
        }
    }

    /// The issue's worktree.
    pub fn path(&self, issue: i64) -> PathBuf {
        self.root.join("worktrees").join(format!("issue-{issue}"))
    }

    fn mirror(&self, repo: &str) -> PathBuf {
        self.root
            .join("mirrors")
            .join(format!("{}.git", repo_name(repo)))
    }

    /// The variables every git, and every harness process, runs with.
    pub fn env(&self) -> Vec<(String, OsString)> {
        vec![
            (
                "GIT_CONFIG_GLOBAL".to_owned(),
                self.git_home.join("config").into(),
            ),
            ("GIT_CONFIG_NOSYSTEM".to_owned(), "1".into()),
            ("GIT_TERMINAL_PROMPT".to_owned(), "0".into()),
        ]
    }

    /// The repo's lock, keyed by its real path (`/var` is `/private/var` on macOS, and git
    /// records real paths).
    async fn lock(&self, mirror: &Path) -> OwnedMutexGuard<()> {
        let real = mirror
            .parent()
            .and_then(|dir| dir.canonicalize().ok())
            .zip(mirror.file_name())
            .map_or_else(|| mirror.to_owned(), |(dir, name)| dir.join(name));
        let lock = self
            .locks
            .lock()
            .expect("locks")
            .entry(real)
            .or_default()
            .clone();
        lock.lock_owned().await
    }

    /// `git args…` in `dir`, set up as every git here runs (see the module docs).
    fn command(&self, dir: &Path, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.git);
        cmd.args(args)
            .current_dir(dir)
            .env_clear()
            .env("HOME", &self.git_home)
            .envs(self.env())
            .stdin(Stdio::null())
            .kill_on_drop(true);
        for name in ["PATH", "LANG"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        if let Some(askpass) = &self.askpass {
            cmd.env("GIT_ASKPASS", askpass);
        }
        cmd
    }

    /// `git args…` in `dir`: its stdout, or why it failed with git's stderr tail.
    async fn git(&self, dir: &Path, args: &[&str]) -> Result<String, String> {
        let what = format!("git {}", args.first().unwrap_or(&""));
        let out = self.command(dir, args).output().await;
        let out = out.map_err(|e| format!("{what}: {e}"))?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let said = tail(&stderr, 500);
        let no_prompt = stderr.contains("terminal prompts disabled");
        if no_prompt && self.askpass.is_none() {
            return Err(format!(
                "{what}: the repo needs credentials and this runner has none (set \
                 CITADEL_GIT_ASKPASS): {said}"
            ));
        }
        Err(format!("{what} failed ({}): {said}", out.status))
    }

    /// Sets the commit identity agents commit as, in the runner-owned global config: `name`
    /// and `email` when given, else whatever that file already holds. The identity it ends
    /// up with, or why there is none (the runner must not start without one).
    pub async fn set_identity(
        &self,
        name: Option<&str>,
        email: Option<&str>,
    ) -> Result<(String, String), String> {
        let config = self.git_home.join("config");
        std::fs::create_dir_all(&self.git_home)
            .and_then(|()| {
                let mut open = std::fs::OpenOptions::new();
                open.create(true).append(true).open(&config).map(drop)
            })
            .map_err(|e| format!("{}: {e}", config.display()))?;
        let mut found = vec![];
        for (key, value) in [("user.name", name), ("user.email", email)] {
            if let Some(value) = value {
                if value.trim().is_empty() || value.chars().any(char::is_control) {
                    return Err(format!("bad {key} {value:?}"));
                }
                self.git(&self.git_home, &["config", "--global", key, value])
                    .await?;
            }
            match self
                .git(&self.git_home, &["config", "--global", "--get", key])
                .await
            {
                Ok(value) if !value.trim().is_empty() => found.push(value.trim().to_owned()),
                _ => {
                    return Err(format!(
                        "no git {key} for agent commits: pass --git-name and --git-email, or \
                         set it in {}",
                        config.display()
                    ));
                }
            }
        }
        let [name, email] = <[String; 2]>::try_from(found).expect("two keys");
        Ok((name, email))
    }

    /// What the askpass answers git's username and password prompts with, for redaction.
    // ponytail: asked once, for a generic host; an askpass that answers per host may give
    // other values for a real repo. Asking per repo at clone time is the upgrade.
    pub async fn askpass_answers(&self) -> Vec<String> {
        let Some(askpass) = &self.askpass else {
            return vec![];
        };
        let mut answers = vec![];
        for prompt in [
            "Username for 'https://citadel': ",
            "Password for 'https://citadel': ",
        ] {
            let mut cmd = Command::new(askpass);
            cmd.arg(prompt)
                .env_clear()
                .env("HOME", &self.git_home)
                .stdin(Stdio::null())
                .kill_on_drop(true);
            if let Some(path) = std::env::var_os("PATH") {
                cmd.env("PATH", path);
            }
            let out = cmd.output();
            match tokio::time::timeout(std::time::Duration::from_secs(10), out).await {
                Ok(Ok(out)) if out.status.success() => {
                    answers.push(String::from_utf8_lossy(&out.stdout).trim().to_owned());
                }
                _ => tracing::warn!("the git askpass did not answer; its secrets are not known"),
            }
        }
        answers
    }

    /// Where `ws`'s worktree of `issue` is: the issue dir, or a dir of it named after the repo
    /// when the issue touches several (`nested`).
    pub fn tree(&self, issue: i64, ws: &Workspace, nested: bool) -> PathBuf {
        match nested {
            true => self.path(issue).join(&ws.name),
            false => self.path(issue),
        }
    }

    /// The issue's worktrees on disk: its dir, or the worktrees in it.
    pub(crate) fn trees(&self, issue: i64) -> Vec<PathBuf> {
        let dir = self.path(issue);
        if dir.join(".git").is_file() {
            return vec![dir];
        }
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return vec![];
        };
        let mut all: Vec<PathBuf> = entries
            .filter_map(|e| Some(e.ok()?.path()))
            .filter(|p| p.join(".git").is_file())
            .collect();
        all.sort();
        all
    }

    /// The issue's worktrees, one per repo of `trees` (the issue dir itself for one), created or
    /// reused, marked in use until `release`. The issue dir.
    pub async fn prepare(&self, issue: i64, trees: &[Workspace]) -> Result<PathBuf, String> {
        if let Some(why) = trees.iter().find_map(Workspace::problem) {
            return Err(why);
        }
        let nested = trees.len() > 1;
        if nested && trees.iter().any(|t| t.name.is_empty()) {
            return Err("every repo of a multi-repo workspace needs a name".to_owned());
        }
        *self
            .in_use
            .lock()
            .expect("in_use")
            .entry(issue)
            .or_default() += 1;
        let set = self.setup_all(issue, trees, nested).await;
        match set.is_ok() {
            true => self.touch(issue),
            false => self.release(issue),
        }
        set.map(|()| self.path(issue))
    }

    /// Sets up every tree, after moving or retiring those of a layout that no longer fits
    /// (`layout`).
    async fn setup_all(&self, issue: i64, trees: &[Workspace], nested: bool) -> Result<(), String> {
        let wanted: Vec<PathBuf> = trees.iter().map(|t| self.tree(issue, t, nested)).collect();
        self.relayout(issue, trees, &wanted, nested).await?;
        for (ws, path) in trees.iter().zip(&wanted) {
            self.setup(issue, ws, path).await?;
        }
        self.restore_loose(issue)
    }

    pub fn release(&self, issue: i64) {
        self.touch(issue);
        let mut in_use = self.in_use.lock().expect("in_use");
        if let Some(n) = in_use.get_mut(&issue) {
            *n -= 1;
            if *n == 0 {
                in_use.remove(&issue);
            }
        }
    }

    async fn setup(&self, issue: i64, ws: &Workspace, path: &Path) -> Result<(), String> {
        let io = |what: &Path, e: std::io::Error| format!("{}: {e}", what.display());
        let (mirror, path) = (self.mirror(&ws.repo), path.to_owned());
        for dir in [
            &self.git_home,
            &self.root.join("mirrors"),
            &self.root.join("worktrees"),
        ] {
            std::fs::create_dir_all(dir).map_err(|e| io(dir, e))?;
        }
        let config = self.git_home.join("config");
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config)
            .map_err(|e| io(&config, e))?;
        let utf8 = |p: &Path| p.to_str().map(str::to_owned).ok_or("path is not UTF-8");
        let _repo = self.lock(&mirror).await;
        if !mirror.join("HEAD").exists() {
            // Cloned aside and moved in, so a failed clone leaves no half-made mirror.
            let fresh = mirror.with_extension("cloning");
            let _ = std::fs::remove_dir_all(&fresh);
            let args = ["clone", "--bare", "--", &ws.repo, &utf8(&fresh)?];
            self.git(&self.root, &args).await?;
            std::fs::rename(&fresh, &mirror).map_err(|e| io(&mirror, e))?;
        }
        let refspec = format!("+refs/heads/{0}:refs/remotes/origin/{0}", ws.base);
        self.git(&mirror, &["fetch", "origin", &refspec]).await?;
        let inside = ["rev-parse", "--is-inside-work-tree"];
        if path.join(".git").is_file() && self.git(&path, &inside).await.is_ok() {
            return Ok(());
        }
        if path.exists() {
            std::fs::remove_dir_all(&path).map_err(|e| io(&path, e))?;
        }
        self.git(&mirror, &["worktree", "prune"]).await?;
        let branch = format!("refs/heads/{}", ws.branch);
        let has_branch = ["rev-parse", "--verify", "--quiet", &branch];
        let dir = utf8(&path)?;
        if self.git(&mirror, &has_branch).await.is_ok() {
            self.git(&mirror, &["worktree", "add", &dir, &ws.branch])
                .await?;
        } else {
            let base = format!("refs/remotes/origin/{}", ws.base);
            let add = ["worktree", "add", "-b", &ws.branch, &dir, &base];
            self.git(&mirror, &add).await?;
        }
        self.restore_wip(issue, &mirror, &path).await;
        Ok(())
    }

    /// Files the issue's worktree differs from `base` in (E15.7): committed or not, and new
    /// files git does not ignore. Summed over the worktrees of `trees` (E15.16).
    pub async fn diff_files(&self, issue: i64, trees: &[Workspace]) -> Result<u32, String> {
        let stats = self.diff_stats(issue, trees).await?;
        Ok(stats.iter().map(|d| d.files).sum())
    }

    /// Each worktree of `trees` against its `base` (1.18), in order: files changed (committed or
    /// not) or new and not ignored, and lines added and removed, a new text file's lines all
    /// added. Read-only: it takes none of git's optional locks, so it never races the agent's
    /// own git commands.
    pub async fn diff_stats(
        &self,
        issue: i64,
        trees: &[Workspace],
    ) -> Result<Vec<RepoDiff>, String> {
        let nested = trees.len() > 1;
        let mut stats = vec![];
        for ws in trees {
            let path = self.tree(issue, ws, nested);
            let base = format!("refs/remotes/origin/{}", ws.base);
            let quiet = ["--no-optional-locks"];
            let numstat = [&quiet[..], &["diff", "--numstat", "-z", &base, "--"]].concat();
            let new = [
                &quiet[..],
                &["ls-files", "-z", "--others", "--exclude-standard"],
            ]
            .concat();
            let mut d = RepoDiff {
                repo: ws.name.clone(),
                ..RepoDiff::default()
            };
            let mut files = std::collections::BTreeSet::new();
            // `-z`: `added\tremoved\tpath\0`, a rename's paths in two more fields; `-` for binary.
            let out = self.git(&path, &numstat).await?;
            let mut fields = out.split('\0');
            while let Some(head) = fields.next().filter(|f| !f.is_empty()) {
                let mut parts = head.splitn(3, '\t');
                let (added, removed) = (parts.next(), parts.next());
                let name = match parts.next() {
                    Some("") => {
                        fields.next();
                        fields.next()
                    }
                    name => name,
                };
                d.insertions += added.and_then(|n| n.parse().ok()).unwrap_or(0);
                d.deletions += removed.and_then(|n| n.parse().ok()).unwrap_or(0);
                files.extend(name.map(str::to_owned));
            }
            for name in self
                .git(&path, &new)
                .await?
                .split('\0')
                .filter(|n| !n.is_empty())
            {
                d.insertions += new_lines(&path.join(name));
                files.insert(name.to_owned());
            }
            d.files = files.len() as u32;
            stats.push(d);
        }
        Ok(stats)
    }

    /// The issues it holds a worktree for.
    pub fn held(&self) -> Vec<i64> {
        let Ok(entries) = std::fs::read_dir(self.root.join("worktrees")) else {
            return vec![];
        };
        let mut issues: Vec<i64> = entries
            .filter_map(|e| {
                e.ok()?
                    .file_name()
                    .to_str()?
                    .strip_prefix("issue-")?
                    .parse()
                    .ok()
            })
            .collect();
        issues.sort_unstable();
        issues
    }

    /// Removes the worktrees of `issues`, except those in use (`retire`). The branches stay in
    /// the mirror, so a reopened issue continues where it was.
    pub async fn prune(&self, issues: Vec<i64>) {
        for issue in issues {
            match self.retire(issue).await {
                Ok(()) => tracing::info!(issue, "worktree pruned"),
                Err(why) => tracing::warn!(issue, %why, "worktree kept"),
            }
        }
    }
}

mod disk;
mod layout;
mod push;
mod read;
pub use disk::CacheRule;

#[cfg(test)]
pub(crate) mod tests;
