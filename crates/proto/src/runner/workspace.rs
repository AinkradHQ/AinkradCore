//! Where a run works (1.1, 1.16): its issue's git worktree per repo, and each repo's diff a
//! runner reports back (1.18).

use serde::{Deserialize, Serialize};

/// Where an issue's run works: a git worktree of `repo` on `branch`, cut from `base`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Workspace {
    /// A URL or path git can clone, never holding credentials (`repo_url_problem`).
    pub repo: String,
    /// The project's default branch.
    pub base: String,
    /// The issue's branch, `citadel/<project key>-<number>`.
    pub branch: String,
    /// Push the branch to the repo's origin when the run ends (1.7): its project is on a forge,
    /// where a PR is opened from it (E9.1).
    #[serde(default)]
    pub push: bool,
    /// The repo's name in its project (1.16): its worktree's directory in a multi-repo workspace.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The issue's other repos, in its project's order, when it touches several (1.16).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also: Vec<Workspace>,
    /// The sha the branch was last pushed at (1.28), `None` before its first push. The runner
    /// leases its push on it, so a rewritten branch lands only over the head it last saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_head: Option<String>,
}

impl Workspace {
    /// Why this workspace must not reach git, if it must not.
    pub fn problem(&self) -> Option<String> {
        let bad_name = self.name.starts_with('.')
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
        if bad_name {
            return Some(format!("bad repo name {:?}", self.name));
        }
        if self.also.len() > 15 || self.also.iter().any(|w| !w.also.is_empty()) {
            return Some("too many or nested repositories".into());
        }
        if let Some(why) = self.also.iter().find_map(Workspace::problem) {
            return Some(why);
        }
        repo_url_problem(&self.repo).or_else(|| {
            [&self.base, &self.branch]
                .into_iter()
                .find(|name| !branch_name_ok(name))
                .map(|name| format!("bad branch name {name:?}"))
        })
    }
}

/// Why `url` cannot be a project repo: an option-looking value (argv injection), or
/// credentials in an http(s) URL (they belong in the runner's GIT_ASKPASS, never in a URL
/// that logs and process lists keep).
pub fn repo_url_problem(url: &str) -> Option<String> {
    if url.is_empty()
        || url.len() > 2048
        || url.starts_with('-')
        || url.chars().any(char::is_control)
    {
        return Some(format!("bad repo URL {url:?}"));
    }
    if url.contains(['?', '#', '\'']) || url.chars().any(char::is_whitespace) {
        return Some("repo URLs may not contain secrets, fragments or whitespace".into());
    }
    let lower = url.to_ascii_lowercase();
    let valid = if lower.starts_with("https://") || lower.starts_with("ssh://") {
        let authority = url
            .split_once("://")
            .unwrap()
            .1
            .split('/')
            .next()
            .unwrap_or("");
        let host = authority.rsplit('@').next().unwrap_or("");
        !host.is_empty()
            && if lower.starts_with("https://") {
                !authority.contains('@')
            } else {
                !authority.split('@').next().unwrap_or("").contains(':') || !authority.contains('@')
            }
    } else if let Some((host, path)) = url.split_once(':') {
        host.contains('@')
            && !host.contains('/')
            && !path.is_empty()
            && host.split('@').all(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
    } else {
        false
    };
    (!valid)
        .then(|| "repo must use https or ssh without credentials; local paths are forbidden".into())
}

/// A plain branch name: `[A-Za-z0-9._/-]`, not starting with `-` or `/`, no `..`.
pub fn branch_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && !name.starts_with(['-', '/'])
        && !name.contains("..")
        && !name.contains("//")
        && !name.contains("@{")
        && !name.ends_with(['/', '.'])
        && !name
            .split('/')
            .any(|part| part.is_empty() || part.ends_with(".lock"))
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
}

/// One repo's worktree against its base (1.18): `git diff --numstat` plus untracked files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoDiff {
    /// The repo's name in its project; empty for an issue's only repo.
    #[serde(default)]
    pub repo: String,
    /// Files changed, added or untracked.
    pub files: u32,
    /// Lines added (an untracked text file's every line) and removed.
    pub insertions: u64,
    pub deletions: u64,
}
