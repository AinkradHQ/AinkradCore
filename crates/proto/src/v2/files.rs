//! A session's folder, on its runner (E14): list one level (`agent.files`), revert one file to
//! what it was before the session's recorded edits (`agent.revert`), write one file
//! (`agent.write`). The folder is the one the runner recorded for the session, never a path the
//! Core names; every path below is relative to it, and the runner refuses `..`, a symlink on the
//! way and (for a write) anything under `.git`. A runner that takes an op lists it among its agent
//! driver's commands; the Core sends it to no other. A runner that sends `effort` handling lists
//! [`CAP_EFFORT`].

use serde::{Deserialize, Serialize};

pub const OP_AGENT_FILES: &str = "agent.files";
pub const OP_AGENT_REVERT: &str = "agent.revert";
pub const OP_AGENT_WRITE: &str = "agent.write";

/// Listed by a runner whose harnesses take `Policy::effort` (older runners refuse the field).
pub const CAP_EFFORT: &str = "effort";

/// The most entries one `agent.files` answer holds; the rest is `truncated`.
pub const MAX_FOLDER_ENTRIES: usize = 500;
/// The most bytes `agent.write` puts in a file.
pub const MAX_WRITE_BYTES: usize = 256 * 1024;
/// The most bytes of reasoning one `thinking` transcript entry holds.
pub const MAX_THINKING_BYTES: usize = 16 * 1024;
/// The most bytes of recorded edits one `agent.revert` carries (one frame).
pub const MAX_REVERT_BYTES: usize = 2 * 1024 * 1024;

/// The levels of `Policy::effort`, as the API names them.
pub const EFFORTS: [&str; 4] = ["low", "medium", "high", "max"];

/// Core to runner: the entries of `dir` of session `session`'s folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentFiles {
    pub session: String,
    /// Relative to the folder; empty is the folder itself.
    pub dir: String,
}

/// One entry of a folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FolderEntry {
    pub name: String,
    pub dir: bool,
    /// Bytes, for a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// Runner to Core: one level of a folder, directories first, then by name, at most
/// [`MAX_FOLDER_ENTRIES`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentFolder {
    pub session: String,
    pub dir: String,
    pub entries: Vec<FolderEntry>,
    pub truncated: bool,
}

/// One recorded edit of a file: the text it took out and the text it put in.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RevertEdit {
    pub old: String,
    pub new: String,
}

/// Core to runner: put `path` back as it was before the session's edits. `edits` are the recorded
/// ones, newest first, which the runner reverse-applies (`new` back to `old`); `truncated` says a
/// recorded text was cut, so they cannot be reversed and the file is restored from git `HEAD`
/// instead. No `Debug` of the texts: they are the user's own.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentRevert {
    pub session: String,
    /// Relative to the folder.
    pub path: String,
    pub edits: Vec<RevertEdit>,
    #[serde(default)]
    pub truncated: bool,
}

impl std::fmt::Debug for AgentRevert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentRevert")
            .field("session", &self.session)
            .field("path", &self.path)
            .field("edits", &self.edits.len())
            .finish_non_exhaustive()
    }
}

/// What a revert did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevertResult {
    /// The recorded edits were reversed in the file.
    Reverted,
    /// The file was created by the session: it is deleted.
    Deleted,
    /// The file was restored from git `HEAD` (edits that cannot be reversed).
    Restored,
    /// The file no longer holds the recorded text; nothing was changed.
    Conflict,
    /// Nothing can revert it (no usable edits, and not tracked in git); nothing was changed.
    Impossible,
    /// A result from a newer runner. Never sent.
    #[serde(other)]
    Unknown,
}

/// Runner to Core: the outcome of an `agent.revert`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentReverted {
    pub session: String,
    pub path: String,
    pub result: RevertResult,
    /// Why, for a refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Core to runner: write `content` to `path` of session `session`'s folder (parent folders are
/// created inside it). No `Debug` of the text.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentWrite {
    pub session: String,
    pub path: String,
    pub content: String,
}

impl std::fmt::Debug for AgentWrite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentWrite")
            .field("session", &self.session)
            .field("path", &self.path)
            .field("content", &self.content.len())
            .finish_non_exhaustive()
    }
}

/// Runner to Core: the file was written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentWritten {
    pub session: String,
    pub path: String,
    pub bytes: u64,
}

/// A path relative to a session's folder, cleaned: `a/b`, from `a//b/`, `./a/b` or an absolute
/// `folder/a/b` (`folder` is the session's). `None` for `..`, a NUL or other control character, a
/// backslash, an absolute path outside `folder`, or more than 1024 bytes. The empty string is the
/// folder itself. Both ends use it, so they cannot drift.
pub fn folder_relative(folder: &str, path: &str) -> Option<String> {
    if path.len() > 1024 || path.chars().any(|c| c.is_control() || c == '\\') {
        return None;
    }
    let rel = match path.strip_prefix('/') {
        Some(_) => {
            let root = folder.trim_end_matches('/');
            // The folder itself, or something under it: `/w/sibling` is not inside `/w/s`.
            let rest = path.strip_prefix(root)?;
            match rest {
                "" => "",
                r => r.strip_prefix('/')?,
            }
        }
        None => path,
    };
    let mut parts = Vec::new();
    for p in rel.split('/') {
        match p {
            "" | "." => {}
            ".." => return None,
            p => parts.push(p),
        }
    }
    Some(parts.join("/"))
}

/// The most bytes of one wire path component, of a whole wire path, and the most components.
pub const WIRE_COMPONENT_MAX: usize = 255;
pub const WIRE_PATH_MAX: usize = 4096;
pub const WIRE_DEPTH_MAX: usize = 64;

/// Why `path` is not a wire path (E15 §4.3), or `None` when it is: relative UTF-8 with `/`
/// separators; no empty, `.` or `..` component; no NUL or `\`; each component at most
/// [`WIRE_COMPONENT_MAX`] bytes, at most [`WIRE_DEPTH_MAX`] of them and [`WIRE_PATH_MAX`] bytes in
/// all; and no `.git` component (matched without case: on a case-insensitive disk `.GIT` is
/// `.git`). The one check for `sync.*`, `job.run` and the workspace file routes, at both ends.
pub fn wire_path_problem(path: &str) -> Option<&'static str> {
    if path.is_empty() {
        return Some("the path is empty");
    }
    if path.len() > WIRE_PATH_MAX {
        return Some("the path is too long");
    }
    if path.contains('\0') || path.contains('\\') {
        return Some("the path holds a NUL or a backslash");
    }
    if path.starts_with('/') {
        return Some("the path is absolute");
    }
    let mut depth = 0;
    for c in path.split('/') {
        depth += 1;
        match c {
            "" => return Some("the path has an empty component"),
            "." | ".." => return Some("the path has a . or .. component"),
            c if c.len() > WIRE_COMPONENT_MAX => return Some("a path component is too long"),
            c if c.eq_ignore_ascii_case(".git") => return Some("the path is inside .git"),
            _ => {}
        }
    }
    (depth > WIRE_DEPTH_MAX).then_some("the path is too deep")
}

#[cfg(test)]
mod tests {
    use super::folder_relative as rel;
    use super::wire_path_problem as wire;

    #[test]
    fn wire_paths_are_relative_clean_and_never_git() {
        for ok in ["a", "a/b.rs", "src/.gitignore", ".github/x", "a/.git-keep"] {
            assert_eq!(wire(ok), None, "{ok}");
        }
        for bad in [
            "",
            "/a",
            "a/",
            "a//b",
            "./a",
            "a/./b",
            "../a",
            "a/..",
            "a\0b",
            "a\\b",
            ".git",
            "a/.git/config",
            ".GIT/hooks/x",
        ] {
            assert!(wire(bad).is_some(), "{bad:?}");
        }
        assert!(wire(&"x".repeat(256)).is_some());
        assert_eq!(wire(&"x".repeat(255)), None);
        assert!(wire(&vec!["a"; 65].join("/")).is_some());
        assert_eq!(wire(&vec!["a"; 64].join("/")), None);
        assert!(
            wire(&vec!["x".repeat(200); 21].join("/")).is_some(),
            "over 4096 bytes"
        );
    }

    #[test]
    fn paths_are_cleaned_and_never_leave_the_folder() {
        assert_eq!(rel("/w/s", "").as_deref(), Some(""));
        assert_eq!(rel("/w/s", "./a//b/").as_deref(), Some("a/b"));
        assert_eq!(rel("/w/s", "/w/s/a/b").as_deref(), Some("a/b"));
        assert_eq!(rel("/w/s/", "/w/s").as_deref(), Some(""));
        assert_eq!(rel("/w/s", "/w/other/a"), None);
        assert_eq!(rel("/w/s", "/w/sibling"), None);
        assert_eq!(rel("/w/s", "../a"), None);
        assert_eq!(rel("/w/s", "a/../../b"), None);
        assert_eq!(rel("/w/s", "a\0b"), None);
        assert_eq!(rel("/w/s", "a\\b"), None);
    }
}
