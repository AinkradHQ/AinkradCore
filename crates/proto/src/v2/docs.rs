//! Session documents (Lore E10-2, D-28): the Markdown files an AI session writes in its own folder.
//!
//! One op, `agent.docs`, with three actions, all scoped by the runner to the folder it recorded for the
//! session (never one the Core names), never through a symlink, and only to plain `.md` files:
//!
//! - `list`: the `.md` files created or changed since the session's harness started (the runner takes a
//!   metadata baseline of the folder just before the start), with the sha-256 of each.
//! - `read`: one file's text.
//! - `write`: replaces one file's text, only when its current sha-256 is `base` (a Lore edit that flows back).
//!   A new file takes no `base`.
//!
//! A runner that takes the op lists it among its agent driver's commands; the Core sends it to no other.

use serde::{Deserialize, Serialize};

pub const OP_AGENT_DOCS: &str = "agent.docs";

/// The largest file read or written, in bytes (one frame; Lore notes may be larger, files here may not).
pub const DOC_MAX_BYTES: usize = 1 << 20;
/// The most files one `list` answers.
pub const DOC_MAX_FILES: usize = 200;
/// The deepest folder `list` walks into, and the most entries it looks at.
pub const DOC_MAX_DEPTH: usize = 8;
pub const DOC_MAX_VISITED: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocsAction {
    List,
    Read,
    Write,
}

/// Core to runner.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentDocs {
    /// The Core's session id, `as_…`.
    pub session: String,
    pub action: DocsAction,
    /// `read` and `write`: a path from `valid_doc_path`, relative to the session's folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `write`: the new text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// `write`: the sha-256 (lowercase hex) the file must have now; absent, the file must not exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
}

/// A document is the user's own: no `Debug` of its text.
impl std::fmt::Debug for AgentDocs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentDocs")
            .field("session", &self.session)
            .field("action", &self.action)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// One file of a `list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DocFile {
    pub path: String,
    pub size: u64,
    /// Lowercase hex sha-256 of the bytes.
    pub sha256: String,
}

/// Runner to Core. `list` fills `files`; `read` fills `text` and `sha256`; `write` fills `sha256` (the new one).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Default)]
pub struct DocsReply {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<DocFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl std::fmt::Debug for DocsReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocsReply")
            .field("files", &self.files.len())
            .finish_non_exhaustive()
    }
}

/// Names an AI harness loads as instructions: a Lore edit never writes them (a note must not steer a session).
pub fn is_instruction_file(name: &str) -> bool {
    ["claude.md", "agents.md", "gemini.md", "soul.md"].contains(&name.to_ascii_lowercase().as_str())
}

/// A path the ops accept: relative, `/`-separated, at most 240 bytes and 8 parts, no empty, `.`, `..` or
/// dotted part (so no `.git`, `.ainkrad` or `.claude`), no `\`, NUL or control character, `node_modules` or
/// `target` part, ending in `.md` (any case) and not an instruction file.
pub fn valid_doc_path(p: &str) -> bool {
    let parts: Vec<&str> = p.split('/').collect();
    let Some(name) = parts.last() else {
        return false;
    };
    p.len() <= 240
        && parts.len() <= DOC_MAX_DEPTH
        && parts.iter().all(|s| {
            !s.is_empty()
                && !s.starts_with('.')
                && *s != "node_modules"
                && *s != "target"
                && !s.chars().any(|c| c == '\\' || c.is_control())
        })
        && name.len() > 3
        && name.to_ascii_lowercase().ends_with(".md")
        && !is_instruction_file(name)
}

/// A lowercase hex sha-256.
pub fn valid_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_markdown_paths_inside_the_folder_pass() {
        for ok in ["plan.md", "docs/login-plan.md", "a/b/c/NOTES.MD", "é.md"] {
            assert!(valid_doc_path(ok), "{ok:?}");
        }
        for bad in [
            "",
            "/etc/x.md",
            "../x.md",
            "a/../x.md",
            "a//x.md",
            "./x.md",
            ".git/x.md",
            "a/.hidden/x.md",
            ".md",
            "x.txt",
            "x.md/",
            "a\\b.md",
            "a\0.md",
            "a\n.md",
            "node_modules/x/readme.md",
            "target/doc.md",
            "CLAUDE.md",
            "docs/agents.md",
            &format!("{}.md", "x".repeat(240)),
            "a/b/c/d/e/f/g/h/i.md",
        ] {
            assert!(!valid_doc_path(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_sha_is_64_lowercase_hex() {
        assert!(valid_sha256(&"a".repeat(64)));
        assert!(!valid_sha256(&"A".repeat(64)));
        assert!(!valid_sha256("abc"));
    }
}
