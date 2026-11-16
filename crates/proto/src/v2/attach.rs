//! Attachments of an AI session's messages (E4): a file the Core keeps with the session and hands
//! to the session's runner, which writes it into the session's folder before the message that
//! names it goes to the harness.
//!
//! `agent.attach` carries one whole file, base64, in one frame: [`MAX_ATTACHMENT_BYTES`] keeps
//! that frame under a WebSocket peer's default 16 MiB frame limit. The runner answers with the
//! absolute path it wrote (`AgentAttached`); a runner that takes the op lists it among its agent
//! driver's commands, and the Core sends it to no other.

use serde::{Deserialize, Serialize};

pub const OP_AGENT_ATTACH: &str = "agent.attach";

/// The largest attachment, in bytes: 10 MiB is about 13.4 MiB of base64, one frame.
pub const MAX_ATTACHMENT_BYTES: usize = 10 * 1024 * 1024;

/// The longest attachment name, in bytes.
pub const MAX_ATTACHMENT_NAME: usize = 255;

/// Where in a session's folder its attachments are written: `<folder>/.ainkrad/attachments`.
pub const ATTACHMENTS_DIR: [&str; 2] = [".ainkrad", "attachments"];

/// Core to runner: write file `id` into session `session`'s folder.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentAttach {
    pub session: String,
    /// The Core's id, `at_…`.
    pub id: String,
    /// The name the user gave it; the runner derives the file's name from it
    /// ([`attachment_file_name`]), never uses it as a path.
    pub name: String,
    /// The file, standard base64.
    pub data: String,
}

/// No `Debug` of the bytes: a file is the user's own.
impl std::fmt::Debug for AgentAttach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentAttach")
            .field("session", &self.session)
            .field("id", &self.id)
            .field("data", &self.data.len())
            .finish_non_exhaustive()
    }
}

/// Runner to Core: where the file now is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AgentAttached {
    pub session: String,
    pub id: String,
    /// Absolute, inside the session's folder.
    pub path: String,
}

/// Whether `id` is an attachment id: `at_` and 1 to 61 of `[a-z0-9]`.
pub fn valid_attachment_id(id: &str) -> bool {
    id.strip_prefix("at_").is_some_and(|b| {
        (1..=61).contains(&b.len())
            && b.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    })
}

/// A name a user may give an attachment: 1 to [`MAX_ATTACHMENT_NAME`] bytes, no `/` or `\`, no
/// control character (NUL included), and not `.` or `..`.
pub fn valid_attachment_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_ATTACHMENT_NAME
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|c| c == '/' || c == '\\' || c.is_control())
}

/// The file name an attachment is written under: `<id>-<name>` with every byte outside
/// `[A-Za-z0-9._-]` made `_` and no leading dot, so it is one plain path component whatever the
/// name was, and the id keeps two of the same name apart.
pub fn attachment_file_name(id: &str, name: &str) -> String {
    let safe: String = name
        .chars()
        .take(100)
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '.' | '_' | '-' => c,
            _ => '_',
        })
        .collect();
    format!("{id}-{}", safe.trim_start_matches('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_checked_and_file_names_are_one_plain_component() {
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "a\0b",
            "a\nb",
            &"x".repeat(256),
        ] {
            assert!(!valid_attachment_name(bad), "{bad:?}");
        }
        for good in [
            "shot.png",
            "..png",
            "a b (1).pdf",
            "صورة.png",
            &"x".repeat(255),
        ] {
            assert!(valid_attachment_name(good), "{good:?}");
        }
        assert_eq!(attachment_file_name("at_1", "a b.png"), "at_1-a_b.png");
        assert_eq!(attachment_file_name("at_1", "../x"), "at_1-_x");
        assert_eq!(attachment_file_name("at_1", "..png"), "at_1-png");
        assert_eq!(attachment_file_name("at_1", "صورة.png"), "at_1-____.png");
        assert!(valid_attachment_id("at_0z9"));
        for bad in [
            "at_",
            "at_A",
            "as_1",
            "at_../x",
            &format!("at_{}", "a".repeat(62)),
        ] {
            assert!(!valid_attachment_id(bad), "{bad:?}");
        }
    }
}
