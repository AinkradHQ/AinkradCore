//! The revert logic of E14 (moved from the runner's `agent/files.rs`, which keeps its copy only for
//! legacy sessions until 0.11): reverse-applying a session's recorded edits, falling back to the
//! file's git `HEAD` copy.

use std::path::Path;
use std::process::{Command as Proc, Stdio};

use ainkrad_proto::v2::{RevertEdit, RevertResult};

/// What a revert will do to a file.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// Leave the file with these bytes; the result says how they were got.
    Write(Vec<u8>, RevertResult),
    /// The session created it: remove it.
    Delete,
    /// Change nothing (`Conflict` or `Impossible`).
    Refused(RevertResult),
}

/// The text of `rel` at git `HEAD`, read with the plumbing `cat-file` (no filter, hook or
/// textconv runs): `None` when untracked, not UTF-8, or no repo.
pub(super) fn head_blob(root: &Path, rel: &str) -> Option<String> {
    let out = Proc::new("git")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(["-c", "safe.directory=*"])
        .args(["cat-file", "blob"])
        .arg(format!("HEAD:./{rel}"))
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8(out.stdout).ok())
        .flatten()
}

/// What a reversal leaves in the file.
#[derive(Debug, PartialEq, Eq)]
pub enum Reversal {
    /// The file's new text, and how it was got (`Reverted` or `Restored`).
    Content(String, RevertResult),
    /// The session created the file: it goes.
    Delete,
}

type Refused = (RevertResult, &'static str);

/// The file as it was before `edits` (the session's recorded ones, NEWEST FIRST), from its
/// `current` text (`None`: the file is absent). Each edit is undone by putting its `old` text
/// where its `new` text is; the file must still hold that text exactly once, else nothing is
/// changed (`Conflict`). A write (empty `old`) is the file's creation or whole replacement: it is
/// restored from `head` when git tracks it, else deleted. What cannot be undone (a cut text, a
/// removal inside a file) falls back to `head`, or is `Impossible`.
pub fn reverse(
    current: Option<String>,
    edits: &[RevertEdit],
    truncated: bool,
    head: impl FnOnce() -> Option<String>,
) -> Result<Reversal, Refused> {
    let restore = |head: Option<String>, why: &'static str| match head {
        Some(text) => Ok(Reversal::Content(text, RevertResult::Restored)),
        None => Err((RevertResult::Impossible, why)),
    };
    if truncated || edits.is_empty() {
        return restore(
            head(),
            "the recorded edits cannot be reversed and git has no copy",
        );
    }
    let mut cur = current;
    for e in edits {
        if e.old.is_empty() && !e.new.is_empty() {
            if cur.as_deref() != Some(e.new.as_str()) {
                return Err((
                    RevertResult::Conflict,
                    "the file changed since the session wrote it",
                ));
            }
            return Ok(match head() {
                Some(text) => Reversal::Content(text, RevertResult::Restored),
                None => Reversal::Delete,
            });
        }
        if e.new.is_empty() {
            match cur {
                None => cur = Some(e.old.clone()),
                Some(_) => {
                    return restore(
                        head(),
                        "a removed text cannot be placed again and git has no copy",
                    );
                }
            }
            continue;
        }
        let Some(text) = cur.as_deref() else {
            return Err((RevertResult::Conflict, "the file is gone"));
        };
        cur = Some(match text.matches(&e.new).count() {
            0 => {
                return Err((
                    RevertResult::Conflict,
                    "the file no longer holds the edited text",
                ));
            }
            1 => text.replacen(&e.new, &e.old, 1),
            _ => {
                return Err((
                    RevertResult::Conflict,
                    "the edited text appears more than once",
                ));
            }
        });
    }
    Ok(Reversal::Content(
        cur.unwrap_or_default(),
        RevertResult::Reverted,
    ))
}
