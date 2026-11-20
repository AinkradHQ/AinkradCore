//! The revert logic of E14 (moved from the runner's `agent/files.rs`, which keeps its copy only for
//! legacy sessions until 0.11): reverse-applying a session's recorded edits, falling back to the
//! file's git `HEAD` copy.

use std::path::Path;

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

/// The text of `rel` at its repo's `HEAD`, through the sealed git of E15 H1 (an explicit,
/// verified `--git-dir`; no lazy fetch, no global config): see [`ainkrad_sys::git`].
pub(super) fn head_blob(root: &Path, rel: &str) -> Option<String> {
    ainkrad_sys::git::head_blob(root, rel)
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
