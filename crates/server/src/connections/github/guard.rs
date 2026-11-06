//! What an operation may carry that the URL template cannot say (C2 review): the ref a branch
//! may be made at, the head of a pull request, files no `push` may touch, and whether an issue
//! number is really an issue or really a pull request. Also the build errors.

use std::fmt;

use serde_json::{Map, Value};

/// Why an input was refused; the text names a field, never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    UnknownOperation,
    UnknownField,
    Missing(&'static str),
    BadRepo,
    BadNumber,
    BadPath,
    BadQuery,
    BadBody,
    /// `create_branch` makes branches only: `ref` is `refs/heads/<name>` (never a tag).
    BadRef,
    /// `create_pr` heads are `branch` or `<this repo's owner>:branch`.
    BadHead,
    /// `put_file` does not write workflows or actions (`.github/workflows`, `.github/actions`).
    ProtectedPath,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOperation => f.write_str("no such GitHub operation"),
            Self::UnknownField => f.write_str("the input has a field this operation does not take"),
            Self::Missing(field) => write!(f, "the input needs {field:?}"),
            Self::BadRepo => f.write_str("\"repo\" is `owner/name`"),
            Self::BadNumber => f.write_str("\"number\" is a positive whole number"),
            Self::BadPath => {
                f.write_str("\"path\" is a file path inside the repository, with no `.` or `..`")
            }
            Self::BadQuery => f.write_str("\"query\" is a few plain name and value pairs"),
            Self::BadBody => {
                f.write_str("\"body\" is a JSON object this operation takes, at most 256 KiB")
            }
            Self::BadRef => f.write_str("\"ref\" is a new branch: `refs/heads/<name>`"),
            Self::BadHead => {
                f.write_str("\"head\" is a branch of this repository: `branch` or `<owner>:branch`")
            }
            Self::ProtectedPath => {
                f.write_str("workflow and action files (`.github/workflows`, `.github/actions`) cannot be written")
            }
        }
    }
}

impl std::error::Error for BuildError {}

/// What an issue number must be before an operation acts on it. GitHub treats a pull request as
/// an issue, so a call that needs `issues_write` must not reach a pull request, and one that
/// needs `pr_write` must not reach a plain issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    Nothing,
    NotPull,
    IsPull,
}

pub fn check_of(operation: &str) -> Check {
    match operation {
        "github.update_issue" | "github.comment_issue" => Check::NotPull,
        "github.comment_pr" | "github.update_pr" => Check::IsPull,
        _ => Check::Nothing,
    }
}

/// A branch name git accepts, and nothing odd: no `..`, `//`, `@{`, spaces, control or
/// `~^:?*[\` characters, no trailing `/`, `.` or `.lock`.
fn branch_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 200
        && !s.contains("..")
        && !s.contains("//")
        && !s.contains("@{")
        && !s.starts_with('/')
        && !s.ends_with('/')
        && !s.ends_with('.')
        && !s.ends_with(".lock")
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !b"~^:?*[\\".contains(&b))
}

/// The body rules of the operations that need them; `owner` is the repository's owner.
pub fn body(operation: &str, owner: &str, b: &Map<String, Value>) -> Result<(), BuildError> {
    match operation {
        "github.create_branch" => {
            let name = b
                .get("ref")
                .and_then(Value::as_str)
                .and_then(|r| r.strip_prefix("refs/heads/"))
                .ok_or(BuildError::BadRef)?;
            branch_ok(name).then_some(()).ok_or(BuildError::BadRef)
        }
        "github.create_pr" => {
            if b.contains_key("head_repo") {
                return Err(BuildError::BadHead);
            }
            let head = b
                .get("head")
                .and_then(Value::as_str)
                .ok_or(BuildError::BadHead)?;
            let branch = match head.split_once(':') {
                None => head,
                Some((o, br)) if o.eq_ignore_ascii_case(owner) => br,
                Some(_) => return Err(BuildError::BadHead),
            };
            branch_ok(branch).then_some(()).ok_or(BuildError::BadHead)
        }
        _ => Ok(()),
    }
}

/// Whether a file path is under `.github/workflows` or `.github/actions` (any letter case).
pub fn protected_path(path: &str) -> bool {
    let mut segs = path.split('/').map(str::to_ascii_lowercase);
    segs.next().as_deref() == Some(".github")
        && matches!(segs.next().as_deref(), Some("workflows" | "actions"))
}
