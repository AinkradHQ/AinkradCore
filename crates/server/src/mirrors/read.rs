//! Reading one file out of a mirror, for the run spec drafts (P4-03). Read-only: the object is
//! read with `git cat-file` straight from the bare copy, so nothing is checked out, no file is
//! followed (a symlink in the repo is just its target's text) and no hook or filter runs. The path
//! is checked here and the answer is capped, whatever the caller did.

use super::Mirrors;

/// The most a file read may be.
pub const READ_MAX: usize = 64 * 1024;

/// A path inside a repo: relative, `/`-separated, no `.` or `..` part, no control characters.
pub fn path_ok(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 200
        && !path.starts_with('/')
        && !path.chars().any(char::is_control)
        && path.split('/').all(|p| !matches!(p, "" | "." | ".."))
}

impl Mirrors {
    /// Whether a fetch has made the repo's copy.
    pub fn has_copy(&self, repo: i64, key: &str) -> bool {
        self.ready(repo, key).is_ok()
    }

    /// `path` at the head of the repo's default branch: `Ok(None)` when the mirror has no such
    /// file (or it is a folder), `Err` when there is no copy yet or the file is too big or not text.
    pub async fn read_file(
        &self,
        repo: i64,
        key: &str,
        path: &str,
    ) -> Result<Option<String>, String> {
        if !path_ok(path) {
            return Err("not a path inside the repo".to_owned());
        }
        let dir = self
            .ready(repo, key)
            .map_err(|_| "the Core has not fetched this repo yet".to_owned())?;
        let spec = format!("HEAD:{path}");
        // A folder, a missing path and a missing HEAD all fail here and read as "not there".
        let Ok(kind) = self.run(&["-C", &dir, "cat-file", "-t", &spec], None).await else {
            return Ok(None);
        };
        if kind.trim() != "blob" {
            return Ok(None);
        }
        let size = self
            .run(&["-C", &dir, "cat-file", "-s", &spec], None)
            .await?;
        if size
            .trim()
            .parse::<usize>()
            .ok()
            .is_none_or(|n| n > READ_MAX)
        {
            return Err(format!("{path} is larger than {} KiB", READ_MAX / 1024));
        }
        let text = self
            .run(&["-C", &dir, "cat-file", "blob", &spec], None)
            .await?;
        Ok(Some(text))
    }
}
