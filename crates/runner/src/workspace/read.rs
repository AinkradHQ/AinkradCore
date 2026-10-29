//! Reading a file an agent published by path (E15.12): only inside the issue's worktree (its
//! dir: every repo's worktree in it), symlinks resolved first so none leads out, and the size
//! checked before a byte is read.

use std::io::Read;

use super::*;

impl Workspaces {
    /// The bytes of `path` (relative) in `issue`'s dir, at most `max_bytes`, or why not.
    pub fn read_file(&self, issue: i64, path: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
        let plain = !path.is_empty()
            && !path.starts_with('/')
            && path
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != "..");
        if !plain {
            return Err(format!(
                "{path:?} is not a plain relative path in the worktree"
            ));
        }
        let root = self
            .path(issue)
            .canonicalize()
            .map_err(|_| "the issue has no worktree on this runner".to_owned())?;
        let file = root
            .join(path)
            .canonicalize()
            .map_err(|_| format!("no file {path} in the worktree"))?;
        if !file.starts_with(&root) {
            return Err(format!("{path} leads outside the worktree"));
        }
        let meta = std::fs::metadata(&file).map_err(|e| format!("{path}: {e}"))?;
        if !meta.is_file() {
            return Err(format!("{path} is not a file"));
        }
        if meta.len() > max_bytes {
            return Err(format!(
                "{path} is {} bytes; the most is {max_bytes}",
                meta.len()
            ));
        }
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        // A file growing meanwhile still stops at the limit.
        std::fs::File::open(&file)
            .and_then(|f| f.take(max_bytes + 1).read_to_end(&mut bytes))
            .map_err(|e| format!("{path}: {e}"))?;
        if bytes.len() as u64 > max_bytes {
            return Err(format!("{path} grew past {max_bytes} bytes"));
        }
        Ok(bytes)
    }
}
