//! The Core's own file access inside the canonical workspace (E15-2, spec 4.3 and 4.7).
//!
//! [`Tree`] (one open root directory, every access beneath it) is `ainkrad_sys::tree`, shared
//! with the runner's caches; this adds the Core's folder listing.
//!
//! The revert logic of E14 lives here too (moved from the runner's `agent/files.rs`, which keeps
//! its copy only for legacy sessions until 0.11).

use std::io;
use std::path::Path;

use super::revert::head_blob;
pub use super::revert::{Plan, Reversal, reverse};
use ainkrad_proto::v2::{FolderEntry, MAX_FOLDER_ENTRIES, RevertEdit, RevertResult};
use ainkrad_sys::Kind;

/// Longest path, component and depth a wire path may have (spec 4.3).
pub use ainkrad_proto::v2::{
    WIRE_COMPONENT_MAX as MAX_COMPONENT, WIRE_DEPTH_MAX as MAX_DEPTH, WIRE_PATH_MAX as MAX_PATH,
};

/// Names a listing leaves out: noise nobody browses.
const NOISE: [&str; 4] = [".git", "node_modules", ".DS_Store", ".ainkrad"];
const READ_CAP: usize = 20_000;
/// The biggest file the Core reads whole for a revert.
const MAX_TEXT: u64 = 16 * 1024 * 1024;

pub use ainkrad_proto::v2::synctree::check_path;
pub use ainkrad_sys::tree::{Staged, TMP_PREFIX, Tree};

fn refuse(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

/// The Core's own uses of a workspace [`Tree`]: the E14 folder listing and revert.
pub trait TreeExt {
    fn list_folder(&self, rel: &str) -> io::Result<(Vec<FolderEntry>, bool)>;
    fn plan_revert(
        &self,
        root: &Path,
        rel: &str,
        edits: &[RevertEdit],
        truncated: bool,
    ) -> io::Result<Plan>;
    fn revert(
        &self,
        root: &Path,
        rel: &str,
        edits: &[RevertEdit],
        truncated: bool,
    ) -> io::Result<RevertResult>;
}

impl TreeExt for Tree {
    /// One level of the folder for the E14 listing: directories first, then by name, at most
    /// [`MAX_FOLDER_ENTRIES`]; noise (`.git`, `node_modules` ...) left out; a link listed as a file.
    fn list_folder(&self, rel: &str) -> io::Result<(Vec<FolderEntry>, bool)> {
        let all = self.read_dir(rel)?;
        let cargo = all.iter().any(|(n, _)| n == "Cargo.toml");
        let mut cut = false;
        let mut entries = Vec::new();
        for (name, st) in all {
            if NOISE.contains(&name.as_str()) || (cargo && name == "target") {
                continue;
            }
            if entries.len() >= READ_CAP {
                cut = true;
                break;
            }
            let dir = st.kind == Kind::Dir;
            entries.push(FolderEntry {
                size: (!dir).then_some(st.size),
                dir,
                name,
            });
        }
        entries.sort_by(|a, b| {
            (!a.dir, a.name.to_lowercase(), &a.name).cmp(&(!b.dir, b.name.to_lowercase(), &b.name))
        });
        let truncated = cut || entries.len() > MAX_FOLDER_ENTRIES;
        entries.truncate(MAX_FOLDER_ENTRIES);
        Ok((entries, truncated))
    }

    /// What reverting the file `rel` as `edits` (the session's recorded ones, newest first) would
    /// do, without doing it; see [`reverse`]. `root` is the folder's path, for the git `HEAD`
    /// fallback.
    fn plan_revert(
        &self,
        root: &Path,
        rel: &str,
        edits: &[RevertEdit],
        truncated: bool,
    ) -> io::Result<Plan> {
        check_path(rel).map_err(refuse)?;
        let current = match self.read(rel, MAX_TEXT) {
            Ok(b) => Some(String::from_utf8(b).map_err(|_| refuse("the file is not UTF-8 text"))?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        Ok(
            match reverse(current, edits, truncated, || head_blob(root, rel)) {
                Ok(Reversal::Content(text, result)) => Plan::Write(text.into_bytes(), result),
                Ok(Reversal::Delete) => Plan::Delete,
                // Nothing is changed: the reason is the result (`Conflict` or `Impossible`).
                Err((result, _)) => Plan::Refused(result),
            },
        )
    }

    /// Reverts the file `rel` in this folder, as [`Tree::plan_revert`] plans.
    fn revert(
        &self,
        root: &Path,
        rel: &str,
        edits: &[RevertEdit],
        truncated: bool,
    ) -> io::Result<RevertResult> {
        Ok(match self.plan_revert(root, rel, edits, truncated)? {
            Plan::Write(bytes, result) => {
                self.write(rel, &bytes, None)?;
                result
            }
            Plan::Delete => {
                self.remove(rel)?;
                RevertResult::Deleted
            }
            Plan::Refused(result) => result,
        })
    }
}

#[cfg(test)]
#[path = "fs_tests.rs"]
mod tests;
