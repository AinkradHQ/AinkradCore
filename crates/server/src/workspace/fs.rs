//! The Core's own file access inside the canonical workspace (E15-2, spec 4.3 and 4.7).
//!
//! A [`Tree`] holds one open root directory. Every read, write, listing and removal names a path
//! RELATIVE to it and goes through `ainkrad_sys`' beneath wrappers (`openat2` with
//! `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` on Linux, an `O_NOFOLLOW` walk elsewhere), so a link a
//! session planted can never lead a read or a write out of the folder. A write is a temp file in
//! the target's folder, fsynced, then moved into place with `renameat`: it never writes through a
//! link and a reader never sees half a file.
//!
//! The revert logic of E14 lives here too (moved from the runner's `agent/files.rs`, which keeps
//! its copy only for legacy sessions until 0.11).

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use super::revert::head_blob;
pub use super::revert::{Plan, Reversal, reverse};
use ainkrad_proto::v2::{FolderEntry, MAX_FOLDER_ENTRIES, RevertEdit, RevertResult};
use ainkrad_sys::{Kind, Stat};

use super::rules::has_git;

/// Longest path, component and depth a wire path may have (spec 4.3).
pub const MAX_PATH: usize = 4096;
pub const MAX_COMPONENT: usize = 255;
pub const MAX_DEPTH: usize = 64;
/// The prefix of a temp file; manifests and listings ignore these.
pub const TMP_PREFIX: &str = ".ainkrad-tmp-";

/// Names a listing leaves out: noise nobody browses.
const NOISE: [&str; 4] = [".git", "node_modules", ".DS_Store", ".ainkrad"];
const READ_CAP: usize = 20_000;
/// The biggest file the Core reads whole for a revert.
const MAX_TEXT: u64 = 16 * 1024 * 1024;

/// Checks a wire path (spec 4.3): relative UTF-8 with `/`, no `..`, `.`, empty part, NUL, `\` or
/// control character, parts of at most 255 bytes, depth at most 64, at most 4096 bytes, and no
/// `.git` part in any case. `Err` is the reason, for a `bad_path` answer.
pub fn check_path(rel: &str) -> Result<(), &'static str> {
    if rel.is_empty() {
        return Err("empty path");
    }
    if rel.len() > MAX_PATH {
        return Err("path too long");
    }
    if rel.starts_with('/') {
        return Err("absolute path");
    }
    if rel.chars().any(|c| c.is_control() || c == '\\') {
        return Err("control character or backslash");
    }
    let mut depth = 0;
    for p in rel.split('/') {
        depth += 1;
        match p {
            "" => return Err("empty component"),
            "." | ".." => return Err("`.` or `..` component"),
            p if p.len() > MAX_COMPONENT => return Err("component too long"),
            _ => {}
        }
    }
    if depth > MAX_DEPTH {
        return Err("path too deep");
    }
    if has_git(rel) {
        return Err("inside .git");
    }
    Ok(())
}

fn refuse(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

/// A workspace folder, open as a root descriptor.
pub struct Tree {
    root: OwnedFd,
}

/// A temp file not yet moved into place; dropped uncommitted, it removes itself.
pub struct Staged {
    dir: OwnedFd,
    tmp: String,
    name: String,
    pub file: File,
    done: bool,
}

impl Staged {
    /// Moves the temp file to its final name, as an executable or not (`None`: keep the mode an
    /// existing file has, else `0660`).
    pub fn commit(mut self, exec: Option<bool>) -> io::Result<()> {
        let mode = match exec {
            Some(true) => 0o770,
            Some(false) => 0o660,
            None => match ainkrad_sys::fstatat(self.dir.as_fd(), &self.name) {
                Ok(s) if s.kind == Kind::File => s.mode & 0o777,
                _ => 0o660,
            },
        };
        self.file.flush()?;
        self.file
            .set_permissions(std::fs::Permissions::from_mode(mode))?;
        self.file.sync_all()?;
        ainkrad_sys::renameat(self.dir.as_fd(), &self.tmp, self.dir.as_fd(), &self.name)?;
        self.done = true;
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.done {
            let _ = ainkrad_sys::unlinkat(self.dir.as_fd(), &self.tmp, false);
        }
    }
}

static SEQ: AtomicU64 = AtomicU64::new(0);

impl Tree {
    /// Opens the folder `root` (the Core's own path, never a client's).
    pub fn open(root: &Path) -> io::Result<Self> {
        Ok(Self {
            root: ainkrad_sys::open_root(root)?,
        })
    }

    /// The folder holding `rel` (made when `make`), and the name of `rel` in it.
    fn parent<'a>(&self, rel: &'a str, make: bool) -> io::Result<(OwnedFd, &'a str)> {
        let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
        let fd = match make {
            true => ainkrad_sys::mkdir_all_beneath(self.root.as_fd(), dir, 0o770)?,
            false => ainkrad_sys::open_beneath(self.root.as_fd(), dir, ainkrad_sys::FLAGS_DIR, 0)?,
        };
        Ok((fd, name))
    }

    /// What `rel` is (a link is reported, not followed).
    pub fn stat(&self, rel: &str) -> io::Result<Stat> {
        check_path(rel).map_err(refuse)?;
        let (dir, name) = self.parent(rel, false)?;
        ainkrad_sys::fstatat(dir.as_fd(), name)
    }

    /// The whole of the plain file `rel`, at most `max` bytes. A FIFO or device is refused without
    /// blocking.
    pub fn read(&self, rel: &str, max: u64) -> io::Result<Vec<u8>> {
        check_path(rel).map_err(refuse)?;
        let fd = ainkrad_sys::open_beneath(self.root.as_fd(), rel, ainkrad_sys::FLAGS_READ, 0)?;
        let file = File::from(fd);
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(refuse("not a plain file"));
        }
        if meta.len() > max {
            return Err(refuse("file too large"));
        }
        let mut out = Vec::with_capacity(meta.len() as usize);
        file.take(max + 1).read_to_end(&mut out)?;
        match out.len() as u64 > max {
            true => Err(refuse("file too large")),
            false => Ok(out),
        }
    }

    /// An open reader of the plain file `rel` (for hashing and chunking big files).
    pub fn open_file(&self, rel: &str) -> io::Result<File> {
        check_path(rel).map_err(refuse)?;
        let fd = ainkrad_sys::open_beneath(self.root.as_fd(), rel, ainkrad_sys::FLAGS_READ, 0)?;
        let file = File::from(fd);
        match file.metadata()?.is_file() {
            true => Ok(file),
            false => Err(refuse("not a plain file")),
        }
    }

    /// Starts a write of `rel`: a temp file in its folder (made on the way, inside the tree).
    pub fn stage(&self, rel: &str) -> io::Result<Staged> {
        check_path(rel).map_err(refuse)?;
        let (dir, name) = self.parent(rel, true)?;
        let tmp = format!(
            "{TMP_PREFIX}{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let fd =
            ainkrad_sys::openat_nofollow(dir.as_fd(), &tmp, ainkrad_sys::FLAGS_CREATE_NEW, 0o660)?;
        Ok(Staged {
            dir,
            tmp,
            name: name.to_owned(),
            file: File::from(fd),
            done: false,
        })
    }

    /// Writes `data` to `rel` through a temp file and a rename.
    pub fn write(&self, rel: &str, data: &[u8], exec: Option<bool>) -> io::Result<()> {
        let mut s = self.stage(rel)?;
        s.file.write_all(data)?;
        s.commit(exec)
    }

    /// Makes the link `rel` to `target`. The caller checked the target is relative and inside.
    pub fn symlink(&self, rel: &str, target: &str) -> io::Result<()> {
        check_path(rel).map_err(refuse)?;
        let (dir, name) = self.parent(rel, true)?;
        let tmp = format!(
            "{TMP_PREFIX}{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        ainkrad_sys::symlinkat(target, dir.as_fd(), &tmp)?;
        let moved = ainkrad_sys::renameat(dir.as_fd(), &tmp, dir.as_fd(), name);
        if moved.is_err() {
            let _ = ainkrad_sys::unlinkat(dir.as_fd(), &tmp, false);
        }
        moved
    }

    /// Where the link `rel` points.
    pub fn read_link(&self, rel: &str) -> io::Result<String> {
        check_path(rel).map_err(refuse)?;
        let (dir, name) = self.parent(rel, false)?;
        ainkrad_sys::readlinkat(dir.as_fd(), name)?
            .into_string()
            .map_err(|_| refuse("link target is not UTF-8"))
    }

    /// Removes the file or link `rel` (a folder only when empty). Absent is not an error.
    pub fn remove(&self, rel: &str) -> io::Result<()> {
        check_path(rel).map_err(refuse)?;
        let (dir, name) = match self.parent(rel, false) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let is_dir = match ainkrad_sys::fstatat(dir.as_fd(), name) {
            Ok(s) => s.kind == Kind::Dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        ainkrad_sys::unlinkat(dir.as_fd(), name, is_dir)?;
        // A folder left empty goes too (a folder that becomes a file needs the way clear).
        let mut up = rel.rsplit_once('/').map(|(d, _)| d);
        while let Some(d) = up {
            let Ok((parent, name)) = self.parent(d, false) else {
                break;
            };
            if ainkrad_sys::unlinkat(parent.as_fd(), name, true).is_err() {
                break;
            }
            up = d.rsplit_once('/').map(|(d, _)| d);
        }
        Ok(())
    }

    /// The entries of folder `rel` (`""` is the root): name and what it is, links not followed,
    /// temp files and names that are not UTF-8 left out.
    pub fn read_dir(&self, rel: &str) -> io::Result<Vec<(String, Stat)>> {
        if !rel.is_empty() {
            check_path(rel).map_err(refuse)?;
        }
        let fd = ainkrad_sys::open_beneath(self.root.as_fd(), rel, ainkrad_sys::FLAGS_DIR, 0)?;
        let mut out = Vec::new();
        for name in ainkrad_sys::list_dir(fd.as_fd())? {
            let Ok(name) = name.into_string() else {
                continue;
            };
            if name.starts_with(TMP_PREFIX) {
                continue;
            }
            // Gone between the listing and the stat: skip.
            if let Ok(st) = ainkrad_sys::fstatat(fd.as_fd(), &name) {
                out.push((name, st));
            }
        }
        Ok(out)
    }

    /// One level of the folder for the E14 listing: directories first, then by name, at most
    /// [`MAX_FOLDER_ENTRIES`]; noise (`.git`, `node_modules` ...) left out; a link listed as a file.
    pub fn list_folder(&self, rel: &str) -> io::Result<(Vec<FolderEntry>, bool)> {
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
    pub fn plan_revert(
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
    pub fn revert(
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
