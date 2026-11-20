//! A cache folder held open as a root descriptor (E15-4, the runner end of spec §4.3): every open,
//! write, remove and listing happens beneath it through `ainkrad_sys`'s `*at` wrappers, never by
//! path, so a symlink planted in the tree (by a job, say) cannot send a write outside it. Writes
//! go to a temp file in the same folder and are renamed into place.
//!
//! Mirrors the Core's `workspace::fs::Tree` (E15-2); both sit on the same `ainkrad_sys` wrappers.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use ainkrad_proto::v2::wire_path_problem;
use ainkrad_sys::{Kind, Stat};

/// The prefix of a temp file; listings ignore these.
pub const TMP_PREFIX: &str = ".ainkrad-tmp-";
/// Folders deeper than this are not walked.
pub const MAX_DEPTH: usize = ainkrad_proto::v2::WIRE_DEPTH_MAX;

/// A wire path plus no control character (spec §4.3). `Err` is the reason.
pub fn check_path(rel: &str) -> Result<(), &'static str> {
    if let Some(why) = wire_path_problem(rel) {
        return Err(why);
    }
    match rel.chars().any(char::is_control) {
        true => Err("the path holds a control character"),
        false => Ok(()),
    }
}

fn refuse(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

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

static SEQ: AtomicU64 = AtomicU64::new(0);

fn tmp_name() -> String {
    format!(
        "{TMP_PREFIX}{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

impl Staged {
    /// Moves the temp file to its final name, executable or not.
    pub fn commit(mut self, exec: bool) -> io::Result<()> {
        self.file.flush()?;
        self.file
            .set_permissions(std::fs::Permissions::from_mode(if exec {
                0o770
            } else {
                0o660
            }))?;
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

impl Tree {
    /// Opens the folder `root` (the runner's own path, never the Core's).
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

    /// An open reader of the plain file `rel`; a FIFO or device is refused without blocking.
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
        let tmp = tmp_name();
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

    /// Makes the link `rel` to `target`; the caller checked the target is relative and inside.
    pub fn symlink(&self, rel: &str, target: &str) -> io::Result<()> {
        check_path(rel).map_err(refuse)?;
        let (dir, name) = self.parent(rel, true)?;
        let tmp = tmp_name();
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

    /// Removes the file or link `rel` (a folder only when empty); absent is not an error. A folder
    /// left empty goes too.
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

    /// The entries of folder `rel` (`""` is the root): name and what it is, links not followed;
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
}
