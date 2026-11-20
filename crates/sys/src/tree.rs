//! A folder held open as a root descriptor (E15 workspace sync, spec 4.3), shared by the Core's
//! canonical workspace and the runner's warm caches.
//!
//! Every read, write, listing and removal names a path RELATIVE to the root, checked as a wire
//! path (`ainkrad_proto::v2::synctree::check_path`), and goes through the beneath wrappers
//! (`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` on Linux, an `O_NOFOLLOW` walk
//! elsewhere), so a link a session or a job planted can never lead a read or a write out of the
//! folder. A write is a temp file in the target's folder, fsynced, then moved into place with
//! `renameat`: it never writes through a link and a reader never sees half a file.

use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use ainkrad_proto::v2::synctree::check_path;

use crate::{Kind, Stat};

/// The prefix of a temp file; manifests and listings ignore these.
pub const TMP_PREFIX: &str = ".ainkrad-tmp-";

fn refuse(why: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, why)
}

static SEQ: AtomicU64 = AtomicU64::new(0);

fn tmp_name() -> String {
    format!(
        "{TMP_PREFIX}{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// A folder, open as a root descriptor.
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
            None => match crate::fstatat(self.dir.as_fd(), &self.name) {
                Ok(s) if s.kind == Kind::File => s.mode & 0o777,
                _ => 0o660,
            },
        };
        self.file.flush()?;
        self.file
            .set_permissions(std::fs::Permissions::from_mode(mode))?;
        self.file.sync_all()?;
        crate::renameat(self.dir.as_fd(), &self.tmp, self.dir.as_fd(), &self.name)?;
        self.done = true;
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.done {
            let _ = crate::unlinkat(self.dir.as_fd(), &self.tmp, false);
        }
    }
}

impl Tree {
    /// Opens the folder `root` (the caller's own path, never a client's).
    pub fn open(root: &Path) -> io::Result<Self> {
        Ok(Self {
            root: crate::open_root(root)?,
        })
    }

    /// The folder holding `rel` (made when `make`), and the name of `rel` in it.
    fn parent<'a>(&self, rel: &'a str, make: bool) -> io::Result<(OwnedFd, &'a str)> {
        let (dir, name) = rel.rsplit_once('/').unwrap_or(("", rel));
        let fd = match make {
            true => crate::mkdir_all_beneath(self.root.as_fd(), dir, 0o770)?,
            false => crate::open_beneath(self.root.as_fd(), dir, crate::FLAGS_DIR, 0)?,
        };
        Ok((fd, name))
    }

    /// What `rel` is (a link is reported, not followed).
    pub fn stat(&self, rel: &str) -> io::Result<Stat> {
        check_path(rel).map_err(refuse)?;
        let (dir, name) = self.parent(rel, false)?;
        crate::fstatat(dir.as_fd(), name)
    }

    /// The whole of the plain file `rel`, at most `max` bytes. A FIFO or device is refused without
    /// blocking.
    pub fn read(&self, rel: &str, max: u64) -> io::Result<Vec<u8>> {
        let file = self.open_file(rel)?;
        if file.metadata()?.len() > max {
            return Err(refuse("file too large"));
        }
        let mut out = Vec::new();
        file.take(max + 1).read_to_end(&mut out)?;
        match out.len() as u64 > max {
            true => Err(refuse("file too large")),
            false => Ok(out),
        }
    }

    /// An open reader of the plain file `rel` (for hashing and chunking big files).
    pub fn open_file(&self, rel: &str) -> io::Result<File> {
        check_path(rel).map_err(refuse)?;
        let fd = crate::open_beneath(self.root.as_fd(), rel, crate::FLAGS_READ, 0)?;
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
        let fd = crate::openat_nofollow(dir.as_fd(), &tmp, crate::FLAGS_CREATE_NEW, 0o660)?;
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
        let tmp = tmp_name();
        crate::symlinkat(target, dir.as_fd(), &tmp)?;
        let moved = crate::renameat(dir.as_fd(), &tmp, dir.as_fd(), name);
        if moved.is_err() {
            let _ = crate::unlinkat(dir.as_fd(), &tmp, false);
        }
        moved
    }

    /// Where the link `rel` points.
    pub fn read_link(&self, rel: &str) -> io::Result<String> {
        check_path(rel).map_err(refuse)?;
        let (dir, name) = self.parent(rel, false)?;
        crate::readlinkat(dir.as_fd(), name)?
            .into_string()
            .map_err(|_| refuse("link target is not UTF-8"))
    }

    /// Removes the file or link `rel` (a folder only when empty). Absent is not an error. A folder
    /// left empty goes too (a folder that becomes a file needs the way clear).
    pub fn remove(&self, rel: &str) -> io::Result<()> {
        check_path(rel).map_err(refuse)?;
        let (dir, name) = match self.parent(rel, false) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        let is_dir = match crate::fstatat(dir.as_fd(), name) {
            Ok(s) => s.kind == Kind::Dir,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        crate::unlinkat(dir.as_fd(), name, is_dir)?;
        let mut up = rel.rsplit_once('/').map(|(d, _)| d);
        while let Some(d) = up {
            let Ok((parent, name)) = self.parent(d, false) else {
                break;
            };
            if crate::unlinkat(parent.as_fd(), name, true).is_err() {
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
        let fd = crate::open_beneath(self.root.as_fd(), rel, crate::FLAGS_DIR, 0)?;
        let mut out = Vec::new();
        for name in crate::list_dir(fd.as_fd())? {
            let Ok(name) = name.into_string() else {
                continue;
            };
            if name.starts_with(TMP_PREFIX) {
                continue;
            }
            // Gone between the listing and the stat: skip.
            if let Ok(st) = crate::fstatat(fd.as_fd(), &name) {
                out.push((name, st));
            }
        }
        Ok(out)
    }
}
