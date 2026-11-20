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
            // Gone between the listing and the stat: skip. Any other failure fails the listing,
            // so a sync never reads a name it could not stat as deleted (E15 L9).
            match crate::fstatat(fd.as_fd(), &name) {
                Ok(st) => out.push((name, st)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Whether `rel` resolves to an entry already on disk under ANOTHER spelling: on a
    /// case-insensitive or normalisation-insensitive disk (APFS), `SRC/Main.rs` opens
    /// `src/main.rs`, and an NFD name opens its NFC twin (E15 security review L1). Each component
    /// is compared byte for byte with its folder's listing. An absent path is not aliased.
    pub fn aliased(&self, rel: &str) -> io::Result<bool> {
        check_path(rel).map_err(refuse)?;
        if matches!(self.stat(rel), Err(e) if e.kind() == io::ErrorKind::NotFound) {
            return Ok(false);
        }
        let mut dir = String::new();
        for name in rel.split('/') {
            let fd = match crate::open_beneath(self.root.as_fd(), &dir, crate::FLAGS_DIR, 0) {
                Ok(fd) => fd,
                Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR)) => {
                    return Ok(false);
                }
                Err(e) => return Err(e),
            };
            let exact = crate::list_dir(fd.as_fd())?
                .iter()
                .any(|n| n.as_encoded_bytes() == name.as_bytes());
            if !exact {
                return match crate::fstatat(fd.as_fd(), name) {
                    Ok(_) => Ok(true),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
                    Err(e) => Err(e),
                };
            }
            if !dir.is_empty() {
                dir.push('/');
            }
            dir.push_str(name);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ainkrad-tree-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The disk under the temp folder folds case (APFS default) when `A` opens `a`.
    fn folds(d: &Path) -> bool {
        std::fs::write(d.join("probe"), "").unwrap();
        let f = d.join("PROBE").exists();
        std::fs::remove_file(d.join("probe")).unwrap();
        f
    }

    #[test]
    fn another_spelling_of_an_existing_path_is_an_alias() {
        // L1: on APFS a runner's `SRC/main.rs` or `.ENV` lands on the Core's `src/main.rs`/`.env`.
        let d = temp("alias");
        std::fs::create_dir_all(d.join("src")).unwrap();
        std::fs::write(d.join("src/main.rs"), "x").unwrap();
        std::fs::write(d.join("caf\u{e9}.txt"), "nfc").unwrap();
        let t = Tree::open(&d).unwrap();
        assert!(!t.aliased("src/main.rs").unwrap(), "the exact spelling");
        assert!(!t.aliased("src/new.rs").unwrap(), "absent");
        assert!(!t.aliased("nope/new.rs").unwrap(), "absent folder");
        let fold = folds(&d);
        assert_eq!(t.aliased("SRC/main.rs").unwrap(), fold);
        assert_eq!(t.aliased("src/MAIN.rs").unwrap(), fold);
        // NFD `e` + combining acute: APFS opens the NFC file whatever its case handling.
        let nfd_twin = d.join("cafe\u{301}.txt").exists();
        assert_eq!(t.aliased("cafe\u{301}.txt").unwrap(), nfd_twin);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_folder_that_cannot_be_read_fails_the_listing() {
        // L9: an unreadable folder must be an error, never an empty (all deleted) listing.
        if crate::getuid() == 0 {
            return;
        }
        let d = temp("unreadable");
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::write(d.join("sub/f"), "x").unwrap();
        std::fs::set_permissions(d.join("sub"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let t = Tree::open(&d).unwrap();
        let r = t.read_dir("sub");
        std::fs::set_permissions(d.join("sub"), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(r.is_err(), "{r:?}");
        let _ = std::fs::remove_dir_all(d);
    }
}
