//! Small file helpers for `/var/lib/ainkrad-host` (root `0700`, so only root is in here): bounded
//! reads that never follow a symlink, atomic replace, and the lock.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Reads at most `max` bytes of `path`; larger is an error (a corrupt or hostile file).
pub fn read_capped(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    let mut out = Vec::new();
    f.take(max + 1).read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(io::Error::other("file too large"));
    }
    Ok(out)
}

/// Writes `bytes` to `dir/name` atomically: temp file, fsync, rename, fsync of the directory.
/// The temp file is never created exclusively, so a stale one cannot wedge the writer; a
/// directory or symlink in its place is an error.
pub fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!("{name}.tmp"));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, dir.join(name))?;
    File::open(dir)?.sync_all()
}

/// Opens (creating, mode `0600`) a lock file.
pub fn open_lock(dir: &Path, name: &str) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dir.join(name))
}

/// Whether the state directory is what the helper assumes: a real directory (not a symlink) owned
/// by `owner_uid` (root) with no group or other access, under a parent owned by `owner_uid` that
/// nobody else can write to. If uid `ainkrad` could replace the directory or its parent, none of the
/// fail-closed state would mean anything, so mutations refuse and `status` says so. Only the parent
/// is checked, not further up: `/var/lib` and above are root's on any host this runs on.
pub fn dir_safe(dir: &Path, owner_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let own = std::fs::symlink_metadata(dir)
        .is_ok_and(|m| m.is_dir() && m.uid() == owner_uid && m.mode() & 0o077 == 0);
    let parent = dir
        .parent()
        .and_then(|p| std::fs::symlink_metadata(p).ok())
        .is_some_and(|m| m.is_dir() && m.uid() == owner_uid && m.mode() & 0o022 == 0);
    own && parent
}

/// [`dir_safe`], after tightening a state directory that is ours but too open. systemd's
/// `StateDirectory=` and `install -d` both make `0755`, so a helper that only refused would refuse
/// on every fresh install. It chmods to `0700` only a real directory (never a symlink) owned by
/// `owner_uid` under a safe parent; it never creates, never chowns, and fails closed otherwise.
pub fn ensure_dir(dir: &Path, owner_uid: u32) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let parent_ok = dir
        .parent()
        .and_then(|p| std::fs::symlink_metadata(p).ok())
        .is_some_and(|m| m.is_dir() && m.uid() == owner_uid && m.mode() & 0o022 == 0);
    if parent_ok
        && let Ok(m) = std::fs::symlink_metadata(dir)
        && m.is_dir()
        && m.uid() == owner_uid
        && m.mode() & 0o077 != 0
    {
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    dir_safe(dir, owner_uid)
}
