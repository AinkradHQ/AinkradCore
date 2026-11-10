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
