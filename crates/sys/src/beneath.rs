//! Path-safe file access beneath a root descriptor (E15-2, spec section 4.3).
//!
//! Every call names a path RELATIVE to an open directory descriptor and never follows a symbolic
//! link on the way: Linux asks the kernel (`openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS`), macOS (and a Linux older than 5.6) walks the components itself with
//! `O_NOFOLLOW`, one `openat` each, so a link swapped in between two steps is still refused. A
//! path with a `..`, a `.`, an empty part, a NUL or a leading `/` is refused before any syscall.
//! The callers (`workspace::fs`) write by temp file plus [`renameat`], never in place.
//!
//! Each `unsafe` block lives in a `pub fn` listed in [`crate::INVENTORY`].

// libc's integer types differ by platform (`mode_t`, `time_t`, `ino_t`), so a cast that is a no-op on
// one is needed on the other.
#![allow(clippy::unnecessary_cast)]

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

/// The longest path and component a caller may name (spec 4.3).
pub const MAX_PATH: usize = 4096;
pub const MAX_COMPONENT: usize = 255;

/// Flags for [`open_beneath`] and [`openat_nofollow`]: a folder, a read that cannot block on a
/// FIFO, a new file that must not exist.
pub const FLAGS_DIR: i32 = libc::O_RDONLY | libc::O_DIRECTORY;
/// `O_NOCTTY`: a device node opened before its type check never becomes a terminal (E15 L10).
pub const FLAGS_READ: i32 = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY;
pub const FLAGS_CREATE_NEW: i32 = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL;

fn invalid() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidInput)
}

/// One path component: not empty, not `.` or `..`, no `/` or NUL, at most 255 bytes.
fn component(name: &str) -> io::Result<CString> {
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > MAX_COMPONENT
        || name.contains('/');
    if bad {
        return Err(invalid());
    }
    CString::new(name).map_err(|_| invalid())
}

/// `rel` split into components (empty for the root itself). Refuses what [`component`] does, a
/// leading `/`, and a path over 4096 bytes.
fn parts(rel: &str) -> io::Result<Vec<&str>> {
    if rel.len() > MAX_PATH || rel.starts_with('/') {
        return Err(invalid());
    }
    if rel.is_empty() {
        return Ok(Vec::new());
    }
    let all: Vec<&str> = rel.split('/').collect();
    for p in &all {
        component(p)?;
    }
    Ok(all)
}

/// What a directory entry is, as `lstat` says (a link is never followed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

/// What [`fstatat`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stat {
    pub kind: Kind,
    pub size: u64,
    /// Permission bits only (`0o7777`).
    pub mode: u32,
    pub mtime_ns: i64,
    pub ino: u64,
}

/// Opens the directory `path` (the root every other call here is beneath). The path itself is
/// trusted: it is the Core's own configured root, never a client's.
pub fn open_root(path: &std::path::Path) -> io::Result<OwnedFd> {
    let dir = std::fs::File::open(path)?;
    if !dir.metadata()?.is_dir() {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    Ok(OwnedFd::from(dir))
}

/// `openat(2)` of the single component `name` in `dir`, never following a link there.
#[allow(unsafe_code)]
pub fn openat_nofollow(
    dir: BorrowedFd<'_>,
    name: &str,
    flags: i32,
    mode: u32,
) -> io::Result<OwnedFd> {
    let name = component(name)?;
    let flags = flags | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: openat(2) with a descriptor we borrow, a NUL-terminated name that lives to the end
    // of the call, and integer flags and mode.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor openat just returned and nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Linux only: `openat2(2)` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn openat2_beneath(
    dir: BorrowedFd<'_>,
    rel: &str,
    flags: i32,
    mode: u32,
) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    let path = CString::new(rel).map_err(|_| invalid())?;
    let how = OpenHow {
        flags: u64::from((flags | libc::O_CLOEXEC) as u32),
        mode: u64::from(mode),
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: the openat2 syscall with a descriptor we borrow, a NUL-terminated path and an
    // `open_how` we own, both alive for the call, and its exact size.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            path.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor the kernel just returned and nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as std::os::fd::RawFd) })
}

/// The portable walk: each component opened with `O_NOFOLLOW` (the last with the caller's
/// `flags`), so a link anywhere on the way, the last part included, is an error.
fn walk(root: BorrowedFd<'_>, names: &[&str], flags: i32, mode: u32) -> io::Result<OwnedFd> {
    let Some((last, dirs)) = names.split_last() else {
        return root.try_clone_to_owned();
    };
    let mut cur = root.try_clone_to_owned()?;
    for d in dirs {
        cur = openat_nofollow(cur.as_fd(), d, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
    }
    openat_nofollow(cur.as_fd(), last, flags, mode)
}

/// Opens `rel` beneath `root` and returns the descriptor. `rel` is relative with `/` separators
/// (empty: the root itself); `..`, `.`, an empty part, a NUL, a leading `/`, a symbolic link at any
/// step (the last included) and anything that would leave `root` are errors. `flags` are the
/// usual `O_*` (no `O_NOFOLLOW` needed), `mode` is used with `O_CREAT`.
pub fn open_beneath(root: BorrowedFd<'_>, rel: &str, flags: i32, mode: u32) -> io::Result<OwnedFd> {
    let names = parts(rel)?;
    #[cfg(target_os = "linux")]
    if !names.is_empty() {
        match openat2_beneath(root, rel, flags, mode) {
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) => {}
            done => return done,
        }
    }
    walk(root, &names, flags, mode)
}

/// Makes every folder of `rel` beneath `root` (each created with `mode`, an existing plain folder
/// reused, a link or file refused) and returns the innermost one's descriptor.
pub fn mkdir_all_beneath(root: BorrowedFd<'_>, rel: &str, mode: u32) -> io::Result<OwnedFd> {
    let mut cur = root.try_clone_to_owned()?;
    for name in parts(rel)? {
        let open =
            |d: &OwnedFd| openat_nofollow(d.as_fd(), name, libc::O_RDONLY | libc::O_DIRECTORY, 0);
        cur = match open(&cur) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match mkdirat(cur.as_fd(), name, mode) {
                    Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
                    _ => {}
                }
                open(&cur)?
            }
            Err(e) => return Err(e),
        };
    }
    Ok(cur)
}

/// `mkdirat(2)` of the single component `name` in `dir`.
#[allow(unsafe_code)]
pub fn mkdirat(dir: BorrowedFd<'_>, name: &str, mode: u32) -> io::Result<()> {
    let name = component(name)?;
    // SAFETY: mkdirat(2) with a borrowed descriptor, a NUL-terminated name alive for the call
    // and an integer mode.
    let r = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `renameat(2)`: moves `old` of `old_dir` to `new` of `new_dir`, replacing a plain file there
/// atomically. Single components only.
#[allow(unsafe_code)]
pub fn renameat(
    old_dir: BorrowedFd<'_>,
    old: &str,
    new_dir: BorrowedFd<'_>,
    new: &str,
) -> io::Result<()> {
    let (old, new) = (component(old)?, component(new)?);
    // SAFETY: renameat(2) with two borrowed descriptors and two NUL-terminated names alive for
    // the call.
    let r = unsafe {
        libc::renameat(
            old_dir.as_raw_fd(),
            old.as_ptr(),
            new_dir.as_raw_fd(),
            new.as_ptr(),
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `unlinkat(2)` of the single component `name` in `dir`: a file or link, or (`dir_entry`) an
/// empty folder. Never follows a link.
#[allow(unsafe_code)]
pub fn unlinkat(dir: BorrowedFd<'_>, name: &str, dir_entry: bool) -> io::Result<()> {
    let name = component(name)?;
    let flag = if dir_entry { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: unlinkat(2) with a borrowed descriptor, a NUL-terminated name alive for the call
    // and an integer flag.
    let r = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), flag) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `symlinkat(2)`: a link `name` in `dir` holding `target` (the caller checked the target is
/// relative and stays inside the tree).
#[allow(unsafe_code)]
pub fn symlinkat(target: &str, dir: BorrowedFd<'_>, name: &str) -> io::Result<()> {
    let name = component(name)?;
    let target = CString::new(target).map_err(|_| invalid())?;
    // SAFETY: symlinkat(2) with two NUL-terminated strings alive for the call and a borrowed
    // descriptor.
    let r = unsafe { libc::symlinkat(target.as_ptr(), dir.as_raw_fd(), name.as_ptr()) };
    if r == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `readlinkat(2)`: where the link `name` of `dir` points (at most 4095 bytes).
#[allow(unsafe_code)]
pub fn readlinkat(dir: BorrowedFd<'_>, name: &str) -> io::Result<OsString> {
    let name = component(name)?;
    let mut buf = vec![0u8; MAX_PATH];
    // SAFETY: readlinkat(2) writes at most `buf.len()` bytes into a buffer we own; the name is
    // NUL-terminated and alive for the call.
    let n = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            name.as_ptr(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
        )
    };
    let Ok(n) = usize::try_from(n) else {
        return Err(io::Error::last_os_error());
    };
    if n >= buf.len() {
        return Err(invalid());
    }
    buf.truncate(n);
    Ok(OsString::from_vec(buf))
}

/// `fstatat(2)` of the single component `name` in `dir`, without following a link.
#[allow(unsafe_code)]
pub fn fstatat(dir: BorrowedFd<'_>, name: &str) -> io::Result<Stat> {
    let name = component(name)?;
    // SAFETY: an all-zero `stat` is a valid value of a plain C struct of integers.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: fstatat(2) with a borrowed descriptor, a NUL-terminated name and a `stat` we own,
    // all alive for the call.
    let r = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr(),
            &raw mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    let kind = match bits(st.st_mode) & bits(libc::S_IFMT) {
        m if m == bits(libc::S_IFREG) => Kind::File,
        m if m == bits(libc::S_IFDIR) => Kind::Dir,
        m if m == bits(libc::S_IFLNK) => Kind::Symlink,
        _ => Kind::Other,
    };
    Ok(Stat {
        kind,
        size: u64::try_from(st.st_size).unwrap_or(0),
        mode: bits(st.st_mode) & 0o7777,
        mtime_ns: (st.st_mtime as i64)
            .saturating_mul(1_000_000_000)
            .saturating_add(st.st_mtime_nsec as i64),
        ino: st.st_ino as u64,
    })
}

/// The names in the directory `dir` (not `.` or `..`), in no order. `dir` stays usable.
#[allow(unsafe_code)]
pub fn list_dir(dir: BorrowedFd<'_>) -> io::Result<Vec<OsString>> {
    let dup = dir.try_clone_to_owned()?;
    // SAFETY: fdopendir(3) on a descriptor we own; on success the stream owns it (we give it up
    // below), on failure we still hold it and it closes when `dup` drops.
    let stream = unsafe { libc::fdopendir(dup.as_raw_fd()) };
    if stream.is_null() {
        return Err(io::Error::last_os_error());
    }
    let _ = dup.into_raw_fd();
    // SAFETY: `stream` is the open stream just made; a duplicate shares the offset of `dir`, so
    // start at the top.
    unsafe { libc::rewinddir(stream) };
    let mut names = Vec::new();
    let failed = loop {
        // readdir(3) returns NULL both at the end and on an error; only errno tells them apart, so
        // it is cleared first (E15 security review L9: a partial listing read as "deleted").
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        // SAFETY: __error(3) returns this thread's errno slot, always valid to write.
        unsafe {
            *libc::__error() = 0
        };
        #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
        // SAFETY: __errno_location(3) returns this thread's errno slot, always valid to write.
        unsafe {
            *libc::__errno_location() = 0
        };
        // SAFETY: readdir(3) on our open stream; the entry is read before the next call.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let e = io::Error::last_os_error();
            break (e.raw_os_error() != Some(0)).then_some(e);
        }
        // SAFETY: a non-null entry's `d_name` is a NUL-terminated string valid until the next
        // readdir or closedir.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let name = OsStr::from_bytes(name.to_bytes());
        if name != "." && name != ".." {
            names.push(name.to_owned());
        }
    };
    // SAFETY: closedir(3) on the stream we opened, once; it closes the descriptor too.
    unsafe { libc::closedir(stream) };
    match failed {
        Some(e) => Err(e),
        None => Ok(names),
    }
}

/// A `mode_t` as `u32`: it is `u16` on macOS and already `u32` on Linux.
#[allow(clippy::useless_conversion)]
fn bits(m: libc::mode_t) -> u32 {
    u32::from(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read as _, Write as _};

    fn temp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ainkrad-beneath-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d.canonicalize().unwrap()
    }

    #[test]
    fn a_walk_makes_reads_and_lists_beneath_the_root() {
        let d = temp("walk");
        let root = open_root(&d).unwrap();
        let dir = mkdir_all_beneath(root.as_fd(), "a/b", 0o777).unwrap();
        let fd = openat_nofollow(
            dir.as_fd(),
            "f",
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o644,
        )
        .unwrap();
        fs::File::from(fd).write_all(b"hi").unwrap();
        let mut got = String::new();
        let fd = open_beneath(root.as_fd(), "a/b/f", libc::O_RDONLY, 0).unwrap();
        fs::File::from(fd).read_to_string(&mut got).unwrap();
        assert_eq!(got, "hi");
        let names = list_dir(dir.as_fd()).unwrap();
        assert_eq!(names, [OsString::from("f")]);
        let st = fstatat(dir.as_fd(), "f").unwrap();
        assert_eq!((st.kind, st.size), (Kind::File, 2));
        renameat(dir.as_fd(), "f", dir.as_fd(), "g").unwrap();
        unlinkat(dir.as_fd(), "g", false).unwrap();
        assert!(list_dir(dir.as_fd()).unwrap().is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn a_link_dotdot_or_an_absolute_path_is_refused_whatever_the_route() {
        let d = temp("refuse");
        let outside = temp("refuse-out");
        fs::write(outside.join("secret"), "x").unwrap();
        fs::create_dir_all(d.join("sub")).unwrap();
        std::os::unix::fs::symlink(&outside, d.join("sub/out")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), d.join("leaf")).unwrap();
        let root = open_root(&d).unwrap();
        let rd = |p: &str| open_beneath(root.as_fd(), p, libc::O_RDONLY, 0);
        assert!(rd("sub/out/secret").is_err(), "a link folder on the way");
        assert!(rd("leaf").is_err(), "a link as the last part");
        assert!(rd("../x").is_err() && rd("a/../x").is_err() && rd("a/./x").is_err());
        assert!(rd("/etc/passwd").is_err() && rd("a//b").is_err() && rd("a\0b").is_err());
        let long = "x".repeat(MAX_COMPONENT + 1);
        assert!(rd(&long).is_err());
        // The portable walk refuses the same, so a kernel without openat2 is no weaker.
        let w = |p: &str| walk(root.as_fd(), &parts(p).unwrap(), libc::O_RDONLY, 0);
        assert!(w("sub/out/secret").is_err() && w("leaf").is_err());
        assert!(mkdir_all_beneath(root.as_fd(), "sub/out/new", 0o777).is_err());
        assert!(!outside.join("new").exists());
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn links_are_read_and_made_without_being_followed() {
        let d = temp("link");
        let root = open_root(&d).unwrap();
        symlinkat("a/b", root.as_fd(), "l").unwrap();
        assert_eq!(
            readlinkat(root.as_fd(), "l").unwrap(),
            OsString::from("a/b")
        );
        assert_eq!(fstatat(root.as_fd(), "l").unwrap().kind, Kind::Symlink);
        assert!(readlinkat(root.as_fd(), "..").is_err());
        let _ = fs::remove_dir_all(&d);
    }
}
