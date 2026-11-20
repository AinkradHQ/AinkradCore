//! The workspace's only `unsafe` (decision P2.2): small, audited wrappers over libc calls the
//! standard library does not offer. Every other crate keeps `unsafe_code = forbid` and calls
//! these. Each block is listed in [`INVENTORY`]; a test fails when a block is added without it.
//!
//! The terminal host (E2-02, E2-03) needs: its own session (`setsid`), signals to a terminal's
//! process group (`killpg`), and the user id its socket admits (`getuid`). Landlock, seccomp
//! and Seatbelt (E2-09) come here too.

use std::io;

mod beneath;
pub use beneath::*;

/// Every `unsafe` block in this crate, by function: what it calls and why it holds.
pub const INVENTORY: &[(&str, &str)] = &[
    ("setsid", "libc::setsid: no arguments, no memory"),
    ("killpg", "libc::kill with a negative pid: integers only"),
    (
        "kill_pid",
        "libc::kill with one positive pid: integers only",
    ),
    ("getuid", "libc::getuid: no arguments, cannot fail"),
    (
        "redirect_output",
        "libc::dup2 of a descriptor we own onto 1 and 2: integers only",
    ),
    (
        "peer_uid",
        "libc::getsockopt(SO_PEERCRED) into a ucred we own, on a borrowed descriptor",
    ),
    ("wait_exited", "libc::waitid into a zeroed siginfo_t we own"),
    ("reap", "libc::waitpid with a null status pointer"),
    (
        "close_fds_on_exec",
        "pre_exec closure: one raw close_range syscall with integer arguments",
    ),
    (
        "pty_child_on_exec",
        "pre_exec closure: setsid, ioctl(TIOCSCTTY), fcntl, dup2 and close_range with integer arguments",
    ),
    (
        "tty_size",
        "libc::ioctl(TIOCGWINSZ) into a winsize we own, on a borrowed descriptor",
    ),
    (
        "raw_mode",
        "libc::tcgetattr, cfmakeraw and tcsetattr on a termios we own, on a borrowed descriptor",
    ),
    (
        "pipe_setup",
        "libc::fcntl(F_GETFL, F_SETFL, F_SETPIPE_SZ) with integer arguments, on a borrowed descriptor",
    ),
    ("no_dump", "libc::prctl(PR_SET_DUMPABLE, 0): integers only"),
    (
        "adopt_fd",
        "libc::fcntl(F_GETFD) probe, then OwnedFd::from_raw_fd on a descriptor the caller says it was handed",
    ),
    (
        "sandbox_child",
        "pre_exec closure: prctl(PR_SET_PDEATHSIG) and fcntl(F_SETFD) with integer arguments",
    ),
    (
        "join_cgroup",
        "pre_exec closure: one write(2) of a static one-byte buffer to a descriptor we own",
    ),
    (
        "die_with_parent",
        "pre_exec closure: prctl(PR_SET_PDEATHSIG) and getppid, integer arguments only",
    ),
    (
        "openat_nofollow",
        "libc::openat on a borrowed descriptor and a NUL-terminated single component, O_NOFOLLOW forced",
    ),
    (
        "openat2_beneath",
        "raw openat2 syscall with RESOLVE_BENEATH|NO_SYMLINKS|NO_MAGICLINKS and an open_how we own",
    ),
    (
        "mkdirat",
        "libc::mkdirat on a borrowed descriptor and one component",
    ),
    (
        "renameat",
        "libc::renameat on two borrowed descriptors and two single components",
    ),
    (
        "unlinkat",
        "libc::unlinkat on a borrowed descriptor and one component",
    ),
    (
        "symlinkat",
        "libc::symlinkat with two NUL-terminated strings and a borrowed descriptor",
    ),
    (
        "readlinkat",
        "libc::readlinkat into a buffer we own, on a borrowed descriptor",
    ),
    (
        "fstatat",
        "libc::fstatat(AT_SYMLINK_NOFOLLOW) into a zeroed stat we own",
    ),
    (
        "list_dir",
        "fdopendir on a duplicated descriptor we own, readdir/closedir on that stream only",
    ),
];

/// Makes the calling process the leader of a new session and process group, with no
/// controlling terminal: a parent's death or its terminal's hang-up no longer reaches it.
#[allow(unsafe_code)]
pub fn setsid() -> io::Result<()> {
    // SAFETY: setsid(2) takes no arguments and touches no memory of ours; it only fails
    // (EPERM) when the caller already leads a process group, which is reported.
    let r = unsafe { libc::setsid() };
    if r == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Points this process's stdout and stderr at `file` (a launchd agent has no log of its own).
#[allow(unsafe_code)]
pub fn redirect_output(file: &std::fs::File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    for target in [1, 2] {
        // SAFETY: dup2(2) with a descriptor `file` keeps open and a standard descriptor number;
        // it touches no memory of ours and failure is reported.
        if unsafe { libc::dup2(file.as_raw_fd(), target) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Marks every descriptor above 2 close-on-exec in the child just before it execs `cmd`, so a
/// descriptor the parent leaked (a connected socket, a listener) does not reach the program, which
/// bubblewrap otherwise passes through. Linux only. Kernels before 5.9 have no `close_range`, and
/// 5.9 to 5.10 have it but reject the CLOEXEC flag (EINVAL): the call is then ignored, and the
/// sandbox script, which closes the descriptors itself, is what covers those kernels.
#[allow(unsafe_code)]
pub fn close_fds_on_exec(cmd: &mut std::process::Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `pre_exec` is unsafe because its closure runs between fork and exec. This one
        // makes a single raw close_range(2) syscall with integer arguments (CLOSE_RANGE_CLOEXEC is
        // 4): it allocates nothing, takes no lock and touches no memory of ours, so it is
        // async-signal-safe. An error (an old kernel without the call) is ignored on purpose.
        unsafe {
            cmd.pre_exec(|| {
                let _ = libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 4u32);
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cmd;
}

/// Makes the PTY slave on stdin the child's controlling terminal and hands it `fd` as descriptor 3
/// (the key handoff of `ssh-pty`: a pipe the parent filled and closed) and, when given, `report` as
/// descriptor 4 (the write end of a pipe the parent reads after the child ended).
///
/// Invariant this relies on: every descriptor the terminal host holds is close-on-exec (Rust's
/// standard library opens everything that way, and the host opens nothing by hand), so exec drops
/// whatever is above 4 on every OS. On Linux, `close_range` additionally marks everything above the
/// handed descriptors close-on-exec before the exec, against a descriptor that was not. An old
/// kernel (ENOSYS, EINVAL) or a seccomp filter (EPERM) is tolerated because of that invariant; any
/// other error fails the spawn instead of leaving the descriptors open (`pre_exec` may not log: it
/// runs between fork and exec, where nothing may allocate).
#[allow(unsafe_code)]
pub fn pty_child_on_exec(
    cmd: &mut std::process::Command,
    fd: std::os::fd::RawFd,
    report: Option<std::os::fd::RawFd>,
) {
    use std::os::unix::process::CommandExt;
    // SAFETY: `pre_exec` is unsafe because its closure runs between fork and exec. This one only
    // makes integer-argument syscalls (setsid, ioctl, fcntl, dup2, close_range): it allocates
    // nothing, takes no lock and touches no memory of ours, so it is async-signal-safe.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            #[allow(clippy::cast_lossless)]
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            // Both sources are first moved out of 3 and 4 (close-on-exec copies at 10 or above), so
            // neither `dup2` below can land on the other's source.
            let key = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10);
            if key == -1 {
                return Err(io::Error::last_os_error());
            }
            let rep = match report {
                Some(report) => libc::fcntl(report, libc::F_DUPFD_CLOEXEC, 10),
                None => -1,
            };
            if report.is_some() && rep == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::dup2(key, 3) == -1 || (rep != -1 && libc::dup2(rep, 4) == -1) {
                return Err(io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            {
                let first: u32 = if report.is_some() { 5 } else { 4 };
                if libc::syscall(libc::SYS_close_range, first, u32::MAX, 4u32) == -1 {
                    let e = io::Error::last_os_error();
                    if !matches!(
                        e.raw_os_error(),
                        Some(libc::ENOSYS | libc::EINVAL | libc::EPERM)
                    ) {
                        return Err(e);
                    }
                }
            }
            Ok(())
        });
    }
}

/// Makes a pipe end non-blocking and, on Linux, asks for a capacity of `size` bytes (the request
/// may be refused or rounded: it is best effort). A write that would block then fails with
/// `WouldBlock` instead of hanging.
#[allow(unsafe_code)]
pub fn pipe_setup(fd: std::os::fd::BorrowedFd<'_>, size: usize) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let raw = fd.as_raw_fd();
    // SAFETY: fcntl(2) with integer arguments on a descriptor borrowed for the call; no memory.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(io::Error::last_os_error());
    }
    #[cfg(target_os = "linux")]
    {
        let size = libc::c_int::try_from(size).unwrap_or(libc::c_int::MAX);
        // SAFETY: as above; a refusal (EPERM over the pipe limit) is ignored on purpose.
        let _ = unsafe { libc::fcntl(raw, libc::F_SETPIPE_SZ, size) };
    }
    #[cfg(not(target_os = "linux"))]
    let _ = size;
    Ok(())
}

/// Keeps this process's memory out of core dumps and away from `ptrace` by other processes of the
/// same user (Linux; elsewhere nothing). Best effort.
#[allow(unsafe_code)]
pub fn no_dump() {
    #[cfg(target_os = "linux")]
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes integers and touches no memory of ours.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

/// Takes ownership of descriptor `fd` the caller was handed by its parent (e.g. 3), so dropping the
/// result closes it. Fails when `fd` is not open.
#[allow(unsafe_code)]
pub fn adopt_fd(fd: std::os::fd::RawFd) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: fcntl(F_GETFD) takes integers and only reports whether `fd` is open.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is open (just probed) and the caller states it is handed over to us alone, so
    // nothing else closes it: single ownership.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// The size of the terminal on `fd`, as `(rows, cols)`.
#[allow(unsafe_code)]
pub fn tty_size(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<(u16, u16)> {
    use std::os::fd::AsRawFd;
    // SAFETY: an all-zero `winsize` is a valid value (integers only).
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: TIOCGWINSZ writes one `winsize` through the pointer, which is ours and live; `fd` is
    // borrowed, so open for the call.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ as _, &mut ws) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((ws.ws_row, ws.ws_col))
}

/// The terminal settings of a descriptor, put back on drop.
pub struct RawMode<'a> {
    fd: std::os::fd::BorrowedFd<'a>,
    saved: libc::termios,
}

/// Switches the terminal on `fd` to raw mode (no echo, no line editing, no signals from keys):
/// bytes go through as typed. The returned guard restores the old settings on drop.
#[allow(unsafe_code)]
pub fn raw_mode(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<RawMode<'_>> {
    use std::os::fd::AsRawFd;
    let raw = fd.as_raw_fd();
    // SAFETY: an all-zero `termios` is a valid value (integers only); tcgetattr fills it.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: tcgetattr writes one `termios` through a pointer that is ours and live; failure
    // (not a terminal) is reported.
    if unsafe { libc::tcgetattr(raw, &mut t) } == -1 {
        return Err(io::Error::last_os_error());
    }
    let saved = t;
    // SAFETY: cfmakeraw only edits the `termios` we own.
    unsafe { libc::cfmakeraw(&mut t) };
    // SAFETY: tcsetattr reads one `termios` through a pointer that is ours and live.
    if unsafe { libc::tcsetattr(raw, libc::TCSANOW, &t) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(RawMode { fd, saved })
}

impl Drop for RawMode<'_> {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: tcsetattr reads the `termios` we saved; the descriptor is borrowed for as long as
        // this guard lives. A failure leaves the terminal as it is.
        unsafe { libc::tcsetattr(self.fd.as_raw_fd(), libc::TCSANOW, &self.saved) };
    }
}

/// For a sandbox the runner starts (Design V6-01), in the child just before exec: it gets SIGKILL
/// when the thread that started it dies (a runner restart cannot leave a sandbox behind), and `keep`
/// (a descriptor the caller holds open, such as a seccomp program for bubblewrap's `--seccomp`) is
/// inherited across exec under its own number. Register it after [`close_fds_on_exec`], which
/// marks every descriptor above 2 close-on-exec. Linux only; elsewhere nothing is done.
#[allow(unsafe_code)]
pub fn sandbox_child(cmd: &mut std::process::Command, keep: Option<std::os::fd::RawFd>) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `pre_exec` is unsafe because its closure runs between fork and exec. This one
        // makes two calls with integer arguments only, prctl(2) and fcntl(2): no allocation, no
        // lock, no memory of ours, so it is async-signal-safe. A failure is reported and the
        // spawn fails.
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                ) == -1
                {
                    return Err(io::Error::last_os_error());
                }
                if let Some(fd) = keep
                    && libc::fcntl(fd, libc::F_SETFD, 0) == -1
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (cmd, keep);
}

/// Moves the child into the cgroup whose `cgroup.procs` is open as `procs` (writes `0`, "me"),
/// between fork and exec: everything it then starts is born inside that cgroup's limits. The spawn
/// fails when the move does. Keep `procs` open until the spawn. Linux only; elsewhere nothing is
/// done.
#[allow(unsafe_code)]
pub fn join_cgroup(cmd: &mut std::process::Command, procs: &std::fs::File) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::process::CommandExt;
        let fd = procs.as_raw_fd();
        // SAFETY: `pre_exec` is unsafe because its closure runs between fork and exec. This one
        // makes one write(2) of a static one-byte buffer to a descriptor the parent keeps open
        // across the spawn: no allocation, no lock, so it is async-signal-safe. A failure is
        // reported and the spawn fails.
        unsafe {
            cmd.pre_exec(move || {
                if libc::write(fd, b"0".as_ptr().cast(), 1) == 1 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (cmd, procs);
}

/// Has the child `cmd` starts killed (SIGKILL) when the thread that spawned it dies, so a helper
/// that is itself killed leaves no `git`/`podman` behind. Linux only; elsewhere a no-op. A child
/// whose parent died before the call exits at once.
#[allow(unsafe_code)]
pub fn die_with_parent(cmd: &mut std::process::Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let parent = i32::try_from(std::process::id()).unwrap_or(0);
        // SAFETY: the closure runs between fork and exec. prctl(2) with integer arguments and
        // getppid(2) allocate nothing, take no lock and touch no memory of ours, so they are
        // async-signal-safe; an error is reported back to `spawn`.
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == -1 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(io::Error::other("the parent is gone"));
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = cmd;
}

/// Sends `signal` to every process in the group `pgid`. `Ok(false)` when the group is gone
/// (ESRCH). A `pgid` of 0 or 1 is refused: those mean "my own group" and "every process".
#[allow(unsafe_code)]
pub fn killpg(pgid: u32, signal: i32) -> io::Result<bool> {
    let Ok(pgid) = i32::try_from(pgid) else {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    };
    if pgid <= 1 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    // SAFETY: kill(2) with integer arguments only; a negative pid addresses the group, and
    // `pgid > 1` was checked above so it can never mean "every process" (-1).
    let r = unsafe { libc::kill(-pgid, signal) };
    if r == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        _ => Err(e),
    }
}

/// Sends `signal` to the single process `pid`. `Ok(false)` when it is gone (ESRCH). A `pid`
/// of 0 or 1 is refused: those mean "my own group" and "init".
#[allow(unsafe_code)]
pub fn kill_pid(pid: u32, signal: i32) -> io::Result<bool> {
    let Ok(pid) = i32::try_from(pid) else {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    };
    if pid <= 1 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    // SAFETY: kill(2) with integer arguments only; `pid > 1` was checked, so it is never a
    // group (<= 0) or "every process" (-1).
    let r = unsafe { libc::kill(pid, signal) };
    if r == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        _ => Err(e),
    }
}

/// The real user id of this process.
#[allow(unsafe_code)]
pub fn getuid() -> u32 {
    // SAFETY: getuid(2) takes no arguments and always succeeds.
    unsafe { libc::getuid() }
}

/// The effective user id of the process on the other end of the connected Unix socket `fd`, as
/// the kernel recorded it when the connection was made (`SO_PEERCRED`); the peer cannot choose it.
/// Linux only: elsewhere it is an `Unsupported` error, so a caller that fails closed refuses.
#[allow(unsafe_code)]
pub fn peer_uid(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let want = size_of::<libc::ucred>();
        let mut len = want as libc::socklen_t;
        // SAFETY: `fd` is a descriptor borrowed for the call; `cred` is a plain C struct we own,
        // `len` is its size, and the kernel writes at most `len` bytes into it.
        let r = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &mut len,
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
        if len as usize != want {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        Ok(cred.uid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = fd;
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

/// How a waited-for child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// `exit(code)`.
    Code(i32),
    /// Killed by this signal (a core dump included).
    Signal(i32),
}

/// Blocks until child `pid` has exited and reports how, **without reaping it**
/// (`waitid(P_PID, pid, WEXITED | WNOWAIT)`). The child stays a zombie, so its pid, and the
/// process group it led, cannot be reused until [`reap`]: a signal to that group can never
/// reach an unrelated process that later got the same number.
#[allow(unsafe_code)]
pub fn wait_exited(pid: u32) -> io::Result<Ended> {
    let id = libc::id_t::from(pid);
    loop {
        // SAFETY: an all-zero `siginfo_t` is a valid value of this plain C struct; `waitid`
        // writes into it through the pointer, which lives for the call.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: integer arguments and a pointer to the `siginfo_t` above, which we own and
        // which outlives the call.
        let r = unsafe { libc::waitid(libc::P_PID, id, &mut info, libc::WEXITED | libc::WNOWAIT) };
        if r == -1 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        // SAFETY: `waitid` succeeded for a child that exited, so the kernel filled the
        // child-status fields `si_status` reads (Linux and macOS both define the accessor).
        let status = unsafe { info.si_status() };
        return Ok(match info.si_code {
            libc::CLD_EXITED => Ended::Code(status),
            _ => Ended::Signal(status),
        });
    }
}

/// Reaps child `pid` (one that [`wait_exited`] reported), freeing its pid. `Ok(false)` if it
/// was not a child of ours to reap (ECHILD).
#[allow(unsafe_code)]
pub fn reap(pid: u32) -> io::Result<bool> {
    let Ok(pid) = i32::try_from(pid) else {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    };
    loop {
        // SAFETY: integer arguments; a null status pointer is allowed and means "do not report".
        let r = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        if r == pid {
            return Ok(true);
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::ECHILD) => return Ok(false),
            _ => return Err(e),
        }
    }
}

/// The number of a signal named without `SIG` (`"TERM"`), if it is one we deliver.
pub fn signal_number(name: &str) -> Option<i32> {
    Some(match name {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "TERM" => libc::SIGTERM,
        "KILL" => libc::SIGKILL,
        "USR1" => libc::SIGUSR1,
        "USR2" => libc::SIGUSR2,
        "CONT" => libc::SIGCONT,
        "STOP" => libc::SIGSTOP,
        "TSTP" => libc::SIGTSTP,
        "WINCH" => libc::SIGWINCH,
        _ => return None,
    })
}

/// The name (without `SIG`) of a signal number, for the ones [`signal_number`] knows.
pub fn signal_name(n: i32) -> Option<&'static str> {
    [
        "HUP", "INT", "QUIT", "TERM", "KILL", "USR1", "USR2", "CONT", "STOP", "TSTP", "WINCH",
    ]
    .into_iter()
    .find(|name| signal_number(name) == Some(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unsafe inventory (E2-09.1's rule from the start): one entry per block.
    #[test]
    fn every_unsafe_block_is_in_the_inventory() {
        let src = concat!(include_str!("lib.rs"), include_str!("beneath.rs"));
        let blocks = src.matches(concat!("unsafe", " {")).count();
        let any = src.matches(concat!("unsafe", "{")).count()
            + src.matches(concat!("unsafe", " fn")).count()
            + src.matches(concat!("unsafe", " impl")).count();
        assert_eq!(any, 0, "only plain unsafe blocks, each in INVENTORY");
        let safety = src.matches(concat!("// SAFE", "TY:")).count();
        assert_eq!(blocks, safety, "every block has a SAFETY comment");
        // Each inventoried function holds at least one block.
        assert!(blocks >= INVENTORY.len(), "add the new block to INVENTORY");
        for (name, _) in INVENTORY {
            assert!(src.contains(&format!("pub fn {name}(")), "{name}");
        }
    }

    #[test]
    fn closing_descriptors_on_exec_leaves_the_spawn_working() {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "exit 7"]);
        close_fds_on_exec(&mut cmd);
        assert_eq!(cmd.status().unwrap().code(), Some(7));
    }

    /// The death signal follows the thread that spawned the child (what the run helper relies on
    /// when it is killed mid-op).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_child_dies_with_the_thread_that_spawned_it() {
        use std::os::unix::process::ExitStatusExt;
        let mut child = std::thread::spawn(|| {
            let mut cmd = std::process::Command::new("sleep");
            cmd.arg("60");
            die_with_parent(&mut cmd);
            cmd.spawn().unwrap()
        })
        .join()
        .unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn group_signals_refuse_the_dangerous_ids() {
        assert!(killpg(0, 0).is_err());
        assert!(killpg(1, 0).is_err());
        assert!(killpg(u32::MAX, 0).is_err());
        // A group that does not exist (pids are below this on both OSes).
        assert!(!killpg(99_999_999, 0).unwrap());
    }

    /// The exit is seen and the child stays a zombie (pid held) until it is reaped; this is
    /// what keeps a later signal to its group from reaching a recycled pid (review H1).
    // The children are reaped by `reap`, which is what is under test.
    #[allow(clippy::zombie_processes)]
    #[test]
    fn an_exit_is_observed_without_reaping() {
        let child = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 7"])
            .spawn()
            .unwrap();
        let pid = child.id();
        assert_eq!(wait_exited(pid).unwrap(), Ended::Code(7));
        assert_eq!(wait_exited(pid).unwrap(), Ended::Code(7), "still there");
        let stat = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&stat.stdout)
                .trim_start()
                .starts_with('Z')
        );
        assert!(reap(pid).unwrap());
        assert!(!reap(pid).unwrap(), "gone after the reap");
        let killed = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let _ = killpg_or_kill(killed.id());
        assert_eq!(
            wait_exited(killed.id()).unwrap(),
            Ended::Signal(libc::SIGKILL)
        );
        assert!(reap(killed.id()).unwrap());
    }

    fn killpg_or_kill(pid: u32) -> std::io::Result<()> {
        std::process::Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .map(drop)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_socket_peer_is_this_user_and_a_plain_file_is_refused() {
        use std::os::fd::AsFd;
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(peer_uid(a.as_fd()).unwrap(), getuid());
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(peer_uid(f.as_fd()).is_err());
    }

    #[test]
    fn names_map_to_numbers() {
        assert_eq!(signal_number("TERM"), Some(libc::SIGTERM));
        assert_eq!(signal_number("SIGTERM"), None);
        assert_ne!(getuid(), u32::MAX);
    }
}
