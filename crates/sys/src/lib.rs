//! The workspace's only `unsafe` (decision P2.2): small, audited wrappers over libc calls the
//! standard library does not offer. Every other crate keeps `unsafe_code = forbid` and calls
//! these. Each block is listed in [`INVENTORY`]; a test fails when a block is added without it.
//!
//! The terminal host (E2-02, E2-03) needs: its own session (`setsid`), signals to a terminal's
//! process group (`killpg`), and the user id its socket admits (`getuid`). Landlock, seccomp
//! and Seatbelt (E2-09) come here too.

use std::io;

/// Every `unsafe` block in this crate, by function: what it calls and why it holds.
pub const INVENTORY: &[(&str, &str)] = &[
    ("setsid", "libc::setsid: no arguments, no memory"),
    ("killpg", "libc::kill with a negative pid: integers only"),
    (
        "kill_pid",
        "libc::kill with one positive pid: integers only",
    ),
    ("getuid", "libc::getuid: no arguments, cannot fail"),
    ("wait_exited", "libc::waitid into a zeroed siginfo_t we own"),
    ("reap", "libc::waitpid with a null status pointer"),
    (
        "close_fds_on_exec",
        "pre_exec closure: one raw close_range syscall with integer arguments",
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

/// Marks every descriptor above 2 close-on-exec in the child just before it execs `cmd`, so a
/// descriptor the parent leaked (a connected socket, a listener) does not reach the program, which
/// bubblewrap otherwise passes through. Linux only; a kernel without `close_range` ignores it.
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
        let src = include_str!("lib.rs");
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

    #[test]
    fn names_map_to_numbers() {
        assert_eq!(signal_number("TERM"), Some(libc::SIGTERM));
        assert_eq!(signal_number("SIGTERM"), None);
        assert_ne!(getuid(), u32::MAX);
    }
}
