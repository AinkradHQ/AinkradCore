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
    ("getuid", "libc::getuid: no arguments, cannot fail"),
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

/// The real user id of this process.
#[allow(unsafe_code)]
pub fn getuid() -> u32 {
    // SAFETY: getuid(2) takes no arguments and always succeeds.
    unsafe { libc::getuid() }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The unsafe inventory (E2-09.1's rule from the start): one entry per block.
    #[test]
    fn every_unsafe_block_is_in_the_inventory() {
        let src = include_str!("lib.rs");
        let blocks = src.matches(concat!("unsafe", " {")).count();
        assert_eq!(blocks, INVENTORY.len(), "add the new block to INVENTORY");
        for (name, _) in INVENTORY {
            assert!(src.contains(&format!("pub fn {name}(")), "{name}");
        }
    }

    #[test]
    fn group_signals_refuse_the_dangerous_ids() {
        assert!(killpg(0, 0).is_err());
        assert!(killpg(1, 0).is_err());
        assert!(killpg(u32::MAX, 0).is_err());
        // A group that does not exist (pids are below this on both OSes).
        assert!(!killpg(99_999_999, 0).unwrap());
    }

    #[test]
    fn names_map_to_numbers() {
        assert_eq!(signal_number("TERM"), Some(libc::SIGTERM));
        assert_eq!(signal_number("SIGTERM"), None);
        assert_ne!(getuid(), u32::MAX);
    }
}
