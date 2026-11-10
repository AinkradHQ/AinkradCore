//! The only place a process is started. Two programs, fixed absolute paths, empty environment,
//! no stdin: `systemctl` and `journalctl`. Nothing installed under `/usr/local/bin` is ever run.

use std::io::{self, Read};
use std::process::{Command, Stdio};

pub const SYSTEMCTL: &str = "/usr/bin/systemctl";
pub const JOURNALCTL: &str = "/usr/bin/journalctl";

pub struct Out {
    pub ok: bool,
    pub stdout: Vec<u8>,
}

pub trait Exec: Send + Sync {
    /// Runs `prog` with exactly `args` (one argv element each, no shell). Output beyond
    /// `max_out` bytes is an error.
    fn run(&self, prog: &str, args: &[String], max_out: usize) -> io::Result<Out>;
}

pub struct Real;

impl Exec for Real {
    fn run(&self, prog: &str, args: &[String], max_out: usize) -> io::Result<Out> {
        if prog != SYSTEMCTL && prog != JOURNALCTL {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        run_unchecked(prog, args, max_out)
    }
}

/// Starts `prog` with an empty environment and no stdin. The allow-list is in `Real::run`.
/// ponytail: no wall-clock timeout on the child; the unit's `RuntimeMaxSec=30` ends a hung one.
fn run_unchecked(prog: &str, args: &[String], max_out: usize) -> io::Result<Out> {
    let mut child = Command::new(prog)
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = Vec::new();
    let mut pipe = child.stdout.take().expect("piped");
    let read = (&mut pipe)
        .take(max_out as u64 + 1)
        .read_to_end(&mut stdout);
    if read.is_err() || stdout.len() > max_out {
        drop(pipe);
        let _ = child.kill();
        let _ = child.wait();
        return Err(read
            .err()
            .unwrap_or_else(|| io::Error::other("output too large")));
    }
    let ok = child.wait()?.success();
    Ok(Out { ok, stdout })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// `env_clear` verified by behaviour: this test process has PATH, HOME and more, and a child
    /// started the helper's way sees none of it.
    #[test]
    fn a_child_sees_an_empty_environment_and_no_stdin() {
        assert!(std::env::vars().count() > 0);
        let out = run_unchecked("/usr/bin/env", &[], 4096).unwrap();
        assert!(
            out.ok && out.stdout.is_empty(),
            "{:?}",
            String::from_utf8_lossy(&out.stdout)
        );
        let cat = run_unchecked("/bin/cat", &[], 4096).unwrap();
        assert!(cat.ok && cat.stdout.is_empty(), "stdin is /dev/null");
    }

    #[test]
    fn output_over_the_cap_is_an_error_and_the_child_is_stopped() {
        let args = ["-c".to_owned(), "yes".to_owned()];
        assert!(run_unchecked("/bin/sh", &args, 1000).is_err());
    }
}
