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
}
