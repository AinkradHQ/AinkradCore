//! `actions.log`: every mutating action and every refusal, never a successful read. Capped at
//! 1 MiB, then rotated to `actions.log.1` (the current file and one previous generation).
//!
//! A line is `<seq> <unix-seconds> <result> <action> <fields>`. Only validated values go in:
//! registry action names, ULIDs, device ids, numbers and codes. Request text is never copied, so
//! a client cannot forge or inject a line.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::state;

pub const FILE: &str = "actions.log";
pub const PREVIOUS: &str = "actions.log.1";
pub const MAX_BYTES: u64 = 1024 * 1024;
const LOCK: &str = "actions.lock";

pub struct Line<'a> {
    pub now: u64,
    pub result: &'a str,
    pub action: &'a str,
    pub fields: String,
    /// fsync the line: set for the record that comes before a root action.
    pub durable: bool,
}

fn seq_of(line: &str) -> Option<u64> {
    line.split(' ').next()?.parse().ok()
}

/// The sequence number of the last line in `path`, from its final 1 KiB.
fn last_seq(path: &Path) -> Option<u64> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let len = f.metadata().ok()?.len();
    f.seek(SeekFrom::Start(len.saturating_sub(1024))).ok()?;
    let mut tail = Vec::new();
    f.take(1024).read_to_end(&mut tail).ok()?;
    String::from_utf8_lossy(&tail)
        .lines()
        .rev()
        .find_map(seq_of)
}

/// Appends one line, rotating first when it would pass the cap. Holds a short blocking lock of
/// its own (`actions.lock`), so concurrent instances neither repeat a sequence number nor race
/// the rotation. An error means the line was not written.
pub fn append(dir: &Path, line: &Line) -> io::Result<()> {
    let lock = state::open_lock(dir, LOCK)?;
    lock.lock()?;
    let path = dir.join(FILE);
    let seq = last_seq(&path)
        .or_else(|| last_seq(&dir.join(PREVIOUS)))
        .map_or(1, |s| s + 1);
    let text = format!(
        "{seq} {} {} {} {}\n",
        line.now, line.result, line.action, line.fields
    );
    let size = std::fs::symlink_metadata(&path).map_or(0, |m| m.len());
    if size > 0 && size + text.len() as u64 > MAX_BYTES {
        std::fs::rename(&path, dir.join(PREVIOUS))?;
    }
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    f.write_all(text.as_bytes())?;
    if line.durable {
        f.sync_data()?;
    }
    Ok(())
}

/// One parsed line, oldest first across the rotation.
pub struct Entry {
    pub seq: u64,
    pub at: u64,
    pub result: String,
    pub text: String,
}

pub fn read_all(dir: &Path) -> Vec<Entry> {
    let mut out = Vec::new();
    for name in [PREVIOUS, FILE] {
        let Ok(bytes) = state::read_capped(&dir.join(name), MAX_BYTES * 2) else {
            continue;
        };
        for line in String::from_utf8_lossy(&bytes).lines() {
            let mut p = line.splitn(4, ' ');
            let (Some(seq), Some(at), Some(result), Some(text)) = (
                p.next().and_then(|s| s.parse().ok()),
                p.next().and_then(|s| s.parse().ok()),
                p.next(),
                p.next(),
            ) else {
                continue;
            };
            out.push(Entry {
                seq,
                at,
                result: result.to_owned(),
                text: text.to_owned(),
            });
        }
    }
    out
}
