//! Backups (E2-6): `backup_now` starts the backup unit (in `lib.rs`, with the restarts) and
//! `backup_info` reads the schedule, the last run and the backups on disk. Reads only: the
//! unit's properties through `systemctl show` and the metadata of `*.age` files (never followed
//! through a link, never read, and no name leaves).

use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::{Code, Ctx, state, status};

pub const SERVICE: &str = "ainkrad-backup.service";
const TIMER: &str = "ainkrad-backup.timer";
/// The most backups listed, newest first.
const KEEP: usize = 60;
/// The Core's own default when the config has no `backup_keep_local`.
const KEEP_DEFAULT: u32 = 7;
const KEY: &str = "backup_keep_local";
const CONFIG_MAX: u64 = 64 * 1024;

/// The Core's `config.toml`: next to its `backups/` directory (`<home>/config.toml`).
fn config_path(ctx: &Ctx) -> Option<PathBuf> {
    Some(ctx.backups_dir.parent()?.join("config.toml"))
}

/// The value of `backup_keep_local = N` on a line (a trailing `# comment` is ignored).
fn keep_of(line: &str) -> Option<Option<u32>> {
    let rest = line.trim_start().strip_prefix(KEY)?;
    let value = rest.trim_start().strip_prefix('=')?;
    Some(value.split('#').next()?.trim().parse().ok())
}

/// How many local backups the config keeps (the Core's default, 7, when the key is absent);
/// `None` when the config cannot be read or the key is not a count.
pub fn retention(ctx: &Ctx) -> Option<u32> {
    let bytes = state::read_capped(&config_path(ctx)?, CONFIG_MAX).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    text.lines().find_map(keep_of).unwrap_or(Some(KEEP_DEFAULT))
}

/// `text` with the `backup_keep_local` line set to `keep` (added at the end when there is none).
/// Every other line is kept byte for byte.
fn with_keep(text: &str, keep: u32) -> String {
    let line = format!("{KEY} = {keep}");
    let mut done = false;
    let mut out: Vec<String> = text
        .lines()
        .map(|l| {
            if !done && keep_of(l).is_some() {
                done = true;
                line.clone()
            } else {
                l.to_owned()
            }
        })
        .collect();
    if !done {
        out.push(line);
    }
    out.join("\n") + "\n"
}

/// Sets `backup_keep_local` in the Core's config (the one thing this action may write). The
/// config is the Core user's, in a directory that user can write, and this runs as root, so: the
/// file is read without following a link and capped; the new copy is a fresh file made
/// exclusively (a link or file planted at its name is removed first, and one planted after the
/// removal fails the write), given the old file's mode and owner, synced, then renamed over it.
pub fn set_keep(ctx: &Ctx, keep: u32) -> Result<(), Code> {
    let path = config_path(ctx).ok_or(Code::Failed)?;
    let old = match std::fs::symlink_metadata(&path) {
        Ok(m) if m.is_file() => m,
        Ok(_) => return Err(Code::Failed),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Code::NotInstalled),
        Err(_) => return Err(Code::Failed),
    };
    let text = state::read_capped(&path, CONFIG_MAX)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or(Code::Failed)?;
    let tmp = path.with_file_name("config.toml.keep.tmp");
    let _ = std::fs::remove_file(&tmp);
    let written = (|| -> io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(old.mode() & 0o777)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        std::os::unix::fs::fchown(&f, Some(old.uid()), Some(old.gid()))?;
        f.write_all(with_keep(&text, keep).as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, &path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(Code::Failed);
    }
    Ok(())
}

/// The `OnCalendar=` expression in `systemctl show`'s `TimersCalendar` value
/// (`{ OnCalendar=daily ; next_elapse=… }`).
pub fn calendar(v: &str) -> Option<String> {
    let rest = v.split_once("OnCalendar=")?.1;
    let end = rest.find(" ;").unwrap_or(rest.len());
    let c = rest[..end].trim().trim_end_matches('}').trim();
    (!c.is_empty()).then(|| c.to_owned())
}

/// `(unix seconds, bytes)` of every regular `*.age` file in the backups directory, newest first.
pub fn backups(ctx: &Ctx) -> Vec<(u64, u64)> {
    let Ok(dir) = std::fs::read_dir(&ctx.backups_dir) else {
        return vec![];
    };
    let mut out: Vec<(u64, u64)> = dir
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().ends_with(".age"))
        // `DirEntry::metadata` does not follow a link: a link is not a regular file here.
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| (u64::try_from(m.mtime()).unwrap_or(0), m.len()))
        .collect();
    out.sort_unstable_by(|a, b| b.cmp(a));
    out.truncate(KEEP);
    out
}

pub fn info(ctx: &Ctx) -> Result<Value, Code> {
    let get = |p: &std::collections::BTreeMap<String, String>, k: &str| {
        p.get(k).cloned().unwrap_or_default()
    };
    let Some(timer) = status::unit_ts(
        ctx,
        TIMER,
        "LoadState,ActiveState,NextElapseUSecRealtime,LastTriggerUSec,TimersCalendar",
        true,
    ) else {
        return Err(Code::Failed);
    };
    let Some(run) = status::unit_ts(
        ctx,
        SERVICE,
        "LoadState,ActiveState,Result,ExecMainStartTimestamp,ExecMainExitTimestamp,ExecMainStatus",
        true,
    ) else {
        return Err(Code::Failed);
    };
    let installed = get(&run, "LoadState") != "not-found" && !get(&run, "LoadState").is_empty();
    let history: Vec<Value> = backups(ctx)
        .into_iter()
        .map(|(at, bytes)| json!({"at": at, "bytes": bytes}))
        .collect();
    Ok(json!({
        "installed": installed,
        "timer": {
            "active": get(&timer, "ActiveState"),
            "calendar": calendar(&get(&timer, "TimersCalendar")),
            "next": get(&timer, "NextElapseUSecRealtime"),
            "last": get(&timer, "LastTriggerUSec"),
        },
        "run": {
            "active": get(&run, "ActiveState"),
            "result": get(&run, "Result"),
            "started": get(&run, "ExecMainStartTimestamp"),
            "finished": get(&run, "ExecMainExitTimestamp"),
            "exit_status": get(&run, "ExecMainStatus").parse::<i64>().ok(),
        },
        "history": history,
        "retention": retention(ctx),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_calendar_is_read_out_of_the_timers_calendar_value() {
        assert_eq!(
            calendar("{ OnCalendar=daily ; next_elapse=Fri 2026-11-20 00:12:00 UTC }").as_deref(),
            Some("daily")
        );
        assert_eq!(
            calendar("{ OnCalendar=*-*-* 03:00:00 ; next_elapse=n/a }").as_deref(),
            Some("*-*-* 03:00:00")
        );
        assert_eq!(calendar("{ OnCalendar=hourly }").as_deref(), Some("hourly"));
        assert_eq!(calendar(""), None);
    }

    #[test]
    fn the_keep_line_is_read_and_set_and_the_rest_of_the_config_is_kept() {
        let text = "home = \"/x\"\n# keep\nbackup_keep_local = 7 # days\nmodules = []\n";
        assert_eq!(text.lines().find_map(keep_of), Some(Some(7)));
        assert_eq!(
            with_keep(text, 30),
            "home = \"/x\"\n# keep\nbackup_keep_local = 30\nmodules = []\n"
        );
        assert_eq!(
            with_keep("home = \"/x\"", 3),
            "home = \"/x\"\nbackup_keep_local = 3\n"
        );
        assert_eq!(keep_of("backup_keep_local_x = 1"), None, "another key");
        assert_eq!(keep_of("backup_keep_local = many"), Some(None));
    }
}
