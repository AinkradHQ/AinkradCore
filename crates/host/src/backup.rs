//! Backups (E2-6): `backup_now` starts the backup unit (in `lib.rs`, with the restarts) and
//! `backup_info` reads the schedule, the last run and the backups on disk. Reads only: the
//! unit's properties through `systemctl show` and the metadata of `*.age` files (never followed
//! through a link, never read, and no name leaves).

use std::os::unix::fs::MetadataExt;

use serde_json::{Value, json};

use crate::{Code, Ctx, status};

pub const SERVICE: &str = "ainkrad-backup.service";
const TIMER: &str = "ainkrad-backup.timer";
/// The most backups listed, newest first.
const KEEP: usize = 60;

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
    let Some(timer) = status::unit_with(
        ctx,
        TIMER,
        "LoadState,ActiveState,NextElapseUSecRealtime,LastTriggerUSec,TimersCalendar",
    ) else {
        return Err(Code::Failed);
    };
    let Some(run) = status::unit_with(
        ctx,
        SERVICE,
        "LoadState,ActiveState,Result,ExecMainStartTimestamp,ExecMainExitTimestamp,ExecMainStatus",
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
}
