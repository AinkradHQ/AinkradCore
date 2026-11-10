//! `logs`: the journal of one fixed unit through `journalctl`, or, for `helper`, the helper's own
//! records: `actions.log` (refusals and root actions) and `mutations.log` (root actions only), merged.
//!
//! Fixed argv: `journalctl -u <fixed unit> -o json --no-pager --output-fields=MESSAGE,PRIORITY -n <N+1>`
//! (the cursor and timestamp fields are always printed), plus, when paging,
//! `-r` and `--cursor=<C>` as **one** argv element. A cursor is validated at parse
//! (`^[A-Za-z0-9=;_]{1,256}$`, so never a leading `-`).
//!
//! A log line is attacker-influenced text (anything the Core prints). It is redacted and cut, but
//! control characters are not removed: **a client must strip or escape control characters
//! (escape sequences, `\r`, backspace) before showing a line in a terminal.**
//!
//! Paging: the first page is the newest N entries (the extra one fetched only to know there are
//! older ones). "Older" asks `-r --cursor=<oldest seen>`, which returns that entry first and then
//! the N older ones; the cursor's own entry is dropped.

use serde_json::{Value, json};

use crate::exec::JOURNALCTL;
use crate::wire::{Code, Logs, Unit, valid_cursor};
use crate::{Ctx, actlog, redact};

const MAX_JOURNAL_OUTPUT: usize = 8 * 1024 * 1024;
/// The answer is cut to the newest lines that fit under this (the wire cap is 512 KiB).
const BUDGET: usize = 480 * 1024;

struct Raw {
    cursor: String,
    at_us: u64,
    level: &'static str,
    text: String,
}

fn level(priority: u8) -> &'static str {
    match priority {
        0..=3 => "error",
        4 => "warn",
        7 => "debug",
        _ => "info",
    }
}

/// `MESSAGE` as journalctl prints it: a string, or an array of numbers when it holds bytes that
/// are not UTF-8. Decoded lossily; the raw array is never passed on.
fn message(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => {
            let bytes: Vec<u8> = a
                .iter()
                .filter_map(|n| n.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub fn rfc3339(us: u64) -> String {
    let secs = (us / 1_000_000) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        (us / 1000) % 1000
    )
}

fn journal(ctx: &Ctx, unit: &str, l: &Logs) -> Result<Vec<Raw>, Code> {
    let mut args: Vec<String> = [
        "-u",
        unit,
        "-o",
        "json",
        "--no-pager",
        "--output-fields=MESSAGE,PRIORITY",
        "-n",
    ]
    .map(String::from)
    .into();
    args.push((l.lines + 1).to_string());
    if let Some(c) = &l.before {
        args.push("-r".into());
        args.push(format!("--cursor={c}"));
    }
    let out = ctx
        .exec
        .run(JOURNALCTL, &args, MAX_JOURNAL_OUTPUT)
        .map_err(|_| Code::Failed)?;
    if !out.ok {
        return Err(Code::Failed);
    }
    let mut raws: Vec<Raw> = out
        .stdout
        .split(|b| *b == b'\n')
        .filter_map(|line| serde_json::from_slice::<Value>(line).ok())
        .filter_map(|v| {
            let cursor = v
                .get("__CURSOR")?
                .as_str()
                .filter(|c| valid_cursor(c))?
                .to_owned();
            let at_us = v.get("__REALTIME_TIMESTAMP")?.as_str()?.parse().ok()?;
            let priority = v
                .get("PRIORITY")
                .and_then(Value::as_str)
                .and_then(|p| p.parse().ok());
            Some(Raw {
                cursor,
                at_us,
                level: level(priority.unwrap_or(6)),
                text: message(v.get("MESSAGE").unwrap_or(&Value::Null)),
            })
        })
        .collect();
    if l.before.is_some() {
        raws.reverse();
        // `-r --cursor` starts at the cursor's own entry: it was on the previous page.
        if raws.last().map(|r| &r.cursor) == l.before.as_ref() {
            raws.pop();
        }
    }
    Ok(raws)
}

/// The `helper` unit: `actions.log` and `mutations.log`. A cursor is `h<time><a|m><seq>`.
fn helper(ctx: &Ctx, l: &Logs) -> Result<Vec<Raw>, Code> {
    let key = |at: u64, mutation: bool, seq: u64| (at, mutation, seq);
    let before = match l.before.as_deref() {
        None => None,
        Some(c) => {
            let rest = c.strip_prefix('h').ok_or(Code::BadRequest)?;
            let split = rest.find(['a', 'm']).ok_or(Code::BadRequest)?;
            let (at, tail) = rest.split_at(split);
            let at: u64 = at.parse().map_err(|_| Code::BadRequest)?;
            let seq: u64 = tail[1..].parse().map_err(|_| Code::BadRequest)?;
            Some(key(at, tail.starts_with('m'), seq))
        }
    };
    Ok(actlog::read_all(&ctx.state_dir)
        .into_iter()
        .filter(|e| before.is_none_or(|b| key(e.at, e.mutation, e.seq) < b))
        .map(|e| Raw {
            cursor: format!("h{}{}{}", e.at, if e.mutation { 'm' } else { 'a' }, e.seq),
            at_us: e.at.saturating_mul(1_000_000),
            level: if matches!(e.result.as_str(), "ok" | "accepted") {
                "info"
            } else {
                "warn"
            },
            text: format!("{} {}", e.result, e.text),
        })
        .collect())
}

pub fn logs(ctx: &Ctx, l: &Logs) -> Result<Value, Code> {
    let mut raws = match l.unit.systemd() {
        Some(unit) => journal(ctx, unit, l)?,
        None => helper(ctx, l)?,
    };
    // Redact first, over everything fetched (the lookahead entry included, so a PEM block that
    // opened just before the page is still seen), then cut.
    let mut texts: Vec<String> = raws
        .iter()
        .map(|r| redact::pre_cut(r.text.clone()))
        .collect();
    redact::pem_across(&mut texts);
    // Newest `lines`, plus whether anything older was fetched.
    let paged_journal = l.before.is_some() && l.unit != Unit::Helper;
    let mut more = false;
    if raws.len() > l.lines {
        more = !paged_journal;
        let extra = raws.len() - l.lines;
        raws.drain(..extra);
        texts.drain(..extra);
    }
    let mut used = 0;
    let mut kept = Vec::new();
    for (r, t) in raws.iter().zip(texts).rev() {
        let text = redact::cap(redact::one(&t), redact::LINE_CAP);
        // The size on the wire: quotes double, control bytes become six, and the keys.
        used += serde_json::to_string(&text).map_or(text.len() * 6, |s| s.len()) + 64;
        if used > BUDGET {
            more = true;
            break;
        }
        kept.push(json!({"at": rfc3339(r.at_us), "level": r.level, "text": text}));
    }
    let cut = kept.len();
    let oldest = raws.len().checked_sub(cut).and_then(|i| raws.get(i));
    // A full journal page may have older entries behind it; the next ask finds out.
    let more = more || (paged_journal && cut == l.lines);
    kept.reverse();
    let mut out = json!({"lines": kept});
    if let (true, Some(o)) = (more, oldest) {
        out["next_before"] = json!(o.cursor);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::rfc3339;

    #[test]
    fn timestamps_are_rfc3339_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_709_164_800_123_000), "2024-02-29T00:00:00.123Z");
        assert_eq!(rfc3339(1_794_000_000_000_000), "2026-11-06T21:20:00.000Z");
    }
}
