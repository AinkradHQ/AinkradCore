//! `runner ls | show <id>` and `run noop <id>`: the paired runners and their live state
//! (`/api/v1/runners`, scope `read`), and the no-op command sent through the Core's runner hub
//! (`POST /api/v1/runners/{id}/noop`, scope `agent`, no step-up).

use std::io::Write;

use serde_json::Value;

use crate::Error;
use crate::client::{Client, parse};
use crate::devices::s;

fn rid(id: &str) -> Result<&str, Error> {
    let ok = id
        .strip_prefix("d_")
        .is_some_and(|b| b.len() == 26 && b.bytes().all(|c| c.is_ascii_alphanumeric()));
    ok.then_some(id)
        .ok_or_else(|| Error::Usage(format!("{id:?} is not a runner's device id (d_…)")))
}

/// `id  name  online|degraded|offline  load/capacity  commands  version  last_seen`.
fn row(r: &Value) -> String {
    let state = match (r["online"].as_bool(), r["degraded"].as_bool()) {
        (Some(true), Some(true)) => "degraded",
        (Some(true), _) => "online",
        _ => "offline",
    };
    let commands: Vec<&str> = r["drivers"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|d| d["commands"].as_array().into_iter().flatten().map(s))
        .collect();
    let num = |v: &Value| v.as_u64().map_or_else(|| "-".to_owned(), |n| n.to_string());
    format!(
        "{}\t{}\t{state}\t{}/{}\t{}\t{}\t{}",
        s(&r["id"]),
        s(&r["name"]),
        num(&r["load"]),
        num(&r["capacity"]),
        if commands.is_empty() {
            "-".to_owned()
        } else {
            commands.join(",")
        },
        s(&r["version"]),
        s(&r["last_seen"]),
    )
}

fn print(out: &mut impl Write, text: impl std::fmt::Display) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

/// `runner …`.
pub async fn runner(
    c: &mut Client,
    words: &[&str],
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["ls" | "list"] => {
            let v: Value = c.get("/api/v1/runners", "").await?;
            if json {
                return print(out, v);
            }
            for r in v.as_array().into_iter().flatten() {
                print(out, row(r))?;
            }
            Ok(())
        }
        ["show", id] => {
            let r: Value = c.get(&format!("/api/v1/runners/{}", rid(id)?), "").await?;
            match json {
                true => print(out, r),
                false => print(out, row(&r)),
            }
        }
        _ => Err(Error::Usage("runner ls | show <id>".into())),
    }
}

/// `run noop <id>`: prints `ok <duration_ms> ms`.
pub async fn run(
    c: &mut Client,
    words: &[&str],
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    let ["noop", id] = words else {
        return Err(Error::Usage("run noop <runner-id>".into()));
    };
    let path = format!("/api/v1/runners/{}/noop", rid(id)?);
    let v: Value = parse(&c.call("POST", &path, "", None).await?)?;
    if v["ok"].as_bool() != Some(true) {
        return Err(Error::Protocol(format!("the no-op answered {v}")));
    }
    match json {
        true => print(out, v),
        false => print(out, format_args!("ok {} ms", v["duration_ms"])),
    }
}
