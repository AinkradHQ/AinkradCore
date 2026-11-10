//! `system show | restart core|runner | logs <unit> [-n N] [--before C]`: the Core machine
//! (`/api/v1/system/…`, scope `admin`). The host helper behind the Core is the only judge of what
//! is installed and of the restart limits; a restart and the runner and backup logs need a step-up,
//! which `Client::call` does once when the Core asks. There is no `--follow`.

use std::io::Write;

use serde_json::{Value, json};

use crate::Error;
use crate::client::{Client, parse};
use crate::devices::s;

const USAGE: &str = "system show | restart core|runner | logs core|helper|runner|backup [-n <1..500>] [--before <cursor>]";

fn print(out: &mut impl Write, text: impl std::fmt::Display) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

/// `name  version  sha256_12  state` per program, then one line per unit.
fn show(v: &Value, out: &mut impl Write) -> Result<(), Error> {
    print(out, format_args!("helper\t{}", s(&v["helper"])))?;
    if v["helper"] != "present" {
        return Ok(());
    }
    print(out, format_args!("host_id\t{}", s(&v["host_id"])))?;
    print(out, format_args!("manifest\t{}", s(&v["manifest"])))?;
    for b in v["binaries"].as_array().into_iter().flatten() {
        print(
            out,
            format_args!(
                "{}\t{}\t{}\t{}",
                s(&b["name"]),
                s(&b["version"]),
                s(&b["sha256_12"]),
                s(&b["state"])
            ),
        )?;
    }
    if v["bin_dir_safe"] == false {
        print(out, "bin_dir\tUNSAFE: /usr/local/bin is writable by others")?;
    }
    for (name, u) in v["units"].as_object().into_iter().flatten() {
        let restarts = u["restarts"]
            .as_u64()
            .map_or("-".to_owned(), |n| n.to_string());
        print(
            out,
            format_args!(
                "{name}\t{}/{}\tsince {}\trestarts {restarts}",
                s(&u["state"]),
                s(&u["sub"]),
                s(&u["since"])
            ),
        )?;
    }
    Ok(())
}

/// A journal cursor goes into a query: `=` and `;` are escaped, the rest must be `[A-Za-z0-9_]`.
fn cursor(c: &str) -> Result<String, Error> {
    let ok = (1..=256).contains(&c.len())
        && !c.starts_with('-')
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'=' | b';' | b'_'));
    if !ok {
        return Err(Error::Usage(
            "--before takes the cursor a log page printed (letters, digits, = ; _)".into(),
        ));
    }
    Ok(c.replace('=', "%3D").replace(';', "%3B"))
}

/// `system …`.
pub async fn system(
    c: &mut Client,
    words: &[&str],
    before: Option<&str>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["show"] => {
            let v: Value = c.get("/api/v1/system/host", "").await?;
            match json {
                true => print(out, v),
                false => show(&v, out),
            }
        }
        ["restart", target @ ("core" | "runner")] => {
            let body = json!({"target": target});
            let res = c
                .call("POST", "/api/v1/system/restart", "", Some(&body))
                .await;
            let res = res.map_err(|e| match (e, c.retry_after) {
                (
                    Error::Refused {
                        status: 429,
                        code,
                        message,
                        server_time,
                        local_time,
                    },
                    Some(wait),
                ) => Error::Refused {
                    status: 429,
                    code,
                    message: format!("{message}; try again in {wait} s"),
                    server_time,
                    local_time,
                },
                (e, _) => e,
            })?;
            let v: Value = parse(&res)?;
            match json {
                true => print(out, v),
                false => print(out, format_args!("accepted {}", s(&v["request_id"]))),
            }
        }
        [
            "logs",
            unit @ ("core" | "helper" | "runner" | "backup"),
            rest @ ..,
        ] => {
            let lines = match rest {
                [] => None,
                ["-n", n] => Some(
                    n.parse::<u32>()
                        .ok()
                        .filter(|n| (1..=500).contains(n))
                        .ok_or_else(|| Error::Usage("-n takes a number from 1 to 500".into()))?,
                ),
                _ => return Err(Error::Usage(USAGE.into())),
            };
            let mut query = Vec::new();
            if let Some(n) = lines {
                query.push(format!("lines={n}"));
            }
            if let Some(b) = before {
                query.push(format!("before={}", cursor(b)?));
            }
            let path = format!("/api/v1/system/logs/{unit}");
            let v: Value = c.get(&path, &query.join("&")).await?;
            if json {
                return print(out, v);
            }
            for l in v["lines"].as_array().into_iter().flatten() {
                print(
                    out,
                    format_args!("{} {} {}", s(&l["at"]), s(&l["level"]), s(&l["text"])),
                )?;
            }
            if let Some(next) = v["next_before"].as_str() {
                print(out, format_args!("older: --before {next}"))?;
            }
            Ok(())
        }
        _ => Err(Error::Usage(USAGE.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cursor_is_escaped_for_the_query_and_never_starts_with_a_dash() {
        assert_eq!(cursor("s=ab;i=1_z").unwrap(), "s%3Dab%3Bi%3D1_z");
        for bad in ["", "-r", "a b", "a/b", "--cursor-file=/etc/shadow"] {
            assert!(cursor(bad).is_err(), "{bad:?}");
        }
        assert!(cursor(&"a".repeat(257)).is_err());
    }

    #[test]
    fn show_prints_the_units_and_stops_when_the_helper_is_not_there() {
        let mut out = Vec::new();
        show(&json!({"helper": "absent"}), &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "helper\tabsent\n");
        let v = json!({"helper": "present", "host_id": "h", "manifest": "ok",
            "bin_dir_safe": false,
            "binaries": [{"name": "a", "version": "1", "sha256_12": "x", "state": "differs"}],
            "units": {"core": {"state": "active", "sub": "running", "since": "t", "restarts": 2}}});
        let mut out = Vec::new();
        show(&v, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("a\t1\tx\tdiffers"), "{text}");
        assert!(text.contains("UNSAFE"), "{text}");
        assert!(
            text.contains("core\tactive/running\tsince t\trestarts 2"),
            "{text}"
        );
    }
}
