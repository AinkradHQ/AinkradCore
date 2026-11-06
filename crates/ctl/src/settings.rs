//! `setting ls [prefix] | get <key> | set <key> <value>* | reset <key>*` (`settings` too): the
//! Core's server-wide settings (`/api/v1/settings`, scope `admin`), `scheduler.*` among them.
//! The Core is the only judge of a key and its range: a refusal (`unknown`, `out_of_bounds`,
//! `wrong_scope`) is printed as the Core said it, and ctl keeps no list of keys or bounds. A
//! set and a reset need a step-up, which `Client::call` does once when the Core asks.

use std::io::Write;

use serde_json::{Value, json};

use crate::Error;
use crate::client::{Client, parse};
use crate::devices::s;

fn print(out: &mut impl Write, text: impl std::fmt::Display) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

/// `key  value unit  (default D, min..max)  source`; `source` is `default` when never set.
pub fn row(v: &Value) -> String {
    format!(
        "{}\t{} {}\t(default {}, {}..{})\t{}",
        s(&v["key"]),
        v["value"],
        s(&v["unit"]),
        v["default"],
        v["min"],
        v["max"],
        v["source"].as_str().unwrap_or("default"),
    )
}

/// A key goes into a path: `[a-z0-9._]`, which every setting key is.
fn key(k: &str) -> Result<&str, Error> {
    let ok = !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._".contains(&b));
    ok.then_some(k).ok_or_else(|| {
        Error::Usage(format!(
            "{k:?} is not a setting key (like scheduler.max_hops)"
        ))
    })
}

/// `setting …`.
pub async fn setting(
    c: &mut Client,
    words: &[&str],
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    let shown = |out: &mut _, v: Value| match json {
        true => print(out, v),
        false => print(out, row(&v)),
    };
    match words {
        ["ls" | "list", prefix @ ..] if prefix.len() <= 1 => {
            let v: Value = c.get("/api/v1/settings", "").await?;
            let prefix = prefix.first().copied().unwrap_or("");
            let all = v.as_array().into_iter().flatten();
            let mine: Vec<&Value> = all.filter(|e| s(&e["key"]).starts_with(prefix)).collect();
            if json {
                return print(out, Value::from_iter(mine.into_iter().cloned()));
            }
            mine.into_iter().try_for_each(|e| print(out, row(e)))
        }
        ["get", k] => {
            let v: Value = c
                .get(&format!("/api/v1/settings/server/{}", key(k)?), "")
                .await?;
            shown(out, v)
        }
        ["set", k, value] => {
            let n: i64 = value
                .parse()
                .map_err(|_| Error::Usage(format!("{value:?} is not a whole number")))?;
            let path = format!("/api/v1/settings/server/{}", key(k)?);
            let res = c.call("PUT", &path, "", Some(&json!({"value": n}))).await?;
            shown(out, parse(&res)?)
        }
        ["reset", k] => {
            let path = format!("/api/v1/settings/server/{}", key(k)?);
            let res = c.call("DELETE", &path, "", None).await?;
            shown(out, parse(&res)?)
        }
        _ => Err(Error::Usage(
            "setting ls [prefix] | get <key> | set <key> <whole number> | reset <key>".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_row_shows_the_core_s_own_bounds() {
        let v = json!({"key": "scheduler.max_hops", "value": 3, "unit": "count",
            "default": 3, "min": 0, "max": 8, "source": null});
        assert_eq!(
            row(&v),
            "scheduler.max_hops\t3 count\t(default 3, 0..8)\tdefault"
        );
    }

    #[test]
    fn a_key_is_checked_only_for_the_path_it_goes_into() {
        assert!(key("scheduler.wait_max_secs").is_ok());
        for bad in ["", "a/b", "A", "a b", "../x"] {
            assert!(key(bad).is_err(), "{bad:?}");
        }
    }
}
