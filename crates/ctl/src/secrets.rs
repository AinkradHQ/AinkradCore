//! `secret ls | set | rotate | rm` (E2-07.4): the Core's secrets broker (scope `admin`; every
//! write needs a step-up, which `Client::call` does once when asked). There is no `get`: a
//! value never comes back to a client. A value is read from stdin, never from the command line,
//! which `ps` and the shell history would show.

use std::io::{Read, Write};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::Error;
use crate::client::{Client, parse};
use crate::devices::s;

fn print(out: &mut impl Write, text: impl std::fmt::Display) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

/// `name  vN  size bytes  delivery  runners  updated_at`.
fn row(v: &Value) -> String {
    let runners: Vec<&str> = v["runners"]
        .as_array()
        .into_iter()
        .flatten()
        .map(s)
        .collect();
    format!(
        "{}\tv{}\t{} bytes\t{}\t{}\t{}",
        s(&v["name"]),
        v["version"],
        v["size"],
        s(&v["delivery"]),
        if runners.is_empty() {
            "-".to_owned()
        } else {
            runners.join(",")
        },
        s(&v["updated_at"]),
    )
}

/// The value from stdin, one trailing newline dropped.
fn value_from_stdin() -> Result<Zeroizing<String>, Error> {
    let mut v = Zeroizing::new(String::new());
    std::io::stdin()
        .read_to_string(&mut v)
        .map_err(|e| Error::Usage(format!("reading the value from stdin: {e}")))?;
    let keep = v
        .strip_suffix('\n')
        .map(|t| t.strip_suffix('\r').unwrap_or(t).len());
    if let Some(n) = keep {
        v.truncate(n);
    }
    if v.is_empty() {
        return Err(Error::Usage("the value (on stdin) is empty".into()));
    }
    Ok(v)
}

/// A secret's name as the Core takes it: `[a-z][a-z0-9_.-]{0,63}`.
fn valid(name: &str) -> Result<&str, Error> {
    let ok = (1..=64).contains(&name.len())
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b));
    ok.then_some(name)
        .ok_or_else(|| Error::Usage(format!("{name:?} is not a secret name ([a-z][a-z0-9_.-]*)")))
}

/// `secret …`; `runners` and `delivery` are the `--runners` and `--delivery` flags.
pub async fn secret(
    c: &mut Client,
    words: &[&str],
    runners: Option<Vec<String>>,
    delivery: Option<&str>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["ls" | "list"] => {
            let v: Value = c.get("/api/v1/secrets", "").await?;
            if json {
                return print(out, v);
            }
            for r in v.as_array().into_iter().flatten() {
                print(out, row(r))?;
            }
            Ok(())
        }
        ["set", name] | ["rotate", name] => {
            let name = valid(name)?;
            let value = value_from_stdin()?;
            let mut body = json!({"value": value.as_str()});
            if let Some(r) = runners {
                body["runners"] = json!(r);
            }
            if let Some(d) = delivery {
                body["delivery"] = json!(d);
            }
            let res = if words[0] == "set" {
                body["name"] = json!(name);
                c.call("POST", "/api/v1/secrets", "", Some(&body)).await
            } else {
                let path = format!("/api/v1/secrets/{name}");
                c.call("PUT", &path, "", Some(&body)).await
            };
            drop(body);
            let v: Value = parse(&res?)?;
            match json {
                true => print(out, v),
                false => print(out, row(&v)),
            }
        }
        ["rm", name] => {
            let name = valid(name)?;
            let path = format!("/api/v1/secrets/{name}");
            c.call("DELETE", &path, "", None).await?;
            print(out, format_args!("deleted {name}"))
        }
        _ => Err(Error::Usage(
            "secret ls | set <name> | rotate <name> | rm <name>".into(),
        )),
    }
}
