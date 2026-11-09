//! `account add | login | state | rm | cap | limit | session-limits | rotate | test | providers |
//! usage | costs` (the write and read routes of the contract's accounts surface, scope `admin`;
//! every write needs a step-up, which `Client::call` does once when the Core asks). `ls` and
//! `show` stay in [`crate::accounts`]; pools are in [`crate::pools`], budgets in
//! [`crate::budgets`], the subscription sign-in in [`crate::acct_login`], usage and costs in
//! [`crate::acct_usage`]. Syntax checks only: the Core is the judge of every policy (a key's
//! shape, a taken label, the cap's range). An API key is read from `--key-file`, `$AINKRAD_ACCOUNT_KEY`
//! or stdin, sent only in the body of the request that carries it and never printed.

use std::io::Write;

use serde_json::{Value, json};

use crate::Error;
use crate::accounts;
use crate::client::Client;
use crate::conn_input::{print, secret};
use crate::connections::send;
use crate::devices::s;

/// The environment variable `add` and `rotate` read the API key from.
pub const KEY_ENV: &str = "AINKRAD_ACCOUNT_KEY";
/// The flags (taking a value) of the account, pool and budget commands.
pub const VALUED: [&str; 15] = [
    "--key",
    "--key-file",
    "--cap",
    "--reason",
    "--until",
    "--runner",
    "--warn-percent",
    "--max-tokens",
    "--max-usd-micros",
    "--tokens",
    "--usd-micros",
    "--account",
    "--session",
    "--subject",
    "--company",
];
pub const SWITCHES: [&str; 1] = ["--no-hard-stop"];

/// The flags these commands read.
#[derive(Default)]
pub struct Opts<'a> {
    pub key: Option<&'a str>,
    pub key_file: Option<&'a str>,
    pub label: Option<&'a str>,
    pub cap: Option<&'a str>,
    pub runners: Option<&'a str>,
    pub runner: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub until: Option<&'a str>,
    pub warn_percent: Option<&'a str>,
    pub max_tokens: Option<&'a str>,
    pub max_usd_micros: Option<&'a str>,
    pub tokens: Option<&'a str>,
    pub usd_micros: Option<&'a str>,
    pub account: Option<&'a str>,
    pub session: Option<&'a str>,
    pub subject: Option<&'a str>,
    pub company: Option<&'a str>,
    pub kind: Option<&'a str>,
    pub limit: Option<&'a str>,
    pub no_hard_stop: bool,
}

impl<'a> Opts<'a> {
    pub fn new(value: impl Fn(&str) -> Option<&'a str>, on: impl Fn(&str) -> bool) -> Self {
        Self {
            key: value("--key"),
            key_file: value("--key-file"),
            label: value("--label"),
            cap: value("--cap"),
            runners: value("--runners"),
            runner: value("--runner"),
            reason: value("--reason"),
            until: value("--until"),
            warn_percent: value("--warn-percent"),
            max_tokens: value("--max-tokens"),
            max_usd_micros: value("--max-usd-micros"),
            tokens: value("--tokens"),
            usd_micros: value("--usd-micros"),
            account: value("--account"),
            session: value("--session"),
            subject: value("--subject"),
            company: value("--company"),
            kind: value("--kind"),
            limit: value("--limit"),
            no_hard_stop: on("--no-hard-stop"),
        }
    }
}

pub const USAGE: &str = "account ls | show <id> | providers | add <provider> [--label l] [--cap n] [--runners id,...] | login <provider> [--label l] [--runner id] | state <id> <state> [--reason r] [--until t] | cap <id> <n> | limit set <id> <tokens|messages> <window-secs> <cap> [--warn-percent n] | limit clear <id> <unit> <window-secs> | session-limits <id> [--max-tokens n] [--max-usd-micros n] | rotate <id> [--runners id,...] | test <id> | rm <id> | usage | costs [--account id] [--session id] [--limit n]";

/// A number flag: a whole number, not negative.
pub fn num(name: &str, v: Option<&str>) -> Result<Option<i64>, Error> {
    v.map(|v| {
        v.parse::<i64>()
            .ok()
            .filter(|n| *n >= 0)
            .ok_or_else(|| Error::Usage(format!("{name} takes a whole number, 0 or more")))
    })
    .transpose()
}

/// A number word of the command (an id, a count, a window).
pub fn count(what: &str, v: &str) -> Result<i64, Error> {
    num(what, Some(v)).map(|n| n.unwrap_or(0))
}

/// A word that goes into a path or a body: ascii letters, digits and `_.-`, 1 to `max`, led by a
/// letter or digit.
pub fn word<'a>(what: &str, w: &'a str, max: usize) -> Result<&'a str, Error> {
    let ok = (1..=max).contains(&w.len())
        && w.as_bytes()[0].is_ascii_alphanumeric()
        && w.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b));
    ok.then_some(w)
        .ok_or_else(|| Error::Usage(format!("{w:?} is not {what}")))
}

/// An account or pool or budget id (a positive number).
pub fn id(what: &str, v: &str) -> Result<i64, Error> {
    v.parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::Usage(format!("{v:?} is not {what} id (a number)")))
}

/// Millionths of a dollar as `$0.0123`.
pub fn usd(micros: &Value) -> String {
    micros
        .as_i64()
        .map_or_else(|| "-".to_owned(), |m| format!("${:.4}", m as f64 / 1e6))
}

fn csv(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(str::to_owned)
        .collect()
}

/// What an `admin` write of an account answers: the account, then the runners its key may go to.
fn written(v: &Value, json: bool, out: &mut impl Write) -> Result<(), Error> {
    if json {
        return print(out, v);
    }
    print(out, accounts::row(&v["account"]))?;
    let runners: Vec<&str> = v["runners"]
        .as_array()
        .into_iter()
        .flatten()
        .map(s)
        .collect();
    match runners.is_empty() {
        true => print(out, "runners -"),
        false => print(out, format_args!("runners {}", runners.join(","))),
    }
}

fn row_or_json(v: &Value, json: bool, out: &mut impl Write) -> Result<(), Error> {
    match json {
        true => print(out, v),
        false => print(out, accounts::row(v)),
    }
}

/// `account …` (`accounts` too).
pub async fn account(
    c: &mut Client,
    words: &[&str],
    o: &Opts<'_>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["ls" | "list"] | ["show", _] => accounts::account(c, words, json, out).await,
        ["providers"] => providers(c, json, out).await,
        ["add", p] => {
            let p = word("a provider (like anthropic)", p, 64)?;
            let key = secret(
                "API key",
                ("--key", o.key),
                ("--key-file", o.key_file),
                Some(KEY_ENV),
            )?;
            let mut body =
                json!({"provider": p, "label": o.label.unwrap_or(p), "value": key.as_str()});
            if let Some(n) = num("--cap", o.cap)? {
                body["cap"] = json!(n);
            }
            if let Some(r) = o.runners {
                body["runners"] = json!(csv(r));
            }
            let what = format!("adding an account for {p}");
            let v = send(
                c,
                "POST",
                "/api/v1/accounts",
                "",
                Some(&body),
                &what,
                &[key.as_str()],
            )
            .await;
            drop(body);
            written(&v?, json, out)
        }
        ["login", p] => {
            crate::acct_login::login(
                c,
                word("a provider (like claude-sub)", p, 64)?,
                o,
                json,
                out,
            )
            .await
        }
        ["state", i, state] => {
            let i = id("an account", i)?;
            let state = word("an account state (like disabled)", state, 32)?;
            let mut body = json!({"state": state});
            for (k, v) in [("reason", o.reason), ("until", o.until)] {
                if let Some(v) = v {
                    body[k] = json!(v);
                }
            }
            let path = format!("/api/v1/accounts/{i}/state");
            let v = send(
                c,
                "PUT",
                &path,
                "",
                Some(&body),
                &format!("setting account {i} {state}"),
                &[],
            )
            .await?;
            if state != "active" && o.until.is_none() && !json {
                eprintln!(
                    "ainkradctl: note: no --until, so account {i} stays {state} until you set it active"
                );
            }
            row_or_json(&v, json, out)
        }
        ["cap", i, n] => {
            let i = id("an account", i)?;
            let body = json!({"cap": count("the cap", n)?});
            let path = format!("/api/v1/accounts/{i}/cap");
            let v = send(
                c,
                "PUT",
                &path,
                "",
                Some(&body),
                &format!("setting the cap of account {i}"),
                &[],
            )
            .await?;
            row_or_json(&v, json, out)
        }
        ["limit", "set", i, unit, window, cap] => {
            let i = id("an account", i)?;
            let mut body = json!({"unit": word("a unit (tokens or messages)", unit, 16)?,
                "window_secs": count("the window", window)?, "cap": count("the cap", cap)?});
            if let Some(w) = num("--warn-percent", o.warn_percent)? {
                body["warn_percent"] = json!(w);
            }
            let path = format!("/api/v1/accounts/{i}/limits");
            let v = send(
                c,
                "PUT",
                &path,
                "",
                Some(&body),
                &format!("setting a limit on account {i}"),
                &[],
            )
            .await?;
            match json {
                true => print(out, v),
                false => print(
                    out,
                    format_args!(
                        "account {i} limit {}/{} s cap {} warn {}%",
                        s(&v["unit"]),
                        v["window_secs"],
                        v["cap"],
                        v["warn_percent"].as_i64().unwrap_or(80)
                    ),
                ),
            }
        }
        ["limit", "clear", i, unit, window] => {
            let i = id("an account", i)?;
            let (unit, window) = (
                word("a unit (tokens or messages)", unit, 16)?,
                count("the window", window)?,
            );
            let path = format!("/api/v1/accounts/{i}/limits/{unit}/{window}");
            let v = send(
                c,
                "DELETE",
                &path,
                "",
                None,
                &format!("clearing a limit on account {i}"),
                &[],
            )
            .await?;
            match (json, v["cleared"].as_bool() == Some(true)) {
                (true, _) => print(out, v),
                (_, true) => print(
                    out,
                    format_args!("cleared account {i} limit {unit}/{window} s"),
                ),
                _ => print(
                    out,
                    format_args!("account {i} had no limit {unit}/{window} s"),
                ),
            }
        }
        ["session-limits", i] => {
            let i = id("an account", i)?;
            let mut body = json!({});
            if let Some(n) = num("--max-tokens", o.max_tokens)? {
                body["max_tokens"] = json!(n);
            }
            if let Some(n) = num("--max-usd-micros", o.max_usd_micros)? {
                body["max_usd_micros"] = json!(n);
            }
            let path = format!("/api/v1/accounts/{i}/session-limits");
            let what = format!("setting the session limits of account {i}");
            let v = send(c, "PUT", &path, "", Some(&body), &what, &[]).await?;
            row_or_json(&v, json, out)
        }
        ["rotate", i] => {
            let i = id("an account", i)?;
            let key = secret(
                "API key",
                ("--key", o.key),
                ("--key-file", o.key_file),
                Some(KEY_ENV),
            )?;
            let mut body = json!({"value": key.as_str()});
            if let Some(r) = o.runners {
                body["runners"] = json!(csv(r));
            }
            let path = format!("/api/v1/accounts/{i}/secret");
            let what = format!("replacing the key of account {i}");
            let v = send(c, "PUT", &path, "", Some(&body), &what, &[key.as_str()]).await;
            drop(body);
            written(&v?, json, out)
        }
        ["test", i] => {
            let i = id("an account", i)?;
            let path = format!("/api/v1/accounts/{i}/test");
            let v = send(
                c,
                "POST",
                &path,
                "",
                None,
                &format!("testing account {i}"),
                &[],
            )
            .await?;
            match (json, s(&v["runner"])) {
                (true, _) => print(out, v),
                (_, "-" | "") => print(
                    out,
                    format_args!("tested account {i}: {} (nothing was sent)", s(&v["result"])),
                ),
                (_, r) => print(
                    out,
                    format_args!(
                        "tested account {i}: {} ({} ms, runner {r})",
                        s(&v["result"]),
                        v["latency_ms"]
                    ),
                ),
            }
        }
        ["rm" | "delete", i] => {
            let i = id("an account", i)?;
            let path = format!("/api/v1/accounts/{i}");
            let v = send(
                c,
                "DELETE",
                &path,
                "",
                None,
                &format!("removing account {i}"),
                &[],
            )
            .await?;
            match json {
                true => print(out, v),
                false => print(out, format_args!("removed account {i}")),
            }
        }
        ["usage"] => crate::acct_usage::usage(c, json, out).await,
        ["costs"] => crate::acct_usage::costs(c, o, json, out).await,
        _ => Err(Error::Usage(USAGE.into())),
    }
}

/// `id  name  harness  base_url  delivery  built-in|user`.
async fn providers(c: &mut Client, json: bool, out: &mut impl Write) -> Result<(), Error> {
    let v = send(
        c,
        "GET",
        "/api/v1/accounts/providers",
        "",
        None,
        "listing the providers",
        &[],
    )
    .await?;
    if json {
        return print(out, v);
    }
    v.as_array().into_iter().flatten().try_for_each(|p| {
        let delivery: Vec<&str> = p["delivery"]
            .as_array()
            .into_iter()
            .flatten()
            .map(s)
            .collect();
        print(
            out,
            format_args!(
                "{}\t{}\t{}\t{}\t{}\t{}",
                s(&p["id"]),
                s(&p["name"]),
                s(&p["harness"]),
                s(&p["base_url"]),
                delivery.join(","),
                if p["builtin"].as_bool() == Some(true) {
                    "built-in"
                } else {
                    "user"
                },
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syntax_is_checked_and_nothing_else() {
        assert_eq!(count("n", "12").unwrap(), 12);
        for bad in ["-1", "x", "", "1.5"] {
            assert!(count("n", bad).is_err(), "{bad:?}");
        }
        assert!(id("an account", "0").is_err() && id("an account", "7").is_ok());
        assert!(word("w", "claude-sub", 64).is_ok() && word("w", "my.prov_2", 64).is_ok());
        for bad in ["", "a/b", "../x", "-x", "a b", "x?y"] {
            assert!(word("w", bad, 64).is_err(), "{bad:?}");
        }
        assert_eq!(usd(&json!(12_300)), "$0.0123");
        assert_eq!(usd(&Value::Null), "-");
    }
}
