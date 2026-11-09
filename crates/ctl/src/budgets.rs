//! `budget ls | set | raise | rm` (`budgets` too): the spend budgets of the contract
//! (`/api/v1/budgets`, scope `admin`; writes need a step-up): per account, pool, agent or
//! company, per day, week, month or in total, in tokens and optionally dollars. A session
//! needs about a turn of room in a hard-stop budget to start. Syntax checks only.

use std::io::Write;

use serde_json::{Value, json};

use crate::Error;
use crate::acct::{Opts, id, num, usd, word};
use crate::client::Client;
use crate::conn_input::print;
use crate::connections::send;
use crate::devices::s;

pub const USAGE: &str = "budget ls [--kind k] [--subject s] [--company c] | set <kind> <subject> <day|week|month|total> --tokens n [--usd-micros n] [--warn-percent n] [--no-hard-stop] [--company c] | raise <id> <period-key> [--tokens n] [--usd-micros n] | rm <id>";

/// `id  kind:subject  period  tokens spent/cap  usd spent/cap  warn N%  hard-stop|warn-only  [exhausted]`.
pub fn row(b: &Value) -> String {
    let n = |k: &str| b[k].as_i64().unwrap_or(0);
    format!(
        "{}\t{}:{}\t{}\ttokens {}/{}\tusd {}/{}\twarn {}%\t{}{}",
        b["id"],
        s(&b["kind"]),
        s(&b["subject"]),
        s(&b["period"]),
        n("spent"),
        n("token_cap"),
        usd(&b["usd_spent"]),
        usd(&b["usd_cap_micros"]),
        n("warn_at_percent"),
        if b["hard_stop"].as_bool() == Some(true) {
            "hard-stop"
        } else {
            "warn-only"
        },
        if b["exhausted"].as_bool() == Some(true) {
            "\texhausted"
        } else {
            ""
        },
    )
}

fn shown(b: &Value, json: bool, out: &mut impl Write) -> Result<(), Error> {
    match json {
        true => print(out, b),
        false => print(out, row(b)),
    }
}

/// `budget …` (`budgets` too).
pub async fn budget(
    c: &mut Client,
    words: &[&str],
    o: &Opts<'_>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["ls" | "list"] => {
            let mut q = Vec::new();
            for (k, v) in [
                ("kind", o.kind),
                ("subject", o.subject),
                ("company", o.company),
            ] {
                if let Some(v) = v {
                    q.push(format!("{k}={}", word("a name or id", v, 64)?));
                }
            }
            let v = send(
                c,
                "GET",
                "/api/v1/budgets",
                &q.join("&"),
                None,
                "listing the budgets",
                &[],
            )
            .await?;
            if json {
                return print(out, v);
            }
            v.as_array()
                .into_iter()
                .flatten()
                .try_for_each(|b| print(out, row(b)))
        }
        ["set", kind, subject, period] => {
            let Some(tokens) = num("--tokens", o.tokens)? else {
                return Err(Error::Usage(
                    "budget set needs --tokens <n> (0 with --usd-micros is a dollars-only budget)"
                        .into(),
                ));
            };
            let (kind, subject, period) = (
                word("a kind (like account)", kind, 32)?,
                word("a subject id", subject, 64)?,
                word("a period (like month)", period, 16)?,
            );
            let mut body =
                json!({"kind": kind, "subject": subject, "period": period, "token_cap": tokens});
            if let Some(n) = num("--usd-micros", o.usd_micros)? {
                body["usd_cap_micros"] = json!(n);
            }
            if let Some(n) = num("--warn-percent", o.warn_percent)? {
                body["warn_at_percent"] = json!(n);
            }
            if o.no_hard_stop {
                body["hard_stop"] = json!(false);
            }
            if let Some(co) = o.company {
                body["company"] = json!(word("a company", co, 64)?);
            }
            let what = format!("setting the {period} budget of {kind} {subject}");
            let v = send(c, "PUT", "/api/v1/budgets", "", Some(&body), &what, &[]).await?;
            shown(&v, json, out)
        }
        ["raise", i, key] => {
            let i = id("a budget", i)?;
            let mut body = json!({"period_key": word("a period key (like 2026-10)", key, 16)?});
            for (k, f, v) in [
                ("tokens", "--tokens", o.tokens),
                ("usd_micros", "--usd-micros", o.usd_micros),
            ] {
                if let Some(n) = num(f, v)? {
                    body[k] = json!(n);
                }
            }
            let path = format!("/api/v1/budgets/{i}/raise");
            let v = send(
                c,
                "POST",
                &path,
                "",
                Some(&body),
                &format!("raising budget {i}"),
                &[],
            )
            .await?;
            shown(&v, json, out)
        }
        ["rm" | "delete", i] => {
            let i = id("a budget", i)?;
            let v = send(
                c,
                "DELETE",
                &format!("/api/v1/budgets/{i}"),
                "",
                None,
                &format!("removing budget {i}"),
                &[],
            )
            .await?;
            match (json, v["deleted"].as_bool() == Some(true)) {
                (true, _) => print(out, v),
                (_, true) => print(out, format_args!("removed budget {i}")),
                _ => print(out, format_args!("there was no budget {i}")),
            }
        }
        _ => Err(Error::Usage(USAGE.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_budget_reads_as_a_row() {
        let b = json!({"id": 4, "kind": "account", "subject": "7", "period": "month", "token_cap": 1000000,
            "spent": 250, "usd_spent": 1500, "usd_cap_micros": 5000000, "warn_at_percent": 80,
            "hard_stop": true, "exhausted": false});
        assert_eq!(
            row(&b),
            "4\taccount:7\tmonth\ttokens 250/1000000\tusd $0.0015/$5.0000\twarn 80%\thard-stop"
        );
        let w = json!({"id": 5, "kind": "pool", "subject": "2", "period": "total", "token_cap": 10, "spent": 10,
            "warn_at_percent": 50, "hard_stop": false, "exhausted": true});
        assert!(row(&w).ends_with("usd -/-\twarn 50%\twarn-only\texhausted"));
    }
}
