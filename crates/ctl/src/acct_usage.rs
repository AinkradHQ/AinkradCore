//! `account usage` and `account costs`: what the accounts spent (`/api/v1/accounts/usage`) and the
//! cost events behind it (`/api/v1/costs`), both scope `admin`, reads only.

use std::io::Write;

use serde_json::Value;

use crate::Error;
use crate::acct::{Opts, num, usd, word};
use crate::client::Client;
use crate::conn_input::print;
use crate::connections::send;
use crate::devices::s;

fn window(w: &Value) -> String {
    format!(
        "{} tokens {} msgs {}",
        w["total_tokens"].as_i64().unwrap_or(0),
        w["messages"].as_i64().unwrap_or(0),
        usd(&w["cost_usd_micros"])
    )
}

/// `account  5h <window>  7d <window>  at N% of its tightest limit  drops N`, then a line per limit.
pub fn usage_lines(a: &Value) -> Vec<String> {
    let bps = a["max_utilisation_bps"].as_i64().unwrap_or(0);
    let mut l = vec![format!(
        "{}\t5h {}\t7d {}\tutilisation {}.{}%\tdrops {}",
        a["account_id"],
        window(&a["five_hours"]),
        window(&a["seven_days"]),
        bps / 100,
        bps % 100 / 10,
        a["recent_drops"].as_i64().unwrap_or(0),
    )];
    for k in a["limits"].as_array().into_iter().flatten() {
        l.push(format!(
            "  limit {}/{} s\t{}/{}\twarn {}%{}",
            s(&k["unit"]),
            k["window_secs"],
            k["used"],
            k["cap"],
            k["warn_percent"],
            if k["exhausted"].as_bool() == Some(true) {
                "\texhausted"
            } else {
                ""
            },
        ));
    }
    l
}

/// `id  at  session#epoch  account N|-  provider  model  in/out/cache  basis  cost`.
pub fn cost_row(e: &Value) -> String {
    let n = |k: &str| e[k].as_i64().unwrap_or(0);
    format!(
        "{}\t{}\t{}#{}\taccount {}\t{}\t{}\tin {} out {} cache {}\t{}{}\t{}",
        e["id"],
        s(&e["occurred_at"]),
        s(&e["session"]),
        e["epoch"],
        e["account_id"]
            .as_i64()
            .map_or_else(|| "-".to_owned(), |a| a.to_string()),
        s(&e["provider"]),
        s(&e["model"]),
        n("input_tokens"),
        n("output_tokens"),
        n("cache_tokens"),
        s(&e["basis"]),
        if e["approximate"].as_bool() == Some(true) {
            " (approximate)"
        } else {
            ""
        },
        if e["cost_usd_micros"].is_null() {
            "unpriced".to_owned()
        } else {
            usd(&e["cost_usd_micros"])
        },
    )
}

pub async fn usage(c: &mut Client, json: bool, out: &mut impl Write) -> Result<(), Error> {
    let v = send(
        c,
        "GET",
        "/api/v1/accounts/usage",
        "",
        None,
        "reading the accounts' usage",
        &[],
    )
    .await?;
    if json {
        return print(out, v);
    }
    let all = v.as_array().into_iter().flatten();
    all.flat_map(usage_lines).try_for_each(|l| print(out, l))
}

pub async fn costs(
    c: &mut Client,
    o: &Opts<'_>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    let mut q = Vec::new();
    if let Some(a) = num("--account", o.account)? {
        q.push(format!("account={a}"));
    }
    if let Some(sn) = o.session {
        q.push(format!("session={}", word("a session id", sn, 64)?));
    }
    if let Some(n) = num("--limit", o.limit)? {
        q.push(format!("limit={n}"));
    }
    let v = send(
        c,
        "GET",
        "/api/v1/costs",
        &q.join("&"),
        None,
        "reading the costs",
        &[],
    )
    .await?;
    if json {
        return print(out, v);
    }
    v.as_array()
        .into_iter()
        .flatten()
        .try_for_each(|e| print(out, cost_row(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn usage_and_cost_read_as_rows() {
        let w = json!({"total_tokens": 1200, "messages": 3, "cost_usd_micros": 15000});
        let a = json!({"account_id": 7, "five_hours": w, "seven_days": w, "max_utilisation_bps": 8340,
            "recent_drops": 1, "limits": [{"unit": "tokens", "window_secs": 18000, "used": 10, "cap": 100, "warn_percent": 80, "exhausted": false}]});
        assert_eq!(
            usage_lines(&a),
            [
                "7\t5h 1200 tokens 3 msgs $0.0150\t7d 1200 tokens 3 msgs $0.0150\tutilisation 83.4%\tdrops 1",
                "  limit tokens/18000 s\t10/100\twarn 80%"
            ]
        );
        let e = json!({"id": 9, "occurred_at": "T", "session": "as_1", "epoch": 2, "account_id": null, "provider": "anthropic",
            "model": "m", "input_tokens": 1, "output_tokens": 2, "cache_tokens": 3, "basis": "unpriced", "approximate": true});
        assert_eq!(
            cost_row(&e),
            "9\tT\tas_1#2\taccount -\tanthropic\tm\tin 1 out 2 cache 3\tunpriced (approximate)\tunpriced"
        );
    }
}
