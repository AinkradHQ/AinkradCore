//! `pool ls | show | create | add | remove | default | rm` (`pools` too): the pools of accounts
//! (`/api/v1/pools`, scope `admin`; writes need a step-up). A pool holds accounts of one
//! provider in fallback order; the Core refuses what does not belong (another provider's account,
//! a second subscription, the default pool's removal) and its 400/404/409 is said plainly.
//! The contract has no read of one pool, so `show` finds it in the list.

use std::io::Write;

use serde_json::{Value, json};

use crate::Error;
use crate::accounts;
use crate::acct::{id, word};
use crate::client::Client;
use crate::conn_input::print;
use crate::connections::send;
use crate::devices::s;

pub const USAGE: &str = "pool ls | show <id> | create <name> <provider> | add <pool-id> <account-id> | remove <pool-id> <account-id> | default <pool-id> | rm <pool-id>";

fn members(p: &Value) -> Vec<String> {
    p["members"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| m.to_string())
        .collect()
}

/// `id  name  provider  members 3,5  default|-`; members are in fallback order.
pub fn row(p: &Value) -> String {
    let m = members(p);
    format!(
        "{}\t{}\t{}\tmembers {}\t{}",
        p["id"],
        s(&p["name"]),
        s(&p["provider"]),
        if m.is_empty() {
            "-".to_owned()
        } else {
            m.join(",")
        },
        if p["is_default"].as_bool() == Some(true) {
            "default"
        } else {
            "-"
        },
    )
}

fn shown(p: &Value, json: bool, out: &mut impl Write) -> Result<(), Error> {
    match json {
        true => print(out, p),
        false => print(out, row(p)),
    }
}

/// `pool …` (`pools` too).
pub async fn pool(
    c: &mut Client,
    words: &[&str],
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["ls" | "list"] => {
            let v = send(
                c,
                "GET",
                "/api/v1/pools",
                "",
                None,
                "listing the pools",
                &[],
            )
            .await?;
            if json {
                return print(out, v);
            }
            v.as_array()
                .into_iter()
                .flatten()
                .try_for_each(|p| print(out, row(p)))
        }
        ["show", i] => {
            let i = id("a pool", i)?;
            let what = format!("pool {i}");
            let all = send(c, "GET", "/api/v1/pools", "", None, &what, &[]).await?;
            let Some(p) = all
                .as_array()
                .into_iter()
                .flatten()
                .find(|p| p["id"].as_i64() == Some(i))
            else {
                return Err(Error::Refused {
                    status: 404,
                    code: "not_found".into(),
                    message: format!("{what}: no such pool"),
                    server_time: None,
                    local_time: 0,
                });
            };
            if json {
                return print(out, p);
            }
            print(out, row(p))?;
            // The seats, in order, with what each account is now.
            let accts = send(c, "GET", "/api/v1/accounts", "", None, &what, &[]).await?;
            for (n, m) in p["members"].as_array().into_iter().flatten().enumerate() {
                let a = accts
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|a| a["id"] == *m);
                match a {
                    Some(a) => print(out, format_args!("  seat {}\t{}", n + 1, accounts::row(a)))?,
                    None => print(out, format_args!("  seat {}\taccount {m}", n + 1))?,
                }
            }
            Ok(())
        }
        ["create", name, provider] => {
            let body = json!({"name": name, "provider": word("a provider (like anthropic)", provider, 64)?});
            let v = send(
                c,
                "POST",
                "/api/v1/pools",
                "",
                Some(&body),
                &format!("creating pool {name}"),
                &[],
            )
            .await?;
            shown(&v, json, out)
        }
        [verb @ ("add" | "remove"), p, a] => {
            let (p, a) = (id("a pool", p)?, id("an account", a)?);
            let (method, doing) = match *verb {
                "add" => ("PUT", format!("adding account {a} to pool {p}")),
                _ => ("DELETE", format!("removing account {a} from pool {p}")),
            };
            let v = send(
                c,
                method,
                &format!("/api/v1/pools/{p}/members/{a}"),
                "",
                None,
                &doing,
                &[],
            )
            .await?;
            shown(&v, json, out)
        }
        ["default", p] => {
            let p = id("a pool", p)?;
            let v = send(
                c,
                "PUT",
                &format!("/api/v1/pools/{p}/default"),
                "",
                None,
                &format!("making pool {p} the default"),
                &[],
            )
            .await?;
            shown(&v, json, out)
        }
        ["rm" | "delete", p] => {
            let p = id("a pool", p)?;
            let v = send(
                c,
                "DELETE",
                &format!("/api/v1/pools/{p}"),
                "",
                None,
                &format!("removing pool {p}"),
                &[],
            )
            .await?;
            match json {
                true => print(out, v),
                false => print(out, format_args!("removed pool {p}")),
            }
        }
        _ => Err(Error::Usage(USAGE.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pool_reads_as_a_row_in_fallback_order() {
        let p = json!({"id": 2, "name": "main", "provider": "anthropic", "is_default": true, "members": [9, 3]});
        assert_eq!(row(&p), "2\tmain\tanthropic\tmembers 9,3\tdefault");
        let e =
            json!({"id": 5, "name": "x", "provider": "openai", "is_default": false, "members": []});
        assert_eq!(row(&e), "5\tx\topenai\tmembers -\t-");
    }
}
