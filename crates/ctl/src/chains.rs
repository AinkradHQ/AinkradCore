//! `chains ls | show | create | update | delete | default | bind | unbind | bindings`: the
//! fallback chains of the account scheduler (`/api/v1/chains…`, scope `admin`). Every write needs
//! a step-up, which `Client::call` does once when the Core asks. An entry is `pool[:model]`; the
//! Core validates the lot (1 to 4 entries, a pool once, priced models), so a 400, 404 or 409 is
//! the Core's own sentence, put after what was being done.

use std::io::Write;

use serde_json::{Value, json};

use crate::Error;
use crate::client::{Client, parse};
use crate::devices::s;

fn print(out: &mut impl Write, text: impl std::fmt::Display) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

const USAGE: &str = "chains ls | show <id> | create <name> <pool[:model]>… | update <id> <name> <pool[:model]>… | delete <id> | default <id> | bind <agent> <chain-id> | unbind <agent> | bindings";

/// `id  name  default|-  N entries  updated_at`.
pub fn row(v: &Value) -> String {
    format!(
        "{}\t{}\t{}\t{} entries\t{}",
        v["id"],
        s(&v["name"]),
        if v["is_default"].as_bool() == Some(true) {
            "default"
        } else {
            "-"
        },
        v["entries"].as_array().map_or(0, Vec::len),
        s(&v["updated_at"]),
    )
}

/// One line per entry, in fallback order: `  [0]  pool 2  anthropic  claude  <model|default>`.
pub fn entry_lines(entries: &Value) -> Vec<String> {
    entries
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(i, e)| {
            format!(
                "  [{i}]\tpool {}\t{}\t{}\t{}",
                e["pool"],
                s(&e["provider"]),
                s(&e["harness"]),
                e["model"].as_str().unwrap_or("default"),
            )
        })
        .collect()
}

fn chain_id(id: &str) -> Result<i64, Error> {
    id.parse::<i64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| Error::Usage(format!("{id:?} is not a chain id (a number)")))
}

/// An agent id goes into a path: `[A-Za-z0-9._:-]`, 1 to 64 (the Core's own rule).
pub fn agent_id(id: &str) -> Result<&str, Error> {
    let ok = (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:_-".contains(&b));
    ok.then_some(id).ok_or_else(|| {
        Error::Usage(format!(
            "{id:?} is not an agent id ([A-Za-z0-9._:-], 1 to 64)"
        ))
    })
}

/// `pool[:model]` as the API takes an entry.
fn entry(spec: &str) -> Result<Value, Error> {
    let (pool, model) = match spec.split_once(':') {
        Some((p, m)) => (p, Some(m)),
        None => (spec, None),
    };
    let pool: i64 = pool.parse().ok().filter(|n| *n > 0).ok_or_else(|| {
        Error::Usage(format!(
            "{spec:?} is not pool[:model] (the pool's id first)"
        ))
    })?;
    match model {
        Some("") => Err(Error::Usage(format!("{spec:?} has an empty model"))),
        Some(m) => Ok(json!({"pool": pool, "model": m})),
        None => Ok(json!({"pool": pool})),
    }
}

fn entries(specs: &[&str]) -> Result<Vec<Value>, Error> {
    if specs.is_empty() {
        return Err(Error::Usage(
            "a chain needs at least one pool[:model]".into(),
        ));
    }
    specs.iter().map(|e| entry(e)).collect()
}

/// A 400, 404 or 409 from the Core, said plainly: what was being done, then the Core's reason.
/// The exit code stays that of a refusal (4).
fn friendly(e: Error, what: &str) -> Error {
    match e {
        Error::Refused {
            status: status @ (400 | 404 | 409),
            code,
            message,
            server_time,
            local_time,
        } => {
            let reason = match (message.is_empty(), status) {
                (false, _) => message,
                (true, 400) => "the Core refused the input".into(),
                (true, 404) => "not found".into(),
                (true, _) => "it conflicts with what the Core holds".into(),
            };
            Error::Refused {
                status,
                code,
                message: format!("{what}: {reason}"),
                server_time,
                local_time,
            }
        }
        e => e,
    }
}

async fn send(
    c: &mut Client,
    method: &str,
    path: &str,
    body: Option<&Value>,
    what: &str,
) -> Result<Value, Error> {
    let res = c
        .call(method, path, "", body)
        .await
        .map_err(|e| friendly(e, what))?;
    parse(&res)
}

fn shown_chain(v: Value, json: bool, out: &mut impl Write) -> Result<(), Error> {
    if json {
        return print(out, v);
    }
    print(out, row(&v))?;
    entry_lines(&v["entries"])
        .into_iter()
        .try_for_each(|l| print(out, l))
}

/// `chains …` (`chain` too).
pub async fn chains(
    c: &mut Client,
    words: &[&str],
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["ls" | "list"] => {
            let v = send(c, "GET", "/api/v1/chains", None, "listing the chains").await?;
            if json {
                return print(out, v);
            }
            v.as_array()
                .into_iter()
                .flatten()
                .try_for_each(|r| print(out, row(r)))
        }
        ["show", id] => {
            let id = chain_id(id)?;
            let v = send(
                c,
                "GET",
                &format!("/api/v1/chains/{id}"),
                None,
                &format!("chain {id}"),
            )
            .await?;
            shown_chain(v, json, out)
        }
        ["create", name, specs @ ..] => {
            let body = json!({"name": name, "entries": entries(specs)?});
            let v = send(
                c,
                "POST",
                "/api/v1/chains",
                Some(&body),
                &format!("creating chain {name:?}"),
            )
            .await?;
            shown_chain(v, json, out)
        }
        ["update", id, name, specs @ ..] => {
            let id = chain_id(id)?;
            let body = json!({"name": name, "entries": entries(specs)?});
            let v = send(
                c,
                "PUT",
                &format!("/api/v1/chains/{id}"),
                Some(&body),
                &format!("updating chain {id}"),
            )
            .await?;
            shown_chain(v, json, out)
        }
        ["delete" | "rm", id] => {
            let id = chain_id(id)?;
            let v = send(
                c,
                "DELETE",
                &format!("/api/v1/chains/{id}"),
                None,
                &format!("deleting chain {id}"),
            )
            .await?;
            match json {
                true => print(out, v),
                false => print(out, format_args!("deleted chain {id}")),
            }
        }
        ["default", id] => {
            let id = chain_id(id)?;
            let v = send(
                c,
                "PUT",
                &format!("/api/v1/chains/{id}/default"),
                None,
                &format!("making chain {id} the default"),
            )
            .await?;
            shown_chain(v, json, out)
        }
        ["bind", agent, id] => {
            let (agent, id) = (agent_id(agent)?, chain_id(id)?);
            let body = json!({"chain": id});
            let v = send(
                c,
                "PUT",
                &format!("/api/v1/chains/bindings/{agent}"),
                Some(&body),
                &format!("binding agent {agent} to chain {id}"),
            )
            .await?;
            match json {
                true => print(out, v),
                false => print(out, format_args!("bound agent {agent} to chain {id}")),
            }
        }
        ["unbind", agent] => {
            let agent = agent_id(agent)?;
            let v = send(
                c,
                "DELETE",
                &format!("/api/v1/chains/bindings/{agent}"),
                None,
                &format!("unbinding agent {agent}"),
            )
            .await?;
            match json {
                true => print(out, v),
                false => print(out, format_args!("unbound agent {agent}")),
            }
        }
        ["bindings"] => {
            let v = send(
                c,
                "GET",
                "/api/v1/chains/bindings",
                None,
                "listing the bindings",
            )
            .await?;
            if json {
                return print(out, v);
            }
            v.as_array().into_iter().flatten().try_for_each(|b| {
                print(
                    out,
                    format_args!("{}\tchain {}", s(&b["agent"]), b["chain"]),
                )
            })
        }
        _ => Err(Error::Usage(USAGE.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_pool_and_optional_model() {
        assert_eq!(entry("3").unwrap(), json!({"pool": 3}));
        assert_eq!(
            entry("3:claude-sonnet-4").unwrap(),
            json!({"pool": 3, "model": "claude-sonnet-4"})
        );
        // Only the first colon splits: a model may carry one.
        assert_eq!(entry("3:a:b").unwrap(), json!({"pool": 3, "model": "a:b"}));
        for bad in ["", "x", "0", "-1", "3:", ":m", "1.5"] {
            assert!(matches!(entry(bad), Err(Error::Usage(_))), "{bad:?}");
        }
        assert!(matches!(entries(&[]), Err(Error::Usage(_))));
    }

    #[test]
    fn ids_and_agents_are_checked_before_they_reach_a_path() {
        assert_eq!(chain_id("12").unwrap(), 12);
        for bad in ["0", "-3", "a", ""] {
            assert!(chain_id(bad).is_err(), "{bad:?}");
        }
        assert!(agent_id("repo-bot:v1.2_x").is_ok());
        for bad in ["", "a/b", "a b", "../x", &"a".repeat(65)] {
            assert!(agent_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_refusal_keeps_its_exit_code_and_gains_what_was_done() {
        let refused = |status, message: &str| Error::Refused {
            status,
            code: "x".into(),
            message: message.into(),
            server_time: None,
            local_time: 0,
        };
        let e = friendly(
            refused(409, "a chain of that name exists"),
            "creating chain \"a\"",
        );
        assert_eq!(e.code(), 4);
        assert_eq!(
            e.to_string(),
            "409 x: creating chain \"a\": a chain of that name exists"
        );
        assert_eq!(
            friendly(refused(404, ""), "chain 5").to_string(),
            "404 x: chain 5: not found"
        );
        // Not a 400, 404 or 409: untouched.
        assert_eq!(
            friendly(refused(403, "no"), "chain 5").to_string(),
            "403 x: no"
        );
    }

    #[test]
    fn a_chain_prints_one_row_and_its_entries_in_order() {
        let v = json!({"id": 1, "name": "main", "is_default": true, "updated_at": "T",
            "entries": [
              {"pool": 2, "provider": "anthropic", "harness": "claude", "model": "m1"},
              {"pool": 5, "provider": "openai", "harness": "codex", "model": null}]});
        assert_eq!(row(&v), "1\tmain\tdefault\t2 entries\tT");
        assert_eq!(
            entry_lines(&v["entries"]),
            [
                "  [0]\tpool 2\tanthropic\tclaude\tm1",
                "  [1]\tpool 5\topenai\tcodex\tdefault"
            ]
        );
    }
}
