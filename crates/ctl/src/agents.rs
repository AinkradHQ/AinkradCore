//! `agent ls | run | show | cancel | kill` (E2-08.2): agent sessions on runners
//! (`/api/v1/agent-sessions`, scope `agent`). Starting, cancelling and killing one need a
//! step-up, which `Client::call` does once when the Core asks. Secrets are named, never given:
//! `--secrets name:VAR,…` leases each broker secret to the session's runner at each start.

use std::io::Write;

use serde_json::{Value, json};

use crate::Error;
use crate::client::{Client, parse};
use crate::devices::s;

fn print(out: &mut impl Write, text: impl std::fmt::Display) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

/// `id  state  harness  runner  last_seq  tokens in/out  created_at`.
fn row(v: &Value) -> String {
    format!(
        "{}\t{}\t{}\t{}\tseq {}\ttokens {}/{}\t{}",
        s(&v["id"]),
        s(&v["state"]),
        s(&v["harness"]),
        s(&v["runner"]),
        v["last_seq"],
        v["usage"]["input"],
        v["usage"]["output"],
        s(&v["created_at"]),
    )
}

fn sid(id: &str) -> Result<&str, Error> {
    let ok = id
        .strip_prefix("as_")
        .is_some_and(|b| b.len() == 26 && b.bytes().all(|c| c.is_ascii_alphanumeric()));
    ok.then_some(id)
        .ok_or_else(|| Error::Usage(format!("{id:?} is not an agent session id (as_…)")))
}

/// `name:VAR,…` as the API takes it.
fn secrets(spec: &str) -> Result<Value, Error> {
    let mut all = Vec::new();
    for item in spec.split(',').map(str::trim).filter(|i| !i.is_empty()) {
        let (name, var) = item
            .split_once(':')
            .ok_or_else(|| Error::Usage(format!("{item:?} is not name:VAR")))?;
        all.push(json!({"name": name, "var": var}));
    }
    Ok(Value::Array(all))
}

/// `agent …`; `secrets_flag` is `--secrets`.
pub async fn agent(
    c: &mut Client,
    words: &[&str],
    secrets_flag: Option<&str>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    let shown = |out: &mut _, v: Value| match json {
        true => print(out, v),
        false => print(out, row(&v)),
    };
    match words {
        ["ls" | "list"] => {
            let v: Value = c.get("/api/v1/agent-sessions", "").await?;
            if json {
                return print(out, v);
            }
            for r in v.as_array().into_iter().flatten() {
                print(out, row(r))?;
            }
            Ok(())
        }
        ["run", runner, harness, prompt @ ..] => {
            let mut body = json!({"runner": runner, "harness": harness});
            if !prompt.is_empty() {
                body["prompt"] = json!(prompt.join(" "));
            }
            if let Some(spec) = secrets_flag {
                body["secrets"] = secrets(spec)?;
            }
            let res = c
                .call("POST", "/api/v1/agent-sessions", "", Some(&body))
                .await?;
            shown(out, parse(&res)?)
        }
        ["show", id] => {
            let id = sid(id)?;
            let v: Value = c.get(&format!("/api/v1/agent-sessions/{id}"), "").await?;
            shown(out, v.clone())?;
            if json {
                return Ok(());
            }
            let path = format!("/api/v1/agent-sessions/{id}/transcript");
            let t: Value = c.get(&path, "after=0&limit=1000").await?;
            for e in t["entries"].as_array().into_iter().flatten() {
                print(out, format_args!("{}\t{}", e["seq"], e["body"]))?;
            }
            Ok(())
        }
        [verb @ ("cancel" | "kill"), id] => {
            let path = format!("/api/v1/agent-sessions/{}/{verb}", sid(id)?);
            let res = c.call("POST", &path, "", None).await?;
            shown(out, parse(&res)?)
        }
        _ => Err(Error::Usage(
            "agent ls | run <runner-id> <harness> [prompt…] | show <id> | cancel <id> | kill <id>"
                .into(),
        )),
    }
}
