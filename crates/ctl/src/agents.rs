//! `agent ls | wake <id> [text…] | run | show | cancel | kill` (E2-08.2): agent sessions on runners
//! (`/api/v1/agent-sessions`, scope `agent`). Starting, cancelling and killing one need a
//! step-up, which `Client::call` does once when the Core asks. Secrets are named, never given:
//! `--secrets name:VAR,…` leases each broker secret to the session's runner at each start.

use std::io::Write;
use std::time::Duration;

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

const RUN_USAGE: &str = "agent run <runner-id> <harness> [prompt…], or agent run <runner-id> [prompt…] --chain <id> [--agent <name>]";

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

/// The flags `agent …` reads.
#[derive(Default)]
pub struct Opts<'a> {
    /// `--secrets`.
    pub secrets: Option<&'a str>,
    /// `--after`.
    pub after: Option<i64>,
    /// Whether `tail` follows (no `--no-follow`).
    pub follow: bool,
    /// `--chain`: the fallback chain's id; the session draws its account from it.
    pub chain: Option<i64>,
    /// `--agent`: the agent id, whose bound (else the default) chain serves the session.
    pub agent: Option<&'a str>,
    /// `--run`: `ls` lists only the attempts of this run (its first attempt's id).
    pub run: Option<&'a str>,
}

/// `agent …`.
pub async fn agent(
    c: &mut Client,
    words: &[&str],
    opts: &Opts<'_>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    let Opts {
        secrets: secrets_flag,
        after,
        follow,
        chain,
        agent,
        run,
    } = *opts;
    let shown = |out: &mut _, v: Value| match json {
        true => print(out, v),
        false => print(out, row(&v)),
    };
    match words {
        ["ls" | "list"] => {
            let query = run.map(|r| sid(r).map(|r| format!("run={r}"))).transpose()?;
            let v: Value = c
                .get("/api/v1/agent-sessions", query.as_deref().unwrap_or(""))
                .await?;
            if json {
                return print(out, v);
            }
            for r in v.as_array().into_iter().flatten() {
                print(out, row(r))?;
            }
            Ok(())
        }
        ["run" | "start", runner, rest @ ..] => {
            // With a chain (or an agent, whose chain serves it) the allocated account sets the
            // harness and the model, so none is given: everything after the runner is the prompt.
            let scheduled = chain.is_some() || agent.is_some();
            let (mut body, prompt) = match (scheduled, rest) {
                (true, prompt) => {
                    let mut b = json!({"runner": runner});
                    if let Some(id) = chain {
                        b["chain"] = json!(id);
                    }
                    if let Some(a) = agent {
                        b["agent"] = json!(crate::chains::agent_id(a)?);
                    }
                    (b, prompt)
                }
                (false, [harness, prompt @ ..]) => (json!({"runner": runner, "harness": harness}), prompt),
                (false, []) => return Err(Error::Usage(RUN_USAGE.into())),
            };
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
            for l in crate::sessions::detail(&v) {
                print(out, l)?;
            }
            let path = format!("/api/v1/agent-sessions/{id}/transcript");
            let t: Value = c.get(&path, "after=0&limit=1000").await?;
            for e in t["entries"].as_array().into_iter().flatten() {
                print(out, format_args!("{}\t{}", e["seq"], e["body"]))?;
            }
            Ok(())
        }
        ["tail", id] => {
            let id = sid(id)?;
            let mut next = after.unwrap_or(0).max(0) as u64;
            loop {
                let t: Value = c.get(&format!("/api/v1/agent-sessions/{id}/transcript"), &format!("after={next}&limit=1000")).await?;
                let entries = t["entries"].as_array().ok_or_else(|| Error::Protocol("transcript entries are not an array".into()))?;
                for entry in entries {
                    let seq = entry["seq"].as_u64().ok_or_else(|| Error::Protocol("transcript entry without seq".into()))?;
                    if seq != next + 1 { return Err(Error::Protocol(format!("transcript gap: expected {}, got {seq}", next + 1))); }
                    if json { print(out, entry)?; } else { print(out, format_args!("{seq}\t{}", entry["body"]))?; }
                    next = seq;
                }
                let state = t["state"].as_str().unwrap_or("");
                if !follow || matches!(state, "ended" | "lost") { return Ok(()); }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        ["send", id, message @ ..] => {
            let body = json!({"text": message.join(" ")});
            let res = c.call("POST", &format!("/api/v1/agent-sessions/{}/messages", sid(id)?), "", Some(&body)).await?;
            shown(out, parse(&res)?)
        }
        [verb @ ("approve" | "deny"), id, request, reason @ ..] => {
            let body = json!({"approved": *verb == "approve", "reply": (!reason.is_empty()).then(|| reason.join(" "))});
            let res = c.call("POST", &format!("/api/v1/agent-sessions/{}/approvals/{request}", sid(id)?), "", Some(&body)).await?;
            shown(out, parse(&res)?)
        }
        ["wake", id, text @ ..] => {
            let id = sid(id)?;
            let mut body = json!({});
            if !text.is_empty() {
                body["text"] = json!(text.join(" "));
            }
            let path = format!("/api/v1/agent-sessions/{id}/wake");
            let res = c
                .call("POST", &path, "", Some(&body))
                .await
                .map_err(|e| crate::chains::friendly(e, &format!("waking {id}")))?;
            let v: Value = parse(&res)?;
            match (json, v["queued"].as_bool()) {
                (true, _) => print(out, v),
                (false, Some(false)) => print(out, format_args!("not queued: key {} was used", s(&v["key"]))),
                (false, _) => print(out, format_args!("queued wake for {} key {}", s(&v["session"]), s(&v["key"]))),
            }
        }
        [verb @ ("cancel" | "kill"), id] => {
            let path = format!("/api/v1/agent-sessions/{}/{verb}", sid(id)?);
            let res = c.call("POST", &path, "", None).await?;
            shown(out, parse(&res)?)
        }
        _ => Err(Error::Usage(
            "agent ls | run <runner-id> <harness> [prompt…] (or, with --chain <id> / --agent <name>: run <runner-id> [prompt…]) | show <id> | tail <id> | send <id> <message…> | approve/deny <id> <request> | cancel/kill <id>"
                .into(),
        )),
    }
}
