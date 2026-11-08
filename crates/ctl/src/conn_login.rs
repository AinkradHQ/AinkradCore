//! `connection login <kind>`: the sign-in flow. Starts a flow, says in plain words what to open
//! (GitHub: an address and a code; Jira: an authorize address), then polls the flow and prints
//! each step once (waiting, approved, choose a site, connected as ...) until it ends. The Mac
//! app catches Jira's loopback redirect; here the person gives the address the browser ended on
//! (`--callback-url`, or pasted at the prompt) and ctl posts its `code` and `state` to the flow.
//! Ctrl-C drops the flow at the Core. The `code`, `state` and the pasted address are never
//! printed. Prompts go to stderr; with `--json` stdout carries the flow as the Core gave it, one
//! object per step.

use std::io::Write;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use crate::Error;
use crate::client::Client;
use crate::conn_input::{conn_id, print};
use crate::connections::{Opts, send};
use crate::devices::s;

/// A flow's own id goes into a path: `cf_` and word characters only.
fn flow_id(id: &str) -> Result<&str, Error> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    ok.then_some(id)
        .ok_or_else(|| Error::Protocol("a flow id that is not safe to put in a path".into()))
}

fn percent_decode(v: &str) -> String {
    let b = v.as_bytes();
    let (mut out, mut i) = (Vec::new(), 0);
    while i < b.len() {
        let hex = |x: u8| (x as char).to_digit(16);
        match (
            b[i],
            b.get(i + 1).and_then(|x| hex(*x)),
            b.get(i + 2).and_then(|x| hex(*x)),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (c, ..) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The `code` and `state` of the address the browser was sent to. Nothing of the address is
/// ever put in a message.
pub fn callback_parts(url: &str) -> Result<(String, String), Error> {
    let query = url
        .split('#')
        .next()
        .unwrap_or("")
        .split_once('?')
        .map_or("", |(_, q)| q);
    let get = |k: &str| {
        query
            .split('&')
            .filter_map(|p| p.split_once('='))
            .find(|(n, _)| *n == k)
            .map(|(_, v)| percent_decode(v))
    };
    if let Some(e) = get("error") {
        let safe: String = e
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(40)
            .collect();
        return Err(Error::Usage(format!(
            "that address says the sign-in did not finish (error={safe}): run `connection login` again"
        )));
    }
    match (get("code"), get("state")) {
        (Some(c), Some(s)) if !c.is_empty() && !s.is_empty() => Ok((c, s)),
        _ => Err(Error::Usage(
            "that address has no code and state: give the whole address the browser ended on"
                .into(),
        )),
    }
}

/// Lines from stdin on a thread of their own, so a read nobody answers never holds the process
/// back when it is cancelled.
fn stdin_lines() -> UnboundedReceiver<String> {
    let (tx, rx) = unbounded_channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        while std::io::stdin().read_line(&mut line).is_ok_and(|n| n > 0) {
            if tx.send(line.trim().to_owned()).is_err() {
                break;
            }
            line.clear();
        }
    });
    rx
}

struct Cancelled;

/// `fut`, unless Ctrl-C comes first.
async fn or_cancel<T>(sig: &mut Signal, fut: impl Future<Output = T>) -> Result<T, Cancelled> {
    tokio::select! {
        r = fut => Ok(r),
        _ = sig.recv() => Err(Cancelled),
    }
}

fn ended(text: String, code: u8) -> Error {
    Error::Flow { text, code }
}

/// Drops the flow at the Core, saying nothing: a refusal ended it for good.
async fn drop_quiet(c: &mut Client, id: &str) {
    let _ = c
        .call(
            "DELETE",
            &format!("/api/v1/connections/flows/{id}"),
            "",
            None,
        )
        .await;
}

/// Drops the flow at the Core and says so.
async fn drop_flow(c: &mut Client, id: &str) -> Error {
    let path = format!("/api/v1/connections/flows/{id}");
    match c.call("DELETE", &path, "", None).await {
        Ok(_) => eprintln!("ainkradctl: cancelled: the sign-in flow was dropped at the Core"),
        Err(e) => eprintln!("ainkradctl: cancelled, but the Core could not drop the flow: {e}"),
    }
    ended("cancelled: the sign-in was not finished".into(), 130)
}

fn sites_lines(v: &Value) -> Vec<String> {
    let sites = v["sites"].as_array().into_iter().flatten();
    sites
        .enumerate()
        .map(|(i, st)| {
            format!(
                "  {}\t{}\t{}\t{}",
                i + 1,
                s(&st["name"]),
                s(&st["url"]),
                s(&st["id"])
            )
        })
        .collect()
}

/// The site `want` names: its number in the list, its id, its name or its address.
fn pick_site<'a>(v: &'a Value, want: &str) -> Option<&'a str> {
    let sites = v["sites"].as_array()?;
    let by_number = want
        .parse::<usize>()
        .ok()
        .and_then(|n| sites.get(n.checked_sub(1)?));
    let hit = by_number.or_else(|| {
        sites.iter().find(|st| {
            s(&st["id"]) == want
                || s(&st["name"]).eq_ignore_ascii_case(want)
                || s(&st["url"]).trim_end_matches('/') == want.trim_end_matches('/')
        })
    });
    hit.and_then(|st| st["id"].as_str())
}

/// What to do now, in plain words, once, when the flow starts.
fn instructions(v: &Value, out: &mut impl Write) -> Result<(), Error> {
    if let (Some(code), Some(uri)) = (v["user_code"].as_str(), v["verification_uri"].as_str()) {
        print(out, format_args!("open this address: {uri}"))?;
        print(out, format_args!("and enter this code: {code}"))?;
    }
    if let Some(url) = v["authorize_url"].as_str() {
        print(out, format_args!("open this address and sign in: {url}"))?;
    }
    Ok(())
}

/// `login <kind>`.
pub async fn login(
    c: &mut Client,
    kind: &str,
    o: &Opts<'_>,
    json_mode: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    let callback = o.callback_url.map(callback_parts).transpose()?;
    let mut body = json!({"kind": kind});
    if let Some(n) = o.name {
        body["name"] = json!(n);
    }
    if let Some(l) = o.label {
        body["label"] = json!(l);
    }
    if let Some(id) = o.connection {
        body["connection"] = json!(conn_id(id)?);
    }
    if o.confirm_identity_change {
        body["confirm_identity_change"] = json!(true);
    }
    let mut sig =
        signal(SignalKind::interrupt()).map_err(|e| Error::Unreachable(format!("signal: {e}")))?;
    let what = format!("signing in to {kind}");
    let mut view = send(
        c,
        "POST",
        "/api/v1/connections/start",
        "",
        Some(&body),
        &what,
        &[],
    )
    .await?;
    let id = flow_id(s(&view["id"]))?.to_owned();
    let path = format!("/api/v1/connections/flows/{id}");
    let mut lines: Option<UnboundedReceiver<String>> = None;
    let (mut last, mut callback) = (String::new(), callback);
    let mut first = true;
    loop {
        let step = s(&view["step"]).to_owned();
        if step != last {
            if json_mode {
                print(out, &view)?;
            } else {
                if first {
                    instructions(&view, out)?;
                }
                match step.as_str() {
                    "waiting" => print(out, "waiting for you to approve")?,
                    "approved" => print(out, "approved, finishing the sign-in")?,
                    "connected" => print(
                        out,
                        format_args!(
                            "connected as {} (connection {})",
                            view["identity"].as_str().unwrap_or("-"),
                            view["connection"]
                        ),
                    )?,
                    "choose_site" => {
                        print(out, "choose a site:")?;
                        sites_lines(&view)
                            .into_iter()
                            .try_for_each(|l| print(out, l))?;
                    }
                    _ => {}
                }
            }
            first = false;
            last = step.clone();
        }
        match step.as_str() {
            "connected" => return Ok(()),
            "expired" => {
                return Err(ended(
                    format!(
                        "expired: the {kind} sign-in ran out of time; run `connection login {kind}` again"
                    ),
                    4,
                ));
            }
            "denied" => {
                return Err(ended(
                    format!("denied: the {kind} sign-in was refused, nothing was connected"),
                    4,
                ));
            }
            "failed" => {
                let code = view["error_code"].as_str().unwrap_or("failed");
                let msg = view["error_message"]
                    .as_str()
                    .unwrap_or("the sign-in did not finish");
                return Err(ended(format!("failed: {code}: {msg}"), 4));
            }
            "choose_site" => {
                let want = match o.site {
                    Some(w) => w.to_owned(),
                    None => {
                        eprint!("site number or id: ");
                        let rx = lines.get_or_insert_with(stdin_lines);
                        match or_cancel(&mut sig, rx.recv()).await {
                            Err(Cancelled) => return Err(drop_flow(c, &id).await),
                            Ok(Some(l)) => l,
                            Ok(None) => String::new(),
                        }
                    }
                };
                let Some(site) = pick_site(&view, &want).map(str::to_owned) else {
                    let e = if want.is_empty() {
                        "no site chosen: give --site <number|id|name>".to_owned()
                    } else {
                        "no site matches that; give --site <number|id|name> from the list"
                            .to_owned()
                    };
                    let _ = drop_flow(c, &id).await;
                    return Err(Error::Usage(e));
                };
                let p = format!("{path}/choose");
                let b = json!({"site": site});
                match or_cancel(&mut sig, send(c, "POST", &p, "", Some(&b), &what, &[])).await {
                    Err(Cancelled) => return Err(drop_flow(c, &id).await),
                    Ok(Ok(v)) => view = v,
                    Ok(Err(e)) => {
                        drop_quiet(c, &id).await;
                        return Err(e);
                    }
                }
                continue;
            }
            _ => {}
        }
        // An Atlassian flow waits for the redirect's code and state: from the flag, or pasted.
        if step == "waiting" && view["authorize_url"].is_string() {
            if callback.is_none() {
                eprint!(
                    "then paste the address your browser ended on (it may fail to load, that is fine): "
                );
                let rx = lines.get_or_insert_with(stdin_lines);
                let line = match or_cancel(&mut sig, rx.recv()).await {
                    Err(Cancelled) => return Err(drop_flow(c, &id).await),
                    Ok(l) => l.unwrap_or_default(),
                };
                match callback_parts(&line) {
                    Ok(p) => callback = Some(p),
                    Err(e) => {
                        let _ = drop_flow(c, &id).await;
                        return Err(e);
                    }
                }
            }
            if let Some((code, state)) = callback.take() {
                let p = format!("{path}/callback");
                let b = json!({"code": code, "state": state});
                let hide = [code.as_str(), state.as_str()];
                match or_cancel(&mut sig, send(c, "POST", &p, "", Some(&b), &what, &hide)).await {
                    Err(Cancelled) => return Err(drop_flow(c, &id).await),
                    Ok(Ok(v)) => view = v,
                    Ok(Err(e)) => {
                        drop_quiet(c, &id).await;
                        return Err(e);
                    }
                }
                continue;
            }
        }
        let wait = view["interval"].as_u64().unwrap_or(2).min(30);
        if or_cancel(&mut sig, tokio::time::sleep(Duration::from_secs(wait)))
            .await
            .is_err()
        {
            return Err(drop_flow(c, &id).await);
        }
        match or_cancel(&mut sig, send(c, "GET", &path, "", None, &what, &[])).await {
            Err(Cancelled) => return Err(drop_flow(c, &id).await),
            Ok(r) => view = r?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_redirect_gives_its_code_and_state_and_never_echoes_them() {
        let (c, s) =
            callback_parts("http://127.0.0.1:47613/callback?code=a%2Fb&state=xyz#f").unwrap();
        assert_eq!((c.as_str(), s.as_str()), ("a/b", "xyz"));
        for bad in [
            "",
            "http://x/?code=a",
            "http://x/?state=a",
            "http://x/?code=&state=b",
        ] {
            assert!(
                matches!(callback_parts(bad), Err(Error::Usage(_))),
                "{bad:?}"
            );
        }
        let e = callback_parts("http://x/?error=access_denied&code=SECRETCODE").unwrap_err();
        assert!(e.to_string().contains("access_denied") && !e.to_string().contains("SECRETCODE"));
    }

    #[test]
    fn a_site_is_picked_by_number_id_name_or_address() {
        let v = json!({"sites": [{"id": "s1", "name": "Acme", "url": "https://acme.atlassian.net"},
            {"id": "s2", "name": "Beta", "url": "https://beta.atlassian.net"}]});
        for (want, id) in [
            ("2", "s2"),
            ("s1", "s1"),
            ("acme", "s1"),
            ("https://beta.atlassian.net/", "s2"),
        ] {
            assert_eq!(pick_site(&v, want), Some(id), "{want}");
        }
        assert_eq!(pick_site(&v, "3"), None);
        assert_eq!(pick_site(&v, ""), None);
    }

    #[test]
    fn a_flow_id_is_safe_for_a_path() {
        assert!(flow_id("cf_abc123").is_ok());
        assert!(flow_id("cf/../x").is_err() && flow_id("").is_err());
    }
}
