//! `account login <provider>`: a subscription account by sign-in. Starts the sign-in on a runner
//! (`POST /accounts/logins`), says what to open, takes the approval code the person pastes
//! (stdin, or `$AINKRAD_ACCOUNT_CODE`), sends it once, then polls until the account is stored
//! (`starting`, `open_url`, `waiting_code`, `storing`, `done`, `failed`, `cancelled`). Ctrl-C
//! cancels it at the Core (exit 130). The code is never printed, logged or kept; prompts go to
//! stderr; with `--json` stdout carries the sign-in as the Core gave it, one object per step.

use std::io::Write;
use std::time::Duration;

use serde_json::json;
use tokio::signal::unix::{SignalKind, signal};

use crate::Error;
use crate::acct::Opts;
use crate::client::Client;
use crate::conn_input::print;
use crate::conn_login::{Cancelled, or_cancel, stdin_lines};
use crate::connections::send;
use crate::devices::s;

/// The environment variable the approval code can be read from (instead of a prompt).
pub const CODE_ENV: &str = "AINKRAD_ACCOUNT_CODE";

/// A sign-in's id goes into a path: word characters and `-` only.
fn login_id(id: &str) -> Result<&str, Error> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    ok.then_some(id)
        .ok_or_else(|| Error::Protocol("a sign-in id that is not safe to put in a path".into()))
}

/// The contract's shape of a code: 8 to 512 of letters, digits and `-_.~#:+/=`.
pub fn code_ok(code: &str) -> bool {
    (8..=512).contains(&code.len())
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.~#:+/=".contains(&b))
}

fn ended(text: String, code: u8) -> Error {
    Error::Flow { text, code }
}

/// Cancels the sign-in at the Core and says so.
async fn cancel(c: &mut Client, id: &str, loud: bool) {
    let path = format!("/api/v1/accounts/logins/{id}");
    match (c.call("DELETE", &path, "", None).await, loud) {
        (Ok(_), true) => eprintln!("ainkradctl: cancelled: the sign-in was dropped at the Core"),
        (Err(e), true) => eprintln!("ainkradctl: cancelled, but the Core could not drop it: {e}"),
        _ => {}
    }
}

/// `login <provider>`.
pub async fn login(
    c: &mut Client,
    provider: &str,
    o: &Opts<'_>,
    json_mode: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    let mut body = json!({"provider": provider, "label": o.label.unwrap_or(provider)});
    if let Some(r) = o.runner {
        body["runner"] = json!(r);
    }
    let mut sig =
        signal(SignalKind::interrupt()).map_err(|e| Error::Unreachable(format!("signal: {e}")))?;
    let what = format!("signing in to {provider}");
    let mut view = send(
        c,
        "POST",
        "/api/v1/accounts/logins",
        "",
        Some(&body),
        &what,
        &[],
    )
    .await?;
    let id = login_id(s(&view["id"]))?.to_owned();
    let path = format!("/api/v1/accounts/logins/{id}");
    let mut lines = None;
    let mut last = String::new();
    loop {
        let state = s(&view["state"]).to_owned();
        if state != last {
            if json_mode {
                print(out, &view)?;
            } else {
                match state.as_str() {
                    "starting" => print(
                        out,
                        format_args!("starting the sign-in on runner {}", s(&view["runner"])),
                    )?,
                    "open_url" => print(
                        out,
                        format_args!("open this address and sign in: {}", s(&view["url"])),
                    )?,
                    "waiting_code" => print(
                        out,
                        "the code is with the runner, waiting for the sign-in to finish",
                    )?,
                    "storing" => print(out, "storing the account")?,
                    "done" => print(
                        out,
                        format_args!(
                            "signed in: account {} ({})",
                            view["account_id"],
                            s(&view["label"])
                        ),
                    )?,
                    _ => {}
                }
            }
            last = state.clone();
        }
        match state.as_str() {
            "done" => return Ok(()),
            "failed" | "cancelled" => {
                let why = view["reason"]
                    .as_str()
                    .unwrap_or("the sign-in did not finish");
                return Err(ended(
                    format!("{state}: {why}; run `account login {provider}` again"),
                    4,
                ));
            }
            "open_url" => {
                let code = match std::env::var(CODE_ENV).ok().filter(|v| !v.is_empty()) {
                    Some(v) => v,
                    None => {
                        eprint!("then paste the approval code (it is not shown again): ");
                        let rx = lines.get_or_insert_with(stdin_lines);
                        match or_cancel(&mut sig, rx.recv()).await {
                            Err(Cancelled) => {
                                cancel(c, &id, true).await;
                                return Err(ended(
                                    "cancelled: the sign-in was not finished".into(),
                                    130,
                                ));
                            }
                            Ok(l) => l.unwrap_or_default(),
                        }
                    }
                };
                if !code_ok(&code) {
                    cancel(c, &id, false).await;
                    return Err(Error::Usage(
                        "the approval code is missing or not the shape of one (8 to 512 letters, \
                         digits and -_.~#:+/=); the sign-in was dropped, run `account login` again"
                            .into(),
                    ));
                }
                let p = format!("{path}/code");
                let b = json!({"code": code});
                match or_cancel(
                    &mut sig,
                    send(c, "POST", &p, "", Some(&b), &what, &[code.as_str()]),
                )
                .await
                {
                    Err(Cancelled) => {
                        cancel(c, &id, true).await;
                        return Err(ended("cancelled: the sign-in was not finished".into(), 130));
                    }
                    Ok(Ok(v)) => view = v,
                    Ok(Err(e)) => {
                        cancel(c, &id, false).await;
                        return Err(e);
                    }
                }
                continue;
            }
            _ => {}
        }
        if or_cancel(&mut sig, tokio::time::sleep(Duration::from_secs(1)))
            .await
            .is_err()
        {
            cancel(c, &id, true).await;
            return Err(ended("cancelled: the sign-in was not finished".into(), 130));
        }
        match or_cancel(&mut sig, send(c, "GET", &path, "", None, &what, &[])).await {
            Err(Cancelled) => {
                cancel(c, &id, true).await;
                return Err(ended("cancelled: the sign-in was not finished".into(), 130));
            }
            Ok(r) => view = r?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_and_an_id_are_checked_for_shape_only() {
        assert!(code_ok("ABCD-1234_x.y~z#a:b+c/d="));
        for bad in [
            "",
            "short",
            "has space 12345",
            "tab\t123456789",
            &"x".repeat(513),
        ] {
            assert!(!code_ok(bad), "{bad:?}");
        }
        assert!(login_id("al_01-ab").is_ok());
        assert!(login_id("../x").is_err() && login_id("").is_err());
    }
}
