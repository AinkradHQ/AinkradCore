//! `connection kinds | ls | show | add | test | rename | enable | disable | rm | credential |
//! activity` (`connections` too): the Core's connections to outside services (`/api/v1/connection…`
//! routes of the contract). Reads need scope `read`, writes `admin` and a step-up, which
//! `Client::call` does once when the Core asks. Grants, defaults and the apps config are in
//! [`crate::conn_access`], sign-in in [`crate::conn_login`]. A credential is read from stdin, a
//! file or the environment, sent only in the body of the request that carries it, and never
//! printed.

use std::io::Write;

use serde_json::{Value, json};

use crate::Error;
use crate::client::{Client, parse};
use crate::conn_input::{TOKEN_ENV, conn_id, kind, print, said, secret};
use crate::devices::s;

/// The flags `connection …` reads.
#[derive(Default)]
pub struct Opts<'a> {
    pub token: Option<&'a str>,
    pub token_file: Option<&'a str>,
    pub email: Option<&'a str>,
    pub site: Option<&'a str>,
    pub name: Option<&'a str>,
    pub label: Option<&'a str>,
    pub kind: Option<&'a str>,
    pub connection: Option<&'a str>,
    pub caps: Option<&'a str>,
    pub limits: Vec<&'a str>,
    pub callback_url: Option<&'a str>,
    pub fields: Vec<&'a str>,
    pub file: Option<&'a str>,
    pub limit: Option<&'a str>,
    pub clear: bool,
    pub confirm_identity_change: bool,
}

const USAGE: &str = "connection kinds | ls [--kind k] | show <id> | add <kind> [--token-file f] [--email e] [--site s] [--name n] [--label l] | login <kind> [--name n] [--connection id] [--site s] [--callback-url u] | test <id> | rename <id> <name> | enable <id> | disable <id> | rm <id> | credential <id> | grants <id> | grant <id> <user|role|agent> <who> --caps a,b [--limit key=v1,v2] | revoke <id> <grantee-kind> <who> | default [kind] | default <kind> <id|--clear> | activity <id> [--limit n] | app <kind> [set --field name=value]";

/// One signed request; a refusal said plainly. `hide` is blanked from the Core's reason.
pub async fn send(
    c: &mut Client,
    method: &str,
    path: &str,
    query: &str,
    body: Option<&Value>,
    what: &str,
    hide: &[&str],
) -> Result<Value, Error> {
    let res = c.call(method, path, query, body).await;
    let res = res.map_err(|e| said(e, what, c.retry_after, hide))?;
    parse(&res)
}

/// `id  kind  name  status  identity  default|-`.
pub fn row(v: &Value) -> String {
    format!(
        "{}\t{}\t{}\t{}{}\t{}\t{}",
        v["id"],
        s(&v["kind"]),
        s(&v["name"]),
        s(&v["status"]),
        if v["disabled"].as_bool() == Some(true) {
            " (disabled)"
        } else {
            ""
        },
        v["identity"].as_str().unwrap_or("-"),
        if v["is_default"].as_bool() == Some(true) {
            "default"
        } else {
            "-"
        },
    )
}

fn yes(v: &Value) -> &'static str {
    if v.as_bool() == Some(true) {
        "yes"
    } else {
        "no"
    }
}

/// A connection, one `key value` line per fact.
pub fn show_lines(v: &Value) -> Vec<String> {
    let mut l = vec![
        format!("id {}", v["id"]),
        format!("kind {}", s(&v["kind"])),
        format!("name {}", s(&v["name"])),
    ];
    if let Some(label) = v["label"].as_str().filter(|x| !x.is_empty()) {
        l.push(format!("label {label}"));
    }
    l.push(format!("auth {}", s(&v["auth_method"])));
    l.push(format!(
        "identity {}",
        v["identity"].as_str().unwrap_or("-")
    ));
    l.push(format!("status {}", s(&v["status"])));
    if let Some(r) = v["state_reason"].as_str() {
        l.push(format!("reason {r}"));
    }
    if let Some(u) = v["state_until"].as_str() {
        l.push(format!("until {u}"));
    }
    l.push(format!("disabled {}", yes(&v["disabled"])));
    l.push(format!(
        "last_tested {}",
        v["last_tested_at"].as_str().unwrap_or("never")
    ));
    l.push(format!("default {}", yes(&v["is_default"])));
    if let Some(n) = v["grant_count"].as_i64() {
        l.push(format!("grants {n}"));
    }
    if let Some(caps) = v["my_capabilities"].as_array() {
        let caps: Vec<&str> = caps.iter().map(s).collect();
        l.push(format!("my_capabilities {}", caps.join(",")));
    }
    l
}

fn shown(v: Value, json: bool, out: &mut impl Write) -> Result<(), Error> {
    if json {
        return print(out, v);
    }
    show_lines(&v).into_iter().try_for_each(|l| print(out, l))
}

/// A kind: its row, then its capabilities and limit keys.
fn kind_lines(k: &Value) -> Vec<String> {
    let methods: Vec<String> = k["auth_methods"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| {
            let off = if m["available"].as_bool() == Some(false) {
                " (unavailable)"
            } else {
                ""
            };
            format!("{}{off}", s(&m["id"]))
        })
        .collect();
    let mut l = vec![format!(
        "{}\t{}\t{}\tauth {}",
        s(&k["kind"]),
        s(&k["title"]),
        if k["configured"].as_bool() == Some(true) {
            "configured"
        } else {
            "not configured"
        },
        methods.join(","),
    )];
    for c in k["capabilities"].as_array().into_iter().flatten() {
        l.push(format!(
            "  {}\t{}\t{}\t{}",
            s(&c["name"]),
            s(&c["class"]),
            if c["write"].as_bool() == Some(true) {
                "write"
            } else {
                "read"
            },
            s(&c["title"]),
        ));
    }
    for k in k["limits"].as_array().into_iter().flatten() {
        l.push(format!("  limit {}\t{}", s(&k["key"]), s(&k["help"])));
    }
    l
}

/// `connection …`.
pub async fn connection(
    c: &mut Client,
    words: &[&str],
    o: &Opts<'_>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["kinds"] => {
            let v = send(
                c,
                "GET",
                "/api/v1/connection-kinds",
                "",
                None,
                "listing the kinds",
                &[],
            )
            .await?;
            if json {
                return print(out, v);
            }
            let all = v.as_array().into_iter().flatten();
            all.flat_map(kind_lines).try_for_each(|l| print(out, l))
        }
        ["ls" | "list"] => {
            let query = o
                .kind
                .map(|k| kind(k).map(|k| format!("kind={k}")))
                .transpose()?;
            let q = query.as_deref().unwrap_or("");
            let v = send(
                c,
                "GET",
                "/api/v1/connections",
                q,
                None,
                "listing the connections",
                &[],
            )
            .await?;
            if json {
                return print(out, v);
            }
            v.as_array()
                .into_iter()
                .flatten()
                .try_for_each(|r| print(out, row(r)))
        }
        ["show", id] => {
            let id = conn_id(id)?;
            let path = format!("/api/v1/connections/{id}");
            shown(
                send(c, "GET", &path, "", None, &format!("connection {id}"), &[]).await?,
                json,
                out,
            )
        }
        ["add", k] => {
            let k = kind(k)?;
            let token = secret(
                "token",
                ("--token", o.token),
                ("--token-file", o.token_file),
                Some(TOKEN_ENV),
            )?;
            let mut body = json!({"kind": k, "auth_method": "token", "token": token.as_str()});
            for (key, v) in [
                ("email", o.email),
                ("site", o.site),
                ("name", o.name),
                ("label", o.label),
            ] {
                if let Some(v) = v {
                    body[key] = json!(v);
                }
            }
            let what = format!("adding a {k} connection");
            let v = send(
                c,
                "POST",
                "/api/v1/connections",
                "",
                Some(&body),
                &what,
                &[token.as_str()],
            )
            .await;
            drop(body);
            shown(v?, json, out)
        }
        ["login", k] => crate::conn_login::login(c, kind(k)?, o, json, out).await,
        ["test", id] => {
            let id = conn_id(id)?;
            let path = format!("/api/v1/connections/{id}/test");
            let v = send(
                c,
                "POST",
                &path,
                "",
                None,
                &format!("testing connection {id}"),
                &[],
            )
            .await?;
            if !json {
                let reason = v["state_reason"]
                    .as_str()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default();
                print(
                    out,
                    format_args!("tested connection {id}: {}{reason}", s(&v["status"])),
                )?;
            }
            shown(v, json, out)
        }
        ["rename", id, name] => {
            let id = conn_id(id)?;
            patch(c, id, json!({"name": name}), "renaming", json, out).await
        }
        [verb @ ("enable" | "disable"), id] => {
            let id = conn_id(id)?;
            let what = if *verb == "enable" {
                "enabling"
            } else {
                "disabling"
            };
            patch(
                c,
                id,
                json!({"disabled": *verb == "disable"}),
                what,
                json,
                out,
            )
            .await
        }
        ["rm" | "delete", id] => {
            let id = conn_id(id)?;
            let path = format!("/api/v1/connections/{id}");
            let v = send(
                c,
                "DELETE",
                &path,
                "",
                None,
                &format!("removing connection {id}"),
                &[],
            )
            .await;
            let v = v.map_err(|e| match e {
                Error::Refused { status: 409, code, message, server_time, local_time } => Error::Refused {
                    status: 409,
                    code,
                    message: format!(
                        "{message}; fix: make another connection the default (`connection default <kind> <id>`) or clear it (`connection default <kind> --clear`), then remove this one"
                    ),
                    server_time,
                    local_time,
                },
                e => e,
            })?;
            match json {
                true => print(out, v),
                false => print(out, format_args!("removed connection {id}")),
            }
        }
        ["credential", id] => {
            let id = conn_id(id)?;
            let token = secret(
                "token",
                ("--token", o.token),
                ("--token-file", o.token_file),
                Some(TOKEN_ENV),
            )?;
            let mut body = json!({"token": token.as_str()});
            for (key, v) in [("email", o.email), ("site", o.site)] {
                if let Some(v) = v {
                    body[key] = json!(v);
                }
            }
            let path = format!("/api/v1/connections/{id}/credential");
            let what = format!("replacing the credential of connection {id}");
            let v = send(c, "PUT", &path, "", Some(&body), &what, &[token.as_str()]).await;
            drop(body);
            shown(v?, json, out)
        }
        ["activity", id] => {
            let id = conn_id(id)?;
            let limit = o
                .limit
                .map(|n| {
                    n.parse::<u32>()
                        .map_err(|_| Error::Usage("--limit takes a number".into()))
                })
                .transpose()?;
            let q = limit.map(|n| format!("limit={n}")).unwrap_or_default();
            let path = format!("/api/v1/connections/{id}/activity");
            let v = send(
                c,
                "GET",
                &path,
                &q,
                None,
                &format!("activity of connection {id}"),
                &[],
            )
            .await?;
            if json {
                return print(out, v);
            }
            v.as_array().into_iter().flatten().try_for_each(|a| {
                print(
                    out,
                    format_args!(
                        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                        a["seq"],
                        s(&a["at"]),
                        s(&a["kind"]),
                        s(&a["action"]),
                        s(&a["result"]),
                        s(&a["code"]),
                        s(&a["agent"]),
                        s(&a["session"]),
                    ),
                )
            })
        }
        ["grants", ..] | ["grant", ..] | ["revoke", ..] | ["default", ..] | ["app", ..] => {
            crate::conn_access::access(c, words, o, json, out).await
        }
        _ => Err(Error::Usage(USAGE.into())),
    }
}

async fn patch(
    c: &mut Client,
    id: i64,
    body: Value,
    doing: &str,
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    let path = format!("/api/v1/connections/{id}");
    let v = send(
        c,
        "PATCH",
        &path,
        "",
        Some(&body),
        &format!("{doing} connection {id}"),
        &[],
    )
    .await?;
    shown(v, json, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connection_reads_as_a_row_and_as_lines() {
        let v = json!({"id": 3, "kind": "github", "name": "work", "label": "", "auth_method": "token",
            "status": "auth_suspected", "state_reason": "auth_suspected", "disabled": true,
            "is_default": true, "identity": null, "grant_count": 2, "last_tested_at": null});
        assert_eq!(
            row(&v),
            "3\tgithub\twork\tauth_suspected (disabled)\t-\tdefault"
        );
        let l = show_lines(&v);
        assert!(l.contains(&"reason auth_suspected".to_owned()));
        assert!(l.contains(&"last_tested never".to_owned()) && l.contains(&"grants 2".to_owned()));
        assert!(
            !l.iter()
                .any(|x| x.starts_with("label") || x.starts_with("until"))
        );
    }
}
