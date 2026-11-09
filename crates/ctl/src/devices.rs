//! `device …` and `lockouts …`: device management over `/api/v1/devices`, `/api/v1/pairings`
//! and `/api/v1/auth/lockouts`. The destructive ones (spec §8: pairing create, approve and
//! reject; revoke, rename, scope change; clearing a lockout) go through `Client::call`, which
//! elevates once when the Core answers `step_up_required`.

use std::io::Write;

use serde_json::{Value, json};

use crate::Error;
use crate::client::{Client, parse};

fn pid(id: &str) -> Result<&str, Error> {
    let ok = id
        .strip_prefix("p_")
        .is_some_and(|b| b.len() == 26 && b.bytes().all(|c| c.is_ascii_alphanumeric()));
    ok.then_some(id)
        .ok_or_else(|| Error::Usage(format!("{id:?} is not a pairing id (p_…)")))
}

fn did(id: &str) -> Result<&str, Error> {
    let ok = id
        .strip_prefix("d_")
        .is_some_and(|b| b.len() == 26 && b.bytes().all(|c| c.is_ascii_alphanumeric()));
    ok.then_some(id)
        .ok_or_else(|| Error::Usage(format!("{id:?} is not a device id (d_…)")))
}

pub fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("-")
}

fn device_row(d: &Value) -> String {
    let scopes: Vec<&str> = d["scopes"]
        .as_array()
        .map(|a| a.iter().map(s).collect())
        .unwrap_or_default();
    let revoked = d["revoked_at"]
        .as_str()
        .map(|r| format!("\trevoked {r}"))
        .unwrap_or_default();
    let stepup = match d["stepup"].as_bool() {
        Some(true) => "stepup",
        Some(false) => "no-stepup",
        None => "-",
    };
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\t{stepup}{revoked}",
        s(&d["id"]),
        s(&d["kind"]),
        s(&d["name"]),
        s(&d["status"]),
        scopes.join(","),
        s(&d["fingerprint"])
    )
}

fn pairing_rows(p: &Value) -> Vec<String> {
    [
        "pairing_id",
        "name",
        "kind",
        "status",
        "device_id",
        "sas",
        "fingerprint",
        "platform",
        "key_storage",
        "expires_at",
    ]
    .iter()
    .filter(|k| !p[**k].is_null())
    .map(|k| format!("{k} {}", s(&p[*k])))
    .collect()
}

fn print(out: &mut impl Write, json: bool, v: &Value, rows: Vec<String>) -> Result<(), Error> {
    let text = if json { v.to_string() } else { rows.join("\n") };
    writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

/// The last-admin refusal (409) in words; anything else unchanged.
fn last_admin(e: Error) -> Error {
    match e {
        Error::Refused {
            status: 409,
            code,
            local_time,
            ..
        } => Error::Refused {
            status: 409,
            code,
            message: "refused: that would leave no active admin device; pair and approve \
                      another admin first"
                .into(),
            server_time: None,
            local_time,
        },
        e => e,
    }
}

const DEVICE_USAGE: &str = "device ls | show <id> | revoke <id> | rename <id> <name> | \
    scopes <id> <scope>... | add <name> | pairing <id> | approve <id> <SAS> | reject <id>";

/// `device …`; `scopes` is `--scopes` split on commas.
pub async fn device(
    c: &mut Client,
    words: &[&str],
    kind: Option<&str>,
    scopes: Option<Vec<String>>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["ls" | "list"] => {
            let v: Value = c.get("/api/v1/devices", "").await?;
            let rows = v
                .as_array()
                .map(|a| a.iter().map(device_row).collect())
                .unwrap_or_default();
            print(out, json, &v, rows)
        }
        ["show", id] => {
            let d: Value = c.get(&format!("/api/v1/devices/{}", did(id)?), "").await?;
            print(out, json, &d, vec![device_row(&d)])
        }
        ["revoke", id] => {
            let path = format!("/api/v1/devices/{}", did(id)?);
            let res = c
                .call("DELETE", &path, "", None)
                .await
                .map_err(last_admin)?;
            let d: Value = parse(&res)?;
            print(out, json, &d, vec![format!("revoked {}", s(&d["id"]))])
        }
        ["rename", id, name @ ..] if !name.is_empty() => {
            let path = format!("/api/v1/devices/{}", did(id)?);
            let body = json!({"name": name.join(" ")});
            let d: Value = parse(&c.call("PATCH", &path, "", Some(&body)).await?)?;
            print(out, json, &d, vec![device_row(&d)])
        }
        ["scopes", id, list @ ..] if !list.is_empty() => {
            let path = format!("/api/v1/devices/{}/scopes", did(id)?);
            let list: Vec<&str> = list
                .iter()
                .flat_map(|w| w.split(','))
                .map(str::trim)
                .filter(|w| !w.is_empty())
                .collect();
            let body = json!({ "scopes": list });
            let res = c
                .call("PUT", &path, "", Some(&body))
                .await
                .map_err(last_admin)?;
            let d: Value = parse(&res)?;
            print(out, json, &d, vec![device_row(&d)])
        }
        ["add", name] => {
            let kind = kind.unwrap_or("device");
            let scopes = match (scopes, kind) {
                (Some(s), _) => s,
                (None, "runner") => vec!["runner".to_owned()],
                (None, _) => {
                    return Err(Error::Usage(
                        "device add needs --scopes (e.g. read,approve)".into(),
                    ));
                }
            };
            let body = json!({"name": name, "kind": kind, "scopes": scopes});
            let p: Value = parse(&c.call("POST", "/api/v1/pairings", "", Some(&body)).await?)?;
            // Showing the code and QR payload is this command's job; nothing else prints them.
            let rows = ["pairing_id", "code", "qr", "expires_at"]
                .iter()
                .map(|k| format!("{k} {}", s(&p[*k])))
                .collect();
            print(out, json, &p, rows)
        }
        ["pairing", id] => {
            let p: Value = c.get(&format!("/api/v1/pairings/{}", pid(id)?), "").await?;
            print(out, json, &p, pairing_rows(&p))
        }
        ["approve", id, sas] => {
            let sas = sas.trim().to_ascii_uppercase();
            let shaped = sas.len() == 19
                && sas
                    .split('-')
                    .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_alphanumeric()));
            if !shaped {
                return Err(Error::Usage(
                    "the SAS is XXXX-XXXX-XXXX-XXXX, as the new device shows it".into(),
                ));
            }
            let mut body = json!({"sas": sas});
            if let Some(scopes) = scopes {
                body["scopes"] = json!(scopes);
            }
            let path = format!("/api/v1/pairings/{}/approve", pid(id)?);
            let p: Value = parse(&c.call("POST", &path, "", Some(&body)).await?)?;
            print(
                out,
                json,
                &p,
                vec![format!("approved {}", s(&p["device_id"]))],
            )
        }
        ["reject", id] => {
            let path = format!("/api/v1/pairings/{}/reject", pid(id)?);
            let p: Value = parse(&c.call("POST", &path, "", None).await?)?;
            print(
                out,
                json,
                &p,
                vec![format!("rejected {}", s(&p["pairing_id"]))],
            )
        }
        _ => Err(Error::Usage(DEVICE_USAGE.into())),
    }
}

/// `lockouts ls | clear <key>`.
pub async fn lockouts(
    c: &mut Client,
    words: &[&str],
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["ls" | "list"] => {
            let v: Value = c.get("/api/v1/auth/lockouts", "").await?;
            let rows = v
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|l| {
                            format!(
                                "{}\t{}\t{}",
                                s(&l["key"]),
                                s(&l["locked_until"]),
                                l["strikes"]
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            print(out, json, &v, rows)
        }
        ["clear", key] => {
            let body = json!({ "key": key });
            let res = c
                .call("POST", "/api/v1/auth/lockouts/clear", "", Some(&body))
                .await?;
            let v: Value = parse(&res)?;
            print(out, json, &v, vec![format!("cleared {}", s(&v["key"]))])
        }
        _ => Err(Error::Usage("lockouts ls | clear <key>".into())),
    }
}
