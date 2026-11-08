//! `connection grants | grant | revoke | default | app`: who may use a connection and for what,
//! which connection is a kind's default, and Ainkrad's sign-in apps config (owner admin only).
//! The Core judges every capability, limit and field; ctl checks only the syntax. A value for a
//! secret field of an app is read from stdin or `--file`, never from the command line.

use std::io::Write;

use serde_json::{Map, Value, json};

use crate::Error;
use crate::client::Client;
use crate::conn_input::{conn_id, grantee, kind, limit, names, print, secret};
use crate::connections::{Opts, send};
use crate::devices::s;

/// `grantee_kind  grantee  caps  limits`.
fn grant_row(g: &Value) -> String {
    let caps: Vec<&str> = g["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .map(s)
        .collect();
    let limits: Vec<String> = g["limits"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, v)| {
            let vals: Vec<&str> = v.as_array().into_iter().flatten().map(s).collect();
            format!("{k}={}", vals.join(","))
        })
        .collect();
    format!(
        "{}\t{}\t{}\t{}",
        s(&g["grantee_kind"]),
        s(&g["grantee"]),
        if caps.is_empty() {
            "-".to_owned()
        } else {
            caps.join(",")
        },
        if limits.is_empty() {
            "-".to_owned()
        } else {
            limits.join(" ")
        },
    )
}

fn app_lines(v: &Value) -> Vec<String> {
    let yes = |b: &Value| {
        if b.as_bool() == Some(true) {
            "yes"
        } else {
            "no"
        }
    };
    let mut l = vec![
        format!("kind {}", s(&v["kind"])),
        format!("configured {}", yes(&v["configured"])),
        format!(
            "app_install_configured {}",
            yes(&v["app_install_configured"])
        ),
    ];
    if let Some(r) = v["redirect_uri"].as_str() {
        l.push(format!("redirect_uri {r}"));
    }
    for f in v["fields"].as_array().into_iter().flatten() {
        let secret = if f["secret"].as_bool() == Some(true) {
            "secret"
        } else {
            "plain"
        };
        let set = if f["set"].as_bool() == Some(true) {
            "set"
        } else {
            "unset"
        };
        l.push(format!("field {}\t{secret}\t{set}", s(&f["name"])));
    }
    l
}

/// `name=value`, the name being `[a-z][a-z0-9_]*`.
fn field_spec(spec: &str) -> Result<(&str, &str), Error> {
    let (name, v) = spec.split_once('=').ok_or_else(|| {
        Error::Usage("a --field is name=value (name=- reads from stdin or --file)".into())
    })?;
    let name_ok = !name.is_empty()
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    name_ok
        .then_some((name, v))
        .ok_or_else(|| Error::Usage(format!("{name:?} is not a field name")))
}

/// `name=value` pairs of `app set`, with the Core's own word on which fields are secret: a
/// secret given on the command line is refused (it would sit in the process list), `name=-` takes
/// the value from stdin or `--file`, and an empty value clears the field.
fn app_fields(
    specs: &[&str],
    known: &Value,
    file: Option<&str>,
) -> Result<(Value, Vec<String>), Error> {
    let secret_fields: Vec<&str> = known["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["secret"].as_bool() == Some(true))
        .map(|f| s(&f["name"]))
        .collect();
    let mut fields = Map::new();
    let mut from_input = 0;
    for spec in specs {
        let (name, v) = field_spec(spec)?;
        if v != "-" && !v.is_empty() && secret_fields.contains(&name) {
            return Err(Error::Usage(format!(
                "field {name} is secret: give it as {name}=- and pipe the value in (stdin or --file), never on the command line"
            )));
        }
        fields.insert(name.to_owned(), json!(v));
        from_input += usize::from(v == "-");
    }
    if from_input > 1 {
        return Err(Error::Usage(
            "only one field can be read from stdin or --file".into(),
        ));
    }
    let mut piped = Vec::new();
    for (_, v) in fields.iter_mut() {
        match v.as_str() {
            Some("-") => {
                let value = secret("value", ("", None), ("--file", file), None)?;
                piped.push(value.as_str().to_owned());
                *v = json!(value.as_str());
            }
            Some("") => *v = Value::Null,
            _ => {}
        }
    }
    Ok((Value::Object(fields), piped))
}

/// `grants | grant | revoke | default | app`.
pub async fn access(
    c: &mut Client,
    words: &[&str],
    o: &Opts<'_>,
    json: bool,
    out: &mut impl Write,
) -> Result<(), Error> {
    match words {
        ["grants", id] => {
            let id = conn_id(id)?;
            let path = format!("/api/v1/connections/{id}/grants");
            let v = send(c, "GET", &path, "", None, &format!("grants of connection {id}"), &[]).await?;
            if json {
                return print(out, v);
            }
            v.as_array().into_iter().flatten().try_for_each(|g| print(out, grant_row(g)))
        }
        ["grant", id, gk, who] => {
            let id = conn_id(id)?;
            let (gk, who) = grantee(gk, who)?;
            let caps = names(o.caps.ok_or_else(|| Error::Usage("grant needs --caps a,b".into()))?)?;
            if caps.is_empty() {
                return Err(Error::Usage("--caps names at least one capability".into()));
            }
            let mut limits: Map<String, Value> = Map::new();
            for spec in &o.limits {
                let (key, vals) = limit(spec)?;
                let slot = limits.entry(key).or_insert_with(|| json!([]));
                slot.as_array_mut().expect("array").extend(vals.into_iter().map(Value::from));
            }
            let mut body = json!({"grantee_kind": gk, "grantee": who, "capabilities": caps});
            if !limits.is_empty() {
                body["limits"] = Value::Object(limits);
            }
            let path = format!("/api/v1/connections/{id}/grants");
            let what = format!("granting {gk} {who} connection {id}");
            let v = send(c, "PUT", &path, "", Some(&body), &what, &[]).await?;
            match json {
                true => print(out, v),
                false => print(out, grant_row(&v)),
            }
        }
        ["revoke", id, gk, who] => {
            let id = conn_id(id)?;
            let (gk, who) = grantee(gk, who)?;
            let path = format!("/api/v1/connections/{id}/grants/{gk}/{who}");
            let what = format!("revoking {gk} {who} from connection {id}");
            let v = send(c, "DELETE", &path, "", None, &what, &[]).await?;
            match json {
                true => print(out, v),
                false => print(out, format_args!("revoked {gk} {who} from connection {id}")),
            }
        }
        ["default", rest @ ..] if rest.len() <= 1 && !o.clear => {
            let only = rest.first().map(|k| kind(k)).transpose()?;
            let v = send(c, "GET", "/api/v1/connection-defaults", "", None, "listing the defaults", &[]).await?;
            let all: Vec<&Value> = v
                .as_array()
                .into_iter()
                .flatten()
                .filter(|d| only.is_none_or(|k| s(&d["kind"]) == k))
                .collect();
            if json {
                return print(out, Value::from_iter(all.into_iter().cloned()));
            }
            if all.is_empty()
                && let Some(k) = only
            {
                return print(out, format_args!("{k}\t-"));
            }
            all.into_iter()
                .try_for_each(|d| print(out, format_args!("{}\tconnection {}", s(&d["kind"]), d["connection"])))
        }
        ["default", k] if o.clear => {
            let k = kind(k)?;
            let path = format!("/api/v1/connection-defaults/{k}");
            let v = send(c, "DELETE", &path, "", None, &format!("clearing the default {k} connection"), &[]).await?;
            match json {
                true => print(out, v),
                false => print(out, format_args!("cleared the default {k} connection")),
            }
        }
        ["default", k, id] if !o.clear => {
            let (k, id) = (kind(k)?, conn_id(id)?);
            let path = format!("/api/v1/connection-defaults/{k}");
            let body = json!({"connection": id});
            let what = format!("making connection {id} the default {k}");
            let v = send(c, "PUT", &path, "", Some(&body), &what, &[]).await?;
            match json {
                true => print(out, v),
                false => print(out, format_args!("connection {id} is the default {k}")),
            }
        }
        ["app", k] => {
            let k = kind(k)?;
            let path = format!("/api/v1/connection-apps/{k}");
            let v = send(c, "GET", &path, "", None, &format!("the {k} sign-in app"), &[]).await?;
            match json {
                true => print(out, v),
                false => app_lines(&v).into_iter().try_for_each(|l| print(out, l)),
            }
        }
        ["app", k, "set"] => {
            let k = kind(k)?;
            if o.fields.is_empty() {
                return Err(Error::Usage("app <kind> set needs --field name=value (name=- reads the value from stdin or --file)".into()));
            }
            o.fields.iter().try_for_each(|f| field_spec(f).map(drop))?;
            let path = format!("/api/v1/connection-apps/{k}");
            let what = format!("setting the {k} sign-in app");
            let known = send(c, "GET", &path, "", None, &what, &[]).await?;
            let (fields, piped) = app_fields(&o.fields, &known, o.file)?;
            let hide: Vec<&str> = piped.iter().map(String::as_str).collect();
            let body = json!({"fields": fields});
            let v = send(c, "PUT", &path, "", Some(&body), &what, &hide).await?;
            match json {
                true => print(out, v),
                false => app_lines(&v).into_iter().try_for_each(|l| print(out, l)),
            }
        }
        _ => Err(Error::Usage(
            "grants <id> | grant <id> <user|role|agent> <who> --caps a,b [--limit key=v1,v2] | revoke <id> <grantee-kind> <who> | default [kind] | default <kind> <id> | default <kind> --clear | app <kind> | app <kind> set --field name=value".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_field_never_comes_from_the_command_line() {
        let known = json!({"fields": [{"name": "client_id", "secret": false}, {"name": "client_secret", "secret": true}]});
        let ok = app_fields(&["client_id=abc", "other="], &known, None)
            .unwrap()
            .0;
        assert_eq!(ok, json!({"client_id": "abc", "other": null}));
        let e = app_fields(&["client_secret=hunter2"], &known, None).unwrap_err();
        assert!(matches!(e, Error::Usage(_)) && !e.to_string().contains("hunter2"));
        assert!(app_fields(&["a=-", "b=-"], &known, None).is_err());
        assert!(app_fields(&["Bad=1"], &known, None).is_err());
    }

    #[test]
    fn a_grant_reads_as_one_row() {
        let g = json!({"grantee_kind": "agent", "grantee": "bot", "capabilities": ["read_repo", "issues_write"],
            "limits": {"repos": ["a/b", "c/d"]}});
        assert_eq!(
            grant_row(&g),
            "agent\tbot\tread_repo,issues_write\trepos=a/b,c/d"
        );
    }
}
