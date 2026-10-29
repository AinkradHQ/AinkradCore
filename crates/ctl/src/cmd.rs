//! The command line: global flags, the commands, and what each prints. `run` is the whole
//! program but for the exit code (`main`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::client::{Client, parse};
use crate::keystore::{self, Keystore};
use crate::net::{Endpoint, Net};
use crate::pair::{Credential, Pairing};
use crate::{EXIT_CODES, Error, events, pair};

pub const USAGE: &str =
    "usage: ainkradctl [--socket <path> | --url <http(s)://host:port>] [--host <name>]
                  [--keystore <file>] [--ca <roots.pem>] [--json] <command>

  pair <code | ainkrad-pair:v1?...> [--core-fp <fp>] [--wait <secs>]
      Pair this machine as a new device: makes its key, claims the pairing, prints the
      device id and the check code (SAS) to compare on the approving device, and waits for
      the approval. The first device claims the code `ainkrad-core-server bootstrap` prints,
      over the server's Unix socket (--core-fp: the fingerprint it printed). A QR payload
      names its Core; a typed code needs --socket or --url.
  health
      The Core's identity (against the pinned one), versions, and this device's session.
  device ls | show <id> | revoke <id>
  device add <name> [--kind device|runner] [--scopes read,approve,...]
      Start pairing another device: prints the one-time code and QR payload (5 minutes).
  device pairing <pairing-id>
  device approve <pairing-id> <SAS> [--scopes ...]
      Approve with the SAS the NEW device shows (typed from its screen, never copied from
      this one: the Core checks it matches the one it computed).
  device reject <pairing-id>
  events tail [--after <seq>] [--no-follow]
      Events after <seq> (default: from now), one JSON object per line; follows the live
      stream and resumes after drops and Core restarts, without gaps or repeats.

The keystore (default $AINKRADCTL_KEYSTORE, else ~/.config/ainkradctl/keystore.json) holds
this device's private key (mode 0600) and the Core fingerprint pinned at pairing. Nothing is
signed or sent before the Core's /handshake shows that fingerprint. The Host header is
`localhost` on a socket and the URL's host:port otherwise (--host overrides; a TCP Core's
admin socket answers to the Core's own host name).
";

const VALUED: [&str; 10] = [
    "--socket",
    "--url",
    "--host",
    "--keystore",
    "--ca",
    "--after",
    "--scopes",
    "--kind",
    "--core-fp",
    "--wait",
];
const SWITCHES: [&str; 3] = ["--json", "--no-follow", "--help"];

/// The arguments: flags (anywhere) and the words.
struct Args {
    flags: Vec<(String, Option<String>)>,
    words: Vec<String>,
}

impl Args {
    fn parse(args: &[String]) -> Result<Self, Error> {
        let (mut flags, mut words) = (Vec::new(), Vec::new());
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if VALUED.contains(&a.as_str()) {
                let v = it
                    .next()
                    .ok_or_else(|| Error::Usage(format!("{a} needs a value")))?;
                flags.push((a.clone(), Some(v.clone())));
            } else if SWITCHES.contains(&a.as_str()) || a == "-h" {
                flags.push((a.clone(), None));
            } else if a.starts_with("--") {
                return Err(Error::Usage(format!("unknown flag {a}")));
            } else {
                words.push(a.clone());
            }
        }
        Ok(Self { flags, words })
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .rev()
            .find(|(f, _)| f == name)
            .and_then(|(_, v)| v.as_deref())
    }

    fn on(&self, name: &str) -> bool {
        self.flags.iter().any(|(f, _)| f == name)
    }

    fn number(&self, name: &str) -> Result<Option<i64>, Error> {
        self.value(name)
            .map(|v| {
                v.parse()
                    .map_err(|_| Error::Usage(format!("{name} takes a number")))
            })
            .transpose()
    }

    fn scopes(&self) -> Option<Vec<String>> {
        self.value("--scopes").map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
    }

    fn endpoint(&self) -> Result<Option<Endpoint>, Error> {
        match (self.value("--socket"), self.value("--url")) {
            (Some(_), Some(_)) => Err(Error::Usage("one of --socket and --url".into())),
            (Some(s), None) => Ok(Some(Endpoint::Unix(s.into()))),
            (None, Some(u)) => Endpoint::parse(u).map(Some),
            (None, None) => Ok(None),
        }
    }

    fn keystore(&self) -> Result<PathBuf, Error> {
        self.value("--keystore")
            .map(PathBuf::from)
            .or_else(keystore::default_path)
            .ok_or_else(|| Error::Usage("no --keystore and no HOME".into()))
    }

    /// A client for the paired device in the keystore.
    fn client(&self) -> Result<Client, Error> {
        let store = Keystore::load(&self.keystore()?).map_err(Error::Usage)?;
        let endpoint = match self.endpoint()? {
            Some(e) => e,
            None => Endpoint::parse(&store.endpoint)?,
        };
        let host = self
            .value("--host")
            .map(str::to_owned)
            .or_else(|| store.host.clone());
        let net = Net::new(endpoint, host, self.value("--ca").map(Path::new))?;
        Ok(Client::new(net, store))
    }
}

fn line(out: &mut impl Write, text: impl std::fmt::Display) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
}

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

fn s(v: &Value) -> &str {
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
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}{revoked}",
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

/// The program: parses `args` and runs the command, printing to `out`.
pub async fn run(args: &[String], out: &mut impl Write) -> Result<(), Error> {
    let a = Args::parse(args)?;
    let json = a.on("--json");
    let words: Vec<&str> = a.words.iter().map(String::as_str).collect();
    if a.on("--help") || a.on("-h") || matches!(words.as_slice(), [] | ["help"]) {
        return line(out, format_args!("{USAGE}\n{EXIT_CODES}"));
    }
    match words.as_slice() {
        ["pair", credential] => {
            let wait = a.number("--wait")?.unwrap_or(300).max(1) as u64;
            let ks = a.keystore()?;
            let p = Pairing {
                endpoint: a.endpoint()?,
                host: a.value("--host").map(str::to_owned),
                ca: a.value("--ca").map(Path::new),
                keystore: &ks,
                core_fp: a.value("--core-fp").map(str::to_owned),
                json,
                wait: Duration::from_secs(wait),
            };
            pair::pair(Credential::parse(credential)?, p, out).await
        }
        ["health"] => health(&mut a.client()?, json, out).await,
        ["device", rest @ ..] => device(&a, rest, json, out).await,
        ["events", "tail"] => {
            let mut c = a.client()?;
            events::tail(&mut c, a.number("--after")?, !a.on("--no-follow"), out).await
        }
        _ => Err(Error::Usage(format!(
            "unknown command {:?}; see --help",
            words.join(" ")
        ))),
    }
}

async fn health(c: &mut Client, json: bool, out: &mut impl Write) -> Result<(), Error> {
    let up = c.net.send("GET", "/healthz", &[], Vec::new()).await?;
    if up.status != 200 {
        return Err(Error::Protocol(format!("/healthz answered {}", up.status)));
    }
    let h = c.check_identity().await?;
    let session = c.open_session().await?.clone();
    let me: Value = c.get("/api/v1/me", "").await?;
    let api = &me["versions"]["api"];
    let summary = json!({
        "endpoint": c.net.endpoint.to_string(),
        "core_fp": c.store.core_fp,
        "identity": "pinned",
        "server_version": h.server_version,
        "api": format!("{}.{}", s(&api["major"]), api["minor"]),
        "device_id": me["device"]["id"],
        "device_name": me["device"]["name"],
        "scopes": session.scopes,
        "session_expires": session.expires,
    });
    if json {
        return line(out, summary);
    }
    line(out, format_args!("endpoint {}", c.net.endpoint))?;
    line(
        out,
        format_args!("core_fp {} (matches the pinned one)", c.store.core_fp),
    )?;
    line(
        out,
        format_args!(
            "server {} api {}",
            h.server_version.as_deref().unwrap_or("-"),
            summary["api"].as_str().unwrap_or("-")
        ),
    )?;
    line(
        out,
        format_args!(
            "device {} {}",
            s(&me["device"]["id"]),
            s(&me["device"]["name"])
        ),
    )?;
    line(out, format_args!("scopes {}", session.scopes.join(",")))
}

async fn device(a: &Args, words: &[&str], json: bool, out: &mut impl Write) -> Result<(), Error> {
    let mut c = a.client()?;
    let print = |out: &mut dyn Write, v: &Value, rows: Vec<String>| -> Result<(), Error> {
        let text = if json { v.to_string() } else { rows.join("\n") };
        writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
    };
    match words {
        ["ls" | "list"] => {
            let v: Value = c.get("/api/v1/devices", "").await?;
            let rows = v.as_array().map(|a| a.iter().map(device_row).collect()).unwrap_or_default();
            print(out, &v, rows)
        }
        ["show", id] => {
            // The contract has no single-device route: the list, filtered.
            let id = did(id)?;
            let v: Value = c.get("/api/v1/devices", "").await?;
            let d = v
                .as_array()
                .and_then(|a| a.iter().find(|d| d["id"] == id))
                .cloned()
                .ok_or_else(|| Error::Refused {
                    status: 404,
                    code: "not_found".into(),
                    message: format!("no device {id}"),
                    server_time: None,
                    local_time: c.now(),
                })?;
            print(out, &d, vec![device_row(&d)])
        }
        ["revoke", id] => {
            let res = c.call("DELETE", &format!("/api/v1/devices/{}", did(id)?), "", None).await?;
            let d: Value = parse(&res)?;
            print(out, &d, vec![format!("revoked {}", s(&d["id"]))])
        }
        ["add", name] => {
            let kind = a.value("--kind").unwrap_or("device");
            let scopes = match (a.scopes(), kind) {
                (Some(s), _) => s,
                (None, "runner") => vec!["runner".to_owned()],
                (None, _) => return Err(Error::Usage("device add needs --scopes (e.g. read,approve)".into())),
            };
            let body = json!({"name": name, "kind": kind, "scopes": scopes});
            let res = c.call("POST", "/api/v1/pairings", "", Some(&body)).await?;
            let p: Value = parse(&res)?;
            // Showing the code and QR payload is this command's job; nothing else prints them.
            let rows = ["pairing_id", "code", "qr", "expires_at"].iter().map(|k| format!("{k} {}", s(&p[*k]))).collect();
            print(out, &p, rows)
        }
        ["pairing", id] => {
            let p: Value = c.get(&format!("/api/v1/pairings/{}", pid(id)?), "").await?;
            print(out, &p, pairing_rows(&p))
        }
        ["approve", id, sas] => {
            let sas = sas.trim().to_ascii_uppercase();
            let shaped = sas.len() == 19 && sas.split('-').all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_alphanumeric()));
            if !shaped {
                return Err(Error::Usage("the SAS is XXXX-XXXX-XXXX-XXXX, as the new device shows it".into()));
            }
            let mut body = json!({"sas": sas});
            if let Some(scopes) = a.scopes() {
                body["scopes"] = json!(scopes);
            }
            let path = format!("/api/v1/pairings/{}/approve", pid(id)?);
            let p: Value = parse(&c.call("POST", &path, "", Some(&body)).await?)?;
            print(out, &p, vec![format!("approved {}", s(&p["device_id"]))])
        }
        ["reject", id] => {
            let path = format!("/api/v1/pairings/{}/reject", pid(id)?);
            let p: Value = parse(&c.call("POST", &path, "", None).await?)?;
            print(out, &p, vec![format!("rejected {}", s(&p["pairing_id"]))])
        }
        _ => Err(Error::Usage("device ls | show <id> | revoke <id> | add <name> | pairing <id> | approve <id> <SAS> | reject <id>".into())),
    }
}
