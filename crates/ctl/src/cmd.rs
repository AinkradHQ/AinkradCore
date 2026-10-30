//! The command line: global flags, the commands, and what each prints. `run` is the whole
//! program but for the exit code (`main`).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};

use crate::client::Client;
use crate::devices::s;
use crate::keystore::{self, Keystore};
use crate::net::{Endpoint, Net};
use crate::pair::{Credential, Pairing};
use crate::stepup::{self, Passphrase};
use crate::{EXIT_CODES, Error, agents, devices, events, pair, runners, secrets, terminals};

pub const USAGE: &str =
    "usage: ainkradctl [--socket <path> | --url <http(s)://host:port>] [--host <name>]
                  [--keystore <file>] [--ca <roots.pem>] [--json]
                  [--stepup-passphrase-file <file>] <command>

  pair <code | ainkrad-pair:v1?...> [--core-fp <fp>] [--wait <secs>] [--no-stepup]
      Pair this machine as a new device: makes its two keys (routine and step-up), claims
      the pairing, prints the device id and the check code (SAS) to compare on the
      approving device, and waits for the approval. It asks for a passphrase (twice) that
      seals the step-up key; --no-stepup enrols none, and the device can then never
      elevate. The first device claims the code `ainkrad-core-server bootstrap` prints,
      over the server's Unix socket (--core-fp: the fingerprint it printed). A QR payload
      names its Core; a typed code needs --socket or --url.
  health
      The Core's identity (against the pinned one), versions, and this device's session.
  elevate
      Step up (asks for the step-up passphrase): elevates this device's session for the
      Core's window (default 5 minutes) and prints elevated_until. Sessions this device
      opens in that window carry the elevation over. Commands that need it (marked *)
      elevate by themselves once when the Core asks, then retry once.
  device ls | show <id>
  device revoke <id>*  |  rename <id> <name>*  |  scopes <id> <scope>...*
      Revoking or demoting the last admin device that can elevate is refused (409).
  device add <name>* [--kind device|runner] [--scopes read,approve,...]
      Start pairing another device: prints the one-time code and QR payload (5 minutes).
  device pairing <pairing-id>
  device approve <pairing-id> <SAS>* [--scopes ...]
      Approve with the SAS the NEW device shows (typed from its screen, never copied from
      this one: the Core checks it matches the one it computed).
  device reject <pairing-id>*
  lockouts ls | clear <key>*
      The auth lockouts (ip:..., ipdev:..., stepup:<device>) and clearing one.
  runner ls | show <id>
      The paired runners: id, name, online|degraded|offline, load/capacity, the commands
      it advertised, its version and last_seen (scope read).
  run noop <runner-id>
      Sends the runner the no-op command through the Core and prints `ok <ms> ms`
      (scope agent; no step-up; audited as runner.command).
  secret ls
  secret set <name>* [--runners <runner-id>,...] [--delivery env|file|askpass]
  secret rotate <name>* [--runners ...] [--delivery ...]  |  secret rm <name>*
      The Core's secrets (scope admin): set and rotate read the value from stdin (never
      the command line); there is no get, a value never comes back to a client. A secret
      is leased only to the runners listed (default none).
  agent ls  |  show <id>  |  tail <id> [--after <seq>] [--no-follow]
  agent run <runner-id> <harness> [prompt...]* [--secrets <name>:<VAR>,...]
  agent send <id> <message...>*  |  approve <id> <request>  |  deny <id> <request> [reason...]
  agent cancel <id>*  |  agent kill <id>*
      Agent sessions on runners (scope agent): run starts one (the runner must offer
      agents: ainkrad-runner connect --enable-agents); --secrets leases each named secret
      to that runner for the session, delivered under VAR; show prints its transcript.
  events tail [--after <seq>] [--no-follow]
      Events after <seq> (default: from now), one JSON object per line (every kind this
      device may see, runner.connected/.disconnected/.degraded included); follows the live
      stream and resumes after drops and Core restarts, without gaps or repeats.

The keystore (default $AINKRADCTL_KEYSTORE, else ~/.config/ainkradctl/keystore.json) holds
this device's routine key (mode 0600) and the Core fingerprint pinned at pairing; the
step-up key is beside it (<keystore>.stepup.json, 0600), sealed with its passphrase
(PBKDF2-HMAC-SHA256, 600k rounds, AES-256-GCM). The passphrase comes from
--stepup-passphrase-file, else $AINKRAD_STEPUP_PASSPHRASE_FILE, else the terminal. Nothing is
signed or sent before the Core signs a fresh nonce with that key (POST /handshake). The Host header is
`localhost` on a socket and the URL's host:port otherwise (--host overrides; a TCP Core's
admin socket answers to the Core's own host name).
";

const VALUED: [&str; 18] = [
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
    "--stepup-passphrase-file",
    "--runners",
    "--delivery",
    "--secrets",
    "--rows",
    "--cols",
    "--cwd",
    "--signal",
];
const SWITCHES: [&str; 4] = ["--json", "--no-follow", "--help", "--no-stepup"];

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
        let mut c = Client::new(net, store);
        c.stepup_file = Some(stepup::path_for(&self.keystore()?));
        c.passphrase = self.passphrase();
        Ok(c)
    }

    fn passphrase(&self) -> Passphrase {
        Passphrase::new(self.value("--stepup-passphrase-file"))
    }
}

fn line(out: &mut impl Write, text: impl std::fmt::Display) -> Result<(), Error> {
    writeln!(out, "{text}").map_err(|e| Error::Unreachable(format!("stdout: {e}")))
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
                stepup: (!a.on("--no-stepup")).then(|| a.passphrase()),
            };
            pair::pair(Credential::parse(credential)?, p, out).await
        }
        ["health"] => health(&mut a.client()?, json, out).await,
        ["elevate"] => {
            let mut c = a.client()?;
            let until = c.elevate().await?;
            let v = json!({"elevated_until": until});
            match json {
                true => line(out, v),
                false => line(out, format_args!("elevated_until {until}")),
            }
        }
        ["device", rest @ ..] => {
            let mut c = a.client()?;
            devices::device(&mut c, rest, a.value("--kind"), a.scopes(), json, out).await
        }
        ["lockouts", rest @ ..] => devices::lockouts(&mut a.client()?, rest, json, out).await,
        ["runner", rest @ ..] => runners::runner(&mut a.client()?, rest, json, out).await,
        ["run", rest @ ..] => runners::run(&mut a.client()?, rest, json, out).await,
        ["secret", rest @ ..] => {
            let runners = a.value("--runners").map(|r| {
                r.split(',')
                    .map(str::trim)
                    .filter(|r| !r.is_empty())
                    .map(str::to_owned)
                    .collect()
            });
            let delivery = a.value("--delivery");
            secrets::secret(&mut a.client()?, rest, runners, delivery, json, out).await
        }
        ["agent", rest @ ..] => {
            let secrets = a.value("--secrets");
            agents::agent(
                &mut a.client()?,
                rest,
                secrets,
                a.number("--after")?,
                !a.on("--no-follow"),
                json,
                out,
            )
            .await
        }
        ["term", rest @ ..] | ["terminal", rest @ ..] => {
            let options = terminals::Options {
                rows: a.number("--rows")?,
                cols: a.number("--cols")?,
                cwd: a.value("--cwd"),
                signal: a.value("--signal"),
            };
            terminals::terminal(&mut a.client()?, rest, &options, json, out).await
        }
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
        "elevated_until": session.elevated_until,
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
    line(out, format_args!("scopes {}", session.scopes.join(",")))?;
    match session.elevated_until {
        Some(t) => line(out, format_args!("elevated_until {t}")),
        None => line(out, "elevated_until -"),
    }
}
