use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::ids::UserId;
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::scheduler::{Clock, Scheduler, SystemClock};
use ainkrad_core_server::store::{self, gov};
use ainkrad_core_server::{gateway, push};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};

mod admin;

fn usage() -> String {
    format!(
        "{USAGE}\nSettings (E15.17, as the admin):\n{}\n{}\n{}",
        admin::USAGE,
        ainkrad_core_server::ops::USAGE,
        admin::bootstrap::USAGE
    )
}

const USAGE: &str = "usage:
  ainkrad-core-server serve <db> [--listen unix:<path>|loopback:<port>|public]
                 [--bind <addr:port>] [--host <name>]
                 [--hostname <dns-name> --acme-contact <email>
                 [--acme-directory <url>] [--acme-http01]]
                 [--trusted-proxy <addr|cidr>[,…]]
                 [--passkeys] [--allow-origin <origin>[,…]]
                 [--iroh [--iroh-relay <https-url>[,…]] [--iroh-bind <addr:port>[,…]]]
                 [--apns-key <file.p8> --apns-key-id <id> --apns-team-id <id>
                 --apns-topic <bundle-id>] [--log-format text|json]
  ainkrad-core-server iroh-id <db>
  ainkrad-core-server openapi
  ainkrad-core-server backup <db> <dest>
  ainkrad-core-server restore [--force] <src> <db>
  ainkrad-core-server --help
  ainkrad-core-server device list <db>
  ainkrad-core-server device revoke <db> <device-id>

serve listens on a Unix socket next to the database (<db dir>/core.sock, 0600) by default and
serves the app at /api/v1 (signed requests from a paired device) and the modules mounted
inside it. --listen loopback:<port> serves 127.0.0.1, --bind any address (plain HTTP, as before). --listen public
serves TLS 1.3 on :443 with a certificate from ACME (Let's Encrypt production unless
--acme-directory says otherwise, kept in <db dir>/tls) and needs --hostname and --acme-contact;
the challenge is TLS-ALPN-01 on :443, or HTTP-01 on :80 with --acme-http01. Unsigned, only
/handshake, pairing and /healthz answer. The Core identity key is <db dir>/core-identity.p8
(0600), made on first start; its fingerprint is what /handshake shows and every request signs.
--host is the Host header clients must send (default: localhost on a socket, the address on loopback, the hostname in public); --trusted-proxy the
proxies whose X-Forwarded-For names the client for the lockouts and logs (default: none; the
Core terminates TLS itself). --passkeys turns on passkeys for the web client (E1-08): the
relying party is the --host name (a DNS name, never an IP; localhost only on loopback), paired
from an elevated admin device only. A browser Origin is refused unless it is the Core's own
(https://<host>, http://localhost:<port> on loopback) or one --allow-origin names. SIGTERM or Ctrl-C shuts serve
down: it stops accepting, gives requests in flight up to 10 s, closes event sockets so they
reconnect, and checkpoints the database. Limits and intervals are settings (`setting list`),
read when serve starts. With the four --apns-* flags, what a module's push rules pick is pushed
to the app's devices through APNs; without them it is only logged. The platform alone pushes
nothing. --log-format json writes JSON lines; both formats are redacted (E1-13.4).
--iroh (E2-19; off unless given) also serves the same API over iroh, for a Core behind NAT: QUIC with
hole punching, through the relays named by --iroh-relay (your own `iroh-relay`; none means direct
connections only, and no third-party relay is ever used), on the UDP addresses of --iroh-bind. iroh
is transport only: a peer authenticates with the same signed device handshake as on any listener.
The transport key is <db dir>/iroh.key (0600); iroh-id prints the endpoint id clients pin.
openapi prints the client API's contract (api/openapi.json; `make contract`).
device list shows every device (id, kind, name, status, fingerprint); device revoke stops one at
once (its open sockets close within 2 s); the row stays listed. A device enrolls only by
pairing (bootstrap for the first): there are no keys to hand out.
backup <db> <dest> is a raw, unencrypted local snapshot (VACUUM INTO); restore [--force] <src>
<db> swaps such a snapshot over a stopped database in place. The encrypted, signed backups and
the fresh-home restore are under Operations.";

/// Devices are revoked as the one admin user (#18).
pub(crate) const ADMIN: AuditActor = AuditActor::User(UserId(1));

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let seeded = match args.first() {
        Some(&"setting" | &"audit") => admin::run(&args).await,
        Some(&("init" | "backup" | "backup-keygen" | "restore" | "export" | "import")) => {
            ainkrad_core_server::ops::run(&args).await
        }
        _ => None,
    };
    let result = match args.as_slice() {
        _ if seeded.is_some() => seeded.expect("checked"),
        [] => {
            println!("ainkrad-core-server {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        ["--help" | "-h" | "help"] => {
            println!("{}", usage());
            return ExitCode::SUCCESS;
        }
        ["serve", "--config", file, given @ ..] => {
            match ainkrad_core_server::ops::config::Config::load(Path::new(file)) {
                Ok(config) => {
                    let flags = config.serve_flags(given);
                    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
                    match serve_flags(&flags) {
                        Some(flags) => serve(&config.home().db(), flags).await,
                        None => {
                            eprintln!("{}", usage());
                            return ExitCode::from(2);
                        }
                    }
                }
                Err(e) => Err(e.into()),
            }
        }
        ["serve", db, flags @ ..] => match serve_flags(flags) {
            Some(flags) => serve(Path::new(db), flags).await,
            None => {
                eprintln!("{}", usage());
                return ExitCode::from(2);
            }
        },
        ["backup", db, dest] => backup(Path::new(db), Path::new(dest))
            .await
            .map_err(Into::into),
        ["restore", src, db] => store::restore(Path::new(src), Path::new(db), false)
            .await
            .map_err(Into::into),
        ["restore", "--force", src, db] => store::restore(Path::new(src), Path::new(db), true)
            .await
            .map_err(Into::into),
        ["iroh-id", db] => iroh_id(Path::new(db)),
        ["openapi"] => {
            print!("{}", ainkrad_core_server::api::v1::spec::json());
            return ExitCode::SUCCESS;
        }
        ["device", "list", db] => list_devices(Path::new(db)).await,
        ["bootstrap", db] => admin::bootstrap::bootstrap(Path::new(db), "first device").await,
        ["bootstrap", db, name] => admin::bootstrap::bootstrap(Path::new(db), name).await,
        ["recover", db, rest @ ..] => {
            let flag = |f: &str| rest.contains(&f);
            let names: Vec<&&str> = rest.iter().filter(|a| !a.starts_with("--")).collect();
            let known = rest.iter().all(|a| {
                !a.starts_with("--") || ["--keep-devices", "--revoke-runners"].contains(a)
            });
            match (known, names.as_slice()) {
                (true, [] | [_]) => {
                    let name = names.first().map_or("recovered admin", |n| **n);
                    let (keep, runners) = (flag("--keep-devices"), flag("--revoke-runners"));
                    admin::bootstrap::recover(Path::new(db), name, keep, runners).await
                }
                _ => {
                    eprintln!("{}", usage());
                    return ExitCode::from(2);
                }
            }
        }
        ["device", "revoke", db, id] => revoke_device(Path::new(db), id).await,
        _ => {
            eprintln!("{}", usage());
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ainkrad-core-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn comma_list(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

type Result_ = Result<(), Box<dyn std::error::Error>>;

/// One line per device: id, kind, name, status, fingerprint, created, last used, revoked.
async fn list_devices(db: &Path) -> Result_ {
    let pool = store::connect(db).await?;
    for d in gov::list_devices(&pool).await? {
        println!(
            "{}\t{}\t{}\t{}\t{}\tcreated {}\tlast used {}{}",
            d.id,
            d.kind,
            d.name,
            d.status,
            d.fingerprint,
            d.created_at,
            d.last_used_at.as_deref().unwrap_or("never"),
            d.revoked_at
                .map(|at| format!("\trevoked {at}"))
                .unwrap_or_default(),
        );
    }
    Ok(())
}

async fn revoke_device(db: &Path, id: &str) -> Result_ {
    let pool = store::connect(db).await?;
    let now = SystemClock.now();
    if gov::revoke_device(&pool, id, ADMIN, None, &now).await? {
        eprintln!("device {id} revoked; it no longer authenticates");
        Ok(())
    } else {
        Err(format!("no live device {id}").into())
    }
}

/// Snapshots an existing database without creating or migrating it.
async fn backup(db: &Path, dest: &Path) -> Result<(), store::BackupError> {
    let options = SqliteConnectOptions::new()
        .filename(db)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePool::connect_with(options).await?;
    store::backup(&pool, dest).await
}

/// `serve`'s flags.
struct Serve {
    /// `--listen` or `--bind`; `None` is the default socket next to the database.
    listen: Option<String>,
    host: Option<String>,
    hostname: Option<String>,
    acme_contact: Option<String>,
    acme_directory: String,
    acme_http01: bool,
    /// `--apns-key`, `--apns-key-id`, `--apns-team-id`, `--apns-topic`, all or none.
    apns: Option<[String; 4]>,
    trusted_proxies: Option<Vec<ainkrad_core_server::api::limit::Cidr>>,
    log_json: bool,
    /// `--passkeys`.
    passkeys: bool,
    /// `--allow-origin`: browser origins let through beside the Core's own.
    origins: Vec<String>,
    /// `--iroh`: the opt-in iroh listener (E2-19). Off by default.
    iroh: bool,
    iroh_relays: Vec<String>,
    iroh_bind: Vec<std::net::SocketAddr>,
}

/// `serve`'s flags; `None` (after saying why) on anything else.
fn serve_flags(flags: &[&str]) -> Option<Serve> {
    let mut s = Serve {
        listen: None,
        host: None,
        hostname: None,
        acme_contact: None,
        acme_directory: gateway::acme::LETS_ENCRYPT.to_owned(),
        acme_http01: false,
        apns: None,
        trusted_proxies: None,
        log_json: false,
        passkeys: false,
        origins: Vec::new(),
        iroh: false,
        iroh_relays: Vec::new(),
        iroh_bind: Vec::new(),
    };
    let mut apns: [Option<String>; 4] = Default::default();
    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        if *flag == "--acme-http01" {
            s.acme_http01 = true;
            continue;
        }
        if *flag == "--passkeys" {
            s.passkeys = true;
            continue;
        }
        if *flag == "--iroh" {
            s.iroh = true;
            continue;
        }
        let value = (*it.next()?).to_owned();
        match *flag {
            "--bind" | "--listen" if s.listen.is_some() => {
                eprintln!("ainkrad-core-server: one of --bind and --listen");
                return None;
            }
            "--bind" => s.listen = Some(format!("tcp:{value}")),
            "--listen" => s.listen = Some(value),
            "--host" => s.host = Some(value),
            "--log-format" => match value.as_str() {
                "text" | "json" => s.log_json = value == "json",
                _ => return None,
            },
            "--hostname" => s.hostname = Some(value),
            "--allow-origin" => {
                for o in comma_list(&value) {
                    let localhost = o == "http://localhost"
                        || o.strip_prefix("http://localhost:").is_some_and(|p| {
                            !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
                        });
                    let https = o
                        .strip_prefix("https://")
                        .is_some_and(|h| !h.is_empty() && !h.contains(['/', '?', '#', '@']));
                    let ok = https || localhost;
                    if !ok {
                        eprintln!("ainkrad-core-server: --allow-origin {o}: an https:// origin");
                        return None;
                    }
                    s.origins.push(o.to_ascii_lowercase());
                }
            }
            "--iroh-relay" => s.iroh_relays.extend(comma_list(&value)),
            "--iroh-bind" => {
                for a in comma_list(&value) {
                    match a.parse() {
                        Ok(addr) => s.iroh_bind.push(addr),
                        Err(_) => {
                            eprintln!(
                                "ainkrad-core-server: --iroh-bind {a}: an address like 0.0.0.0:7000"
                            );
                            return None;
                        }
                    }
                }
            }
            "--acme-contact" => s.acme_contact = Some(value),
            "--acme-directory" => s.acme_directory = value,
            "--trusted-proxy" => {
                let parsed: Result<Vec<_>, _> =
                    comma_list(&value).iter().map(|c| c.parse()).collect();
                match parsed {
                    Ok(list) => s.trusted_proxies = Some(list),
                    Err(why) => {
                        eprintln!("ainkrad-core-server: --trusted-proxy: {why}");
                        return None;
                    }
                }
            }
            "--apns-key" => apns[0] = Some(value),
            "--apns-key-id" => apns[1] = Some(value),
            "--apns-team-id" => apns[2] = Some(value),
            "--apns-topic" => apns[3] = Some(value),
            _ => return None,
        }
    }
    if !s.iroh && (!s.iroh_relays.is_empty() || !s.iroh_bind.is_empty()) {
        eprintln!("ainkrad-core-server: --iroh-relay and --iroh-bind only go with --iroh");
        return None;
    }
    s.apns = match apns {
        [Some(a), Some(b), Some(c), Some(d)] => Some([a, b, c, d]),
        [None, None, None, None] => None,
        _ => return None,
    };
    Some(s)
}

/// The directory the database is in: where the socket, the TLS state and the identity key go.
fn state_dir(db: &Path) -> &Path {
    db.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Where to listen, from the flags: `unix:<path>`, `loopback:<port>`, `public[:<port>]`
/// (443), or `--bind`'s address; a socket next to the database by default. Public needs a
/// hostname and an ACME contact.
fn listen(db: &Path, flags: &Serve) -> Result<gateway::Listen, String> {
    let state = state_dir(db);
    let spec = flags.listen.as_deref().unwrap_or("unix:");
    let port = |p: &str| p.parse::<u16>().map_err(|_| format!("{p:?} is not a port"));
    let public = matches!(spec.split(':').next(), Some("public"));
    if !public && (flags.hostname.is_some() || flags.acme_contact.is_some() || flags.acme_http01) {
        return Err("--hostname, --acme-* only go with --listen public".into());
    }
    Ok(match spec.split_once(':').unwrap_or((spec, "")) {
        ("unix", "") => gateway::Listen::Unix(state.join("core.sock")),
        ("unix", path) => gateway::Listen::Unix(path.into()),
        ("loopback", p) => gateway::Listen::Tcp(format!("127.0.0.1:{}", port(p)?)),
        ("tcp", addr) => gateway::Listen::Tcp(addr.to_owned()),
        ("public", p) => {
            let (Some(hostname), Some(contact)) = (&flags.hostname, &flags.acme_contact) else {
                return Err("--listen public needs --hostname and --acme-contact".into());
            };
            if hostname.is_empty() || !contact.contains('@') {
                return Err("--hostname must be a name and --acme-contact an email".into());
            }
            gateway::Listen::Public {
                port: if p.is_empty() { 443 } else { port(p)? },
                http01: flags.acme_http01.then_some(80),
                acme: gateway::acme::Acme {
                    hostname: hostname.clone(),
                    contact: contact.clone(),
                    directory: flags.acme_directory.clone(),
                    http01: flags.acme_http01,
                    ca_root: None,
                    dir: state.join("tls"),
                },
            }
        }
        _ => {
            return Err(format!(
                "--listen {spec}: unix:<path>, loopback:<port> or public"
            ));
        }
    })
}

/// Turns the iroh listener on (`--iroh`) and logs the endpoint id clients pin.
#[cfg(feature = "iroh")]
async fn with_iroh(
    gateway: gateway::Gateway,
    db: &Path,
    flags: &Serve,
) -> Result<gateway::Gateway, Box<dyn std::error::Error>> {
    let config = gateway::p2p::Config {
        key_path: state_dir(db).join("iroh.key"),
        relays: flags.iroh_relays.clone(),
        bind: flags.iroh_bind.clone(),
    };
    let gateway = gateway.with_iroh(config).await?;
    if let Some(e) = gateway.iroh_endpoint() {
        tracing::info!(endpoint_id = %e.id(), relays = flags.iroh_relays.len(), "iroh listener on");
    }
    Ok(gateway)
}

#[cfg(not(feature = "iroh"))]
async fn with_iroh(
    _: gateway::Gateway,
    _: &Path,
    _: &Serve,
) -> Result<gateway::Gateway, Box<dyn std::error::Error>> {
    Err("this build has no iroh support (built without the `iroh` feature)".into())
}

/// Prints the endpoint id of the iroh key next to `db`, making the key if there is none.
#[cfg(feature = "iroh")]
fn iroh_id(db: &Path) -> Result_ {
    println!(
        "{}",
        gateway::p2p::endpoint_id(&state_dir(db).join("iroh.key"))?
    );
    Ok(())
}

#[cfg(not(feature = "iroh"))]
fn iroh_id(_: &Path) -> Result_ {
    Err("this build has no iroh support (built without the `iroh` feature)".into())
}

/// SIGTERM (systemd's stop) or Ctrl-C.
async fn stop_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        },
        Err(_) => drop(tokio::signal::ctrl_c().await),
    }
}

/// The listener for the log, without the ACME account's contact.
struct ListenLog<'a>(&'a gateway::Listen);

impl std::fmt::Debug for ListenLog<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            gateway::Listen::Unix(path) => write!(f, "unix:{}", path.display()),
            gateway::Listen::Tcp(addr) => write!(f, "tcp:{addr}"),
            gateway::Listen::Public { port, http01, acme } => write!(
                f,
                "public:{port} {} via {}{}",
                acme.hostname,
                acme.directory,
                if http01.is_some() {
                    " (HTTP-01 on :80)"
                } else {
                    ""
                }
            ),
        }
    }
}

/// Serves the client API and runs the scheduler and the pusher until SIGTERM or Ctrl-C, then
/// shuts down cleanly (`USAGE`).
async fn serve(db: &Path, flags: Serve) -> Result<(), Box<dyn std::error::Error>> {
    ainkrad_core_server::ops::logging::init(flags.log_json);
    // Flags first: a refused --listen never creates or migrates the database.
    let listen = listen(db, &flags)?;
    let pool = store::connect(db).await?;
    // Read once: a change to these takes effect at the next start (E15.17).
    let [tick, push_every] = ainkrad_core_server::scheduler::loop_intervals(&pool).await?;
    let limits = Arc::new(ainkrad_core_server::api::v1::Limits::from_settings(&pool).await?);
    let notifier: Arc<dyn push::Notifier> = match &flags.apns {
        Some([key, key_id, team, topic]) => {
            let pem = std::fs::read_to_string(key)
                .map_err(|e| format!("reading the APNs key {key}: {e}"))?;
            Arc::new(push::apns::ApnsNotifier::new(&pem, key_id, team, topic)?)
        }
        None => Arc::new(push::LogNotifier),
    };
    let pusher = push::Pusher {
        pool: pool.clone(),
        notifier,
        classifier: Arc::new(push::Silent),
        every: push_every,
    };
    let host = flags.host.clone().unwrap_or_else(|| listen.default_host());
    let mut gateway = gateway::Gateway::bind(listen.clone(), gateway::Limits::default()).await?;
    // On TCP the host still gets a Unix socket, for `bootstrap`'s first device (§7.3).
    if !matches!(listen, gateway::Listen::Unix(_)) {
        gateway = gateway.with_admin_socket(&state_dir(db).join("admin.sock"))?;
    }
    if flags.iroh {
        gateway = with_iroh(gateway, db, &flags).await?;
    }
    tracing::info!(listen = ?ListenLog(&listen), %host, "serving");
    let scheduler = Scheduler {
        pool: pool.clone(),
        clock: SystemClock,
        every: tick,
    };
    // Dropping `stop` ends both loops.
    let (stop, mut stopped) = tokio::sync::watch::channel(());
    let mut stopped_push = stopped.clone();
    let pushing = tokio::spawn(async move {
        pusher
            .run(async { drop(stopped_push.changed().await) })
            .await
    });
    let ticking =
        tokio::spawn(async move { scheduler.run(async { drop(stopped.changed().await) }).await });
    let identity = Arc::new(ainkrad_core_server::auth::Identity::load_or_create(
        state_dir(db),
    )?);
    tracing::info!(core_fp = identity.fp, "Core identity");
    let mut app = App::new(pool, Arc::new(SystemClock), host, identity);
    app.limits = limits;
    if let Some(list) = flags.trusted_proxies {
        app.trusted_proxies = list.into();
    }
    if !flags.origins.is_empty() {
        app.origins = app.origins.iter().cloned().chain(flags.origins).collect();
    }
    if flags.passkeys {
        let loopback = match &listen {
            gateway::Listen::Unix(_) => true,
            gateway::Listen::Tcp(addr) => addr
                .parse::<std::net::SocketAddr>()
                .is_ok_and(|a| a.ip().is_loopback()),
            gateway::Listen::Public { .. } => false,
        };
        let passkeys = ainkrad_core_server::auth::web::Passkeys::new(&app.host, loopback)?;
        tracing::info!(
            rp_id = passkeys.rp_id,
            origin = passkeys.origin,
            "passkeys on"
        );
        app.passkeys = Some(Arc::new(passkeys));
    }
    let (closing, pool) = (Arc::clone(&app.closing), app.pool.clone());
    let server = gateway.serve(router(app), Arc::clone(&closing), gateway::SHUTDOWN_GRACE);
    tokio::pin!(server);
    tokio::select! {
        served = &mut server => served?,
        () = stop_signal() => {
            tracing::info!("stopping: finishing requests in flight, closing sockets");
            // Stops accepting; event sockets close themselves (`App::closing`); requests in
            // flight get the grace.
            closing.send_replace(true);
            server.await?;
        }
    }
    drop(stop);
    ticking.await?;
    pushing.await?;
    // Folds the WAL back into the database file, so a stopped server leaves one file.
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await?;
    pool.close().await;
    tracing::info!("stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::serve_flags;

    #[test]
    fn iroh_is_off_unless_asked_for() {
        let s = serve_flags(&[]).unwrap();
        assert!(!s.iroh && s.iroh_relays.is_empty() && s.iroh_bind.is_empty());
        assert!(serve_flags(&["--iroh"]).unwrap().iroh);
        // Its options mean nothing without it.
        assert!(serve_flags(&["--iroh-relay", "https://relay.example.test"]).is_none());
        assert!(serve_flags(&["--iroh-bind", "0.0.0.0:7000"]).is_none());
        let s = serve_flags(&["--iroh", "--iroh-relay", "https://relay.example.test"]).unwrap();
        assert_eq!(s.iroh_relays, ["https://relay.example.test"]);
    }
}
