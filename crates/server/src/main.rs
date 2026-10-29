use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::ids::{DeviceKeyId, UserId};
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::scheduler::{Clock, Scheduler, SystemClock};
use ainkrad_core_server::store::{self, gov};
use ainkrad_core_server::{gateway, push};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};

mod admin;

fn usage() -> String {
    format!(
        "{USAGE}\nSettings (E15.17, as the admin):\n{}",
        admin::USAGE
    )
}

const USAGE: &str = "usage:
  ainkrad-core-server serve <db> [--listen unix:<path>|loopback:<port>|public]
                 [--bind <addr:port>] [--host <name>]
                 [--hostname <dns-name> --acme-contact <email>
                 [--acme-directory <url>] [--acme-http01]]
                 [--trusted-proxy <addr|cidr>[,…]]
                 [--apns-key <file.p8> --apns-key-id <id> --apns-team-id <id>
                 --apns-topic <bundle-id>]
  ainkrad-core-server openapi
  ainkrad-core-server backup <db> <dest>
  ainkrad-core-server restore [--force] <src> <db>
  ainkrad-core-server device add <db> <name>
  ainkrad-core-server device list <db>
  ainkrad-core-server device revoke <db> <device-id>

serve listens on a Unix socket next to the database (<db dir>/core.sock, 0600) by default and
serves the app at /api/v1 (a device key) and the modules mounted inside it. --listen
loopback:<port> serves 127.0.0.1, --bind any address (plain HTTP, as before). --listen public
serves TLS 1.3 on :443 with a certificate from ACME (Let's Encrypt production unless
--acme-directory says otherwise, kept in <db dir>/tls) and needs --hostname and --acme-contact;
the challenge is TLS-ALPN-01 on :443, or HTTP-01 on :80 with --acme-http01. Without a key only
/handshake, pairing and /healthz answer. --host is the Host header clients must send (default:
localhost on a socket, the address on loopback, the hostname in public); --trusted-proxy the
proxies whose X-Forwarded-For names the client for the API's
failure limit and logs (default: loopback, 127.0.0.0/8 and ::1). SIGTERM or Ctrl-C shuts serve
down: it stops accepting, gives requests in flight up to 10 s, closes event sockets so they
reconnect, and checkpoints the database. Limits and intervals are settings (`setting list`),
read when serve starts. With the four --apns-* flags, what a module's push rules pick is pushed
to the app's devices through APNs; without them it is only logged. The platform alone pushes
nothing.
openapi prints the client API's contract (api/openapi.json; `make contract`).
device add prints a new device key for the app (E10.3) once; only its hash is kept. It goes
in `Authorization: Bearer` on /api/v1. device revoke stops it at once; the row stays listed.";

/// Device keys are issued and revoked as the one admin user (#18).
pub(crate) const ADMIN: AuditActor = AuditActor::User(UserId(1));

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let seeded = match args.first() {
        Some(&"setting") => admin::run(&args).await,
        _ => None,
    };
    let result = match args.as_slice() {
        _ if seeded.is_some() => seeded.expect("checked"),
        [] => {
            println!("ainkrad-core-server {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
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
        ["openapi"] => {
            print!("{}", ainkrad_core_server::api::v1::spec::json());
            return ExitCode::SUCCESS;
        }
        ["device", "add", db, name] => add_device(Path::new(db), name).await,
        ["device", "list", db] => list_devices(Path::new(db)).await,
        ["device", "revoke", db, id] => match id.parse() {
            Ok(id) => revoke_device(Path::new(db), id).await,
            Err(_) => Err(format!("{id:?} is not a device id").into()),
        },
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

/// Issues a device key and prints it, the only time it is ever shown.
async fn add_device(db: &Path, name: &str) -> Result_ {
    let pool = store::connect(db).await?;
    let (device, key) = gov::issue_device_key(&pool, name, ADMIN).await?;
    eprintln!(
        "device {} (id {}) added. Its key, shown only now; give it to the app:",
        device.name, device.id.0
    );
    println!("{key}");
    Ok(())
}

/// One line per device key: id, name, created, last used, revoked. Never a key.
async fn list_devices(db: &Path) -> Result_ {
    let pool = store::connect(db).await?;
    for d in gov::list_device_keys(&pool).await? {
        println!(
            "{}\t{}\tcreated {}\tlast used {}{}",
            d.id.0,
            d.name,
            d.created_at,
            d.last_used_at.as_deref().unwrap_or("never"),
            d.revoked_at
                .map(|at| format!("\trevoked {at}"))
                .unwrap_or_default(),
        );
    }
    Ok(())
}

async fn revoke_device(db: &Path, id: i64) -> Result_ {
    let pool = store::connect(db).await?;
    let now = SystemClock.now();
    if gov::revoke_device_key(&pool, DeviceKeyId(id), ADMIN, &now).await? {
        eprintln!("device {id} revoked; its key no longer authenticates");
        Ok(())
    } else {
        Err(format!("no live device key {id}").into())
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
    };
    let mut apns: [Option<String>; 4] = Default::default();
    let mut it = flags.iter();
    while let Some(flag) = it.next() {
        if *flag == "--acme-http01" {
            s.acme_http01 = true;
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
            "--hostname" => s.hostname = Some(value),
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
    s.apns = match apns {
        [Some(a), Some(b), Some(c), Some(d)] => Some([a, b, c, d]),
        [None, None, None, None] => None,
        _ => return None,
    };
    Some(s)
}

/// Where to listen, from the flags: `unix:<path>`, `loopback:<port>`, `public[:<port>]`
/// (443), or `--bind`'s address; a socket next to the database by default. Public needs a
/// hostname and an ACME contact.
fn listen(db: &Path, flags: &Serve) -> Result<gateway::Listen, String> {
    let state = db
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
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
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
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
    let listen = listen(db, &flags)?;
    let host = flags.host.clone().unwrap_or_else(|| listen.default_host());
    let gateway = gateway::Gateway::bind(listen.clone(), gateway::Limits::default()).await?;
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
    let mut app = App::new(pool, Arc::new(SystemClock), host);
    app.limits = limits;
    if let Some(list) = flags.trusted_proxies {
        app.trusted_proxies = list.into();
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
