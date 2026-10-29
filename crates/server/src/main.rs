use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::ids::{DeviceKeyId, UserId};
use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::push;
use ainkrad_core_server::scheduler::{Clock, Scheduler, SystemClock};
use ainkrad_core_server::store::{self, gov};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};

mod admin;

fn usage() -> String {
    format!(
        "{USAGE}\nSettings (E15.17, as the admin):\n{}",
        admin::USAGE
    )
}

const USAGE: &str = "usage:
  ainkrad-core-server serve <db> [--bind <addr:port>] [--host <name>]
                 [--trusted-proxy <addr|cidr>[,…]]
                 [--apns-key <file.p8> --apns-key-id <id> --apns-team-id <id>
                 --apns-topic <bundle-id>]
  ainkrad-core-server openapi
  ainkrad-core-server backup <db> <dest>
  ainkrad-core-server restore [--force] <src> <db>
  ainkrad-core-server device add <db> <name>
  ainkrad-core-server device list <db>
  ainkrad-core-server device revoke <db> <device-id>

serve binds 127.0.0.1:7700 by default and serves the app at /api/v1 (a device key) and the
modules mounted inside it; --host is the Host header clients must send (default: the bind
address); --trusted-proxy the proxies whose X-Forwarded-For names the client for the API's
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
    bind: String,
    host: String,
    /// `--apns-key`, `--apns-key-id`, `--apns-team-id`, `--apns-topic`, all or none.
    apns: Option<[String; 4]>,
    trusted_proxies: Option<Vec<ainkrad_core_server::api::limit::Cidr>>,
}

/// `--bind`, `--host`, `--trusted-proxy` and the `--apns-*` flags for `serve`; `None` on
/// anything else.
fn serve_flags(flags: &[&str]) -> Option<Serve> {
    let (mut bind, mut host) = ("127.0.0.1:7700".to_owned(), None);
    let mut apns: [Option<String>; 4] = Default::default();
    let mut trusted_proxies = None;
    for pair in flags.chunks(2) {
        match pair {
            ["--bind", addr] => bind = (*addr).to_owned(),
            ["--host", name] => host = Some((*name).to_owned()),
            ["--trusted-proxy", list] => {
                let parsed: Result<Vec<_>, _> =
                    comma_list(list).iter().map(|c| c.parse()).collect();
                match parsed {
                    Ok(list) => trusted_proxies = Some(list),
                    Err(why) => {
                        eprintln!("ainkrad-core-server: --trusted-proxy: {why}");
                        return None;
                    }
                }
            }
            ["--apns-key", v] => apns[0] = Some((*v).to_owned()),
            ["--apns-key-id", v] => apns[1] = Some((*v).to_owned()),
            ["--apns-team-id", v] => apns[2] = Some((*v).to_owned()),
            ["--apns-topic", v] => apns[3] = Some((*v).to_owned()),
            _ => return None,
        }
    }
    let host = host.unwrap_or_else(|| bind.clone());
    let apns = match apns {
        [Some(a), Some(b), Some(c), Some(d)] => Some([a, b, c, d]),
        [None, None, None, None] => None,
        _ => return None,
    };
    Some(Serve {
        bind,
        host,
        apns,
        trusted_proxies,
    })
}

/// How long requests in flight get to finish once serve is told to stop.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

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
    let listener = tokio::net::TcpListener::bind(&flags.bind).await?;
    tracing::info!(addr = %listener.local_addr()?, host = %flags.host, "serving");
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
    let mut app = App::new(pool, Arc::new(SystemClock), flags.host);
    app.limits = limits;
    if let Some(list) = flags.trusted_proxies {
        app.trusted_proxies = list.into();
    }
    let (closing, pool) = (Arc::clone(&app.closing), app.pool.clone());
    // The peer address feeds the client API's per-address failure limit.
    let service = router(app).into_make_service_with_connect_info::<std::net::SocketAddr>();
    let mut stopping = closing.subscribe();
    let server = axum::serve(listener, service)
        .with_graceful_shutdown(async move { drop(stopping.wait_for(|c| *c).await) })
        .into_future();
    tokio::pin!(server);
    tokio::select! {
        served = &mut server => served?,
        () = stop_signal() => {
            tracing::info!("stopping: finishing requests in flight, closing sockets");
            // Stops accepting; event sockets close themselves (`App::closing`).
            closing.send_replace(true);
            match tokio::time::timeout(SHUTDOWN_GRACE, server).await {
                Ok(served) => served?,
                Err(_) => tracing::warn!("requests still in flight after 10 s; dropped"),
            }
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
