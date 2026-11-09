use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use citadel_core::audit::AuditActor;
use citadel_core::exec::NewRunner;
use citadel_core::gov::DeviceKeyId;
use citadel_core::settings::{Key::DispatchPollMs, Scope};
use citadel_core::work::UserId;
use citadel_server::api::{App, router};
use citadel_server::forge::Poller;
use citadel_server::push;
use citadel_server::scheduler::{Clock, Scheduler, SystemClock};
use citadel_server::store::{self, exec, gov};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};

mod admin;

fn usage() -> String {
    format!(
        "{USAGE}\nSeeding (E4.4; each prints the new id):\n{}\nPlanning (E5, as the admin):\n{}\n\
         Org (E6, as the admin):\n{}\nAvatars (decision #61, as the admin):\n{}\nGovernance (E7, as the admin):\n{}\n\
         Knowledge and skills (E8, E4.3, as the admin):\n{}\nProject profile (E15.13, as the admin):\n{}\nForges (E9, as the admin):\n{}{}\nRepos (E15.16, as the admin):\n{}\n\
         Accounts (E15, as the admin):\n{}\nRouting (E15.5, as the admin):\n{}\n\
         Settings (E15.17, as the admin):\n{}\nLatency (E15.6):\n{}\nRequirements (E15.10):\n{}",
        admin::USAGE,
        admin::PM_USAGE,
        admin::ORG_USAGE,
        admin::AVATAR_USAGE,
        admin::MONEY_USAGE,
        admin::KNOWLEDGE_USAGE,
        admin::PROFILE_USAGE,
        admin::FORGE_USAGE,
        admin::LINEAR_USAGE,
        admin::REPO_USAGE,
        admin::ACCOUNT_USAGE,
        admin::ROUTING_USAGE,
        admin::SETTING_USAGE,
        admin::TIMING_USAGE,
        admin::REQUIREMENT_USAGE
    )
}

const USAGE: &str = "usage:
  citadel-server serve <db> [--bind <addr:port>] [--host <name>] [--artifacts <dir>]
                 [--trusted-proxy <addr|cidr>[,…]]
                 [--apns-key <file.p8> --apns-key-id <id> --apns-team-id <id>
                 --apns-topic <bundle-id>]
  citadel-server openapi
  citadel-server backup <db> <dest>
  citadel-server restore [--force] <src> <db>
  citadel-server runner add <db> <name> [--tags <a,b,…>]
  citadel-server runner list <db>
  citadel-server runner revoke <db> <name>
  citadel-server device add <db> <name>
  citadel-server device list <db>
  citadel-server device revoke <db> <device-id>

serve binds 127.0.0.1:7700 by default and serves runners at /runner/v1/connect, agents' MCP
tools at /mcp/v1 (a run token as the bearer) and the app at /api/v1 (a device key); --host is
the Host header clients must send (default: the bind address); --artifacts where published
artifacts are stored (default: artifacts/ next to the database); --trusted-proxy the proxies
whose X-Forwarded-For names the client for the API's failure limit and logs (default:
loopback, 127.0.0.0/8 and ::1). SIGTERM or Ctrl-C shuts serve down: it stops accepting, gives
requests in flight up to 10 s, closes runner and event sockets so they reconnect, and
checkpoints the database. Limits, intervals and
thresholds are settings (`setting list`): run.token_cap is the tokens a run may use when no
budget caps it lower; forge.poll_secs how often pull requests are opened and followed on the
projects' forges; the scheduler, push and API rate settings are read when serve starts. With the four
--apns-* flags, new approvals, blocked and stuck issues and escalations are pushed to the
app's devices through APNs; without them they are only logged.
openapi prints the client API's contract (api/openapi.json; `make contract`).
runner add prints the new runner's key once; only its hash is kept. runner revoke deletes
the runner, so its key stops working; it is refused while the runner holds live runs.
device add prints a new device key for the app (E10.3) once; only its hash is kept. It goes
in `Authorization: Bearer` on /api/v1. device revoke stops it at once; the row stays listed.";

/// Device keys are issued and revoked as the one admin user (#18).
const ADMIN: AuditActor = AuditActor::User(UserId(1));

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let seeded = match args.first() {
        Some(
            &("company" | "agent" | "project" | "issue" | "epic" | "sprint" | "wip" | "approval"
            | "department" | "team" | "member" | "intake" | "template" | "budget" | "price"
            | "billing" | "cost" | "knowledge" | "skill" | "forge" | "linear" | "account"
            | "setting" | "runs" | "repo" | "requirement"),
        ) => admin::run(&args).await,
        _ => None,
    };
    let result = match args.as_slice() {
        _ if seeded.is_some() => seeded.expect("checked"),
        [] => {
            println!("citadel-server {}", env!("CARGO_PKG_VERSION"));
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
        ["runner", "add", db, name, flags @ ..] => match flags {
            [] => add_runner(Path::new(db), name, vec![]).await,
            ["--tags", list] => add_runner(Path::new(db), name, tags(list)).await,
            _ => {
                eprintln!("{}", usage());
                return ExitCode::from(2);
            }
        },
        ["openapi"] => {
            print!("{}", citadel_server::api::v1::spec::json());
            return ExitCode::SUCCESS;
        }
        ["runner", "list", db] => list_runners(Path::new(db)).await,
        ["runner", "revoke", db, name] => revoke_runner(Path::new(db), name).await,
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
            eprintln!("citadel-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn tags(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

type Result_ = Result<(), Box<dyn std::error::Error>>;

/// Registers a runner and prints its key, the only time it is ever shown.
async fn add_runner(db: &Path, name: &str, tags: Vec<String>) -> Result_ {
    let pool = store::connect(db).await?;
    let new = NewRunner {
        name: name.to_owned(),
        tags,
    };
    let (runner, key) = exec::register_runner(&pool, &new).await?;
    eprintln!(
        "runner {} (id {}) registered. Its key, shown only now; give it to the runner as \
         CITADEL_RUNNER_KEY or --key-file:",
        runner.name, runner.id.0
    );
    println!("{key}");
    Ok(())
}

/// One line per runner: name, id, status, tags, last seen. Never a key: none is stored.
async fn list_runners(db: &Path) -> Result_ {
    let pool = store::connect(db).await?;
    for r in exec::list_runners(&pool).await? {
        println!(
            "{}\tid {}\t{}\ttags {}\tlast seen {}{}",
            r.name,
            r.id.0,
            r.status.as_str(),
            r.tags.join(","),
            r.last_seen_at.as_deref().unwrap_or("never"),
            r.health_reason
                .map(|why| format!("\t({why})"))
                .unwrap_or_default(),
        );
    }
    Ok(())
}

async fn revoke_runner(db: &Path, name: &str) -> Result_ {
    let pool = store::connect(db).await?;
    match exec::revoke_runner(&pool, name).await {
        Ok(true) => {
            eprintln!("runner {name} revoked; its key no longer connects");
            Ok(())
        }
        Ok(false) => Err(format!("no runner named {name}").into()),
        Err(exec::DeleteRunnerError::LiveRuns(runs)) => {
            let runs: Vec<String> = runs.iter().map(|r| r.0.to_string()).collect();
            Err(format!(
                "runner {name} holds live runs ({}); cancel them, or stop the runner and let \
                 their leases expire, then revoke again",
                runs.join(", ")
            )
            .into())
        }
        Err(e) => Err(e.into()),
    }
}

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
    artifacts: Option<PathBuf>,
    /// `--apns-key`, `--apns-key-id`, `--apns-team-id`, `--apns-topic`, all or none.
    apns: Option<[String; 4]>,
    trusted_proxies: Option<Vec<citadel_server::api::limit::Cidr>>,
}

/// `--bind`, `--host`, `--artifacts` and the `--apns-*` flags for `serve`; `None` on anything else.
fn serve_flags(flags: &[&str]) -> Option<Serve> {
    let (mut bind, mut host, mut artifacts) = ("127.0.0.1:7700".to_owned(), None, None);
    let mut apns: [Option<String>; 4] = Default::default();
    let mut trusted_proxies = None;
    for pair in flags.chunks(2) {
        match pair {
            ["--bind", addr] => bind = (*addr).to_owned(),
            ["--host", name] => host = Some((*name).to_owned()),
            ["--artifacts", dir] => artifacts = Some(PathBuf::from(dir)),
            ["--trusted-proxy", list] => {
                let parsed: Result<Vec<_>, _> = tags(list).iter().map(|c| c.parse()).collect();
                match parsed {
                    Ok(list) => trusted_proxies = Some(list),
                    Err(why) => {
                        eprintln!("citadel-server: --trusted-proxy: {why}");
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
        artifacts,
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

/// Serves the runner endpoint and runs the scheduler and the forge poller until SIGTERM or
/// Ctrl-C, then shuts down cleanly (`USAGE`).
async fn serve(db: &Path, flags: Serve) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let pool = store::connect(db).await?;
    // Read once: a change to these takes effect at the next start (E15.17).
    let [tick, push_every, forge_poll] =
        citadel_server::scheduler::loop_intervals(&pool).await?;
    let limits = Arc::new(citadel_server::api::v1::Limits::from_settings(&pool).await?);
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
        clock: Arc::new(SystemClock),
        every: push_every,
    };
    let listener = tokio::net::TcpListener::bind(&flags.bind).await?;
    tracing::info!(addr = %listener.local_addr()?, host = %flags.host, "serving");
    let scheduler = Scheduler {
        pool: pool.clone(),
        clock: SystemClock,
        every: tick,
    };
    let poller = Poller {
        pool: pool.clone(),
        client: ainkrad_providers::client(),
        every: forge_poll,
    };
    // Dropping `stop` ends both loops.
    let (stop, mut stopped) = tokio::sync::watch::channel(());
    let mut stopped_too = stopped.clone();
    let mut stopped_push = stopped.clone();
    let pushing = tokio::spawn(async move {
        pusher
            .run(async { drop(stopped_push.changed().await) })
            .await
    });
    let ticking =
        tokio::spawn(async move { scheduler.run(async { drop(stopped.changed().await) }).await });
    let polling = tokio::spawn(async move {
        poller
            .run(async { drop(stopped_too.changed().await) })
            .await
    });
    let dispatch_poll = store::settings::value(&pool, DispatchPollMs, Scope::Server).await?;
    let mut app = App::new(pool, Arc::new(SystemClock), flags.host);
    app.limits = limits;
    app.dispatch_poll = Duration::from_millis(dispatch_poll as u64);
    if let Some(dir) = flags.artifacts {
        app.artifacts = dir;
    }
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
            // Stops accepting; runner and event sockets close themselves (`App::closing`).
            closing.send_replace(true);
            match tokio::time::timeout(SHUTDOWN_GRACE, server).await {
                Ok(served) => served?,
                Err(_) => tracing::warn!("requests still in flight after 10 s; dropped"),
            }
        }
    }
    drop(stop);
    ticking.await?;
    polling.await?;
    pushing.await?;
    // Folds the WAL back into the database file, so a stopped server leaves one file.
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&pool)
        .await?;
    pool.close().await;
    tracing::info!("stopped");
    Ok(())
}
