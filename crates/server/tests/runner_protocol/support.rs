//! The runner protocol suite's stack: a real server on an ephemeral port behind a TCP proxy
//! the test can cut, a fake clock, a temp database, and an executor the test holds open.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ainkrad_core_server::api::{App, router};
use ainkrad_core_server::scheduler::Clock;
use ainkrad_harness::claude;
use ainkrad_proto::runner::{Outcome, RunToken};
use ainkrad_runner::{Config, Executor, Job, Report};
use sqlx::SqlitePool;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::harness::{self, Db, count};

/// The suite's fake time, shared by the server and the test.
pub struct FakeClock(Mutex<harness::Clock>);

impl Clock for FakeClock {
    fn now(&self) -> String {
        self.0.lock().unwrap().now()
    }
}

/// A TCP proxy in front of the server: `cut` drops every connection through it, `down`
/// also refuses new ones, as a network outage would.
pub struct Proxy {
    pub addr: SocketAddr,
    cut: broadcast::Sender<()>,
    down: Arc<AtomicBool>,
}

impl Proxy {
    async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (cut, _) = broadcast::channel(4);
        let down = Arc::new(AtomicBool::new(false));
        let (cuts, is_down) = (cut.clone(), down.clone());
        tokio::spawn(async move {
            loop {
                let (mut client, _) = listener.accept().await.unwrap();
                if is_down.load(Ordering::SeqCst) {
                    continue;
                }
                let mut cut = cuts.subscribe();
                tokio::spawn(async move {
                    let Ok(mut server) = TcpStream::connect(target).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut client, &mut server) => {}
                        _ = cut.recv() => {}
                    }
                });
            }
        });
        Proxy { addr, cut, down }
    }

    pub fn cut(&self) {
        let _ = self.cut.send(());
    }

    pub fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
        if down {
            self.cut();
        }
    }
}

pub struct Stack {
    pub db: Db,
    pub clock: Arc<FakeClock>,
    pub proxy: Proxy,
    server: JoinHandle<()>,
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Stack {
    /// A migrated database and a server that expects the proxy's address as its `Host`.
    pub async fn new() -> Self {
        Self::with_dispatch_poll(Duration::from_millis(20)).await
    }

    /// `new`, with the server's fallback dispatch poll at `every` (E15.6).
    pub async fn with_dispatch_poll(every: Duration) -> Self {
        let db = Db::new().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = Proxy::start(listener.local_addr().unwrap()).await;
        let clock = Arc::new(FakeClock(Mutex::new(harness::Clock::new())));
        let mut app = App::new(db.pool.clone(), clock.clone(), proxy.addr.to_string());
        app.poll = Duration::from_millis(20);
        app.dispatch_poll = every;
        let server = tokio::spawn(async move { axum::serve(listener, router(app)).await.unwrap() });
        Stack {
            db,
            clock,
            proxy,
            server,
        }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.db.pool
    }

    pub fn url(&self) -> String {
        format!("ws://{}/runner/v1/connect", self.proxy.addr)
    }

    pub fn now(&self) -> String {
        self.clock.0.lock().unwrap().now()
    }

    pub fn advance(&self, secs: i64) -> String {
        self.clock.0.lock().unwrap().advance(secs)
    }

    /// Starts a runner daemon (a separate "host": its own task, key and connection) that
    /// has Claude at the supported version.
    pub fn runner<E: Executor>(&self, key: &str, tags: &[&str], executor: E) -> JoinHandle<()> {
        self.runner_with(key, tags, &[("claude", claude::VERSION)], executor)
    }

    /// `runner`, reporting `harnesses` (name, version) in its `Hello`.
    pub fn runner_with<E: Executor>(
        &self,
        key: &str,
        tags: &[&str],
        harnesses: &[(&str, &str)],
        executor: E,
    ) -> JoinHandle<()> {
        let config = Config {
            log: None,
            url: self.url(),
            key: key.to_owned(),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            harnesses: harnesses
                .iter()
                .map(|(name, version)| (name.to_string(), version.to_string()))
                .collect(),
        };
        tokio::spawn(async move {
            let e = ainkrad_runner::run(config, executor).await;
            panic!("runner stopped: {e}");
        })
    }
}

/// Waits up to 10 s for `sql` to count at least one row.
pub async fn until(pool: &SqlitePool, what: &str, sql: &str) {
    for _ in 0..500 {
        if count(pool, sql).await > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Starts at once, hands each run's token to the test, then works until released.
pub struct Held {
    pub tokens: mpsc::UnboundedSender<(i64, RunToken)>,
    pub release: Arc<Notify>,
}

/// A `Held` executor, the tokens it receives, and its release.
pub fn held() -> (Held, mpsc::UnboundedReceiver<(i64, RunToken)>, Arc<Notify>) {
    let (tokens, rx) = mpsc::unbounded_channel();
    let release = Arc::new(Notify::new());
    let executor = Held {
        tokens,
        release: release.clone(),
    };
    (executor, rx, release)
}

impl Executor for Held {
    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        Ok(Some(format!("held-{}", job.run)))
    }

    async fn run(&self, job: &Job, token: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        let _ = self.tokens.send((job.run, token));
        let chunk = serde_json::json!({"held": job.run});
        let _ = reports.send(Report::Event(chunk)).await;
        self.release.notified().await;
        Outcome::Succeeded
    }
}

/// Every log line of this test binary, at every level, from servers and runners alike.
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    pub fn text(&self) -> Vec<u8> {
        self.0.lock().unwrap().clone()
    }
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The binary's log capture, installed as the global subscriber on first use.
pub fn logs() -> &'static Capture {
    static LOGS: OnceLock<Capture> = OnceLock::new();
    LOGS.get_or_init(|| {
        let logs = Capture::default();
        let sink = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || sink.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();
        logs
    })
}

/// Sets `key` server-wide to `value`: the server sends runner limits from settings (E15.17).
pub async fn setting(pool: &SqlitePool, key: &str, value: i64) {
    let key = key.parse().unwrap();
    let at = ainkrad_core::settings::Scope::Server;
    let by = ainkrad_core::audit::AuditActor::System;
    ainkrad_core_server::store::settings::set(
        pool,
        key,
        at,
        &value.to_string(),
        by,
        "2026-10-22T10:00:00.000Z",
    )
    .await
    .unwrap();
}
