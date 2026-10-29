//! Fault injection (E1-11.4, after Citadel's `fault_injection`): the real runner daemon talks
//! to the Core through a TCP proxy that the test cuts mid-stream. Commands running across a
//! cut, and commands sent into a dying connection, each answer exactly once, with nothing
//! lost.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core_server::hub::{Dispatched, HubConfig};
use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::*;
use ainkrad_runner::v2::client::Client;
use ainkrad_runner::v2::daemon::{Backoff, Daemon};
use ainkrad_runner::v2::key::{Enrolment, Key};
use ainkrad_runner::v2::{ExecConfig, ExecDriver};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::AbortHandle;

use super::runner::{paired, state};
use super::{Core, quick};

/// A TCP proxy to `upstream` whose open connections `cut` drops at once, both ways.
struct Proxy {
    port: u16,
    pipes: Arc<Mutex<Vec<AbortHandle>>>,
}

impl Proxy {
    async fn start(upstream: Arc<Mutex<u16>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let pipes: Arc<Mutex<Vec<AbortHandle>>> = Arc::default();
        let held = Arc::clone(&pipes);
        tokio::spawn(async move {
            while let Ok((mut down, _)) = listener.accept().await {
                let to = *upstream.lock().unwrap();
                let pipe = tokio::spawn(async move {
                    if let Ok(mut up) = TcpStream::connect(("127.0.0.1", to)).await {
                        let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                    }
                });
                held.lock().unwrap().push(pipe.abort_handle());
            }
        });
        Self { port, pipes }
    }

    /// Drops every open connection; later ones go through.
    fn cut(&self) -> usize {
        let pipes: Vec<AbortHandle> = self.pipes.lock().unwrap().drain(..).collect();
        pipes.iter().for_each(AbortHandle::abort);
        pipes.len()
    }
}

fn echo(i: usize, sleep_ms: u64) -> Command {
    Command::ExecRun(ExecRun {
        program: "/bin/sh".to_owned(),
        args: vec![
            "-c".to_owned(),
            format!("sleep {}; echo {i}", sleep_ms as f64 / 1000.0),
        ],
        cwd: None,
        env: Default::default(),
        env_pass: vec!["PATH".to_owned()],
        limits: ExecLimits::default(),
    })
}

/// Every dispatched command's one answer, in order; each stream ends right after it.
async fn answers(all: Vec<Dispatched>) -> Vec<String> {
    let mut out = Vec::new();
    for mut d in all {
        let body = tokio::time::timeout(Duration::from_secs(20), d.next())
            .await
            .expect("answered");
        match body {
            Some(Body::Result(Reply::ExecRun(r))) => out.push(r.stdout.text),
            other => panic!("stream {}: {other:?}", d.stream),
        }
        assert_eq!(
            d.next().await,
            None,
            "stream {} answered more than once",
            d.stream
        );
    }
    out
}

async fn online(core: &Core, id: &str) {
    for _ in 0..500 {
        if core.app.hub.online(id) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the runner did not come back");
}

#[tokio::test]
async fn a_cut_mid_stream_loses_nothing_and_answers_once() {
    // The proxy needs the Core's port, the Core the proxy's Host: proxy first.
    let upstream = Arc::new(Mutex::new(0));
    let proxy = Proxy::start(Arc::clone(&upstream)).await;
    let front = format!("127.0.0.1:{}", proxy.port);
    let cfg = HubConfig {
        resume: Duration::from_secs(20),
        ..quick()
    };
    let listen = ainkrad_core_server::gateway::Listen::Tcp("127.0.0.1:0".to_owned());
    let core = Core::start_on("fault", cfg, listen, None, Some(&front)).await;
    *upstream.lock().unwrap() = core.port;
    let base = format!("http://{front}");
    let st = state("fault");
    let e = paired(&core, &base, None, &st).await;

    let exec = ExecConfig {
        run_enabled: true,
        capacity: 8,
        env_allow: vec!["PATH".to_owned()],
        ..ExecConfig::default()
    };
    let daemon = Daemon {
        client: Client::new(&base, None).unwrap(),
        key: Arc::new(Key::load(&st.key()).unwrap()),
        enrolment: Arc::new(Mutex::new(Enrolment::load(&st.enrolment()).unwrap())),
        save: None,
        exec: Arc::new(ExecDriver::new(exec, Redactor::new())),
        tls: None,
        backoff: Backoff {
            min: Duration::from_millis(50),
            max: Duration::from_millis(200),
            ..Backoff::default()
        },
    };
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let running = tokio::spawn(daemon.run(stopping));
    online(&core, &e.device_id).await;
    let hub = Arc::clone(&core.app.hub);

    // Commands running across the cut: they finish while the runner is away, and their
    // answers come over the next connection.
    let first: Vec<Dispatched> = (0..6)
        .map(|i| hub.dispatch(&e.device_id, echo(i, 600)).unwrap())
        .collect();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(proxy.cut() >= 1, "a connection was cut");
    let got = answers(first).await;
    assert_eq!(got, (0..6).map(|i| format!("{i}\n")).collect::<Vec<_>>());

    // Commands sent into a connection as it dies: resent on the next, run once.
    online(&core, &e.device_id).await;
    let second: Vec<Dispatched> = (10..14)
        .map(|i| hub.dispatch(&e.device_id, echo(i, 0)).unwrap())
        .collect();
    proxy.cut();
    let got = answers(second).await;
    assert_eq!(got, (10..14).map(|i| format!("{i}\n")).collect::<Vec<_>>());

    // And it still serves.
    online(&core, &e.device_id).await;
    hub.noop(&e.device_id).await.unwrap();
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let _ = std::fs::remove_dir_all(&st.0);
}
