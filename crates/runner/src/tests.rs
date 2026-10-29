use std::collections::BTreeMap;
use std::sync::mpsc as std_mpsc;

use ainkrad_proto::runner::HostLoad;

use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::http::header;

use super::*;

fn config(url: &str) -> Config {
    Config {
        log: None,
        url: url.to_owned(),
        key: "k1".to_owned(),
        tags: vec![],
        harnesses: BTreeMap::new(),
    }
}

#[test]
fn plain_ws_only_to_loopback_and_the_key_only_in_a_header() {
    for ok in [
        "wss://citadel.example/runner/v1/connect",
        "ws://127.0.0.1:7700/runner/v1/connect",
        "ws://localhost:7700/runner/v1/connect",
        "ws://[::1]:7700/runner/v1/connect",
    ] {
        let req = request(&config(ok)).unwrap();
        let auth = &req.headers()[header::AUTHORIZATION];
        assert_eq!(auth, "Bearer k1");
        assert!(auth.is_sensitive());
    }
    for bad in [
        "ws://citadel.example/runner/v1/connect",
        "ws://127.0.0.2.example/runner/v1/connect",
        "http://127.0.0.1/runner/v1/connect",
        "wss://citadel.example/runner/v1/connect?key=k1",
    ] {
        assert!(request(&config(bad)).is_err(), "{bad}");
    }
}

/// Leaks every secret it can: the run token, the runner key, its own secret, and a key
/// shape, in a chunk and in its failure reason.
struct Leaky;

const OWN_SECRET: &str = "askpass-answer-0123456789";
const SHAPED: &str = "ghp_16C7e42F292c6912E7710c838347Ae178B4a";

impl Executor for Leaky {
    async fn secrets(&self) -> Vec<(String, String)> {
        vec![("git_askpass".to_owned(), OWN_SECRET.to_owned())]
    }

    async fn start(&self, _job: &Job) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn run(&self, _job: &Job, token: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        let leak = format!("{} k1-runner-key {OWN_SECRET} {SHAPED}", token.expose());
        let chunk = serde_json::json!({"type": "assistant_text", "text": leak});
        let _ = reports.send(Report::Event(chunk)).await;
        Outcome::Failed {
            reason: format!("crashed: {leak}"),
            fingerprint: None,
        }
    }
}

type ServerWs = WebSocketStream<TcpStream>;

async fn to_runner(ws: &mut ServerWs, msg: ServerMessage) {
    let text = serde_json::to_string(&msg).unwrap();
    ws.send(Message::Text(text.into())).await.unwrap();
}

/// The runner's next message but its `Status` reports (1.20), which come after every
/// clean-up pass.
async fn from_runner(ws: &mut ServerWs) -> RunnerMessage {
    loop {
        if let Message::Text(text) = ws.next().await.unwrap().unwrap() {
            match serde_json::from_str(&text).unwrap() {
                RunnerMessage::Status { .. } => {}
                msg => return msg,
            }
        }
    }
}

/// Everything the run reports is redacted before it leaves the runner, and an
/// unacknowledged `RunEnded` is resent on the heartbeat timer, on the same connection.
#[tokio::test]
async fn reports_are_redacted_and_run_ended_is_resent_until_acked() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/runner/v1/connect", listener.local_addr().unwrap());
    let mut cfg = config(&url);
    cfg.key = "k1-runner-key".to_owned();
    tokio::spawn(run(cfg, Leaky));
    let (tcp, _) = listener.accept().await.unwrap();
    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    assert!(matches!(
        from_runner(&mut ws).await,
        RunnerMessage::Hello { .. }
    ));
    let welcome = ServerMessage::Welcome {
        runner: 1,
        lease_ttl_secs: 3,
        limits: None,
        power_nap: None,
    };
    to_runner(&mut ws, welcome).await;
    assert!(matches!(
        from_runner(&mut ws).await,
        RunnerMessage::Ready { .. }
    ));
    let assign = ServerMessage::Assign {
        run: 5,
        agent: 1,
        issue: None,
        harness: "claude".to_owned(),
        model: String::new(),
        context_ref: String::new(),
        workspace: None,
        token_cap: None,
        token_caps: None,
        policy: Default::default(),
        issue_key: None,
        instructions: None,
        account: None,
        fallbacks: vec![],
        limits: None,
        resume_session: None,
        prompt: None,
    };
    to_runner(&mut ws, assign).await;
    assert!(matches!(
        from_runner(&mut ws).await,
        RunnerMessage::RunStarted { run: 5, .. }
    ));
    let token = RunToken::new("token-for-run-5-xyz".to_owned());
    to_runner(&mut ws, ServerMessage::Token { run: 5, token }).await;

    let RunnerMessage::RunEvent {
        seq: 1, payload, ..
    } = from_runner(&mut ws).await
    else {
        panic!("no chunk");
    };
    let redacted = "[redacted:run_token] [redacted:runner_key] [redacted:git_askpass] \
                    [redacted:github_token]";
    assert_eq!(payload["text"], redacted);
    let ended = RunnerMessage::RunEnded {
        run: 5,
        outcome: Outcome::Failed {
            reason: format!("crashed: {redacted}"),
            fingerprint: None,
        },
    };
    let mut ends = 0;
    let started = tokio::time::Instant::now();
    while ends < 2 {
        match from_runner(&mut ws).await {
            RunnerMessage::Heartbeat { run: 5, .. } => {}
            msg => {
                assert_eq!(msg, ended);
                ends += 1;
            }
        }
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    to_runner(&mut ws, ServerMessage::Ack { run: 5 }).await;
    assert!(matches!(
        from_runner(&mut ws).await,
        RunnerMessage::Ready { .. }
    ));
}

/// Holds its run open and serves one text file and one image carrying every secret it knows.
struct Publisher;

const ENV_SECRET: &str = "env-secret-value-0123456789";
const ACCOUNT: &str = "account-credential-0123456789";

impl Executor for Publisher {
    async fn secrets(&self) -> Vec<(String, String)> {
        vec![
            ("git_askpass".to_owned(), OWN_SECRET.to_owned()),
            ("env:OPENAI_API_KEY".to_owned(), ENV_SECRET.to_owned()),
        ]
    }

    fn run_secrets(&self, _job: &Job) -> Vec<(String, String)> {
        vec![("account_credential".to_owned(), ACCOUNT.to_owned())]
    }

    async fn start(&self, _job: &Job) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn run(&self, _job: &Job, _token: RunToken, _reports: mpsc::Sender<Report>) -> Outcome {
        std::future::pending().await
    }

    async fn read_file(&self, _: Option<i64>, path: &str, _: u64) -> Result<Vec<u8>, String> {
        let leak = format!("token-for-run-5-xyz k1-runner-key {OWN_SECRET} {ENV_SECRET} {ACCOUNT}");
        Ok(match path {
            "out/report.md" => leak.into_bytes(),
            _ => [b"\x89PNG ".as_slice(), leak.as_bytes()].concat(),
        })
    }
}

/// A text file read for a publish (E15.18) leaves the runner with every secret it knows
/// redacted: the run token, its key, askpass answers, secret env values and the account's
/// credential; an image is sent as it is (the server marks it unscanned).
#[tokio::test]
async fn files_read_for_a_publish_are_redacted_when_text() {
    use base64::Engine;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/runner/v1/connect", listener.local_addr().unwrap());
    let mut cfg = config(&url);
    cfg.key = "k1-runner-key".to_owned();
    tokio::spawn(run(cfg, Publisher));
    let (tcp, _) = listener.accept().await.unwrap();
    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    from_runner(&mut ws).await;
    let welcome = ServerMessage::Welcome {
        runner: 1,
        lease_ttl_secs: 30,
        limits: None,
        power_nap: None,
    };
    to_runner(&mut ws, welcome).await;
    from_runner(&mut ws).await;
    let assign = ServerMessage::Assign {
        run: 5,
        agent: 1,
        issue: Some(9),
        harness: "claude".to_owned(),
        model: String::new(),
        context_ref: String::new(),
        workspace: None,
        token_cap: None,
        token_caps: None,
        policy: Default::default(),
        issue_key: None,
        instructions: None,
        account: None,
        fallbacks: vec![],
        limits: None,
        resume_session: None,
        prompt: None,
    };
    to_runner(&mut ws, assign).await;
    from_runner(&mut ws).await;
    let token = RunToken::new("token-for-run-5-xyz".to_owned());
    to_runner(&mut ws, ServerMessage::Token { run: 5, token }).await;
    for (request, path) in [(1, "out/report.md"), (2, "shot.png")] {
        let read = ServerMessage::ReadFile {
            run: 5,
            request,
            path: path.to_owned(),
            max_bytes: 1 << 20,
        };
        to_runner(&mut ws, read).await;
        let content = loop {
            if let RunnerMessage::FileRead {
                request: r,
                content,
                ..
            } = from_runner(&mut ws).await
            {
                assert_eq!(r, request);
                break content.unwrap();
            }
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(content)
            .unwrap();
        let text = String::from_utf8_lossy(&bytes);
        if request == 1 {
            assert_eq!(
                text,
                "[redacted:run_token] [redacted:runner_key] [redacted:git_askpass] \
                 [redacted:env:OPENAI_API_KEY] [redacted:account_credential]"
            );
        } else {
            assert!(text.contains(ACCOUNT), "an image is sent as it is");
        }
    }
}

/// Ends its run when `go` is notified.
struct Gated(Arc<tokio::sync::Notify>);

impl Executor for Gated {
    async fn start(&self, _job: &Job) -> Result<Option<String>, String> {
        Ok(None)
    }

    async fn run(&self, _job: &Job, _token: RunToken, _reports: mpsc::Sender<Report>) -> Outcome {
        self.0.notified().await;
        Outcome::Succeeded
    }
}

/// Connects a `run_until` daemon and welcomes it: the server side and the daemon.
async fn stoppable(executor: Gated, stop: watch::Receiver<bool>) -> (ServerWs, JoinHandle<Error>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/runner/v1/connect", listener.local_addr().unwrap());
    let daemon = tokio::spawn(run_until(config(&url), executor, stop));
    let (tcp, _) = listener.accept().await.unwrap();
    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    assert!(matches!(
        from_runner(&mut ws).await,
        RunnerMessage::Hello { .. }
    ));
    let welcome = ServerMessage::Welcome {
        runner: 1,
        lease_ttl_secs: 30,
        limits: None,
        power_nap: None,
    };
    to_runner(&mut ws, welcome).await;
    assert!(matches!(
        from_runner(&mut ws).await,
        RunnerMessage::Ready { .. }
    ));
    (ws, daemon)
}

#[tokio::test]
async fn told_to_stop_an_idle_runner_closes_and_returns() {
    let (stop, stopping) = watch::channel(false);
    let (mut ws, daemon) = stoppable(Gated(Arc::default()), stopping).await;
    stop.send_replace(true);
    let error = tokio::time::timeout(Duration::from_secs(5), daemon).await;
    assert!(matches!(error.unwrap().unwrap(), Error::Stopped));
    while let Some(Ok(msg)) = ws.next().await {
        assert!(
            !matches!(msg, Message::Text(t) if t.contains("ready")),
            "asked for work"
        );
    }
}

#[tokio::test]
async fn told_to_stop_mid_run_it_finishes_the_run_and_asks_for_no_more() {
    let go = Arc::new(tokio::sync::Notify::new());
    let (stop, stopping) = watch::channel(false);
    let (mut ws, mut daemon) = stoppable(Gated(Arc::clone(&go)), stopping).await;
    let assign = ServerMessage::Assign {
        run: 7,
        agent: 1,
        issue: None,
        harness: "claude".to_owned(),
        model: String::new(),
        context_ref: String::new(),
        workspace: None,
        token_cap: None,
        token_caps: None,
        policy: Default::default(),
        issue_key: None,
        instructions: None,
        account: None,
        fallbacks: vec![],
        limits: None,
        resume_session: None,
        prompt: None,
    };
    to_runner(&mut ws, assign).await;
    assert!(matches!(
        from_runner(&mut ws).await,
        RunnerMessage::RunStarted { run: 7, .. }
    ));
    let token = RunToken::new("token-for-run-7-xyz".to_owned());
    to_runner(&mut ws, ServerMessage::Token { run: 7, token }).await;
    stop.send_replace(true);
    // The run goes on: the daemon waits for it.
    let early = tokio::time::timeout(Duration::from_millis(300), &mut daemon).await;
    assert!(early.is_err(), "returned with a run in flight");
    go.notify_one();
    loop {
        match from_runner(&mut ws).await {
            RunnerMessage::Heartbeat { .. } => {}
            RunnerMessage::RunEnded { run: 7, outcome } => {
                assert_eq!(outcome, Outcome::Succeeded);
                break;
            }
            msg => panic!("unexpected {msg:?}"),
        }
    }
    to_runner(&mut ws, ServerMessage::Ack { run: 7 }).await;
    let error = tokio::time::timeout(Duration::from_secs(5), daemon).await;
    assert!(matches!(error.unwrap().unwrap(), Error::Stopped));
    while let Some(Ok(msg)) = ws.next().await {
        assert!(
            !matches!(msg, Message::Text(t) if t.contains("ready")),
            "asked for work"
        );
    }
}

/// A dropped connection does not give up the run: the runner reconnects and its `Hello`
/// announces the run it still holds, so the server can re-claim its lease (inside the grace).
#[tokio::test]
async fn a_reconnect_announces_the_run_it_still_holds() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/runner/v1/connect", listener.local_addr().unwrap());
    let gate = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(run(config(&url), Gated(gate.clone())));
    let (tcp, _) = listener.accept().await.unwrap();
    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    from_runner(&mut ws).await;
    let welcome = ServerMessage::Welcome {
        runner: 1,
        lease_ttl_secs: 30,
        limits: None,
        power_nap: None,
    };
    to_runner(&mut ws, welcome).await;
    from_runner(&mut ws).await;
    let assign = ServerMessage::Assign {
        run: 5,
        agent: 1,
        issue: Some(9),
        harness: "claude".to_owned(),
        model: String::new(),
        context_ref: String::new(),
        workspace: None,
        token_cap: None,
        token_caps: None,
        policy: Default::default(),
        issue_key: None,
        instructions: None,
        account: None,
        fallbacks: vec![],
        limits: None,
        resume_session: None,
        prompt: None,
    };
    to_runner(&mut ws, assign).await;
    from_runner(&mut ws).await;
    let token = RunToken::new("token-for-run-5-xyz".to_owned());
    to_runner(&mut ws, ServerMessage::Token { run: 5, token }).await;
    // The network drops; the run is still in flight on the runner.
    drop(ws);

    let (tcp, _) = listener.accept().await.unwrap();
    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    let RunnerMessage::Hello { runs, .. } = from_runner(&mut ws).await else {
        panic!("not a hello");
    };
    assert_eq!(runs, vec![5]);
    gate.notify_one();
}

/// The heartbeat goes out on its own clock while nothing else is queued: the daemon's loop
/// is not involved in `pump`, so a loaded host that stalls that loop still renews its lease
/// (AIN-55). Each beat carries the host's load, and a queued message goes out first.
#[test]
fn the_heartbeat_keeps_its_clock_and_carries_the_load() {
    let (frames, rx) = std_mpsc::channel();
    let beat: Beat = Mutex::new(Some(RunnerMessage::Heartbeat { run: 5, load: None }));
    let (sent_tx, sent) = std_mpsc::channel();
    let load = HostLoad {
        avg1: 44.0,
        cores: 4,
    };
    std::thread::scope(|s| {
        s.spawn(|| {
            pump(
                rx,
                &beat,
                Duration::from_millis(20),
                || Some(load),
                |msg| sent_tx.send(msg.clone()).is_ok(),
                || true,
            )
        });
        frames
            .send(Frame::Send(RunnerMessage::Ready { workspaces: vec![] }))
            .unwrap();
        let first = sent.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(first, RunnerMessage::Ready { .. }));
        for _ in 0..3 {
            let beat = sent.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(
                beat,
                RunnerMessage::Heartbeat {
                    run: 5,
                    load: Some(load)
                }
            );
        }
        frames.send(Frame::Close).unwrap();
    });
}

/// A run's `RunEnded` is resent on the heartbeat clock, unchanged by the load (AIN-55).
#[test]
fn the_beat_resends_run_ended_and_nothing_once_there_is_no_run() {
    let (frames, rx) = std_mpsc::channel();
    let ended = RunnerMessage::RunEnded {
        run: 5,
        outcome: Outcome::Failed {
            reason: "crashed".to_owned(),
            fingerprint: None,
        },
    };
    let beat: Beat = Mutex::new(Some(ended.clone()));
    let (sent_tx, sent) = std_mpsc::channel();
    std::thread::scope(|s| {
        s.spawn(|| {
            pump(
                rx,
                &beat,
                Duration::from_millis(20),
                || None,
                |msg| sent_tx.send(msg.clone()).is_ok(),
                || true,
            )
        });
        assert_eq!(sent.recv_timeout(Duration::from_secs(2)).unwrap(), ended);
        *beat.lock().unwrap() = None;
        // Nothing more is sent while there is no run; the queue still closes the loop.
        assert!(sent.recv_timeout(Duration::from_millis(200)).is_err());
        frames.send(Frame::Close).unwrap();
    });
}

/// How long a test runner waits in silence: short, since the tests run in real time.
const TEST_SILENCE: Duration = Duration::from_secs(2);

/// Welcomes a fresh connection with a short lease (so the runner pings every second) and gets
/// past its hello and ready.
async fn welcomed(listener: &tokio::net::TcpListener) -> ServerWs {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    from_runner(&mut ws).await;
    let welcome = ServerMessage::Welcome {
        runner: 1,
        lease_ttl_secs: 3,
        limits: None,
        power_nap: None,
    };
    to_runner(&mut ws, welcome).await;
    assert!(matches!(
        from_runner(&mut ws).await,
        RunnerMessage::Ready { .. }
    ));
    ws
}

/// A server that stops talking leaves the runner with a dead socket that never errors; the
/// runner drops it after the silence limit and reconnects, with no restart.
#[tokio::test]
async fn a_silent_server_is_dropped_and_the_runner_reconnects() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/runner/v1/connect", listener.local_addr().unwrap());
    let gate = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(run_silenced(
        config(&url),
        Gated(gate.clone()),
        TEST_SILENCE,
    ));
    // Held but never read, so no pong comes back: the runner gives up on the socket.
    let _silent = welcomed(&listener).await;
    let (tcp, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
        .await
        .expect("the runner kept a silent socket open")
        .unwrap();
    let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
    assert!(matches!(
        from_runner(&mut ws).await,
        RunnerMessage::Hello { .. }
    ));
    gate.notify_one();
}

/// An idle runner pings each beat; a server that answers the pongs keeps it connected however
/// long it stays idle.
#[tokio::test]
async fn an_idle_runner_whose_server_answers_its_pings_stays_connected() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/runner/v1/connect", listener.local_addr().unwrap());
    let gate = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(run_silenced(
        config(&url),
        Gated(gate.clone()),
        TEST_SILENCE,
    ));
    let mut ws = welcomed(&listener).await;
    // Reading flushes the pong that answers each ping; a dropped socket ends the stream. Several
    // silence limits pass, so a pong that never counted would have dropped it.
    let quiet = tokio::time::timeout(TEST_SILENCE * 4, async {
        while let Some(msg) = ws.next().await {
            assert!(msg.is_ok(), "the connection failed: {msg:?}");
            ws.flush().await.unwrap();
        }
    })
    .await;
    assert!(quiet.is_err(), "a live idle connection was dropped");
    gate.notify_one();
}
