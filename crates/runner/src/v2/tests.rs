//! A fake Core driving `serve` over an in-memory WebSocket with v2 frames.

use std::time::Duration;

use ainkrad_proto::v2::{
    Close, CoreWelcome, DriverInfo, ExecResult, ExecRun, OP_EXEC_RUN, OP_NOOP,
};
use tokio::io::DuplexStream;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::protocol::Role;

use super::exec::tests::{PLANTED, RUNNER_KEY, driver, sh};
use super::*;

struct Core {
    ws: WebSocketStream<DuplexStream>,
    runner: JoinHandle<Result<(), StreamError>>,
    seq: u64,
}

impl Core {
    /// A runner with an `exec` driver of `capacity`, past its hello (returned) and our welcome.
    async fn start(capacity: u32) -> (Self, RunnerHello) {
        let (mut core, hello) = Self::connect(capacity).await;
        core.send(
            CONTROL_STREAM,
            Body::Control(Control::Welcome(CoreWelcome {
                protocol: PROTOCOL_VERSION.to_owned(),
            })),
        )
        .await;
        (core, hello)
    }

    async fn connect(capacity: u32) -> (Self, RunnerHello) {
        let (a, b) = tokio::io::duplex(1 << 16);
        let runner_ws = WebSocketStream::from_raw_socket(a, Role::Client, None).await;
        let runner = tokio::spawn(serve(runner_ws, Arc::new(driver(capacity))));
        let ws = WebSocketStream::from_raw_socket(b, Role::Server, None).await;
        let mut core = Self { ws, runner, seq: 0 };
        let first = core.recv().await;
        assert_eq!((first.stream_id, first.seq), (CONTROL_STREAM, 0));
        let Ok(Some(Body::Control(Control::Hello(hello)))) = first.body() else {
            panic!("first frame {first:?}")
        };
        (core, hello)
    }

    async fn send(&mut self, stream: u64, body: Body) {
        self.seq += 1;
        let text = serde_json::to_string(&Frame::new(stream, self.seq, body)).unwrap();
        self.ws.send(Message::Text(text.into())).await.unwrap();
    }

    async fn recv(&mut self) -> Frame {
        let msg = tokio::time::timeout(Duration::from_secs(10), self.ws.next())
            .await
            .expect("a frame in time")
            .expect("open")
            .expect("ok");
        serde_json::from_str(msg.to_text().unwrap()).unwrap()
    }

    /// The answer on `stream`: its only frame, numbered 0.
    async fn answer(&mut self, stream: u64) -> Body {
        let f = self.recv().await;
        assert_eq!((f.stream_id, f.seq), (stream, 0), "{f:?}");
        f.body().unwrap().unwrap()
    }

    async fn exec(&mut self, stream: u64, req: ExecRun) {
        self.send(stream, Body::Command(Command::ExecRun(req)))
            .await;
    }
}

fn result(body: Body) -> ExecResult {
    match body {
        Body::Result(Reply::ExecRun(r)) => r,
        other => panic!("{other:?}"),
    }
}

fn error(body: Body) -> ErrorCode {
    match body {
        Body::Error(e) => e.code,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn hello_lists_the_exec_driver_and_its_capacity_then_noop_answers() {
    let (mut core, hello) = Core::start(3).await;
    assert_eq!(hello.protocol, PROTOCOL_VERSION);
    assert_eq!(
        hello.drivers,
        vec![DriverInfo {
            name: "exec".to_owned(),
            commands: vec![OP_NOOP.to_owned(), OP_EXEC_RUN.to_owned()],
            capacity: 3,
        }]
    );
    core.send(1, Body::Command(Command::Noop)).await;
    assert_eq!(core.answer(1).await, Body::Result(Reply::Noop));
    // The Core closes: the runner returns.
    core.ws.close(None).await.unwrap();
    assert_eq!(core.runner.await.unwrap(), Ok(()));
}

#[tokio::test]
async fn exec_returns_exit_and_redacted_output() {
    let (mut core, _) = Core::start(1).await;
    let script = format!("echo out {RUNNER_KEY}; echo err >&2; exit 4");
    core.exec(1, sh(&script, 5_000, None)).await;
    let r = result(core.answer(1).await);
    assert_eq!(r.exit_code, Some(4));
    assert_eq!(r.stdout.text, "out [redacted:runner_key]\n");
    assert_eq!(r.stderr.text, "err\n");
    assert!(!r.timed_out);
}

#[tokio::test]
async fn exec_is_killed_at_its_timeout() {
    let (mut core, _) = Core::start(1).await;
    core.exec(1, sh("echo started; sleep 30", 200, None)).await;
    let r = result(core.answer(1).await);
    assert!(r.timed_out);
    assert_eq!(r.exit_code, None);
    assert_eq!(r.stdout.text, "started\n");
    assert!(r.duration_ms < 5_000);
}

#[tokio::test]
async fn exec_output_is_cut_at_its_limit() {
    let (mut core, _) = Core::start(1).await;
    core.exec(
        1,
        sh("head -c 50000 /dev/zero | tr '\\0' b", 5_000, Some(100)),
    )
    .await;
    let r = result(core.answer(1).await);
    assert!(r.stdout.truncated);
    assert_eq!(r.stdout.bytes, 50_000);
    assert_eq!(
        r.stdout.text.len(),
        100 + ainkrad_proto::v2::TRUNCATED_MARKER.len()
    );
}

#[tokio::test]
async fn close_cancels_a_running_command_and_frees_its_slot() {
    let (mut core, _) = Core::start(1).await;
    core.exec(1, sh("sleep 30", 60_000, None)).await;
    // Capacity 1: a second command is busy at once.
    core.exec(3, sh("true", 1_000, None)).await;
    assert_eq!(error(core.answer(3).await), ErrorCode::Busy);
    core.send(1, Body::Close(Close::default())).await;
    assert_eq!(error(core.answer(1).await), ErrorCode::Cancelled);
    core.exec(5, sh("echo again", 5_000, None)).await;
    assert_eq!(result(core.answer(5).await).stdout.text, "again\n");
}

#[tokio::test]
async fn the_planted_env_secret_never_reaches_the_child() {
    let (mut core, _) = Core::start(1).await;
    let mut req = sh("env", 5_000, None);
    req.env_pass = vec!["AWS_SECRET_ACCESS_KEY".to_owned()];
    core.exec(1, req).await;
    let r = result(core.answer(1).await);
    assert!(!r.stdout.text.contains(PLANTED), "{}", r.stdout.text);
    assert!(!r.stdout.text.contains("AWS_SECRET_ACCESS_KEY"));
}

#[tokio::test]
async fn unknown_or_misplaced_commands_are_refused_and_unknown_kinds_skipped() {
    let (mut core, _) = Core::start(1).await;
    // A newer kind and a newer command op, as a newer Core would send them.
    let raw = [
        r#"{"stream_id":7,"kind":"resize","seq":9,"payload":{"cols":80}}"#,
        r#"{"stream_id":9,"kind":"command","seq":10,"payload":{"op":"pty.open"}}"#,
    ];
    for text in raw {
        core.ws.send(Message::Text(text.into())).await.unwrap();
    }
    assert_eq!(error(core.answer(9).await), ErrorCode::UnsupportedCommand);
    // Even streams are the runner's to open.
    core.send(2, Body::Command(Command::Noop)).await;
    assert_eq!(error(core.answer(2).await), ErrorCode::BadFrame);
    // Still serving.
    core.send(11, Body::Command(Command::Noop)).await;
    assert_eq!(core.answer(11).await, Body::Result(Reply::Noop));
}

#[tokio::test]
async fn a_core_of_another_major_or_a_refusal_ends_the_session() {
    let (mut core, _) = Core::connect(1).await;
    let welcome = CoreWelcome {
        protocol: "3.0".to_owned(),
    };
    core.send(CONTROL_STREAM, Body::Control(Control::Welcome(welcome)))
        .await;
    let e = core.runner.await.unwrap().unwrap_err();
    assert_eq!(e.code, ErrorCode::UnsupportedVersion);

    let (mut core, _) = Core::connect(1).await;
    let refusal = StreamError::new(ErrorCode::UnsupportedVersion, "speak 2");
    core.send(CONTROL_STREAM, Body::Error(refusal.clone()))
        .await;
    assert_eq!(core.runner.await.unwrap(), Err(refusal));
}
