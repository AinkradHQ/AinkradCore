//! A fake Core driving `serve` over an in-memory WebSocket with v2 frames.

use std::time::Duration;

use ainkrad_proto::v2::{
    Close, Command, CoreWelcome, DriverInfo, ExecResult, ExecRun, NO_CHANNEL_BINDING, OP_EXEC_RUN,
    OP_NOOP, Reply, Rotation, rotation_message,
};
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};

use super::key::{Enrolment, Key, b64, fingerprint, unb64};
use tokio::io::DuplexStream;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::protocol::Role;

use super::exec::tests::{PLANTED, RUNNER_KEY, driver, sh};
use super::*;

struct Core {
    ws: WebSocketStream<DuplexStream>,
    runner: JoinHandle<Result<Option<u16>, StreamError>>,
    seq: u64,
    key: Key,
    enrolment: Arc<std::sync::Mutex<Enrolment>>,
    /// The runner's public key.
    runner_spki: Vec<u8>,
}

/// A fresh P-256 key, as a Core or a runner holds one.
pub(super) fn new_key() -> Key {
    let der = EcdsaKeyPair::generate_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &ring::rand::SystemRandom::new(),
    )
    .unwrap();
    Key::from_pkcs8(der.as_ref()).unwrap()
}

/// How the fake Core answers the hello.
#[derive(Clone, Copy, PartialEq)]
enum Answer {
    /// The pinned key over this connection's binding.
    Honest,
    /// Another key: a second Core.
    OtherCore,
    /// The pinned key, but over another session's exporter: a relayed `sig_core`.
    OtherSession,
}

impl Core {
    /// A runner with an `exec` driver of `capacity`, past its hello (returned) and our welcome.
    async fn start(capacity: u32) -> (Self, RunnerHello) {
        let (mut core, hello) = Self::connect(capacity).await;
        core.send(
            CONTROL_STREAM,
            Body::Control(Control::Welcome(CoreWelcome {
                protocol: PROTOCOL_VERSION.to_owned(),
                ..Default::default()
            })),
        )
        .await;
        (core, hello)
    }

    async fn connect(capacity: u32) -> (Self, RunnerHello) {
        let (mut core, hello) = Self::hello(capacity, None).await;
        core.answer_hello(&hello, Answer::Honest).await;
        let proof = core.recv().await;
        let Ok(Some(Body::Control(Control::Proof(_)))) = proof.body() else {
            panic!("expected the runner's proof, got {proof:?}")
        };
        (core, hello)
    }

    /// Up to the runner's hello, which is returned; `save` is where a rotated pin goes.
    async fn hello(capacity: u32, save: Option<std::path::PathBuf>) -> (Self, RunnerHello) {
        Self::hello_pty(capacity, save, None).await
    }

    /// A runner that also offers `pty`, past its hello and our welcome.
    async fn start_pty(pty: Arc<PtyDriver>) -> (Self, RunnerHello) {
        let (mut core, hello) = Self::hello_pty(1, None, Some(pty)).await;
        core.answer_hello(&hello, Answer::Honest).await;
        let proof = core.recv().await;
        assert!(matches!(
            proof.body(),
            Ok(Some(Body::Control(Control::Proof(_))))
        ));
        core.send(
            CONTROL_STREAM,
            Body::Control(Control::Welcome(CoreWelcome {
                protocol: PROTOCOL_VERSION.to_owned(),
                ..Default::default()
            })),
        )
        .await;
        (core, hello)
    }

    async fn hello_pty(
        capacity: u32,
        save: Option<std::path::PathBuf>,
        pty: Option<Arc<PtyDriver>>,
    ) -> (Self, RunnerHello) {
        let key = new_key();
        let enrolment = Arc::new(std::sync::Mutex::new(Enrolment {
            url: "http://127.0.0.1:1".to_owned(),
            device_id: "d_5v0v4qa7a8h2tb3219mtz5znvv".to_owned(),
            core_fp: key.fp(),
            rotation_seq: 0,
        }));
        let runner_key = Arc::new(new_key());
        let runner_spki = runner_key.spki.clone();
        let link = Link {
            key: runner_key,
            enrolment: Arc::clone(&enrolment),
            save,
            exporter: NO_CHANNEL_BINDING,
        };
        let (a, b) = tokio::io::duplex(1 << 16);
        let runner_ws = WebSocketStream::from_raw_socket(a, Role::Client, None).await;
        let exec = Arc::new(driver(capacity));
        let runner = tokio::spawn(async move {
            match pty {
                Some(p) => Session::new(exec).with_pty(p).serve(runner_ws, &link).await,
                None => serve(runner_ws, exec, &link).await,
            }
        });
        let ws = WebSocketStream::from_raw_socket(b, Role::Server, None).await;
        let mut core = Self {
            ws,
            runner,
            seq: 0,
            key,
            enrolment,
            runner_spki,
        };
        let first = core.recv().await;
        assert_eq!((first.stream_id, first.seq), (CONTROL_STREAM, 0));
        let Ok(Some(Body::Control(Control::Hello(hello)))) = first.body() else {
            panic!("first frame {first:?}")
        };
        (core, hello)
    }

    async fn answer_hello(&mut self, hello: &RunnerHello, how: Answer) {
        let nonce_r = unb64(hello.nonce.as_deref().unwrap(), 43).unwrap();
        let device = hello.device_id.as_deref().unwrap();
        let other = new_key();
        let (key, x) = match how {
            Answer::Honest => (&self.key, NO_CHANNEL_BINDING),
            Answer::OtherCore => (&other, NO_CHANNEL_BINDING),
            Answer::OtherSession => (&self.key, [9; 32]),
        };
        let sig = key.sign(&core_auth_message(&x, &nonce_r, device));
        let auth = CoreAuth {
            core_spki: b64(&key.spki),
            nonce: b64(&[3; 32]),
            sig: b64(&sig),
        };
        self.send(CONTROL_STREAM, Body::Control(Control::Auth(auth)))
            .await;
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
            ..DriverInfo::default()
        }]
    );
    core.send(1, Body::Command(Command::Noop)).await;
    assert_eq!(core.answer(1).await, Body::Result(Reply::Noop));
    // The Core closes: the runner returns.
    core.ws.close(None).await.unwrap();
    assert_eq!(core.runner.await.unwrap(), Ok(None));
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
        r#"{"stream_id":9,"kind":"command","seq":10,"payload":{"op":"vm.boot"}}"#,
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
async fn the_proof_signs_this_connection_for_the_pinned_core() {
    let (mut core, hello) = Core::hello(1, None).await;
    core.answer_hello(&hello, Answer::Honest).await;
    let proof = core.recv().await;
    let Ok(Some(Body::Control(Control::Proof(p)))) = proof.body() else {
        panic!("{proof:?}")
    };
    let message = runner_auth_message(&NO_CHANNEL_BINDING, &[3; 32], &core.key.fp());
    let sig = unb64(&p.sig, 86).unwrap();
    assert!(key::verify(&core.runner_spki, &message, &sig));
    assert!(!key::verify(&core.runner_spki, &message[1..], &sig));
    assert_eq!(
        hello.device_id.as_deref(),
        Some("d_5v0v4qa7a8h2tb3219mtz5znvv")
    );
}

/// Handshake spec §17 tests 27 and 28: a second Core, or the pinned Core's signature from
/// another TLS session, is refused with `core_identity_mismatch`, and the runner sends nothing
/// after its hello.
#[tokio::test]
async fn another_core_or_a_relayed_proof_is_refused_and_nothing_more_is_sent() {
    for how in [Answer::OtherCore, Answer::OtherSession] {
        let (mut core, hello) = Core::hello(1, None).await;
        core.answer_hello(&hello, how).await;
        let e = core.runner.await.unwrap().unwrap_err();
        assert_eq!(e.code, ErrorCode::CoreIdentityMismatch);
        let after = tokio::time::timeout(Duration::from_secs(5), core.ws.next())
            .await
            .unwrap();
        assert!(
            !matches!(after, Some(Ok(Message::Text(_)))),
            "nothing after the hello: {after:?}"
        );
    }
}

/// Handshake spec §17 test 29: a statement signed by the pinned key moves the pin (and saves
/// it); one signed by another key, one for another pin, or an old one is ignored.
#[tokio::test]
async fn a_rotation_by_the_pinned_key_moves_the_pin_and_anything_else_is_ignored() {
    let dir = std::env::temp_dir().join(format!("runner-rotate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let save = dir.join("enrolment.json");
    let (mut core, hello) = Core::hello(1, Some(save.clone())).await;
    core.answer_hello(&hello, Answer::Honest).await;
    core.recv().await;
    core.send(
        CONTROL_STREAM,
        Body::Control(Control::Welcome(CoreWelcome {
            protocol: PROTOCOL_VERSION.to_owned(),
            ..Default::default()
        })),
    )
    .await;
    let old = core.key.fp();
    let next = new_key();
    let statement = |signer: &Key, old_fp: &str, seq| {
        let mut r = Rotation {
            old_fp: old_fp.to_owned(),
            new_fp: fingerprint(&next.spki),
            not_before: 1,
            seq,
            sig: String::new(),
        };
        r.sig = b64(&signer.sign(&rotation_message(&r)));
        Body::Control(Control::Rotation(r))
    };
    let stranger = new_key();
    core.send(CONTROL_STREAM, statement(&stranger, &old, 1))
        .await;
    core.send(CONTROL_STREAM, statement(&core.key, &stranger.fp(), 1))
        .await;
    // A noop round trip: every frame before it was handled.
    core.send(1, Body::Command(Command::Noop)).await;
    core.answer(1).await;
    assert_eq!(core.enrolment.lock().unwrap().core_fp, old, "ignored");
    assert!(!save.exists());

    core.send(CONTROL_STREAM, statement(&core.key, &old, 1))
        .await;
    core.send(3, Body::Command(Command::Noop)).await;
    core.answer(3).await;
    let moved = core.enrolment.lock().unwrap().clone();
    assert_eq!(
        (moved.core_fp.as_str(), moved.rotation_seq),
        (fingerprint(&next.spki).as_str(), 1)
    );
    assert_eq!(Enrolment::load(&save).unwrap(), moved, "saved");
    // Replayed, or signed by the old key after the move: the pin stays.
    core.send(CONTROL_STREAM, statement(&core.key, &old, 1))
        .await;
    core.send(5, Body::Command(Command::Noop)).await;
    core.answer(5).await;
    assert_eq!(core.enrolment.lock().unwrap().rotation_seq, 1);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn a_core_of_another_major_or_a_refusal_ends_the_session() {
    let (mut core, _) = Core::connect(1).await;
    let welcome = CoreWelcome {
        protocol: "3.0".to_owned(),
        ..Default::default()
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

/// Security review RH1: a Core frame whose `seq` has no successor is refused as `bad_frame`
/// on its stream, and the session carries on.
#[tokio::test]
async fn a_seq_at_its_maximum_is_refused_and_the_session_serves_on() {
    let (mut core, _) = Core::start(1).await;
    let hostile = Frame::new(1, u64::MAX, Body::Command(Command::Noop));
    let text = serde_json::to_string(&hostile).unwrap();
    core.ws.send(Message::Text(text.into())).await.unwrap();
    assert_eq!(error(core.answer(1).await), ErrorCode::BadFrame);
    core.send(3, Body::Command(Command::Noop)).await;
    assert_eq!(core.answer(3).await, Body::Result(Reply::Noop));
}

mod pty {
    //! The `pty` driver through the session (E2-02, E2-03), with the real `ainkrad-ptyhost`.

    use ainkrad_proto::v2::{
        Credit, OP_PTY_ATTACH, OP_PTY_CLOSE, OP_PTY_OPEN, Output, PtyAttach, PtyClose, PtyOpen,
        STREAM_WINDOW, Size, TerminalExit,
    };
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    fn driver(dir: &std::path::Path, enabled: bool) -> Arc<PtyDriver> {
        let host = ainkrad_ptyhost::client::find_host_binary()
            .expect("ainkrad-ptyhost is built next to the tests (cargo test --workspace)");
        Arc::new(PtyDriver::new(PtyConfig {
            enabled,
            capacity: 4,
            host,
            grace: Duration::from_millis(200),
            ..PtyConfig::new(dir.to_path_buf())
        }))
    }

    fn tmp() -> std::path::PathBuf {
        let r = b64(&super::super::key::random::<6>()).replace(['-', '_'], "x");
        std::path::PathBuf::from(format!("/tmp/apr-{r}"))
    }

    fn open(script: &str) -> Body {
        Body::Command(Command::PtyOpen(PtyOpen {
            program: Some("/bin/sh".to_owned()),
            args: vec!["-c".to_owned(), script.to_owned()],
            cwd: Some("/".to_owned()),
            env: Default::default(),
            env_pass: vec![],
            size: Size { rows: 24, cols: 80 },
        }))
    }

    /// Frames on `stream` until `done` says so of the output read so far (and the frame).
    async fn until(
        core: &mut Core,
        stream: u64,
        out: &mut String,
        done: impl Fn(&str, &Body) -> bool,
    ) -> Body {
        loop {
            let f = core.recv().await;
            if f.stream_id != stream {
                continue;
            }
            let b = f.body().unwrap().unwrap();
            if let Body::Output(Output { data }) = &b {
                out.push_str(&String::from_utf8_lossy(&STANDARD.decode(data).unwrap()));
            }
            if done(out, &b) {
                return b;
            }
        }
    }

    fn input(text: &str) -> Body {
        Body::Output(Output {
            data: STANDARD.encode(text),
        })
    }

    #[tokio::test]
    async fn pty_is_off_unless_enabled() {
        let (mut core, hello) = Core::start(1).await;
        assert!(hello.drivers.iter().all(|d| d.name != "pty"));
        core.send(1, open("true")).await;
        assert_eq!(error(core.answer(1).await), ErrorCode::UnsupportedCommand);
        let (mut core, hello) = Core::start_pty(driver(&tmp(), false)).await;
        assert!(hello.drivers.iter().all(|d| d.name != "pty"));
        core.send(1, open("true")).await;
        assert_eq!(error(core.answer(1).await), ErrorCode::UnsupportedCommand);
    }

    /// Open, type, detach (the terminal keeps running), a new runner session re-announces it
    /// in its hello, attach resumes from byte 0, close answers the exit on both streams.
    #[tokio::test]
    async fn a_terminal_outlives_its_stream_and_its_session() {
        let dir = tmp();
        let (mut core, hello) = Core::start_pty(driver(&dir, true)).await;
        let pty = hello.drivers.iter().find(|d| d.name == "pty").unwrap();
        assert_eq!(pty.commands, [OP_PTY_OPEN, OP_PTY_ATTACH, OP_PTY_CLOSE]);
        core.send(1, open("echo UP; while read l; do echo \"got $l\"; done"))
            .await;
        let mut out = String::new();
        let Body::Control(Control::Opened(info)) = until(&mut core, 1, &mut out, |_, _| true).await
        else {
            panic!("opened first")
        };
        let id = info.terminal;
        until(&mut core, 1, &mut out, |o, _| o.contains("UP")).await;
        core.send(1, input("ping\n")).await;
        until(&mut core, 1, &mut out, |o, _| o.contains("got ping")).await;
        core.send(1, Body::Close(Close::default())).await;
        let detached = until(&mut core, 1, &mut out, |_, b| matches!(b, Body::Error(_))).await;
        assert_eq!(error(detached), ErrorCode::Cancelled);

        // A restarted runner: a new session over the same terminal directory.
        let (mut core, hello) = Core::start_pty(driver(&dir, true)).await;
        assert_eq!(hello.terminals.len(), 1, "{hello:?}");
        assert_eq!(hello.terminals[0].terminal, id);
        assert!(hello.terminals[0].seq > 0);
        core.send(
            3,
            Body::Command(Command::PtyAttach(PtyAttach {
                terminal: id.clone(),
                seq: 0,
            })),
        )
        .await;
        let mut out = String::new();
        until(&mut core, 3, &mut out, |o, _| o.contains("got ping")).await;
        assert!(out.starts_with("UP"), "{out:?}");
        core.send(
            5,
            Body::Command(Command::PtyClose(PtyClose {
                terminal: id.clone(),
            })),
        )
        .await;
        let (mut closed, mut attach_end) = (None, None);
        while closed.is_none() || attach_end.is_none() {
            let f = core.recv().await;
            match (f.stream_id, f.body().unwrap().unwrap()) {
                (5, b @ (Body::Result(_) | Body::Error(_))) => closed = Some(b),
                (3, b @ (Body::Result(_) | Body::Error(_))) => attach_end = Some(b),
                _ => {}
            }
        }
        let Some(Body::Result(Reply::PtyClose(TerminalExit {
            terminal,
            exit_code,
            ..
        }))) = closed
        else {
            panic!("{closed:?}")
        };
        assert_eq!((terminal.as_str(), exit_code), (id.as_str(), None));
        assert!(
            matches!(attach_end, Some(Body::Result(Reply::PtyAttach(_)))),
            "{attach_end:?}"
        );
        let (_, hello) = Core::start_pty(driver(&dir, true)).await;
        assert!(hello.terminals.is_empty(), "reaped: {hello:?}");
    }

    /// E2-01.4 on the wire: with no credit from the Core, a flood sends at most the window and
    /// is cut to a snapshot rather than buffered without bound; credit lets output flow again.
    #[tokio::test]
    async fn output_respects_credit_and_a_flood_becomes_a_snapshot() {
        let dir = tmp();
        let (mut core, _) = Core::start_pty(driver(&dir, true)).await;
        core.send(
            1,
            open("while :; do echo 0123456789abcdefghijklmnopqrstuvwxyz; done"),
        )
        .await;
        let (mut bytes, mut snapshot) = (0u64, None);
        let mut granted = false;
        while snapshot.is_none() {
            // The window is spent and the flood keeps coming: no snapshot goes without credit
            // (it costs credit too); one more grant brings it.
            if bytes == STREAM_WINDOW && !granted {
                tokio::time::sleep(Duration::from_millis(500)).await;
                core.send(1, Body::Credit(Credit { bytes: 4096 })).await;
                granted = true;
            }
            let f = core.recv().await;
            match f.body().unwrap().unwrap() {
                Body::Output(Output { data }) => {
                    bytes += STANDARD.decode(data).unwrap().len() as u64
                }
                Body::Control(Control::Snapshot(s)) => snapshot = Some(s),
                _ => {}
            }
        }
        assert!(bytes <= STREAM_WINDOW + 4096, "{bytes} past the credit");
        assert!(snapshot.unwrap().seq > bytes);
        // More credit: the stream carries on (output, or another snapshot under the flood).
        core.send(1, Body::Credit(Credit { bytes: 65536 })).await;
        let mut more = String::new();
        until(&mut core, 1, &mut more, |o, b| {
            !o.is_empty() || matches!(b, Body::Control(Control::Snapshot(_)))
        })
        .await;
        core.send(
            3,
            Body::Command(Command::PtyClose(PtyClose {
                terminal: ainkrad_ptyhost::client::scan(&dir).await[0].id.clone(),
            })),
        )
        .await;
        until(&mut core, 3, &mut more, |_, b| matches!(b, Body::Result(_))).await;
    }
}
