//! Golden frames (E1-11.1): v1 and v2 messages pinned byte for byte in `tests/golden/`.
//! Each value must encode to its file exactly, and the file must decode to the value and
//! re-encode to the same bytes. Any change to the wire fails here; a deliberate, additive one
//! is re-pinned with `UPDATE_GOLDEN=1 cargo test -p ainkrad-proto --test golden`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ainkrad_proto::runner::{self, Outcome, Policy, RunToken, RunnerMessage, ServerMessage};
use ainkrad_proto::v2::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

fn check<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(
    dir: &str,
    name: &str,
    value: T,
) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/golden/{dir}/{name}.json"));
    let encoded = serde_json::to_string(&value).unwrap() + "\n";
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &encoded).unwrap();
    }
    let pinned = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    assert_eq!(encoded, pinned, "{dir}/{name} encodes differently");
    let decoded: T = serde_json::from_str(&pinned).unwrap();
    assert_eq!(decoded, value, "{dir}/{name} decodes differently");
    assert_eq!(serde_json::to_string(&decoded).unwrap() + "\n", pinned);
}

#[test]
fn v1_messages_are_pinned() {
    let v1 = |name, msg| check("v1", name, msg);
    v1(
        "hello",
        RunnerMessage::Hello {
            protocol: runner::PROTOCOL_VERSION.to_owned(),
            runner_version: "0.1.0".to_owned(),
            tags: vec!["linux".to_owned()],
            harnesses: BTreeMap::from([("claude".to_owned(), "2.1.306".to_owned())]),
            runs: vec![7],
            disk: None,
            info: None,
            os: Some("linux".to_owned()),
            arch: Some("aarch64".to_owned()),
        },
    );
    v1(
        "ready",
        RunnerMessage::Ready {
            workspaces: vec![3],
        },
    );
    v1("heartbeat", RunnerMessage::Heartbeat { run: 7, load: None });
    v1(
        "run_event",
        RunnerMessage::RunEvent {
            run: 7,
            seq: 1,
            payload: json!({"type": "assistant_text", "text": "hi"}),
        },
    );
    v1(
        "run_ended",
        RunnerMessage::RunEnded {
            run: 7,
            outcome: Outcome::Failed {
                reason: "build broke".to_owned(),
                fingerprint: None,
            },
        },
    );
    let v1s = |name, msg| check::<ServerMessage>("v1", name, msg);
    v1s(
        "welcome",
        ServerMessage::Welcome {
            runner: 1,
            lease_ttl_secs: 60,
            limits: None,
            power_nap: None,
        },
    );
    v1s(
        "assign",
        ServerMessage::Assign {
            run: 7,
            agent: 2,
            issue: Some(9),
            harness: "claude".to_owned(),
            model: "opus".to_owned(),
            context_ref: "ctx".to_owned(),
            workspace: None,
            token_cap: Some(1000),
            token_caps: None,
            policy: Policy::default(),
            issue_key: None,
            instructions: None,
            account: None,
            fallbacks: vec![],
            limits: None,
            resume_session: None,
            prompt: None,
        },
    );
    v1s(
        "token",
        ServerMessage::Token {
            run: 7,
            token: RunToken::new("cit_run_x".to_owned()),
        },
    );
    v1s(
        "cancel",
        ServerMessage::Cancel {
            run: 7,
            reason: "stop".to_owned(),
        },
    );
}

/// v1 has no catch-all: an unknown `type` is a decode error, and an unknown field is ignored.
#[test]
fn v1_unknown_type_is_refused_and_unknown_fields_ignored() {
    assert!(serde_json::from_str::<ServerMessage>(r#"{"type":"from_the_future"}"#).is_err());
    let msg: ServerMessage =
        serde_json::from_str(r#"{"type":"ack","run":7,"from_the_future":true}"#).unwrap();
    assert_eq!(msg, ServerMessage::Ack { run: 7 });
}

#[test]
fn v2_frames_are_pinned() {
    let v2 = |name, stream, seq, body| check("v2", name, Frame::new(stream, seq, body));
    v2(
        "hello",
        CONTROL_STREAM,
        0,
        Body::Control(Control::Hello(RunnerHello {
            protocol: PROTOCOL_VERSION.to_owned(),
            runner_version: "0.1.0".to_owned(),
            drivers: vec![DriverInfo {
                name: "exec".to_owned(),
                commands: vec![OP_NOOP.to_owned(), OP_EXEC_RUN.to_owned()],
                capacity: 4,
                ..Default::default()
            }],
            os: Some("linux".to_owned()),
            arch: Some("aarch64".to_owned()),
            ..Default::default()
        })),
    );
    v2(
        "hello_auth",
        CONTROL_STREAM,
        0,
        Body::Control(Control::Hello(RunnerHello {
            protocol: PROTOCOL_VERSION.to_owned(),
            runner_version: "0.1.0".to_owned(),
            drivers: vec![],
            os: None,
            arch: None,
            device_id: Some("d_5v0v4qa7a8h2tb3219mtz5znvv".to_owned()),
            nonce: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8".to_owned()),
            ..Default::default()
        })),
    );
    v2(
        "auth",
        CONTROL_STREAM,
        1,
        Body::Control(Control::Auth(CoreAuth {
            core_spki: "MFkw…".to_owned(),
            nonce: "nonce_c".to_owned(),
            sig: "sig_core".to_owned(),
        })),
    );
    v2(
        "proof",
        CONTROL_STREAM,
        1,
        Body::Control(Control::Proof(RunnerProof {
            sig: "sig_runner".to_owned(),
        })),
    );
    v2(
        "rotation",
        CONTROL_STREAM,
        3,
        Body::Control(Control::Rotation(Rotation {
            old_fp: "old".to_owned(),
            new_fp: "new".to_owned(),
            not_before: 1761730000,
            seq: 1,
            sig: "sig_old".to_owned(),
        })),
    );
    v2(
        "welcome",
        CONTROL_STREAM,
        0,
        Body::Control(Control::Welcome(CoreWelcome {
            protocol: PROTOCOL_VERSION.to_owned(),
            ..Default::default()
        })),
    );
    v2(
        "hello_resume",
        CONTROL_STREAM,
        0,
        Body::Control(Control::Hello(RunnerHello {
            protocol: PROTOCOL_VERSION.to_owned(),
            runner_version: "0.1.0".to_owned(),
            boot: Some("b_runner".to_owned()),
            streams: vec![StreamState {
                stream_id: 3,
                received: 1,
            }],
            ..Default::default()
        })),
    );
    v2(
        "welcome_resume",
        CONTROL_STREAM,
        1,
        Body::Control(Control::Welcome(CoreWelcome {
            protocol: PROTOCOL_VERSION.to_owned(),
            boot: Some("b_core".to_owned()),
            heartbeat_ms: Some(15000),
            streams: vec![StreamState {
                stream_id: 3,
                received: 0,
            }],
        })),
    );
    v2("heartbeat", CONTROL_STREAM, 1, Body::Heartbeat);
    v2("command_noop", 1, 0, Body::Command(Command::Noop));
    v2("result_noop", 1, 0, Body::Result(Reply::Noop));
    v2(
        "command_exec",
        3,
        0,
        Body::Command(Command::ExecRun(ExecRun {
            program: "/bin/echo".to_owned(),
            args: vec!["hi".to_owned()],
            cwd: Some("/tmp".to_owned()),
            env: BTreeMap::from([("LANG".to_owned(), "C".to_owned())]),
            env_pass: vec!["PATH".to_owned()],
            limits: ExecLimits {
                timeout_ms: Some(5000),
                max_output_bytes: Some(65536),
            },
        })),
    );
    v2(
        "result_exec",
        3,
        0,
        Body::Result(Reply::ExecRun(ExecResult {
            exit_code: Some(0),
            timed_out: false,
            duration_ms: 12,
            stdout: Captured {
                text: "hi\n".to_owned(),
                bytes: 3,
                truncated: false,
            },
            stderr: Captured::default(),
        })),
    );
    v2(
        "output",
        5,
        2,
        Body::Output(Output {
            data: "aGkK".to_owned(),
        }),
    );
    v2("credit", 5, 1, Body::Credit(Credit { bytes: 65536 }));
    v2("close", 3, 1, Body::Close(Close::default()));
    v2(
        "error",
        3,
        1,
        Body::Error(StreamError::new(ErrorCode::Busy, "exec is at capacity (4)")),
    );
}

/// The two-stage decode in every case a newer peer can produce.
#[test]
fn v2_reads_what_a_newer_peer_sends() {
    let frame = |s: &str| serde_json::from_str::<Frame>(s).unwrap();
    // An unknown kind decodes and is skipped.
    let f = frame(r#"{"stream_id":7,"kind":"resize","seq":0,"payload":{"cols":80}}"#);
    assert_eq!(f.kind, FrameKind::Unknown);
    assert_eq!(f.body(), Ok(None));
    // Unknown fields, in the frame and in a payload, are ignored.
    let f = frame(
        r#"{"stream_id":1,"kind":"command","seq":0,"lane":"x","payload":{"op":"noop","nice":5}}"#,
    );
    assert_eq!(f.body(), Ok(Some(Body::Command(Command::Noop))));
    // An unknown op, control type and error code each have a catch-all.
    let f =
        frame(r#"{"stream_id":1,"kind":"command","seq":0,"payload":{"op":"pty.open","cols":80}}"#);
    assert_eq!(f.body(), Ok(Some(Body::Command(Command::Unknown))));
    let f =
        frame(r#"{"stream_id":5,"kind":"control","seq":3,"payload":{"type":"resize","cols":80}}"#);
    assert_eq!(f.body(), Ok(Some(Body::Control(Control::Unknown))));
    let f =
        frame(r#"{"stream_id":1,"kind":"error","seq":0,"payload":{"code":"quota","message":"m"}}"#);
    let Ok(Some(Body::Error(e))) = f.body() else {
        panic!("{f:?}")
    };
    assert_eq!(e.code, ErrorCode::Unknown);
    // A payload that does not fit its kind is `bad_frame`, not a dead connection.
    let f = frame(r#"{"stream_id":1,"kind":"credit","seq":0,"payload":{"bytes":"many"}}"#);
    assert_eq!(f.body().unwrap_err().code, ErrorCode::BadFrame);
    // A close may come without a payload.
    let f = frame(r#"{"stream_id":1,"kind":"close","seq":1}"#);
    assert_eq!(f.body(), Ok(Some(Body::Close(Close::default()))));
}

/// Agent sessions (E2-08): the `agent` driver's ops, and a driver with slots and streams.
#[test]
fn v2_agent_frames_are_pinned() {
    let v2 = |name, stream, seq, body| check("v2", name, Frame::new(stream, seq, body));
    v2(
        "hello_agent",
        CONTROL_STREAM,
        0,
        Body::Control(Control::Hello(RunnerHello {
            protocol: PROTOCOL_VERSION.to_owned(),
            runner_version: "0.1.0".to_owned(),
            drivers: vec![DriverInfo {
                name: AGENT_DRIVER.to_owned(),
                commands: AGENT_OPS.iter().map(|o| (*o).to_owned()).collect(),
                capacity: 2,
                slots: BTreeMap::from([("claude".to_owned(), 2), ("codex".to_owned(), 1)]),
                streams: Some(12),
            }],
            ..Default::default()
        })),
    );
    v2(
        "agent_start",
        5,
        0,
        Body::Command(Command::AgentStart(AgentStart {
            session: "as_a".to_owned(),
            harness: "claude".to_owned(),
            model: Some("haiku".to_owned()),
            prompt: Some("fix the bug".to_owned()),
            workspace: None,
            policy: Policy::default(),
            resume: Some("h-1".to_owned()),
            secrets: vec![SecretGrant {
                lease: "l_lease".to_owned(),
                var: "GH_TOKEN".to_owned(),
            }],
        })),
    );
    v2(
        "agent_read",
        7,
        0,
        Body::Command(Command::AgentRead(AgentRead {
            session: "as_a".to_owned(),
            after: 3,
            wait_ms: Some(20000),
        })),
    );
    v2(
        "agent_events",
        7,
        0,
        Body::Result(Reply::AgentRead(AgentEvents {
            session: "as_a".to_owned(),
            state: AgentState::Ended,
            last_seq: 4,
            entries: vec![TranscriptEntry {
                seq: 4,
                at: 1761730000000,
                body: json!({"type": "ended", "outcome": {"kind": "succeeded"}}),
            }],
            harness_session: Some("h-1".to_owned()),
            usage: Some(runner::Tokens {
                input: 10,
                output: 20,
                ..Default::default()
            }),
            outcome: Some(Outcome::Succeeded),
        })),
    );
    v2(
        "agent_decide",
        9,
        0,
        Body::Command(Command::AgentDecide(AgentDecide {
            session: "as_a".to_owned(),
            request: "t1".to_owned(),
            approved: false,
            reply: Some("not on main".to_owned()),
        })),
    );
    v2(
        "agent_stop",
        11,
        0,
        Body::Command(Command::AgentStop(AgentStop {
            session: "as_a".to_owned(),
            kill: true,
        })),
    );
}
