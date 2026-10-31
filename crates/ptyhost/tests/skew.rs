//! Version skew (E2-03.5): a runner of this build talks to a host started by the previous
//! build (host protocol 1 as it was before the disk ring), and an older runner to this host.
//! The golden lines in `tests/fixtures/` are what the previous host sent and the previous
//! runner sent; they are never regenerated from the current code, only checked against it.

mod support;
use std::path::PathBuf;
use std::time::Duration;
use support::TestDir;

use ainkrad_ptyhost::client::connect;
use ainkrad_ptyhost::host::{HostConfig, private_dir, random_hex, run};
use ainkrad_ptyhost::pty::{Spec, environment};
use ainkrad_ptyhost::screen::Raw;
use ainkrad_ptyhost::wire::{FromHost, ToHost};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

const FRAMES: &str = include_str!("fixtures/host_v1_frames.jsonl");
const CLIENT: &str = include_str!("fixtures/client_v1_messages.jsonl");
const ID: &str = "t_oldhost0000001";

/// The previous runner's view of a message from the host, frozen as it was.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(dead_code)]
enum V1FromHost {
    Hello {
        protocol: u32,
        info: V1Info,
    },
    Out {
        seq: u64,
        data: String,
    },
    Snapshot {
        seq: u64,
        data: String,
    },
    Exit {
        exit: serde_json::Value,
    },
    Error {
        message: String,
    },
    #[serde(other)]
    Unknown,
}
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct V1Info {
    id: String,
    pid: u32,
    boot: String,
    started: u64,
    child: Option<u32>,
    state: String,
    size: serde_json::Value,
    seq: u64,
}

/// The previous host's view of a message from the runner, frozen as it was.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum V1ToHost {
    Attach {
        seq: u64,
    },
    Input {
        data: String,
    },
    Resize {
        size: serde_json::Value,
    },
    Signal {
        signal: String,
    },
    Snapshot,
    Close {
        grace_ms: u64,
    },
    Ack,
    #[serde(other)]
    Unknown,
}

fn tmp() -> TestDir {
    let d = PathBuf::from(format!("/tmp/apk-{}", &random_hex().unwrap()[..8]));
    std::fs::create_dir_all(&d).unwrap();
    TestDir(d)
}

/// A host of the previous build: sends `lines[0]` at once and each later line after reading
/// one client message; returns every line the client sent.
fn old_host(dir: &std::path::Path, lines: Vec<String>) -> tokio::task::JoinHandle<Vec<String>> {
    private_dir(dir).unwrap();
    let listener = UnixListener::bind(dir.join(format!("{ID}.sock"))).unwrap();
    tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let (rd, mut wr) = s.into_split();
        let mut rd = BufReader::new(rd).lines();
        wr.write_all(format!("{}\n", lines[0]).as_bytes())
            .await
            .unwrap();
        let mut got = Vec::new();
        for l in &lines[1..] {
            if let Ok(Some(m)) = rd.next_line().await {
                got.push(m);
            }
            wr.write_all(format!("{l}\n").as_bytes()).await.unwrap();
        }
        while let Ok(Ok(Some(m))) =
            tokio::time::timeout(Duration::from_millis(300), rd.next_line()).await
        {
            got.push(m);
        }
        got
    })
}

/// The golden lines are exactly what this build's wire types read and write: a drift in
/// either direction fails here, before a deployed host does.
#[test]
fn the_golden_frames_match_the_current_wire_types() {
    for l in FRAMES.lines() {
        let m: FromHost = serde_json::from_str(l).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(l).unwrap(),
            serde_json::to_value(&m).unwrap(),
            "{l}"
        );
    }
    for l in CLIENT.lines() {
        let m: ToHost = serde_json::from_str(l).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(l).unwrap(),
            serde_json::to_value(&m).unwrap(),
            "{l}"
        );
    }
}

/// A runner of this build reads an old host's hello and frames, skips a frame type it does not
/// know and fields it does not know, and what it sends (including the new `shed`) parses in
/// the old host without an error: unknown messages are skipped, never fatal.
#[tokio::test]
async fn a_new_runner_talks_to_an_old_host() {
    let dir = tmp();
    let d = dir.join("t");
    let mut lines: Vec<String> = FRAMES.lines().map(str::to_owned).collect();
    // A frame type and extra fields another build might add: skipped. (The unknown frame goes
    // out together with the frame after it, as the fake host sends one group per message.)
    lines[2] = format!(
        "{}\n{}",
        r#"{"type":"telemetry","load":0.5,"note":"unknown to this build"}"#, lines[2]
    );
    lines[1] = lines[1].replacen('}', r#","extra":{"a":1}}"#, 1);
    let host = old_host(&d, lines);
    let (info, mut r, mut w) = connect(&d, ID).await.unwrap();
    assert_eq!(
        (info.id.as_str(), info.pid, info.child),
        (ID, 4242, Some(4243))
    );
    assert!(info.exit.is_none(), "an absent optional field is None");
    w.send(&ToHost::Attach { seq: 0 }).await.unwrap();
    match r.recv().await.unwrap().unwrap() {
        FromHost::Out { seq, data } => {
            assert_eq!(seq, 0);
            assert_eq!(STANDARD.decode(data).unwrap(), b"hello from the old host");
        }
        other => panic!("{other:?}"),
    }
    w.send(&ToHost::Shed).await.unwrap();
    assert!(
        matches!(
            r.recv().await.unwrap().unwrap(),
            FromHost::Snapshot { seq: 23, .. }
        ),
        "the unknown frame was skipped"
    );
    w.send(&ToHost::Snapshot).await.unwrap();
    assert!(matches!(
        r.recv().await.unwrap().unwrap(),
        FromHost::Error { .. }
    ));
    w.send(&ToHost::Ack).await.unwrap();
    assert!(matches!(
        r.recv().await.unwrap().unwrap(),
        FromHost::Exit { .. }
    ));
    drop((r, w));
    let got = host.await.unwrap();
    let parsed: Vec<V1ToHost> = got
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(parsed[0], V1ToHost::Attach { seq: 0 });
    assert_eq!(
        parsed[1],
        V1ToHost::Unknown,
        "shed is skipped by an old host"
    );
    assert_eq!(parsed[2], V1ToHost::Snapshot);
    assert_eq!(parsed[3], V1ToHost::Ack);
}

/// A host of a newer major is refused with a message that names its protocol, and a socket
/// that does not greet with a hello is refused too, never half-trusted.
#[tokio::test]
async fn a_newer_major_is_refused_clearly() {
    let dir = tmp();
    let d = dir.join("t");
    let hello = FRAMES
        .lines()
        .next()
        .unwrap()
        .replace("\"protocol\":1", "\"protocol\":2");
    let host = old_host(&d, vec![hello]);
    let e = connect(&d, ID).await.err().expect("refused");
    assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
    assert!(e.to_string().contains("protocol 2"), "{e}");
    host.abort();

    let dir2 = tmp();
    let d2 = dir2.join("t");
    let host = old_host(
        &d2,
        vec![r#"{"type":"error","message":"no hello first"}"#.to_owned()],
    );
    let e = connect(&d2, ID).await.err().expect("refused");
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    host.abort();
}

/// The other direction: an old runner reads everything a host of this build sends (its hello,
/// output and a snapshot) with its frozen types, and no frame is an error for it.
#[tokio::test]
async fn an_old_runner_reads_what_this_host_sends() {
    let dir = tmp();
    let d = dir.join("t");
    let id = ainkrad_ptyhost::client::new_id().unwrap();
    let spec = Spec {
        program: Some("/bin/sh".to_owned()),
        args: vec!["-c".to_owned(), "echo NEW-HOST; sleep 5".to_owned()],
        cwd: Some("/".to_owned()),
        env: environment(
            &std::env::vars_os().collect::<Vec<_>>(),
            &[],
            &[],
            &Default::default(),
        ),
        size: ainkrad_proto::v2::Size { rows: 24, cols: 80 },
        scrollback_bytes: None,
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    let reg = d.clone();
    tokio::spawn(run(
        HostConfig::new(d.clone(), id.clone()),
        spec,
        Box::new(Raw::new(4096)),
        move |i| {
            support::register(&reg, 0, i.child);
            let _ = tx.send(());
        },
    ));
    rx.await.unwrap();
    let s = tokio::net::UnixStream::connect(d.join(format!("{id}.sock")))
        .await
        .unwrap();
    let (rd, mut wr) = s.into_split();
    wr.write_all(b"{\"type\":\"attach\",\"seq\":0}\n{\"type\":\"snapshot\"}\n")
        .await
        .unwrap();
    let mut lines = BufReader::new(rd).lines();
    let (mut hello, mut out, mut snap) = (false, false, false);
    while !(hello && out && snap) {
        let l = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .expect("the host closed");
        match serde_json::from_str::<V1FromHost>(&l).unwrap() {
            V1FromHost::Hello { protocol, info } => {
                assert_eq!((protocol, info.id.as_str()), (1, id.as_str()));
                hello = true;
            }
            V1FromHost::Out { data, .. } => {
                out |=
                    String::from_utf8_lossy(&STANDARD.decode(data).unwrap()).contains("NEW-HOST");
            }
            V1FromHost::Snapshot { .. } => snap = true,
            V1FromHost::Exit { .. } | V1FromHost::Error { .. } | V1FromHost::Unknown => {}
        }
    }
}
