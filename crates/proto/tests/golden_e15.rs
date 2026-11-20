//! Golden frames for protocol 2.1 (E15: hardware, sync, jobs, `gateway.call`), pinned byte for byte
//! in `tests/golden/v2/e15/` as `golden.rs` pins the older ones. Re-pin a deliberate, additive change
//! with `UPDATE_GOLDEN=1 cargo test -p ainkrad-proto --test golden_e15`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ainkrad_proto::v2::*;
use serde_json::json;

fn check(name: &str, value: Frame) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("tests/golden/v2/e15/{name}.json"));
    let encoded = serde_json::to_string(&value).unwrap() + "\n";
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &encoded).unwrap();
    }
    let pinned = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    assert_eq!(encoded, pinned, "{name} encodes differently");
    let decoded: Frame = serde_json::from_str(&pinned).unwrap();
    assert_eq!(decoded, value, "{name} decodes differently");
    // The typed body survives the trip too.
    assert_eq!(
        Frame::new(
            decoded.stream_id,
            decoded.seq,
            decoded.body().unwrap().unwrap()
        ),
        value
    );
}

fn capacity() -> Capacity {
    Capacity {
        cores: 8,
        cpu_pct: 12,
        mem_total_mb: 16384,
        mem_free_mb: 9000,
        disk_free_mb: 120_000,
        battery: Some(Battery {
            on_battery: false,
            percent: 80,
        }),
        idle_secs: Some(300),
        gate: Gate::Open,
        toolchains: BTreeMap::from([
            ("node".to_owned(), "22.22.1".to_owned()),
            ("rust".to_owned(), "1.99.1".to_owned()),
        ]),
        caches: vec![CacheInfo {
            project: 3,
            tree_hash: Hash([7; 32]),
            bytes: 1_048_576,
        }],
        job_slots: 2,
    }
}

fn entry() -> Entry {
    Entry {
        path: "src/main.rs".to_owned(),
        kind: EntryKind::File,
        exec: false,
        size: 12,
        hash: Hash([1; 32]),
        chunks: vec![Hash([2; 32])],
        link: None,
    }
}

#[test]
fn e15_frames_are_pinned() {
    let cmd = |name, op| check(name, Frame::new(1, 0, Body::Command(op)));
    let res = |name, r| check(name, Frame::new(1, 3, Body::Result(r)));
    check(
        "hello_capacity",
        Frame::new(
            CONTROL_STREAM,
            0,
            Body::Control(Control::Hello(RunnerHello {
                protocol: PROTOCOL_VERSION.to_owned(),
                runner_version: "0.10.0".to_owned(),
                drivers: vec![
                    DriverInfo {
                        name: CAP_JOB.to_owned(),
                        commands: vec![OP_JOB_RUN.to_owned()],
                        capacity: 2,
                        ..Default::default()
                    },
                    DriverInfo {
                        name: CAP_SYNC.to_owned(),
                        commands: [
                            OP_SYNC_MANIFEST,
                            OP_SYNC_PUSH,
                            OP_SYNC_PULL,
                            OP_SYNC_WATCH,
                            OP_SYNC_DROP,
                        ]
                        .map(str::to_owned)
                        .to_vec(),
                        capacity: 4,
                        ..Default::default()
                    },
                ],
                os: Some("macos".to_owned()),
                arch: Some("aarch64".to_owned()),
                capacity: Some(Box::new(capacity())),
                ..Default::default()
            })),
        ),
    );
    check(
        "heartbeat_capacity",
        Frame::new(
            CONTROL_STREAM,
            1,
            Body::Heartbeat(Heartbeat {
                capacity: Some(Capacity {
                    gate: Gate::OnBattery,
                    ..capacity()
                }),
                ..Default::default()
            }),
        ),
    );
    cmd(
        "job_run",
        Command::JobRun(JobRun {
            job: "j_abc".to_owned(),
            project: 3,
            cache: "c_core".to_owned(),
            argv: ["cargo", "build"].map(str::to_owned).to_vec(),
            cwd_rel: String::new(),
            env: BTreeMap::from([("CARGO_TERM_COLOR".to_owned(), "always".to_owned())]),
            secrets: vec![RunSecret {
                name: "NPM_TOKEN".to_owned(),
                lease: "l_x".to_owned(),
            }],
            prepare: vec![["npm", "ci"].map(str::to_owned).to_vec()],
            timeout_ms: Some(3_600_000),
            need: JobNeed {
                os: Some(Os::Linux),
                arch: None,
                toolchains: vec!["rust".to_owned()],
                xcode: false,
            },
        }),
    );
    res(
        "job_done",
        Reply::JobRun(JobDone {
            exit_code: Some(0),
            signal: None,
            changed: vec![entry()],
            deleted: vec!["old.txt".to_owned()],
            tree: TreeHash([9; 32]),
            duration_ms: 42_000,
        }),
    );
    cmd(
        "sync_manifest",
        Command::SyncManifest(SyncManifest {
            project: 3,
            lease: "l_s".to_owned(),
            rules_hash: Hash([4; 32]),
            rules: SyncRules {
                exclude: vec!["target/".to_owned()],
                ..Default::default()
            },
        }),
    );
    res(
        "sync_manifest_reply",
        Reply::SyncManifest(SyncManifestReply {
            entries: vec![
                entry(),
                Entry {
                    path: "link".to_owned(),
                    kind: EntryKind::Symlink,
                    link: Some("src/main.rs".to_owned()),
                    chunks: vec![],
                    ..entry()
                },
            ],
            tree: TreeHash([9; 32]),
        }),
    );
    cmd(
        "sync_push",
        Command::SyncPush(SyncPush {
            project: 3,
            lease: "l_s".to_owned(),
            base: TreeHash([8; 32]),
            put: vec![entry()],
            delete: vec!["gone.rs".to_owned()],
            want_tree: TreeHash([9; 32]),
            rules: SyncRules {
                include: vec![".env.example".to_owned()],
                exclude: vec!["target/".to_owned(), ".env*".to_owned()],
                outputs: vec!["target/release/app".to_owned()],
            },
            base_files: vec![("src/main.rs".to_owned(), Hash([1; 32]))],
        }),
    );
    res(
        "sync_pushed",
        Reply::SyncPush(SyncPushed {
            tree: TreeHash([9; 32]),
        }),
    );
    // One chunk frame: a plain credited `output`.
    check(
        "sync_chunk",
        Frame::new(
            1,
            1,
            Body::Output(Output {
                data: "aGVsbG8gd29ybGQK".to_owned(),
            }),
        ),
    );
    cmd(
        "sync_pull",
        Command::SyncPull(SyncPull {
            project: 3,
            cache_or_session: "as_abc".to_owned(),
            paths: vec![("src/main.rs".to_owned(), Hash([1; 32]))],
            lease: "l_s".to_owned(),
        }),
    );
    res("sync_pulled", Reply::SyncPull(SyncPulled { count: 1 }));
    cmd(
        "sync_watch",
        Command::SyncWatch(SyncWatch {
            session: "as_abc".to_owned(),
            lease: "l_s".to_owned(),
            rules: SyncRules::default(),
        }),
    );
    check(
        "sync_event",
        Frame::new(
            1,
            2,
            Body::Control(Control::SyncEvent(SyncEvent {
                seq: 1,
                put: vec![entry()],
                delete: vec![],
                inline: vec![InlineFile {
                    path: "src/main.rs".to_owned(),
                    data: "Zm4gbWFpbigpIHt9Cg==".to_owned(),
                }],
            })),
        ),
    );
    res(
        "sync_watched",
        Reply::SyncWatch(SyncWatched { last_seq: 1 }),
    );
    cmd("sync_drop", Command::SyncDrop(SyncDrop { project: 3 }));
    res(
        "sync_dropped",
        Reply::SyncDrop(SyncDropped { bytes_freed: 4096 }),
    );
    cmd(
        "gateway_call",
        Command::GatewayCall(GatewayCall {
            lease: "l_g".to_owned(),
            provider: "google".to_owned(),
            user_key: None,
            upstream: Some(Upstream {
                host: "generativelanguage.googleapis.com".to_owned(),
                base_path: String::new(),
                wire: Wire::GeminiGenerate,
                auth: GatewayAuth::XGoogApiKey,
            }),
            path: "/v1beta/decisions:score".to_owned(),
            body: "{}".to_owned(),
            timeout_ms: Some(8000),
        }),
    );
    res(
        "gateway_called",
        Reply::GatewayCall(GatewayCalled {
            result: UpstreamStatus::Ok,
            http_status: 200,
            body: "{}".to_owned(),
            truncated: false,
            usage: CallUsage {
                input: 10,
                output: 2,
                ..Default::default()
            },
            latency_ms: 300,
            retry_after: None,
        }),
    );
    cmd(
        "pty_open_login",
        Command::PtyOpen(
            serde_json::from_value(json!({
                "program": "agy", "size": {"rows": 24, "cols": 80}, "purpose": PTY_PURPOSE_LOGIN
            }))
            .unwrap(),
        ),
    );
    check(
        "error_terminal_target_removed",
        Frame::new(
            1,
            0,
            Body::Error(StreamError::new(
                ErrorCode::TerminalTargetRemoved,
                "terminals open on the Core or This Mac only",
            )),
        ),
    );
}

/// A 2.0 runner's hello and heartbeat (no `capacity`) still parse, and a 2.1 frame with a field
/// from a newer runner too: every E15 type defaults.
#[test]
fn e15_reads_older_and_newer_peers() {
    let hello: Control = serde_json::from_value(json!({
        "type": "hello", "protocol": "2.0", "runner_version": "0.9.0", "drivers": []
    }))
    .unwrap();
    let Control::Hello(h) = hello else { panic!() };
    assert_eq!(h.capacity, None);
    let cap: Capacity =
        serde_json::from_value(json!({"cores": 4, "gate": "warp", "x": 1})).unwrap();
    assert_eq!(cap.cores, 4);
    assert_eq!(cap.gate, Gate::Unknown);
    assert_eq!(cap.job_slots, 0);
    let e: Entry = serde_json::from_value(json!({"path": "a"})).unwrap();
    assert_eq!(e.kind, EntryKind::File);
    let d: JobDone = serde_json::from_value(json!({})).unwrap();
    assert_eq!(d, JobDone::default());
    assert_eq!(Capacity::default_job_slots(2), 1);
    assert_eq!(Capacity::default_job_slots(16), 4);
}

/// The shim's line protocol (§5.1), pinned by shape.
#[test]
fn the_shim_lines_are_pinned() {
    fn line<T: serde::Serialize>(v: &T) -> String {
        serde_json::to_string(v).unwrap()
    }
    assert_eq!(
        line(&ShimVerdict::Local {
            reason: "light".into(),
            report: true
        }),
        r#"{"verdict":"local","reason":"light","report":true}"#
    );
    assert_eq!(
        line(&ShimVerdict::Remote {
            job: "j_1".into(),
            device_name: "box".into()
        }),
        r#"{"verdict":"remote","job":"j_1","device_name":"box"}"#
    );
    assert_eq!(
        line(&ShimFrame::Out {
            fd: 1,
            b64: "aGk=".into()
        }),
        r#"{"t":"out","fd":1,"b64":"aGk="}"#
    );
    assert_eq!(
        line(&ShimFrame::Exit {
            code: Some(0),
            signal: None
        }),
        r#"{"t":"exit","code":0}"#
    );
    assert_eq!(
        line(&ShimFrame::Done {
            code: Some(2),
            signal: None,
            duration_ms: 1500
        }),
        r#"{"t":"done","code":2,"duration_ms":1500}"#
    );
    let v: ShimVerdict = serde_json::from_str(r#"{"verdict":"local","reason":"x"}"#).unwrap();
    assert_eq!(
        v,
        ShimVerdict::Local {
            reason: "x".into(),
            report: false
        }
    );
    let f: ShimFrame = serde_json::from_str(r#"{"t":"warp"}"#).unwrap();
    assert_eq!(f, ShimFrame::Unknown);
}
