//! Commands through the hub: the no-op end to end, only advertised ops reach a runner, the
//! in-flight cap and output credit, and every way a connection ends.

use std::sync::Arc;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::hub::Elevated;
use ainkrad_core_server::store::gov;
use ainkrad_proto::v2::*;

use super::{Core, Fake, exec_driver, quick};

#[tokio::test]
async fn the_noop_runs_end_to_end_and_only_advertised_commands_reach_the_runner() {
    let core = Core::start("noop", quick()).await;
    let dev = core.runner().await;
    let mut fake = Fake::welcomed(&core, &dev, vec![exec_driver(&[OP_NOOP], 2)]).await;
    let hub = Arc::clone(&core.app.hub);
    assert!(hub.online(&dev.id));

    let exec = Command::ExecRun(ExecRun {
        program: "/bin/true".to_owned(),
        args: vec![],
        cwd: None,
        env: Default::default(),
        env_pass: vec![],
        limits: ExecLimits::default(),
    });
    // Security review RH5: exec.run without a step-up proof is refused before anything else.
    let unelevated = hub.dispatch(&dev.id, exec.clone()).err().expect("no proof");
    assert_eq!(unelevated.code, ErrorCode::InvalidArgs);
    let agent_read = hub
        .dispatch(
            &dev.id,
            Command::AgentRead(AgentRead {
                session: "as_plain".to_owned(),
                after: 0,
                wait_ms: None,
            }),
        )
        .err()
        .expect("agent operations need the agent path");
    assert_eq!(agent_read.code, ErrorCode::InvalidArgs);
    // Re-review M1: deny by default; a shell (`pty.open`) or typing into one (`pty.attach`) is
    // code on the runner too.
    let shell = Command::PtyOpen(PtyOpen {
        program: Some("/bin/sh".to_owned()),
        args: vec!["-c".to_owned(), "id".to_owned()],
        cwd: None,
        env: Default::default(),
        env_pass: vec![],
        size: Size { rows: 24, cols: 80 },
    });
    for cmd in [
        shell,
        Command::PtyAttach(PtyAttach {
            terminal: "t_x".to_owned(),
            seq: 0,
        }),
    ] {
        let refused = hub.dispatch(&dev.id, cmd).err().expect("no proof");
        assert_eq!(refused.code, ErrorCode::InvalidArgs);
    }
    let refused = hub
        .dispatch_elevated(&dev.id, exec, Elevated::for_tests())
        .err()
        .expect("not advertised");
    assert_eq!(refused.code, ErrorCode::UnsupportedCommand);
    let other = hub.dispatch("d_00000000000000000000000000", Command::Noop);
    assert_eq!(other.err().unwrap().code, ErrorCode::Offline);

    let noop = tokio::spawn({
        let (hub, id) = (Arc::clone(&hub), dev.id.clone());
        async move { hub.noop(&id).await }
    });
    // The first command frame the runner sees is the no-op: the refused exec never left.
    let cmd = fake.next().await;
    assert_eq!((cmd.kind, cmd.seq), (FrameKind::Command, 0));
    assert_eq!(cmd.stream_id % 2, 1, "the Core opens odd streams");
    assert_eq!(cmd.body().unwrap(), Some(Body::Command(Command::Noop)));
    fake.send(cmd.stream_id, Body::Result(Reply::Noop)).await;
    noop.await.unwrap().expect("the no-op answered");
}

/// E2-15.2: a runner whose host is past `cores * 2` load is `busy` (hello or heartbeat); it takes
/// work again once a heartbeat reports it back under.
#[tokio::test]
async fn a_loaded_host_refuses_new_commands_until_its_load_drops() {
    let core = Core::start("hostload", quick()).await;
    let dev = core.runner().await;
    let hot = HostLoad {
        avg1: 9.0,
        cores: 4,
    };
    let cool = HostLoad {
        avg1: 1.0,
        cores: 4,
    };
    let mut fake = Fake::plain(&core, &dev).await;
    fake.load = Some(hot);
    let auth = fake
        .hello(&dev, vec![exec_driver(&[OP_NOOP], 2)], &super::random32())
        .await;
    fake.prove(
        &dev,
        &auth,
        &super::NO_CHANNEL_BINDING,
        &core.app.auth.identity.fp,
    )
    .await;
    fake.welcome().await;
    let hub = Arc::clone(&core.app.hub);
    let busy = hub.dispatch(&dev.id, Command::Noop).err().expect("loaded");
    assert_eq!(busy.code, ErrorCode::Busy);
    assert!(busy.message.contains("load"), "{}", busy.message);
    assert_eq!(hub.runners()[&dev.id].host_load, Some(hot));

    fake.heartbeat(Some(cool)).await;
    for _ in 0..100 {
        if hub.runners()[&dev.id].host_load == Some(cool) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    hub.dispatch(&dev.id, Command::Noop).expect("load dropped");
    // A heartbeat without a measure keeps the last one.
    fake.heartbeat(None).await;
    fake.heartbeat(Some(hot)).await;
    for _ in 0..100 {
        if hub.runners()[&dev.id].host_load == Some(hot) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        hub.dispatch(&dev.id, Command::Noop)
            .err()
            .expect("loaded again")
            .code,
        ErrorCode::Busy
    );
}

#[tokio::test]
async fn past_its_capacity_a_runner_is_busy_and_output_is_held_to_its_credit() {
    let core = Core::start("busy", quick()).await;
    let dev = core.runner().await;
    let mut fake = Fake::welcomed(&core, &dev, vec![exec_driver(&[OP_NOOP], 2)]).await;
    let hub = Arc::clone(&core.app.hub);
    let mut a = hub.dispatch(&dev.id, Command::Noop).unwrap();
    let b = hub.dispatch(&dev.id, Command::Noop).unwrap();
    let busy = hub.dispatch(&dev.id, Command::Noop).err().unwrap();
    assert_eq!(busy.code, ErrorCode::Busy, "capacity 2");
    let (sa, sb) = (fake.next().await.stream_id, fake.next().await.stream_id);
    assert_eq!((sa, sb), (a.stream, b.stream));

    // Within the window: delivered, and reading it grants as much credit back.
    let chunk = "aGkK".repeat(1024); // 3 KiB
    fake.send(
        sa,
        Body::Output(Output {
            data: chunk.clone(),
        }),
    )
    .await;
    assert_eq!(a.next().await, Some(Body::Output(Output { data: chunk })));
    let credit = fake.next().await;
    assert_eq!(
        (credit.stream_id, credit.kind, credit.seq),
        (sa, FrameKind::Credit, 1)
    );
    assert_eq!(
        credit.body().unwrap(),
        Some(Body::Credit(Credit { bytes: 3072 }))
    );
    fake.send(sa, Body::Result(Reply::Noop)).await;
    assert_eq!(a.next().await, Some(Body::Result(Reply::Noop)));
    // The answer is acknowledged with a close: the runner may forget the stream.
    let ack = fake.next().await;
    assert_eq!(
        (ack.stream_id, ack.kind, ack.seq),
        (sa, FrameKind::Close, 2)
    );

    // Past the window: the stream fails, the runner is told to close it, and a slot frees.
    let past = "AAAA".repeat((STREAM_WINDOW as usize / 3) + 1);
    fake.send(sb, Body::Output(Output { data: past })).await;
    let err = b.outcome().await.unwrap_err();
    assert_eq!(err.code, ErrorCode::BadFrame);
    let close = fake.next().await;
    assert_eq!((close.stream_id, close.kind), (sb, FrameKind::Close));
    assert!(
        hub.dispatch(&dev.id, Command::Noop).is_ok(),
        "both slots free again"
    );
}

#[tokio::test]
async fn a_newer_connection_replaces_the_older_whose_commands_are_lost_once() {
    let core = Core::start("replace", quick()).await;
    let dev = core.runner().await;
    let mut old = Fake::welcomed(&core, &dev, vec![exec_driver(&[OP_NOOP], 1)]).await;
    let hub = Arc::clone(&core.app.hub);
    let mut pending = hub.dispatch(&dev.id, Command::Noop).unwrap();
    old.next().await;

    let session = core.app.auth.issue_session(
        &dev.id,
        ainkrad_core_server::scheduler::Clock::unix(&ainkrad_core_server::scheduler::SystemClock),
    );
    dev.set_session(Some(session.id));
    let mut new = Fake::welcomed(&core, &dev, vec![exec_driver(&[OP_NOOP], 1)]).await;
    assert_eq!(old.closed().await, close_code::REPLACED);
    match pending.next().await {
        Some(Body::Error(e)) => assert_eq!(e.code, ErrorCode::Lost),
        other => panic!("{other:?}"),
    }
    assert_eq!(pending.next().await, None, "lost exactly once");

    // The new connection carries commands; the old one's late answer goes nowhere.
    let noop = tokio::spawn({
        let (hub, id) = (Arc::clone(&hub), dev.id.clone());
        async move { hub.noop(&id).await }
    });
    let cmd = new.next().await;
    new.send(cmd.stream_id, Body::Result(Reply::Noop)).await;
    noop.await.unwrap().unwrap();
}

#[tokio::test]
async fn revocation_shutdown_and_silence_close_with_their_codes() {
    let core = Core::start("ends", quick()).await;
    let dev = core.runner().await;
    let mut fake = Fake::welcomed(&core, &dev, vec![exec_driver(&[OP_NOOP], 1)]).await;
    let now =
        ainkrad_core_server::scheduler::Clock::now(&ainkrad_core_server::scheduler::SystemClock);
    assert!(
        gov::revoke_device(&core.app.pool, &dev.id, AuditActor::System, None, &now)
            .await
            .unwrap()
    );
    core.app.auth.revoked(&dev.id);
    assert_eq!(fake.closed().await, close_code::REVOKED);

    let dev = core.runner().await;
    let mut silent = Fake::welcomed(&core, &dev, vec![exec_driver(&[OP_NOOP], 1)]).await;
    // Reads nothing and sends nothing: after three heartbeats the Core gives up.
    tokio::time::sleep(std::time::Duration::from_millis(3500)).await;
    let code = loop {
        use futures_util::StreamExt;
        match silent.ws.next().await {
            Some(Ok(tokio_tungstenite::tungstenite::Message::Close(Some(c)))) => {
                break u16::from(c.code);
            }
            Some(Ok(_)) => continue,
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(code, close_code::SILENT);
    assert!(!core.app.hub.online(&dev.id));

    let dev = core.runner().await;
    let mut fake = Fake::welcomed(&core, &dev, vec![exec_driver(&[OP_NOOP], 1)]).await;
    core.app.closing.send_replace(true);
    assert_eq!(fake.closed().await, close_code::RESTART);
}

/// Review M2: a terminal stream takes one `opened` and snapshots under credit (read back as
/// credit, like output); a second `opened`, a snapshot with no credit left, or any control on
/// a plain command stream fails that stream.
#[tokio::test]
async fn terminal_streams_take_only_metered_snapshots_and_one_opened() {
    let core = Core::start("pty", quick()).await;
    let dev = core.runner().await;
    let pty = DriverInfo {
        name: DRIVER_PTY.to_owned(),
        commands: vec![OP_PTY_OPEN.to_owned(), OP_PTY_ATTACH.to_owned()],
        capacity: 4,
        ..DriverInfo::default()
    };
    let mut fake = Fake::welcomed(&core, &dev, vec![exec_driver(&[OP_NOOP], 4), pty]).await;
    let hub = Arc::clone(&core.app.hub);
    let attach = |t: &str| {
        Command::PtyAttach(PtyAttach {
            terminal: t.to_owned(),
            seq: 0,
        })
    };
    let info = TerminalInfo {
        terminal: "t_a".to_owned(),
        state: TerminalState::Running,
        size: Size { rows: 24, cols: 80 },
        seq: 0,
        pid: None,
        exit: None,
    };
    let opened = || Body::Control(Control::Opened(info.clone()));
    let snap = |n: usize| {
        Body::Control(Control::Snapshot(Snapshot {
            seq: 1,
            data: "AAAA".repeat(n / 3),
        }))
    };

    // Opened once, then a snapshot of the whole window: delivered, and granted back on read.
    let mut a = hub
        .dispatch_elevated(&dev.id, attach("t_a"), Elevated::for_tests())
        .unwrap();
    let sa = fake.next().await.stream_id;
    fake.send(sa, opened()).await;
    assert_eq!(a.next().await, Some(opened()));
    fake.send(sa, snap(STREAM_WINDOW as usize)).await;
    assert!(matches!(
        a.next().await,
        Some(Body::Control(Control::Snapshot(_)))
    ));
    let credit = fake.next().await;
    assert_eq!(
        credit.body().unwrap(),
        Some(Body::Credit(Credit {
            bytes: (STREAM_WINDOW / 3) * 3
        }))
    );
    // A second `opened` fails the stream.
    fake.send(sa, opened()).await;
    assert_eq!(a.outcome().await.unwrap_err().code, ErrorCode::BadFrame);

    // A snapshot past an empty credit fails the stream: overdraw once (to zero), not twice.
    let b = hub
        .dispatch_elevated(&dev.id, attach("t_b"), Elevated::for_tests())
        .unwrap();
    let sb = loop {
        let f = fake.next().await;
        if f.kind == FrameKind::Command {
            break f.stream_id;
        }
    };
    fake.send(sb, snap(2 * STREAM_WINDOW as usize)).await;
    fake.send(sb, snap(3)).await;
    // The hub failed it (and told the runner) before anything was read, so no grant raced in.
    loop {
        let f = fake.next().await;
        if (f.stream_id, f.kind) == (sb, FrameKind::Close) {
            break;
        }
    }
    let mut b = b;
    assert!(matches!(
        b.next().await,
        Some(Body::Control(Control::Snapshot(_)))
    ));
    assert_eq!(b.outcome().await.unwrap_err().code, ErrorCode::BadFrame);

    // Any control on a plain command stream fails it.
    let c = hub.dispatch(&dev.id, Command::Noop).unwrap();
    let sc = loop {
        let f = fake.next().await;
        if f.kind == FrameKind::Command {
            break f.stream_id;
        }
    };
    fake.send(sc, opened()).await;
    assert_eq!(c.outcome().await.unwrap_err().code, ErrorCode::BadFrame);
}
