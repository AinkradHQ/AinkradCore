//! Commands through the hub: the no-op end to end, only advertised ops reach a runner, the
//! in-flight cap and output credit, and every way a connection ends.

use std::sync::Arc;

use ainkrad_core::audit::AuditActor;
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
    let refused = hub.dispatch(&dev.id, exec).err().expect("not advertised");
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
