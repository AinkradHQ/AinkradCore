//! Resume by `seq` (E1-11.4), hub side, with the fake runner choosing exactly what it claims:
//! the Core resends only what the runner did not receive, drops what it sees twice, and a
//! command is lost exactly once when its runner does not come back in time or comes back as
//! another process.

use std::sync::Arc;
use std::time::Duration;

use ainkrad_core_server::auth::testing::TestDevice;
use ainkrad_core_server::hub::HubConfig;
use ainkrad_proto::v2::*;

use super::{Core, Fake, exec_driver, quick, random32};

/// Connected and welcomed as process `boot`, claiming `streams`.
async fn as_process(
    core: &Core,
    dev: &TestDevice,
    boot: &str,
    streams: Vec<StreamState>,
) -> (Fake, CoreWelcome) {
    let mut f = Fake::plain(core, dev).await;
    f.boot = Some(boot.to_owned());
    f.streams = streams;
    let auth = f
        .hello(dev, vec![exec_driver(&[OP_NOOP], 4)], &random32())
        .await;
    f.prove(dev, &auth, &NO_CHANNEL_BINDING, &core.app.auth.identity.fp)
        .await;
    let w = f.welcome().await;
    (f, w)
}

fn window(resume: Duration) -> HubConfig {
    HubConfig { resume, ..quick() }
}

#[tokio::test]
async fn the_core_resends_what_the_runner_missed_and_an_answer_arrives_once() {
    let core = Core::start("resume", window(Duration::from_secs(10))).await;
    let dev = core.runner().await;
    let hub = Arc::clone(&core.app.hub);
    let (mut f, w) = as_process(&core, &dev, "b_one", vec![]).await;
    assert_eq!(w.boot.as_deref(), Some(hub.boot.as_str()));
    assert_eq!(w.heartbeat_ms, Some(1000));
    assert!(w.streams.is_empty());
    let mut a = hub.dispatch(&dev.id, Command::Noop).unwrap();
    let mut b = hub.dispatch(&dev.id, Command::Noop).unwrap();
    assert_eq!(f.next().await.stream_id, a.stream);
    assert_eq!(f.next().await.stream_id, b.stream);
    drop(f);

    // Back as the same process, claiming it received a's command but not b's.
    let got_a = StreamState {
        stream_id: a.stream,
        received: 1,
    };
    let (mut f, w) = as_process(&core, &dev, "b_one", vec![got_a]).await;
    let none = |id| StreamState {
        stream_id: id,
        received: 0,
    };
    assert_eq!(
        w.streams,
        vec![none(a.stream), none(b.stream)],
        "both in flight, nothing received"
    );
    let resent = f.next().await;
    assert_eq!(
        (resent.stream_id, resent.seq, resent.kind),
        (b.stream, 0, FrameKind::Command)
    );
    // a's answer twice (a resend after a cut): delivered once.
    let answer = Frame::new(a.stream, 0, Body::Result(Reply::Noop));
    f.send_frame(&answer).await;
    f.send_frame(&answer).await;
    f.send_frame(&Frame::new(b.stream, 0, Body::Result(Reply::Noop)))
        .await;
    assert_eq!(a.next().await, Some(Body::Result(Reply::Noop)));
    assert_eq!(a.next().await, None, "exactly once");
    assert_eq!(b.next().await, Some(Body::Result(Reply::Noop)));
    // Each answer is acknowledged, and nothing else comes.
    let acks = [f.next().await, f.next().await];
    assert!(acks.iter().all(|f| f.kind == FrameKind::Close));
    assert!(hub.dispatch(&dev.id, Command::Noop).is_ok());
}

#[tokio::test]
async fn a_command_is_lost_once_past_the_window_or_when_another_process_returns() {
    let core = Core::start("lost", window(Duration::from_millis(300))).await;
    let dev = core.runner().await;
    let hub = Arc::clone(&core.app.hub);

    let (mut f, _) = as_process(&core, &dev, "b_one", vec![]).await;
    let mut late = hub.dispatch(&dev.id, Command::Noop).unwrap();
    f.next().await;
    drop(f);
    let lost = tokio::time::timeout(Duration::from_secs(5), late.next())
        .await
        .unwrap();
    assert!(matches!(lost, Some(Body::Error(e)) if e.code == ErrorCode::Lost));
    assert_eq!(late.next().await, None, "lost exactly once");

    let (mut f, w) = as_process(&core, &dev, "b_one", vec![]).await;
    assert!(w.streams.is_empty(), "nothing left in flight");
    let mut gone = hub.dispatch(&dev.id, Command::Noop).unwrap();
    f.next().await;
    drop(f);
    // Back within the window, but as a restarted process: its streams are gone.
    let (mut f, w) = as_process(&core, &dev, "b_two", vec![]).await;
    assert!(w.streams.is_empty());
    assert!(matches!(gone.next().await, Some(Body::Error(e)) if e.code == ErrorCode::Lost));
    assert_eq!(gone.next().await, None);
    // A late answer for it goes nowhere, and the new process serves.
    f.send_frame(&Frame::new(gone.stream, 0, Body::Result(Reply::Noop)))
        .await;
    let noop = tokio::spawn({
        let (hub, id) = (Arc::clone(&hub), dev.id.clone());
        async move { hub.noop(&id).await }
    });
    let cmd = f.next().await;
    f.send_frame(&Frame::new(cmd.stream_id, 0, Body::Result(Reply::Noop)))
        .await;
    noop.await.unwrap().unwrap();
}

/// Security review RH1: a hostile `seq` with no successor fails its own stream and nothing
/// else; the hub keeps serving that runner and every other.
#[tokio::test]
async fn a_seq_at_its_maximum_fails_only_its_stream() {
    let core = Core::start("seqmax", quick()).await;
    let hub = Arc::clone(&core.app.hub);
    let (dev, other) = (core.runner().await, core.runner().await);
    let (mut f, _) = as_process(&core, &dev, "b_one", vec![]).await;
    let (mut g, _) = as_process(&core, &other, "b_two", vec![]).await;
    let hostile = hub.dispatch(&dev.id, Command::Noop).unwrap();
    f.next().await;
    f.send_frame(&Frame::new(
        hostile.stream,
        u64::MAX,
        Body::Result(Reply::Noop),
    ))
    .await;
    assert_eq!(
        hostile.outcome().await.unwrap_err().code,
        ErrorCode::BadFrame
    );
    for (fake, id) in [(&mut f, &dev.id), (&mut g, &other.id)] {
        let d = hub.dispatch(id, Command::Noop).unwrap();
        let cmd = loop {
            let c = fake.next().await;
            if c.kind == FrameKind::Command {
                break c;
            }
        };
        fake.send_frame(&Frame::new(cmd.stream_id, 0, Body::Result(Reply::Noop)))
            .await;
        assert_eq!(d.outcome().await.unwrap(), Body::Result(Reply::Noop));
    }
}

/// H3: a resume resends by `seq`, not by count. Typed input is never kept or resent, a credit
/// the runner missed is resent (as one frame however many were missed), and one it got is not.
#[tokio::test]
async fn a_terminal_resume_resends_missed_credit_once_and_never_typed_input() {
    use ainkrad_core_server::hub::Elevated;
    use base64::Engine;
    let core = Core::start("tresume", window(Duration::from_secs(10))).await;
    let dev = core.runner().await;
    let hub = Arc::clone(&core.app.hub);
    let pty = DriverInfo {
        name: DRIVER_PTY.to_owned(),
        commands: vec![OP_PTY_OPEN.to_owned(), OP_PTY_ATTACH.to_owned()],
        capacity: 4,
        ..DriverInfo::default()
    };
    let as_process = |received: Option<(u64, u64)>| {
        let (core, dev, pty) = (&core, &dev, pty.clone());
        async move {
            let mut f = Fake::plain(core, dev).await;
            f.boot = Some("b_one".to_owned());
            f.streams = received
                .map(|(stream_id, received)| StreamState {
                    stream_id,
                    received,
                })
                .into_iter()
                .collect();
            let auth = f.hello(dev, vec![pty], &random32()).await;
            f.prove(dev, &auth, &NO_CHANNEL_BINDING, &core.app.auth.identity.fp)
                .await;
            f.welcome().await;
            f
        }
    };
    let mut f = as_process(None).await;
    let attach = Command::PtyAttach(PtyAttach {
        terminal: "t_a".to_owned(),
        seq: 0,
    });
    let mut d = hub
        .dispatch_elevated(&dev.id, attach, Elevated::for_tests())
        .unwrap();
    assert_eq!(f.next().await.kind, FrameKind::Command);
    let info = TerminalInfo {
        terminal: "t_a".to_owned(),
        state: TerminalState::Running,
        size: Size { rows: 24, cols: 80 },
        seq: 0,
        pid: None,
        exit: None,
    };
    f.send(d.stream, Body::Control(Control::Opened(info))).await;
    assert!(matches!(
        d.next().await,
        Some(Body::Control(Control::Opened(_)))
    ));
    let typed = base64::engine::general_purpose::STANDARD.encode("hunter2\n");
    hub.send_terminal(&dev.id, d.stream, Body::Output(Output { data: typed }))
        .unwrap();
    assert_eq!(f.next().await.seq, 1);
    let chunk = "aGkK".repeat(1024);
    for _ in 0..3 {
        f.send(
            d.stream,
            Body::Output(Output {
                data: chunk.clone(),
            }),
        )
        .await;
        d.next().await;
        assert_eq!(f.next().await.kind, FrameKind::Credit);
    }
    drop(f);

    // Back having received seqs 0 and 1 only: the three credits (seq 2..=4) were missed.
    let mut f = as_process(Some((d.stream, 2))).await;
    let c = f.next().await;
    assert_eq!((c.kind, c.seq), (FrameKind::Credit, 4));
    assert_eq!(
        c.body().unwrap(),
        Some(Body::Credit(Credit { bytes: 3 * 3072 }))
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(400), f.next())
            .await
            .is_err(),
        "no command, no input"
    );
    drop(f);
    // Back having received it all: nothing to resend.
    let mut f = as_process(Some((d.stream, 5))).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(400), f.next())
            .await
            .is_err()
    );

    // Many grants stay bounded: one merged frame, with every byte.
    for n in 0..200 {
        // A new connection's fake counts its own seqs from 0: go past the ones the hub saw.
        let out = Body::Output(Output {
            data: chunk.clone(),
        });
        f.send_frame(&Frame::new(d.stream, 100 + n, out)).await;
        d.next().await;
        assert_eq!(f.next().await.kind, FrameKind::Credit);
    }
    drop(f);
    let mut f = as_process(Some((d.stream, 5))).await;
    let c = f.next().await;
    assert_eq!(
        c.body().unwrap(),
        Some(Body::Credit(Credit { bytes: 200 * 3072 }))
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(400), f.next())
            .await
            .is_err()
    );
    // Past the bound the oldest grants merge into one span. A resume inside that span cannot
    // tell what the runner got, so the span is resent whole and its bytes are tolerated as
    // output past the credit: the stream neither fails nor stalls.
    for n in 0..100 {
        let out = Body::Output(Output {
            data: chunk.clone(),
        });
        f.send_frame(&Frame::new(d.stream, 300 + n, out)).await;
        d.next().await;
        assert_eq!(f.next().await.kind, FrameKind::Credit);
    }
    drop(f);
    // Grants 205..=304 were sent; the oldest 37 merged into one span ending near seq 241, so a
    // runner that received up to 220 is inside it.
    let mut f = as_process(Some((d.stream, 220))).await;
    assert_eq!(f.next().await.kind, FrameKind::Credit);
    // 30 chunks are 90 KiB, more than the 64 KiB window the Core believes is open.
    for n in 0..30 {
        let out = Body::Output(Output {
            data: chunk.clone(),
        });
        f.send_frame(&Frame::new(d.stream, 400 + n, out)).await;
    }
    // Nothing is read (and so no credit returned) until the Core has taken all of them.
    tokio::time::sleep(Duration::from_millis(500)).await;
    for _ in 0..30 {
        let got = d.next().await;
        assert!(matches!(got, Some(Body::Output(_))), "{got:?}");
    }
}
