//! `port.open` (P6-01): a TCP stream from the Core to an exposed port of a live run.
//!
//! SECURITY MODEL. The Core names (run, service, container port); everything else is the runner's:
//! - the address is always `127.0.0.1:<host_port>`, the host port Podman published for that container
//!   port, read back from the run's own containers (never given by the Core);
//! - only a port the spec marked `expose: true` (label `ainkrad.expose`, set by the helper) of a run
//!   that is `running` resolves; any other port, service or run is `invalid_args`;
//! - the stream ends, with `run_ended`, as soon as the run stops, fails or stops publishing that
//!   port at that address (checked every [`WATCH`]);
//! - bytes are `output` frames, each way held to `credit`: the runner sends the Core only what the Core
//!   granted, and closes a stream whose Core sends more than the runner granted, so a slow service or
//!   reader costs the runner at most one window.

use std::future::Future;
use std::time::Duration;

use ainkrad_proto::v2::{
    Body, Credit, ErrorCode, Output, PortClosed, PortOpen, Reply, RunList, RunPhase, STREAM_WINDOW,
    StreamError,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

/// How often a stream re-checks that its run is still live.
const WATCH: Duration = Duration::from_secs(1);
const DIAL: Duration = Duration::from_secs(3);
const WRITE: Duration = Duration::from_secs(10);
const CHUNK: usize = 16 * 1024;

/// The host port on 127.0.0.1 for `req`, if the run is running and exposes that port of that service.
pub(super) fn resolve(list: &RunList, req: &PortOpen) -> Result<u16, String> {
    let refuse = || "not an exposed port of a running run".to_owned();
    let run = list
        .runs
        .iter()
        .find(|r| r.run == req.run && r.phase == RunPhase::Running)
        .ok_or_else(refuse)?;
    run.services
        .iter()
        .find(|s| s.name == req.service && s.state == "running")
        .and_then(|s| s.ports.iter().find(|p| p.port == req.port && p.expose))
        .map(|p| p.host_port)
        .filter(|p| *p != 0)
        .ok_or_else(refuse)
}

/// Pumps bytes between the Core's stream and `127.0.0.1:host_port` until either side ends or
/// `alive` says the run is gone. Non-final frames go to `out`; the last is returned.
pub(super) async fn bridge<F, Fut>(
    host_port: u16,
    alive: F,
    stream: u64,
    mut inbox: mpsc::UnboundedReceiver<Body>,
    mut cancel: oneshot::Receiver<()>,
    out: mpsc::UnboundedSender<(u64, Body)>,
) -> Body
where
    F: Fn() -> Fut,
    Fut: Future<Output = bool>,
{
    let err = |c, m: &str| Body::Error(StreamError::new(c, m));
    let dial = TcpStream::connect(("127.0.0.1", host_port));
    let sock = match tokio::time::timeout(DIAL, dial).await {
        Ok(Ok(s)) => s,
        _ => {
            return err(
                ErrorCode::Internal,
                "the service did not accept the connection",
            );
        }
    };
    let (mut rd, mut wr) = sock.into_split();
    let done = |reason: &str| {
        Body::Result(Reply::PortOpen(PortClosed {
            reason: reason.to_owned(),
        }))
    };
    // `credit`: what the runner may still send the Core. `window`: what the Core may still send the
    // runner. `owed`: bytes written to the service and not yet granted back.
    let mut credit = STREAM_WINDOW;
    let (mut window, mut owed) = (STREAM_WINDOW, 0u64);
    let mut buf = vec![0u8; CHUNK];
    let mut tick = tokio::time::interval(WATCH);
    loop {
        let cap = buf.len().min(usize::try_from(credit).unwrap_or(usize::MAX));
        tokio::select! {
            _ = &mut cancel => return err(ErrorCode::Cancelled, "closed"),
            _ = tick.tick() => if !alive().await { return done("run_ended") },
            b = inbox.recv() => match b {
                None => return err(ErrorCode::Cancelled, "the stream was dropped"),
                Some(Body::Output(Output { data })) => {
                    let Ok(bytes) = STANDARD.decode(data) else {
                        return err(ErrorCode::BadFrame, "output is not base64");
                    };
                    let n = bytes.len() as u64;
                    if n > window {
                        return err(ErrorCode::BadFrame, "output past its credit");
                    }
                    window -= n;
                    // ponytail: a stalled service blocks this select for up to WRITE (cancel and
                    // the run check wait); split the halves into two tasks if that ever matters.
                    if !matches!(tokio::time::timeout(WRITE, wr.write_all(&bytes)).await, Ok(Ok(()))) {
                        return done("eof");
                    }
                    owed += n;
                    // Granted in batches of a quarter window: one frame per 16 KiB, not per write.
                    if owed >= STREAM_WINDOW / 4 {
                        let _ = out.send((stream, Body::Credit(Credit { bytes: owed })));
                        window += owed;
                        owed = 0;
                    }
                }
                Some(Body::Credit(c)) => credit = credit.saturating_add(c.bytes),
                Some(_) => {}
            },
            n = rd.read(&mut buf[..cap]), if cap > 0 => match n {
                Ok(n) if n > 0 => {
                    credit -= n as u64;
                    let data = STANDARD.encode(&buf[..n]);
                    let _ = out.send((stream, Body::Output(Output { data })));
                }
                _ => return done("eof"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use ainkrad_proto::v2::{PublishedPort, RunInfo, ServiceStatus};

    use super::*;

    fn list(phase: RunPhase, state: &str) -> RunList {
        let port = |port, host_port, expose| PublishedPort {
            port,
            host_port,
            expose,
        };
        RunList {
            runs: vec![RunInfo {
                run: "r1".into(),
                project: 7,
                phase,
                failed_service: None,
                reason: None,
                services: vec![ServiceStatus {
                    name: "web".into(),
                    state: state.into(),
                    exit_code: None,
                    ports: vec![port(3000, 40001, true), port(5432, 40002, false)],
                }],
            }],
        }
    }

    fn open(run: &str, service: &str, port: u16) -> PortOpen {
        PortOpen {
            run: run.into(),
            service: service.into(),
            port,
        }
    }

    #[test]
    fn only_an_exposed_port_of_a_running_run_resolves() {
        let up = list(RunPhase::Running, "running");
        assert_eq!(resolve(&up, &open("r1", "web", 3000)), Ok(40001));
        for bad in [
            open("r1", "web", 5432),  // published but not exposed
            open("r1", "web", 40001), // a host port, not a container port
            open("r1", "web", 22),    // not published at all
            open("r1", "db", 3000),   // another service
            open("r2", "web", 3000),  // another run
        ] {
            assert!(resolve(&up, &bad).is_err(), "{bad:?}");
        }
        for (phase, state) in [
            (RunPhase::Stopped, "exited"),
            (RunPhase::Failed, "running"),
            (RunPhase::Starting, "running"),
            (RunPhase::Running, "exited"),
        ] {
            assert!(resolve(&list(phase, state), &open("r1", "web", 3000)).is_err());
        }
        assert!(resolve(&RunList::default(), &open("r1", "web", 3000)).is_err());
    }

    #[test]
    fn a_malformed_request_is_a_problem() {
        assert!(open("r1", "web", 3000).problem().is_none());
        for bad in [
            open("", "web", 1),
            open("r1", "../x", 1),
            open("R", "web", 1),
            open("r1", "web", 0),
        ] {
            assert!(bad.problem().is_some(), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn bytes_flow_both_ways_and_the_stream_closes_with_the_run() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 5];
            s.read_exact(&mut b).await.unwrap();
            s.write_all(&b).await.unwrap(); // echo, then hold the socket open
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let up = Arc::new(AtomicBool::new(true));
        let (inbox_tx, inbox) = mpsc::unbounded_channel();
        let (out_tx, mut out) = mpsc::unbounded_channel();
        let (_cancel_tx, cancel) = oneshot::channel();
        let flag = Arc::clone(&up);
        let task = tokio::spawn(bridge(
            port,
            move || {
                let flag = Arc::clone(&flag);
                async move { flag.load(Ordering::SeqCst) }
            },
            9,
            inbox,
            cancel,
            out_tx,
        ));
        inbox_tx
            .send(Body::Output(Output {
                data: STANDARD.encode(b"hello"),
            }))
            .unwrap();
        let mut echoed = Vec::new();
        while echoed.len() < 5 {
            match out.recv().await.unwrap().1 {
                Body::Output(o) => echoed.extend(STANDARD.decode(o.data).unwrap()),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(echoed, b"hello");
        up.store(false, Ordering::SeqCst); // the run ends
        let last = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the stream closes")
            .unwrap();
        assert!(matches!(
            last,
            Body::Result(Reply::PortOpen(PortClosed { reason })) if reason == "run_ended"
        ));
    }

    #[tokio::test]
    async fn a_core_that_sends_past_its_credit_is_cut_off() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _held = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let (inbox_tx, inbox) = mpsc::unbounded_channel();
        let (out_tx, _out) = mpsc::unbounded_channel();
        let (_cancel_tx, cancel) = oneshot::channel();
        let big = vec![0u8; STREAM_WINDOW as usize + 1];
        inbox_tx
            .send(Body::Output(Output {
                data: STANDARD.encode(big),
            }))
            .unwrap();
        let last = bridge(port, || async { true }, 9, inbox, cancel, out_tx).await;
        assert!(matches!(last, Body::Error(e) if e.code == ErrorCode::BadFrame));
    }
}
