//! PR 324 review: a run of another project never resolves, and a stream whose run ended while it
//! dialled closes at once.
use std::time::Duration;

use ainkrad_proto::v2::{PublishedPort, RunInfo, ServiceStatus};

use super::*;

fn list(project: u64) -> RunList {
    RunList {
        runs: vec![RunInfo {
            run: "r1".into(),
            project,
            phase: RunPhase::Running,
            failed_service: None,
            reason: None,
            services: vec![ServiceStatus {
                name: "web".into(),
                state: "running".into(),
                exit_code: None,
                ports: vec![PublishedPort {
                    port: 3000,
                    host_port: 40001,
                    expose: true,
                }],
            }],
        }],
    }
}

fn open(project: u64) -> PortOpen {
    PortOpen {
        project,
        run: "r1".into(),
        service: "web".into(),
        port: 3000,
    }
}

#[test]
fn a_run_of_another_project_does_not_resolve() {
    assert_eq!(resolve(&list(7), &open(7)), Ok(40001));
    assert!(resolve(&list(7), &open(8)).is_err());
}

#[tokio::test]
async fn a_run_gone_before_the_first_byte_closes_the_stream_at_once() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _held = listener.accept().await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let (_inbox_tx, inbox) = mpsc::unbounded_channel();
    let (out_tx, _out) = mpsc::unbounded_channel();
    let (_cancel_tx, cancel) = oneshot::channel();
    let last = tokio::time::timeout(
        Duration::from_millis(500),
        bridge(port, || async { false }, 1, inbox, cancel, out_tx),
    )
    .await
    .expect("closes before the first watch tick");
    assert!(matches!(last, Body::Result(Reply::PortOpen(c)) if c.reason == "run_ended"));
}
