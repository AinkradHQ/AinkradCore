//! P6-02 acceptance: 100 requests per second through the Host router to a fixture runner (the
//! [`Local`](super::host_router::Local) dial, a loopback service per port stream) for 3 s. Every
//! request must answer 200, under the rate cap, and the whole run must keep pace (no request
//! queues behind another). The idle stop is pushed back once per `TOUCH_EVERY`, not per request.

use std::time::{Duration, Instant};

use super::host_router::{DOMAIN, call, get, local, running};
use super::*;
use crate::gateway::projects as host;

const RPS: u64 = 100;
const SECONDS: u64 = 3;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hundred_requests_a_second_through_a_fixture_runner() {
    let fx = fx().await;
    let dial = local().await;
    running(&fx, "load").await;
    let r = host::router(fx.app.clone(), dial.clone(), DOMAIN);
    let started = Instant::now();
    let mut tick = tokio::time::interval(Duration::from_millis(1000 / RPS));
    let mut sent = Vec::new();
    for i in 0..RPS * SECONDS {
        tick.tick().await;
        let r = r.clone();
        sent.push(tokio::spawn(async move {
            let at = Instant::now();
            let (status, _, body) = call(&r, get("load.proj.test", &format!("/n/{i}"))).await;
            (
                status,
                body["uri"].as_str().map(str::to_owned),
                at.elapsed(),
            )
        }));
    }
    let mut slowest = Duration::ZERO;
    for (i, h) in sent.into_iter().enumerate() {
        let (status, uri, took) = h.await.unwrap();
        assert_eq!(status, StatusCode::OK, "request {i}");
        assert_eq!(uri.as_deref(), Some(format!("/n/{i}").as_str()));
        slowest = slowest.max(took);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(SECONDS + 2),
        "{elapsed:?} for {} requests",
        RPS * SECONDS
    );
    assert!(
        slowest < Duration::from_secs(2),
        "slowest request {slowest:?}"
    );
    assert_eq!(dial.opened.lock().unwrap().len() as u64, RPS * SECONDS);
    // Under the cap: 100 rps is half the sustained rate, so nothing was refused with a 429.
    assert!(host::RATE >= 2.0 * RPS as f64);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn past_the_burst_a_project_gets_429_and_another_project_does_not() {
    let fx = fx().await;
    let dial = local().await;
    running(&fx, "hot").await;
    running(&fx, "calm").await;
    let r = host::router(fx.app.clone(), dial, DOMAIN);
    // At once, well past the burst: the refill during the spike cannot cover it.
    let sent: Vec<_> = (0..host::BURST as usize * 3)
        .map(|_| {
            let r = r.clone();
            tokio::spawn(async move { call(&r, get("hot.proj.test", "/")).await.0 })
        })
        .collect();
    let mut limited = 0;
    for h in sent {
        if h.await.unwrap() == StatusCode::TOO_MANY_REQUESTS {
            limited += 1;
        }
    }
    assert!(limited > 0, "the burst was never cut");
    assert_eq!(call(&r, get("calm.proj.test", "/")).await.0, StatusCode::OK);
}
