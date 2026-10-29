//! The v2 runner daemon (E1-11.4): dial, serve, and on any end dial again with a jittered,
//! capped backoff, keeping one [`Session`] so streams resume by `seq` across reconnects.
//!
//! - A connection that was served resets the backoff; a failed dial doubles it up to `max`.
//! - A wrong Core (`core_identity_mismatch`) or a `4009` (another process took over this
//!   runner's connection) waits `refused` (5 minutes), as handshake spec §13 asks.
//! - A configuration error (bad URL, unusable TLS setup) ends the daemon.
//! - So does a rejection (`LinkError::Rejected`): a `4001` close (revoked), or `REJECT_AFTER`
//!   dials in a row answered `auth_failed`, which is what a revoked or unknown device gets.
//!   A network error, a 5xx, a 429 or one stray `auth_failed` is retried.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::close_code;
use tokio::sync::watch;

use super::client::{Client, LinkError};
use super::dial::dial;
use super::key::{self, Enrolment, Key};
use super::{ExecDriver, Link, Session};

/// Dials in a row refused `auth_failed` before the runner gives up. Under the Core's lockout of
/// an address and device (5 failures in 10 minutes), so the last answer is still the refusal,
/// not a 429; over 1 so a refusal from a Core restart mid-handshake is retried.
pub const REJECT_AFTER: u32 = 3;

/// How long to wait between connections.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    pub min: Duration,
    pub max: Duration,
    /// After a wrong Core, or after being replaced.
    pub refused: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            min: Duration::from_millis(500),
            max: Duration::from_secs(60),
            refused: Duration::from_secs(300),
        }
    }
}

/// `wait` less up to half of it, at random, so runners do not redial in step.
fn jitter(wait: Duration) -> Duration {
    let r = u64::from_be_bytes(key::random::<8>()) % 1000;
    wait - wait / 2 * u32::try_from(r).unwrap_or(0) / 1000
}

/// What the daemon runs with.
pub struct Daemon {
    pub client: Client,
    pub key: Arc<Key>,
    pub enrolment: Arc<Mutex<Enrolment>>,
    /// Where a rotated pin is saved.
    pub save: Option<PathBuf>,
    pub exec: Arc<ExecDriver>,
    pub tls: Option<Arc<rustls::ClientConfig>>,
    pub backoff: Backoff,
}

impl Daemon {
    /// Runs until `stop` turns true (`Ok`) or a configuration error (`Err`).
    pub async fn run(self, mut stop: watch::Receiver<bool>) -> Result<(), LinkError> {
        let mut session = Session::new(Arc::clone(&self.exec));
        let mut delay = self.backoff.min;
        let mut refused = 0;
        loop {
            let attempt = async {
                let current = self.enrolment.lock().unwrap().clone();
                let (ws, exporter) =
                    dial(&self.client, &self.key, &current, self.tls.clone()).await?;
                let link = Link {
                    key: Arc::clone(&self.key),
                    enrolment: Arc::clone(&self.enrolment),
                    save: self.save.clone(),
                    exporter,
                };
                session.serve(ws, &link).await.map_err(LinkError::Protocol)
            };
            let outcome = tokio::select! {
                o = attempt => o,
                _ = stop.wait_for(|s| *s) => return Ok(()),
            };
            if !matches!(&outcome, Err(e) if e.auth_failed()) {
                refused = 0;
            }
            let wait = match outcome {
                Ok(Some(close_code::REVOKED)) => {
                    let why = "this runner was revoked (close 4001)";
                    tracing::error!("{why}; stopping");
                    return Err(LinkError::Rejected(why.to_owned()));
                }
                Err(e) if e.auth_failed() && refused + 1 >= REJECT_AFTER => {
                    tracing::error!(error = %e, "refused {REJECT_AFTER} times in a row; stopping");
                    return Err(LinkError::Rejected(format!(
                        "auth_failed {REJECT_AFTER} times in a row: this device is revoked or \
                         unknown to the Core"
                    )));
                }
                Err(e) if e.auth_failed() => {
                    refused += 1;
                    tracing::warn!(error = %e, refused, ?delay, "refused by the Core; redialing");
                    let wait = delay;
                    delay = (delay * 2).min(self.backoff.max);
                    wait
                }
                Ok(Some(close_code::REPLACED)) => {
                    tracing::error!("another connection of this runner took over; waiting");
                    self.backoff.refused
                }
                Ok(code) => {
                    tracing::info!(?code, "the Core closed the connection; redialing");
                    delay = self.backoff.min;
                    delay
                }
                Err(e) if e.mismatch() => {
                    tracing::error!(error = %e, "refusing this Core");
                    self.backoff.refused
                }
                Err(e @ LinkError::Config(_)) => return Err(e),
                Err(e) => {
                    tracing::warn!(error = %e, ?delay, "connection failed; redialing");
                    let wait = delay;
                    delay = (delay * 2).min(self.backoff.max);
                    wait
                }
            };
            tokio::select! {
                () = tokio::time::sleep(jitter(wait)) => {}
                _ = stop.wait_for(|s| *s) => return Ok(()),
            }
        }
    }
}

/// Builds the daemon from the state directory and runs it (`ainkrad-runner connect`).
pub async fn from_state(
    state: &key::State,
    exec: Arc<ExecDriver>,
    tls: Option<Arc<rustls::ClientConfig>>,
    stop: watch::Receiver<bool>,
) -> Result<(), LinkError> {
    let config = |e: std::io::Error| LinkError::Config(e.to_string());
    let enrolment = Enrolment::load(&state.enrolment()).map_err(config)?;
    let key = Key::load(&state.key()).map_err(config)?;
    let daemon = Daemon {
        client: Client::new(&enrolment.url, tls.clone())?,
        key: Arc::new(key),
        enrolment: Arc::new(Mutex::new(enrolment)),
        save: Some(state.enrolment()),
        exec,
        tls,
        backoff: Backoff::default(),
    };
    daemon.run(stop).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const FP: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    /// A fake Core: `/handshake` names `FP`, a challenge is given, and `/handshake/session` is
    /// answered `status` with `code`. Returns its URL and how many sessions were asked for.
    async fn core(status: u16, code: &'static str) -> (String, Arc<AtomicU32>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let sessions = Arc::new(AtomicU32::new(0));
        let seen = Arc::clone(&sessions);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0; 16 * 1024];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let (status, body) = if head.starts_with("GET /handshake ") {
                    (200, format!(r#"{{"identity_fingerprint":"{FP}"}}"#))
                } else if head.starts_with("POST /handshake/challenge ") {
                    (200, r#"{"challenge":"c"}"#.to_owned())
                } else {
                    seen.fetch_add(1, Ordering::SeqCst);
                    (status, format!(r#"{{"code":"{code}"}}"#))
                };
                let reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(reply.as_bytes()).await;
            }
        });
        (url, sessions)
    }

    fn daemon(url: &str) -> Daemon {
        let enrolment = Enrolment {
            url: url.to_owned(),
            device_id: "d_5v0v4qa7a8h2tb3219mtz5znvv".to_owned(),
            core_fp: FP.to_owned(),
            rotation_seq: 0,
        };
        Daemon {
            client: Client::new(url, None).unwrap(),
            key: Arc::new(super::super::tests::new_key()),
            enrolment: Arc::new(Mutex::new(enrolment)),
            save: None,
            exec: Arc::new(super::super::exec::tests::driver(1)),
            tls: None,
            backoff: Backoff {
                min: Duration::from_millis(10),
                max: Duration::from_millis(20),
                refused: Duration::from_millis(20),
            },
        }
    }

    /// E1 exit gate finding 2: a revoked or unknown runner stops, after `REJECT_AFTER` dials.
    #[tokio::test]
    async fn a_device_the_core_refuses_stops_the_runner() {
        let (url, sessions) = core(401, "auth_failed").await;
        let (_stop, stopping) = watch::channel(false);
        let run = daemon(&url).run(stopping);
        let e = tokio::time::timeout(Duration::from_secs(10), run)
            .await
            .expect("it stops by itself")
            .unwrap_err();
        assert!(matches!(e, LinkError::Rejected(_)), "{e}");
        assert!(e.to_string().contains("revoked or unknown"), "{e}");
        assert_eq!(sessions.load(Ordering::SeqCst), REJECT_AFTER);
    }

    /// A 5xx, a 429 or no Core at all is retried for as long as it lasts.
    #[tokio::test]
    async fn server_errors_and_a_dead_core_are_retried() {
        let (busy, _) = core(503, "unavailable").await;
        let (limited, _) = core(429, "rate_limited").await;
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        for url in [busy, limited, dead] {
            let (stop, stopping) = watch::channel(false);
            let run = tokio::spawn(daemon(&url).run(stopping));
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(!run.is_finished(), "{url}: it gave up");
            stop.send_replace(true);
            assert!(run.await.unwrap().is_ok(), "{url}");
        }
    }

    #[test]
    fn jitter_stays_within_half_of_the_wait() {
        for _ in 0..1000 {
            let j = jitter(Duration::from_secs(10));
            assert!(
                j > Duration::from_secs(5) && j <= Duration::from_secs(10),
                "{j:?}"
            );
        }
    }
}
