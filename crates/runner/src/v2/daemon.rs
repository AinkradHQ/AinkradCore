//! The v2 runner daemon (E1-11.4): dial, serve, and on any end dial again with a jittered,
//! capped backoff, keeping one [`Session`] so streams resume by `seq` across reconnects.
//!
//! - A connection that was served resets the backoff; a failed dial doubles it up to `max`.
//! - A wrong Core (`core_identity_mismatch`) or a `4009` (another process took over this
//!   runner's connection) waits `refused` (5 minutes), as handshake spec §13 asks.
//! - A configuration error (bad URL, unusable TLS setup) ends the daemon.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_proto::v2::close_code;
use tokio::sync::watch;

use super::client::{Client, LinkError};
use super::dial::dial;
use super::key::{self, Enrolment, Key};
use super::{ExecDriver, Link, Session};

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
            let wait = match outcome {
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
