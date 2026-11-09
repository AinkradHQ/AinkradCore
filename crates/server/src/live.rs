//! What every long-lived socket used to poll for itself, polled once per process (E1-19): the
//! event head and the device table. 200 event sockets each reading the events table every
//! 250 ms and their devices every 2 s cost 22.7 % of a core while idle.
//!
//! - **Head** ([`Live::head`]): one task reads the newest event seq every `poll` while any
//!   socket listens, and publishes it only when it grew, so an idle stream wakes nobody and a
//!   socket reads the database only when there is something past its cursor. A poll, not a
//!   writer hook: events are also appended by other processes (the admin CLI's audit rows, the
//!   perf and soak harnesses), which no in-process notify would see.
//! - **Devices** ([`Live::devices`]): one task reads every device's state every `every` (the
//!   §10 backstop, 2 s) while any socket listens, in one query whatever the number of sockets,
//!   and publishes the snapshot. `auth::until_revoked` and `until_rescoped` check their device
//!   in it.
//!
//! Each poll runs on its own task, which nothing cancels mid-query, so no socket can park a
//! pool connection (the E1-19 starvation). A task ends once its `Live` is dropped.

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use sqlx::SqlitePool;
use tokio::sync::watch;
use tokio::time::Instant;

/// One device as the backstop sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceState {
    /// Active and not revoked.
    pub usable: bool,
    pub scopes: Vec<String>,
}

/// Every device, as of one read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Devices {
    /// When the read that produced it started.
    pub at: Instant,
    pub devices: HashMap<String, DeviceState>,
}

/// A socket's view of [`Devices`]: only a snapshot read after `since` (when the socket
/// subscribed, after its gate check) may close it, so a read already under way when the
/// device enrolled or was rescoped cannot.
pub struct DeviceWatch {
    pub rx: watch::Receiver<Option<Arc<Devices>>>,
    pub since: Instant,
}

impl DeviceWatch {
    /// `device`'s state in the newest snapshot read after `since`; `Some(None)` when it has no
    /// row there; `None` when there is no such snapshot yet.
    pub fn current(&mut self, device: &str) -> Option<Option<DeviceState>> {
        let snap = self.rx.borrow_and_update();
        let snap = snap.as_ref().filter(|s| s.at > self.since)?;
        Some(snap.devices.get(device).cloned())
    }
}

#[derive(Default)]
pub struct Live {
    head: OnceLock<Arc<watch::Sender<i64>>>,
    devices: OnceLock<Arc<watch::Sender<Option<Arc<Devices>>>>>,
    /// Event pages read by sockets (what the idle test counts).
    pub reads: AtomicU64,
}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Live").finish_non_exhaustive()
    }
}

impl Live {
    /// The newest event seq, polled every `every` (the first caller's) while anyone listens.
    pub fn head(&self, pool: &SqlitePool, every: Duration) -> watch::Receiver<i64> {
        let tx = self.head.get_or_init(|| {
            let tx = Arc::new(watch::Sender::new(0));
            let weak = Arc::downgrade(&tx);
            let pool = pool.clone();
            tokio::spawn(poll(weak, every, move |tx| {
                let pool = pool.clone();
                async move {
                    if let Ok(head) = crate::store::events::last_event_seq(&pool).await {
                        tx.send_if_modified(|v| {
                            let grew = head > *v;
                            if grew {
                                *v = head;
                            }
                            grew
                        });
                    }
                }
            }));
            tx
        });
        tx.subscribe()
    }

    /// The device snapshot, read every `every` (the first caller's) while anyone listens.
    pub fn devices(&self, pool: &SqlitePool, every: Duration) -> DeviceWatch {
        let tx = self.devices.get_or_init(|| {
            let tx = Arc::new(watch::Sender::new(None));
            let weak = Arc::downgrade(&tx);
            let pool = pool.clone();
            tokio::spawn(poll(weak, every, move |tx| {
                let pool = pool.clone();
                async move {
                    let at = Instant::now();
                    // A failed read keeps the last snapshot; the next tick retries.
                    // Every snapshot wakes its watchers, unchanged or not: one read after a
                    // socket's `since` must reach it even when the change it shows (a
                    // revocation between the gate and the subscription) came before. A wake is
                    // a map lookup, no database read.
                    if let Ok(devices) = read_devices(&pool).await {
                        tx.send_replace(Some(Arc::new(Devices { at, devices })));
                    }
                }
            }));
            tx
        });
        DeviceWatch {
            rx: tx.subscribe(),
            since: Instant::now(),
        }
    }
}

/// Runs `tick` every `every` while `tx` lives and has a receiver.
async fn poll<T, F, Fut>(tx: Weak<watch::Sender<T>>, every: Duration, tick: F)
where
    F: Fn(Arc<watch::Sender<T>>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let mut timer = tokio::time::interval(every);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        timer.tick().await;
        let Some(tx) = tx.upgrade() else { return };
        if tx.receiver_count() > 0 {
            tick(tx).await;
        }
    }
}

async fn read_devices(pool: &SqlitePool) -> Result<HashMap<String, DeviceState>, sqlx::Error> {
    let rows: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT id, scopes, status = 'active' AND revoked_at IS NULL FROM core_devices",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, scopes, usable)| {
            // Unparsable scopes never match a socket's, so it is closed: fail closed.
            let scopes = serde_json::from_str(&scopes).unwrap_or_default();
            (id, DeviceState { usable, scopes })
        })
        .collect())
}
