//! The driver's side of the gateway: the capability gate, the stop race, the order of closing,
//! `agent.limit`, and the reports' own channel (numbering, acknowledgement, restart, forgery).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use ainkrad_proto::v2::{
    AgentLimit, Ceiling, GatewayAuth, GatewayGrant, GatewayReportKind, ModelPrice, Rate, Upstream,
    UpstreamStatus, Wire,
};
use tokio::sync::Notify;

use super::super::tests::{dirs, start};
use super::*;
use crate::{Executor, Job, Report};

const SESSION: &str = "as_gwtest0000000000000000001";

/// Records what the harness side sees: whether the gateway's socket still existed whenever it was
/// signalled, and whether it was ever started.
#[derive(Clone, Default)]
struct Rec {
    sock: Arc<Mutex<Option<PathBuf>>>,
    started: Arc<AtomicUsize>,
    saw: Arc<Mutex<Vec<bool>>>,
    hold: Arc<Notify>,
}

impl Executor for Rec {
    async fn start(&self, _: &Job) -> Result<Option<String>, String> {
        self.started.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    async fn run(&self, _: &Job, _: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        // A harness that prints a line shaped like a usage report: only a transcript entry.
        let forged = json!({"type": "gateway_usage", "gw_seq": 99, "input": 1_000_000});
        let _ = reports.send(Report::Event(forged)).await;
        self.hold.notified().await;
        Outcome::Succeeded
    }

    fn control(&self, _: i64, _: Control) {
        let sock = self.sock.lock().unwrap().clone();
        self.saw
            .lock()
            .unwrap()
            .push(sock.is_some_and(|s| s.exists()));
    }

    fn session_env(&self, _: i64, env: Option<Vec<(String, String)>>) {
        for (n, v) in env.into_iter().flatten() {
            if n == "AINKRAD_SANDBOX_GW_SOCK" {
                *self.sock.lock().unwrap() = Some(PathBuf::from(v));
            }
        }
    }
}

/// A sandbox that has proven its gateway.
struct WithGateway;

impl Sandbox for WithGateway {
    fn name(&self) -> &'static str {
        "test"
    }
    fn prepare(&self, _: &AgentStart, _: &mut Vec<(String, String)>) -> Result<(), String> {
        Ok(())
    }
    fn capabilities(&self) -> &'static [&'static str] {
        &[CAP_GATEWAY]
    }
}

fn grant(lease: &str) -> GatewayGrant {
    GatewayGrant {
        lease: lease.to_owned(),
        account: 1,
        provider: "anthropic".to_owned(),
        user_key: None,
        upstream: Upstream {
            host: "api.anthropic.com".to_owned(),
            base_path: String::new(),
            wire: Wire::AnthropicMessages,
            auth: GatewayAuth::XApiKey,
        },
        models: vec!["m".to_owned()],
        prices: vec![ModelPrice {
            model: "m".to_owned(),
            input: 1,
            output: 1,
            cache_read: 1,
            cache_write: 1,
        }],
        ceiling: Ceiling {
            tokens: 1000,
            usd_micros: 1000,
        },
        rate: Rate {
            per_minute: 60,
            concurrent: 2,
        },
    }
}

/// `l_fast` answers at once, `l_slow` when the gate opens (and says it was asked).
fn redeem(gate: Arc<Notify>, asked: Arc<AtomicBool>) -> Redeem {
    Arc::new(move |lease: String| {
        let (gate, asked) = (gate.clone(), asked.clone());
        Box::pin(async move {
            asked.store(true, Ordering::SeqCst);
            if lease == "l_slow" {
                gate.notified().await;
            } else if lease != "l_fast" {
                return Err("no such lease".to_owned());
            }
            Ok(secrets::Leased {
                name: "acct.anthropic.1".to_owned(),
                delivery: "gateway".to_owned(),
                // Built at runtime from a shape prefix and a filler.
                value: zeroize::Zeroizing::new(format!("sk-ant-{}", "k9".repeat(12))),
            })
        })
    })
}

struct Rig {
    d: Arc<AgentDriver>,
    rec: Rec,
    gate: Arc<Notify>,
    asked: Arc<AtomicBool>,
    _root: crate::workspace::tests::TestDir,
}

fn rig(name: &str, gateway_capable: bool) -> Rig {
    let (root, config) = dirs(name);
    let (rec, gate, asked) = (Rec::default(), Arc::new(Notify::new()), Arc::default());
    let mut d = AgentDriver::new(config, rec.clone())
        .unwrap()
        .with_redeem(redeem(gate.clone(), Arc::clone(&asked)));
    if gateway_capable {
        d = d.with_sandbox(Arc::new(WithGateway));
    }
    Rig {
        d: Arc::new(d),
        rec,
        gate,
        asked,
        _root: root,
    }
}

fn gateway_start(lease: &str) -> AgentStart {
    AgentStart {
        gateway: Some(Box::new(grant(lease))),
        ..start(SESSION, "fake")
    }
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..300 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

fn ceiling_of(d: &AgentDriver) -> Option<Ceiling> {
    let all = d.sessions.lock().unwrap();
    all.get(SESSION)?
        .gateway
        .as_ref()
        .map(|g| g.meter().ceiling())
}

#[tokio::test]
async fn a_grant_is_refused_unless_the_runner_has_proven_its_gateway() {
    let r = rig("gw-cap", false);
    let e = r.d.start(gateway_start("l_fast")).unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    assert!(r.d.states().is_empty(), "nothing was started");
    // The ops answer unsupported_command there, too.
    let limit = AgentLimit {
        session: SESSION.to_owned(),
        ceiling: Ceiling {
            tokens: 0,
            usd_micros: 0,
        },
    };
    assert_eq!(
        r.d.limit(limit).unwrap_err().code,
        ErrorCode::UnsupportedCommand
    );
}

#[tokio::test]
async fn stopping_closes_the_gateway_before_the_harness_is_signalled() {
    let r = rig("gw-order", true);
    r.d.start(gateway_start("l_fast")).unwrap();
    until("the harness to run", || {
        r.rec.started.load(Ordering::SeqCst) == 1 && ceiling_of(&r.d).is_some()
    })
    .await;
    let sock = r.rec.sock.lock().unwrap().clone().unwrap();
    assert!(sock.exists(), "the gateway is open while the session runs");
    r.d.stop(AgentStop {
        session: SESSION.to_owned(),
        kill: false,
    })
    .unwrap();
    // `control` ran after the stop closed the gateway: the socket was already gone.
    assert_eq!(*r.rec.saw.lock().unwrap(), [false]);
    assert!(!sock.exists());
    r.rec.hold.notify_one();
}

#[tokio::test]
async fn a_stop_during_lease_redemption_never_starts_the_harness() {
    let r = rig("gw-race", true);
    r.d.start(gateway_start("l_slow")).unwrap();
    until("the lease to be asked for", || {
        r.asked.load(Ordering::SeqCst)
    })
    .await;
    r.d.stop(AgentStop {
        session: SESSION.to_owned(),
        kill: false,
    })
    .unwrap();
    r.gate.notify_one(); // the redemption completes after the stop
    until("the session to end", || {
        r.d.states().get(SESSION) == Some(&AgentState::Ended)
    })
    .await;
    assert_eq!(
        r.rec.started.load(Ordering::SeqCst),
        0,
        "the harness was started"
    );
    let ev =
        r.d.read(&AgentRead {
            session: SESSION.to_owned(),
            after: 0,
            wait_ms: None,
            gw_after: 0,
        })
        .await
        .unwrap();
    assert!(
        matches!(ev.outcome, Some(Outcome::Cancelled { .. })),
        "{:?}",
        ev.outcome
    );
    // A later start of the same session is not poisoned by the old marker.
    let sock = socket_of(&r);
    assert!(sock.is_none_or(|s| !s.exists()));
}

fn socket_of(r: &Rig) -> Option<PathBuf> {
    r.rec.sock.lock().unwrap().clone()
}

#[tokio::test]
async fn agent_limit_moves_the_ceiling_and_one_sent_during_redemption_is_applied_on_install() {
    let r = rig("gw-limit", true);
    r.d.start(gateway_start("l_slow")).unwrap();
    until("the lease to be asked for", || {
        r.asked.load(Ordering::SeqCst)
    })
    .await;
    let limit = |tokens, usd_micros| AgentLimit {
        session: SESSION.to_owned(),
        ceiling: Ceiling { tokens, usd_micros },
    };
    r.d.limit(limit(7, 9)).unwrap(); // no gateway yet: kept for the install
    r.gate.notify_one();
    until("the gateway to open", || ceiling_of(&r.d).is_some()).await;
    assert_eq!(
        ceiling_of(&r.d),
        Some(Ceiling {
            tokens: 7,
            usd_micros: 9
        })
    );
    r.d.limit(limit(0, 0)).unwrap();
    assert_eq!(
        ceiling_of(&r.d),
        Some(Ceiling {
            tokens: 0,
            usd_micros: 0
        })
    );
    // A session with no gateway has nothing to limit.
    let plain = AgentStart {
        session: "as_plain000000000000000000001".to_owned(),
        ..start("as_plain000000000000000000001", "fake")
    };
    r.d.start(plain).unwrap();
    let e =
        r.d.limit(AgentLimit {
            session: "as_plain000000000000000000001".to_owned(),
            ..limit(0, 0)
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidArgs);
    r.rec.hold.notify_waiters();
}

fn report(model: &str) -> GatewayReport {
    GatewayReport {
        gw_seq: 0,
        epoch: 0,
        kind: GatewayReportKind::Usage,
        model: Some(model.to_owned()),
        input: 1,
        output: 2,
        cache_read: 0,
        cache_write: 0,
        status: UpstreamStatus::Ok,
        approximate: false,
        reported_usd_micros: None,
        retry_after: None,
        reset_at: None,
    }
}

#[tokio::test]
async fn reports_have_their_own_numbering_and_acknowledgement_and_a_harness_line_is_not_one() {
    let r = rig("gw-reports", true);
    r.d.start(gateway_start("l_fast")).unwrap();
    until("the harness to run", || {
        r.rec.started.load(Ordering::SeqCst) == 1
    })
    .await;
    // The harness printed a line shaped like a usage report: a transcript entry, no report.
    let forged = |ev: &AgentEvents| {
        ev.entries
            .iter()
            .any(|e| e.body["type"] == "gateway_usage" && e.body["gw_seq"] == 99)
    };
    let mut ev = AgentEvents {
        gateway: vec![],
        session: String::new(),
        state: AgentState::Running,
        last_seq: 0,
        entries: vec![],
        harness_session: None,
        usage: None,
        outcome: None,
    };
    for _ in 0..50 {
        if forged(&ev) {
            break;
        }
        ev =
            r.d.read(&AgentRead {
                session: SESSION.to_owned(),
                after: 0,
                wait_ms: Some(200),
                gw_after: 0,
            })
            .await
            .unwrap();
    }
    assert!(forged(&ev) && ev.gateway.is_empty());
    let read = |gw_after| AgentRead {
        session: SESSION.to_owned(),
        after: ev.last_seq,
        wait_ms: Some(300),
        gw_after,
    };
    // Reports the gateway made are numbered from 1 by the driver, whatever they carry.
    for m in ["a", "b"] {
        r.d.with(SESSION, |live, cfg, s| {
            live.reports.push(cfg, s, live.meta.epoch, report(m))
        });
    }
    let ev = r.d.read(&read(0)).await.unwrap();
    let seqs: Vec<u64> = ev.gateway.iter().map(|g| g.gw_seq).collect();
    assert_eq!(seqs, [1, 2]);
    // Shown once and not acknowledged: they come again, and do not end a wait early.
    let t = std::time::Instant::now();
    let again = r.d.read(&read(0)).await.unwrap();
    assert_eq!(again.gateway.len(), 2);
    assert!(t.elapsed() >= Duration::from_millis(250), "it spun");
    // Acknowledged: gone.
    let ev = r.d.read(&read(1)).await.unwrap();
    assert_eq!(ev.gateway.iter().map(|g| g.gw_seq).collect::<Vec<_>>(), [2]);
    let ev = r.d.read(&read(2)).await.unwrap();
    assert!(ev.gateway.is_empty());
    r.rec.hold.notify_one();
}

#[tokio::test]
async fn unacknowledged_reports_survive_a_restart_and_numbering_goes_on() {
    let (root, config) = dirs("gw-restart");
    let meta = |acked| -> Meta {
        serde_json::from_value(
            json!({"harness":"fake","state":"ended","last_seq":0,"acked":0,"gw_acked":acked}),
        )
        .unwrap()
    };
    secrets::private_dir(&config.dir.join(SESSION)).unwrap();
    let mut reports = Reports::default();
    for m in ["a", "b", "c"] {
        reports.push(&config, SESSION, 0, report(m));
    }
    let loaded = Reports::load(&config, SESSION, &meta(1));
    let seqs: Vec<u64> = loaded.batch().iter().map(|g| g.gw_seq).collect();
    assert_eq!(seqs, [2, 3], "the acknowledged one is not held again");
    let mut loaded = loaded;
    loaded.push(&config, SESSION, 0, report("d"));
    assert_eq!(loaded.batch().last().unwrap().gw_seq, 4);
    // All acknowledged and none new: numbering continues from the acknowledgement.
    let none = Reports::load(&config, SESSION, &meta(4));
    assert!(none.batch().is_empty());
    let mut none = none;
    none.push(&config, SESSION, 0, report("e"));
    assert_eq!(none.batch()[0].gw_seq, 5);
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(path(&config, SESSION))
            .unwrap()
            .permissions(),
    );
    assert_eq!(mode & 0o777, 0o600);
    drop(root);
}

#[tokio::test]
async fn a_report_the_disk_cannot_hold_fails_closed_and_the_epoch_is_stamped() {
    let (root, config) = dirs("gw-broken");
    secrets::private_dir(&config.dir.join(SESSION)).unwrap();
    // The file's path is a directory: the append fails.
    std::fs::create_dir(path(&config, SESSION)).unwrap();
    let mut reports = Reports::default();
    assert!(!reports.full());
    reports.push(&config, SESSION, 3, report("a"));
    assert!(
        reports.full(),
        "a failed write stops the gateway admitting requests"
    );
    let held = reports.batch();
    assert_eq!(
        (held[0].gw_seq, held[0].epoch),
        (1, 3),
        "kept in memory, numbered, stamped"
    );
    // Acknowledging does not lift it: the numbering may not be trusted again this run.
    reports.acknowledge(&config, SESSION, 1);
    assert!(reports.full());
    drop(root);
}

#[tokio::test]
async fn acknowledged_reports_are_dropped_from_the_file_and_a_reload_seeds_the_cap() {
    let (root, config) = dirs("gw-compact");
    secrets::private_dir(&config.dir.join(SESSION)).unwrap();
    let mut reports = Reports::default();
    for _ in 0..(COMPACT_AT + 5) {
        reports.push(&config, SESSION, 0, report("a"));
    }
    let lines = |c: &AgentConfig| {
        std::fs::read_to_string(path(c, SESSION))
            .unwrap()
            .lines()
            .count()
    };
    assert_eq!(lines(&config), COMPACT_AT + 5);
    reports.acknowledge(&config, SESSION, COMPACT_AT as u64);
    assert_eq!(lines(&config), 5, "the acknowledged lines are gone");
    reports.push(&config, SESSION, 0, report("b")); // appended to the new file
    assert_eq!(lines(&config), 6);
    assert_eq!(
        reports.batch().last().unwrap().gw_seq,
        COMPACT_AT as u64 + 6
    );
    // A reload holding more than the cap starts the gateway refusing.
    let mut many = Reports::default();
    for _ in 0..MAX_HELD {
        many.held.push_back(report("c"));
    }
    assert!(many.full());
    drop(root);
}
