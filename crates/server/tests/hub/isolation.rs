//! Isolation tiers end to end (E8a-09): a runner advertises what its sandbox gives, the Core
//! places a session needing a tier only where it is offered and says why not, the runner refuses
//! again whatever the Core believed, and a tier that goes away mid-life ends the sessions that
//! need it loudly and stops being offered. The real Core and the real runner daemon; the runner's
//! sandbox is a stand-in whose tier the test flips.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::agents::{self as service, tier_refusal};
use ainkrad_core_server::hub::RunnerState;
use ainkrad_core_server::store::agents::{self as sessions, NewSession};
use ainkrad_proto::runner::{Isolation, Outcome, RunToken};
use ainkrad_proto::v2::{AgentStart, IsolationCaps, Kvm};
use ainkrad_runner::v2::agent::{AgentConfig, AgentDriver, Sandbox};
use ainkrad_runner::v2::client::Client;
use ainkrad_runner::v2::daemon::{Backoff, Daemon};
use ainkrad_runner::v2::key::{Enrolment, Key, State};
use ainkrad_runner::{Executor, Job, Report};
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};

use super::agents::make_admin;
use super::runner::{driver, paired, state};
use super::{Core, quick};

/// A harness that works until it is stopped.
#[derive(Clone, Default)]
struct Hang;

impl Executor for Hang {
    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        Ok(Some(format!("h-{}", job.context_ref)))
    }
    async fn run(&self, _: &Job, _: RunToken, _: mpsc::Sender<Report>) -> Outcome {
        std::future::pending().await
    }
}

/// A sandbox whose tier the test sets: 0 none, 1 process.
struct Flip(Arc<AtomicU8>, Arc<Mutex<usize>>);

impl Sandbox for Flip {
    fn name(&self) -> &'static str {
        "flip"
    }
    fn tier(&self) -> Isolation {
        match self.0.load(Ordering::SeqCst) {
            0 => Isolation::None,
            _ => Isolation::Process,
        }
    }
    fn prepare(&self, _: &AgentStart, _: &mut Vec<(String, String)>) -> Result<(), String> {
        *self.1.lock().unwrap() += 1;
        Ok(())
    }
}

struct Live {
    id: String,
    driver: Arc<AgentDriver>,
    tier: Arc<AtomicU8>,
    prepared: Arc<Mutex<usize>>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

async fn until(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..600 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn runner(core: &Core, name: &str, tier: u8) -> Live {
    let base = format!("http://{}", core.host);
    let st: State = state(name);
    let e = paired(core, &base, None, &st).await;
    let key = Arc::new(Key::load(&st.key()).unwrap());
    let enrolment = Arc::new(Mutex::new(Enrolment::load(&st.enrolment()).unwrap()));
    let (flag, prepared) = (Arc::new(AtomicU8::new(tier)), Arc::new(Mutex::new(0)));
    let config = AgentConfig::new(st.0.join("agents"), st.0.join("secrets"));
    let agents = Arc::new(
        AgentDriver::new(config, Hang)
            .unwrap()
            .with_sandbox(Arc::new(Flip(flag.clone(), prepared.clone()))),
    );
    // The daemon's own constructor starts this watch; the test builds the Daemon directly.
    agents.watch_isolation(Duration::from_millis(100));
    let daemon = Daemon {
        client: Client::new(&base, None).unwrap(),
        key,
        enrolment,
        save: None,
        exec: driver(),
        pty: None,
        agents: Some(Arc::clone(&agents)),
        tls: None,
        backoff: Backoff {
            min: Duration::from_millis(50),
            max: Duration::from_millis(200),
            refused: Duration::from_millis(200),
        },
    };
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(async move {
        let _ = daemon.run(stopped).await;
    });
    until("the runner online", || core.app.hub.online(&e.device_id)).await;
    Live {
        id: e.device_id,
        driver: agents,
        tier: flag,
        prepared,
        stop,
        task,
    }
}

impl Live {
    async fn halt(self) {
        self.stop.send_replace(true);
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
    }

    fn offered(&self, core: &Core) -> Option<IsolationCaps> {
        core.app.hub.runners()[&self.id].isolation.clone()
    }
}

fn needs(tier: &str) -> Value {
    json!({"mode": "ask", "min_isolation": tier})
}

async fn refusal(core: &Core, runner: &str, policy: &Value) -> Option<String> {
    service::admit_with(&core.app, runner, "fake", policy)
        .await
        .err()
        .map(|e| service::describe(&e))
}

async fn session(core: &Core, runner: &str, policy: &Value) -> String {
    make_admin(core, runner).await;
    let new = NewSession {
        runner,
        harness: "fake",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy,
        secrets: &[],
        created_by: runner,
    };
    let s = sessions::create(
        &core.app.pool,
        &new,
        AuditActor::System,
        &core.app.clock.now(),
    )
    .await
    .unwrap();
    service::authorize_for_tests(&core.app, &s.id);
    service::start(&core.app, &s)
        .await
        .unwrap_or_else(|e| panic!("{}", service::describe(&e)));
    s.id
}

#[tokio::test]
async fn a_runner_advertises_its_tier_and_the_core_places_by_it_with_a_reason() {
    let core = Core::start("iso-place", quick()).await;
    let none = runner(&core, "iso-none", 0).await;
    let process = runner(&core, "iso-proc", 1).await;
    // Listed per runner: hello's tiers and kvm state, and the architecture.
    assert_eq!(
        none.offered(&core),
        Some(IsolationCaps::of(Isolation::None, Kvm::NotApplicable))
    );
    assert_eq!(
        process.offered(&core),
        Some(IsolationCaps::of(Isolation::Process, Kvm::NotApplicable))
    );
    assert!(core.app.hub.runners()[&process.id].arch.is_some());
    // A tier requested on a process-only or unsandboxed runner is refused with the reason.
    let why = refusal(&core, &process.id, &needs("microvm"))
        .await
        .unwrap();
    assert!(why.contains("microvm") && why.contains("process"), "{why}");
    let why = refusal(&core, &none.id, &needs("process")).await.unwrap();
    assert!(why.contains("process") && why.contains("none"), "{why}");
    // An isolation field alone (no min_isolation) needs a sandbox too: refused on the unsandboxed one.
    let why = refusal(&core, &none.id, &json!({"mode": "ask", "wall_secs": 60}))
        .await
        .unwrap();
    assert!(why.contains("process") && why.contains("none"), "{why}");
    // The legacy sandbox flag and mode need `process` as well.
    let legacy = json!({"mode": "sandboxed", "sandboxed": true});
    assert!(refusal(&core, &none.id, &legacy).await.is_some());
    assert_eq!(refusal(&core, &process.id, &legacy).await, None);
    // Controls: the tier it offers, a weaker one, and a policy with no requirement place.
    assert_eq!(refusal(&core, &process.id, &needs("process")).await, None);
    assert_eq!(refusal(&core, &process.id, &needs("none")).await, None);
    assert_eq!(
        refusal(&core, &none.id, &json!({"mode": "ask"})).await,
        None
    );
    // A refused session never reached either runner's sandbox.
    assert_eq!(
        *process.prepared.lock().unwrap() + *none.prepared.lock().unwrap(),
        0
    );
    none.halt().await;
    process.halt().await;
}

#[tokio::test]
async fn a_forged_advertisement_is_caught_by_the_runner_itself() {
    let core = Core::start("iso-forged", quick()).await;
    let r = runner(&core, "iso-forged", 0).await;
    // The Core is told (or believes) that this runner offers a VM: the runner's own sandbox does
    // not, and the start the Core sends is refused by the runner, never run weaker.
    let forged = IsolationCaps::of(Isolation::Microvm, Kvm::Usable);
    assert!(forged.meets(Isolation::Microvm));
    let mut start = AgentStart {
        session: "as_forged".to_owned(),
        harness: "fake".to_owned(),
        model: None,
        prompt: None,
        workspace: None,
        policy: Default::default(),
        resume: None,
        secrets: vec![],
    };
    start.policy.min_isolation = Some(Isolation::Microvm);
    let why = r.driver.start(start).unwrap_err();
    assert!(
        why.message.contains("microvm") && why.message.contains("none"),
        "{why:?}"
    );
    assert_eq!(*r.prepared.lock().unwrap(), 0);
    assert!(r.driver.states().is_empty());
    r.halt().await;
}

#[tokio::test]
async fn a_tier_that_disappears_ends_its_sessions_loudly_and_is_no_longer_offered() {
    let core = Core::start("iso-loss", quick()).await;
    let r = runner(&core, "iso-loss", 1).await;
    let needing = session(&core, &r.id, &needs("process")).await;
    let plain = session(&core, &r.id, &json!({"mode": "ask"})).await;
    until("both running", || {
        r.driver
            .states()
            .values()
            .filter(|s| format!("{s:?}") == "Running")
            .count()
            == 2
    })
    .await;
    // The probe fails (the stand-in for /dev/kvm vanishing): the runner stops offering the tier.
    r.tier.store(0, Ordering::SeqCst);
    // The session that needed it ends, failed, with the reason; the plain one is left alone.
    let reason = loop {
        let s = sessions::get(&core.app.pool, &needing)
            .await
            .unwrap()
            .unwrap();
        if !s.live() {
            break s.outcome.as_ref().map(Value::to_string).unwrap_or_default();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(
        reason.contains("no longer available") && reason.contains("process"),
        "{reason}"
    );
    assert!(
        sessions::get(&core.app.pool, &plain)
            .await
            .unwrap()
            .unwrap()
            .live()
    );
    // The Core learns it from the next heartbeat, and refuses the next placement.
    until("the Core to see the loss", || {
        r.offered(&core) == Some(IsolationCaps::of(Isolation::None, Kvm::NotApplicable))
    })
    .await;
    let why = refusal(&core, &r.id, &needs("process")).await.unwrap();
    assert!(why.contains("process") && why.contains("none"), "{why}");
    // Never downgraded: the refused session was not started anywhere at the weaker tier.
    let before = *r.prepared.lock().unwrap();
    assert!(session_start_refused(&core, &r.id).await);
    assert_eq!(*r.prepared.lock().unwrap(), before);
    r.halt().await;
}

/// Starting a session that needs `process` on the now-unsandboxed runner fails (it is ended,
/// not run).
async fn session_start_refused(core: &Core, runner: &str) -> bool {
    make_admin(core, runner).await;
    let policy = needs("process");
    let new = NewSession {
        runner,
        harness: "fake",
        model: None,
        prompt: Some("go"),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: runner,
    };
    let s = sessions::create(
        &core.app.pool,
        &new,
        AuditActor::System,
        &core.app.clock.now(),
    )
    .await
    .unwrap();
    service::authorize_for_tests(&core.app, &s.id);
    service::start(&core.app, &s).await.is_err()
}

fn state_of(isolation: Option<IsolationCaps>, degraded: bool) -> RunnerState {
    RunnerState {
        online: true,
        degraded,
        last_seen: 0,
        version: String::new(),
        drivers: vec![],
        capacity: 1,
        load: 0,
        host_load: None,
        isolation,
        arch: None,
    }
}

#[test]
fn placement_refuses_a_degraded_silent_unreported_or_short_runner_and_an_unreadable_policy() {
    let process = Some(IsolationCaps::of(Isolation::Process, Kvm::Absent));
    let vm = needs("microvm");
    let proc_req = needs("process");
    // Offered and fresh: placed.
    assert_eq!(
        tier_refusal(&state_of(process.clone(), false), &proc_req),
        None
    );
    // On a degraded (silent) runner, even for a tier it last offered.
    let why = tier_refusal(&state_of(process.clone(), true), &proc_req).unwrap();
    assert!(why.contains("silent"), "{why}");
    // A runner that never reported: no guarantee, so no session that needs one.
    let why = tier_refusal(&state_of(None, false), &proc_req).unwrap();
    assert!(why.contains("not reported"), "{why}");
    // Too weak.
    assert!(tier_refusal(&state_of(process.clone(), false), &vm).is_some());
    // An empty offer and an unknown tier meet nothing.
    for offered in [vec![], vec!["gvisor".to_owned()]] {
        let caps = IsolationCaps {
            tiers: offered,
            kvm: Kvm::Unusable,
        };
        assert!(tier_refusal(&state_of(Some(caps), false), &proc_req).is_some());
    }
    // A policy that does not parse is refused, never read as "no requirement".
    let why = tier_refusal(&state_of(process, false), &json!({"min_isolation": "vm"})).unwrap();
    assert!(why.contains("shape"), "{why}");
    // No requirement needs no report: an old runner still takes plain sessions.
    assert_eq!(
        tier_refusal(&state_of(None, false), &json!({"mode": "ask"})),
        None
    );
    assert_eq!(tier_refusal(&state_of(None, true), &needs("none")), None);
}

#[test]
fn egress_rules_are_placed_only_on_a_runner_that_advertises_the_filter() {
    use ainkrad_proto::v2::{AGENT_DRIVER, DriverInfo};
    let with = |commands: &[&str]| {
        let mut r = state_of(
            Some(IsolationCaps::of(Isolation::Process, Kvm::NotApplicable)),
            false,
        );
        r.drivers = vec![DriverInfo {
            name: AGENT_DRIVER.to_owned(),
            commands: commands.iter().map(|c| (*c).to_owned()).collect(),
            capacity: 1,
            ..Default::default()
        }];
        r
    };
    let rules = json!({"mode": "ask", "egress": {"allow": ["10.0.0.0/8"]}});
    let why = tier_refusal(&with(&["agent.start"]), &rules).unwrap();
    assert!(why.contains("egress filter"), "{why}");
    assert_eq!(
        tier_refusal(&with(&["agent.start", "egress-filter"]), &rules),
        None
    );
    // The marker on some other driver does not count, and a plain session needs none.
    assert!(tier_refusal(&state_of(None, false), &rules).is_some());
    assert_eq!(
        tier_refusal(&with(&["agent.start"]), &json!({"mode": "ask"})),
        None
    );
}

fn only(field: Value) -> Value {
    let mut policy = json!({"mode": "ask"});
    policy
        .as_object_mut()
        .unwrap()
        .extend(field.as_object().unwrap().clone());
    policy
}

fn each_field() -> Vec<Value> {
    vec![
        only(json!({"min_isolation": "process"})),
        only(json!({"image": format!("sha256:{}", "ab".repeat(32))})),
        only(json!({"vcpus": 2})),
        only(json!({"memory_mb": 512})),
        only(json!({"disk_mb": 512})),
        only(json!({"wall_secs": 60})),
        only(json!({"workspace": "copy"})),
        only(json!({"egress": {"allow": ["10.0.0.0/8"]}})),
    ]
}

#[test]
fn any_isolation_field_alone_is_never_sent_to_a_runner_that_has_not_advertised_or_is_silent() {
    use ainkrad_proto::v2::{AGENT_DRIVER, DriverInfo};
    let filtered = |mut r: RunnerState| {
        r.drivers = vec![DriverInfo {
            name: AGENT_DRIVER.to_owned(),
            commands: vec!["agent.start".to_owned(), "egress-filter".to_owned()],
            capacity: 1,
            ..Default::default()
        }];
        r
    };
    let process = Some(IsolationCaps::of(Isolation::Process, Kvm::NotApplicable));
    for policy in each_field() {
        // Never reported: refused (an old runner would drop the field and run without it).
        let why = tier_refusal(&filtered(state_of(None, false)), &policy).unwrap();
        assert!(why.contains("not reported"), "{policy}: {why}");
        // Silent: refused.
        let why = tier_refusal(&filtered(state_of(process.clone(), true)), &policy).unwrap();
        assert!(why.contains("silent"), "{policy}: {why}");
        // Offering `none` (an unsandboxed runner): refused.
        let none = Some(IsolationCaps::of(Isolation::None, Kvm::NotApplicable));
        assert!(
            tier_refusal(&filtered(state_of(none, false)), &policy).is_some(),
            "{policy}"
        );
        // Control: a fresh runner that offers the sandbox is placed (it enforces or refuses itself).
        assert_eq!(
            tier_refusal(&filtered(state_of(process.clone(), false)), &policy),
            None,
            "{policy}"
        );
    }
}

#[test]
fn legacy_sandbox_sessions_need_the_process_tier_at_placement() {
    let process = Some(IsolationCaps::of(Isolation::Process, Kvm::NotApplicable));
    let none = Some(IsolationCaps::of(Isolation::None, Kvm::NotApplicable));
    for policy in [
        json!({"mode": "ask", "sandboxed": true}),
        json!({"mode": "sandboxed"}),
        json!({"mode": "sandboxed", "sandboxed": true}),
    ] {
        assert!(
            tier_refusal(&state_of(None, false), &policy).is_some(),
            "{policy}"
        );
        assert!(
            tier_refusal(&state_of(none.clone(), false), &policy).is_some(),
            "{policy}"
        );
        assert!(
            tier_refusal(&state_of(process.clone(), true), &policy).is_some(),
            "{policy}"
        );
        assert_eq!(
            tier_refusal(&state_of(process.clone(), false), &policy),
            None,
            "{policy}"
        );
    }
    // A plain policy still places on a runner that reported nothing.
    assert_eq!(
        tier_refusal(&state_of(None, false), &json!({"mode": "ask"})),
        None
    );
}

#[tokio::test]
async fn placement_at_launch_refuses_a_runner_the_hub_does_not_know_or_that_lost_the_tier() {
    use ainkrad_core_server::agents::{Placement, placement};
    let core = Core::start("iso-launch", quick()).await;
    let r = runner(&core, "iso-launch", 1).await;
    let mk = |runner: String, policy: Value| {
        let core = &core;
        async move {
            make_admin(core, &runner).await;
            let new = NewSession {
                runner: &runner,
                harness: "fake",
                model: None,
                prompt: Some("go"),
                workspace: None,
                policy: &policy,
                secrets: &[],
                created_by: &runner,
            };
            sessions::create(
                &core.app.pool,
                &new,
                AuditActor::System,
                &core.app.clock.now(),
            )
            .await
            .unwrap()
        }
    };
    // A runner the hub never saw is not a pass (it used to be, through a missing entry).
    let ghost = "d_00000000000000000000000000".to_owned();
    let s = mk(ghost, needs("process")).await;
    assert!(matches!(placement(&core.app, &s), Placement::Away));
    // A connected one with the tier is placed; without it, refused with the reason.
    let s = mk(r.id.clone(), needs("process")).await;
    assert!(matches!(placement(&core.app, &s), Placement::Ok));
    r.tier.store(0, Ordering::SeqCst);
    until("the Core to see the loss", || {
        r.offered(&core) == Some(IsolationCaps::of(Isolation::None, Kvm::NotApplicable))
    })
    .await;
    match placement(&core.app, &s) {
        Placement::Refused(why) => {
            assert!(why.contains("process") && why.contains("none"), "{why}")
        }
        _ => panic!("a runner that lost the tier must refuse"),
    }
    r.halt().await;
}
