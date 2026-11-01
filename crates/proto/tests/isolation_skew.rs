//! Version skew of the isolation capability (E8a-09): an old runner on a new Core and the
//! reverse. The capability is additive; what a Core does without it is decided in the server.

use ainkrad_proto::runner::Isolation;
use ainkrad_proto::v2::{Heartbeat, IsolationCaps, Kvm, RunnerHello};
use serde::Deserialize;
use serde_json::json;

/// A hello as it was before E8a-09, ignoring what it does not know (as an old Core does).
#[derive(Debug, Deserialize)]
struct OldHello {
    protocol: String,
    #[serde(default)]
    arch: Option<String>,
}

fn caps() -> IsolationCaps {
    IsolationCaps::of(Isolation::Process, Kvm::Absent)
}

#[test]
fn an_old_runners_hello_and_heartbeat_parse_with_no_capability() {
    let hello: RunnerHello = serde_json::from_value(json!({
        "protocol": "2.0", "runner_version": "0.1.0", "drivers": [], "arch": "aarch64"
    }))
    .unwrap();
    assert_eq!(hello.isolation, None);
    let beat: Heartbeat =
        serde_json::from_value(json!({"load": {"avg1": 1.0, "cores": 2}})).unwrap();
    assert_eq!(beat.isolation, None);
    // And a plain hello or heartbeat serializes without the key: old goldens stay byte-identical.
    assert!(!serde_json::to_string(&hello).unwrap().contains("isolation"));
    assert!(
        !serde_json::to_string(&Heartbeat::default())
            .unwrap()
            .contains("isolation")
    );
}

#[test]
fn an_old_core_reads_a_new_hello_and_drops_the_capability() {
    let hello = RunnerHello {
        protocol: "2.0".to_owned(),
        arch: Some("x86_64".to_owned()),
        isolation: Some(caps()),
        ..Default::default()
    };
    let old: OldHello = serde_json::from_value(serde_json::to_value(&hello).unwrap()).unwrap();
    assert_eq!(old.protocol, "2.0");
    assert_eq!(old.arch.as_deref(), Some("x86_64"));
}

#[test]
fn a_tier_or_state_from_a_newer_runner_parses_and_meets_nothing() {
    let beat: Heartbeat = serde_json::from_value(
        json!({"isolation": {"tiers": ["gvisor", "process"], "kvm": "degraded"}}),
    )
    .unwrap();
    let caps = beat.isolation.unwrap();
    assert_eq!(caps.kvm, Kvm::Unknown);
    assert!(caps.meets(Isolation::Process));
    assert!(!caps.meets(Isolation::Microvm));
    let only_new = IsolationCaps {
        tiers: vec!["gvisor".to_owned()],
        kvm: Kvm::NotApplicable,
    };
    for tier in [Isolation::None, Isolation::Process, Isolation::Microvm] {
        assert!(!only_new.meets(tier), "{tier:?}");
    }
}

#[test]
fn offered_tiers_meet_the_same_or_a_weaker_requirement_only() {
    let process = IsolationCaps::of(Isolation::Process, Kvm::Absent);
    assert!(process.meets(Isolation::None) && process.meets(Isolation::Process));
    assert!(!process.meets(Isolation::Microvm));
    let none = IsolationCaps::of(Isolation::None, Kvm::NotApplicable);
    assert!(none.meets(Isolation::None) && !none.meets(Isolation::Process));
    assert!(
        !IsolationCaps::default().meets(Isolation::None),
        "an empty list offers nothing"
    );
    let vm = IsolationCaps::of(Isolation::Microvm, Kvm::Usable);
    assert!(vm.meets(Isolation::Process) && vm.meets(Isolation::Microvm));
}
