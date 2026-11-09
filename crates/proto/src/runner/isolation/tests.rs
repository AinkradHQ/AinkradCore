use super::*;
use crate::runner::Policy;

pub(super) fn full() -> Policy {
    Policy {
        min_isolation: Some(Isolation::Microvm),
        image: Some(format!("sha256:{}", "0f".repeat(32))),
        vcpus: Some(4),
        memory_mb: Some(1024),
        disk_mb: Some(2048),
        wall_secs: Some(600),
        egress: Some(Egress {
            allow: vec!["192.0.2.0/24".to_owned()],
            deny: vec![],
        }),
        workspace: Some(WorkspaceMode::Copy),
        ..Policy::default()
    }
}

#[test]
fn a_populated_policy_round_trips() {
    let p = full();
    let back: Policy = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
    assert_eq!(back, p);
    assert!(p.asks_for_isolation());
    assert_eq!(p.problem(), None);
}

#[test]
fn resources_are_bounded() {
    let with = |f: fn(&mut Policy)| {
        let mut p = Policy::default();
        f(&mut p);
        p.problem()
    };
    assert!(with(|p| p.vcpus = Some(0)).is_some());
    assert!(with(|p| p.vcpus = Some(33)).is_some());
    assert!(with(|p| p.vcpus = Some(32)).is_none());
    assert!(with(|p| p.memory_mb = Some(63)).is_some());
    assert!(with(|p| p.memory_mb = Some(262_145)).is_some());
    assert!(with(|p| p.memory_mb = Some(64)).is_none());
    assert!(with(|p| p.disk_mb = Some(15)).is_some());
    assert!(with(|p| p.disk_mb = Some(1_048_577)).is_some());
    assert!(with(|p| p.disk_mb = Some(16)).is_none());
    assert!(with(|p| p.wall_secs = Some(0)).is_some());
    assert!(with(|p| p.wall_secs = Some(86_401)).is_some());
    assert!(with(|p| p.wall_secs = Some(86_400)).is_none());
    assert!(with(|p| p.wall_secs = Some(u32::MAX)).is_some());
}

#[test]
fn an_image_is_a_sha256_digest() {
    let ok = format!("sha256:{}", "a1".repeat(32));
    assert_eq!(digest_problem(&ok), None);
    for bad in [
        "",
        "sha256:",
        &format!("sha256:{}", "A1".repeat(32)),
        &format!("sha256:{}", "a1".repeat(31)),
        &format!("sha256:{}", "a1".repeat(33)),
        &format!("sha512:{}", "a1".repeat(32)),
        &"a1".repeat(32),
        &format!("sha256:{}g", "a".repeat(63)),
        "ubuntu:latest",
        "registry.example/img@sha256:abc",
    ] {
        assert!(digest_problem(bad).is_some(), "{bad:?}");
    }
}

#[test]
fn egress_rules_are_ip_literals_or_cidrs_never_names() {
    for ok in [
        "10.0.0.0/8",
        "192.0.2.1",
        "0.0.0.0/0",
        "255.255.255.255/32",
        "fd00::/8",
        "2001:db8::1/128",
        "::1",
    ] {
        assert_eq!(cidr_problem(ok), None, "{ok}");
    }
    for bad in [
        "",
        "example.com",
        "localhost",
        "*.example.com",
        "10.0.0.0/33",
        "fd00::/129",
        "10.0.0.0/",
        "10.0.0.0/-1",
        "10.0.0.0/+8",
        "10.0.0.0/8/8",
        "10.0.0.0/abc",
        " 10.0.0.0/8",
        "10.0.0.0/8 ",
        "10.0.0",
        "http://10.0.0.1",
        "10.0.0.1:443",
        &"1".repeat(65),
    ] {
        assert!(cidr_problem(bad).is_some(), "{bad:?}");
    }
    let many = Egress {
        allow: vec!["10.0.0.0/8".to_owned(); 65],
        deny: vec![],
    };
    assert!(many.problem().is_some());
    let named = Policy {
        egress: Some(Egress {
            allow: vec![],
            deny: vec!["evil.example".to_owned()],
        }),
        ..Policy::default()
    };
    assert!(named.problem().unwrap().contains("deny"));
}

#[test]
fn a_stronger_tier_meets_a_weaker_requirement_and_never_the_reverse() {
    use Isolation::{Microvm, None as Nothing, Process};
    for (offered, required, ok) in [
        (Nothing, Nothing, true),
        (Nothing, Process, false),
        (Nothing, Microvm, false),
        (Process, Nothing, true),
        (Process, Process, true),
        (Process, Microvm, false),
        (Microvm, Nothing, true),
        (Microvm, Process, true),
        (Microvm, Microvm, true),
    ] {
        assert_eq!(
            offered.satisfies(required),
            ok,
            "{offered:?} vs {required:?}"
        );
    }
}

#[test]
fn the_required_tier_is_one_definition_for_every_way_a_policy_asks_for_a_sandbox() {
    use crate::runner::PermissionMode;
    let with = |f: fn(&mut Policy)| {
        let mut p = Policy::default();
        f(&mut p);
        p.required_tier()
    };
    assert_eq!(Policy::default().required_tier(), None);
    assert_eq!(with(|p| p.min_isolation = Some(Isolation::None)), None);
    assert_eq!(
        with(|p| p.min_isolation = Some(Isolation::Process)),
        Some(Isolation::Process)
    );
    assert_eq!(
        with(|p| p.min_isolation = Some(Isolation::Microvm)),
        Some(Isolation::Microvm)
    );
    // Any field implies at least `process`, and never lowers an explicit microvm.
    for set in [
        (|p: &mut Policy| p.wall_secs = Some(5)) as fn(&mut Policy),
        |p| p.memory_mb = Some(128),
        |p| p.disk_mb = Some(128),
        |p| p.vcpus = Some(1),
        |p| p.image = Some(format!("sha256:{}", "ab".repeat(32))),
        |p| p.egress = Some(Egress::default()),
        |p| p.workspace = Some(WorkspaceMode::Bind),
        |p| p.sandboxed = true,
        |p| p.mode = PermissionMode::Sandboxed,
    ] {
        assert_eq!(with(set), Some(Isolation::Process));
        let mut p = Policy::default();
        set(&mut p);
        p.min_isolation = Some(Isolation::Microvm);
        assert_eq!(p.required_tier(), Some(Isolation::Microvm));
    }
}
