//! Version skew of the isolation fields (E8a-08): an old policy on a new side and the reverse.

use serde_json::json;

use super::tests::full;
use super::*;
use crate::runner::{PermissionMode, Policy};

/// What a policy was before E8a-08: three fields, ignoring any it does not know (as a serde
/// struct without `deny_unknown_fields` does, which is what an old runner is).
#[derive(Debug, PartialEq, Deserialize)]
struct OldPolicy {
    mode: PermissionMode,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    sandboxed: bool,
}

#[test]
fn an_old_policy_parses_with_every_new_field_absent_and_serializes_back_unchanged() {
    let old = r#"{"mode":"accept_edits","allow":["Edit"],"sandboxed":false}"#;
    let p: Policy = serde_json::from_str(old).unwrap();
    assert_eq!(p.min_isolation, None);
    assert_eq!(p.egress, None);
    assert!(!p.asks_for_isolation());
    assert_eq!(p.problem(), None);
    assert_eq!(serde_json::to_string(&p).unwrap(), old);
    // The default policy is byte-identical to what an old Core sent.
    assert_eq!(
        serde_json::to_string(&Policy::default()).unwrap(),
        r#"{"mode":"ask","allow":[],"sandboxed":false}"#
    );
}

#[test]
fn an_old_runner_reads_a_new_policy_and_silently_drops_the_isolation_fields() {
    // This is why placement must not rely on the runner to refuse (E8a-09): an old runner
    // cannot see `min_isolation`. It parses the frame and runs it at its own tier.
    let wire = serde_json::to_value(full()).unwrap();
    let old: OldPolicy = serde_json::from_value(wire).unwrap();
    assert_eq!(old.mode, PermissionMode::Ask);
}

#[test]
fn an_unknown_tier_or_workspace_mode_is_refused_not_defaulted() {
    for bad in [
        json!({"mode":"ask","min_isolation":"vm"}),
        json!({"mode":"ask","min_isolation":"MICROVM"}),
        json!({"mode":"ask","workspace":"mount"}),
        json!({"mode":"ask","vcpus":-1}),
        json!({"mode":"ask","egress":{"allow":"10.0.0.0/8"}}),
    ] {
        assert!(
            serde_json::from_value::<Policy>(bad.clone()).is_err(),
            "{bad}"
        );
    }
}
