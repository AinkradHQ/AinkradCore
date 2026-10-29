use super::*;
use crate::auth::crypto::unb64;

/// The committed vector (`tests/vectors/stepup-v1.json`) client SDKs check themselves against.
#[test]
fn the_golden_vector_reproduces_and_verifies() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/vectors/stepup-v1.json")).unwrap();
    let s = |k: &str| v[k].as_str().unwrap();
    let m = message(
        s("core_fp"),
        s("device_id"),
        s("session_id"),
        s("challenge"),
    );
    assert_eq!(m, s("message").as_bytes());
    let spki = unb64(s("stepup_spki"), 122).unwrap();
    let sig = unb64(s("stepup_sig"), 86).unwrap();
    assert!(crypto::verify(&spki, &m, &sig));
    let other = message(s("core_fp"), s("device_id"), "s_other", s("challenge"));
    assert!(!crypto::verify(&spki, &other, &sig), "bound to the session");
}

#[test]
fn the_device_budget_counts_attempts_and_gives_back_successes() {
    let f = StepUpFailures::default();
    for _ in 0..STEP_UP.threshold {
        assert!(f.take("d_a", 0));
    }
    assert!(!f.take("d_a", 1), "spent");
    assert!(f.take("d_b", 1), "per device");
    f.give_back("d_a");
    assert!(f.take("d_a", 1));
    assert!(f.take("d_a", STEP_UP.window), "a new window");
    f.clear("d_a");
    assert!(f.take("d_a", STEP_UP.window));
}
