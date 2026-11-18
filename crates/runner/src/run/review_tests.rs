//! PR 324 review: the `ainkrad.expose` label is always set by the runner, so an image's own
//! `LABEL ainkrad.expose` can never expose a port.
use ainkrad_proto::v2::{RunLimits, RunService};

use super::*;

#[test]
fn the_expose_label_is_set_even_when_nothing_is_exposed() {
    let s: RunService = serde_json::from_value(serde_json::json!({
        "image": "web:1", "ports": [{"port": 3000}]
    }))
    .unwrap();
    let limits = RunLimits {
        cpus: 0.5,
        memory_mb: 128,
        pids: 128,
    };
    let a = create_args(
        "r1",
        7,
        "web",
        &s,
        "web:1",
        limits,
        None,
        Path::new("/runs/r1"),
    );
    let want = format!("{LABEL_EXPOSE}=");
    let i = a.iter().position(|x| *x == want).expect("label present");
    assert_eq!(a[i - 1], "--label", "{a:?}");
}
