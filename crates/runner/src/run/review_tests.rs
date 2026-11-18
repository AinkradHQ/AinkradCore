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

#[test]
fn a_start_and_its_cleanup_fit_the_helper_units_runtime() {
    // `RuntimeMaxSec=1800` in deploy/systemd/ainkrad-run@.service.
    let sum = START_BUDGET + OVERRUN + STOP_MAX;
    assert!(sum < Duration::from_secs(1800), "{sum:?}");
    // The phases each start-bound child may take never exceed the budget on their own.
    for cap in [CLONE_MAX, BUILD_MAX, CREATE_MAX, HEALTH_WAIT] {
        assert!(cap < START_BUDGET);
    }
}

#[test]
fn host_image_transports_are_refused_in_from_and_copy_from() {
    use prepare::image_source_problem as p;
    for bad in [
        "FROM oci-archive:/etc/x.tar\n",
        "from docker-archive:/x\n",
        "FROM --platform=linux/amd64 dir:/var/lib\n",
        "FROM alpine AS a\nFROM oci:/x\n",
        "FROM alpine\nCOPY --from=OCI-ARCHIVE:/x /a /b\n",
        "FROM alpine\nRUN --mount=type=bind,from=dir:/x,target=/m true\n",
        "FROM \\\n  oci:/x\n",
    ] {
        assert!(p(bad).is_some(), "{bad:?}");
    }
    for ok in [
        "FROM alpine:3.20\n",
        "FROM docker.io/library/alpine AS b\nCOPY --from=b /a /b\n",
        "FROM dirty/img\nCOPY --from=dirty /a /b\n",
        "# FROM oci:/x\nFROM alpine\n",
    ] {
        assert!(p(ok).is_none(), "{ok:?}");
    }
}

#[test]
fn project_stores_use_file_locks() {
    assert!(containers_conf().contains("lock_type = \"file\""));
}
