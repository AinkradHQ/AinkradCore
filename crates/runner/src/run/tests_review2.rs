//! Round-2 security review fixes (PR #297): per-project Podman stores, a run's own build `TMPDIR`,
//! capped logs, the egress deploy files, and the helper's time budgets and stale build slices.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use ainkrad_proto::v2::{RunCheckout, RunPhase, RunService, RunStart};

use super::prepare::{build_slice, stale_slice};
use super::tests::{ALPINE, Host, bundle, podman, repo, start};
use super::*;

const HELPER_UNIT: &str = include_str!("../../../../deploy/systemd/ainkrad-run@.service");
const EGRESS_UNIT: &str = include_str!("../../../../deploy/systemd/ainkrad-run-egress.service");
const EGRESS_APPLY: &str =
    include_str!("../../../../deploy/systemd/ainkrad-run-egress-apply.service");
const EGRESS_TIMER: &str = include_str!("../../../../deploy/systemd/ainkrad-run-egress.timer");
const EGRESS_NFT: &str = include_str!("../../../../deploy/run-egress.nft");

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("run-r2-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn engine(d: &Path) -> Engine {
    Engine {
        podman: "podman".into(),
        root: d.join("runs"),
        projects: d.join("projects"),
        networks: d.join("networks"),
        env_dir: d.join("env"),
        runtime_dir: Some(d.join("rt")),
        checkout_cap: MAX_CHECKOUT_BYTES,
    }
}

#[test]
fn each_project_gets_its_own_podman_store() {
    let e = engine(Path::new("/h"));
    let seven = e.store_args(7).join(" ");
    assert_eq!(
        seven,
        "--root /h/projects/7/storage --runroot /h/projects/7/runroot \
         --network-config-dir /h/networks --tmpdir /h/rt/ainkrad-p7"
    );
    let eight = e.store_args(8).join(" ");
    assert!(eight.contains("--root /h/projects/8/storage"), "{eight}");
    assert!(eight.contains("--runroot /h/projects/8/runroot"), "{eight}");
    // One network directory for all: netavark hands each project network its own subnet.
    assert!(
        eight.contains("--network-config-dir /h/networks"),
        "{eight}"
    );
    // Every podman call goes through the store flags, before the subcommand.
    let cmd = e.podman_cmd(7, &["ps"]);
    let args: Vec<String> = cmd
        .get_args()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    assert_eq!(args.first().map(String::as_str), Some("--root"));
    assert_eq!(args.last().map(String::as_str), Some("ps"));
    // Only numeric dirs are stores.
    let d = scratch("stores");
    let e = engine(&d);
    for p in ["7", "12", "junk", ".incoming"] {
        std::fs::create_dir_all(e.projects.join(p)).unwrap();
    }
    let mut stores = e.stores();
    stores.sort_unstable();
    assert_eq!(stores, [7, 12]);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn container_logs_are_capped() {
    let s: RunService = serde_json::from_value(serde_json::json!({"image": "alpine:3"})).unwrap();
    let limits = RunLimits {
        cpus: 0.5,
        memory_mb: 128,
        pids: 64,
    };
    let a = create_args(
        "r1",
        7,
        "web",
        &s,
        "alpine:3",
        limits,
        None,
        Path::new("/r"),
    );
    let j = a.join(" ");
    assert!(
        j.contains("--log-driver k8s-file --log-opt max-size=10m --log-opt max-file=2"),
        "{j}"
    );
}

#[test]
fn a_start_and_its_cleanup_fit_inside_the_helper_units_runtime_cap() {
    let max: u64 = HELPER_UNIT
        .lines()
        .find_map(|l| l.strip_prefix("RuntimeMaxSec="))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // The 10 s request read and a margin for the answer on top.
    assert!(
        (START_BUDGET + CLEANUP_BUDGET + Duration::from_secs(30)).as_secs() <= max,
        "START_BUDGET + CLEANUP_BUDGET exceed RuntimeMaxSec={max}"
    );
}

#[test]
fn a_podman_call_never_outlives_its_deadline() {
    let d = scratch("deadline");
    let fake = d.join("podman");
    std::fs::write(&fake, "#!/bin/sh\nsleep 30\n").unwrap();
    let mut perms = std::fs::metadata(&fake).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&fake, perms).unwrap();
    let mut e = engine(&d);
    e.podman = fake.display().to_string();
    e.runtime_dir = None;
    let t = Instant::now();
    let why = e.podman(7, &["ps"], Instant::now()).unwrap_err();
    assert!(why.contains("did not finish"), "{why}");
    let why = e
        .podman(7, &["ps"], Instant::now() + Duration::from_secs(1))
        .unwrap_err();
    assert!(why.contains("did not finish"), "{why}");
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn only_a_build_slice_nobody_holds_is_stale() {
    let slice = build_slice("r-1", "web");
    assert!(slice.starts_with("ainkradbuild_") && slice.ends_with(".slice"));
    // `-` would nest the slice under another one.
    assert!(!slice.trim_end_matches(".slice").contains('-'), "{slice}");
    assert_ne!(slice, build_slice("r-1", "db"));
    let d = scratch("slices");
    // No lock file: the build that made it is gone.
    assert!(stale_slice(&d, &slice));
    let lock = std::fs::File::create(d.join(format!(".{slice}.lock"))).unwrap();
    lock.lock().unwrap();
    assert!(!stale_slice(&d, &slice), "a held lock is a live build");
    drop(lock);
    assert!(stale_slice(&d, &slice), "a free lock is a dead build");
    for other in ["user.slice", "app.slice", "ainkradbuild_x.service"] {
        assert!(!stale_slice(&d, other), "{other}");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_egress_table_is_reapplied_and_never_removed_by_a_stop() {
    assert!(
        !EGRESS_UNIT.contains("ExecStop"),
        "a stop removes the table"
    );
    assert!(EGRESS_UNIT.contains("ReloadPropagatedFrom=nftables.service"));
    assert!(EGRESS_UNIT.contains("ExecReload=/bin/sh -c '/usr/sbin/nft -f "));
    assert!(EGRESS_TIMER.contains("OnUnitActiveSec=1min"));
    assert!(EGRESS_TIMER.contains("Unit=ainkrad-run-egress-apply.service"));
    // Each load is listed back before the runner's marker is touched.
    for unit in [EGRESS_UNIT, EGRESS_APPLY, HELPER_UNIT] {
        assert!(
            unit.contains(
                "nft list table inet ainkrad_run_egress >/dev/null && touch /run/ainkrad-run-egress.ok"
            ),
            "{unit}"
        );
    }
}

#[test]
fn the_egress_table_blocks_wireserver_multicast_and_ipv6() {
    for want in [
        "168.63.129.16/32",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "meta skuid \"ainkrad-run\" meta nfproto ipv6 reject",
    ] {
        assert!(EGRESS_NFT.contains(want), "{want} missing");
    }
    // The IPv6 deny comes after the established/DNS accepts, so replies and DNS keep working.
    let pos = |s: &str| EGRESS_NFT.find(s).unwrap();
    assert!(pos("ct state established,related accept") < pos("meta nfproto ipv6 reject"));
    assert!(pos("th dport 53 accept") < pos("meta nfproto ipv6 reject"));
}

// --- On a host with rootless Podman, as the helper's user: `cargo test -p ainkrad-runner run:: -- --ignored`.

/// A one-service run of `project` built from the checkout `web`.
fn build_run(run: &str, project: u64) -> RunStart {
    let mut r = start(
        run,
        project,
        serde_json::json!({"services": {"web": {
            "build": {"repo": "web"}, "repo": "web", "command": ["sleep", "600"]}}}),
    );
    r.checkouts = vec![RunCheckout {
        repo: "web".into(),
        dir: "/unused".into(),
    }];
    r
}

/// A repo with `dockerfile`, as the bundle map `start_with` takes.
fn from_dockerfile(h: &Host, name: &str, dockerfile: &str) -> BTreeMap<String, PathBuf> {
    let src = h.tmp.join(format!("src-{name}"));
    repo(&src, &[("Dockerfile", dockerfile.as_bytes())], &[]);
    let b = h.tmp.join(format!("bundle-{name}"));
    bundle(&src, &b);
    BTreeMap::from([("web".to_owned(), b)])
}

#[test]
#[ignore = "needs rootless podman"]
fn a_dockerfile_cannot_read_another_projects_build() {
    let mut h = Host::new("store");
    let (pa, pb) = (h.project(7), h.project(8));
    let id = std::process::id();
    let a = build_run(&format!("t{id}sa"), pa);
    let b = from_dockerfile(
        &h,
        "a",
        &format!("FROM {ALPINE}\nRUN echo a-secret > /secret\n"),
    );
    let r = h.start_with(&a, &b);
    assert_eq!(r.phase, RunPhase::Running, "{r:?}");
    let a_tag = format!("localhost/{}-web:{}", network(pa), a.run);
    assert!(podman(&h.engine, pa, &["images", "-q", &a_tag]).len() > 1);
    // Project B names A's build each way a Dockerfile can: none of them builds.
    for (n, dockerfile) in [
        ("from", format!("FROM {a_tag}\n")),
        ("storage", format!("FROM containers-storage:{a_tag}\n")),
        (
            "copy",
            format!("FROM {ALPINE}\nCOPY --from={a_tag} /secret /x\n"),
        ),
        (
            "mount",
            format!("FROM {ALPINE}\nRUN --mount=type=bind,from={a_tag},target=/a cat /a/secret\n"),
        ),
    ] {
        let req = build_run(&format!("t{id}s{n}"), pb);
        let b = from_dockerfile(&h, n, &dockerfile);
        let r = h.start_with(&req, &b);
        assert_eq!(
            (r.phase, r.failed_service.as_deref()),
            (RunPhase::Failed, Some("web")),
            "{n}: {r:?}"
        );
    }
    // A's image is not in B's store at all.
    assert_eq!(podman(&h.engine, pb, &["images", "-q", &a_tag]), "");
}

#[test]
#[ignore = "needs rootless podman"]
fn a_build_cache_mount_is_the_runs_own() {
    let mut h = Host::new("cache");
    let p = h.project(9);
    let id = std::process::id();
    let first = build_run(&format!("t{id}c1"), p);
    let b = from_dockerfile(
        &h,
        "c1",
        &format!("FROM {ALPINE}\nRUN --mount=type=cache,target=/c touch /c/first-was-here\n"),
    );
    assert_eq!(h.start_with(&first, &b).phase, RunPhase::Running);
    // A later run of the same project sees an empty cache: its TMPDIR is its own run dir.
    let second = build_run(&format!("t{id}c2"), p);
    let b = from_dockerfile(
        &h,
        "c2",
        &format!("FROM {ALPINE}\nRUN --mount=type=cache,target=/c test ! -e /c/first-was-here\n"),
    );
    let r = h.start_with(&second, &b);
    assert_eq!(r.phase, RunPhase::Running, "the cache was shared: {r:?}");
    // And the run dir (with that TMPDIR) goes with the run.
    h.engine.stop(&first.run).unwrap();
    assert!(!h.engine.root.join(&first.run).exists());
}
