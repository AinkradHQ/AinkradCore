use std::collections::BTreeMap;

use ainkrad_proto::v2::{CacheInfo, Gate};

use super::*;

fn hw(device: &str, kind: HwKind) -> HwView {
    HwView {
        device: device.into(),
        name: device.into(),
        kind,
        online: true,
        degraded: false,
        paused: false,
        os: Some(if kind == HwKind::Mac {
            Os::Macos
        } else {
            Os::Linux
        }),
        arch: Some(if kind == HwKind::Mac {
            Arch::Aarch64
        } else {
            Arch::X86_64
        }),
        capacity: Some(Capacity {
            cores: 8,
            cpu_pct: 10,
            gate: if kind == HwKind::Core {
                Gate::Off
            } else {
                Gate::Open
            },
            job_slots: 2,
            ..Capacity::default()
        }),
        sessions: 0,
        jobs: 0,
        job_slots: 2,
        sustained_full: false,
    }
}

fn with(mut h: HwView, f: impl FnOnce(&mut HwView)) -> HwView {
    f(&mut h);
    h
}

fn cap(h: &mut HwView) -> &mut Capacity {
    h.capacity.as_mut().unwrap()
}

fn at(device: &str, reason: PlaceReason) -> Placed {
    Placed {
        device: device.into(),
        reason,
    }
}

fn yes(_: &str) -> bool {
    true
}

#[test]
fn a_session_stays_on_the_core_until_it_is_full() {
    let core = hw("d_core", HwKind::Core);
    let r = hw("d_r", HwKind::Runner);
    // Room: the Core.
    assert_eq!(
        place_session(&[r.clone(), core.clone()], &yes),
        Ok(at("d_core", PlaceReason::Core))
    );
    // 8 cores -> 4 sessions fill it; 3 do not.
    let three = with(core.clone(), |c| c.sessions = 3);
    assert_eq!(
        place_session(&[r.clone(), three], &yes),
        Ok(at("d_core", PlaceReason::Core))
    );
    let four = with(core.clone(), |c| c.sessions = 4);
    assert_eq!(
        place_session(&[r.clone(), four], &yes),
        Ok(at("d_r", PlaceReason::Overflow))
    );
    // Sustained full does too.
    let hot = with(core.clone(), |c| c.sustained_full = true);
    assert_eq!(
        place_session(&[r.clone(), hot], &yes),
        Ok(at("d_r", PlaceReason::Overflow))
    );
    // A one-core Core fills at one session (max(1, cores/2)).
    let tiny = with(core.clone(), |c| {
        cap(c).cores = 1;
        c.sessions = 1;
    });
    assert_eq!(
        place_session(&[r.clone(), tiny], &yes),
        Ok(at("d_r", PlaceReason::Overflow))
    );
    // A Core that cannot fit the session hands it on.
    assert_eq!(
        place_session(&[r, core], &|d| d != "d_core"),
        Ok(at("d_r", PlaceReason::Overflow))
    );
}

#[test]
fn overflow_takes_the_least_loaded_qualifying_runner() {
    let full = with(hw("d_core", HwKind::Core), |c| c.sustained_full = true);
    let busy = with(hw("d_a", HwKind::Runner), |h| cap(h).cpu_pct = 60);
    let jobs = with(hw("d_b", HwKind::Runner), |h| {
        cap(h).cpu_pct = 10;
        h.jobs = 1;
    });
    let calm = with(hw("d_c", HwKind::Runner), |h| cap(h).cpu_pct = 20);
    // cpu + jobs: a=60, b=11, c=20.
    assert_eq!(
        place_session(
            &[full.clone(), busy.clone(), jobs.clone(), calm.clone()],
            &yes
        ),
        Ok(at("d_b", PlaceReason::Overflow))
    );
    // Each disqualifier removes the best runner in turn.
    let off = |f: fn(&mut HwView)| {
        let b = with(jobs.clone(), f);
        place_session(&[full.clone(), busy.clone(), b, calm.clone()], &yes)
    };
    let next = Ok(at("d_c", PlaceReason::Overflow));
    assert_eq!(off(|h| h.online = false), next);
    assert_eq!(off(|h| h.degraded = true), next);
    assert_eq!(off(|h| h.paused = true), next);
    assert_eq!(off(|h| cap(h).gate = Gate::Busy), next);
    assert_eq!(off(|h| cap(h).gate = Gate::OnBattery), next);
    assert_eq!(off(|h| h.capacity = None), next);
    assert_eq!(
        place_session(&[full, busy, jobs, calm], &|d| d != "d_b"),
        next
    );
}

#[test]
fn a_full_core_with_no_qualifying_runner_keeps_the_session() {
    let full = with(hw("d_core", HwKind::Core), |c| c.sessions = 9);
    let paused = with(hw("d_r", HwKind::Runner), |h| h.paused = true);
    assert_eq!(
        place_session(&[full.clone(), paused], &yes),
        Ok(at("d_core", PlaceReason::Core))
    );
    assert_eq!(
        place_session(&[full], &yes),
        Ok(at("d_core", PlaceReason::Core))
    );
}

#[test]
fn no_core_online_is_no_fit_unless_a_runner_takes_it() {
    let gone = with(hw("d_core", HwKind::Core), |c| c.online = false);
    assert_eq!(place_session(std::slice::from_ref(&gone), &yes), Err(NoFit));
    assert_eq!(place_session(&[], &yes), Err(NoFit));
    assert_eq!(
        place_session(&[gone, hw("d_r", HwKind::Runner)], &yes),
        Ok(at("d_r", PlaceReason::Overflow))
    );
    // A runner that reports no gate (before 2.1, or no hwgate yet) is session hardware only.
    let old = with(hw("d_r", HwKind::Runner), |h| h.capacity = None);
    assert_eq!(place_session(&[old], &yes), Err(NoFit));
}

#[test]
fn a_pinned_login_keeps_its_runner() {
    assert_eq!(pinned("d_x"), at("d_x", PlaceReason::Pinned));
    assert_eq!(PlaceReason::Pinned.as_str(), "pinned");
}

fn need() -> JobNeed {
    JobNeed::default()
}

#[test]
fn a_job_goes_to_the_lowest_load_then_cpu() {
    let core = hw("d_core", HwKind::Core);
    let a = with(hw("d_a", HwKind::Runner), |h| h.jobs = 1);
    let b = with(hw("d_b", HwKind::Runner), |h| cap(h).cpu_pct = 50);
    let c = with(hw("d_c", HwKind::Runner), |h| cap(h).cpu_pct = 30);
    // jobs/slots: a=0.5, b=0, c=0; cpu breaks b/c.
    assert_eq!(
        place_job(&[core, a, b, c], &need(), "7"),
        at("d_c", PlaceReason::Runner)
    );
}

#[test]
fn a_warm_cache_beats_a_lighter_runner_and_this_mac_beats_both_for_macos() {
    let core = hw("d_core", HwKind::Core);
    let warm = with(hw("d_w", HwKind::Runner), |h| {
        h.jobs = 1;
        cap(h).caches = vec![CacheInfo {
            project: 7,
            ..CacheInfo::default()
        }];
    });
    let light = hw("d_l", HwKind::Runner);
    let mac = with(hw("d_mac", HwKind::Mac), |h| h.jobs = 1);
    let all = [core, warm, light, mac];
    assert_eq!(
        place_job(&all, &need(), "7"),
        at("d_w", PlaceReason::Runner)
    );
    assert_eq!(
        place_job(&all, &need(), "8"),
        at("d_l", PlaceReason::Runner)
    );
    let macos = JobNeed {
        os: Some(Os::Macos),
        ..need()
    };
    assert_eq!(
        place_job(&all, &macos, "7"),
        at("d_mac", PlaceReason::ThisMac)
    );
    // A linux job does not prefer the Mac.
    let linux = JobNeed {
        os: Some(Os::Linux),
        ..need()
    };
    assert_eq!(place_job(&all, &linux, "8"), at("d_l", PlaceReason::Runner));
}

#[test]
fn a_job_never_goes_where_it_may_not() {
    let core = hw("d_core", HwKind::Core);
    let no = |f: fn(&mut HwView)| {
        place_job(
            &[core.clone(), with(hw("d_r", HwKind::Runner), f)],
            &need(),
            "1",
        )
    };
    let nofit = at(
        "d_core",
        PlaceReason::CoreNoFit {
            missing: "capacity".into(),
        },
    );
    assert_eq!(no(|h| h.paused = true), nofit);
    assert_eq!(no(|h| cap(h).gate = Gate::Busy), nofit);
    assert_eq!(no(|h| cap(h).gate = Gate::OnBattery), nofit);
    assert_eq!(no(|h| cap(h).gate = Gate::Paused), nofit);
    assert_eq!(no(|h| cap(h).gate = Gate::Off), nofit);
    assert_eq!(no(|h| h.capacity = None), nofit);
    assert_eq!(no(|h| h.jobs = 2), nofit, "slots are full");
    assert_eq!(
        no(|h| h.degraded = true),
        at(
            "d_core",
            PlaceReason::CoreNoFit {
                missing: "runner".into()
            }
        )
    );
    assert_eq!(
        no(|h| h.online = false),
        at(
            "d_core",
            PlaceReason::CoreNoFit {
                missing: "runner".into()
            }
        )
    );
    // A Core placement is never on the Core as a candidate, even when it is Open.
    let open_core = with(core, |c| cap(c).gate = Gate::Open);
    assert_eq!(
        place_job(&[open_core], &need(), "1"),
        at(
            "d_core",
            PlaceReason::CoreNoFit {
                missing: "runner".into()
            }
        )
    );
}

#[test]
fn a_job_matches_os_arch_and_toolchains() {
    let core = hw("d_core", HwKind::Core);
    let lin = with(hw("d_lin", HwKind::Runner), |h| {
        cap(h).toolchains = BTreeMap::from([("docker".to_owned(), "27".to_owned())]);
    });
    let mac = with(hw("d_mac", HwKind::Mac), |h| {
        cap(h).toolchains = BTreeMap::from([("xcode".to_owned(), "27.0".to_owned())]);
    });
    let all = [core, lin, mac];
    let miss = |m: &str| at("d_core", PlaceReason::CoreNoFit { missing: m.into() });
    // Installable from pins counts; docker does not unless reported.
    let n = JobNeed {
        toolchains: vec!["rust".into()],
        ..need()
    };
    assert_eq!(place_job(&all, &n, "1"), at("d_lin", PlaceReason::Runner));
    let n = JobNeed {
        toolchains: vec!["docker".into()],
        os: Some(Os::Macos),
        ..need()
    };
    assert_eq!(place_job(&all, &n, "1"), miss("docker"));
    let n = JobNeed {
        toolchains: vec!["docker".into()],
        ..need()
    };
    assert_eq!(place_job(&all, &n, "1"), at("d_lin", PlaceReason::Runner));
    // Xcode needs a macOS runner that reports it.
    let n = JobNeed {
        xcode: true,
        ..need()
    };
    assert_eq!(place_job(&all, &n, "1"), at("d_mac", PlaceReason::ThisMac));
    assert_eq!(place_job(&all[..2], &n, "1"), miss("xcode"));
    // OS and arch.
    let n = JobNeed {
        os: Some(Os::Macos),
        ..need()
    };
    assert_eq!(place_job(&all[..2], &n, "1"), miss("os macos"));
    let n = JobNeed {
        arch: Some(Arch::Aarch64),
        os: Some(Os::Linux),
        ..need()
    };
    assert_eq!(place_job(&all, &n, "1"), miss("arch aarch64"));
    // A runner that never said its OS never matches a need for one.
    let blind = with(hw("d_b", HwKind::Runner), |h| h.os = None);
    let n = JobNeed {
        os: Some(Os::Linux),
        ..need()
    };
    assert_eq!(
        place_job(&[blind], &n, "1"),
        at(
            "",
            PlaceReason::CoreNoFit {
                missing: "os linux".into()
            }
        )
    );
}

#[test]
fn no_hardware_at_all_is_the_core_or_an_empty_device() {
    assert_eq!(
        place_job(&[], &need(), "1"),
        at(
            "",
            PlaceReason::CoreNoFit {
                missing: "runner".into()
            }
        )
    );
    assert_eq!(
        PlaceReason::CoreNoFit {
            missing: "xcode".into()
        }
        .as_str(),
        "core_no_fit:xcode"
    );
}

#[test]
fn a_session_is_never_pinned_to_a_paused_degraded_or_offline_runner() {
    // M9: both pinning paths (a runner-bound login, and no hardware fits) ask this first.
    let hw = [
        hw("ok", HwKind::Runner),
        with(hw("p", HwKind::Runner), |h| h.paused = true),
        with(hw("d", HwKind::Runner), |h| h.degraded = true),
        with(hw("o", HwKind::Runner), |h| h.online = false),
    ];
    assert_eq!(pin_refusal(&hw, "ok"), None);
    assert_eq!(pin_refusal(&hw, "p"), Some("paused"));
    assert_eq!(pin_refusal(&hw, "d"), Some("degraded"));
    assert_eq!(pin_refusal(&hw, "o"), Some("offline"));
    assert_eq!(pin_refusal(&hw, "gone"), Some("offline"));
}
