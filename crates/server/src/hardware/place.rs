//! Placement (E15 §3.3): where an AI session or a heavy job runs. Pure over a snapshot of the
//! hardware ([`HwView`], built from `Hub::hardware()` and `core_hardware_prefs`), so every rule is
//! a table test.
//!
//! F0 froze the signatures and types; E15-1 wrote the rules of §3.3 behind them.

pub use ainkrad_proto::v2::{Arch, JobNeed, Os};
use ainkrad_proto::v2::{Capacity, HwKind};

/// One piece of hardware as placement sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwView {
    /// The runner device, `d_…`.
    pub device: String,
    pub name: String,
    pub kind: HwKind,
    pub online: bool,
    pub degraded: bool,
    /// Paused on the Core (`core_hardware_prefs.paused_until` in the future, or pause-all).
    pub paused: bool,
    pub os: Option<Os>,
    pub arch: Option<Arch>,
    /// What it last reported; absent from a runner before protocol 2.1 (session hardware only).
    pub capacity: Option<Capacity>,
    /// AI sessions live on it now.
    pub sessions: u32,
    /// Jobs running on it now.
    pub jobs: u32,
    /// Its job slots: the Core's override, else `capacity.job_slots`.
    pub job_slots: u32,
    /// Every sample of the last 60 s showed CPU above 85 or free RAM below 15%.
    pub sustained_full: bool,
}

/// Where something was placed, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed {
    pub device: String,
    pub reason: PlaceReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaceReason {
    /// The Core host, as the default.
    Core,
    /// An AI session sent to a runner because the Core is full.
    Overflow,
    /// A heavy job on a remote runner.
    Runner,
    /// A heavy job on This Mac.
    ThisMac,
    /// A heavy job no other hardware could take: what was missing (`xcode`, `os macos`, ...).
    CoreNoFit { missing: String },
    /// A runner-bound login (codex-sub, Antigravity) pins its runner.
    Pinned,
}

impl PlaceReason {
    /// The stored form (`core_hw_jobs.place_reason`, `core_agent_sessions.place_reason`) and the
    /// API's `place_reason`.
    pub fn as_str(&self) -> String {
        match self {
            Self::Core => "core".into(),
            Self::Overflow => "overflow".into(),
            Self::Runner => "runner".into(),
            Self::ThisMac => "this_mac".into(),
            Self::CoreNoFit { missing } => format!("core_no_fit:{missing}"),
            Self::Pinned => "pinned".into(),
        }
    }
}

/// No hardware can take the session: not even the Core (it is offline or absent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoFit;

/// Toolchains a runner can install from the pins when it does not report them (E15-4).
const INSTALLABLE: [&str; 4] = ["rust", "node", "python", "go"];

/// The Core host in `hw`.
fn core(hw: &[HwView]) -> Option<&HwView> {
    hw.iter().find(|h| h.kind == HwKind::Core)
}

fn cpu(h: &HwView) -> u8 {
    h.capacity.as_ref().map_or(0, |c| c.cpu_pct)
}

fn gate_open(h: &HwView) -> bool {
    h.capacity
        .as_ref()
        .is_some_and(|c| c.gate == ainkrad_proto::v2::Gate::Open)
}

/// The Core is full: `sustained_full`, or as many AI sessions as half its cores (at least one).
fn core_full(c: &HwView) -> bool {
    let cores = c.capacity.as_ref().map_or(0, |c| c.cores);
    c.sustained_full || c.sessions >= (cores / 2).max(1)
}

/// The placement of a session pinned to `device` (a runner-bound login: codex-sub, Antigravity).
pub fn pinned(device: &str) -> Placed {
    Placed {
        device: device.to_owned(),
        reason: PlaceReason::Pinned,
    }
}

/// An AI session: the Core unless it is full (or cannot `fit` the session), else the least loaded
/// runner that is online, not degraded, `Open`, not paused and `fits` (by device id), else the
/// Core anyway. `NoFit` only when there is no Core to fall back on and no runner qualifies.
pub fn place_session(hw: &[HwView], fits: &dyn Fn(&str) -> bool) -> Result<Placed, NoFit> {
    let core = core(hw);
    if let Some(c) = core.filter(|c| c.online && !core_full(c) && fits(&c.device)) {
        return Ok(Placed {
            device: c.device.clone(),
            reason: PlaceReason::Core,
        });
    }
    let overflow = hw
        .iter()
        .filter(|h| h.kind != HwKind::Core)
        .filter(|h| h.online && !h.degraded && !h.paused && gate_open(h) && fits(&h.device))
        .min_by_key(|h| (u32::from(cpu(h)) + h.jobs, h.device.clone()));
    if let Some(h) = overflow {
        return Ok(Placed {
            device: h.device.clone(),
            reason: PlaceReason::Overflow,
        });
    }
    core.filter(|c| c.online)
        .map(|c| Placed {
            device: c.device.clone(),
            reason: PlaceReason::Core,
        })
        .ok_or(NoFit)
}

/// The remote hardware that can take `need` now, or what is missing (the first requirement no
/// online remote meets, structural ones first).
fn candidates<'a>(hw: &'a [HwView], need: &JobNeed) -> Result<Vec<&'a HwView>, String> {
    let mut set: Vec<&HwView> = hw
        .iter()
        .filter(|h| h.kind != HwKind::Core && h.online && !h.degraded)
        .collect();
    let step = |set: &mut Vec<&'a HwView>, keep: &dyn Fn(&HwView) -> bool, missing: String| {
        set.retain(|h| keep(h));
        if set.is_empty() { Err(missing) } else { Ok(()) }
    };
    if set.is_empty() {
        return Err("runner".into());
    }
    if let Some(os) = need.os {
        step(
            &mut set,
            &|h| h.os == Some(os),
            format!("os {os:?}").to_lowercase(),
        )?;
    }
    if let Some(arch) = need.arch {
        step(
            &mut set,
            &|h| h.arch == Some(arch),
            format!("arch {arch:?}").to_lowercase(),
        )?;
    }
    if need.xcode {
        step(
            &mut set,
            &|h| {
                h.os == Some(Os::Macos)
                    && h.capacity
                        .as_ref()
                        .is_some_and(|c| c.toolchains.contains_key("xcode"))
            },
            "xcode".into(),
        )?;
    }
    for t in &need.toolchains {
        let can = INSTALLABLE.contains(&t.as_str());
        step(
            &mut set,
            &|h| {
                can || h
                    .capacity
                    .as_ref()
                    .is_some_and(|c| c.toolchains.contains_key(t))
            },
            t.clone(),
        )?;
    }
    step(
        &mut set,
        &|h| !h.paused && gate_open(h) && h.jobs < h.job_slots,
        "capacity".into(),
    )?;
    Ok(set)
}

/// A heavy job of `project`: This Mac for macOS, then a warm cache, then the lowest load; else
/// the Core with `CoreNoFit` (an empty device when `hw` has no Core).
pub fn place_job(hw: &[HwView], need: &JobNeed, project: &str) -> Placed {
    let core = || core(hw).map(|c| c.device.clone()).unwrap_or_default();
    let set = match candidates(hw, need) {
        Ok(s) => s,
        Err(missing) => {
            return Placed {
                device: core(),
                reason: PlaceReason::CoreNoFit { missing },
            };
        }
    };
    let warm = |h: &HwView| {
        h.capacity
            .as_ref()
            .is_some_and(|c| c.caches.iter().any(|k| k.project.to_string() == project))
    };
    let best = set
        .into_iter()
        .min_by_key(|h| {
            (
                !(need.os == Some(Os::Macos) && h.kind == HwKind::Mac),
                !warm(h),
                h.jobs * 1000 / h.job_slots.max(1),
                cpu(h),
                h.device.clone(),
            )
        })
        .expect("candidates are never empty");
    Placed {
        device: best.device.clone(),
        reason: if best.kind == HwKind::Mac {
            PlaceReason::ThisMac
        } else {
            PlaceReason::Runner
        },
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(place_session(&[gone.clone()], &yes), Err(NoFit));
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
}
