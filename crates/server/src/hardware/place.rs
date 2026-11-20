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
#[path = "place_tests.rs"]
mod tests;
