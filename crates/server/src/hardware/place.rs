//! Placement (E15 §3.3): where an AI session or a heavy job runs. Pure over a snapshot of the
//! hardware ([`HwView`], built from `Hub::hardware()` and `core_hardware_prefs`), so every rule is
//! a table test.
//!
//! F0 freezes the signatures and types; the bodies are stubs that place everything on the Core.
//! The E15-1 lane writes the rules of §3.3 behind them.

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

/// The Core host in `hw`.
fn core(hw: &[HwView]) -> Option<&HwView> {
    hw.iter().find(|h| h.kind == HwKind::Core)
}

/// An AI session: the Core unless it is full, else the least loaded qualifying runner that
/// `fits` (by device id), else the Core anyway. The stub: the Core.
pub fn place_session(hw: &[HwView], fits: &dyn Fn(&str) -> bool) -> Result<Placed, NoFit> {
    let _ = fits;
    core(hw).map_or(Err(NoFit), |c| {
        Ok(Placed {
            device: c.device.clone(),
            reason: PlaceReason::Core,
        })
    })
}

/// A heavy job of `project`: This Mac for macOS, then a warm cache, then the lowest load; else
/// the Core with `CoreNoFit`. The stub: the Core (an empty device when `hw` has none).
pub fn place_job(hw: &[HwView], need: &JobNeed, project: &str) -> Placed {
    let _ = (need, project);
    Placed {
        device: core(hw).map(|c| c.device.clone()).unwrap_or_default(),
        reason: PlaceReason::Core,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hw(device: &str, kind: HwKind) -> HwView {
        HwView {
            device: device.into(),
            name: device.into(),
            kind,
            online: true,
            degraded: false,
            paused: false,
            os: Some(Os::Linux),
            arch: Some(Arch::X86_64),
            capacity: None,
            sessions: 0,
            jobs: 0,
            job_slots: 1,
            sustained_full: false,
        }
    }

    #[test]
    fn the_stubs_place_on_the_core() {
        let all = [hw("d_r", HwKind::Runner), hw("d_core", HwKind::Core)];
        let core = Placed {
            device: "d_core".into(),
            reason: PlaceReason::Core,
        };
        assert_eq!(place_session(&all, &|_| true), Ok(core.clone()));
        assert_eq!(place_session(&all[..1], &|_| true), Err(NoFit));
        assert_eq!(place_job(&all, &JobNeed::default(), "3"), core);
        assert_eq!(
            PlaceReason::CoreNoFit {
                missing: "xcode".into()
            }
            .as_str(),
            "core_no_fit:xcode"
        );
    }
}
