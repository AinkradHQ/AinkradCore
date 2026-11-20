//! What E15-4 tells E15-1's capacity report (`capacity::HwSource`): the gate verdict with its battery
//! and idle readings (`hwgate`), the warm caches (`sync`) and the toolchains (`toolchains`).
//! Registered with `capacity::configure` when the runner offers jobs; until then the gate reads `Off`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ainkrad_proto::v2::{Battery, CacheInfo, Gate};

use super::capacity::HwSource;
use super::hwgate::{HwGate, Reading};
use super::sync::SyncDriver;
use super::toolchains::Toolchains;

pub struct HwHost {
    gate: HwGate,
    toolchains: Arc<Toolchains>,
    sync: Arc<SyncDriver>,
    slots: Option<u32>,
    /// The reading the last `gate` call took: the report asks for the battery and idle time next.
    last: Mutex<Reading>,
}

impl HwHost {
    /// `slots`: an override of the default job slots (cores / 4).
    pub fn new(
        gate: HwGate,
        toolchains: Arc<Toolchains>,
        sync: Arc<SyncDriver>,
        slots: Option<u32>,
    ) -> Self {
        Self {
            gate,
            toolchains,
            sync,
            slots,
            last: Mutex::default(),
        }
    }
}

impl HwSource for HwHost {
    fn gate(&self, cpu_pct: u8) -> Gate {
        // No working sandbox means no jobs, whatever the host is doing.
        if !super::ProcessSandbox::available_here() {
            return Gate::Off;
        }
        let (gate, reading) = self.gate.sample(cpu_pct);
        *self.last.lock().unwrap() = reading;
        gate
    }

    fn battery(&self) -> Option<Battery> {
        self.last.lock().unwrap().battery
    }

    fn idle_secs(&self) -> Option<u64> {
        self.last.lock().unwrap().idle_secs
    }

    fn caches(&self) -> Vec<CacheInfo> {
        self.sync.caches()
    }

    fn toolchains(&self) -> BTreeMap<String, String> {
        self.toolchains.report()
    }

    fn job_slots(&self) -> Option<u32> {
        self.slots
    }
}

/// What the CLI decided about hardware duty (`--workspace-root`, `--bundled`), read once when the
/// daemon starts its session.
#[derive(Clone)]
pub struct HwSetup {
    /// The runner's state folder (`jobs/`, `toolchains/`, `work/` live under it).
    pub state: std::path::PathBuf,
    /// `--workspace-root <dir>`: the Core host's built-in runner; its jobs run in the workspace.
    pub workspace_root: Option<std::path::PathBuf>,
    /// `--bundled`: This Mac, which has the battery and idle gate.
    pub bundled: bool,
}

static SETUP: std::sync::OnceLock<HwSetup> = std::sync::OnceLock::new();

/// Called once by `connect_main`.
pub fn set_setup(setup: HwSetup) {
    let _ = SETUP.set(setup);
}

/// `--workspace-root`, once `connect_main` has set the runner up.
pub fn workspace_root() -> Option<std::path::PathBuf> {
    SETUP.get().and_then(|s| s.workspace_root.clone())
}

/// The `job` and `sync` drivers for this runner, and the capacity source registered. `None` when
/// the CLI set nothing up or the Core's identity is not a safe path name.
pub fn build(
    core_fp: &str,
    redeem: super::agent::secrets::Redeem,
    agents: Option<Arc<super::agent::AgentDriver>>,
) -> Option<(Arc<super::job::JobDriver>, Arc<SyncDriver>)> {
    let setup = SETUP.get()?;
    let work_root = setup.state.join("work");
    let mut sync = SyncDriver::new(super::sync::SyncConfig {
        work_root: work_root.clone(),
        core_id: core_fp.to_owned(),
        agents: setup.state.join("agents"),
        capacity: 4,
    })?;
    if let Some(a) = agents {
        sync = sync.with_clones(a);
    }
    let sync = Arc::new(sync);
    let toolchains = Toolchains::new(&setup.state);
    let gate = HwGate::new(&setup.state, setup.bundled);
    let cores =
        std::thread::available_parallelism().map_or(1, |n| u32::try_from(n.get()).unwrap_or(1));
    let job = Arc::new(super::job::JobDriver::new(
        super::job::JobConfig {
            state: setup.state.clone(),
            workspace_root: setup.workspace_root.clone(),
            exe: std::env::current_exe().unwrap_or_default(),
            capacity: ainkrad_proto::v2::Capacity::default_job_slots(cores),
            max_timeout: std::time::Duration::from_secs(6 * 3600),
            kill_grace: std::time::Duration::from_secs(10),
        },
        Arc::clone(&toolchains),
        Arc::clone(&sync),
        redeem,
        gate.clone(),
    ));
    let host = HwHost::new(gate, toolchains, Arc::clone(&sync), None);
    super::capacity::configure(work_root, Arc::new(host));
    Some((job, sync))
}
