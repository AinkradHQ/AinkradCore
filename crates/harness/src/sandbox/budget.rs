//! Aggregate resource backstop. Hard inherited rlimits stop individual fork/CPU/file/AS
//! excess; the host-side watchdog also kills a session exceeding aggregate RSS or disk.
//! Sampling (100 ms) permits overshoot, so these are process-level budgets, not quotas
//! suitable for mutually hostile tenants. VM/filesystem quotas remain E8.
use super::tree::{self, Tracker};
use super::*;
use std::time::Duration;
use tokio::task::JoinHandle;

pub(crate) fn configure(cmd: &mut Command, spec: &Spec) {
    let roots: Vec<_> = writable(spec);
    cmd.env(
        "AINKRAD_GUARD_PATHS",
        serde_json::to_string(&roots).expect("paths"),
    );
    cmd.env("AINKRAD_GUARD_MEMORY", env(spec, "AINKRAD_SANDBOX_MEMORY"));
    cmd.env("AINKRAD_GUARD_DISK", env(spec, "AINKRAD_SANDBOX_DISK"));
    cmd.env("AINKRAD_GUARD_CPU", env(spec, "AINKRAD_SANDBOX_CPU"));
    cmd.env(
        "AINKRAD_GUARD_PROCESSES",
        env(spec, "AINKRAD_SANDBOX_PROCESSES"),
    );
}

pub(crate) struct Budget {
    paths: Vec<PathBuf>,
    memory: u64,
    disk: u64,
    cpu: u64,
    processes: u64,
}
impl Budget {
    pub(crate) fn take(cmd: &mut Command) -> Option<Self> {
        let get = |key: &str| {
            cmd.as_std()
                .get_envs()
                .find(|(n, _)| n == &key)
                .and_then(|(_, v)| v)
                .map(|s| s.to_string_lossy().into_owned())
        };
        let paths = get("AINKRAD_GUARD_PATHS")?;
        let memory = get("AINKRAD_GUARD_MEMORY")
            .and_then(|s| s.parse().ok())
            .unwrap_or(4194304);
        let disk = get("AINKRAD_GUARD_DISK")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1048576);
        let cpu = get("AINKRAD_GUARD_CPU")
            .and_then(|s| s.parse().ok())
            .unwrap_or(900);
        let processes = get("AINKRAD_GUARD_PROCESSES")
            .and_then(|s| s.parse().ok())
            .unwrap_or(64);
        let paths = serde_json::from_str(&paths).ok()?;
        for k in [
            "AINKRAD_GUARD_PATHS",
            "AINKRAD_GUARD_MEMORY",
            "AINKRAD_GUARD_DISK",
            "AINKRAD_GUARD_CPU",
            "AINKRAD_GUARD_PROCESSES",
        ] {
            cmd.env_remove(k);
        }
        Some(Self {
            paths,
            memory,
            disk,
            cpu,
            processes,
        })
    }
    pub(crate) fn start(self, pgid: u32) -> Watch {
        let tracker = Tracker::new(pgid);
        let t = tracker.clone();
        let handle = tokio::spawn(async move {
            let mut cpu = CpuLedger::default();
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let Ok(Ok(snap)) = tokio::task::spawn_blocking(tree::snapshot).await else {
                    t.kill(); // cannot see the tree: fail closed
                    return;
                };
                let members = t.members(&snap);
                if members.is_empty() {
                    return;
                }
                let rss: u64 = members.iter().map(|p| p.rss_kb).sum();
                let cpu_spent = cpu.see(&members);
                let count = members.len() as u64;
                let paths = self.paths.clone();
                let disk = tokio::task::spawn_blocking(move || {
                    paths.iter().map(|p| disk_kb(p)).sum::<u64>()
                })
                .await
                .unwrap_or(u64::MAX);
                if count > self.processes
                    || rss > self.memory
                    || disk > self.disk
                    || cpu_spent >= self.cpu as f64
                {
                    tracing::warn!(
                        pgid,
                        "session exceeded aggregate CPU/memory/disk/process budget"
                    );
                    t.kill();
                    return;
                }
            }
        });
        Watch { handle, tracker }
    }
}

/// CPU seconds a session has used, across every process it ever had. A process that has left the
/// tree is folded into one total, so the map holds only live pids and a session that forks
/// forever does not grow it (KAN-419).
#[derive(Default)]
pub(crate) struct CpuLedger {
    live: std::collections::HashMap<u32, f64>,
    gone: f64,
}
impl CpuLedger {
    /// Notes the tree's current members; returns the session's total CPU seconds.
    pub(crate) fn see(&mut self, members: &[&tree::P]) -> f64 {
        for p in members {
            let prior = self.live.entry(p.pid).or_default();
            *prior = prior.max(p.cpu_s);
        }
        let gone = &mut self.gone;
        self.live.retain(|pid, cpu| {
            let here = members.iter().any(|p| p.pid == *pid);
            if !here {
                *gone += *cpu;
            }
            here
        });
        self.gone + self.live.values().sum::<f64>()
    }
}

/// The running watchdog; dropping the session stops it and kills every process it saw.
pub(crate) struct Watch {
    handle: JoinHandle<()>,
    tracker: Tracker,
}
impl Watch {
    /// The tree this watch tracks, for a kill that reaches `setsid` escapees too.
    pub(crate) fn tracker(&self) -> Tracker {
        self.tracker.clone()
    }
    pub(crate) fn stop(&self) {
        self.tracker.kill();
        self.handle.abort();
    }
}

/// Allocated kilobytes under `path`, walked in-process (no fork, so it works when the host
/// cannot spawn). A file that vanishes mid-walk is skipped. Symlinks are not followed.
fn disk_kb(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return 0;
    };
    let mut total = meta.blocks() / 2;
    if meta.is_dir()
        && let Ok(entries) = std::fs::read_dir(path)
    {
        total += entries.flatten().map(|e| disk_kb(&e.path())).sum::<u64>();
    }
    total
}

pub(super) fn cpu_seconds(text: &str) -> f64 {
    let (days, rest) = text
        .split_once('-')
        .map_or((0.0, text), |(d, r)| (d.parse::<f64>().unwrap_or(0.0), r));
    days * 86400.0
        + rest.split(':').fold(0.0, |total, n| {
            total * 60.0 + n.parse::<f64>().unwrap_or(0.0)
        })
}

#[cfg(test)]
mod ledger_tests {
    use super::*;

    fn proc(pid: u32, cpu_s: f64) -> tree::P {
        tree::P {
            pid,
            ppid: 1,
            pgid: 1,
            rss_kb: 0,
            cpu_s,
        }
    }

    #[test]
    fn a_session_that_forks_forever_keeps_a_bounded_map_and_an_exact_total() {
        let mut ledger = CpuLedger::default();
        let long = proc(7, 0.0);
        let mut total = 0.0;
        for pid in 1000..11_000u32 {
            let short = proc(pid, 0.5);
            total += 0.5;
            let seen = ledger.see(&[&long, &short]);
            assert_eq!(seen, total, "dead and live CPU both count");
            assert!(ledger.live.len() <= 2, "only live pids are kept");
        }
    }

    #[test]
    fn cpu_never_goes_backwards_for_a_live_pid() {
        let mut ledger = CpuLedger::default();
        assert_eq!(ledger.see(&[&proc(5, 2.0)]), 2.0);
        assert_eq!(ledger.see(&[&proc(5, 1.0)]), 2.0);
        assert_eq!(ledger.see(&[&proc(5, 3.0)]), 3.0);
    }
}
