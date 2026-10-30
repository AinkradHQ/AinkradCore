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
            let mut cpu_seen = std::collections::HashMap::<u32, f64>::new();
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
                for p in &members {
                    let prior = cpu_seen.entry(p.pid).or_default();
                    *prior = prior.max(p.cpu_s);
                }
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
                    || cpu_seen.values().sum::<f64>() >= self.cpu as f64
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

/// The running watchdog; dropping the session stops it and kills every process it saw.
pub(crate) struct Watch {
    handle: JoinHandle<()>,
    tracker: Tracker,
}
impl Watch {
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
