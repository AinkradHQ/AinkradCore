//! Aggregate resource backstop. Hard inherited rlimits stop individual fork/CPU/file/AS
//! excess; the host-side watchdog also kills a session exceeding aggregate RSS or disk.
//! Sampling (100 ms) permits overshoot, so these are process-level budgets, not quotas
//! suitable for mutually hostile tenants. VM/filesystem quotas remain E8.
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
    pub(crate) fn start(self, pgid: u32) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut cpu_seen = std::collections::HashMap::<u32, f64>::new();
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let Ok(ps) = Command::new("/bin/ps")
                    .args(["-A", "-o", "pgid=,pid=,rss=,time="])
                    .output()
                    .await
                else {
                    super::super::proc::kill_group(pgid);
                    return;
                };
                if !ps.status.success() {
                    super::super::proc::kill_group(pgid);
                    return;
                }
                let mut rss = 0_u64;
                let mut count = 0;
                for l in String::from_utf8_lossy(&ps.stdout).lines() {
                    let mut cols = l.split_whitespace();
                    if cols.next().and_then(|s| s.parse::<u32>().ok()) == Some(pgid) {
                        count += 1;
                        let pid = cols.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
                        rss += cols.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                        let time = cpu_seconds(cols.next().unwrap_or("0"));
                        let prior = cpu_seen.entry(pid).or_default();
                        *prior = prior.max(time);
                    }
                }
                if count == 0 {
                    return;
                }
                let mut disk = 0;
                for path in &self.paths {
                    let Ok(du) = Command::new("/usr/bin/du")
                        .arg("-sk")
                        .arg(path)
                        .output()
                        .await
                    else {
                        super::super::proc::kill_group(pgid);
                        return;
                    };
                    if !du.status.success() {
                        super::super::proc::kill_group(pgid);
                        return;
                    }
                    disk += String::from_utf8_lossy(&du.stdout)
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse::<u64>().ok())
                        .unwrap_or(u64::MAX / 8);
                }
                if count > self.processes
                    || rss > self.memory
                    || disk > self.disk
                    || cpu_seen.values().sum::<f64>() >= self.cpu as f64
                {
                    tracing::warn!(pgid, "session exceeded aggregate CPU/memory/disk budget");
                    super::super::proc::kill_group(pgid);
                    return;
                }
            }
        })
    }
}

fn cpu_seconds(text: &str) -> f64 {
    let (days, rest) = text
        .split_once('-')
        .map_or((0.0, text), |(d, r)| (d.parse::<f64>().unwrap_or(0.0), r));
    days * 86400.0
        + rest.split(':').fold(0.0, |total, n| {
            total * 60.0 + n.parse::<f64>().unwrap_or(0.0)
        })
}
