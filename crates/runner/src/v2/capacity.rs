//! What this host can take (E15 §3.1): CPU averaged over 60 s, memory, disk, toolchains, warm
//! caches and job slots, as `Capacity` in the hello and in every heartbeat. The crate forbids
//! `unsafe`, so macOS asks `sysctl`, `vm_stat` and `df`, as `load.rs` does.
//!
//! Battery, idle time, the gate verdict and the warm caches come from E15-4 (`hwgate`, `sync`)
//! through [`HwSource`]; until it is registered ([`configure`]) the gate reads `Off`: the host
//! takes sessions but no jobs.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ainkrad_proto::v2::{Battery, CacheInfo, Capacity, Gate};

/// The CPU window.
const WINDOW: Duration = Duration::from_secs(60);
/// Toolchain versions are probed this often: each probe runs a program.
const TOOLCHAIN_TTL: Duration = Duration::from_secs(300);

/// What only the hardware gate and the sync driver know (E15-4 implements it).
pub trait HwSource: Send + Sync {
    /// Whether this host takes jobs now. `cpu_pct` is the 60 s average just measured.
    fn gate(&self, cpu_pct: u8) -> Gate {
        let _ = cpu_pct;
        Gate::Off
    }
    fn battery(&self) -> Option<Battery> {
        None
    }
    fn idle_secs(&self) -> Option<u64> {
        None
    }
    /// The warm project caches held.
    fn caches(&self) -> Vec<CacheInfo> {
        Vec::new()
    }
    /// Toolchains installed from the pins (merged over the ones found on `PATH`).
    fn toolchains(&self) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
    /// An override of the default job slots.
    fn job_slots(&self) -> Option<u32> {
        None
    }
}

/// The source until E15-4's is registered.
struct NoSource;
impl HwSource for NoSource {}

struct Sampler {
    /// (when, busy, total) CPU counters, newest last; Linux only.
    cpu: VecDeque<(Instant, u64, u64)>,
    toolchains: Option<(Instant, BTreeMap<String, String>)>,
    root: PathBuf,
    source: Arc<dyn HwSource>,
}

fn sampler() -> &'static Mutex<Sampler> {
    static S: OnceLock<Mutex<Sampler>> = OnceLock::new();
    S.get_or_init(|| {
        Mutex::new(Sampler {
            cpu: VecDeque::new(),
            toolchains: None,
            root: std::env::var_os("HOME").map_or_else(std::env::temp_dir, PathBuf::from),
            source: Arc::new(NoSource),
        })
    })
}

/// Registers E15-4's source and the cache root whose free disk is reported.
pub fn configure(root: PathBuf, source: Arc<dyn HwSource>) {
    let mut s = sampler().lock().unwrap();
    s.root = root;
    s.source = source;
}

/// The capacity now. Runs a few short programs: call it off the async threads.
pub fn capacity() -> Capacity {
    sampler().lock().unwrap().sample(Instant::now())
}

impl Sampler {
    fn sample(&mut self, now: Instant) -> Capacity {
        let cores = std::thread::available_parallelism()
            .ok()
            .and_then(|n| u32::try_from(n.get()).ok())
            .unwrap_or(1);
        let cpu_pct = self.cpu_pct(now, cores);
        let (mem_total_mb, mem_free_mb) = memory().unwrap_or_default();
        if self
            .toolchains
            .as_ref()
            .is_none_or(|(at, _)| now.duration_since(*at) > TOOLCHAIN_TTL)
        {
            self.toolchains = Some((now, found_toolchains()));
        }
        let mut toolchains = self
            .toolchains
            .as_ref()
            .map(|t| t.1.clone())
            .unwrap_or_default();
        toolchains.extend(self.source.toolchains());
        Capacity {
            cores,
            cpu_pct,
            mem_total_mb,
            mem_free_mb,
            disk_free_mb: disk_free_mb(&self.root).unwrap_or_default(),
            battery: self.source.battery(),
            idle_secs: self.source.idle_secs(),
            gate: self.source.gate(cpu_pct),
            toolchains,
            caches: self.source.caches(),
            job_slots: self
                .source
                .job_slots()
                .map_or_else(|| Capacity::default_job_slots(cores), |n| n.max(1)),
        }
    }

    /// CPU use over the last 60 s: counter deltas on Linux; elsewhere the one-minute load average
    /// per core, which is itself a minute's average. ponytail: a coarse stand-in on macOS.
    fn cpu_pct(&mut self, now: Instant, cores: u32) -> u8 {
        let Some((busy, total)) = cpu_counters() else {
            return crate::load::host_load().map_or(0, |l| load_pct(l.avg1, cores));
        };
        self.cpu.push_back((now, busy, total));
        // Keep one sample at or beyond the window so a full minute is always spanned.
        while self.cpu.len() > 2 && now.duration_since(self.cpu[1].0) >= WINDOW {
            self.cpu.pop_front();
        }
        let (_, b0, t0) = self.cpu[0];
        if total > t0 {
            delta_pct(b0, t0, busy, total)
        } else {
            0
        }
    }
}

/// `busy` over `total` between two counter readings, 0 to 100.
fn delta_pct(b0: u64, t0: u64, b1: u64, t1: u64) -> u8 {
    let (db, dt) = (b1.saturating_sub(b0), t1.saturating_sub(t0));
    if dt == 0 {
        return 0;
    }
    u8::try_from((db.saturating_mul(100) / dt).min(100)).unwrap_or(100)
}

/// A load average over `cores` as a percentage, capped at 100.
fn load_pct(avg1: f64, cores: u32) -> u8 {
    if cores == 0 || !avg1.is_finite() || avg1 < 0.0 {
        return 0;
    }
    (avg1 / f64::from(cores) * 100.0).round().min(100.0) as u8
}

/// The first line of `/proc/stat` as (busy, total) jiffies; idle and iowait are not busy.
fn parse_proc_stat(text: &str) -> Option<(u64, u64)> {
    let f: Vec<u64> = text
        .lines()
        .next()?
        .strip_prefix("cpu ")?
        .split_whitespace()
        .map(|w| w.parse().ok())
        .collect::<Option<_>>()?;
    let total: u64 = f.iter().take(8).sum();
    let idle = f.get(3)? + f.get(4).copied().unwrap_or(0);
    Some((total.saturating_sub(idle), total))
}

fn cpu_counters() -> Option<(u64, u64)> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    parse_proc_stat(&std::fs::read_to_string("/proc/stat").ok()?)
}

/// `/proc/meminfo` as (total, available) in MB.
fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let kb = |key: &str| -> Option<u64> {
        text.lines().find_map(|l| {
            l.strip_prefix(key)?
                .trim()
                .strip_suffix("kB")?
                .trim()
                .parse()
                .ok()
        })
    };
    Some((kb("MemTotal:")? / 1024, kb("MemAvailable:")? / 1024))
}

/// `vm_stat` output as the MB that new work can take: free, inactive and speculative pages.
fn parse_vm_stat(text: &str) -> Option<u64> {
    let page: u64 = text
        .lines()
        .next()?
        .split("page size of ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let pages = |key: &str| -> u64 {
        text.lines()
            .find_map(|l| {
                l.strip_prefix(key)?
                    .trim()
                    .trim_end_matches('.')
                    .parse()
                    .ok()
            })
            .unwrap_or(0)
    };
    let n = pages("Pages free:") + pages("Pages inactive:") + pages("Pages speculative:");
    Some(n * page / (1024 * 1024))
}

fn memory() -> Option<(u64, u64)> {
    if cfg!(target_os = "linux") {
        return parse_meminfo(&std::fs::read_to_string("/proc/meminfo").ok()?);
    }
    let total = run("sysctl", &["-n", "hw.memsize"])?
        .trim()
        .parse::<u64>()
        .ok()?
        / (1024 * 1024);
    Some((total, parse_vm_stat(&run("vm_stat", &[])?)?.min(total)))
}

/// `df -Pk` output as the available MB of its one data row.
fn parse_df(text: &str) -> Option<u64> {
    let kb: u64 = text
        .lines()
        .nth(1)?
        .split_whitespace()
        .nth(3)?
        .parse()
        .ok()?;
    Some(kb / 1024)
}

fn disk_free_mb(root: &std::path::Path) -> Option<u64> {
    parse_df(&run("df", &["-Pk", root.to_str()?])?)
}

/// The version in a tool's `--version` first line: its first word that starts with a digit.
fn parse_version(out: &str) -> Option<String> {
    out.lines().next()?.split_whitespace().find_map(|w| {
        let w = w.trim_start_matches('v').trim_end_matches(',');
        w.starts_with(|c: char| c.is_ascii_digit())
            .then(|| w.to_owned())
    })
}

/// Toolchains on `PATH` (`rust`, `node`, `python`, `go`, `swift`, `docker`; `xcode` on macOS).
fn found_toolchains() -> BTreeMap<String, String> {
    let mut probes: Vec<(&str, &str, &[&str])> = vec![
        ("rust", "rustc", &["--version"]),
        ("node", "node", &["--version"]),
        ("python", "python3", &["--version"]),
        ("go", "go", &["version"]),
        ("swift", "swift", &["--version"]),
        ("docker", "docker", &["--version"]),
    ];
    if cfg!(target_os = "macos") {
        probes.push(("xcode", "xcodebuild", &["-version"]));
    }
    probes
        .into_iter()
        .filter_map(|(name, bin, args)| {
            let v = if name == "go" {
                // "go version go1.23.1 linux/amd64"
                parse_version(run(bin, args)?.replace("go version go", "").as_str())
            } else {
                parse_version(&run(bin, args)?)
            }?;
            Some((name.to_owned(), v))
        })
        .collect()
}

/// A program's stdout when it ran and exited 0.
fn run(bin: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(bin).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_is_the_busy_share_of_the_window() {
        assert_eq!(delta_pct(100, 1000, 600, 2000), 50);
        assert_eq!(delta_pct(0, 0, 0, 0), 0);
        assert_eq!(
            delta_pct(500, 1000, 100, 2000),
            0,
            "a counter reset is not negative"
        );
        assert_eq!(load_pct(2.0, 4), 50);
        assert_eq!(load_pct(9.0, 4), 100);
        assert_eq!(load_pct(f64::NAN, 4), 0);
    }

    #[test]
    fn proc_stat_idle_and_iowait_are_not_busy() {
        let t = "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 1 1 1 1 1 1 1 1 1\n";
        assert_eq!(parse_proc_stat(t), Some((200, 1000)));
        assert_eq!(parse_proc_stat("garbage"), None);
    }

    #[test]
    fn the_window_keeps_a_full_minute_and_averages_over_it() {
        let t0 = Instant::now();
        let mut s = Sampler {
            cpu: VecDeque::new(),
            toolchains: None,
            root: PathBuf::new(),
            source: Arc::new(NoSource),
        };
        // Feed counters directly: 10 s apart, half busy, for two minutes.
        for i in 0..=12u64 {
            s.cpu
                .push_back((t0 + Duration::from_secs(10 * i), i * 500, i * 1000));
            let now = t0 + Duration::from_secs(10 * i);
            while s.cpu.len() > 2 && now.duration_since(s.cpu[1].0) >= WINDOW {
                s.cpu.pop_front();
            }
        }
        assert!(
            s.cpu.len() <= 8,
            "older than the window is dropped: {}",
            s.cpu.len()
        );
        let (_, b0, t0c) = s.cpu[0];
        assert_eq!(delta_pct(b0, t0c, 12 * 500, 12 * 1000), 50);
    }

    #[test]
    fn memory_and_disk_parse() {
        let m = "MemTotal:       16384000 kB\nMemFree: 1 kB\nMemAvailable:    8192000 kB\n";
        assert_eq!(parse_meminfo(m), Some((16000, 8000)));
        let v = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\n\
                 Pages free:                               1000.\n\
                 Pages inactive:                           2000.\n\
                 Pages speculative:                        1000.\n";
        assert_eq!(parse_vm_stat(v), Some(4000 * 16384 / (1024 * 1024)));
        let d = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 1000000 400000 600000 40% /\n";
        assert_eq!(parse_df(d), Some(585));
    }

    #[test]
    fn versions_are_read_from_the_first_line() {
        assert_eq!(
            parse_version("rustc 1.90.0 (abc 2026-01-01)\n"),
            Some("1.90.0".into())
        );
        assert_eq!(parse_version("v22.22.1\n"), Some("22.22.1".into()));
        assert_eq!(parse_version("Python 3.13.2"), Some("3.13.2".into()));
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn the_default_source_takes_no_jobs_and_slots_are_a_quarter_of_the_cores() {
        let mut s = Sampler {
            cpu: VecDeque::new(),
            toolchains: Some((Instant::now(), BTreeMap::new())),
            root: std::env::temp_dir(),
            source: Arc::new(NoSource),
        };
        let c = s.sample(Instant::now());
        assert_eq!(c.gate, Gate::Off);
        assert_eq!(c.job_slots, Capacity::default_job_slots(c.cores));
        assert!(c.cores >= 1);
    }
}
