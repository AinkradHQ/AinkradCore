//! The machine the Core runs on (E2-6): memory and CPU from `/proc`, which a Linux host has and
//! needs no root to read. Anywhere else (a macOS dev box) every reading is `None`, never an
//! error. Disk comes from `metrics::disk`.

/// Memory in use and in total, in bytes, from the text of `/proc/meminfo`. "In use" is the total
/// less what the kernel says is available (free plus reclaimable cache).
pub fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let kib = |key: &str| {
        text.lines().find_map(|l| {
            l.strip_prefix(key)?
                .trim()
                .strip_suffix("kB")?
                .trim()
                .parse::<u64>()
                .ok()
        })
    };
    let total = kib("MemTotal:")?.checked_mul(1024)?;
    let avail = kib("MemAvailable:")?.checked_mul(1024)?;
    (total > 0).then(|| (total.saturating_sub(avail), total))
}

/// The one-minute load average, from the text of `/proc/loadavg`.
pub fn parse_loadavg(text: &str) -> Option<f64> {
    text.split_whitespace().next()?.parse().ok()
}

/// `(busy, total)` jiffies of all CPUs, from the text of `/proc/stat`. Two readings make a share.
pub fn parse_cpu_jiffies(text: &str) -> Option<(u64, u64)> {
    let f: Vec<u64> = text
        .lines()
        .next()?
        .strip_prefix("cpu ")?
        .split_whitespace()
        .take(8)
        .map(|v| v.parse().ok())
        .collect::<Option<_>>()?;
    // user nice system idle iowait irq softirq steal
    let [_, _, _, idle, iowait, ..] = f[..] else {
        return None;
    };
    let total: u64 = f.iter().sum();
    Some((total.saturating_sub(idle + iowait), total))
}

/// The share of CPU used between two [`parse_cpu_jiffies`] readings, 0 to 100.
pub fn cpu_share(then: (u64, u64), now: (u64, u64)) -> Option<f64> {
    let total = now.1.checked_sub(then.1).filter(|t| *t > 0)?;
    let busy = now.0.checked_sub(then.0)?;
    Some((busy as f64 / total as f64 * 100.0).min(100.0))
}

pub fn memory() -> Option<(u64, u64)> {
    parse_meminfo(&std::fs::read_to_string("/proc/meminfo").ok()?)
}

pub fn load1() -> Option<f64> {
    parse_loadavg(&std::fs::read_to_string("/proc/loadavg").ok()?)
}

pub fn cpu_jiffies() -> Option<(u64, u64)> {
    parse_cpu_jiffies(&std::fs::read_to_string("/proc/stat").ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_is_the_total_less_what_is_available() {
        let t = "MemTotal:       16000000 kB\nMemFree:  100 kB\nMemAvailable:    4000000 kB\n";
        assert_eq!(
            parse_meminfo(t),
            Some((12_000_000 * 1024, 16_000_000 * 1024))
        );
        assert_eq!(parse_meminfo("MemTotal: 5 kB\n"), None);
        assert_eq!(parse_meminfo(""), None);
    }

    #[test]
    fn load_is_the_first_number() {
        assert_eq!(parse_loadavg("0.52 0.40 0.30 1/200 999\n"), Some(0.52));
        assert_eq!(parse_loadavg(""), None);
    }

    #[test]
    fn cpu_share_is_busy_over_total_between_two_readings() {
        let a = parse_cpu_jiffies("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 1 1 1\n").unwrap();
        assert_eq!(a, (200, 1000));
        let b = parse_cpu_jiffies("cpu  200 0 200 800 100 0 0 0 0 0\n").unwrap();
        assert_eq!(cpu_share(a, b), Some(66.66666666666666));
        assert_eq!(cpu_share(a, a), None, "no time passed");
        assert_eq!(parse_cpu_jiffies("intr 5"), None);
    }
}
