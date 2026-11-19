//! The last 24 hours of the Core's own readings, one per minute, for the Activity app's Ops
//! charts (E2-6). Kept in memory, filled by [`super::Health::tick`]: a restart starts the charts
//! again, and a Core nobody asks still samples, so a chart opened later is already drawn.
// ponytail: in memory only; persist to the store if a chart must survive a restart.

use std::collections::VecDeque;
use std::sync::Mutex;

/// One minute's readings. `None`: the host did not say.
#[derive(Debug, Clone, PartialEq)]
pub struct Sample {
    pub at: i64,
    /// The Core process's share of one core, 0 to 100 and more on several cores.
    pub cpu_pct: Option<f64>,
    pub memory_bytes: Option<u64>,
    pub disk_used_pct: Option<i64>,
}

#[derive(Default)]
struct Inner {
    samples: VecDeque<Sample>,
    /// The process's CPU seconds at the last sample, to turn the total into a share.
    last_cpu: Option<(i64, f64)>,
}

#[derive(Default)]
pub struct History(Mutex<Inner>);

impl History {
    /// A day of minutes.
    pub const KEEP: usize = 1_440;

    /// Adds the sample for `at` (unix seconds). `cpu_secs` is the process's total CPU time.
    pub fn record(
        &self,
        at: i64,
        cpu_secs: Option<f64>,
        memory_bytes: Option<u64>,
        disk_used_pct: Option<i64>,
    ) {
        let mut inner = self.0.lock().unwrap();
        let cpu_pct = match (cpu_secs, inner.last_cpu) {
            (Some(now), Some((then_at, then))) if at > then_at && now >= then => {
                Some((now - then) / (at - then_at) as f64 * 100.0)
            }
            _ => None,
        };
        if let Some(c) = cpu_secs {
            inner.last_cpu = Some((at, c));
        }
        if inner.samples.len() >= Self::KEEP {
            inner.samples.pop_front();
        }
        inner.samples.push_back(Sample {
            at,
            cpu_pct,
            memory_bytes,
            disk_used_pct,
        });
    }

    /// The samples taken at or after `from` (unix seconds), oldest first.
    pub fn since(&self, from: i64) -> Vec<Sample> {
        let inner = self.0.lock().unwrap();
        inner
            .samples
            .iter()
            .filter(|s| s.at >= from)
            .cloned()
            .collect()
    }
}

/// `[[dd-]hh:]mm:ss[.ff]`, what `ps -o cputime=` prints on macOS and Linux, in seconds.
pub fn parse_cpu_time(text: &str) -> Option<f64> {
    let text = text.trim();
    let (days, rest) = match text.split_once('-') {
        Some((d, r)) => (d.parse::<f64>().ok()?, r),
        None => (0.0, text),
    };
    let mut secs = 0.0;
    for part in rest.split(':') {
        secs = secs * 60.0 + part.parse::<f64>().ok()?;
    }
    Some(days * 86_400.0 + secs)
}

/// This process's total CPU time in seconds, from `ps`; `None` where it cannot be read.
pub async fn cpu_secs() -> Option<f64> {
    let out = tokio::process::Command::new("ps")
        .args(["-o", "cputime=", "-p", &std::process::id().to_string()])
        .output()
        .await
        .ok()?;
    parse_cpu_time(&String::from_utf8(out.stdout).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_time_is_read_in_both_ps_formats() {
        assert_eq!(parse_cpu_time("0:05.50"), Some(5.5));
        assert_eq!(parse_cpu_time(" 01:02:03 "), Some(3723.0));
        assert_eq!(parse_cpu_time("2-00:00:10"), Some(172_810.0));
        assert_eq!(parse_cpu_time("nonsense"), None);
    }

    #[test]
    fn a_share_needs_two_samples_and_the_ring_keeps_a_day() {
        let h = History::default();
        h.record(0, Some(10.0), Some(1), Some(40));
        h.record(60, Some(16.0), Some(2), Some(41));
        let s = h.since(0);
        assert_eq!(s[0].cpu_pct, None, "no share from one sample");
        assert_eq!(s[1].cpu_pct, Some(10.0), "6 CPU seconds in 60 s");
        assert_eq!(h.since(60).len(), 1);
        for i in 0..2_000 {
            h.record(120 + i * 60, None, None, None);
        }
        assert_eq!(h.since(0).len(), History::KEEP);
    }
}
