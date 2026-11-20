//! The runner's own verdict on taking heavy jobs (E15-4, spec §6 "Mac gate"), reported as
//! `Capacity::gate` (with `battery` and `idle_secs`) for E15-1's capacity report.
//!
//! - **Open** (the bundled Mac): not on battery, idle for at least [`IDLE_OPEN_SECS`] or CPU below
//!   [`CPU_BUSY_PCT`], and not paused on this machine. Any other runner is `Open` unless paused here.
//! - **On battery during a job:** [`BATTERY_GRACE`] of grace, then the job is cancelled (the Core
//!   places it again). A pause set on the Core always wins; this gate only speaks for the host.
//! - Readings come from `pmset -g batt` (power source and percent) and `ioreg -c IOHIDSystem`
//!   (`HIDIdleTime`, nanoseconds since the last input). The parsers are pure, so tests feed them
//!   stubbed output.
//! - A local pause is the file `<state>/hw-pause`: a Unix time in seconds, or `forever`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use ainkrad_proto::v2::{Battery, Gate};

/// This much idle time opens the gate whatever the CPU does.
pub const IDLE_OPEN_SECS: u64 = 120;
/// Below this CPU use the Mac counts as not busy.
pub const CPU_BUSY_PCT: u8 = 30;
/// How long a running job may go on once the Mac is on battery.
pub const BATTERY_GRACE: Duration = Duration::from_secs(60);

/// What the host says now.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reading {
    pub battery: Option<Battery>,
    pub idle_secs: Option<u64>,
    pub cpu_pct: u8,
}

/// `pmset -g batt`: the source line and the battery line. `None` when there is no battery (a desktop
/// Mac, or a host that is not one).
pub fn parse_pmset(out: &str) -> Option<Battery> {
    let on_battery = out
        .lines()
        .find(|l| l.contains("drawing from"))
        .map(|l| l.contains("Battery Power"))?;
    let percent = out.lines().find_map(|l| {
        let (before, _) = l.split_once('%')?;
        let digits: String = before
            .chars()
            .rev()
            .take_while(char::is_ascii_digit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        digits.parse::<u8>().ok().filter(|p| *p <= 100)
    })?;
    Some(Battery {
        on_battery,
        percent,
    })
}

/// `ioreg -c IOHIDSystem`: `"HIDIdleTime" = <ns>`, as whole seconds. The largest when several
/// devices list one (the machine is idle only when all of them are).
pub fn parse_hid_idle(out: &str) -> Option<u64> {
    out.lines()
        .filter(|l| l.contains("\"HIDIdleTime\""))
        .filter_map(|l| l.split('=').nth(1)?.trim().parse::<u64>().ok())
        .min()
        .map(|ns| ns / 1_000_000_000)
}

/// The gate for a reading. `mac` is the bundled Mac (the only one that reads battery and idle).
pub fn decide(r: &Reading, paused: bool, mac: bool) -> Gate {
    if paused {
        return Gate::Paused;
    }
    if !mac {
        return Gate::Open;
    }
    if r.battery.is_some_and(|b| b.on_battery) {
        return Gate::OnBattery;
    }
    // An unreadable idle time counts as in use: a Mac that cannot say is not offered.
    let idle = r.idle_secs.is_some_and(|s| s >= IDLE_OPEN_SECS);
    if idle || r.cpu_pct < CPU_BUSY_PCT {
        Gate::Open
    } else {
        Gate::Busy
    }
}

/// Whether the pause file `text` (read at `now`, Unix seconds) pauses this host.
pub fn paused_by(text: &str, now: u64) -> bool {
    match text.trim() {
        "" => false,
        "forever" => true,
        t => t.parse::<u64>().is_ok_and(|until| until > now),
    }
}

fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The gate of one runner.
#[derive(Debug, Clone)]
pub struct HwGate {
    pause_file: PathBuf,
    mac: bool,
}

impl HwGate {
    /// `mac`: this is the bundled Mac runner (`--bundled`) on macOS.
    pub fn new(state: &Path, bundled: bool) -> Self {
        Self {
            pause_file: state.join("hw-pause"),
            mac: bundled && cfg!(target_os = "macos"),
        }
    }

    pub fn is_mac(&self) -> bool {
        self.mac
    }

    fn paused(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        std::fs::read_to_string(&self.pause_file).is_ok_and(|t| paused_by(&t, now))
    }

    /// Reads `pmset` and `ioreg` (blocking: a few short programs; call from `spawn_blocking`). `cpu_pct`
    /// is the caller's own 60 s figure.
    pub fn read(&self, cpu_pct: u8) -> Reading {
        if !self.mac {
            return Reading {
                cpu_pct,
                ..Reading::default()
            };
        }
        Reading {
            battery: run("/usr/bin/pmset", &["-g", "batt"]).and_then(|o| parse_pmset(&o)),
            idle_secs: run("/usr/sbin/ioreg", &["-c", "IOHIDSystem", "-r", "-d", "4"])
                .and_then(|o| parse_hid_idle(&o)),
            cpu_pct,
        }
    }

    /// The gate now, with the reading it came from (for `Capacity::{gate, battery, idle_secs}`).
    pub fn sample(&self, cpu_pct: u8) -> (Gate, Reading) {
        let r = self.read(cpu_pct);
        (decide(&r, self.paused(), self.mac), r)
    }

    /// Whether the host is on battery right now: what a running job's watcher polls.
    pub fn on_battery(&self) -> bool {
        self.mac
            && run("/usr/bin/pmset", &["-g", "batt"])
                .and_then(|o| parse_pmset(&o))
                .is_some_and(|b| b.on_battery)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AC: &str = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=4653155)\t87%; charging; 0:42 remaining present: true\n";
    const BATT: &str = "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=4653155)\t41%; discharging; 3:12 remaining present: true\n";
    const DESKTOP: &str = "Now drawing from 'AC Power'\n";

    #[test]
    fn pmset_gives_the_source_and_the_percent() {
        assert_eq!(
            parse_pmset(AC),
            Some(Battery {
                on_battery: false,
                percent: 87
            })
        );
        assert_eq!(
            parse_pmset(BATT),
            Some(Battery {
                on_battery: true,
                percent: 41
            })
        );
        assert_eq!(parse_pmset(DESKTOP), None, "no battery line");
        assert_eq!(parse_pmset("garbage"), None);
    }

    #[test]
    fn ioreg_idle_is_seconds_and_the_smallest_device_wins() {
        let out = "  | |   \"HIDIdleTime\" = 125000000000\n  | |   \"HIDIdleTime\" = 3000000000\n";
        assert_eq!(parse_hid_idle(out), Some(3));
        assert_eq!(parse_hid_idle("\"HIDIdleTime\" = 130000000000"), Some(130));
        assert_eq!(parse_hid_idle("nothing"), None);
    }

    fn r(on_battery: Option<bool>, idle: Option<u64>, cpu: u8) -> Reading {
        Reading {
            battery: on_battery.map(|on_battery| Battery {
                on_battery,
                percent: 50,
            }),
            idle_secs: idle,
            cpu_pct: cpu,
        }
    }

    #[test]
    fn the_mac_is_open_only_off_battery_and_idle_or_quiet() {
        assert_eq!(
            decide(&r(Some(false), Some(300), 90), false, true),
            Gate::Open
        );
        assert_eq!(
            decide(&r(Some(false), Some(5), 10), false, true),
            Gate::Open
        );
        assert_eq!(
            decide(&r(Some(false), Some(5), 80), false, true),
            Gate::Busy
        );
        assert_eq!(decide(&r(Some(false), None, 80), false, true), Gate::Busy);
        assert_eq!(
            decide(&r(Some(true), Some(999), 0), false, true),
            Gate::OnBattery
        );
        assert_eq!(
            decide(&r(Some(false), Some(999), 0), true, true),
            Gate::Paused
        );
        assert_eq!(
            decide(&r(None, Some(5), 29), false, true),
            Gate::Open,
            "a desktop Mac"
        );
    }

    #[test]
    fn another_runner_is_open_unless_paused_here() {
        assert_eq!(decide(&r(Some(true), None, 99), false, false), Gate::Open);
        assert_eq!(decide(&Reading::default(), true, false), Gate::Paused);
    }

    #[test]
    fn the_pause_file_is_a_time_or_forever() {
        assert!(paused_by("forever\n", 10));
        assert!(paused_by("100", 10));
        assert!(!paused_by("100", 100));
        assert!(!paused_by("", 10));
        assert!(!paused_by("soon", 10));
    }
}
