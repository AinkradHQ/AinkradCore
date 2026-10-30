//! The host's load, as a heartbeat reports it (AIN-55): the one-minute load average and the CPU
//! count, so the server can give a loaded runner a longer lease.

use std::sync::atomic::{AtomicBool, Ordering};

use ainkrad_proto::runner::HostLoad;

static DISABLE_LOAD: AtomicBool = AtomicBool::new(false);

/// Called by test binaries so the real host load is not reported during parallel test runs
/// (which would trip the hub's back-pressure). Safe to call multiple times.
pub fn disable_for_tests() {
    DISABLE_LOAD.store(true, Ordering::SeqCst);
}

/// The host's one-minute load average and CPU count; `None` where this platform gives no load
/// average. Sampled on each heartbeat, from the heartbeat's own thread.
pub fn host_load() -> Option<HostLoad> {
    if DISABLE_LOAD.load(Ordering::SeqCst) {
        return None;
    }
    let cores = u32::try_from(std::thread::available_parallelism().ok()?.get()).ok()?;
    let avg1 = load_avg1()?;
    Some(HostLoad { avg1, cores })
}

/// Linux: the first field of `/proc/loadavg`.
#[cfg(target_os = "linux")]
fn load_avg1() -> Option<f64> {
    let text = std::fs::read_to_string("/proc/loadavg").ok()?;
    finite(text.split_whitespace().next()?.parse().ok()?)
}

/// macOS has no std call for the load average and the crate forbids `unsafe`, so it asks
/// `sysctl`, which prints `{ 1.23 1.10 0.98 }`: the second word is the one-minute average.
#[cfg(target_os = "macos")]
fn load_avg1() -> Option<f64> {
    let out = std::process::Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    finite(text.split_whitespace().nth(1)?.parse().ok()?)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn load_avg1() -> Option<f64> {
    None
}

/// `value` if it is a number a load can be (`parse` takes "nan" and "inf" too).
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn finite(value: f64) -> Option<f64> {
    value.is_finite().then_some(value)
}
