//! Default-deny filesystem compilation. Bubblewrap supplies user/mount/PID namespaces
//! without bespoke unsafe Landlock/seccomp code. No host-root bind: adding a toolchain
//! is an explicit read-only grant. Process isolation is not VM isolation (E8).
use crate::Spec;
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use tokio::process::Command;
mod budget;
pub(crate) use budget::Budget;
pub(crate) use budget::configure as configure_budget;

fn env<'a>(spec: &'a Spec, key: &str) -> &'a OsStr {
    spec.env
        .iter()
        .find(|(n, _)| n == key)
        .map_or(OsStr::new(""), |(_, v)| v)
}
fn writable(spec: &Spec) -> Vec<PathBuf> {
    [&spec.cwd, &spec.config_dir]
        .into_iter()
        .cloned()
        .chain(
            ["AINKRAD_SANDBOX_TMP", "AINKRAD_SANDBOX_SECRETS"].map(|k| PathBuf::from(env(spec, k))),
        )
        .filter(|p| p.is_absolute() && p.exists())
        .collect()
}
const TOOLS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/System/Library",
    "/Library/Apple",
    "/opt/homebrew",
];

pub(crate) fn profile(spec: &Spec) -> String {
    let quote = |p: &Path| {
        p.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    };
    let mut s = String::from(
        "(version 1)\n(deny default)\n(allow process-exec process-fork)\n(allow process-info* (target self))\n(allow signal (target self))\n(allow sysctl-read (sysctl-name \"hw.ncpu\") (sysctl-name \"hw.memsize\") (sysctl-name \"kern.osrelease\") (sysctl-name \"kern.ostype\"))\n(allow mach-lookup (global-name \"com.apple.system.logger\"))\n",
    );
    for p in TOOLS {
        s.push_str(&format!("(allow file-read* (subpath \"{p}\"))\n"));
    }
    for p in writable(spec) {
        s.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))\n",
            quote(&p)
        ));
    }
    for p in [&spec.instructions, &spec.mcp_config].into_iter().flatten() {
        s.push_str(&format!("(allow file-read* (literal \"{}\"))\n", quote(p)));
    }
    s.push_str("(allow file-read* (literal \"/dev/null\") (literal \"/dev/urandom\") (literal \"/dev/random\"))\n(allow file-write* (literal \"/dev/null\"))\n");
    // No keychain mach services and no home/state grants, including metadata lookups.
    if env(spec, "AINKRAD_SANDBOX_NETWORK") != "deny" {
        s.push_str("(allow network*)\n");
    }
    s
}

pub(crate) fn command(program: &OsStr, args: &[String], spec: &Spec) -> Command {
    match compile(program, args, spec) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "sandbox compilation failed closed");
            // Preserve adapters' command-building API; spawn fails before any agent starts.
            Command::new("/nonexistent/ainkrad-sandbox-refused")
        }
    }
}
fn compile(program: &OsStr, args: &[String], spec: &Spec) -> io::Result<Command> {
    for path in [
        &spec.cwd,
        &spec.config_dir,
        &PathBuf::from(env(spec, "AINKRAD_SANDBOX_TMP")),
    ] {
        if !path.is_absolute() || path.parent().is_none() || !path.is_dir() {
            return Err(io::Error::other(
                "sandbox grants must be existing absolute session directories",
            ));
        }
    }
    let uid = std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()?;
    if !uid.status.success() || uid.stdout == b"0\n" {
        return Err(io::Error::other(
            "sandbox requires an unprivileged runner uid for fork limits",
        ));
    }
    let mut c;
    if cfg!(target_os = "macos") {
        // The profile contains paths, never values. Passing it directly also prevents a
        // prior agent from planting a profile-file symlink in its writable private tmp.
        c = Command::new("/usr/bin/sandbox-exec");
        c.arg("-p").arg(profile(spec));
    } else {
        c = Command::new("/usr/bin/bwrap");
        c.args([
            "--die-with-parent",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--dir",
            "/tmp",
        ]);
        for p in TOOLS.iter().filter(|p| Path::new(p).exists()) {
            c.args(["--ro-bind", p, p]);
        }
        // Only resolver/CA data, never all of /etc (which can contain credentials).
        for p in [
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/ssl/certs",
            "/etc/ld.so.cache",
        ] {
            if Path::new(p).exists() {
                c.args(["--ro-bind", p, p]);
            }
        }
        for p in writable(spec) {
            c.arg("--bind").arg(&p).arg(&p);
        }
        for p in [&spec.instructions, &spec.mcp_config].into_iter().flatten() {
            c.arg("--ro-bind").arg(p).arg(p);
        }
        if env(spec, "AINKRAD_SANDBOX_NETWORK") == "deny" {
            c.arg("--unshare-net");
        }
        c.args(["--remount-ro", "/dev", "--remount-ro", "/"])
            .arg("--chdir")
            .arg(&spec.cwd)
            .arg("--");
    }
    let limits = |name, default: &str| {
        let v = env(spec, name).to_string_lossy();
        if v.is_empty() {
            Ok(default.to_owned())
        } else if v.parse::<u64>().is_ok_and(|n| n > 0) {
            Ok(v.into_owned())
        } else {
            Err(io::Error::other("invalid sandbox limit"))
        }
    };
    let script = if cfg!(target_os = "macos") {
        "ulimit -S -u \"$1\" && ulimit -H -u \"$1\" && ulimit -S -t \"$2\" && ulimit -H -t \"$2\" && ulimit -S -f \"$3\" && ulimit -H -f \"$3\" || exit 125; shift 4; exec \"$@\""
    } else {
        "ulimit -S -u \"$1\" && ulimit -H -u \"$1\" && ulimit -S -t \"$2\" && ulimit -H -t \"$2\" && ulimit -S -f \"$3\" && ulimit -H -f \"$3\" && ulimit -S -v \"$4\" && ulimit -H -v \"$4\" || exit 125; shift 4; exec \"$@\""
    };
    let mut processes = limits("AINKRAD_SANDBOX_PROCESSES", "64")?
        .parse::<u64>()
        .map_err(io::Error::other)?;
    if cfg!(target_os = "macos") {
        // Darwin charges NPROC to the uid, not a session. Include pre-existing host
        // processes in the inherited hard ceiling; the host watchdog separately counts
        // this session's group. Concurrent host churn can reduce its headroom. Strict
        // independent tenant quotas require separate uids/VMs, outside isolation v1.
        let ps = std::process::Command::new("/bin/ps")
            .args(["-A", "-o", "uid="])
            .output()?;
        if !ps.status.success() {
            return Err(io::Error::other("cannot count uid processes"));
        }
        let uid = String::from_utf8_lossy(&uid.stdout);
        let existing = String::from_utf8_lossy(&ps.stdout)
            .lines()
            .filter(|s| s.trim() == uid.trim())
            .count()
            .saturating_sub(1);
        processes = processes
            .checked_add(existing as u64)
            .ok_or_else(|| io::Error::other("process limit overflow"))?;
    }
    c.arg("/bin/bash")
        .args(["-c", script, "ainkrad-sandbox"])
        .arg(processes.to_string())
        .arg(limits("AINKRAD_SANDBOX_CPU", "900")?)
        .arg(limits("AINKRAD_SANDBOX_FILE", "1048576")?)
        .arg(limits("AINKRAD_SANDBOX_MEMORY", "4194304")?)
        .arg(program)
        .args(args);
    budget::configure(&mut c, spec);
    Ok(c)
}

/// A restart record includes kernel-reported start time, uid and pgid. A recycled pid
/// must never authorize signalling an unrelated group. Linux's start tick has full precision.
pub fn identity(pid: u32) -> io::Result<String> {
    if cfg!(target_os = "linux") {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let fields: Vec<_> = stat
            .rsplit_once(')')
            .ok_or_else(|| io::Error::other("pid stat"))?
            .1
            .split_whitespace()
            .collect();
        return Ok(format!("{pid}:{}:{}", fields[2], fields[19]));
    }
    let o = std::process::Command::new("/bin/ps")
        .args(["-o", "uid=,pgid=,lstart=", "-p", &pid.to_string()])
        .output()?;
    if !o.status.success() || o.stdout.is_empty() {
        return Err(io::Error::other("process is gone"));
    }
    Ok(format!(
        "{pid}:{}",
        String::from_utf8_lossy(&o.stdout).trim()
    ))
}

#[cfg(test)]
mod tests;
