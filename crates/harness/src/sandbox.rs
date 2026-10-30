//! Default-deny filesystem compilation. Bubblewrap supplies user/mount/PID namespaces
//! without bespoke unsafe Landlock/seccomp code. No host-root bind: adding a toolchain
//! is an explicit read-only grant. Process isolation is not VM isolation (E8).
use crate::Spec;
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};
use tokio::process::Command;
mod budget;
pub(crate) mod tree;
pub(crate) use budget::configure as configure_budget;
pub(crate) use budget::{Budget, Watch};

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

pub(crate) fn profile(spec: &Spec, program: &OsStr) -> String {
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
    for dir in program_dirs(program, spec) {
        s.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            quote(&dir)
        ));
    }
    s.push_str("(allow file-read* (literal \"/dev/null\") (literal \"/dev/urandom\") (literal \"/dev/random\"))\n(allow file-write* (literal \"/dev/null\"))\n");
    // No keychain mach services and no home/state grants, including metadata lookups.
    // Network policy (`AINKRAD_SANDBOX_NETWORK`, set per session by the runner):
    //  - `deny`: nothing at all.
    //  - default `allow`: agents must reach their model API and package hosts, so outbound
    //    HTTPS and DNS stay open. It is NOT `network*`: that also covers AF_UNIX connects,
    //    which would let a same-uid agent reach ptyhost, docker or ssh-agent sockets. Only
    //    TCP/443, DNS and loopback IP are granted; unix sockets other than the DNS resolver
    //    are not, and plain-HTTP/link-local hosts (cloud metadata, port 80) are not reachable.
    //    Residual: loopback services on this host are reachable (a harness may run a local
    //    HTTP API); Seatbelt cannot separate those from the internet.
    if env(spec, "AINKRAD_SANDBOX_NETWORK") != "deny" {
        s.push_str(concat!(
            "(allow network-outbound (remote tcp \"*:443\") (remote udp \"*:53\") (remote tcp \"*:53\") (remote ip \"localhost:*\"))\n",
            "(allow network-bind (local ip \"localhost:*\"))\n",
            "(allow network-inbound (local ip \"localhost:*\"))\n",
            "(allow network-outbound (literal \"/private/var/run/mDNSResponder\"))\n",
            "(allow mach-lookup (global-name \"com.apple.dnssd.service\") (global-name \"com.apple.SystemConfiguration.DNSConfiguration\"))\n",
        ));
    }
    s
}

/// Where the harness executable lives, read-only, when that is outside the toolchain paths:
/// the directory the name resolves to and the one its symlink points into (an `nvm` or
/// `~/.local` install). Never `/`, a home directory or its parent, which would expose
/// `~/.ssh`.
fn program_dirs(program: &OsStr, spec: &Spec) -> Vec<PathBuf> {
    let path = Path::new(program);
    let found = if path.is_absolute() {
        Some(path.to_path_buf())
    } else if path.components().count() == 1 {
        let search = spec
            .env
            .iter()
            .find(|(n, _)| n == "PATH")
            .map(|(_, v)| v.clone());
        let search = search
            .or_else(|| std::env::var_os("PATH"))
            .unwrap_or_default();
        std::env::split_paths(&search)
            .map(|d| d.join(path))
            .find(|p| p.is_file())
    } else {
        None
    };
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut dirs = Vec::new();
    for file in found
        .into_iter()
        .flat_map(|f| [f.canonicalize().ok(), Some(f)])
        .flatten()
    {
        let Some(dir) = file.parent().map(Path::to_path_buf) else {
            continue;
        };
        let broad = dir.parent().is_none()
            || Some(&dir) == home.as_ref()
            || home.as_ref().is_some_and(|h| h.starts_with(&dir))
            || TOOLS.iter().any(|t| dir.starts_with(t))
            || writable(spec).iter().any(|w| dir.starts_with(w));
        if !broad && dir.is_dir() && !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
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
        c.arg("-p").arg(profile(spec, program));
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
            // `--dev` gives an unsized /dev/shm tmpfs that counts against no limit.
            "--size",
            "16777216",
            "--tmpfs",
            "/dev/shm",
            "--dir",
            "/tmp",
            // A detached tty (TIOCSTI), no capabilities, and no nested user namespace: a
            // nested `unshare -U` would restart the per-user process count.
            "--new-session",
            "--cap-drop",
            "ALL",
            "--disable-userns",
            "--unshare-cgroup-try",
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
        for p in program_dirs(program, spec) {
            c.arg("--ro-bind").arg(&p).arg(&p);
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

/// Kills the group a restart record names. Safe on a recycled pid: it signals when the leader
/// still matches the record's start time, or when it is gone but a process still has that group id
/// (a pgid cannot be reused while a member lives), so a leader that exited leaving a member is reaped.
pub fn reap_group(record: &str) -> bool {
    let Ok(pgid) = record.split(':').next().unwrap_or("").parse::<u32>() else {
        return false;
    };
    if pgid <= 1 {
        return false;
    }
    // A process with this pid exists: it is the recorded leader only if its start time
    // matches, else the number was recycled by an unrelated process. No such process: the
    // number cannot have been reused while a member of the group lives, so members mean the
    // recorded group, orphaned.
    let ours = match identity(pgid) {
        Ok(id) => id == record,
        Err(_) => tree::group_alive(pgid),
    };
    if !ours {
        return false;
    }
    ainkrad_sys::killpg(pgid, 9).unwrap_or(false)
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

#[cfg(test)]
mod orphan_tests;
