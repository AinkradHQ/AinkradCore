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

/// The value of `key`; when it is set more than once the LAST one wins (`crate::last_env`).
fn env<'a>(spec: &'a Spec, key: &str) -> &'a OsStr {
    crate::last_env(&spec.env, key).map_or(OsStr::new(""), |v| v.as_os_str())
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
/// macOS: the Command Line Tools / Xcode toolchain the `/usr/bin` shims forward to.
const MAC_DEV_TOOLS: &[&str] = &[
    "/Library/Developer/CommandLineTools",
    "/Applications/Xcode.app/Contents/Developer",
    "/private/var/select",
];

pub(crate) fn profile(spec: &Spec, program: &OsStr) -> String {
    let quote = |p: &Path| {
        p.to_string_lossy()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    };
    // `(deny default)` alone kills every process at launch (dyld, the shared cache and
    // libSystem need file maps, mach services, sysctls and /dev nodes). `system.sb` is
    // Apple's own base profile for exactly that; it grants no home, state or network.
    let mut s = String::from(
        "(version 1)\n(deny default)\n(import \"system.sb\")\n(allow process-exec process-fork)\n(allow process-info* (target self))\n(allow signal (target self))\n(allow sysctl-read (sysctl-name \"hw.ncpu\") (sysctl-name \"hw.memsize\") (sysctl-name \"kern.osrelease\") (sysctl-name \"kern.ostype\"))\n(allow mach-lookup (global-name \"com.apple.system.logger\"))\n",
    );
    // MAC_DEV_TOOLS is read-only too: the python3/git shims find the active developer dir.
    for p in TOOLS.iter().chain(MAC_DEV_TOOLS) {
        s.push_str(&format!(
            "(allow file-read* file-map-executable (subpath \"{p}\"))\n"
        ));
    }
    // The /usr/bin developer shims (python3, git, make, ...) run xcode-select, which reads
    // this one symlink (both spellings, /var being a link to /private/var) to find the
    // developer dir, then stats its target (granted above). Nothing else in /var/db.
    for p in [
        "/private/var/db/xcode_select_link",
        "/var/db/xcode_select_link",
    ] {
        s.push_str(&format!("(allow file-read* (literal \"{p}\"))\n"));
    }
    for p in ["/private/var", "/private/var/db", "/var", "/var/db"] {
        s.push_str(&format!("(allow file-read-metadata (literal \"{p}\"))\n"));
    }
    // Explicit denies, before the session grants so a grant inside one of these trees (a
    // worktree under the state dir) still wins. They also hold if system.sb ever widens.
    let mut hidden = vec![PathBuf::from(env(spec, "AINKRAD_SANDBOX_STATE"))];
    for home in [
        std::env::var_os("HOME").map(PathBuf::from),
        Some(PathBuf::from(env(spec, "HOME"))),
    ]
    .into_iter()
    .flatten()
    {
        hidden.extend([".ssh", ".gnupg", ".aws", "Library/Keychains"].map(|d| home.join(d)));
    }
    for p in hidden.iter().filter(|p| p.is_absolute()) {
        s.push_str(&format!(
            "(deny file-read* file-write* (subpath \"{}\"))\n",
            quote(p)
        ));
    }
    // Every unix socket (ptyhost, docker, ssh-agent) is denied; the DNS resolver's is
    // granted again below when the network policy allows it.
    s.push_str("(deny network-outbound (remote unix-socket))\n");
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
    // Path resolution stats each ancestor of a grant: that reveals names, never data.
    let mut ancestors: Vec<PathBuf> = writable(spec)
        .into_iter()
        .chain(program_dirs(program, spec))
        .chain(
            [&spec.instructions, &spec.mcp_config]
                .into_iter()
                .flatten()
                .cloned(),
        )
        .flat_map(|p| p.ancestors().map(Path::to_path_buf).collect::<Vec<_>>())
        .collect();
    ancestors.sort();
    ancestors.dedup();
    for p in ancestors {
        s.push_str(&format!(
            "(allow file-read-metadata (literal \"{}\"))\n",
            quote(&p)
        ));
    }
    s.push_str("(allow file-read* (literal \"/dev/null\") (literal \"/dev/urandom\") (literal \"/dev/random\"))\n(allow file-write* (literal \"/dev/null\"))\n");
    // No keychain mach services and no home/state grants, including metadata lookups.
    // Network policy (`AINKRAD_SANDBOX_NETWORK`, set per session by the runner):
    //  - `deny`, missing or anything but `allow`: nothing at all.
    //  - `allow`: agents must reach their model API and package hosts, so outbound
    //    HTTPS and DNS stay open. It is NOT `network*`: that also covers AF_UNIX connects,
    //    which would let a same-uid agent reach ptyhost, docker or ssh-agent sockets. Only
    //    TCP/443, DNS and loopback IP are granted; unix sockets other than the DNS resolver
    //    are not, and plain-HTTP/link-local hosts (cloud metadata, port 80) are not reachable.
    //    Residual: loopback services on this host are reachable (a harness may run a local
    //    HTTP API); Seatbelt cannot separate those from the internet.
    if env(spec, "AINKRAD_SANDBOX_NETWORK") == "allow" {
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
        // bubblewrap passes inherited descriptors through to the program it runs.
        ainkrad_sys::close_fds_on_exec(c.as_std_mut());
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
        // Only resolver/CA data, never all of /etc (which can contain credentials). A filtered
        // sandbox gets no resolver config: names are resolved by the egress proxy, outside.
        let filtered = env(spec, "AINKRAD_SANDBOX_NETWORK") == "filtered";
        for p in [
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/ssl/certs",
            "/etc/ld.so.cache",
        ] {
            if filtered && matches!(p, "/etc/resolv.conf" | "/etc/hosts") {
                continue;
            }
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
        // Network: the default is none. A run's MCP route comes in through a unix socket the
        // runner bridges to the Core, and a forwarder (the runner itself) on the namespace's
        // own loopback; the host's loopback and the metadata address stay unreachable.
        // Every value but the literal `allow` gets a network namespace of its own: `filtered` is
        // never mapped to `allow`, and a filtered sandbox without its egress socket is refused.
        if env(spec, "AINKRAD_SANDBOX_NETWORK") != "allow" {
            c.arg("--unshare-net");
            let (sock, fwd, port) = (
                env(spec, "AINKRAD_SANDBOX_MCP_SOCK"),
                env(spec, "AINKRAD_SANDBOX_MCP_FWD"),
                env(spec, "AINKRAD_SANDBOX_MCP_PORT"),
            );
            if [sock, fwd, port].iter().all(|v| !v.is_empty()) {
                c.arg("--bind").arg(sock).arg(sock);
                c.arg("--ro-bind").arg(fwd).arg(fwd);
                for (k, v) in [
                    ("AINKRAD_MCP_SOCK", sock),
                    ("AINKRAD_MCP_FWD", fwd),
                    ("AINKRAD_MCP_PORT", port),
                ] {
                    c.arg("--setenv").arg(k).arg(v);
                }
            }
            if filtered {
                let (sock, fwd, port) = (
                    env(spec, "AINKRAD_SANDBOX_EGRESS_SOCK"),
                    env(spec, "AINKRAD_SANDBOX_EGRESS_FWD"),
                    env(spec, "AINKRAD_SANDBOX_EGRESS_PORT"),
                );
                if [sock, fwd, port].iter().any(|v| v.is_empty()) {
                    return Err(io::Error::other(
                        "a filtered sandbox needs its egress socket",
                    ));
                }
                c.arg("--bind").arg(sock).arg(sock);
                if fwd != env(spec, "AINKRAD_SANDBOX_MCP_FWD") {
                    c.arg("--ro-bind").arg(fwd).arg(fwd);
                }
                for (k, v) in [
                    ("AINKRAD_EGRESS_SOCK", sock),
                    ("AINKRAD_EGRESS_FWD", fwd),
                    ("AINKRAD_EGRESS_PORT", port),
                ] {
                    c.arg("--setenv").arg(k).arg(v);
                }
                // Clients reach the proxy on the namespace's own loopback. The MCP route is on
                // loopback too and is not proxied; a client that sends it to the proxy is refused.
                let proxy = format!("http://127.0.0.1:{}", port.to_string_lossy());
                for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
                    c.arg("--setenv").arg(k).arg(&proxy);
                }
                for k in ["NO_PROXY", "no_proxy"] {
                    c.arg("--setenv").arg(k).arg("127.0.0.1,localhost");
                }
                // Node's fetch ignores the proxy variables without this.
                c.args(["--setenv", "NODE_USE_ENV_PROXY", "1"]);
            }
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
    // Starts the MCP and egress forwarders (when bwrap was given them) before the harness; they die
    // with the sandbox. Descriptors above 2 that the runner leaked are closed first, so a connected
    // socket inherited from the host is not reachable from inside.
    const FORWARDER: &str = "for f in /proc/$$/fd/*; do n=${f##*/}; [ \"$n\" -gt 2 ] 2>/dev/null && eval \"exec $n>&-\"; done; if [ -n \"$AINKRAD_MCP_FWD\" ]; then \"$AINKRAD_MCP_FWD\" mcp-forward \"$AINKRAD_MCP_PORT\" \"$AINKRAD_MCP_SOCK\" </dev/null >/dev/null 2>&1 & fi; if [ -n \"$AINKRAD_EGRESS_SOCK\" ]; then \"$AINKRAD_EGRESS_FWD\" mcp-forward \"$AINKRAD_EGRESS_PORT\" \"$AINKRAD_EGRESS_SOCK\" </dev/null >/dev/null 2>&1 & fi; ";
    let script = if cfg!(target_os = "macos") {
        "ulimit -S -u \"$1\" && ulimit -H -u \"$1\" && ulimit -S -t \"$2\" && ulimit -H -t \"$2\" && ulimit -S -f \"$3\" && ulimit -H -f \"$3\" || exit 125; shift 4; exec \"$@\""
    } else {
        "ulimit -S -u \"$1\" && ulimit -H -u \"$1\" && ulimit -S -t \"$2\" && ulimit -H -t \"$2\" && ulimit -S -f \"$3\" && ulimit -H -f \"$3\" && ulimit -S -v \"$4\" && ulimit -H -v \"$4\" || exit 125; shift 4; FORWARDER_HERE exec \"$@\""
    };
    let script = script.replace("FORWARDER_HERE ", FORWARDER);
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
        .args(["-c", script.as_str(), "ainkrad-sandbox"])
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
mod egress_tests;

#[cfg(test)]
mod orphan_tests;
