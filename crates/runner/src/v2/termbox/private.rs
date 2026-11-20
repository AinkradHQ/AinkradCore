//! The private-root sandbox (D-17, E6-1): a terminal opened with `PtyOpen::sandbox = home |
//! project:<id> | session:<id>` does not get the host's filesystem at all. Linux builds a root of
//! its own (bubblewrap); macOS denies everything by default (Seatbelt) and allows the same set.
//! The shell sees the system directories read-only, a fresh `/tmp` (macOS: its own scratch
//! directory, outside everything the shell can write but its own), the user's persistent sandbox
//! home (`<state>/sandbox/<user>`) writable and, only when requested and authorized, one project
//! or session folder.
//!
//! The launcher (bwrap, sandbox-exec) runs with a fixed clean environment: whatever a client
//! asked the shell to have reaches the shell only as `--setenv` (Linux) or `env K=V` (macOS), so
//! `LD_PRELOAD` and its relatives never load into the launcher, outside the sandbox.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{BWRAP, FORWARD_THEN_EXEC, Net, SANDBOX_EXEC, quote};

/// Read-only system directories of a private root (Linux: bound or, where the host has a
/// merged `/usr`, re-created as the same symlink).
const SYSTEM_DIRS: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc",
];

/// Where the sandbox home appears inside a Linux private root.
pub const BOX_HOME: &str = "/home/sandbox";

/// What a private root hides even inside the system directories it binds: the installer's runner
/// configuration (launch flags, `--terminal-hide`), on both OSes.
const ALWAYS_HIDDEN: &[&str] = &["/etc/ainkrad-runner", "/private/etc/ainkrad-runner"];

/// The environment the launcher itself runs with.
const LAUNCHER_PATH: &str = "/usr/bin:/bin";

/// A private-root shell, ready to start: the launcher line, the (clean) environment the launcher
/// itself gets, and the directory the shell starts in.
#[derive(Debug, PartialEq, Eq)]
pub struct Boxed {
    pub launcher: String,
    pub args: Vec<String>,
    /// For the launcher process: never the client's variables.
    pub env: Vec<(String, String)>,
    pub cwd: String,
}

/// `<base>/<user>`, created 0700 when missing: the user's persistent sandbox home. Refuses a bad
/// user name and any symlink in the way, and returns the canonical path, proven to be a direct
/// child of the canonical `base`.
pub fn sandbox_home(base: &Path, user: &str) -> Result<PathBuf, String> {
    if !ainkrad_proto::v2::valid_sandbox_user(user) {
        return Err(format!("{user:?} is not a valid sandbox user"));
    }
    private_dir(base)?;
    let base = base
        .canonicalize()
        .map_err(|e| format!("{}: {e}", base.display()))?;
    let home = base.join(user);
    private_dir(&home)?;
    let home = home
        .canonicalize()
        .map_err(|e| format!("{}: {e}", home.display()))?;
    if home.parent() != Some(base.as_path()) {
        return Err(format!("{}: escapes the sandbox directory", home.display()));
    }
    Ok(home)
}

/// `p`, created 0700 when missing; a symlink or a file in its place is refused.
fn private_dir(p: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_symlink() => {
            Err(format!("{}: is a symlink; refusing to use it", p.display()))
        }
        Ok(m) if !m.is_dir() => Err(format!("{}: is not a directory", p.display())),
        Ok(_) => Ok(()),
        Err(_) => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(p)
            .map_err(|e| format!("{}: {e}", p.display())),
    }
}

/// `<base>/.scratch/<user>/<terminal>`: a terminal's own scratch directory (macOS `TMPDIR`). It
/// lies beside the user's home, not in it, so nothing the shell can write decides where it is
/// made or removed; `base` is canonical.
pub fn scratch_dir(base: &Path, user: &str, terminal: &str) -> Result<PathBuf, String> {
    if !ainkrad_proto::v2::valid_sandbox_user(user) || !valid_terminal(terminal) {
        return Err("a scratch directory needs a plain user and terminal id".to_owned());
    }
    let root = base.join(".scratch");
    private_dir(&root)?;
    let u = root.join(user);
    private_dir(&u)?;
    let d = u.join(terminal);
    private_dir(&d)?;
    Ok(d)
}

/// Removes every `<base>/.scratch/<user>/<terminal>` whose terminal is not in `live` and that has
/// not been touched for a minute (a terminal still starting has no host yet). A symlinked
/// `.scratch` or user directory is skipped, and `remove_dir_all` (std, which works with
/// `openat`/`unlinkat` and never follows a link) removes a link inside as the link itself, so a
/// planted symlink cannot point the removal elsewhere.
pub fn reap_scratch(base: &Path, live: &std::collections::HashSet<String>) {
    let real_dir = |p: &Path| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    let old = |p: &Path| {
        std::fs::symlink_metadata(p)
            .and_then(|m| m.modified())
            .is_ok_and(|t| {
                t.elapsed()
                    .is_ok_and(|e| e > std::time::Duration::from_secs(60))
            })
    };
    let root = base.join(".scratch");
    if !real_dir(&root) {
        return;
    }
    for user in std::fs::read_dir(&root).into_iter().flatten().flatten() {
        let u = user.path();
        if !real_dir(&u) {
            continue;
        }
        for d in std::fs::read_dir(&u).into_iter().flatten().flatten() {
            let (p, name) = (d.path(), d.file_name().to_string_lossy().into_owned());
            if real_dir(&p) && !live.contains(&name) && old(&p) {
                let _ = std::fs::remove_dir_all(&p);
            }
        }
    }
}

fn valid_terminal(t: &str) -> bool {
    !t.is_empty()
        && t.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// The folder a private root may add (`project` / `session`), canonical and checked: a directory;
/// not `/`, not a system directory; not the sandbox directory, inside it (another user's home) or
/// holding it; and not holding a path the runner hides (its state, key, secrets) or the places a
/// launcher lives. `hidden` and `base` are canonical.
pub fn check_folder(folder: &Path, base: &Path, hidden: &[PathBuf]) -> Result<PathBuf, String> {
    let f = folder
        .canonicalize()
        .map_err(|e| format!("{}: {e}", folder.display()))?;
    if !f.is_dir() || f.parent().is_none() {
        return Err(format!("{}: not a usable folder", f.display()));
    }
    if SYSTEM_DIRS
        .iter()
        .chain(&["/proc", "/dev", "/sys"])
        .any(|d| f.starts_with(d))
        || (cfg!(target_os = "macos")
            && ["/System", "/Library", "/private/etc"]
                .iter()
                .any(|d| f.starts_with(d)))
    {
        return Err(format!("{}: is a system directory", f.display()));
    }
    if f.starts_with(base) || base.starts_with(&f) {
        return Err(format!("{}: overlaps the sandbox homes", f.display()));
    }
    if hidden.iter().any(|h| h.starts_with(&f)) {
        return Err(format!(
            "{}: holds a path the terminal sandbox hides; it is not mounted",
            f.display()
        ));
    }
    Ok(f)
}

/// Which directory a path was when it was checked: device and inode.
pub fn identity(p: &Path) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
    if !m.is_dir() {
        return Err(format!("{}: is not a directory", p.display()));
    }
    Ok((m.dev(), m.ino()))
}

/// The folder is still the one that was checked: the same path, not a link, the same directory.
/// Run right before the shell starts. A bind by path cannot be made atomic with this check (that
/// needs `bwrap --bind-fd`, and a descriptor cannot cross to the detached host), so a swap in
/// that last instant needs a writer to a parent directory of the folder; see the E6 threat note.
pub fn recheck_folder(f: &Path, was: (u64, u64)) -> Result<(), String> {
    if f.canonicalize().ok().as_deref() != Some(f) || identity(f)? != was {
        return Err(format!(
            "{}: changed while the terminal opened",
            f.display()
        ));
    }
    Ok(())
}

/// Whether `program` lies in a directory a private root provides.
fn provided(program: &str) -> bool {
    SYSTEM_DIRS
        .iter()
        .any(|d| Path::new(program).starts_with(d))
        || (cfg!(target_os = "macos")
            && ["/System", "/opt/homebrew", "/Library"]
                .iter()
                .any(|d| Path::new(program).starts_with(d)))
}

/// Everything [`wrap_private`] needs.
pub struct PrivateSpec<'a> {
    /// The canonical sandbox directory (`<state>/sandbox`) and the user whose home this is.
    pub base: &'a Path,
    pub user: &'a str,
    /// From [`sandbox_home`].
    pub home: &'a Path,
    /// From [`check_folder`], added when given.
    pub folder: Option<&'a Path>,
    pub program: &'a str,
    pub args: &'a [String],
    pub net: &'a Net,
    pub terminal: &'a str,
    /// The shell's whole environment. `HOME` (and macOS `TMPDIR`) are replaced here.
    pub env: &'a BTreeMap<String, String>,
    /// More paths to hide (`--terminal-hide`, the launcher directories), beside [`ALWAYS_HIDDEN`].
    pub hide: &'a [PathBuf],
    /// Heavy-job shims (E15-3): the directory of the shim links and the directory of this
    /// terminal's job socket (`job.sock`). Both are readable and read-only; the socket connects.
    pub jobs: Option<(&'a Path, &'a Path)>,
}

/// `program args` in a private root: `home` writable and `folder` added when given. `cwd` is the
/// folder, else the home. Fails closed on a program the root does not provide, or a path that is
/// not absolute.
pub fn wrap_private(p: &PrivateSpec) -> Result<Boxed, String> {
    let (home, folder, program, args, net) = (p.home, p.folder, p.program, p.args, p.net);
    if !valid_terminal(p.terminal) {
        return Err("a terminal id is letters, digits, _ and -".to_owned());
    }
    if !program.starts_with('/') || program.contains("/../") || program.ends_with("/..") {
        return Err("a terminal program must be an absolute path".to_owned());
    }
    if !provided(program) {
        return Err(format!(
            "{program}: is not in the sandbox's system directories"
        ));
    }
    let h = |p: &Path| p.to_string_lossy().into_owned();
    let launch_env = vec![("PATH".to_owned(), LAUNCHER_PATH.to_owned())];
    let mut env = p.env.clone();
    env.insert("HOME".to_owned(), BOX_HOME.to_owned());
    let hidden: Vec<PathBuf> = ALWAYS_HIDDEN
        .iter()
        .map(PathBuf::from)
        .chain(p.hide.iter().cloned())
        .collect();
    if cfg!(target_os = "macos") {
        if matches!(net, Net::Filtered { .. }) {
            return Err("a filtered terminal network is Linux only".to_owned());
        }
        let scratch = scratch_dir(p.base, p.user, p.terminal)?;
        env.insert("HOME".to_owned(), h(home));
        env.insert("TMPDIR".to_owned(), h(&scratch));
        let mut profile = seatbelt_profile(home, folder, &scratch, net, &hidden);
        if let Some((bin, sock_dir)) = p.jobs {
            profile.push_str(&jobs_rules(bin, sock_dir));
        }
        let mut out = vec!["-p".to_owned(), profile, "--".to_owned()];
        // The shell's variables travel in `sandbox-exec`'s own environment, never its argv (a
        // process listing shows every argument): it is a SIP platform binary, which drops
        // `DYLD_*`, and the API already refuses loader variables.
        out.push(program.to_owned());
        out.extend(args.iter().cloned());
        return Ok(Boxed {
            launcher: SANDBOX_EXEC.to_owned(),
            args: out,
            env: env.into_iter().collect(),
            cwd: h(folder.unwrap_or(home)),
        });
    }
    let mut out: Vec<String> = [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--die-with-parent",
        "--cap-drop",
        "ALL",
        "--disable-userns",
        "--clearenv",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
    ]
    .map(str::to_owned)
    .to_vec();
    if *net != Net::Host {
        out.push("--unshare-net".to_owned());
    }
    for d in SYSTEM_DIRS {
        match std::fs::read_link(d) {
            Ok(t) => out.extend(["--symlink".to_owned(), h(&t), (*d).to_owned()]),
            Err(_) if Path::new(d).is_dir() => {
                out.extend(["--ro-bind".to_owned(), (*d).to_owned(), (*d).to_owned()]);
            }
            Err(_) => {}
        }
    }
    // Over what /etc brought in: the runner's configuration and anything else to hide.
    for x in &hidden {
        if SYSTEM_DIRS.iter().any(|d| x.starts_with(d)) {
            if x.is_dir() {
                out.extend(["--tmpfs".to_owned(), h(x)]);
            } else if x.exists() {
                out.extend(["--ro-bind".to_owned(), "/dev/null".to_owned(), h(x)]);
            }
        }
    }
    // /etc/resolv.conf is a link into here on systemd-resolved hosts: names would not resolve.
    if *net == Net::Host && Path::new("/run/systemd/resolve").is_dir() {
        out.extend(
            ["--ro-bind", "/run/systemd/resolve", "/run/systemd/resolve"].map(str::to_owned),
        );
    }
    out.extend(["--bind".to_owned(), h(home), BOX_HOME.to_owned()]);
    let cwd = match folder {
        Some(f) => {
            out.extend(["--bind".to_owned(), h(f), h(f)]);
            h(f)
        }
        None => BOX_HOME.to_owned(),
    };
    if let Some((bin, sock_dir)) = p.jobs {
        for d in [bin, sock_dir] {
            out.extend(["--ro-bind".to_owned(), h(d), h(d)]);
        }
    }
    for (k, v) in &env {
        out.extend(["--setenv".to_owned(), k.clone(), v.clone()]);
    }
    if let Net::Filtered { dir, exe } = net {
        let dir = dir
            .canonicalize()
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        let exe = exe
            .canonicalize()
            .map_err(|e| format!("{}: {e}", exe.display()))?;
        let sock = crate::egress::socket_in(&dir);
        out.extend(["--ro-bind".to_owned(), h(&dir), h(&dir)]);
        out.extend(["--ro-bind".to_owned(), h(&exe), h(&exe)]);
        let proxy = format!("http://127.0.0.1:{}", crate::egress::EGRESS_PORT);
        for k in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
            out.extend(["--setenv".to_owned(), k.to_owned(), proxy.clone()]);
        }
        for k in ["NO_PROXY", "no_proxy"] {
            out.extend([
                "--setenv".to_owned(),
                k.to_owned(),
                "127.0.0.1,localhost".to_owned(),
            ]);
        }
        out.extend(["--chdir".to_owned(), cwd.clone(), "--".to_owned()]);
        out.extend(["/bin/sh", "-c", FORWARD_THEN_EXEC, "ainkrad-terminal"].map(str::to_owned));
        out.extend([h(&exe), crate::egress::EGRESS_PORT.to_string(), h(&sock)]);
    } else {
        out.extend(["--chdir".to_owned(), cwd.clone(), "--".to_owned()]);
    }
    out.push(program.to_owned());
    out.extend(args.iter().cloned());
    Ok(Boxed {
        launcher: BWRAP.to_owned(),
        args: out,
        env: launch_env,
        cwd,
    })
}

/// The Seatbelt profile of a private root: everything denied, then exactly what a shell needs.
/// Tried against a real `sandbox-exec` run (curl over TLS, the shell on a pty, the pasteboard and
/// the process-argument sysctl refused). Pure, so its shape is tested on every OS.
pub fn seatbelt_profile(
    home: &Path,
    folder: Option<&Path>,
    scratch: &Path,
    net: &Net,
    hidden: &[PathBuf],
) -> String {
    let mut p = String::from(concat!(
        "(version 1)\n(deny default)\n(allow process-fork)\n(allow process-exec)\n",
        "(allow signal (target self))\n",
        // Only what a shell and its tools read: sizes, versions, the CPU. Not `kern.procargs2`,
        // not `kern.proc.*`, so no other process's arguments or environment.
        "(allow sysctl-read (sysctl-name \"hw.ncpu\" \"hw.activecpu\" \"hw.logicalcpu\" \"hw.physicalcpu\" \"hw.memsize\" \"hw.pagesize\" \"hw.machine\" \"hw.model\" \"hw.byteorder\" \"hw.cputype\" \"hw.cpusubtype\" \"hw.cpufamily\" \"hw.tbfrequency\" \"hw.packages\" \"hw.cachelinesize\" \"hw.l1dcachesize\" \"hw.l2cachesize\" \"kern.ostype\" \"kern.osrelease\" \"kern.osversion\" \"kern.osproductversion\" \"kern.hostname\" \"kern.boottime\" \"kern.maxfilesperproc\" \"kern.argmax\" \"kern.ngroups\" \"kern.usrstack64\" \"kern.hv_vmm_present\" \"kern.monotonicclock\" \"vm.loadavg\" \"sysctl.proc_native\" \"machdep.cpu.brand_string\") (sysctl-name-prefix \"hw.optional.\") (sysctl-name-prefix \"hw.perflevel\"))\n",
        // Named services only: accounts, logging, preferences, names and TLS. No pasteboard, no
        // launch services, no launchd domain.
        "(allow mach-lookup (global-name \"com.apple.system.opendirectoryd.libinfo\") (global-name \"com.apple.system.notification_center\") (global-name \"com.apple.logd\") (global-name \"com.apple.system.logger\") (global-name \"com.apple.cfprefsd.daemon\") (global-name \"com.apple.cfprefsd.agent\") (global-name \"com.apple.bsd.dirhelper\") (global-name \"com.apple.dnssd.service\") (global-name \"com.apple.mDNSResponder\") (global-name \"com.apple.SystemConfiguration.configd\") (global-name \"com.apple.SystemConfiguration.DNSConfiguration\") (global-name \"com.apple.trustd\") (global-name \"com.apple.trustd.agent\") (global-name \"com.apple.securityd.xpc\"))\n",
        "(allow ipc-posix-shm-read* ipc-posix-shm-write-data)\n(allow pseudo-tty)\n",
        "(allow file-read* (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/System\") (subpath \"/Library\") (subpath \"/opt/homebrew\") (subpath \"/private/etc\") (subpath \"/private/var/db\") (subpath \"/private/var/select\") (literal \"/\"))\n",
        "(allow file-read-metadata (literal \"/etc\") (literal \"/var\") (literal \"/tmp\") (literal \"/private\"))\n",
        // The devices a shell opens by name, nothing else under /dev: not another terminal's
        // `ttysNNN`, not the disks. Its own tty is already open; ioctl on it is allowed.
        "(allow file-read* file-write* (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\") (literal \"/dev/urandom\") (literal \"/dev/tty\") (subpath \"/dev/fd\"))\n",
        "(allow file-ioctl (regex #\"^/dev/ttys[0-9]+$\") (literal \"/dev/tty\"))\n",
    ));
    // Hidden first: Seatbelt's last matching rule wins, so the home, the scratch and the session's
    // folder (which lies inside the hidden state) are let in again by the allows that follow.
    for x in hidden {
        let q = quote(x);
        p.push_str(&format!(
            "(deny file-read* file-write* (subpath \"{q}\"))\n"
        ));
    }
    let mut open: Vec<PathBuf> = vec![home.to_owned(), scratch.to_owned()];
    open.extend(folder.map(Path::to_owned));
    // Seatbelt matches the resolved path: a folder reached through a symlink (`/var` is
    // `/private/var`) needs its real path, and that path's parents, let in as well.
    let real: Vec<PathBuf> = open
        .iter()
        .filter_map(|d| d.canonicalize().ok())
        .filter(|r| !open.contains(r))
        .collect();
    open.extend(real);
    for d in &open {
        p.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{}\"))\n",
            quote(d)
        ));
        // Shells and git stat the parents on the way up; stat only, no listing.
        for a in d.ancestors().skip(1) {
            p.push_str(&format!(
                "(allow file-read-metadata (literal \"{}\"))\n",
                quote(a)
            ));
        }
    }
    // The launch tools and launchd's XPC domain stay shut, as in the host-view sandbox.
    p.push_str("(deny process-exec (literal \"/bin/launchctl\") (literal \"/usr/bin/osascript\") (literal \"/usr/bin/open\") (literal \"/usr/bin/at\") (literal \"/usr/bin/crontab\"))\n");
    if *net == Net::Host {
        // Over the network by IP, and over no unix socket but the name service's: the host's own services on `localhost` are out of reach. Link-local
        // ranges cannot be named in Seatbelt; macOS hosts have no metadata service there.
        p.push_str("(allow network-outbound (remote ip \"*:*\") (literal \"/private/var/run/mDNSResponder\"))\n(allow network-bind (local ip \"*:*\"))\n(allow network-inbound (local ip \"*:*\"))\n(deny network-outbound (remote ip \"localhost:*\"))\n(deny network-inbound (local ip \"localhost:*\"))\n");
    }
    p
}

/// Seatbelt rules for the heavy-job shims: read the shim directory and the socket's, and connect to
/// `job.sock` only. Appended last, so they win over the hidden state they lie in.
fn jobs_rules(bin: &Path, sock_dir: &Path) -> String {
    let real = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_owned());
    let (bin, dir) = (real(bin), real(sock_dir));
    let mut r = format!(
        "(allow file-read* (subpath \"{}\") (subpath \"{}\"))\n(allow network-outbound (literal \"{}\"))\n",
        quote(&bin),
        quote(&dir),
        quote(&dir.join("job.sock"))
    );
    for a in bin.ancestors().skip(1).chain(dir.ancestors().skip(1)) {
        r.push_str(&format!("(allow file-read-metadata (literal \"{}\"))\n", quote(a)));
    }
    r
}

/// `env K=V…` for a command a host-view launcher starts, with the launcher itself left clean: on
/// Linux each variable becomes a `--setenv` before `--chdir`, on macOS the program is run through
/// `/usr/bin/env` after `--`. Returns the argv unchanged when there is nothing to set.
pub fn inject_env(args: &mut Vec<String>, env: &BTreeMap<String, String>) {
    // macOS: the variables stay in `sandbox-exec`'s own environment (see `wrap_private`).
    if cfg!(target_os = "macos") || env.is_empty() {
        return;
    }
    if let Some(at) = args.iter().position(|a| a == "--chdir") {
        let ins: Vec<String> = env
            .iter()
            .flat_map(|(k, v)| ["--setenv".to_owned(), k.clone(), v.clone()])
            .collect();
        args.splice(at..at, ins);
    }
}

/// Moves every `--setenv K V` of bubblewrap's argv into the bytes of a pipe, so no variable (a
/// terminal's secret) is in the process listing: `/proc/<pid>/cmdline` is world-readable, a pipe is
/// not. The first one is replaced by `--args 3` (bubblewrap reads its options from descriptor 3
/// there, in order, so `--clearenv` still comes first). The bytes are NUL-terminated arguments;
/// `None` when there is nothing to move or the launcher is not bubblewrap (macOS: `sandbox-exec`
/// has no such option, its variables travel in its environment). The caller hands them to the host
/// as `Spec::fd3`.
pub fn setenv_to_fd(args: &mut Vec<String>) -> Option<Vec<u8>> {
    if cfg!(target_os = "macos") {
        return None;
    }
    // Only bubblewrap's own options: what follows the first `--` is the program and its
    // arguments, where a `--setenv K V` is just text.
    let end = args.iter().position(|a| a == "--").unwrap_or(args.len());
    let first = args[..end].iter().position(|a| a == "--setenv")?;
    let mut bytes = Vec::new();
    let mut kept = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        if i < end && args[i] == "--setenv" && i + 2 < end {
            for a in &args[i..i + 3] {
                bytes.extend_from_slice(a.as_bytes());
                bytes.push(0);
            }
            if i == first {
                kept.push("--args".to_owned());
                kept.push("3".to_owned());
            }
            i += 3;
        } else {
            kept.push(args[i].clone());
            i += 1;
        }
    }
    *args = kept;
    Some(bytes)
}

/// The environment a host-view launcher gets itself.
pub fn launcher_env() -> BTreeMap<String, String> {
    BTreeMap::from([("PATH".to_owned(), LAUNCHER_PATH.to_owned())])
}
