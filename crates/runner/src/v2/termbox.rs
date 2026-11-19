//! A sandbox for terminal shells (final review A, H1).
//!
//! A `terminal` device gets a shell as the runner's own user, which could otherwise read the
//! runner's key, the secrets delivered to agent sessions, the harness logins and the other
//! terminals' host sockets. The shell is run through the same mechanisms as agents (Linux:
//! bubblewrap; macOS: Seatbelt) but the host filesystem stays usable: only the runner's own
//! private paths are hidden. On Linux the shell also gets its own PID namespace and `/proc`,
//! so the runner's process (and `/proc/<pid>/environ`) is not visible to it.
//!
//! Fail closed: the runner refuses to start with terminals on when the sandbox cannot run
//! ([`probe`]); `--terminal-sandbox=off` is the one explicit, loudly logged way to run
//! unsandboxed shells, for hosts where the `terminal` scope is trusted as admin.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BWRAP: &str = "/usr/bin/bwrap";
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The paths of this runner a shell must not reach: its state (key, terminal sockets, agent
/// sessions, harness config), the harness logins, delivered secrets and the agents' work root,
/// plus `extra` (`--terminal-hide`: for example the state dir of a co-located Core, whose admin
/// socket is a bootstrap path).
pub fn hidden_paths(state: &Path, extra: &[PathBuf]) -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut v = vec![state.to_path_buf()];
    v.extend(home.map(|h| h.join(".ainkrad-runner")));
    v.extend(super::cli::runtime_paths(state));
    // The terminals' scrollback (output only, 0600): inside the state dir, so already hidden;
    // named on its own so it stays hidden if the terminal directory ever moves.
    v.push(ainkrad_ptyhost::host::scrollback_dir(
        &state.join("terminals"),
    ));
    v.extend(extra.iter().cloned());
    v
}

/// What a shell may read but not change: the runner binary, its pty host, and the places a
/// launcher lives (systemd user units, launchd agents). Otherwise the same uid could edit how
/// the runner starts (for example adding `--terminal-sandbox=off`) and wait for a restart.
pub fn readonly_paths(host: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::env::current_exe().into_iter().collect();
    v.push(host.to_path_buf());
    // The Ainkrad shell profile (N20): a shell reads it, and cannot change what every later shell starts with.
    let shell = Path::new(super::pty::SHELL_DIR);
    if shell.is_dir() {
        v.push(shell.to_path_buf());
    }
    for d in launcher_dirs() {
        // Created if missing, so the shell cannot plant a unit or agent in a dir that did not
        // exist yet; read-only inside the sandbox from then on.
        let _ = std::fs::create_dir_all(&d);
        v.push(d);
    }
    v
}

/// Where a login-time launcher could be planted for the user.
fn launcher_dirs() -> Vec<PathBuf> {
    let Some(h) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let mut v = vec![
        h.join(".config/systemd/user"),
        h.join(".local/share/systemd/user"),
        h.join(".config/autostart"),
    ];
    if cfg!(target_os = "macos") {
        v.push(h.join("Library/LaunchAgents"));
    }
    v
}

/// Paths hidden when present, never created: a co-located Core's default state dir (its
/// `admin.sock` and `core.sock` are bootstrap paths) and a relay's. A Core in another place is
/// hidden with `--terminal-hide`, or better run as another user.
pub const CORE_STATE_DIRS: &[&str] =
    &["/var/lib/ainkrad", "/var/lib/ainkrad-relay", "/run/ainkrad"];

/// Creates each hidden path that is missing (mode 0700, owned by the runner), so that it
/// exists, and is therefore hidden, before any shell starts: the agents' work root is otherwise
/// created lazily and a shell opened earlier would see it appear.
pub fn prepare(hidden: &[PathBuf]) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    for p in hidden {
        if std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(format!(
                "{}: is a symlink; refusing to hide through it",
                p.display()
            ));
        }
        if !p.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(p)
                .map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    Ok(())
}

fn canonical(paths: &[PathBuf], required: bool) -> Result<Vec<PathBuf>, String> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in paths {
        match p.canonicalize() {
            Ok(c) => {
                if !out.contains(&c) {
                    out.push(c);
                }
            }
            Err(e) if required => return Err(format!("{}: {e}", p.display())),
            Err(_) => {}
        }
    }
    // Parents before children, so a nested overlay lands on top.
    out.sort_by_key(|p| p.components().count());
    Ok(out)
}

fn quote(p: &Path) -> String {
    p.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// A bare program name (`sh`, `htop`) looked up on the shell's `PATH`, as the unsandboxed host
/// would, so [`wrap`] gets the absolute path it requires. Anything else (an absolute or relative
/// path, a name that could be an option) is returned unchanged for [`wrap`] to judge.
pub fn resolve(program: &str, path: Option<&str>) -> String {
    use std::os::unix::fs::PermissionsExt;
    if program.is_empty() || program.contains('/') || program.starts_with('-') {
        return program.to_owned();
    }
    path.unwrap_or_default()
        .split(':')
        .filter(|d| d.starts_with('/'))
        .map(|d| Path::new(d).join(program))
        .find(|p| {
            std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
        .map_or_else(|| program.to_owned(), |p| p.to_string_lossy().into_owned())
}

/// The network of a terminal shell (KAN-416, `--terminal-network`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Net {
    /// The host's network, unfiltered: the accepted scope of an admin-equivalent `terminal`.
    #[default]
    Host,
    /// A network namespace of its own with no interface (Linux: bubblewrap `--unshare-net`;
    /// macOS: Seatbelt `deny network*`). Also closes the host's abstract unix sockets.
    None,
    /// Linux only: no interface either, but `HTTPS_PROXY` reaches the runner's egress proxy
    /// (the one agent sessions use, same allow policy) through the unix socket in `dir`.
    Filtered { dir: PathBuf, exe: PathBuf },
}

impl Net {
    /// The mode's name, as `--terminal-network` and the per-shell record spell it.
    pub fn name(&self) -> &'static str {
        match self {
            Net::Host => "host",
            Net::None => "none",
            Net::Filtered { .. } => "filtered",
        }
    }

    /// How much a shell of the mode can reach, least first: `host` 0, `filtered` 1, `none` 2.
    /// An unknown name is 0 (fail closed: it counts as the weakest).
    pub fn strength(name: &str) -> u8 {
        match name {
            "none" => 2,
            "filtered" => 1,
            _ => 0,
        }
    }

    /// The mode named by `--terminal-network`, `Filtered` needing its socket dir and the runner binary.
    pub fn parse(mode: &str, dir: PathBuf, exe: PathBuf) -> Option<Net> {
        match mode {
            "host" => Some(Net::Host),
            "none" => Some(Net::None),
            "filtered" => Some(Net::Filtered { dir, exe }),
            _ => None,
        }
    }
}

/// Runs the in-namespace forwarder (`mcp-forward <port> <sock>`) in the background, then the shell.
const FORWARD_THEN_EXEC: &str =
    "\"$1\" mcp-forward \"$2\" \"$3\" </dev/null >/dev/null 2>&1 & shift 3; exec \"$@\"";

/// [`wrap_net`] on the host network.
pub fn wrap(
    hidden: &[PathBuf],
    readonly: &[PathBuf],
    program: &str,
    args: &[String],
    cwd: &str,
) -> Result<(String, Vec<String>), String> {
    wrap_net(hidden, readonly, program, args, cwd, &Net::Host)
}

/// `program args` run with `hidden` unreadable and `readonly` unwritable, on `net`: the command
/// line to start instead. Fails closed: an absent hidden path, or a `program` that is not an
/// absolute path (a leading `-` would be read as an option of the launcher, replacing its profile),
/// or a filtered network on a host that is not Linux.
pub fn wrap_net(
    hidden: &[PathBuf],
    readonly: &[PathBuf],
    program: &str,
    args: &[String],
    cwd: &str,
    net: &Net,
) -> Result<(String, Vec<String>), String> {
    wrap_in(hidden, readonly, program, args, cwd, net, None)
}

/// [`wrap_net`], with `reveal` (an AI session's folder, which the runner checked is one it
/// recorded) readable and writable although it lies in a hidden path. Only that folder comes back:
/// its hidden parents stay unreadable (macOS lets the shell stat them, which git needs), and a
/// folder that holds a hidden path is refused, since revealing it would un-hide that path too.
pub fn wrap_in(
    hidden: &[PathBuf],
    readonly: &[PathBuf],
    program: &str,
    args: &[String],
    cwd: &str,
    net: &Net,
    reveal: Option<&Path>,
) -> Result<(String, Vec<String>), String> {
    if !program.starts_with('/') {
        // A bare name [`resolve`] could not find: say that, not a rule it did not break.
        let bare = !program.is_empty() && !program.contains('/') && !program.starts_with('-');
        return Err(if bare {
            format!("{program:?} was not found on the terminal's PATH (give an absolute path)")
        } else {
            "a terminal program must be an absolute path".to_owned()
        });
    }
    if matches!(net, Net::Filtered { .. }) && cfg!(target_os = "macos") {
        return Err("a filtered terminal network is Linux only".to_owned());
    }
    prepare(hidden)?;
    let mut hidden = canonical(hidden, true)?;
    hidden.extend(canonical(
        &CORE_STATE_DIRS
            .iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>(),
        false,
    )?);
    let readonly = canonical(readonly, false)?;
    let reveal = reveal
        .map(|f| {
            f.canonicalize()
                .map_err(|e| format!("{}: {e}", f.display()))
        })
        .transpose()?;
    let holds = |paths: &[PathBuf]| match &reveal {
        Some(f) if paths.iter().any(|h| h.starts_with(f)) => Err(format!(
            "{}: holds a path the terminal sandbox hides; it is not revealed",
            f.display()
        )),
        _ => Ok(()),
    };
    holds(&hidden)?;
    let mut out: Vec<String> = Vec::new();
    let launcher = if cfg!(target_os = "macos") {
        // Everything is allowed but the hidden paths (files and unix sockets alike), writes to
        // the read-only ones, inspecting other processes (so no `ps eww` of their environment),
        // their task ports, the launch tools and launchd's XPC domain (no `launchctl submit`).
        // Not denied: signalling other processes, which Seatbelt cannot separate from the
        // shell's own jobs, and launching through a copied or scripted client of services
        // other than launchd (residual, see the security posture runbook).
        let mut profile = String::from(
            "(version 1)\n(allow default)\n(deny mach-priv-task-port)\n(deny process-info* (target others))\n(deny process-exec (literal \"/bin/launchctl\") (literal \"/usr/bin/osascript\") (literal \"/usr/bin/open\") (literal \"/usr/bin/at\") (literal \"/usr/bin/crontab\"))\n(deny mach-lookup (global-name-prefix \"com.apple.xpc.launchd.domain\"))\n",
        );
        if *net != Net::Host {
            // `deny network*` closes sockets of every kind, unix ones included. The services a
            // process could still ask over Mach (name resolution, URL loading, the network
            // extension and configuration daemons) are refused by name; Seatbelt cannot list
            // every service, so a copied client of one this does not name is residual (best
            // effort, see the sandbox residual-risk spec).
            profile.push_str("(deny network*)\n(deny mach-lookup (global-name \"com.apple.dnssd.service\") (global-name-prefix \"com.apple.mDNSResponder\") (global-name-prefix \"com.apple.lsd\") (global-name-prefix \"com.apple.coreservices.launchservicesd\") (global-name \"com.apple.nsurlsessiond\") (global-name-prefix \"com.apple.networkd\") (global-name-prefix \"com.apple.nehelper\") (global-name-prefix \"com.apple.networkserviceproxy\") (global-name-prefix \"com.apple.SystemConfiguration\") (global-name-prefix \"com.apple.symptoms\"))\n");
        }
        for p in &hidden {
            let q = quote(p);
            profile.push_str(&format!(
                "(deny file-read* file-write* (subpath \"{q}\"))\n(deny network-outbound (remote unix-socket (subpath \"{q}\")))\n"
            ));
        }
        if let Some(f) = &reveal {
            // The last matching rule wins: the folder is open again, and its parents can be
            // stat'ed (not listed or read): git walks up them looking for a repository.
            profile.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{}\"))\n",
                quote(f)
            ));
            for a in f.ancestors().skip(1) {
                profile.push_str(&format!(
                    "(allow file-read-metadata (literal \"{}\"))\n",
                    quote(a)
                ));
            }
        }
        for p in &readonly {
            profile.push_str(&format!("(deny file-write* (subpath \"{}\"))\n", quote(p)));
        }
        out.extend(["-p".to_owned(), profile, "--".to_owned()]);
        SANDBOX_EXEC
    } else {
        out.extend(
            [
                "--bind",
                "/",
                "/",
                // In the user namespace the host's device nodes cannot be opened (`sh: cannot
                // open /dev/null`, so no `cmd &`); a minimal /dev of its own, as for agents.
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--unshare-user",
                "--unshare-pid",
                "--die-with-parent",
                "--cap-drop",
                "ALL",
                // No nested user namespace: with the runner unit allowing `user`, a shell could
                // otherwise `unshare -Urn` and reach nf_tables/overlayfs (as the agent sandbox does).
                "--disable-userns",
            ]
            .map(str::to_owned),
        );
        if *net != Net::Host {
            out.push("--unshare-net".to_owned());
        }
        // The user's systemd and D-Bus sockets (`systemd-run --user` starts a process outside
        // this sandbox) live in the runtime dir.
        let mut tmpfs = hidden.clone();
        if let Ok(uid) =
            std::fs::metadata("/proc/self").map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        {
            tmpfs.extend(canonical(
                &[PathBuf::from(format!("/run/user/{uid}"))],
                false,
            )?);
        }
        if *net != Net::Host {
            // `--unshare-net` closes the abstract and the network sockets, not the unix sockets
            // that live in the shared filesystem (D-Bus and resolved in /run, docker.sock, tmux
            // and ssh ControlMaster/agent sockets in /tmp, the user's ssh and gpg dirs): a shell
            // on a locked network gets an empty /tmp and /run over them (KAN-416).
            let mut shared: Vec<PathBuf> = SOCKET_DIRS.iter().map(PathBuf::from).collect();
            if let Some(h) = std::env::var_os("HOME").map(PathBuf::from) {
                shared.extend([".ssh", ".gnupg", ".docker"].map(|d| h.join(d)));
            }
            tmpfs.extend(canonical(&shared, false)?);
        }
        tmpfs.sort_by_key(|p| p.components().count());
        tmpfs.dedup();
        holds(&tmpfs)?;
        for p in &tmpfs {
            let p = p.to_string_lossy().into_owned();
            if Path::new(&p).is_dir() {
                out.extend(["--tmpfs".to_owned(), p]);
            } else {
                out.extend(["--ro-bind".to_owned(), "/dev/null".to_owned(), p]);
            }
        }
        if let Some(f) = &reveal {
            // Bound back from the host over the emptied state (bubblewrap creates the mount
            // point in the tmpfs); after every tmpfs, before the read-only binds.
            let f = f.to_string_lossy().into_owned();
            out.extend(["--bind".to_owned(), f.clone(), f]);
        }
        for p in &readonly {
            let p = p.to_string_lossy().into_owned();
            out.extend(["--ro-bind".to_owned(), p.clone(), p]);
        }
        if let Net::Filtered { dir, exe } = net {
            // The socket dir comes back over the hidden state dir (a dir, so a proxy restarted
            // after a runner restart is still reached through the same mount).
            let dir = dir
                .canonicalize()
                .map_err(|e| format!("{}: {e}", dir.display()))?;
            let (d, sock) = (
                dir.to_string_lossy().into_owned(),
                crate::egress::socket_in(&dir),
            );
            // Read-only: a shell can connect to the socket but not remove, move or rebind it (that
            // would cut or intercept the other terminals' tunnels).
            out.extend(["--ro-bind".to_owned(), d.clone(), d]);
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
            out.extend(["--chdir".to_owned(), cwd.to_owned(), "--".to_owned()]);
            out.extend(["/bin/sh", "-c", FORWARD_THEN_EXEC, "ainkrad-terminal"].map(str::to_owned));
            out.extend([
                exe.to_string_lossy().into_owned(),
                crate::egress::EGRESS_PORT.to_string(),
                sock.to_string_lossy().into_owned(),
            ]);
        } else {
            out.extend(["--chdir".to_owned(), cwd.to_owned(), "--".to_owned()]);
        }
        BWRAP
    };
    out.push(program.to_owned());
    out.extend(args.iter().cloned());
    Ok((launcher.to_owned(), out))
}

/// Directories of the host's path-socket services, emptied in a shell on a locked network.
const SOCKET_DIRS: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/run",
    "/var/run",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/var/lib/snapd",
];

const SUDO: &str = "/usr/bin/sudo";

/// `[a-z_][a-z0-9_-]{0,31}`: an account name that cannot be an option, a path or a second
/// argument to `sudo`.
pub fn valid_user(name: &str) -> bool {
    let b = name.as_bytes();
    (1..=32).contains(&b.len())
        && (b[0].is_ascii_lowercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(c))
}

/// `program args` run as `user` through `sudo -n` (E2-25, `--terminal-user`): the shell, and
/// the sandbox wrapper around it, get another uid than the runner's. There is no fallback: when
/// `sudo` refuses, the terminal fails to start; it is never started as the runner's own user.
pub fn as_user(user: &str, program: String, args: Vec<String>) -> (String, Vec<String>) {
    let mut out = ["-n", "-u", user, "--"].map(str::to_owned).to_vec();
    out.push(program);
    out.extend(args);
    (SUDO.to_owned(), out)
}

/// The numeric uid of account `name` (`id -u`), `None` when there is no such account.
fn uid_of(name: &str) -> Option<u32> {
    let out = Command::new("/usr/bin/id")
        .args(["-u", "--", name])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().parse().ok())
        .flatten()
}

/// The runner's state dir (its key, delivered secrets) must be closed to every other account:
/// a mode with group or other bits (the umask decides it when the dir is first created) is
/// made 0700, and a dir the runner's user does not own is refused.
pub fn private_state(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if m.uid() != ainkrad_sys::getuid() {
        return Err(format!(
            "{} is not owned by the runner's user",
            dir.display()
        ));
    }
    if m.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(())
}

/// Whether shells can run as `user` here, tried for real: the account exists and is neither root
/// nor the runner's own uid (that would be no separation at all), and `sudo -n` runs a program
/// as it (through the sandbox wrapper when `sandbox`). The error says what the owner must set up.
pub fn probe_user(user: &str, sandbox: bool, net: &Net) -> Result<(), String> {
    if !valid_user(user) {
        return Err(format!("{user:?} is not a valid account name"));
    }
    let uid = uid_of(user).ok_or_else(|| format!("there is no account {user:?} on this host"))?;
    if uid == 0 || uid == ainkrad_sys::getuid() {
        return Err(format!(
            "{user:?} is {} and gives the shells no separation",
            if uid == 0 {
                "root"
            } else {
                "the runner's own user"
            }
        ));
    }
    let (program, args) = if sandbox {
        wrap_net(&[], &[], "/usr/bin/true", &[], "/", &probe_net(net))?
    } else {
        ("/usr/bin/true".to_owned(), Vec::new())
    };
    let (sudo, args) = as_user(user, program, args);
    let ok = Command::new(&sudo)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if ok {
        Ok(())
    } else {
        Err(format!(
            "this runner cannot run a program as {user} with `sudo -n` (a sudoers rule without a \
             password, for the sandbox launcher and /usr/bin/true, is required); terminals are \
             not offered"
        ))
    }
}

/// What a start-up probe tries: a filtered network needs the same namespace as `none` (the
/// proxy path is proven by the egress self-test).
fn probe_net(net: &Net) -> Net {
    match net {
        Net::Host => Net::Host,
        _ => Net::None,
    }
}

/// Whether the sandbox runs here, tried for real (a disabled user namespace shows only then).
pub fn probe(net: &Net) -> Result<(), String> {
    let (program, args) = wrap_net(&[], &[], "/usr/bin/true", &[], "/", &probe_net(net))?;
    let ok = Command::new(&program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if ok {
        Ok(())
    } else {
        Err(format!(
            "the terminal sandbox cannot run ({program} failed); install it, or start with --terminal-sandbox=off to run shells unsandboxed"
        ))
    }
}

// ---- D-17: the private-root sandbox (E6-1) -------------------------------------------------
//
// A terminal opened with `PtyOpen::sandbox = home | project:<id> | session:<id>` does not get the
// host's filesystem at all: Linux builds a root of its own (bubblewrap), macOS denies everything
// by default (Seatbelt) and allows the same set. What the shell sees: the system directories
// read-only, a fresh `/tmp`, the user's persistent sandbox home (`<state>/sandbox/<user>`)
// writable, and, only when requested and authorized, one project or session folder.

/// Read-only system directories of a private root (Linux: bound or, where the host has a
/// merged `/usr`, re-created as the same symlink).
const SYSTEM_DIRS: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/etc",
];

/// Where the sandbox home appears inside a Linux private root.
pub const BOX_HOME: &str = "/home/sandbox";

/// A private-root shell, ready to start: the launcher line, the variables to set in the shell's
/// environment (`HOME`, and on macOS `TMPDIR`) and the directory it starts in.
#[derive(Debug, PartialEq, Eq)]
pub struct Boxed {
    pub launcher: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: String,
}

/// `<base>/<user>`, created 0700 when missing: the user's persistent sandbox home. Refuses a bad
/// user name and any symlink in the way, and returns the canonical path, proven to be a direct
/// child of the canonical `base`.
pub fn sandbox_home(base: &Path, user: &str) -> Result<PathBuf, String> {
    use std::os::unix::fs::DirBuilderExt;
    if !ainkrad_proto::v2::valid_sandbox_user(user) {
        return Err(format!("{user:?} is not a valid sandbox user"));
    }
    let mk = |p: &Path| -> Result<(), String> {
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
    };
    mk(base)?;
    let base = base
        .canonicalize()
        .map_err(|e| format!("{}: {e}", base.display()))?;
    let home = base.join(user);
    mk(&home)?;
    let home = home
        .canonicalize()
        .map_err(|e| format!("{}: {e}", home.display()))?;
    if home.parent() != Some(base.as_path()) {
        return Err(format!("{}: escapes the sandbox directory", home.display()));
    }
    Ok(home)
}

/// The folder a private root may add (`project` / `session`), canonical and checked: a directory;
/// not `/`, not a system directory; not the sandbox directory, inside it (another user's home) or
/// holding it; and not holding a path the runner hides (its state, key, secrets). `hidden` and
/// `base` are canonical.
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

/// `program args` in a private root with `home` (from [`sandbox_home`]) writable and `folder`
/// (from [`check_folder`]) added when given. `cwd` is the folder, else the home. Fails closed on a
/// program the root does not provide, or a path that is not absolute.
pub fn wrap_private(
    home: &Path,
    folder: Option<&Path>,
    program: &str,
    args: &[String],
    net: &Net,
    terminal: &str,
) -> Result<Boxed, String> {
    if terminal.is_empty()
        || !terminal
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    {
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
    let mut out: Vec<String> = Vec::new();
    if cfg!(target_os = "macos") {
        if matches!(net, Net::Filtered { .. }) {
            return Err("a filtered terminal network is Linux only".to_owned());
        }
        let tmp = home.join(".tmp").join(terminal);
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&tmp)
                .map_err(|e| format!("{}: {e}", tmp.display()))?;
        }
        let mut p = String::from(
            "(version 1)\n(deny default)\n(allow process-fork)\n(allow process-exec)\n(allow signal (target self))\n(allow sysctl-read)\n(allow mach-lookup)\n(allow ipc-posix-shm-read* ipc-posix-shm-write-data)\n(allow pseudo-tty)\n(allow file-read* (subpath \"/usr\") (subpath \"/bin\") (subpath \"/sbin\") (subpath \"/System\") (subpath \"/Library\") (subpath \"/opt/homebrew\") (subpath \"/private/etc\") (subpath \"/private/var/db\") (subpath \"/private/var/select\") (subpath \"/dev\") (literal \"/\"))\n(allow file-write* (literal \"/dev/null\") (literal \"/dev/tty\") (regex #\"^/dev/ttys[0-9]+$\"))\n",
        );
        let mut open = vec![home];
        open.extend(folder);
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
        p.push_str("(deny process-exec (literal \"/bin/launchctl\") (literal \"/usr/bin/osascript\") (literal \"/usr/bin/open\") (literal \"/usr/bin/at\") (literal \"/usr/bin/crontab\"))\n(deny mach-lookup (global-name-prefix \"com.apple.xpc.launchd.domain\"))\n");
        if *net == Net::Host {
            p.push_str("(allow network*)\n");
        }
        out.extend(["-p".to_owned(), p, "--".to_owned()]);
        out.push(program.to_owned());
        out.extend(args.iter().cloned());
        let cwd = h(folder.unwrap_or(home));
        return Ok(Boxed {
            launcher: SANDBOX_EXEC.to_owned(),
            args: out,
            env: vec![("HOME".into(), h(home)), ("TMPDIR".into(), h(&tmp))],
            cwd,
        });
    }
    out.extend(
        [
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--die-with-parent",
            "--cap-drop",
            "ALL",
            "--disable-userns",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
        ]
        .map(str::to_owned),
    );
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
    out.extend([
        "--setenv".to_owned(),
        "HOME".to_owned(),
        BOX_HOME.to_owned(),
    ]);
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
        env: vec![("HOME".into(), BOX_HOME.into())],
        cwd,
    })
}

/// Removes every `<base>/<user>/.tmp/<terminal>` whose terminal is not in `live` and that has not
/// been touched for a minute (a terminal still starting has no host yet). Never follows a link.
pub fn reap_scratch(base: &Path, live: &std::collections::HashSet<String>) {
    let old = |p: &Path| {
        std::fs::symlink_metadata(p)
            .and_then(|m| m.modified())
            .is_ok_and(|t| {
                t.elapsed()
                    .is_ok_and(|e| e > std::time::Duration::from_secs(60))
            })
    };
    for user in std::fs::read_dir(base).into_iter().flatten().flatten() {
        let tmp = user.path().join(".tmp");
        for d in std::fs::read_dir(&tmp).into_iter().flatten().flatten() {
            let (p, name) = (d.path(), d.file_name().to_string_lossy().into_owned());
            let is_dir = d.file_type().is_ok_and(|t| t.is_dir());
            if is_dir && !live.contains(&name) && old(&p) {
                let _ = std::fs::remove_dir_all(&p);
            }
        }
    }
}

#[cfg(test)]
mod private_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(net: &Net) -> Result<Vec<String>, String> {
        wrap_net(&[], &[], "/bin/sh", &["-i".to_owned()], "/", net).map(|(_, a)| a)
    }

    /// The host network's launcher line is what it was before `--terminal-network` existed.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_network_launcher_line_is_unchanged() {
        let a = argv(&Net::Host).unwrap();
        let fixed = [
            "--bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--unshare-user",
            "--unshare-pid",
            "--die-with-parent",
            "--cap-drop",
            "ALL",
            "--disable-userns",
        ];
        assert_eq!(a[..fixed.len()], fixed);
        assert_eq!(a[a.len() - 5..], ["--chdir", "/", "--", "/bin/sh", "-i"]);
        // What lies between is only the per-user runtime dir's tmpfs, when it exists.
        for w in a[fixed.len()..a.len() - 5].chunks(2) {
            assert_eq!(w[0], "--tmpfs");
            assert!(w[1].starts_with("/run/user/"), "{w:?}");
        }
        // And a locked network adds the socket dirs' tmpfs on top of that.
        let none = argv(&Net::None).unwrap();
        for dir in ["/tmp", "/run"] {
            let at = none.iter().position(|v| v == dir).expect(dir);
            assert_eq!(none[at - 1], "--tmpfs");
        }
    }

    #[test]
    fn only_a_named_network_changes_the_shell_network_and_the_program_stays_last() {
        let has = |a: &[String], x: &str| a.iter().any(|v| v == x);
        let host = argv(&Net::Host).unwrap();
        assert!(!has(&host, "--unshare-net") && !has(&host, "(deny network*)\n"));
        assert!(!host.iter().any(|a| a.contains("deny network")));
        let none = argv(&Net::None).unwrap();
        if cfg!(target_os = "linux") {
            assert!(has(&none, "--unshare-net"));
        } else {
            assert!(none.iter().any(|a| a.contains("(deny network*)")));
        }
        assert_eq!(none[none.len() - 2..], ["/bin/sh", "-i"]);
        assert!(Net::parse("allow", PathBuf::new(), PathBuf::new()).is_none());
        // A program that could be an option is still refused on a locked network.
        assert!(
            wrap_net(&[], &[], "-f", &[], "/", &Net::None).is_err(),
            "option-like program"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_filtered_network_is_refused_where_it_cannot_be_given() {
        let net = Net::Filtered {
            dir: PathBuf::from("/tmp"),
            exe: PathBuf::from("/x"),
        };
        assert!(argv(&net).unwrap_err().contains("Linux only"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_filtered_shell_gets_the_proxy_variables_the_socket_dir_and_the_forwarder_first() {
        let dir = std::env::temp_dir().join(format!("termnet-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let net = Net::Filtered {
            dir: dir.clone(),
            exe: PathBuf::from("/runner"),
        };
        let a = argv(&net).unwrap();
        let at = |x: &str| a.iter().position(|v| v == x).unwrap();
        assert!(a.iter().any(|v| v == "--unshare-net"));
        let d = dir.canonicalize().unwrap().to_string_lossy().into_owned();
        assert_eq!(a[at(&d) - 1], "--ro-bind", "the socket dir is read-only");
        let proxy = format!("http://127.0.0.1:{}", crate::egress::EGRESS_PORT);
        assert!(a.contains(&proxy));
        // forwarder script, then the real program last
        assert!(at("ainkrad-terminal") > at("--"));
        assert_eq!(a[a.len() - 2..], ["/bin/sh", "-i"]);
        // a missing socket dir fails closed rather than starting without a path out
        let gone = Net::Filtered {
            dir: dir.join("nope"),
            exe: PathBuf::from("/runner"),
        };
        assert!(argv(&gone).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_program_that_could_be_an_option_or_is_relative_is_refused() {
        for bad in ["-f", "--bind", "sh", "./sh", ""] {
            let args = ["/tmp/allow.sb".to_owned(), "/bin/sh".to_owned()];
            assert!(wrap(&[], &[], bad, &args, "/").is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_bare_name_is_found_on_path_and_nothing_else_is_rewritten() {
        let path = Some("relative/dir:/nonexistent:/bin:/usr/bin");
        let sh = resolve("sh", path);
        assert!(sh.starts_with('/') && sh.ends_with("/sh"), "{sh}");
        assert!(wrap(&[], &[], &sh, &[], "/").is_ok());
        for keep in ["-f", "./sh", "bin/sh", "", "no-such-program-e2"] {
            assert_eq!(resolve(keep, path), keep);
            assert!(
                wrap(&[], &[], &resolve(keep, path), &[], "/").is_err(),
                "{keep:?}"
            );
        }
        assert_eq!(resolve("sh", None), "sh");
        // The error names the real problem for a bare name, and the rule for anything else.
        let missing = wrap(&[], &[], "no-such-program-e2", &[], "/").unwrap_err();
        assert!(
            missing.contains("not found on the terminal's PATH"),
            "{missing}"
        );
        let option = wrap(&[], &[], "-f", &[], "/").unwrap_err();
        assert!(
            option.contains("absolute path") && !option.contains("not found"),
            "{option}"
        );
    }

    #[test]
    fn a_shell_user_is_a_plain_account_name_and_sudo_gets_it_before_the_double_dash() {
        for ok in ["ainkrad-shell", "_svc", "a", "shell1"] {
            assert!(valid_user(ok), "{ok}");
        }
        for bad in [
            "",
            "-u",
            "root x",
            "Root",
            "a/b",
            "a:b",
            "a\nb",
            "1abc",
            &"a".repeat(33),
        ] {
            assert!(!valid_user(bad), "{bad:?}");
        }
        let (sudo, args) = as_user("shell", "/bin/sh".to_owned(), vec!["-c".to_owned()]);
        assert_eq!(sudo, "/usr/bin/sudo");
        assert_eq!(args, ["-n", "-u", "shell", "--", "/bin/sh", "-c"]);
    }

    #[test]
    fn terminals_as_another_user_fail_closed_before_any_shell_starts() {
        // Not an account, root, and the runner's own user: each refused with its reason.
        assert!(
            probe_user("no-such-account-e2", false, &Net::Host)
                .unwrap_err()
                .contains("no account")
        );
        assert!(
            probe_user("-n", true, &Net::Host)
                .unwrap_err()
                .contains("valid")
        );
        assert!(
            probe_user("root", false, &Net::Host)
                .unwrap_err()
                .contains("root")
        );
        let me = Command::new("/usr/bin/id").arg("-un").output().unwrap();
        let me = String::from_utf8_lossy(&me.stdout).trim().to_owned();
        if valid_user(&me) {
            assert!(
                probe_user(&me, false, &Net::Host)
                    .unwrap_err()
                    .contains("own user")
            );
        }
    }

    #[test]
    fn the_state_dir_is_closed_to_other_accounts_before_shells_run_as_another_user() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("termbox-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_state(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        assert!(private_state(&dir.join("missing")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_program_follows_a_double_dash_so_it_cannot_be_an_option() {
        let (_, args) = wrap(&[], &[], "/bin/sh", &["-c".to_owned()], "/").unwrap();
        let at = args
            .iter()
            .position(|a| a == "--")
            .expect("a -- before the program");
        assert_eq!(&args[at + 1..], ["/bin/sh", "-c"]);
    }

    #[test]
    fn a_missing_hidden_dir_is_created_private_before_it_is_hidden() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("apr-tb-{}", std::process::id()));
        let late = base.join("work-root");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let (_, args) = wrap(std::slice::from_ref(&late), &[], "/bin/sh", &[], "/").unwrap();
        let mode = std::fs::metadata(&late).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let canon = late.canonicalize().unwrap().to_string_lossy().into_owned();
        assert!(args.iter().any(|a| a.contains(&canon)), "{args:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_co_located_cores_default_state_is_hidden_without_a_flag() {
        assert!(CORE_STATE_DIRS.contains(&"/var/lib/ainkrad"));
        let (_, args) = wrap(&[], &[], "/bin/sh", &[], "/").unwrap();
        if Path::new("/var/lib/ainkrad").exists() && cfg!(target_os = "linux") {
            assert!(args.iter().any(|a| a == "/var/lib/ainkrad"), "{args:?}");
        }
    }

    /// A session's folder comes back over the hidden state after every hiding rule and before the
    /// read-only ones; a folder that would bring a hidden path back with it is refused.
    #[test]
    fn a_revealed_folder_follows_the_hiding_and_never_holds_a_hidden_path() {
        let base = std::env::temp_dir().join(format!("apr-tbr-{}", std::process::id()));
        let (state, ro) = (base.join("state"), base.join("ro"));
        let folder = state.join("work/session-x");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::create_dir_all(&ro).unwrap();
        let go = |reveal: &Path| {
            wrap_in(
                std::slice::from_ref(&state),
                std::slice::from_ref(&ro),
                "/bin/sh",
                &[],
                "/",
                &Net::Host,
                Some(reveal),
            )
            .map(|(_, a)| a)
        };
        let (f, st, r) = (
            folder
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            state.canonicalize().unwrap().to_string_lossy().into_owned(),
            ro.canonicalize().unwrap().to_string_lossy().into_owned(),
        );
        let a = go(&folder).unwrap();
        if cfg!(target_os = "macos") {
            let p = &a[1];
            let at = |x: &str| p.find(x).unwrap_or_else(|| panic!("{x} in {p}"));
            let deny = at(&format!("(deny file-read* file-write* (subpath \"{st}\"))"));
            let allow = at(&format!("(allow file-read* file-write* (subpath \"{f}\"))"));
            let parent = at(&format!("(allow file-read-metadata (literal \"{st}\"))"));
            let readonly = at(&format!("(deny file-write* (subpath \"{r}\"))"));
            assert!(deny < allow && allow < parent && parent < readonly, "{p}");
            assert!(!p.contains(&format!(
                "(allow file-read* file-write* (subpath \"{st}\"))"
            )));
        } else {
            let at = |x: &[&str]| a.windows(x.len()).position(|w| w == x).expect("in argv");
            let tmpfs = at(&["--tmpfs", &st]);
            let bind = at(&["--bind", &f, &f]);
            let readonly = at(&["--ro-bind", &r, &r]);
            assert!(tmpfs < bind && bind < readonly, "{a:?}");
        }
        // The state itself, or a folder holding it, would un-hide all of it.
        for whole in [&state, &base] {
            assert!(go(whole).unwrap_err().contains("hides"), "{whole:?}");
        }
        // No reveal: the argv is what it was.
        assert!(
            !wrap(std::slice::from_ref(&state), &[], "/bin/sh", &[], "/")
                .unwrap()
                .1
                .iter()
                .any(|x| x.contains("(allow file-read* file-write*"))
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_symlinked_hidden_path_is_refused() {
        let base = std::env::temp_dir().join(format!("apr-tbl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::os::unix::fs::symlink("/tmp", base.join("link")).unwrap();
        assert!(prepare(&[base.join("link")]).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
