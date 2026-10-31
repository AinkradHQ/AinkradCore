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
    v.extend(extra.iter().cloned());
    v
}

/// What a shell may read but not change: the runner binary, its pty host, and the places a
/// launcher lives (systemd user units, launchd agents). Otherwise the same uid could edit how
/// the runner starts (for example adding `--terminal-sandbox=off`) and wait for a restart.
pub fn readonly_paths(host: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::env::current_exe().into_iter().collect();
    v.push(host.to_path_buf());
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

/// `program args` run with `hidden` unreadable and `readonly` unwritable: the command line to
/// start instead. Fails closed: an absent hidden path, or a `program` that is not an absolute
/// path (a leading `-` would be read as an option of the launcher, replacing its profile).
pub fn wrap(
    hidden: &[PathBuf],
    readonly: &[PathBuf],
    program: &str,
    args: &[String],
    cwd: &str,
) -> Result<(String, Vec<String>), String> {
    if !program.starts_with('/') {
        return Err("a terminal program must be an absolute path".to_owned());
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
        for p in &hidden {
            let q = quote(p);
            profile.push_str(&format!(
                "(deny file-read* file-write* (subpath \"{q}\"))\n(deny network-outbound (remote unix-socket (subpath \"{q}\")))\n"
            ));
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
                "--proc",
                "/proc",
                "--unshare-user",
                "--unshare-pid",
                "--die-with-parent",
                "--cap-drop",
                "ALL",
            ]
            .map(str::to_owned),
        );
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
            tmpfs.sort_by_key(|p| p.components().count());
        }
        for p in &tmpfs {
            let p = p.to_string_lossy().into_owned();
            if Path::new(&p).is_dir() {
                out.extend(["--tmpfs".to_owned(), p]);
            } else {
                out.extend(["--ro-bind".to_owned(), "/dev/null".to_owned(), p]);
            }
        }
        for p in &readonly {
            let p = p.to_string_lossy().into_owned();
            out.extend(["--ro-bind".to_owned(), p.clone(), p]);
        }
        out.extend(["--chdir".to_owned(), cwd.to_owned(), "--".to_owned()]);
        BWRAP
    };
    out.push(program.to_owned());
    out.extend(args.iter().cloned());
    Ok((launcher.to_owned(), out))
}

/// Whether the sandbox runs here, tried for real (a disabled user namespace shows only then).
pub fn probe() -> Result<(), String> {
    let (program, args) = wrap(&[], &[], "/usr/bin/true", &[], "/")?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_that_could_be_an_option_or_is_relative_is_refused() {
        for bad in ["-f", "--bind", "sh", "./sh", ""] {
            let args = ["/tmp/allow.sb".to_owned(), "/bin/sh".to_owned()];
            assert!(wrap(&[], &[], bad, &args, "/").is_err(), "{bad:?}");
        }
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
