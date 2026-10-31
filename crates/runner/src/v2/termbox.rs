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
/// sessions, harness config), the harness logins, delivered secrets and the agents' work root.
pub fn hidden_paths(state: &Path) -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let mut v = vec![state.to_path_buf()];
    v.extend(home.map(|h| h.join(".ainkrad-runner")));
    v.extend(super::cli::runtime_paths(state));
    v
}

fn existing(hidden: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in hidden {
        if let Ok(c) = p.canonicalize()
            && !out.contains(&c)
        {
            out.push(c);
        }
    }
    out
}

fn quote(p: &Path) -> String {
    p.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// `program args` run with `hidden` unreadable: the command line to start instead.
pub fn wrap(
    hidden: &[PathBuf],
    program: &str,
    args: &[String],
    cwd: &str,
) -> (String, Vec<String>) {
    let hidden = existing(hidden);
    let mut out: Vec<String> = Vec::new();
    let launcher = if cfg!(target_os = "macos") {
        // Everything is allowed but the hidden paths, files and unix sockets alike.
        let mut profile = String::from("(version 1)\n(allow default)\n");
        for p in &hidden {
            let q = quote(p);
            profile.push_str(&format!(
                "(deny file-read* file-write* (subpath \"{q}\"))\n(deny network-outbound (remote unix-socket (subpath \"{q}\")))\n"
            ));
        }
        out.extend(["-p".to_owned(), profile]);
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
        for p in &hidden {
            let p = p.to_string_lossy().into_owned();
            if Path::new(&p).is_dir() {
                out.extend(["--tmpfs".to_owned(), p]);
            } else {
                out.extend(["--ro-bind".to_owned(), "/dev/null".to_owned(), p]);
            }
        }
        out.extend(["--chdir".to_owned(), cwd.to_owned(), "--".to_owned()]);
        BWRAP
    };
    out.push(program.to_owned());
    out.extend(args.iter().cloned());
    (launcher.to_owned(), out)
}

/// Whether the sandbox runs here, tried for real (a disabled user namespace shows only then).
pub fn probe() -> Result<(), String> {
    let (program, args) = wrap(&[], "/usr/bin/true", &[], "/");
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
