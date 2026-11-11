//! The root side of one-click tool install (`ainkrad-runner tools-helper`).
//!
//! The runner is an unprivileged, sandboxed user and stays one. A tool is installed by this helper,
//! started by systemd for each connection to `/run/ainkrad-runner-tools.sock` (`deploy/systemd/
//! ainkrad-runner-tools.socket`, `Accept=yes`, one at a time, mode 0660, group `ainkrad-runner`):
//! the connected socket is standard input. It is not a general root: it reads one line
//! `{"tool":"<name>"}` (a name from the fixed [`Tool`] list, no other field, at most 1 KiB, 5 s),
//! runs the install steps below with fixed argv and an empty environment, and answers JSON lines
//! `{"percent":N,"step":"…"}` ending in `{"done":true}` or `{"failed":"reason"}`.
//!
//! What it installs comes from `deploy/tools.manifest.json`, compiled into this binary (so it is as
//! trusted as the binary, which root owns): Node and Claude Code and Codex at pinned versions with a
//! SHA-256 or SHA-512 checked before anything is unpacked or installed (their dependencies are covered
//! by npm's own integrity check only); git, Python, Go, Rust and Docker from the distro's package
//! manager, by a fixed package list. Download hosts are `nodejs.org` and `registry.npmjs.org`.
//! The peer must be the runner's user (or root, for a runner that runs as root): checked by
//! `SO_PEERCRED` before a byte is read, on top of the socket's mode.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ainkrad_proto::v2::Tool;
use base64::Engine;
use ring::digest;
use serde::Deserialize;
use serde_json::{Value, json};

const MANIFEST: &str = include_str!("../../../deploy/tools.manifest.json");
const NODE_DIR: &str = "/usr/local/lib/ainkrad-node";
const BIN_DIR: &str = "/usr/local/bin";
const MANAGED_SETTINGS: &str = "/etc/claude-code/managed-settings.json";
const RUNNER_USER: &str = "ainkrad-runner";
const PATH: &str = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    tool: Tool,
}

#[derive(Deserialize)]
struct Manifest {
    node: NodePin,
    claude: NpmPin,
    codex: NpmPin,
    distro: std::collections::BTreeMap<String, Distro>,
}

#[derive(Deserialize)]
struct NodePin {
    version: String,
    url: String,
    sha256: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct NpmPin {
    package: String,
    version: String,
    url: String,
    integrity: String,
    #[serde(default)]
    managed_settings: Option<Value>,
}

#[derive(Deserialize)]
struct Distro {
    bin: String,
    apt: Vec<String>,
    dnf: Vec<String>,
}

fn manifest() -> Manifest {
    serde_json::from_str(MANIFEST).expect("deploy/tools.manifest.json is valid (a test parses it)")
}

/// What the install steps need from the machine: tests give a fake that records the calls.
pub trait Host {
    /// Runs `program args…` with fixed argv and an empty environment; `Err` is a short reason.
    fn run(&self, program: &str, args: &[&str]) -> Result<(), String>;
    /// Downloads an https `url` to `dest`.
    fn download(&self, url: &str, dest: &Path) -> Result<(), String>;
    /// `x64` or `arm64`.
    fn arch(&self) -> Result<&'static str, String>;
    /// `apt-get` or `dnf`, whichever is installed.
    fn package_manager(&self) -> Option<&'static str>;
    fn exists(&self, path: &Path) -> bool;
    fn write(&self, path: &Path, text: &str) -> Result<(), String>;
    /// Makes `link` point at `target`, replacing what was there.
    fn link(&self, target: &Path, link: &Path) -> Result<(), String>;
    fn read(&self, path: &Path) -> Result<Vec<u8>, String>;
    fn remove_dir(&self, path: &Path) -> Result<(), String>;
    fn make_dir(&self, path: &Path) -> Result<(), String>;
}

fn sha256_hex(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `sha512-<base64>` as npm writes an integrity.
fn sha512_integrity(bytes: &[u8]) -> String {
    let d = digest::digest(&digest::SHA512, bytes);
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(d.as_ref())
    )
}

type Progress<'a> = &'a mut dyn FnMut(u8, &str);

/// A scratch dir, made and removed here.
struct Scratch<'a>(&'a dyn Host, PathBuf);

impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        let _ = self.0.remove_dir(&self.1);
    }
}

fn node_bin() -> PathBuf {
    Path::new(NODE_DIR).join("bin/node")
}

fn install_node(
    h: &dyn Host,
    m: &Manifest,
    tmp: &Path,
    (lo, hi): (u8, u8),
    say: Progress,
) -> Result<(), String> {
    let at = |f: u8| lo + u8::try_from(u32::from(hi - lo) * u32::from(f) / 100).unwrap_or(0);
    let arch = h.arch()?;
    let want = m
        .node
        .sha256
        .get(arch)
        .ok_or_else(|| format!("no Node build for {arch}"))?;
    let url = m
        .node
        .url
        .replace("{version}", &m.node.version)
        .replace("{arch}", arch);
    guard_url(&url)?;
    say(lo, &format!("Downloading Node {}", m.node.version));
    let file = tmp.join("node.tar.xz");
    h.download(&url, &file)?;
    say(at(50), "Checking the download");
    if &sha256_hex(&h.read(&file)?) != want {
        return Err("the Node download does not match the checksum pinned in this release".into());
    }
    say(at(65), "Unpacking Node");
    let dir = Path::new(NODE_DIR);
    h.remove_dir(dir)?;
    h.make_dir(dir)?;
    let (f, d) = (file.to_string_lossy(), dir.to_string_lossy());
    h.run(
        "/usr/bin/tar",
        &["-xJf", &f, "-C", &d, "--strip-components=1"],
    )?;
    h.link(&node_bin(), &Path::new(BIN_DIR).join("node"))?;
    say(at(90), "Checking Node");
    h.run(&node_bin().to_string_lossy(), &["--version"])
}

fn install_npm(
    h: &dyn Host,
    m: &Manifest,
    pin: &NpmPin,
    bin: &str,
    tmp: &Path,
    say: Progress,
) -> Result<(), String> {
    // Node first, unless a Node of ours is there.
    if h.exists(&node_bin()) && h.run(&node_bin().to_string_lossy(), &["--version"]).is_ok() {
        say(5, "Node is already installed");
    } else {
        install_node(h, m, tmp, (0, 45), say)?;
    }
    guard_url(&pin.url)?;
    say(50, &format!("Downloading {} {}", pin.package, pin.version));
    let file = tmp.join("package.tgz");
    h.download(&pin.url, &file)?;
    say(65, "Checking the download");
    if sha512_integrity(&h.read(&file)?) != pin.integrity {
        return Err(format!(
            "the {} download does not match the checksum pinned in this release",
            pin.package
        ));
    }
    say(70, &format!("Installing {} {}", pin.package, pin.version));
    let node = Path::new(NODE_DIR);
    let (npm, file) = (node.join("bin/npm"), file.to_string_lossy().into_owned());
    // `node` must be on npm's PATH for its `#!/usr/bin/env node`: the helper's PATH has /usr/local/bin.
    h.run(
        &npm.to_string_lossy(),
        &[
            "install",
            "-g",
            "--prefix",
            NODE_DIR,
            "--no-audit",
            "--no-fund",
            &file,
        ],
    )?;
    h.link(&node.join("bin").join(bin), &Path::new(BIN_DIR).join(bin))?;
    if let Some(settings) = &pin.managed_settings {
        say(90, "Turning auto-update off");
        h.make_dir(Path::new(MANAGED_SETTINGS).parent().expect("has a parent"))?;
        h.write(Path::new(MANAGED_SETTINGS), &format!("{settings}\n"))?;
    }
    say(95, &format!("Checking {bin}"));
    h.run(
        &Path::new(BIN_DIR).join(bin).to_string_lossy(),
        &["--version"],
    )
}

fn install_distro(h: &dyn Host, d: &Distro, say: Progress) -> Result<(), String> {
    let pm = h
        .package_manager()
        .ok_or("this host has neither apt-get nor dnf, so the tool cannot be installed")?;
    let pkgs: Vec<&str> = if pm == "apt-get" { &d.apt } else { &d.dnf }
        .iter()
        .map(String::as_str)
        .collect();
    if pm == "apt-get" {
        say(10, "Updating the package list");
        h.run("/usr/bin/apt-get", &["update", "-qq"])?;
    }
    say(30, &format!("Installing {}", pkgs.join(", ")));
    let mut args = vec!["install", "-y"];
    if pm == "apt-get" {
        args.push("--no-install-recommends");
    } else {
        args.push("--setopt=install_weak_deps=False");
    }
    args.extend(pkgs);
    h.run(&format!("/usr/bin/{pm}"), &args)?;
    say(95, "Checking the install");
    h.run(&d.bin, &["--version"])
}

/// Only the two hosts the manifest names.
fn guard_url(url: &str) -> Result<(), String> {
    match url.starts_with("https://nodejs.org/dist/")
        || url.starts_with("https://registry.npmjs.org/")
    {
        true => Ok(()),
        false => Err("a download from an unlisted host was refused".into()),
    }
}

/// Installs `tool`, reporting `(percent, step)`; `Err` is the reason to show.
pub fn install(h: &dyn Host, tool: Tool, say: Progress) -> Result<(), String> {
    let m = manifest();
    let tmp = std::env::temp_dir().join(format!(
        "ainkrad-tools-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos())
    ));
    h.make_dir(&tmp)?;
    let _scratch = Scratch(h, tmp.clone());
    match tool {
        Tool::Node => install_node(h, &m, &tmp, (0, 100), say),
        Tool::Claude => install_npm(h, &m, &m.claude, "claude", &tmp, say),
        Tool::Codex => install_npm(h, &m, &m.codex, "codex", &tmp, say),
        t => {
            let d = m
                .distro
                .get(t.name())
                .ok_or("no install for this tool in the release manifest")?;
            install_distro(h, d, say)
        }
    }
}

/// The real machine.
pub struct Real;

impl Host for Real {
    fn run(&self, program: &str, args: &[&str]) -> Result<(), String> {
        let out = std::process::Command::new(program)
            .args(args)
            .env_clear()
            .env("PATH", PATH)
            .env("HOME", "/root")
            .env("DEBIAN_FRONTEND", "noninteractive")
            .env("LC_ALL", "C")
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| format!("{program}: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        let tail = String::from_utf8_lossy(&out.stderr);
        let tail: String = tail
            .trim()
            .chars()
            .rev()
            .take(400)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        Err(format!(
            "{} failed ({}): {tail}",
            Path::new(program)
                .file_name()
                .map_or_else(|| program.to_owned(), |n| n.to_string_lossy().into_owned()),
            out.status
        ))
    }

    fn download(&self, url: &str, dest: &Path) -> Result<(), String> {
        self.run(
            "/usr/bin/curl",
            &[
                "-fsSL",
                "--proto",
                "=https",
                "--tlsv1.3",
                "--max-time",
                "900",
                "-o",
                &dest.to_string_lossy(),
                url,
            ],
        )
    }

    fn arch(&self) -> Result<&'static str, String> {
        match std::env::consts::ARCH {
            "x86_64" => Ok("x64"),
            "aarch64" => Ok("arm64"),
            other => Err(format!("no build for {other}")),
        }
    }

    fn package_manager(&self) -> Option<&'static str> {
        ["apt-get", "dnf"]
            .into_iter()
            .find(|pm| Path::new("/usr/bin").join(pm).exists())
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn write(&self, path: &Path, text: &str) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    fn link(&self, target: &Path, link: &Path) -> Result<(), String> {
        let _ = std::fs::remove_file(link);
        std::os::unix::fs::symlink(target, link).map_err(|e| format!("{}: {e}", link.display()))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, String> {
        std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn remove_dir(&self, path: &Path) -> Result<(), String> {
        match std::fs::remove_dir_all(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(format!("{}: {e}", path.display()))
            }
            _ => Ok(()),
        }
    }

    fn make_dir(&self, path: &Path) -> Result<(), String> {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(path)
            .map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// The uid of `name` in a passwd file's text.
fn uid_in(passwd: &str, name: &str) -> Option<u32> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then(|| f.nth(1)?.parse().ok())?
    })
}

/// One line of at most 1 KiB inside 5 s, nothing after it.
fn read_request(stream: &mut UnixStream) -> Option<Request> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || stream.set_read_timeout(Some(left)).is_err() {
            return None;
        }
        match stream.read(&mut byte) {
            Ok(1) if byte[0] == b'\n' => break,
            Ok(1) if buf.len() < 1024 => buf.push(byte[0]),
            _ => return None,
        }
    }
    serde_json::from_slice(&buf).ok()
}

fn say_line(stream: &mut UnixStream, v: &Value) {
    // The runner going away must not stop the install half done: the write error is ignored.
    let _ = writeln!(stream, "{v}");
}

/// Serves one connection (`stream` is its socket).
pub fn serve(h: &dyn Host, mut stream: UnixStream, runner_uid: Option<u32>) {
    use std::os::fd::AsFd;
    let peer = ainkrad_sys::peer_uid(stream.as_fd()).ok();
    let allowed = match peer {
        Some(0) => true,
        Some(p) => Some(p) == runner_uid,
        None => false,
    };
    if !allowed {
        say_line(&mut stream, &json!({"failed": "this peer is not allowed"}));
        return;
    }
    let Some(req) = read_request(&mut stream) else {
        say_line(&mut stream, &json!({"failed": "the request was refused"}));
        return;
    };
    let mut out = stream.try_clone().expect("a socket clones");
    let result = install(h, req.tool, &mut |percent, step| {
        say_line(&mut out, &json!({"percent": percent, "step": step}));
    });
    match result {
        Ok(()) => say_line(
            &mut stream,
            &json!({"percent": 100, "step": "Installed", "done": true}),
        ),
        Err(why) => say_line(&mut stream, &json!({"failed": why})),
    }
}

/// `ainkrad-runner tools-helper`: the connected socket is standard input.
pub fn main() -> std::process::ExitCode {
    use std::os::fd::AsFd;
    let Ok(fd) = std::io::stdin().as_fd().try_clone_to_owned() else {
        return std::process::ExitCode::FAILURE;
    };
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    serve(&Real, UnixStream::from(fd), uid_in(&passwd, RUNNER_USER));
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// Records every call; `fail` names a program whose run fails.
    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<String>>,
        download_bytes: Vec<u8>,
        fail: Option<&'static str>,
        pm: Option<&'static str>,
        node_present: bool,
    }

    impl Host for Fake {
        fn run(&self, program: &str, args: &[&str]) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("{program} {}", args.join(" ")));
            match self.fail {
                Some(f) if program.ends_with(f) => Err(format!("{f} failed")),
                _ => Ok(()),
            }
        }
        fn download(&self, url: &str, _: &Path) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("download {url}"));
            Ok(())
        }
        fn arch(&self) -> Result<&'static str, String> {
            Ok("arm64")
        }
        fn package_manager(&self) -> Option<&'static str> {
            self.pm
        }
        fn exists(&self, _: &Path) -> bool {
            self.node_present
        }
        fn write(&self, p: &Path, t: &str) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("write {} {}", p.display(), t.trim()));
            Ok(())
        }
        fn link(&self, _: &Path, l: &Path) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("link {}", l.display()));
            Ok(())
        }
        fn read(&self, _: &Path) -> Result<Vec<u8>, String> {
            Ok(self.download_bytes.clone())
        }
        fn remove_dir(&self, _: &Path) -> Result<(), String> {
            Ok(())
        }
        fn make_dir(&self, _: &Path) -> Result<(), String> {
            Ok(())
        }
    }

    fn run(f: &Fake, tool: Tool) -> (Result<(), String>, Vec<u8>) {
        let mut seen = Vec::new();
        let r = install(f, tool, &mut |p, _| seen.push(p));
        (r, seen)
    }

    #[test]
    fn the_manifest_parses_and_matches_the_installer_pins() {
        let m = manifest();
        let script = include_str!("../../../scripts/install/agent-tools.sh");
        assert!(script.contains(&format!("NODE_VERSION={}", m.node.version)));
        assert!(script.contains(&format!("CLAUDE_VERSION={}", m.claude.version)));
        for sha in m.node.sha256.values() {
            assert!(script.contains(sha), "{sha}");
        }
        assert_eq!(m.claude.version, "2.1.318");
        assert!(m.node.version.starts_with("22."));
        assert_eq!(
            m.claude.managed_settings,
            Some(json!({"env": {"DISABLE_AUTOUPDATER": "1"}}))
        );
        for t in Tool::ALL {
            let known = matches!(t, Tool::Node | Tool::Claude | Tool::Codex)
                || m.distro.contains_key(t.name());
            assert!(known, "{}", t.name());
        }
        for u in [&m.node.url, &m.claude.url, &m.codex.url] {
            assert!(guard_url(&u.replace("{version}", "1").replace("{arch}", "x64")).is_ok());
        }
    }

    #[test]
    fn a_download_that_misses_its_checksum_installs_nothing() {
        let f = Fake {
            download_bytes: b"not node".to_vec(),
            ..Fake::default()
        };
        let (r, _) = run(&f, Tool::Node);
        assert!(r.unwrap_err().contains("checksum"));
        assert!(
            !f.calls
                .borrow()
                .iter()
                .any(|c| c.starts_with("/usr/bin/tar")),
            "nothing unpacked"
        );
        let (r, _) = run(&f, Tool::Claude);
        assert!(r.unwrap_err().contains("checksum"));
        assert!(!f.calls.borrow().iter().any(|c| c.contains("npm")));
    }

    #[test]
    fn distro_tools_use_the_package_manager_with_a_fixed_list_and_progress_rises() {
        let f = Fake {
            pm: Some("apt-get"),
            ..Fake::default()
        };
        let (r, seen) = run(&f, Tool::Git);
        r.unwrap();
        let calls = f.calls.borrow().join("\n");
        assert!(calls.contains("/usr/bin/apt-get update"), "{calls}");
        assert!(
            calls.contains("/usr/bin/apt-get install -y --no-install-recommends git"),
            "{calls}"
        );
        assert!(seen.windows(2).all(|w| w[0] <= w[1]), "{seen:?}");
        let f = Fake {
            pm: None,
            ..Fake::default()
        };
        assert!(run(&f, Tool::Docker).0.unwrap_err().contains("apt-get"));
        let f = Fake {
            pm: Some("dnf"),
            ..Fake::default()
        };
        run(&f, Tool::Rust).0.unwrap();
        assert!(
            f.calls
                .borrow()
                .join("\n")
                .contains("dnf install -y --setopt=install_weak_deps=False rust cargo")
        );
    }

    #[test]
    fn a_failing_step_is_the_reason() {
        let f = Fake {
            pm: Some("apt-get"),
            fail: Some("apt-get"),
            ..Fake::default()
        };
        assert_eq!(run(&f, Tool::Go).0.unwrap_err(), "apt-get failed");
    }

    #[test]
    fn download_urls_outside_the_two_hosts_are_refused() {
        assert!(guard_url("https://evil.example/node.tar.xz").is_err());
        assert!(guard_url("http://nodejs.org/dist/x").is_err());
    }

    #[test]
    fn the_runner_user_is_found_in_passwd() {
        let p = "root:x:0:0::/root:/bin/sh\nainkrad-runner:x:998:998::/var/lib/ainkrad-runner:/usr/sbin/nologin\n";
        assert_eq!(uid_in(p, "ainkrad-runner"), Some(998));
        assert_eq!(uid_in(p, "nobody"), None);
    }

    #[test]
    fn the_request_takes_a_known_tool_and_nothing_else() {
        for bad in [
            r#"{"tool":"bash"}"#,
            r#"{"tool":"git","cmd":"x"}"#,
            r#"{}"#,
            "git",
        ] {
            assert!(serde_json::from_str::<Request>(bad).is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<Request>(r#"{"tool":"docker"}"#).is_ok());
    }
}
