//! The toolchains a runner installs for heavy jobs (E15-4, spec §6): Rust (`rustup-init` plus a pinned
//! toolchain), Node, Python (python-build-standalone) and Go, the same shape as `aitools`: pinned
//! (`pins`), downloaded over TLS, checked against the pinned SHA-256 before anything is unpacked,
//! and installed into `<state>/toolchains/<tool>/<version>`, never as root. A finished install
//! holds a `.ok` file; a folder without one is a half install and is replaced.
//!
//! Jobs see an install read-only (`AINKRAD_SANDBOX_RO`); their caches (`CARGO_HOME`, the npm and Go
//! caches) live in the job's own writable home, never inside an install.
//! `xcode`, `swift` and `docker` are only probed (`probe_system`), never installed.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use ring::digest;

mod pins;
use pins::{Build, Kind, PINS, Pin, RUST_TOOLCHAIN};

/// The most one download may be (the biggest, Go or Python, is under 100 MB).
const MAX_DOWNLOAD: u64 = 300 * 1024 * 1024;
const INSTALL_LIMIT: Duration = Duration::from_secs(30 * 60);

/// The tool a program name belongs to, when this module installs it.
pub fn tool_for(program: &str) -> Option<&'static str> {
    let name = program.rsplit('/').next().unwrap_or(program);
    match name {
        "cargo" | "rustc" | "rustup" | "rustfmt" | "clippy-driver" | "cargo-clippy" => Some("rust"),
        "node" | "npm" | "npx" | "pnpm" | "yarn" | "tsc" | "vitest" | "jest" | "corepack" => {
            Some("node")
        }
        "python" | "python3" | "pytest" | "pip" | "pip3" | "tox" => Some("python"),
        "go" | "gofmt" => Some("go"),
        _ => None,
    }
}

fn platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-x64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        ("linux", "x86_64") => Some("linux-x64"),
        _ => None,
    }
}

fn pin(tool: &str) -> Option<&'static Pin> {
    PINS.iter().find(|p| p.tool == tool)
}

/// Whether `tool` can be installed here (a pin with a build for this machine): E15-1 counts a
/// toolchain a runner can install as available.
pub fn installable(tool: &str) -> bool {
    pin(tool).is_some_and(|p| p.builds.iter().any(|b| Some(b.platform) == platform()))
}

/// The `channel` a project's `rust-toolchain.toml` (or the one-line legacy `rust-toolchain`) names.
pub fn rust_channel(project_root: &Path) -> Option<String> {
    if let Ok(text) = std::fs::read_to_string(project_root.join("rust-toolchain.toml")) {
        return text.lines().find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == "channel").then(|| v.trim().trim_matches(['"', '\'']).to_owned())
        });
    }
    let legacy = std::fs::read_to_string(project_root.join("rust-toolchain")).ok()?;
    let first = legacy.lines().next()?.trim();
    (!first.is_empty() && !first.contains('=')).then(|| first.to_owned())
}

/// A project's toolchain file must ask for `stable` or the pinned release: any other channel is
/// refused here, since the sandbox's network cannot reach the release servers.
/// ponytail: a pinned nightly would need its own digest; add it to `pins` when a project needs one.
pub fn check_rust_channel(project_root: &Path) -> Result<(), String> {
    match rust_channel(project_root).as_deref() {
        None | Some("stable") => Ok(()),
        Some(c) if c == RUST_TOOLCHAIN => Ok(()),
        Some(c) => Err(format!(
            "rust-toolchain asks for {c}; runners have stable ({RUST_TOOLCHAIN}) only"
        )),
    }
}

/// What a job gets of its toolchains.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct JobTools {
    /// Mounted read-only (`AINKRAD_SANDBOX_RO`).
    pub ro: Vec<PathBuf>,
    /// First on `PATH`.
    pub path: Vec<PathBuf>,
    pub env: Vec<(String, String)>,
}

pub struct Toolchains {
    root: PathBuf,
    install: tokio::sync::Mutex<()>,
}

impl Toolchains {
    pub fn new(state: &Path) -> Arc<Self> {
        Arc::new(Self {
            root: state.join("toolchains"),
            install: tokio::sync::Mutex::new(()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn dir(&self, p: &Pin) -> PathBuf {
        self.root.join(p.tool).join(p.version)
    }

    fn ready(&self, p: &Pin) -> bool {
        self.dir(p).join(".ok").is_file()
    }

    /// The managed toolchains and their versions, for `Capacity::toolchains`.
    pub fn installed(&self) -> BTreeMap<String, String> {
        PINS.iter()
            .filter(|p| self.ready(p))
            .map(|p| (p.tool.to_owned(), p.version.to_owned()))
            .collect()
    }

    /// Everything the capacity report says of toolchains: the managed ones plus the host's
    /// `xcode`, `swift` and `docker` (blocking: a few short programs).
    pub fn report(&self) -> BTreeMap<String, String> {
        let mut all = probe_system();
        all.extend(self.installed());
        all
    }

    /// Installs `tool`'s pinned version unless it is there. Never as root.
    pub async fn ensure(&self, tool: &str) -> Result<(), String> {
        let p = pin(tool).ok_or_else(|| format!("{tool} is not a toolchain runners install"))?;
        if self.ready(p) {
            return Ok(());
        }
        if ainkrad_sys::getuid() == 0 {
            return Err("toolchains are never installed as root".to_owned());
        }
        let build = platform()
            .and_then(|pl| p.builds.iter().find(|b| b.platform == pl))
            .ok_or("there is no build of it for this machine")?;
        let _one = self.install.lock().await;
        if self.ready(p) {
            return Ok(());
        }
        let dir = self.dir(p);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let done = tokio::time::timeout(INSTALL_LIMIT, install(p, build, &dir)).await;
        let result = done.unwrap_or_else(|_| Err("the install took too long".to_owned()));
        match &result {
            Ok(()) => std::fs::write(dir.join(".ok"), p.version).map_err(|e| e.to_string())?,
            Err(_) => {
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
        result
    }

    /// The mounts, `PATH` folders and variables for a job that uses `tools` (all of them ready).
    /// The job's own writable home is `home`: caches go there.
    pub fn job_tools(&self, tools: &[&str], home: &Path) -> JobTools {
        let mut out = JobTools::default();
        for t in tools {
            let Some(p) = pin(t).filter(|p| self.ready(p)) else {
                continue;
            };
            let dir = self.dir(p);
            out.ro.push(dir.clone());
            out.path.extend(p.bin.iter().map(|b| dir.join(b)));
            let set =
                |v: &mut Vec<(String, String)>, k: &str, val: String| v.push((k.to_owned(), val));
            match p.tool {
                "rust" => {
                    set(
                        &mut out.env,
                        "RUSTUP_HOME",
                        dir.join("rustup").display().to_string(),
                    );
                    set(&mut out.env, "RUSTUP_TOOLCHAIN", p.version.to_owned());
                    set(&mut out.env, "RUSTUP_AUTO_INSTALL", "0".to_owned());
                    set(
                        &mut out.env,
                        "CARGO_HOME",
                        home.join("cargo").display().to_string(),
                    );
                }
                "go" => {
                    set(&mut out.env, "GOROOT", dir.display().to_string());
                    set(&mut out.env, "GOTOOLCHAIN", "local".to_owned());
                    set(
                        &mut out.env,
                        "GOPATH",
                        home.join("go").display().to_string(),
                    );
                    set(
                        &mut out.env,
                        "GOCACHE",
                        home.join("go-build").display().to_string(),
                    );
                    set(&mut out.env, "GOTELEMETRY", "off".to_owned());
                }
                "node" => {
                    set(
                        &mut out.env,
                        "npm_config_cache",
                        home.join("npm").display().to_string(),
                    );
                    set(
                        &mut out.env,
                        "COREPACK_HOME",
                        home.join("corepack").display().to_string(),
                    );
                }
                "python" => {
                    set(
                        &mut out.env,
                        "PIP_CACHE_DIR",
                        home.join("pip").display().to_string(),
                    );
                    set(&mut out.env, "PYTHONDONTWRITEBYTECODE", "1".to_owned());
                }
                _ => {}
            }
        }
        out
    }
}

/// The name a download is saved under. rustup is a multi-call binary that picks its role from its
/// file name: saved under any other name it answers "unknown proxy name" and installs nothing.
fn download_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Installer => "rustup-init",
        Kind::Tarball => ".download",
    }
}

/// Fetches, checks and unpacks (or runs) one build into the empty `dir`.
async fn install(p: &Pin, build: &Build, dir: &Path) -> Result<(), String> {
    let file = dir.join(download_name(p.kind));
    download(build, &file).await?;
    match p.kind {
        Kind::Tarball => {
            vet_tar(&file).await?;
            let status = tokio::process::Command::new("tar")
                .args([
                    "--no-same-owner",
                    "--no-same-permissions",
                    "--strip-components=1",
                    "-xzf",
                ])
                .arg(&file)
                .arg("-C")
                .arg(dir)
                .status()
                .await
                .map_err(|e| format!("could not unpack it: {e}"))?;
            let _ = std::fs::remove_file(&file);
            status
                .success()
                .then_some(())
                .ok_or("could not unpack the download".to_owned())
        }
        Kind::Installer => {
            let done = run_installer(&file, p.version, build.triple, dir).await;
            let _ = std::fs::remove_file(&file);
            done
        }
    }
}

/// Runs the downloaded `rustup-init` at `file` to install `version` for `triple` into `dir`.
async fn run_installer(file: &Path, version: &str, triple: &str, dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let home = dir.join("home");
    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    // An empty environment: only what rustup-init needs, all of it inside `dir`.
    let out = tokio::process::Command::new(file)
        .args([
            "-y",
            "--no-modify-path",
            "--profile",
            "minimal",
            "--default-toolchain",
        ])
        .arg(version)
        .args(["--default-host", triple])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .env("TMPDIR", &home)
        .env("RUSTUP_HOME", dir.join("rustup"))
        .env("CARGO_HOME", dir.join("cargo"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("could not run rustup-init: {e}"))?;
    let _ = std::fs::remove_dir_all(&home);
    if out.status.success() {
        return Ok(());
    }
    // Its last line says why; without it a failed install is undiagnosable.
    let err = String::from_utf8_lossy(&out.stderr);
    let why: String = err
        .trim()
        .lines()
        .last()
        .unwrap_or("")
        .chars()
        .take(200)
        .collect();
    Err(format!("rustup-init failed: {why}"))
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Downloads `build` to `file`, hashing as it goes, and checks the pinned digest.
async fn download(build: &Build, file: &Path) -> Result<(), String> {
    use std::io::Write;
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(5))
        .connect_timeout(Duration::from_secs(20))
        .timeout(INSTALL_LIMIT)
        .build()
        .map_err(|e| e.to_string())?;
    let mut res = client
        .get(build.url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("could not download it: {}", e.without_url()))?;
    if res.content_length().unwrap_or(0) > MAX_DOWNLOAD {
        return Err(
            "the download is larger than any toolchain should be, so it was refused".to_owned(),
        );
    }
    let mut out = std::fs::File::create(file).map_err(|e| e.to_string())?;
    let mut sha = digest::Context::new(&digest::SHA256);
    let mut got = 0u64;
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| format!("the download broke off: {}", e.without_url()))?
    {
        got += chunk.len() as u64;
        if got > MAX_DOWNLOAD {
            return Err("the download grew past the size limit, so it was stopped".to_owned());
        }
        sha.update(&chunk);
        out.write_all(&chunk).map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())?;
    if !build
        .sha256
        .eq_ignore_ascii_case(&hex_of(sha.finish().as_ref()))
    {
        let _ = std::fs::remove_file(file);
        return Err(
            "the download did not match the checksum Ainkrad expects, so it was thrown away"
                .to_owned(),
        );
    }
    Ok(())
}

/// A member that must not be unpacked: an absolute path or `..` step; anything but a plain file,
/// folder or relative symlink that stays under the archive's top folder (a hard link or device
/// could point out). `names` is `tar -tzf`, `verbose` is `tar -tzvf`, in the same order. Unlike
/// the AI tools' tarballs, these hold symlinks (`bin/npm`, `bin/python3`).
fn unsafe_member(names: &str, verbose: &str) -> Option<String> {
    for (n, v) in names.lines().zip(verbose.lines()) {
        if n.starts_with('/') || n.split('/').any(|p| p == "..") || n.contains('\0') {
            return Some(n.to_owned());
        }
        match v.chars().next() {
            Some('-' | 'd') => {}
            Some('l') => {
                let target = v.rsplit_once(" -> ").map_or("", |(_, t)| t);
                // Folders above the link, the top folder included: a link may not climb out of it.
                let mut depth = n.trim_end_matches('/').split('/').count() as i64 - 1;
                let ok = !target.is_empty()
                    && !target.starts_with('/')
                    && target.split('/').all(|part| {
                        match part {
                            ".." => depth -= 1,
                            "" | "." => {}
                            _ => depth += 1,
                        }
                        depth >= 1
                    });
                if !ok {
                    return Some(n.to_owned());
                }
            }
            _ => return Some(v.chars().take(80).collect()),
        }
    }
    None
}

async fn vet_tar(file: &Path) -> Result<(), String> {
    let list = |flags: &'static str| {
        let file = file.to_owned();
        async move {
            let out = tokio::process::Command::new("tar")
                .arg(flags)
                .arg(&file)
                .output()
                .await
                .map_err(|e| format!("could not read the download: {e}"))?;
            if !out.status.success() {
                return Err("the download is not a tarball".to_owned());
            }
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
    };
    let (names, verbose) = (list("-tzf").await?, list("-tzvf").await?);
    match unsafe_member(&names, &verbose) {
        Some(m) => Err(format!(
            "the download has a member it must not unpack ({m}), so it was refused"
        )),
        None => Ok(()),
    }
}

/// The version after `prefix` on the first line of `out` that has it: `Xcode 16.4` gives `16.4`.
pub fn parse_version(out: &str, prefix: &str) -> Option<String> {
    let rest = out.lines().find_map(|l| l.trim().strip_prefix(prefix))?;
    let v: String = rest
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    (!v.is_empty()).then_some(v)
}

fn probe(program: &str, args: &[&str], prefix: &str) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| parse_version(&String::from_utf8_lossy(&out.stdout), prefix))?
}

/// `xcode` (macOS), `swift` and `docker` as the host has them. Blocking.
pub fn probe_system() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if cfg!(target_os = "macos")
        && let Some(v) = probe("/usr/bin/xcodebuild", &["-version"], "Xcode ")
    {
        out.insert("xcode".to_owned(), v);
    }
    if let Some(v) = probe("swift", &["--version"], "Swift version ")
        .or_else(|| probe("swift", &["--version"], "Apple Swift version "))
    {
        out.insert("swift".to_owned(), v);
    }
    if let Some(v) = probe("docker", &["--version"], "Docker version ") {
        out.insert("docker".to_owned(), v);
    }
    out
}

#[cfg(test)]
mod tests;
