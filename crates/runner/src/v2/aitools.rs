//! The AI tools a runner installs and keeps current itself (D-22): Claude Code, Codex, OpenCode.
//!
//! Each tool is pinned to a tested version (`harness::compat`) and fetched from its official
//! source, Anthropic's release bucket or the npm registry, over TLS. The download is checked
//! against the digest pinned below before anything is unpacked, and it is installed into a
//! runner-owned folder, `<state>/ai-tools`: never system-wide, never as root. `bin/<tool>` there
//! is a small launcher, which the agent driver and the tool probe look in first.
//!
//! The runner installs what is missing, or older than its pin, shortly after it starts and
//! connects (`keep_current`), then restarts once so the agent driver picks the tools up. Progress
//! goes to `<state>/ai-tools/status.json` for the app on the same Mac, and to the caller of
//! `install` for the Core's `tools.install` op.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ainkrad_proto::v2::Tool;
use base64::Engine as _;
use ring::digest;

static PREFIX: OnceLock<PathBuf> = OnceLock::new();
static BUSY: AtomicBool = AtomicBool::new(false);

/// Where the tools live; set once at start (`<state>/ai-tools`).
pub fn set_prefix(p: PathBuf) {
    let _ = PREFIX.set(p);
}

pub fn prefix() -> Option<&'static Path> {
    PREFIX.get().map(PathBuf::as_path)
}

/// The folder of the launchers, for a `PATH` that should find the managed tools.
pub fn bin_dir() -> Option<PathBuf> {
    prefix().map(|p| p.join("bin"))
}

/// The digest an artifact must have: SHA-256 as hex (Anthropic's manifest), or SHA-512 as
/// base64 (npm's `integrity`).
#[derive(Clone, Copy)]
enum Check {
    Sha256(&'static str),
    Sha512(&'static str),
}

impl Check {
    fn matches(self, sha256: &[u8], sha512: &[u8]) -> bool {
        match self {
            Check::Sha256(hex) => hex.eq_ignore_ascii_case(&hex_of(sha256)),
            Check::Sha512(b64) => base64::engine::general_purpose::STANDARD.encode(sha512) == b64,
        }
    }
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One platform's artifact of a pinned tool.
struct Build {
    platform: &'static str,
    url: &'static str,
    check: Check,
    /// The executable, relative to the unpacked folder (a single binary is its own file name).
    entry: &'static str,
}

struct Pin {
    tool: Tool,
    version: &'static str,
    /// A `.tgz` to unpack, or the binary itself.
    packed: bool,
    builds: &'static [Build],
}

mod pins;
use pins::PINS;

fn pin(tool: Tool) -> Option<&'static Pin> {
    PINS.iter().find(|p| p.tool == tool)
}

/// What the app calls a tool: "Claude", "Codex", "OpenCode", "Antigravity".
pub fn display(tool: Tool) -> &'static str {
    match tool {
        Tool::Claude => "Claude",
        Tool::Codex => "Codex",
        Tool::Opencode => "OpenCode",
        Tool::Agy => "Antigravity",
        t => t.name(),
    }
}

/// Whether `tool` is one of the AI tools this module installs (the rest go through the root helper).
pub fn is_ai_tool(tool: Tool) -> bool {
    matches!(
        tool,
        Tool::Claude | Tool::Codex | Tool::Opencode | Tool::Agy
    )
}

/// The AI tools, in the order they are installed: Claude first, as the one most runs need.
pub const AI_TOOLS: [Tool; 4] = [Tool::Claude, Tool::Codex, Tool::Opencode, Tool::Agy];

fn platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-x64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        ("linux", "x86_64") => Some("linux-x64"),
        _ => None,
    }
}

/// The version of `tool` this runner installed, if it did.
pub fn managed_version(prefix: &Path, tool: Tool) -> Option<String> {
    let v = std::fs::read_to_string(prefix.join(format!("{}.version", tool.name()))).ok()?;
    let v = v.trim();
    (!v.is_empty() && prefix.join("bin").join(tool.name()).is_file()).then(|| v.to_owned())
}

/// The pinned version of `tool`, when there is one.
pub fn pinned_version(tool: Tool) -> Option<&'static str> {
    pin(tool).map(|p| p.version)
}

/// Which tools to install now: one missing everywhere (`found_elsewhere` says whether the host
/// already has one) or a managed one older than its pin. A tool the person installed
/// themselves is never replaced.
fn due(prefix: &Path, found_elsewhere: &dyn Fn(Tool) -> bool) -> Vec<Tool> {
    AI_TOOLS
        .into_iter()
        .filter(|t| {
            pin(*t).is_some_and(|p| p.builds.iter().any(|b| Some(b.platform) == platform()))
        })
        .filter(|t| match managed_version(prefix, *t) {
            Some(v) => Some(v.as_str()) != pinned_version(*t),
            None => !found_elsewhere(*t),
        })
        .collect()
}

/// Whether the host has `tool` outside the managed folder: `~/.local/bin` (where Claude Code's
/// own installer puts it) or any `PATH` folder.
fn found_elsewhere(tool: Tool) -> bool {
    let name = tool.name();
    let local = std::env::var_os("HOME").map(|h| Path::new(&h).join(".local/bin").join(name));
    local.is_some_and(|p| p.is_file())
        || std::env::var_os("PATH")
            .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
}

/// Progress of the install now, for the app on this Mac: `{tool, percent, step, failed}`.
fn write_status(prefix: &Path, tool: Tool, percent: u8, step: &str, failed: Option<&str>) {
    let body = serde_json::json!({"tool": tool.name(), "percent": percent, "step": step, "failed": failed});
    let _ = std::fs::create_dir_all(prefix)
        .and_then(|()| std::fs::write(prefix.join("status.json"), body.to_string()));
}

fn clear_status(prefix: &Path) {
    let _ = std::fs::remove_file(prefix.join("status.json"));
}

struct Busy;
impl Busy {
    fn take() -> Result<Busy, String> {
        if BUSY.swap(true, Ordering::SeqCst) {
            Err("another install is running here".to_owned())
        } else {
            Ok(Busy)
        }
    }
}
impl Drop for Busy {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::SeqCst);
    }
}

/// Downloads `build` to `file`, hashing as it goes, and checks the digest. `progress` gets 0..=100.
async fn download(
    build: &Build,
    file: &Path,
    progress: &(dyn Fn(u8) + Sync),
) -> Result<(), String> {
    use std::io::Write;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(25 * 60))
        .build()
        .map_err(|e| e.to_string())?;
    let mut res = client
        .get(build.url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("could not download it: {}", e.without_url()))?;
    let total = res.content_length().unwrap_or(0);
    let mut out = std::fs::File::create(file).map_err(|e| e.to_string())?;
    let mut sha256 = digest::Context::new(&digest::SHA256);
    let mut sha512 = digest::Context::new(&digest::SHA512);
    let mut got = 0u64;
    let mut last = 0u8;
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| format!("the download broke off: {}", e.without_url()))?
    {
        sha256.update(&chunk);
        sha512.update(&chunk);
        out.write_all(&chunk).map_err(|e| e.to_string())?;
        got += chunk.len() as u64;
        if total > 0 {
            let p = (got * 100 / total).min(100) as u8;
            if p != last {
                last = p;
                progress(p);
            }
        }
    }
    out.flush().map_err(|e| e.to_string())?;
    if !build
        .check
        .matches(sha256.finish().as_ref(), sha512.finish().as_ref())
    {
        let _ = std::fs::remove_file(file);
        return Err(
            "the download did not match the checksum Ainkrad expects, so it was thrown away"
                .to_owned(),
        );
    }
    Ok(())
}

/// Puts the unpacked tool in `<prefix>/<name>/<version>`, points `bin/<name>` at it and records
/// the version. The launcher `exec`s the real path, so a tool that looks for files next to
/// itself (Codex) finds them.
fn activate(
    prefix: &Path,
    tool: Tool,
    version: &str,
    unpacked: &Path,
    entry: &str,
) -> Result<(), String> {
    let name = tool.name();
    let exe = unpacked.join(entry);
    if !exe.is_file() {
        return Err(format!("the download had no {entry} in it"));
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    let dir = prefix.join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let home = dir.join(version);
    std::fs::rename(unpacked, &home).map_err(|e| e.to_string())?;
    let real = home.join(entry);
    let bin = prefix.join("bin");
    std::fs::create_dir_all(&bin).map_err(|e| e.to_string())?;
    let quoted = real.display().to_string().replace('\'', r"'\''");
    let launcher = bin.join(format!(".{name}.new"));
    std::fs::write(&launcher, format!("#!/bin/sh\nexec '{quoted}' \"$@\"\n"))
        .map_err(|e| e.to_string())?;
    std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    std::fs::rename(&launcher, bin.join(name)).map_err(|e| e.to_string())?;
    std::fs::write(prefix.join(format!("{name}.version")), version).map_err(|e| e.to_string())
}

/// Installs the pinned version of `tool` into the runner's folder. `progress(percent, step)`.
pub async fn install(tool: Tool, progress: &(dyn Fn(u8, &str) + Sync)) -> Result<(), String> {
    let prefix = prefix().ok_or("this runner has no folder for tools")?;
    let Some(pin) = pin(tool) else {
        return Err(format!(
            "{} has no official download Ainkrad can check yet. Install it on this machine and the runner will find it",
            display(tool)
        ));
    };
    let build = platform()
        .and_then(|p| pin.builds.iter().find(|b| b.platform == p))
        .ok_or("there is no build of it for this machine")?;
    let _busy = Busy::take()?;
    let label = format!("{} {}", display(tool), pin.version);
    let report = |p: u8, step: &str| {
        write_status(prefix, tool, p, step, None);
        progress(p, step);
    };
    let result = async {
        let stage = prefix.join(format!(".stage-{}", tool.name()));
        let _ = std::fs::remove_dir_all(&stage);
        let out = stage.join("out");
        std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
        report(1, &format!("Downloading {label}"));
        let file = stage.join("download");
        download(build, &file, &|p| {
            report(
                1 + (u16::from(p) * 88 / 100) as u8,
                &format!("Downloading {label}"),
            );
        })
        .await?;
        if pin.packed {
            report(91, &format!("Unpacking {label}"));
            let status = tokio::process::Command::new("tar")
                .arg("-xzf")
                .arg(&file)
                .arg("-C")
                .arg(&out)
                .status()
                .await
                .map_err(|e| format!("could not unpack it: {e}"))?;
            if !status.success() {
                return Err("could not unpack the download".to_owned());
            }
        } else {
            std::fs::rename(&file, out.join(build.entry)).map_err(|e| e.to_string())?;
        }
        report(96, &format!("Setting up {label}"));
        activate(prefix, tool, pin.version, &out, build.entry)
    }
    .await;
    let _ = std::fs::remove_dir_all(prefix.join(format!(".stage-{}", tool.name())));
    match &result {
        Ok(()) => report(100, &format!("Installed {label}")),
        Err(why) => write_status(
            prefix,
            tool,
            0,
            &format!("Could not install {}", display(tool)),
            Some(why),
        ),
    }
    result
}

/// After the runner is up: installs what is missing or out of date, one tool at a time, then
/// calls `restart` once if anything landed so the agent driver picks the tools up.
pub async fn keep_current(restart: impl Fn() + Send) {
    let Some(prefix) = prefix() else { return };
    tokio::time::sleep(Duration::from_secs(5)).await;
    let mut changed = false;
    for tool in due(prefix, &found_elsewhere) {
        match install(tool, &|_, _| {}).await {
            Ok(()) => changed = true,
            Err(why) => {
                tracing::warn!(tool = tool.name(), %why, "an AI tool could not be installed")
            }
        }
    }
    if changed {
        clear_status(prefix);
        restart();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ainkrad_harness::compat;

    fn dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "aia-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn every_pin_is_a_tested_version_with_all_four_platforms_and_a_real_digest() {
        for p in PINS {
            let v = compat::check(p.tool.name(), Some(p.version), &Default::default());
            assert!(
                !v.refused,
                "{} {} is refused: {:?}",
                p.tool.name(),
                p.version,
                v.reason
            );
            for plat in ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"] {
                let b = p
                    .builds
                    .iter()
                    .find(|b| b.platform == plat)
                    .unwrap_or_else(|| panic!("{} has no {plat}", p.tool.name()));
                assert!(b.url.starts_with("https://"), "{}", b.url);
                match b.check {
                    Check::Sha256(h) => {
                        assert!(h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()))
                    }
                    Check::Sha512(b64) => assert_eq!(
                        base64::engine::general_purpose::STANDARD
                            .decode(b64)
                            .unwrap()
                            .len(),
                        64
                    ),
                }
                assert_eq!(p.packed, b.url.ends_with(".tgz"));
            }
        }
    }

    #[test]
    fn a_wrong_digest_does_not_match() {
        let abc256 = digest::digest(&digest::SHA256, b"abc");
        let abc512 = digest::digest(&digest::SHA512, b"abc");
        let ok = Check::Sha256("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert!(ok.matches(abc256.as_ref(), abc512.as_ref()));
        let bad = Check::Sha256("00".repeat(32).leak());
        assert!(!bad.matches(abc256.as_ref(), abc512.as_ref()));
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(abc512.as_ref())
            .leak();
        assert!(Check::Sha512(b64).matches(abc256.as_ref(), abc512.as_ref()));
        assert!(!Check::Sha512("AAAA").matches(abc256.as_ref(), abc512.as_ref()));
    }

    #[test]
    fn activate_points_the_launcher_at_the_new_version_and_records_it() {
        let prefix = dir();
        let unpacked = prefix.join("stage/out");
        std::fs::create_dir_all(unpacked.join("package/bin")).unwrap();
        std::fs::write(
            unpacked.join("package/bin/opencode"),
            "#!/bin/sh\necho 1.18.34\n",
        )
        .unwrap();
        activate(
            &prefix,
            Tool::Opencode,
            "1.18.34",
            &unpacked,
            "package/bin/opencode",
        )
        .unwrap();
        assert_eq!(
            managed_version(&prefix, Tool::Opencode).as_deref(),
            Some("1.18.34")
        );
        let out = std::process::Command::new(prefix.join("bin/opencode"))
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "1.18.34");
        // A download without the executable in it is refused and changes nothing.
        let empty = prefix.join("stage2");
        std::fs::create_dir_all(&empty).unwrap();
        assert!(
            activate(
                &prefix,
                Tool::Opencode,
                "9.9.9",
                &empty,
                "package/bin/opencode"
            )
            .is_err()
        );
        assert_eq!(
            managed_version(&prefix, Tool::Opencode).as_deref(),
            Some("1.18.34")
        );
    }

    #[test]
    fn missing_tools_install_an_older_managed_one_updates_and_the_persons_own_is_left_alone() {
        let prefix = dir();
        // Nothing here and nothing on the host: all three with a pin are due, Antigravity has none.
        let due_all = due(&prefix, &|_| false);
        assert_eq!(
            due_all,
            [Tool::Claude, Tool::Codex, Tool::Opencode]
                .into_iter()
                .filter(|_| platform().is_some())
                .collect::<Vec<_>>()
        );
        // The person has Claude themselves: it is not replaced.
        assert!(!due(&prefix, &|t| t == Tool::Claude).contains(&Tool::Claude));
        // A managed Claude at an old version is updated even though the host also has one.
        let unpacked = prefix.join("s/out");
        std::fs::create_dir_all(&unpacked).unwrap();
        std::fs::write(unpacked.join("claude"), "#!/bin/sh\n").unwrap();
        activate(&prefix, Tool::Claude, "2.0.0", &unpacked, "claude").unwrap();
        assert!(due(&prefix, &|_| true).contains(&Tool::Claude));
    }
}
