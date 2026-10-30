//! A run's private files (E4.2): the harness's MCP config, which holds the run token, and its
//! instructions (the run's rendered skills). They live in `<work_root>/private/run-<id>`, a
//! 0700 dir of 0600 files outside the agent's working dir (so never committed), and are
//! removed when the run ends, by any path: `RunFiles` removes them on drop, which a run
//! aborted by `Cancel` also reaches.

use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use ainkrad_harness::{agy, claude, codex, opencode};
use ainkrad_proto::runner::RunToken;

/// The run's private dir; removed with everything in it on drop.
pub(super) struct RunFiles {
    pub dir: PathBuf,
    pub mcp_config: Option<PathBuf>,
    pub instructions: Option<PathBuf>,
}

impl Drop for RunFiles {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.dir)
            && e.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(dir = %self.dir.display(), error = %e, "removing run files failed");
        }
    }
}

/// The MCP server URL a runner's server URL implies: `wss://h/runner/v1/connect` →
/// `https://h/mcp/v1` (`ws://` → `http://`, which the runner allows only to loopback).
pub fn mcp_url(server: &str) -> Option<String> {
    let (scheme, rest) = server.split_once("://")?;
    let scheme = match scheme {
        "wss" => "https",
        "ws" => "http",
        _ => return None,
    };
    let authority = rest.split('/').next().filter(|a| !a.is_empty())?;
    Some(format!("{scheme}://{authority}/mcp/v1"))
}

/// The Core's MCP server for a runner's server URL (`wss://h/runner/v2/connect`): the Citadel
/// module's token route `https://h/token/citadel/v1/mcp` (`ws://` → `http://`, loopback only).
/// `mcp_url` stays the monolith's `/mcp/v1`, which its reference tests still use.
pub fn core_mcp_url(server: &str) -> Option<String> {
    let url = mcp_url(server)?;
    Some(url.replace("/mcp/v1", "/token/citadel/v1/mcp"))
}

/// Writes one 0600 file, refusing to follow or reuse anything already there.
fn private_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)
}

impl RunFiles {
    /// Creates the private dir `name` under `root` (replacing a stale one) with `harness`'s MCP
    /// config for `url` and `token`, when there is a URL, and the instructions, when given: a
    /// run's own `run-<id>`, or its agent's `warm-<agent>-<harness>` for a harness server kept
    /// warm across runs, which reads them again from the same paths (E15.6).
    pub fn write(
        root: &Path,
        name: &str,
        harness: &str,
        mcp: Option<(&str, &RunToken)>,
        instructions: Option<&str>,
    ) -> io::Result<Self> {
        let dir = root.join(name);
        DirBuilder::new().recursive(true).mode(0o700).create(root)?;
        match std::fs::remove_dir_all(&dir) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        DirBuilder::new().mode(0o700).create(&dir)?;
        let mut files = Self {
            dir,
            mcp_config: None,
            instructions: None,
        };
        if let Some((url, token)) = mcp {
            let token = token.expose();
            let config = match harness {
                "claude" => claude::mcp_config(url, token),
                "codex" => codex::mcp_config(url, token),
                "opencode" => opencode::mcp_config(url, token),
                "agy" => agy::mcp_config(url, token),
                other => {
                    let why = format!("no MCP config format for harness {other:?}");
                    return Err(io::Error::new(io::ErrorKind::Unsupported, why));
                }
            };
            let path = files.dir.join("mcp.json");
            private_file(&path, config.to_string().as_bytes())?;
            files.mcp_config = Some(path);
            // No `citadel` CLI and no second copy of the token on disk: the Core has no CLI
            // route, so the agent uses MCP only (the CLI returns with S10).
        }
        if let Some(text) = instructions {
            let path = files.dir.join("instructions.md");
            private_file(&path, text.as_bytes())?;
            files.instructions = Some(path);
        }
        Ok(files)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn the_mcp_url_follows_the_server_url() {
        let url = |s| mcp_url(s);
        assert_eq!(
            url("wss://citadel.lan/runner/v1/connect").as_deref(),
            Some("https://citadel.lan/mcp/v1")
        );
        assert_eq!(
            url("ws://127.0.0.1:7700/runner/v1/connect").as_deref(),
            Some("http://127.0.0.1:7700/mcp/v1")
        );
        assert_eq!(
            core_mcp_url("wss://core.lan/runner/v2/connect").as_deref(),
            Some("https://core.lan/token/citadel/v1/mcp")
        );
        assert_eq!(url("http://x/runner"), None);
        assert_eq!(url("ws:///runner"), None);
    }

    #[test]
    fn files_are_private_and_gone_on_drop() {
        let root = std::env::temp_dir().join(format!("citadel-runfiles-{}", std::process::id()));
        let token = RunToken::new("cit_run_secret".to_owned());
        let mcp = Some(("http://127.0.0.1:1/mcp/v1", &token));
        // A stale dir from a crashed run is replaced, not reused.
        std::fs::create_dir_all(root.join("run-9")).unwrap();
        std::fs::write(root.join("run-9/stale"), "x").unwrap();
        let files = RunFiles::write(&root, "run-9", "claude", mcp, Some("# Skill")).unwrap();
        assert!(!files.dir.join("stale").exists());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&files.dir), 0o700);
        let config = files.mcp_config.clone().unwrap();
        assert_eq!(mode(&config), 0o600);
        assert_eq!(mode(files.instructions.as_ref().unwrap()), 0o600);
        // Instructions are the run's own, with no CLI text appended; the token is only in the
        // MCP config, never in a second file.
        assert_eq!(
            std::fs::read_to_string(files.instructions.as_ref().unwrap()).unwrap(),
            "# Skill"
        );
        assert!(!files.dir.join("token").exists(), "no second copy of the token");
        assert!(!root.join("bin").exists(), "no CLI is installed");
        assert!(
            std::fs::read_to_string(&config)
                .unwrap()
                .contains("Bearer cit_run_secret")
        );
        let dir = files.dir.clone();
        drop(files);
        assert!(!dir.exists(), "removed with the token in it");
        assert!(RunFiles::write(&root, "run-1", "pi", mcp, None).is_err());
        assert!(!root.join("run-1").join("mcp.json").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
