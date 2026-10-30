//! Process isolation for agent harnesses (E2-09).

use std::path::PathBuf;
use std::process::Command;

use ainkrad_proto::v2::AgentStart;

use super::agent::Sandbox;

const DEFAULT_PROCESSES: u32 = 64;

pub struct ProcessSandbox {
    state: PathBuf,
    secrets: PathBuf,
}

impl ProcessSandbox {
    pub fn new(state: PathBuf, secrets: PathBuf) -> Self {
        Self { state, secrets }
    }

    fn available() -> bool {
        let program = if cfg!(target_os = "macos") {
            "sandbox-exec"
        } else {
            "/usr/bin/bwrap"
        };
        if cfg!(target_os = "macos") {
            return Command::new("/usr/bin/sandbox-exec")
                .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
                .output()
                .is_ok_and(|o| o.status.success());
        }
        Command::new(program)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn add(env: &mut Vec<(String, String)>, name: &str, value: impl Into<String>) {
        env.push((name.to_owned(), value.into()));
    }
}

impl Sandbox for ProcessSandbox {
    fn name(&self) -> &'static str {
        if cfg!(target_os = "macos") {
            "seatbelt"
        } else {
            "bubblewrap"
        }
    }

    fn prepare(&self, start: &AgentStart, env: &mut Vec<(String, String)>) -> Result<(), String> {
        if !Self::available() {
            return Err(format!(
                "{} is unavailable; refusing an isolated agent",
                self.name()
            ));
        }
        let session = &start.session;
        let secret_dir = self.secrets.join(session);
        if !secret_dir.exists() && !start.secrets.is_empty() {
            return Err("the session secret directory was not created privately".to_owned());
        }
        let tmp = self.state.join("private-tmp").join(session);
        super::agent::secrets::private_dir(&tmp)
            .map_err(|e| format!("private sandbox tmp: {e}"))?;
        Self::add(env, "AINKRAD_SANDBOX", "1");
        Self::add(
            env,
            "AINKRAD_SANDBOX_STATE",
            self.state.display().to_string(),
        );
        Self::add(
            env,
            "AINKRAD_SANDBOX_SECRETS",
            secret_dir.display().to_string(),
        );
        Self::add(env, "AINKRAD_SANDBOX_TMP", tmp.display().to_string());
        Self::add(env, "TMPDIR", tmp.display().to_string());
        // Harness adapters otherwise inherit the runner's HOME through their allow-list.
        // The process sandbox still owns the filesystem boundary; this makes HOME harmless
        // even on systems whose Seatbelt profile cannot hide a pre-existing home directory.
        Self::add(env, "HOME", "/nonexistent");
        let network = std::env::var("AINKRAD_AGENT_NETWORK").unwrap_or_else(|_| "allow".into());
        if !matches!(network.as_str(), "allow" | "deny") {
            return Err("AINKRAD_AGENT_NETWORK must be allow or deny".into());
        }
        Self::add(env, "AINKRAD_SANDBOX_NETWORK", network);
        Self::add(
            env,
            "AINKRAD_SANDBOX_PGID_FILE",
            self.state
                .join("agents")
                .join(session)
                .join("pgid")
                .display()
                .to_string(),
        );
        for (key, default) in [
            ("PROCESSES", u64::from(DEFAULT_PROCESSES)),
            ("CPU", 900_u64),
            ("MEMORY", 4194304),
            ("FILE", 1048576),
            ("DISK", 1048576),
        ] {
            let value = std::env::var(format!("AINKRAD_AGENT_{key}"))
                .unwrap_or_else(|_| default.to_string());
            if !value.parse::<u64>().is_ok_and(|n| n > 0) {
                return Err(format!("invalid {key} limit"));
            }
            Self::add(env, &format!("AINKRAD_SANDBOX_{key}"), value);
        }
        Ok(())
    }
}
