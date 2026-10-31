//! Process isolation for agent harnesses (E2-09).

use std::path::PathBuf;
use std::process::Command;

use ainkrad_proto::v2::AgentStart;

use super::agent::Sandbox;

const DEFAULT_PROCESSES: u32 = 64;

/// The network policy of one session (`AINKRAD_SANDBOX_NETWORK`). A session that holds leased
/// secrets (`holds`) defaults to `deny`: an agent that can read a secret can send it anywhere
/// the sandbox reaches. Explicit `allow` for such a session is refused on Linux, where
/// bubblewrap would share the host network (cloud metadata, LAN, loopback) with no filter;
/// macOS Seatbelt limits egress to TCP 443, DNS and loopback. Without secrets the default is
/// `allow`, so on Linux that still needs a host with no instance role and nothing on loopback.
fn network_for(requested: Option<&str>, holds: bool, linux: bool) -> Result<&'static str, String> {
    match (requested, holds) {
        (None, true) | (Some("deny"), _) => Ok("deny"),
        (None, false) | (Some("allow"), false) => Ok("allow"),
        (Some("allow"), true) if !linux => Ok("allow"),
        (Some("allow"), true) => Err("this host cannot filter egress for an agent network: a \
            session that holds secrets runs with AINKRAD_AGENT_NETWORK=deny"
            .into()),
        _ => Err("AINKRAD_AGENT_NETWORK must be allow or deny".into()),
    }
}

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
        let holds = start
            .secrets
            .iter()
            .any(|g| g.var != super::agent::RUN_TOKEN_VAR);
        let requested = std::env::var("AINKRAD_AGENT_NETWORK").ok();
        let network = network_for(requested.as_deref(), holds, cfg!(target_os = "linux"))?;
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

#[cfg(test)]
mod tests {
    use super::network_for;

    #[test]
    fn secrets_default_to_deny_and_linux_refuses_unfiltered_allow() {
        assert_eq!(network_for(None, true, true), Ok("deny"));
        assert_eq!(network_for(None, true, false), Ok("deny"));
        assert_eq!(network_for(Some("deny"), true, true), Ok("deny"));
        assert!(network_for(Some("allow"), true, true).is_err());
        assert_eq!(network_for(Some("allow"), true, false), Ok("allow"));
        assert_eq!(network_for(None, false, true), Ok("allow"));
        assert!(network_for(Some("lan"), false, false).is_err());
    }
}
