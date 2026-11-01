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
/// `allow` on macOS; on Linux it is `deny` too, unless an admin sets `allow` for a stage-1 host.
///
/// `filtered` (Linux, E8a-01) is the enforceable middle: the sandbox has no network interface and
/// reaches only the destinations the runner's egress policy lists, through a proxy outside it.
/// It is offered only by a runner whose start-up self-test passed (`ready`), never maps to
/// `allow`, and is refused (not downgraded) anywhere else.
fn network_for(
    requested: Option<&str>,
    holds: bool,
    linux: bool,
    ready: bool,
) -> Result<&'static str, String> {
    match (requested, holds) {
        (Some("filtered"), _) if linux && ready => Ok("filtered"),
        (Some("filtered"), _) => Err("AINKRAD_AGENT_NETWORK=filtered needs a Linux runner whose \
            egress filter passed its start-up check"
            .into()),
        (None, true) | (Some("deny"), _) => Ok("deny"),
        // Linux has no egress filter: even a run holding only its MCP token gets no host
        // network by default (the MCP route is bridged in, see `mcp_bridge`).
        (None, false) if linux => Ok("deny"),
        (None, false) | (Some("allow"), false) => Ok("allow"),
        (Some("allow"), true) if !linux => Ok("allow"),
        (Some("allow"), true) => Err("this host cannot filter egress for an agent network: a \
            session that holds secrets runs with AINKRAD_AGENT_NETWORK=deny or filtered"
            .into()),
        _ => Err("AINKRAD_AGENT_NETWORK must be allow, deny or filtered".into()),
    }
}

pub struct ProcessSandbox {
    state: PathBuf,
    secrets: PathBuf,
    /// The egress filter passed its start-up self-test (`egress::selftest`).
    egress_ready: bool,
    /// `AINKRAD_AGENT_NETWORK`, read once when the driver started: a later change of the
    /// process environment does not change what a session gets.
    requested: Option<String>,
}

impl ProcessSandbox {
    pub fn new(state: PathBuf, secrets: PathBuf) -> Self {
        Self {
            state,
            secrets,
            egress_ready: false,
            requested: None,
        }
    }

    /// The runner's `AINKRAD_AGENT_NETWORK` (`allow`, `deny`, `filtered`); `None` is the default.
    pub fn with_network(mut self, requested: Option<String>) -> Self {
        self.requested = requested;
        self
    }

    /// Marks the egress filter as proven on this host: `filtered` sessions are accepted and the
    /// `egress-filter` capability is advertised.
    pub fn with_egress_ready(mut self) -> Self {
        self.egress_ready = true;
        self
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

    fn capabilities(&self) -> &'static [&'static str] {
        if self.egress_ready {
            &["egress-filter"]
        } else {
            &[]
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
        // The run token goes to the harness's private MCP config, not to the secrets dir: a session
        // whose only grant is the token has no dir, and that is not a failure.
        let delivered = start
            .secrets
            .iter()
            .any(|s| s.var != super::agent::RUN_TOKEN_VAR);
        if !secret_dir.exists() && delivered {
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
        let requested = self.requested.clone();
        let network = network_for(
            requested.as_deref(),
            holds,
            cfg!(target_os = "linux"),
            self.egress_ready,
        )?;
        if network == "allow" && requested.is_some() {
            tracing::warn!(session = %session, holds, "AINKRAD_AGENT_NETWORK=allow: this agent session has the host network");
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

#[cfg(test)]
mod tests {
    use super::{ProcessSandbox, network_for};
    use crate::v2::agent::Sandbox;

    #[test]
    fn secrets_default_to_deny_and_linux_refuses_unfiltered_allow() {
        assert_eq!(network_for(None, true, true, false), Ok("deny"));
        assert_eq!(network_for(None, true, false, false), Ok("deny"));
        assert_eq!(network_for(Some("deny"), true, true, false), Ok("deny"));
        assert!(network_for(Some("allow"), true, true, false).is_err());
        assert_eq!(network_for(Some("allow"), true, false, false), Ok("allow"));
        assert_eq!(network_for(None, false, true, false), Ok("deny"));
        assert_eq!(network_for(None, false, false, false), Ok("allow"));
        assert_eq!(network_for(Some("allow"), false, true, false), Ok("allow"));
        assert!(network_for(Some("lan"), false, false, false).is_err());
    }

    #[test]
    fn filtered_is_offered_only_on_a_proven_linux_runner_and_never_becomes_allow() {
        for holds in [true, false] {
            assert_eq!(
                network_for(Some("filtered"), holds, true, true),
                Ok("filtered")
            );
            // Not proven, or not Linux: refused, never downgraded to deny or allow.
            assert!(network_for(Some("filtered"), holds, true, false).is_err());
            assert!(network_for(Some("filtered"), holds, false, true).is_err());
            assert!(network_for(Some("filtered"), holds, false, false).is_err());
        }
        // The default stays `deny` even on a proven runner: filtered is an explicit choice.
        assert_eq!(network_for(None, true, true, true), Ok("deny"));
        assert_eq!(network_for(None, false, true, true), Ok("deny"));
    }

    #[test]
    fn the_capability_is_advertised_only_when_proven() {
        let sandbox = ProcessSandbox::new("/state".into(), "/secrets".into());
        assert!(sandbox.capabilities().is_empty());
        assert_eq!(
            sandbox.with_egress_ready().capabilities(),
            ["egress-filter"]
        );
    }
}
