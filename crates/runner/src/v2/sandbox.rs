//! Process isolation for agent harnesses (E2-09).

use std::path::PathBuf;
use std::process::Command;

use ainkrad_proto::runner::{Isolation, Policy, WorkspaceMode};
use ainkrad_proto::v2::AgentStart;

use super::agent::Sandbox;

const DEFAULT_PROCESSES: u32 = 64;

/// The network policy of one session (`AINKRAD_SANDBOX_NETWORK`). A session that holds leased
/// secrets (`holds`) defaults to `deny`: an agent that can read a secret can send it anywhere
/// the sandbox reaches. Explicit `allow` for such a session is refused on Linux, where
/// bubblewrap would share the host network (cloud metadata, LAN, loopback) with no filter;
/// macOS Seatbelt limits egress to TCP 443, DNS and loopback. Without secrets the default is
/// `allow` on macOS; on Linux it is `deny` too, unless an admin sets `allow` for a stage-1 host.
fn network_for(requested: Option<&str>, holds: bool, linux: bool) -> Result<&'static str, String> {
    match (requested, holds) {
        (None, true) | (Some("deny"), _) => Ok("deny"),
        // Linux has no egress filter: even a run holding only its MCP token gets no host
        // network by default (the MCP route is bridged in, see `mcp_bridge`).
        (None, false) if linux => Ok("deny"),
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

/// Applies the session policy's isolation fields to the process sandbox's environment, after the
/// runner's own limits are in `env`: a cap can only lower the runner's, the wall-clock cap is
/// the host's, and every field a process sandbox cannot honour refuses the session (it is never
/// ignored, which would be a weaker sandbox than the policy asked for).
///
/// `memory_mb` and `disk_mb` ride the same sampled watchdog as the runner's own caps (a 100 ms
/// aggregate-RSS and disk walk that kills the tree): a process-level budget, not a quota.
fn apply_policy(policy: &Policy, env: &mut Vec<(String, String)>) -> Result<(), String> {
    for (field, set) in [
        ("image", policy.image.is_some()),
        ("vcpus", policy.vcpus.is_some()),
        (
            "workspace copy",
            policy.workspace == Some(WorkspaceMode::Copy),
        ),
        // The session's rules would narrow the runner's allowlist; until that intersection is
        // wired, accepting them would be a policy the sandbox does not enforce.
        ("egress", policy.egress.is_some()),
    ] {
        if set {
            return Err(format!(
                "the policy sets {field}, which the process sandbox cannot enforce; refusing the session"
            ));
        }
    }
    for (var, mb) in [
        ("AINKRAD_SANDBOX_MEMORY", policy.memory_mb),
        ("AINKRAD_SANDBOX_DISK", policy.disk_mb),
    ] {
        let Some(mb) = mb else { continue };
        let cap = u64::from(mb) * 1024;
        let entry = env
            .iter_mut()
            .find(|(n, _)| n == var)
            .ok_or_else(|| format!("{var} is missing"))?;
        let runner = entry
            .1
            .parse::<u64>()
            .map_err(|_| format!("invalid {var}"))?;
        entry.1 = runner.min(cap).to_string();
    }
    if let Some(secs) = policy.wall_secs {
        env.push(("AINKRAD_SANDBOX_WALL".to_owned(), secs.to_string()));
    }
    Ok(())
}

impl Sandbox for ProcessSandbox {
    fn name(&self) -> &'static str {
        if cfg!(target_os = "macos") {
            "seatbelt"
        } else {
            "bubblewrap"
        }
    }

    fn tier(&self) -> Isolation {
        Isolation::Process
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
        let requested = std::env::var("AINKRAD_AGENT_NETWORK").ok();
        let network = network_for(requested.as_deref(), holds, cfg!(target_os = "linux"))?;
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
        apply_policy(&start.policy, env)
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_policy, network_for};
    use ainkrad_proto::runner::{Egress, Policy, WorkspaceMode};

    #[test]
    fn secrets_default_to_deny_and_linux_refuses_unfiltered_allow() {
        assert_eq!(network_for(None, true, true), Ok("deny"));
        assert_eq!(network_for(None, true, false), Ok("deny"));
        assert_eq!(network_for(Some("deny"), true, true), Ok("deny"));
        assert!(network_for(Some("allow"), true, true).is_err());
        assert_eq!(network_for(Some("allow"), true, false), Ok("allow"));
        assert_eq!(network_for(None, false, true), Ok("deny"));
        assert_eq!(network_for(None, false, false), Ok("allow"));
        assert_eq!(network_for(Some("allow"), false, true), Ok("allow"));
        assert!(network_for(Some("lan"), false, false).is_err());
    }

    fn runner_env() -> Vec<(String, String)> {
        [
            ("AINKRAD_SANDBOX_MEMORY", "4194304"),
            ("AINKRAD_SANDBOX_DISK", "1048576"),
        ]
        .map(|(n, v)| (n.to_owned(), v.to_owned()))
        .to_vec()
    }

    fn value(env: &[(String, String)], name: &str) -> Option<String> {
        env.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
    }

    #[test]
    fn a_policy_cap_lowers_the_runners_never_raises_it() {
        let mut env = runner_env();
        let policy = Policy {
            memory_mb: Some(512),
            disk_mb: Some(100_000),
            wall_secs: Some(90),
            ..Policy::default()
        };
        apply_policy(&policy, &mut env).unwrap();
        assert_eq!(
            value(&env, "AINKRAD_SANDBOX_MEMORY").as_deref(),
            Some("524288")
        );
        // 100000 MiB is above the runner's 1 GiB disk cap: the runner's stays.
        assert_eq!(
            value(&env, "AINKRAD_SANDBOX_DISK").as_deref(),
            Some("1048576")
        );
        assert_eq!(value(&env, "AINKRAD_SANDBOX_WALL").as_deref(), Some("90"));
    }

    #[test]
    fn a_policy_with_no_isolation_fields_changes_nothing() {
        let mut env = runner_env();
        apply_policy(&Policy::default(), &mut env).unwrap();
        assert_eq!(env, runner_env());
        assert_eq!(value(&env, "AINKRAD_SANDBOX_WALL"), None);
    }

    #[test]
    fn a_field_the_process_sandbox_cannot_enforce_refuses_the_session() {
        for (field, policy) in [
            (
                "image",
                Policy {
                    image: Some(format!("sha256:{}", "ab".repeat(32))),
                    ..Policy::default()
                },
            ),
            (
                "vcpus",
                Policy {
                    vcpus: Some(2),
                    ..Policy::default()
                },
            ),
            (
                "workspace copy",
                Policy {
                    workspace: Some(WorkspaceMode::Copy),
                    ..Policy::default()
                },
            ),
            (
                "egress",
                Policy {
                    egress: Some(Egress::default()),
                    ..Policy::default()
                },
            ),
        ] {
            let mut env = runner_env();
            let why = apply_policy(&policy, &mut env).unwrap_err();
            assert!(why.contains(field), "{field}: {why}");
            assert_eq!(env, runner_env(), "{field}: a refusal leaves the env alone");
        }
        // The workspace mode the process tier does have is accepted.
        let bind = Policy {
            workspace: Some(WorkspaceMode::Bind),
            ..Policy::default()
        };
        assert!(apply_policy(&bind, &mut runner_env()).is_ok());
    }
}
