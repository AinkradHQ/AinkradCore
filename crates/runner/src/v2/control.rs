//! Runner control: the policy a Core sets from the App (`runner.policy`) and the tool installs
//! (`tools.install`, `tools.status`), as one `control` driver every runner lists.
//!
//! The policy is three settings (terminals, agents, agent capacity). It lives in `<state>/policy.json`
//! (0600, the runner's own state dir), read at start, and overrides the matching `RUNNER_ARGS`
//! flags (`--enable-pty`, `--enable-agents`) and the default capacity. A command saves it, answers,
//! and a second later the runner stops with exit status [`EXIT_RESTART`], which systemd (`Restart=
//! on-failure`) and launchd (`KeepAlive`) start again with the file read. Terminals live in their own
//! host processes and survive the restart; turning terminals off closes them first.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ainkrad_proto::v2::{
    DRIVER_CONTROL, DriverInfo, ErrorCode, OP_RUNNER_POLICY, OP_TOOLS_INSTALL, OP_TOOLS_STATUS,
    PolicyApplied, RunnerPolicy, StreamError, Tool, ToolsInstall,
};
use tokio::sync::watch;

use super::PtyDriver;
use super::tools::ToolsDriver;

/// `connect`'s exit status after a policy change: not 0 (a supervisor with `Restart=on-failure`
/// restarts it), not 6 (rejected by the Core: never restarted).
pub const EXIT_RESTART: u8 = 75;

const FILE: &str = "policy.json";

/// What the Core's command may not do: an agent count outside 1 to 8 is refused by `valid`.
pub fn load(state: &Path) -> Option<RunnerPolicy> {
    let text = std::fs::read_to_string(state.join(FILE)).ok()?;
    serde_json::from_str::<RunnerPolicy>(&text)
        .ok()
        .filter(RunnerPolicy::valid)
}

fn save(state: &Path, p: &RunnerPolicy) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = state.join(format!("{FILE}.tmp"));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(
        serde_json::to_string(p)
            .map_err(std::io::Error::other)?
            .as_bytes(),
    )?;
    f.sync_all()?;
    std::fs::rename(&tmp, state.join(FILE))
}

/// Whether this runner can run agent sessions: a process sandbox, the egress filter proven on this
/// host, and one harness installed. `Err` is the reason, in words for the App.
pub async fn precheck_agents(state: &Path) -> Result<(), String> {
    if !super::ProcessSandbox::available_here() {
        return Err(
            "the agent sandbox cannot run on this host (bubblewrap is missing or blocked)".into(),
        );
    }
    if std::env::var("AINKRAD_AGENT_NETWORK").as_deref() != Ok("filtered") {
        return Err("the egress filter is not set up on this runner (AINKRAD_AGENT_NETWORK=filtered is missing from its runner.env); re-run the runner installer".into());
    }
    let [_, work] = super::cli::runtime_paths(state);
    let mut executor = crate::HarnessExecutor::new(work, state.join("agents-config"));
    super::cli::egress_filter(&mut executor).await?;
    if executor.probe(Duration::from_secs(10)).await.is_empty() {
        return Err(
            "no agent tool (claude, codex) is installed on this runner; install one first".into(),
        );
    }
    Ok(())
}

/// The control driver's state, shared by the session of every connection.
pub struct Control {
    pub state: PathBuf,
    /// What this process runs with now.
    pub active: RunnerPolicy,
    pub tools: Arc<ToolsDriver>,
    pub pty: Option<Arc<PtyDriver>>,
    /// Set before `stop` turns true when the stop is a restart.
    pub restart: Arc<AtomicBool>,
    pub stop: Arc<watch::Sender<bool>>,
}

impl Control {
    pub fn info() -> DriverInfo {
        DriverInfo {
            name: DRIVER_CONTROL.to_owned(),
            commands: [OP_RUNNER_POLICY, OP_TOOLS_INSTALL, OP_TOOLS_STATUS]
                .map(str::to_owned)
                .into(),
            capacity: 4,
            ..DriverInfo::default()
        }
    }

    /// Stops this process after `after`, as a restart.
    fn restart_after(self: &Arc<Self>, after: Duration) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            me.restart.store(true, Ordering::SeqCst);
            me.stop.send_replace(true);
        });
    }

    /// `runner.policy`: validate, check what it needs, save, and restart when it changes what runs.
    pub async fn set_policy(
        self: &Arc<Self>,
        p: RunnerPolicy,
    ) -> Result<PolicyApplied, StreamError> {
        let bad = |code, why: String| StreamError::new(code, why);
        if !p.valid() {
            return Err(bad(
                ErrorCode::InvalidArgs,
                "agent_capacity must be from 1 to 8".to_owned(),
            ));
        }
        if p.agents && !self.active.agents {
            precheck_agents(&self.state)
                .await
                .map_err(|why| bad(ErrorCode::InvalidArgs, why))?;
        }
        save(&self.state, &p)
            .map_err(|e| bad(ErrorCode::Internal, format!("saving the policy: {e}")))?;
        let restarting = p != self.active;
        if restarting {
            if !p.terminals
                && let Some(pty) = &self.pty
            {
                for t in pty.terminals().await {
                    let _ = pty.close(&t.terminal).await;
                }
            }
            self.restart_after(Duration::from_secs(1));
        }
        Ok(PolicyApplied {
            policy: p,
            restarting,
        })
    }

    /// `tools.install`: after a harness tool landed on a runner that offers agents, it restarts to
    /// pick the new tool up (the agent driver reads its harnesses at start), once the Core has had
    /// time to read the `done` status.
    pub fn install_tool(
        self: &Arc<Self>,
        req: ToolsInstall,
    ) -> Result<ainkrad_proto::v2::ToolsStatus, StreamError> {
        let me = Arc::clone(self);
        self.tools.install(req, move |tool| {
            if me.active.agents && matches!(tool, Tool::Claude | Tool::Codex) {
                me.restart_after(Duration::from_secs(5));
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "akc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn control(state: &Path, active: RunnerPolicy) -> (Arc<Control>, watch::Receiver<bool>) {
        let (stop, stopping) = watch::channel(false);
        let c = Control {
            state: state.to_path_buf(),
            active,
            tools: ToolsDriver::new("/nonexistent"),
            pty: None,
            restart: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(stop),
        };
        (Arc::new(c), stopping)
    }

    const OFF: RunnerPolicy = RunnerPolicy {
        terminals: false,
        agents: false,
        agent_capacity: 2,
        share_history: false,
    };

    #[test]
    fn a_saved_policy_reads_back_private_and_a_bad_one_is_ignored() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir();
        assert_eq!(load(&d), None);
        let p = RunnerPolicy {
            terminals: true,
            agents: false,
            agent_capacity: 5,
            share_history: false,
        };
        save(&d, &p).unwrap();
        assert_eq!(load(&d), Some(p));
        assert_eq!(
            std::fs::metadata(d.join(FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::write(
            d.join(FILE),
            r#"{"terminals":true,"agents":true,"agent_capacity":99}"#,
        )
        .unwrap();
        assert_eq!(load(&d), None, "out of range");
        std::fs::write(d.join(FILE), "garbage").unwrap();
        assert_eq!(load(&d), None);
    }

    #[tokio::test]
    async fn a_change_is_saved_and_restarts_the_runner_with_the_restart_status() {
        let d = dir();
        let (c, mut stopping) = control(&d, OFF);
        let want = RunnerPolicy {
            terminals: true,
            ..OFF
        };
        let a = c.set_policy(want).await.unwrap();
        assert!(a.restarting);
        assert_eq!(load(&d), Some(want));
        tokio::time::timeout(Duration::from_secs(5), stopping.wait_for(|s| *s))
            .await
            .unwrap()
            .unwrap();
        assert!(c.restart.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn the_same_policy_saves_without_a_restart_and_a_bad_capacity_is_refused() {
        let d = dir();
        let (c, stopping) = control(&d, OFF);
        assert!(!c.set_policy(OFF).await.unwrap().restarting);
        tokio::time::sleep(Duration::from_millis(1200)).await;
        assert!(!*stopping.borrow());
        for n in [0, 9] {
            let e = c
                .set_policy(RunnerPolicy {
                    agent_capacity: n,
                    ..OFF
                })
                .await
                .unwrap_err();
            assert_eq!(e.code, ErrorCode::InvalidArgs);
        }
    }

    #[tokio::test]
    async fn agents_are_refused_with_the_reason_when_the_host_cannot_run_them() {
        // No egress filter is configured in the test environment, so the reason names it (or the sandbox, where bwrap is absent).
        let d = dir();
        let (c, _stopping) = control(&d, OFF);
        let e = c
            .set_policy(RunnerPolicy {
                agents: true,
                ..OFF
            })
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidArgs);
        assert!(
            e.message.contains("sandbox") || e.message.contains("egress"),
            "{}",
            e.message
        );
        assert_eq!(load(&d), None, "a refused policy is not saved");
    }
}
