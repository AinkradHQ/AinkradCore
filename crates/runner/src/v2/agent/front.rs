//! The driver's side of the connection tools socket (C4b): the Core's `agent.tools` poll, and the
//! per-session socket opened before the harness's sandbox is built.

use super::*;

impl AgentDriver {
    /// The Core's `agent.tools` poll (C4): see [`tools::Tools::poll_live`]. Only a runner that lists
    /// the capability serves it, and only for a running session whose socket was opened here: an
    /// ended session is as good as unknown, and a late poll never makes its state again.
    pub async fn tools(
        &self,
        req: &ainkrad_proto::v2::ToolsPoll,
    ) -> Result<ainkrad_proto::v2::ToolBatch, StreamError> {
        let caps = self.sandbox.capabilities();
        if !caps.contains(&ainkrad_proto::v2::CAP_TOOLS) {
            return Err(refuse(
                ErrorCode::UnsupportedCommand,
                "this runner does not offer the connection tools",
            ));
        }
        let running = self
            .sessions
            .lock()
            .unwrap()
            .get(&req.session)
            .is_some_and(|l| l.meta.state == AgentState::Running);
        if !running {
            return Err(no_session());
        }
        // A session that is running but whose socket is not open yet (its start is still setting up)
        // has no tool state to hold the list: not ready, and the Core sends the poll again.
        self.tools.poll_live(req, MAX_WAIT).await.ok_or_else(|| {
            refuse(
                ErrorCode::Busy,
                "the session's connection tools are not ready; poll again",
            )
        })
    }

    /// Shares `tools` with the harness executor, which checks a connection tool's name against what
    /// the Core listed (`HarnessExecutor::tools`). Set before the first session.
    pub fn with_tools(mut self, tools: Arc<tools::Tools>) -> Self {
        self.tools = tools;
        self
    }

    /// Opens the session's socket (a runner that does not offer the capability opens none) and
    /// gives the sandbox's slot variables. A failure does not fail the session: it runs without
    /// connection tools, and its transcript says so.
    pub(super) fn start_front(&self, session: &str) -> Vec<(String, String)> {
        if !self
            .sandbox
            .capabilities()
            .contains(&ainkrad_proto::v2::CAP_TOOLS)
        {
            return Vec::new();
        }
        match self.open_tools(session) {
            Ok((front, env)) => {
                self.with(session, |live, _, _| {
                    if !live.stopped {
                        live.front = Some(front);
                    }
                });
                env
            }
            Err(why) => {
                tracing::warn!(session = %session, "connection tools unavailable: {why}");
                let entry = json!({"type": "connection_tools_unavailable", "reason": why});
                self.with(session, |live, cfg, s| push(cfg, s, live, entry));
                Vec::new()
            }
        }
    }

    fn open_tools(
        &self,
        session: &str,
    ) -> Result<(tools::sock::Front, Vec<(String, String)>), String> {
        let dir = self.config.dir.join(session);
        secrets::private_dir(&dir).map_err(|e| format!("the session directory: {e}"))?;
        let sock = tools::sock::socket_in(&dir);
        let exe = std::env::current_exe().map_err(|e| format!("the shim: {e}"))?;
        // The state first, then the socket: a poll of the Core finds it as soon as a harness could.
        self.tools.open(session);
        let front = tools::sock::start(&sock, Arc::clone(&self.tools), session)
            .map_err(|e| format!("the tools socket: {e}"))?;
        Ok((front, tools::sock::sandbox_env(&sock, &exe)))
    }
}
