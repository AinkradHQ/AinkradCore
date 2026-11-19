//! `command` and `result` payloads, tagged by `op`. A command's op belongs to the driver
//! that lists it in `RunnerHello::drivers`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The ops of the `exec` driver.
pub const OP_NOOP: &str = "noop";
pub const OP_EXEC_RUN: &str = "exec.run";

/// Core to runner, the first frame of a command stream.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op")]
// `AgentStart` carries a policy with the isolation fields (E8a-08); a frame is built once and sent.
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Answers `result` at once: proves the path end to end.
    #[serde(rename = "noop")]
    Noop,
    #[serde(rename = "exec.run")]
    ExecRun(ExecRun),
    #[serde(rename = "pty.open")]
    PtyOpen(super::PtyOpen),
    #[serde(rename = "pty.attach")]
    PtyAttach(super::PtyAttach),
    #[serde(rename = "pty.close")]
    PtyClose(super::PtyClose),
    #[serde(rename = "agent.start")]
    AgentStart(super::AgentStart),
    #[serde(rename = "agent.read")]
    AgentRead(super::AgentRead),
    #[serde(rename = "agent.send")]
    AgentSend(super::AgentSend),
    #[serde(rename = "agent.decide")]
    AgentDecide(super::AgentDecide),
    #[serde(rename = "agent.stop")]
    AgentStop(super::AgentStop),
    #[serde(rename = "agent.limit")]
    AgentLimit(super::AgentLimit),
    #[serde(rename = "gateway.test")]
    GatewayTest(super::GatewayTest),
    #[serde(rename = "login.start")]
    LoginStart(super::LoginStart),
    #[serde(rename = "login.code")]
    LoginCode(super::LoginCode),
    #[serde(rename = "login.cancel")]
    LoginCancel(super::LoginCancel),
    // After every older op: the schema-compat gate tells variants by position.
    #[serde(rename = "agent.tools")]
    AgentTools(super::ToolsPoll),
    #[serde(rename = "runner.policy")]
    RunnerPolicy(super::RunnerPolicy),
    #[serde(rename = "tools.install")]
    ToolsInstall(super::ToolsInstall),
    #[serde(rename = "tools.status")]
    ToolsStatus(super::ToolsStatusReq),
    #[serde(rename = "plan.check")]
    PlanCheck(super::PlanCheck),
    #[serde(rename = "history.read")]
    HistoryRead(super::HistoryRead),
    #[serde(rename = "agent.mode")]
    AgentMode(super::AgentMode),
    #[serde(rename = "agent.attach")]
    AgentAttach(super::AgentAttach),
    #[serde(rename = "agent.subagent_stop")]
    AgentSubagentStop(super::AgentSubagentStop),
    #[serde(rename = "ssh.exec")]
    SshExec(super::SshExec),
    #[serde(rename = "ssh.sftp.list")]
    SshSftpList(super::SftpList),
    #[serde(rename = "ssh.sftp.stat")]
    SshSftpStat(super::SftpStat),
    #[serde(rename = "ssh.sftp.read")]
    SshSftpRead(super::SftpRead),
    #[serde(rename = "ssh.sftp.write")]
    SshSftpWrite(super::SftpWrite),
    #[serde(rename = "ssh.sftp.mkdir")]
    SshSftpMkdir(super::SftpMkdir),
    #[serde(rename = "ssh.sftp.rename")]
    SshSftpRename(super::SftpRename),
    #[serde(rename = "ssh.sftp.remove")]
    SshSftpRemove(super::SftpRemove),
    #[serde(rename = "design.render")]
    DesignRender(super::DesignRender),
    #[serde(rename = "design.measure")]
    DesignMeasure(super::DesignMeasure),
    #[serde(rename = "design.review")]
    DesignReview(super::DesignReview),
    #[serde(rename = "design.check")]
    DesignCheck(super::DesignCheck),
    #[serde(rename = "design.shot")]
    DesignShot(super::DesignShot),
    #[serde(rename = "design.export")]
    DesignExport(super::DesignExport),
    #[serde(rename = "design.fidelity")]
    DesignFidelity(super::DesignFidelity),
    #[serde(rename = "ssh.agent.load")]
    SshAgentLoad(super::SshAgentLoad),
    #[serde(rename = "ssh.agent.drop")]
    SshAgentDrop(super::SshAgentDrop),
    #[serde(rename = "run.start")]
    RunStart(super::RunStart),
    #[serde(rename = "run.stop")]
    RunStop(super::RunStop),
    #[serde(rename = "run.status")]
    RunStatus(super::RunStatusReq),
    #[serde(rename = "run.observe")]
    RunObserve(super::RunObserveReq),
    /// A TCP stream to an exposed port of a live run (P6-01); bytes are `output` frames.
    #[serde(rename = "port.open")]
    PortOpen(super::PortOpen),
    // After every older op: the schema-compat gate tells variants by position.
    #[serde(rename = "agent.files")]
    AgentFiles(super::AgentFiles),
    #[serde(rename = "agent.revert")]
    AgentRevert(super::AgentRevert),
    #[serde(rename = "agent.write")]
    AgentWrite(super::AgentWrite),
    /// An op from a newer Core: answered `unsupported_command`. Never sent.
    #[serde(other)]
    Unknown,
}

impl Command {
    /// The op on the wire, as drivers list it.
    pub fn op(&self) -> &'static str {
        match self {
            Self::Noop => OP_NOOP,
            Self::ExecRun(_) => OP_EXEC_RUN,
            Self::PtyOpen(_) => super::OP_PTY_OPEN,
            Self::PtyAttach(_) => super::OP_PTY_ATTACH,
            Self::PtyClose(_) => super::OP_PTY_CLOSE,
            Self::AgentStart(_) => super::OP_AGENT_START,
            Self::AgentRead(_) => super::OP_AGENT_READ,
            Self::AgentSend(_) => super::OP_AGENT_SEND,
            Self::AgentDecide(_) => super::OP_AGENT_DECIDE,
            Self::AgentStop(_) => super::OP_AGENT_STOP,
            Self::AgentLimit(_) => super::OP_AGENT_LIMIT,
            Self::GatewayTest(_) => super::OP_GATEWAY_TEST,
            Self::AgentTools(_) => super::OP_AGENT_TOOLS,
            Self::PlanCheck(_) => super::OP_PLAN_CHECK,
            Self::HistoryRead(_) => super::OP_HISTORY_READ,
            Self::AgentMode(_) => super::OP_AGENT_MODE,
            Self::AgentAttach(_) => super::OP_AGENT_ATTACH,
            Self::AgentSubagentStop(_) => super::OP_AGENT_SUBAGENT_STOP,
            Self::LoginStart(_) => super::OP_LOGIN_START,
            Self::LoginCode(_) => super::OP_LOGIN_CODE,
            Self::LoginCancel(_) => super::OP_LOGIN_CANCEL,
            Self::RunnerPolicy(_) => super::OP_RUNNER_POLICY,
            Self::ToolsInstall(_) => super::OP_TOOLS_INSTALL,
            Self::ToolsStatus(_) => super::OP_TOOLS_STATUS,
            Self::SshExec(_) => super::OP_SSH_EXEC,
            Self::SshSftpList(_) => super::OP_SFTP_LIST,
            Self::SshSftpStat(_) => super::OP_SFTP_STAT,
            Self::SshSftpRead(_) => super::OP_SFTP_READ,
            Self::SshSftpWrite(_) => super::OP_SFTP_WRITE,
            Self::SshSftpMkdir(_) => super::OP_SFTP_MKDIR,
            Self::SshSftpRename(_) => super::OP_SFTP_RENAME,
            Self::SshSftpRemove(_) => super::OP_SFTP_REMOVE,
            Self::DesignRender(_) => super::OP_DESIGN_RENDER,
            Self::DesignMeasure(_) => super::OP_DESIGN_MEASURE,
            Self::DesignReview(_) => super::OP_DESIGN_REVIEW,
            Self::DesignCheck(_) => super::OP_DESIGN_CHECK,
            Self::DesignShot(_) => super::OP_DESIGN_SHOT,
            Self::DesignExport(_) => super::OP_DESIGN_EXPORT,
            Self::DesignFidelity(_) => super::OP_DESIGN_FIDELITY,
            Self::SshAgentLoad(_) => super::OP_SSH_AGENT_LOAD,
            Self::SshAgentDrop(_) => super::OP_SSH_AGENT_DROP,
            Self::RunStart(_) => super::OP_RUN_START,
            Self::RunStop(_) => super::OP_RUN_STOP,
            Self::RunStatus(_) => super::OP_RUN_STATUS,
            Self::RunObserve(_) => super::OP_RUN_OBSERVE,
            Self::PortOpen(_) => super::OP_PORT_OPEN,
            Self::AgentFiles(_) => super::OP_AGENT_FILES,
            Self::AgentRevert(_) => super::OP_AGENT_REVERT,
            Self::AgentWrite(_) => super::OP_AGENT_WRITE,
            Self::Unknown => "unknown",
        }
    }
}

/// Runs `program args…` to its end, bounded, and answers with its exit and output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExecRun {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// An absolute directory; absent, the runner's own working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Variables set in the child as given.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Names of the runner's own variables to pass on. Only those also on the runner's
    /// allow-list are; the child's environment starts empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_pass: Vec<String>,
    #[serde(default)]
    pub limits: ExecLimits,
}

/// What the Core asks for; the runner clamps each to its own ceiling and uses its default
/// for an absent one.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
pub struct ExecLimits {
    /// Wall clock until the process group gets TERM, then KILL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// The most of stdout, and of stderr, kept; the rest is dropped and marked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u64>,
}

/// Runner to Core, a command's last frame when it ran.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op")]
pub enum Reply {
    #[serde(rename = "noop")]
    Noop,
    #[serde(rename = "exec.run")]
    ExecRun(ExecResult),
    /// A terminal's exit, on the stream of the op that saw it.
    #[serde(rename = "pty.open")]
    PtyOpen(super::TerminalExit),
    #[serde(rename = "pty.attach")]
    PtyAttach(super::TerminalExit),
    #[serde(rename = "pty.close")]
    PtyClose(super::TerminalExit),
    /// Every `agent.*` op answers with the session's state (`agent.read` with its entries).
    #[serde(rename = "agent.start")]
    AgentStart(super::AgentEvents),
    #[serde(rename = "agent.read")]
    AgentRead(super::AgentEvents),
    #[serde(rename = "agent.send")]
    AgentSend(super::AgentEvents),
    #[serde(rename = "agent.decide")]
    AgentDecide(super::AgentEvents),
    #[serde(rename = "agent.stop")]
    AgentStop(super::AgentEvents),
    #[serde(rename = "agent.limit")]
    AgentLimit(super::AgentEvents),
    #[serde(rename = "gateway.test")]
    GatewayTest(super::GatewayTested),
    /// The answer to `login.start`.
    #[serde(rename = "login.url")]
    LoginUrl(super::LoginUrl),
    /// The answer to `login.code` and `login.cancel`.
    #[serde(rename = "login.result")]
    LoginResult(super::LoginResult),
    /// (After every older op, as `Command`'s.) The answer to `agent.tools`: the calls the harness made.
    #[serde(rename = "agent.tools")]
    AgentTools(super::ToolBatch),
    /// The answer to `runner.policy`.
    #[serde(rename = "runner.policy")]
    RunnerPolicy(super::PolicyApplied),
    /// The answer to `tools.install` and `tools.status`.
    #[serde(rename = "tools.status")]
    ToolsStatus(super::ToolsStatus),
    /// The answer to `plan.check`.
    #[serde(rename = "plan.check")]
    PlanCheck(super::PlanChecked),
    /// The answer to `history.read`.
    #[serde(rename = "history.read")]
    HistoryRead(super::HistoryChunk),
    #[serde(rename = "agent.mode")]
    AgentMode(super::AgentEvents),
    #[serde(rename = "agent.attach")]
    AgentAttach(super::AgentAttached),
    #[serde(rename = "agent.subagent_stop")]
    AgentSubagentStop(super::AgentEvents),
    /// The answer to `ssh.exec`.
    #[serde(rename = "ssh.exec")]
    SshExec(ExecResult),
    #[serde(rename = "ssh.sftp.list")]
    SshSftpList(super::SftpEntries),
    #[serde(rename = "ssh.sftp.stat")]
    SshSftpStat(super::SftpEntry),
    #[serde(rename = "ssh.sftp.read")]
    SshSftpRead(super::SftpTransferred),
    #[serde(rename = "ssh.sftp.write")]
    SshSftpWrite(super::SftpTransferred),
    #[serde(rename = "ssh.sftp.mkdir")]
    SshSftpMkdir(super::SftpDone),
    #[serde(rename = "ssh.sftp.rename")]
    SshSftpRename(super::SftpDone),
    #[serde(rename = "ssh.sftp.remove")]
    SshSftpRemove(super::SftpDone),
    #[serde(rename = "design.render")]
    DesignRender(super::DesignImage),
    #[serde(rename = "design.measure")]
    DesignMeasure(super::DesignBoxes),
    #[serde(rename = "design.review")]
    DesignReview(super::DesignFindings),
    #[serde(rename = "design.check")]
    DesignCheck(super::DesignChecked),
    #[serde(rename = "design.shot")]
    DesignShot(super::DesignImage),
    #[serde(rename = "design.export")]
    DesignExport(super::DesignExported),
    #[serde(rename = "design.fidelity")]
    DesignFidelity(super::DesignFidelityScore),
    #[serde(rename = "ssh.agent.load")]
    SshAgentLoad(super::SshAgentLoaded),
    #[serde(rename = "ssh.agent.drop")]
    SshAgentDrop(super::SshAgentDropped),
    /// `run.start` and `run.stop` answer with the run's state; `run.status` with every run asked for.
    #[serde(rename = "run.start")]
    RunStart(super::RunInfo),
    #[serde(rename = "run.stop")]
    RunStop(super::RunInfo),
    #[serde(rename = "run.status")]
    RunStatus(super::RunList),
    /// `run.observe`: service metrics and the new log lines of one run.
    #[serde(rename = "run.observe")]
    RunObserve(super::RunObserve),
    /// The last frame of `port.open`.
    #[serde(rename = "port.open")]
    PortOpen(super::PortClosed),
    #[serde(rename = "agent.files")]
    AgentFiles(super::AgentFolder),
    #[serde(rename = "agent.revert")]
    AgentRevert(super::AgentReverted),
    #[serde(rename = "agent.write")]
    AgentWrite(super::AgentWritten),
    /// An op from a newer runner. Never sent.
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ExecResult {
    /// Absent when it was ended by a signal (its timeout included).
    pub exit_code: Option<i32>,
    /// It ran past its timeout and was killed.
    pub timed_out: bool,
    pub duration_ms: u64,
    pub stdout: Captured,
    pub stderr: Captured,
}

/// One output pipe: redacted UTF-8 (lossy), cut at the limit with a marker.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Captured {
    pub text: String,
    /// How many bytes the process wrote, kept or not.
    pub bytes: u64,
    /// `text` was cut at the limit and ends in `TRUNCATED_MARKER`.
    pub truncated: bool,
}

/// What ends a cut `Captured::text`.
pub const TRUNCATED_MARKER: &str = "\n[output truncated]";
