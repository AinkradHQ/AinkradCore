//! Every tunable (E15.17, decision #52): name, unit, default, bounds, scopes, meaning. A new
//! one is appended at the end: `Key` indexes `REGISTRY` by position.

use super::*;

registry! {
    RunTokenCap "run.token_cap" Tokens 2_000_000, 1_000, 100_000_000, SCP,
        "Tokens a run may use when no budget caps it lower; a run is never uncapped.";
    StuckAfterSecs "run.stuck_after_secs" Seconds STUCK_AFTER_SECS, 60, 7 * DAY, SCP,
        "How long an issue sits with no wake path, or a wake or queued run waits, before it \
         is reported stuck.";
    WakeMaxAttempts "wake.max_attempts" Count MAX_WAKE_ATTEMPTS, 1, 20, SCP,
        "Attempts a wake gets before a failure stops retrying and escalates.";
    RetryBackoffMaxSecs "wake.retry_backoff_max_secs" Seconds MAX_RETRY_BACKOFF_SECS, 30, DAY,
        SCP, "Longest wait before a retry (30 s, doubling per attempt, up to this).";
    LoopBreakerThreshold "breaker.loop_threshold" Count LOOP_BREAKER_THRESHOLD as i64, 2, 20,
        SCP, "Runs in a row on one agent and issue ending with the same failure before the \
              loop breaker stops retrying and escalates.";
    AgentBreakerTrips "breaker.agent_trips" Count AGENT_BREAKER_TRIPS, 1, 50, SC,
        "Loop-breaker trips of one agent within the window that pause it.";
    AgentBreakerWindowSecs "breaker.agent_window_secs" Seconds AGENT_BREAKER_WINDOW_SECS, 60,
        7 * DAY, SC, "The window agent trips are counted over.";
    LeaseTtlSecs "lease.ttl_secs" Seconds LEASE_TTL_SECS, 15, 3600, SR,
        "How long a run's lease lasts without a heartbeat; the runner renews every third.";
    KnowledgeBudgetBytes "knowledge.budget_bytes" Bytes KNOWLEDGE_BUDGET_BYTES as i64, 0,
        256 * 1024, SCP, "The most of its project's knowledge a run is given.";
    SkillBudgetBytes "skills.budget_bytes" Bytes SKILL_BUDGET_BYTES as i64, 0, 512 * 1024, SCP,
        "The most of its skills' bodies a run is given.";
    VelocityWindow "sprint.velocity_window" Count 3, 1, 20, SCP,
        "Closed sprints a sprint review compares its velocity against.";
    DeadlineSprintCommit "approval.deadline.sprint_commit" Seconds 0, 0, YEAR, SC,
        "How long a sprint commit approval waits before it expires; 0 waits until decided.";
    DeadlinePrMerge "approval.deadline.pr_merge" Seconds 0, 0, YEAR, SC,
        "How long a PR merge approval waits before it expires; 0 waits until decided.";
    DeadlineBudgetOverrun "approval.deadline.budget_overrun" Seconds 0, 0, YEAR, SC,
        "How long a budget overrun approval waits before it expires; 0 waits until decided.";
    DeadlineHireAgent "approval.deadline.hire_agent" Seconds 0, 0, YEAR, SC,
        "How long a hire approval waits before it expires; 0 waits until decided.";
    DeadlinePermissionEscalation "approval.deadline.permission_escalation" Seconds 900, 1,
        7 * DAY, SCP, "How long an escalated tool call waits for a reviewer before the runner \
                       denies it.";
    DeadlinePlanApproval "approval.deadline.plan_approval" Seconds 0, 0, YEAR, SC,
        "How long a requirement's plan approval waits before it expires; 0 waits until decided.";
    DeadlineWorkflowPush "approval.deadline.workflow_push" Seconds 0, 0, YEAR, SC,
        "How long a workflow push approval waits for a human to push before it expires; 0 waits \
         until decided.";
    BudgetWarnPercent "budget.warn_percent" Percent 80, 1, 100, SC,
        "A new budget's warning threshold when none is given.";
    AccountWarnPercent "account.warn_percent" Percent 80, 1, 100, SA,
        "Share of an account's limit (or of a harness-reported window) at which the admin is \
         warned; a new limit's default.";
    DropThreshold "account.drop_threshold" Count 3, 1, 100, SA,
        "Provider drops within the window that make an account unhealthy.";
    DropWindowSecs "account.drop_window_secs" Seconds 600, 60, DAY, SA,
        "The window provider drops are counted over.";
    UnhealthySecs "account.unhealthy_secs" Seconds 600, 60, 7 * DAY, SA,
        "How long an account that dropped too often stays unhealthy.";
    RefusalCoolOffSecs "account.refusal_cooloff_secs" Seconds 900, 60, DAY, SA,
        "How long an account a turn found rate-limited or out of quota is left alone, when \
         its harness gave no reset.";
    RefusedSecs "account.refused_secs" Seconds 3600, 60, 7 * DAY, SA,
        "How long an account its harness reports at its plan limit stays limited, when the \
         harness gave no reset.";
    MaxResumes "runner.max_resumes" Count 2, 0, 10, SR,
        "Resumes of a session the provider dropped before the run gives up on its model.";
    ResumeBackoffMs "runner.resume_backoff_ms" Milliseconds 2000, 10, 60_000, SR,
        "The first wait before a resume, doubling per drop.";
    ResumeBackoffMaxMs "runner.resume_backoff_max_ms" Milliseconds 30_000, 10, 600_000, SR,
        "The longest wait before a resume.";
    RoutingSmallMaxPoints "routing.small_max_points" Count 2, 0, 100, SCP,
        "An issue with at most this many points runs on its agent's small tier, unless a \
         routing rule names its tier.";
    RoutingLargeMinPoints "routing.large_min_points" Count 8, 1, 1000, SCP,
        "An issue with at least this many points runs on its agent's large tier, unless a \
         routing rule names its tier.";
    ResumeUnfinished "run.resume_unfinished" Count 0, 0, 1, SCP,
        "1 lets a new run of an issue resume its agent's previous session when that run ended \
         unfinished (failed, timed out or lost); 0 starts every run in a fresh session.";
    FirstTokenBudgetSecs "latency.first_token_budget_secs" Seconds 10, 1, 3600, SCP,
        "Longest a run may take from its wake to its model's first answer before a \
         run.first_token_slow warning.";
    WarmMax "runner.warm_max" Count 2, 0, 16, SR,
        "Idle harness servers (OpenCode serve, Codex app-server) a runner keeps for its next \
         runs, each run a new session on one; 0 starts a new process every run.";
    DispatchPollMs "dispatch.fallback_poll_ms" Milliseconds 5000, 100, 60_000, SO,
        "How often a waiting runner looks for work besides being told of new wakes (wakes \
         that came due, or were written by another process); read at start.";
    SchedulerTickSecs "scheduler.tick_secs" Seconds 10, 1, 300, SO,
        "Time between scheduler ticks (timers, lease reaping, approval expiry); read at start.";
    PushIntervalSecs "push.interval_secs" Seconds 5, 1, 300, SO,
        "Time between push passes to the app's devices; read at start.";
    ForgePollSecs "forge.poll_secs" Seconds 60, 10, 3600, SO,
        "Time between forge and Linear polls; read at start.";
    ApiRequestBurst "api.request_burst" Count 120, 10, 10_000, SO,
        "Client API requests one device may send at once; read at start.";
    ApiRequestsPerMin "api.requests_per_min" PerMinute 1200, 60, 60_000, SO,
        "Client API requests one device may send per minute, sustained; read at start.";
    ApiAuthFailureBurst "api.auth_failure_burst" Count 10, 3, 100, SO,
        "Failed authentications one address may make before it is refused; read at start.";
    ApiAuthFailuresPerMin "api.auth_failures_per_min" PerMinute 10, 1, 60, SO,
        "Failed authentications one address regains per minute; read at start.";
    StallAfterSecs "run.stall_after_secs" Seconds STALL_AFTER_SECS, 60, 7 * DAY, SCP,
        "How long a running run may go without progress (a tool call, a file change, a new \
         message, more tokens) before its runner stops it as stalled and its issue escalates.";
    RepairBudget "repair.budget" Count 3, 0, 50, SCP,
        "Automatic repairs one stuck issue gets within the window before it goes to the admin \
         with its repair history; 0 sends it at once.";
    RepairWindowSecs "repair.window_secs" Seconds DAY, 3600, 30 * DAY, SCP,
        "The window an issue's repairs are counted over.";
    IdleEscalateSecs "issue.idle_escalate_secs" Seconds DAY, 0, 30 * DAY, SCP,
        "How long an open issue may go untouched before it is escalated up the chain from \
         whoever it waits on; 0 never escalates for idleness.";
    DiskCapBytes "runner.disk_cap_bytes" Bytes 50_000_000_000, 5_000_000_000,
        1_000_000_000_000_000, SR,
        "The most a runner's work root may hold: worktrees, shared build caches and repo \
         mirrors; sent when it connects.";
    DiskEvictPercent "runner.disk_evict_percent" Percent 90, 50, 100, SR,
        "Share of the disk cap past which a runner evicts idle worktrees, oldest first, then \
         build caches; active worktrees never.";
    WorkspaceIdleSecs "workspace.idle_secs" Seconds DAY, 3600, 30 * DAY, SR,
        "How long a worktree may sit with no run before its runner removes it (its work kept \
         on its branch), recreated on demand.";
    WarmIdleSecs "runner.warm_idle_secs" Seconds 900, 60, DAY, SR,
        "How long a warm harness server may sit idle before its runner stops it.";
    ArtifactMaxFileBytes "artifact.max_file_bytes" Bytes 10_000_000, 1_000, 12_000_000, SC,
        "The largest file an agent may publish as an artifact; a file read from a worktree \
         travels in one runner message, which caps it at 12 MB.";
    ArtifactCompanyQuotaBytes "artifact.company_quota_bytes" Bytes 2_000_000_000, 1_000_000,
        1_000_000_000_000, SC,
        "Artifact storage a company may use (each distinct file once); a publish past it is \
         refused, with the reason on the run.";
    ProfileBudgetBytes "profile.budget_bytes" Bytes 4096, 0, 64 * 1024, SCP,
        "The most of its project's profile a run is given in its instructions; what does not \
         fit is named, and the agent reads it with get_context.";
    McpRoleScopedTools "mcp.role_scoped_tools" Count 1, 0, 1, SCP,
        "1 gives each run only its role's MCP tools (plus search_tools and describe_tool to \
         find the rest), so fewer definitions fill its context; 0 lists every tool. Calls are \
         permission-checked either way.";
    CliMaxBatchOps "cli.max_batch_ops" Count 100, 1, 1000, SCP,
        "Operations one `citadel batch` may run, in order; a longer batch is refused whole.";
    IssueAllowSecs "approval.issue_allow_secs" Seconds DAY, 60, 30 * DAY, SCP,
        "How long \"allow for this issue\" on a permission escalation lets the same call through \
         on the issue's runs without asking.";
    IssueTokenCap "issue.token_cap" Tokens 0, 0, 1_000_000_000, SCP,
        "Tokens all the runs of one issue may use together; a run is capped at what is left of \
         it (and at run.token_cap). 0: no cap per issue.";
    ToolOutputBytes "run.tool_output_bytes" Bytes TOOL_OUTPUT_BYTES, 256, 64 * 1024, SCP,
        "The most of a tool call's output its transcript keeps (its head and its tail, with the \
         full size); the run's runner cuts it before it is sent.";
    AvatarMaxBytes "avatar.max_bytes" Bytes 512 * 1024, 1024, 8 * 1024 * 1024, SC,
        "The largest image the admin may upload as an agent's avatar (PNG, JPEG or WebP), shown \
         instead of its figure.";
    RunnerLogTailMaxLines "runner.log_tail_max_lines" Count 200, 1, 2000, SO,
        "The most lines of a runner's own log the app may ask for at once; read from the \
         runner while it is connected, redacted.";
    RunnerLogTailTimeoutSecs "runner.log_tail_timeout_secs" Seconds 10, 1, 120, SO,
        "How long a request for a runner's log waits for the runner to answer.";
    DropDisplayWindowSecs "account.drop_display_window_secs" Seconds DAY, 3600, 30 * DAY, SA,
        "The window an account's provider drops are counted over for the app (not the window \
         that makes it unhealthy, account.drop_window_secs).";
    FallbackOnModelUnavailable "fallback.on_model_unavailable" Count 1, 0, 1, SCP,
        "1 moves a run to the next entry of its agent's fallback chain when its model is \
         unavailable; 0 fails the run instead.";
    FallbackOnRateLimited "fallback.on_rate_limited" Count 1, 0, 1, SCP,
        "1 moves a run to the next entry of its agent's fallback chain when it is rate-limited; \
         0 fails the run instead.";
    FallbackOnQuota "fallback.on_quota" Count 1, 0, 1, SCP,
        "1 moves a run to the next entry of its agent's fallback chain when its account is out \
         of quota; 0 fails the run instead.";
    FallbackOnUnhealthy "fallback.on_unhealthy" Count 1, 0, 1, SCP,
        "1 moves a run to the next entry of its agent's fallback chain when its account dropped \
         too often; 0 fails the run instead.";
    AccountAtLimit "account.at_limit" Count 0, 0, 1, SCA,
        "When no account a chain entry may use is active (limited, unhealthy, disabled): 0 \
         starts the run on the next entry of the agent's chain; 1 waits for one of them.";
    AccountPickStrategy "account.pick_strategy" Count 0, 0, 2, SC,
        "Which account a run gets: 0 the least used in its limit windows, then the least \
         recently used; 1 the least recently used (round robin); 2 the first by id until it is \
         limited (fill first).";
    TranscriptRetentionSecs "transcript.retention_secs" Seconds 0, 0, 10 * YEAR, SC,
        "How long a run's transcript is kept after the run ends, then pruned (the run stays); \
         0 keeps every transcript.";
    FlowWindowSecs "flow.window_secs" Seconds 30 * DAY, DAY, YEAR, SCP,
        "The window a project's throughput and mean cycle and lead times are measured over when \
         the client names none.";
    AllowUntestedNewer "harness.allow_untested_newer" Count 1, 0, 1, SR,
        "1 lets a runner drive a harness version newer than its adapter was tested against (not \
         older than its minimum, not known bad), noted on the runner's harness status; 0 refuses it, making the \
         runner unhealthy for that harness. Read when the runner connects.";
    ClaudeMaxVersion "harness.claude.max_version" Version 0, 0, MAX_VERSION, SR,
        "The newest Claude Code version a runner may drive (major·10¹² + minor·10⁶ + patch: \
         2.3.0 is 2000003000000); 0 caps nothing. Read when the runner connects.";
    CodexMaxVersion "harness.codex.max_version" Version 0, 0, MAX_VERSION, SR,
        "The newest Codex version a runner may drive (major·10¹² + minor·10⁶ + patch: 0.160.0 \
         is 160000000); 0 caps nothing. Read when the runner connects.";
    OpencodeMaxVersion "harness.opencode.max_version" Version 0, 0, MAX_VERSION, SR,
        "The newest OpenCode version a runner may drive (major·10¹² + minor·10⁶ + patch: \
         1.20.0 is 1000020000000); 0 caps nothing. Read when the runner connects.";
    AgyMaxVersion "harness.agy.max_version" Version 0, 0, MAX_VERSION, SR,
        "The newest agy version a runner may drive (major·10¹² + minor·10⁶ + patch: 1.5.0 is \
         1000005000000); 0 caps nothing. Read when the runner connects.";
    SkillMaxBytes "skills.max_bytes" Bytes 64 * 1024, 1, 512 * 1024, SC,
        "The largest skill body the admin may publish (a new version of a company's skill).";
    MaxNoActionRewakes "run.max_no_action_rewakes" Count 1, 0, 10, SCP,
        "Times an agent is woken again, with a nudge, after a run that ended without acting on \
         an issue still waiting on it (no state-changing Citadel call); the next such run \
         escalates the issue up the chain. Reset when the issue changes.";
    CostDailyWarn "cost.daily_warn_usd_micros" Count 0, 0, 1_000_000_000_000, SC,
        "A company's spend in a day, in millionths of a US dollar (1000000 is $1), at which the \
         app warns; 0 sets no warning. Kept for the app: the server does not act on it.";
    AgentWipMax "agent.wip_max" Count 0, 0, 100, SCP,
        "The most issues an agent should work on at once; 0 sets no limit. Kept for the app: \
         the server does not enforce it.";
    RunCacheWeightDivisor "run.cache_weight_divisor" Count 10, 1, 100, SCP,
        "How much a run's cache reads and writes count against `run.token_cap`, as a divisor: \
         10 counts a tenth, so the cap tracks the work a run does rather than the context it \
         re-reads; 1 counts every token in full. Budgets and the issue cap always count in full.";
    LeaseGraceSecs "lease.grace_secs" Seconds LEASE_GRACE_SECS, 0, 3600, SR,
        "How long a run's lease may lapse after its heartbeat stops before the run is lost; a \
         runner back inside it re-claims its run. 0 loses it at once.";
}
