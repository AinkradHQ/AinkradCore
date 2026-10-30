//! Runner protocol suite (E3.1): real runner daemons against a real server over WebSocket,
//! in-process. Each runner is its own task with its own key and connection, which is how a
//! second host looks to the server; the plan's "runner on a second host" is simulated so.
//! Time on the server side is a fake clock the tests move; leases and the reaper follow it.

#[allow(dead_code)]
#[path = "fault_injection/harness.rs"]
mod shared;
/// The shared fixtures, but `assign` wakes the agent while the issue keeps waiting on the
/// admin: this suite's runs are the runner's fake jobs, which never call a Citadel tool, and a
/// run that leaves an issue waiting on its agent untouched is nudged again (`no_action`, which
/// the `company` suite covers with scripted agents).
mod harness {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use citadel_core::exec::{NewWakeRequest, WakeSource};
    use citadel_core::org::AgentId;
    use citadel_core::work::IssueId;
    use citadel_server::store::exec::enqueue_wake;
    use sqlx::SqlitePool;

    pub use super::shared::*;

    /// Wakes `agent` on `issue` with an assignment wake.
    pub async fn assign(pool: &SqlitePool, issue: IssueId, agent: AgentId) {
        static N: AtomicUsize = AtomicUsize::new(0);
        let w = NewWakeRequest {
            agent_id: agent,
            issue_id: Some(issue),
            source: WakeSource::Assignment,
            reason: "assigned".to_owned(),
            idempotency_key: format!("assign:{}", N.fetch_add(1, Ordering::Relaxed)),
            not_before: None,
        };
        enqueue_wake(pool, &w).await.unwrap();
    }
}
mod runner_protocol {
    mod accounts;
    mod admin;
    mod caps;
    mod controls;
    mod disk;
    mod drops;
    mod fallbacks;
    mod latency;
    mod limits;
    mod mac;
    mod permissions;
    mod sleep;
    mod stall;
    mod state;
    pub mod support;
    mod transcripts;
}

use std::time::Duration;

use citadel_core::exec::{LEASE_GRACE_SECS, RunId, RunState, RunnerId, RunnerStatus, WakeSource};
use citadel_core::org::Harness;
use citadel_core::work::ProjectRepo;
use citadel_server::store::exec::{
    Recovery, authorize_run_token, get_run, get_runner, list_runs, list_wake_requests, tick,
};
use citadel_server::store::org::{get_agent, update_agent};
use citadel_server::store::work::set_project_repo;
use ainkrad_harness::codex;
use ainkrad_proto::runner::{Outcome, RunToken, Workspace};
use ainkrad_runner::FakeExecutor;
use ainkrad_runner::{Executor, Job, Report};
use futures_util::{SinkExt, StreamExt};
use harness::{agent, assign, company, count, issue, runner};
use runner_protocol::support::*;
use tokio::sync::mpsc;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{self, Message, http::header};

/// Assign `runs` fake jobs to two runners; both claim and finish, and each run ends with a
/// reason: one succeeded, one failed (and is queued for a retry).
#[tokio::test]
async fn two_runners_claim_and_finish_fake_jobs() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let (dev, qa) = (
        agent(pool, c, "Dev", &[], None).await,
        agent(pool, c, "QA", &[], None).await,
    );
    let (one, two) = (issue(pool, p).await, issue(pool, p).await);
    let box1 = runner(pool, "box-1", &[]).await;
    let box2 = runner(pool, "box-2", &[]).await;
    assign(pool, one, dev).await;
    assign(pool, two, qa).await;

    let slow = |outcome| FakeExecutor {
        events: 3,
        delay: Duration::from_millis(300),
        outcome,
    };
    stack.runner("box-1", &["linux"], slow(Outcome::Succeeded));
    until(pool, "box-1 to claim", "SELECT count(*) FROM runs").await;
    let failed = Outcome::Failed {
        reason: "tests failed".to_owned(),
        fingerprint: Some("E0001@test".to_owned()),
    };
    stack.runner("box-2", &["linux"], slow(failed));
    let ended = "SELECT count(*) = 2 FROM runs WHERE state IN ('succeeded', 'failed')";
    until(pool, "both runs to end", ended).await;

    let (a, b) = (
        list_runs(pool, dev).await.unwrap().remove(0),
        list_runs(pool, qa).await.unwrap().remove(0),
    );
    assert_eq!(a.runner_id, Some(box1));
    assert_eq!(b.runner_id, Some(box2));
    assert_eq!(a.state, RunState::Succeeded);
    assert_eq!(a.terminal_reason.as_deref(), Some("succeeded"));
    assert_eq!(
        a.session_id.as_deref(),
        Some(&*format!("fake-session-{}", a.id.0))
    );
    assert_eq!(b.state, RunState::Failed);
    assert_eq!(b.terminal_reason.as_deref(), Some("tests failed"));
    // The retry is queued just after the run ends, in its own transaction.
    let retry = "SELECT count(*) FROM wake_requests WHERE source = 'retry'";
    until(pool, "the failed run's retry", retry).await;
    let retry = list_wake_requests(pool, qa).await.unwrap();
    assert!(
        retry.iter().any(|w| w.source == WakeSource::Retry),
        "{retry:?}"
    );
    // Each run held one token, revoked when it ended; no lease is left behind.
    let tokens = "SELECT count(*) FROM run_tokens WHERE revoked_at IS NOT NULL";
    assert_eq!(count(pool, tokens).await, 2);
    assert_eq!(count(pool, "SELECT count(*) FROM leases").await, 0);
    for id in [box1, box2] {
        let r = get_runner(pool, id).await.unwrap().unwrap();
        assert_eq!(r.status, RunnerStatus::Online);
        assert_eq!(r.tags, vec!["linux".to_owned()]);
    }
}

/// The status a raw upgrade request gets: 101 when upgraded.
async fn status(req: tungstenite::handshake::client::Request) -> u16 {
    match connect_async(req).await {
        Ok(_) => 101,
        Err(tungstenite::Error::Http(response)) => response.status().as_u16(),
        Err(e) => panic!("{e}"),
    }
}

#[tokio::test]
async fn the_gate_refuses_before_any_upgrade() {
    let stack = Stack::new().await;
    runner(stack.pool(), "k1", &[]).await;
    let req = |url: &str, key: Option<&str>| {
        let mut req = url.into_client_request().unwrap();
        if let Some(key) = key {
            let auth = format!("Bearer {key}").parse().unwrap();
            req.headers_mut().insert(header::AUTHORIZATION, auth);
        }
        req
    };
    let url = stack.url();

    assert_eq!(status(req(&url, Some("k1"))).await, 101);
    assert_eq!(status(req(&url, Some("wrong"))).await, 401);
    assert_eq!(status(req(&url, None)).await, 401);
    // A key in the query string is refused even when it is valid.
    assert_eq!(status(req(&format!("{url}?key=k1"), None)).await, 400);
    assert_eq!(status(req(&format!("{url}?key=k1"), Some("k1"))).await, 400);
    // DNS rebinding: the right key on a foreign Host is refused.
    let mut rebound = req(&url, Some("k1"));
    let evil = "evil.example:80".parse().unwrap();
    rebound.headers_mut().insert(header::HOST, evil);
    assert_eq!(status(rebound).await, 403);
    // A browser page (any Origin) is refused.
    let mut page = req(&url, Some("k1"));
    let origin = "http://evil.example".parse().unwrap();
    page.headers_mut().insert(header::ORIGIN, origin);
    assert_eq!(status(page).await, 403);
    // Nothing was marked online by a refused request.
    let online =
        "SELECT count(*) FROM runners WHERE status = 'online' AND last_seen_at IS NOT NULL";
    assert_eq!(count(stack.pool(), online).await, 0);
}

#[tokio::test]
async fn an_unknown_major_version_is_refused() {
    let stack = Stack::new().await;
    runner(stack.pool(), "k1", &[]).await;
    let mut req = stack.url().into_client_request().unwrap();
    req.headers_mut()
        .insert(header::AUTHORIZATION, "Bearer k1".parse().unwrap());
    let (mut ws, _) = connect_async(req).await.unwrap();
    let hello = r#"{"type":"hello","protocol":"2.0","runner_version":"9","tags":[],
                   "harnesses":{},"runs":[]}"#;
    ws.send(Message::Text(hello.into())).await.unwrap();
    let Some(Ok(Message::Text(reply))) = ws.next().await else {
        panic!("no reply");
    };
    assert!(reply.contains(r#""type":"error""#), "{reply}");
    assert!(reply.contains("unsupported protocol 2.0"), "{reply}");
    assert!(matches!(
        ws.next().await,
        None | Some(Ok(Message::Close(_))) | Some(Err(_))
    ));
}

/// A `macos` job is never offered to a `linux` runner; the `macos` runner takes it.
#[tokio::test]
async fn jobs_route_by_tags() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let builder = agent(pool, c, "Builder", &["macos"], None).await;
    let i = issue(pool, p).await;
    runner(pool, "linux", &[]).await;
    let mac = runner(pool, "mac", &[]).await;
    assign(pool, i, builder).await;

    stack.runner("linux", &["linux"], FakeExecutor::default());
    let online = "SELECT count(*) FROM runners WHERE name = 'linux' AND status = 'online'";
    until(pool, "the linux runner to say hello", online).await;
    // Many poll intervals with a ready runner and a due wake: nothing is claimed.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(count(pool, "SELECT count(*) FROM runs").await, 0);

    stack.runner("mac", &["macos", "xcode"], FakeExecutor::default());
    let done = "SELECT count(*) FROM runs WHERE state = 'succeeded'";
    until(pool, "the mac runner to finish", done).await;
    let run = list_runs(pool, builder).await.unwrap().remove(0);
    assert_eq!(run.runner_id, Some(mac));
}

/// Harness versions (E3.6): a runner reporting a Codex older than the minimum is `unhealthy`
/// with the reason, but still works its Claude, an untested newer version; the Codex
/// job waits for a runner with a supported version, which is `online`. OpenCode, which no
/// runner has, is never dispatched.
#[tokio::test]
async fn harness_versions_decide_health_and_dispatch() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let coder = agent(pool, c, "Coder", &[], None).await;
    let open = agent(pool, c, "Open", &[], None).await;
    for (id, harness) in [(coder, Harness::Codex), (open, Harness::Opencode)] {
        let mut a = get_agent(pool, id).await.unwrap().unwrap();
        a.harness = harness;
        assert!(update_agent(pool, &a).await.unwrap());
    }
    for who in [dev, coder, open] {
        assign(pool, issue(pool, p).await, who).await;
    }
    let stale = runner(pool, "stale", &[]).await;
    let fresh = runner(pool, "fresh", &[]).await;

    let has = [("claude", "99.0.0"), ("codex", "0.1.0")];
    stack.runner_with("stale", &[], &has, FakeExecutor::default());
    let done = "SELECT count(*) FROM runs WHERE state = 'succeeded'";
    until(pool, "the stale runner to work the claude job", done).await;
    let r = get_runner(pool, stale).await.unwrap().unwrap();
    assert_eq!(r.status, RunnerStatus::Unhealthy);
    let reason = r.health_reason.unwrap();
    assert!(reason.contains("codex 0.1.0 is older than"), "{reason}");
    assert!(
        !reason.contains("claude"),
        "an untested newer claude is no refusal: {reason}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(count(pool, "SELECT count(*) FROM runs").await, 1);

    stack.runner_with(
        "fresh",
        &[],
        &[("codex", codex::VERSION)],
        FakeExecutor::default(),
    );
    let two = "SELECT count(*) = 2 FROM runs WHERE state = 'succeeded'";
    until(pool, "the fresh runner to work the codex job", two).await;
    let r = get_runner(pool, fresh).await.unwrap().unwrap();
    assert_eq!((r.status, r.health_reason), (RunnerStatus::Online, None));
    assert_eq!(
        list_runs(pool, coder).await.unwrap()[0].runner_id,
        Some(fresh)
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(list_runs(pool, open).await.unwrap().is_empty());
}

/// The settings tighten the version policy, per runner: with `harness.allow_untested_newer`
/// 0 an untested newer Claude is refused (the runner unhealthy, nothing dispatched to it), and
/// a `harness.claude.max_version` below the version refuses it too; a runner with neither set
/// works the job, online.
#[tokio::test]
async fn settings_refuse_untested_newer_versions() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    assign(pool, issue(pool, p).await, dev).await;
    let set = async |runner: RunnerId, key: &str, value: i64| {
        let at = citadel_core::settings::Scope::Runner(runner);
        let by = citadel_core::audit::AuditActor::System;
        let (key, value) = (key.parse().unwrap(), value.to_string());
        citadel_server::store::settings::set(
            pool,
            key,
            at,
            &value,
            by,
            "2026-10-23T10:00:00.000Z",
        )
        .await
        .unwrap();
    };
    let strict = runner(pool, "strict", &[]).await;
    set(strict, "harness.allow_untested_newer", 0).await;
    let capped = runner(pool, "capped", &[]).await;
    set(capped, "harness.claude.max_version", 98_000_000_000_000).await;
    let has = [("claude", "99.0.0")];
    stack.runner_with("strict", &[], &has, FakeExecutor::default());
    stack.runner_with("capped", &[], &has, FakeExecutor::default());
    for (id, want) in [
        (strict, "claude 99.0.0 is untested (tested up to "),
        (
            capped,
            "claude 99.0.0 is above harness.claude.max_version, 98.0.0",
        ),
    ] {
        let sql = format!(
            "SELECT count(*) FROM runners WHERE id = {} AND status = 'unhealthy'",
            id.0
        );
        until(pool, "the runner to be refused", &sql).await;
        let reason = get_runner(pool, id)
            .await
            .unwrap()
            .unwrap()
            .health_reason
            .unwrap();
        assert!(reason.starts_with(want), "{reason}");
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(count(pool, "SELECT count(*) FROM runs").await, 0);

    let open = runner(pool, "open", &[]).await;
    stack.runner_with("open", &[], &has, FakeExecutor::default());
    let done = "SELECT count(*) FROM runs WHERE state = 'succeeded'";
    until(pool, "the open runner to work the job", done).await;
    assert_eq!(list_runs(pool, dev).await.unwrap()[0].runner_id, Some(open));
    let r = get_runner(pool, open).await.unwrap().unwrap();
    assert_eq!((r.status, r.health_reason), (RunnerStatus::Online, None));
}

/// Records what the runner is told about workspaces; claims to hold `held`.
struct Holding {
    held: Vec<i64>,
    jobs: mpsc::UnboundedSender<Job>,
    pruned: mpsc::UnboundedSender<Vec<i64>>,
}

impl Executor for Holding {
    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        let _ = self.jobs.send(job.clone());
        Ok(None)
    }

    async fn run(&self, _: &Job, _: RunToken, _: mpsc::Sender<Report>) -> Outcome {
        Outcome::Succeeded
    }

    fn workspaces(&self) -> Vec<i64> {
        self.held.clone()
    }

    async fn prune(&self, issues: Vec<i64>) {
        let _ = self.pruned.send(issues);
    }
}

/// Workspaces (E3.7): an issue of a project with a repo is assigned with its worktree, and
/// the worktree of a cancelled issue the runner still holds is pruned. The assign also names
/// the issue and carries the run's skills (E4.2) and its project's accepted knowledge (E8.1).
#[tokio::test]
async fn assigns_carry_the_worktree_and_closed_ones_are_pruned() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let (done, live) = (issue(pool, p).await, issue(pool, p).await);
    let repo = ProjectRepo {
        project_id: p,
        url: "https://example.test/git/citadel.git".to_owned(),
        default_branch: "development".to_owned(),
    };
    set_project_repo(pool, &repo).await.unwrap();
    sqlx::query("UPDATE issues SET state = 'cancelled', next_user_id = NULL WHERE id = ?")
        .bind(done.0)
        .execute(pool)
        .await
        .unwrap();
    runner(pool, "box", &[]).await;
    assign(pool, live, dev).await;
    let by = citadel_core::audit::AuditActor::System;
    let attach = citadel_core::gov::SkillAttach::Company;
    citadel_server::store::gov::publish_skill(pool, c, "style", "Be brief.", &attach, by)
        .await
        .unwrap();
    let landmine = citadel_core::gov::KnowledgeKind::Landmine;
    let admin = citadel_core::work::UserId(1);
    citadel_server::store::gov::add_knowledge(pool, p, landmine, "WAL", "Keep WAL on.", admin)
        .await
        .unwrap();

    let (jobs, mut job) = mpsc::unbounded_channel();
    let (pruned, mut prune) = mpsc::unbounded_channel();
    let held = vec![done.0, live.0];
    stack.runner("box", &[], Holding { held, jobs, pruned });
    assert_eq!(prune.recv().await.unwrap(), vec![done.0]);
    let job = job.recv().await.unwrap();
    assert_eq!(job.issue, Some(live.0));
    let want = Workspace {
        repo: repo.url,
        base: "development".to_owned(),
        branch: "citadel/CIT-2".to_owned(),
        push: false,
        name: "cit".to_owned(),
        also: vec![],
        expected_head: None,
    };
    assert_eq!(job.workspace, Some(want));
    assert_eq!(job.issue_key.as_deref(), Some("CIT-2"));
    let instructions = job.instructions.unwrap();
    assert!(
        instructions.contains("# Skill: style (v1)\n\nBe brief."),
        "{instructions}"
    );
    assert!(
        instructions.contains("## landmine 1: WAL\n\nKeep WAL on."),
        "{instructions}"
    );
}

/// The connection drops mid-run and comes back within the lease TTL: the run keeps its
/// lease (renewed by the resumed `Hello`), survives the reaper, and finishes.
#[tokio::test]
async fn a_reconnect_within_the_ttl_resumes_the_run() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let i = issue(pool, p).await;
    runner(pool, "box", &[]).await;
    assign(pool, i, dev).await;
    let (executor, mut tokens, release) = held();
    stack.runner("box", &[], executor);
    let (run, token) = tokens.recv().await.unwrap();

    stack.proxy.cut();
    let offline = "SELECT count(*) FROM runners WHERE status = 'offline'";
    until(pool, "the server to see the drop", offline).await;
    let back = stack.advance(60);
    let resumed = format!("SELECT count(*) FROM leases WHERE heartbeat_at = '{back}'");
    until(pool, "the resumed hello to renew the lease", &resumed).await;

    // Past the original expiry (90 s after the claim), inside the renewed one.
    let later = stack.advance(60);
    assert!(tick(pool, &later).await.unwrap().reaped.is_empty());
    let r = get_run(pool, RunId(run)).await.unwrap().unwrap();
    assert_eq!(r.state, RunState::Running);
    assert!(
        authorize_run_token(pool, token.expose(), &later)
            .await
            .is_ok()
    );

    release.notify_one();
    let done = "SELECT count(*) FROM runs WHERE state = 'succeeded'";
    until(pool, "the resumed run to finish", done).await;
}

/// The runner stays away past the TTL and its grace: the reaper ends the run `runner_lost` and
/// queues a retry. When the runner comes back it is told to drop the lost run, and it then takes
/// the retry and finishes it.
#[tokio::test]
async fn a_runner_gone_past_the_ttl_loses_the_run_to_a_retry() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let i = issue(pool, p).await;
    runner(pool, "box", &[]).await;
    assign(pool, i, dev).await;
    let (executor, mut tokens, release) = held();
    stack.runner("box", &[], executor);
    let (lost, _) = tokens.recv().await.unwrap();

    stack.proxy.set_down(true);
    let offline = "SELECT count(*) FROM runners WHERE status = 'offline'";
    until(pool, "the server to see the drop", offline).await;
    let late = stack.advance(91 + LEASE_GRACE_SECS);
    let reaped = tick(pool, &late).await.unwrap().reaped;
    assert_eq!(reaped.len(), 1);
    assert!(
        matches!(reaped[0].recovery, Recovery::Retry(_)),
        "{reaped:?}"
    );
    let r = get_run(pool, RunId(lost)).await.unwrap().unwrap();
    assert_eq!(r.state, RunState::RunnerLost);
    assert_eq!(r.terminal_reason.as_deref(), Some("runner_lost"));

    // Back online: the lost run is cancelled on the runner; the retry is due after backoff.
    stack.proxy.set_down(false);
    stack.advance(31);
    let (retry, _) = tokens.recv().await.unwrap();
    assert_ne!(retry, lost);
    release.notify_one();
    let done = format!("SELECT count(*) FROM runs WHERE id = {retry} AND state = 'succeeded'");
    until(pool, "the retry to finish", &done).await;
    let r = get_run(pool, RunId(lost)).await.unwrap().unwrap();
    assert_eq!(r.state, RunState::RunnerLost);
}

/// The run token reaches the harness and works, but no log line, at any level, holds it.
#[tokio::test]
async fn the_run_token_never_reaches_a_log() {
    let logs = logs();
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    let i = issue(pool, p).await;
    runner(pool, "box", &[]).await;
    assign(pool, i, dev).await;
    let (executor, mut tokens, release) = held();
    stack.runner("box", &[], executor);
    let (run, token) = tokens.recv().await.unwrap();
    let scope = authorize_run_token(pool, token.expose(), &stack.now()).await;
    assert_eq!(scope.unwrap().run_id, RunId(run));
    release.notify_one();
    let done = "SELECT count(*) FROM runs WHERE state = 'succeeded'";
    until(pool, "the run to finish", done).await;

    let logs = String::from_utf8(logs.text()).unwrap();
    assert!(
        logs.contains("RunToken(<redacted>)"),
        "token message not logged"
    );
    assert!(
        !logs.contains(token.expose()),
        "a log line holds the run token"
    );
    assert!(!logs.contains("cit_run_"), "a log line holds a run token");
}
