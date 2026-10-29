//! The fault-injection suite's fixtures, fake clock, seeded PRNG and `assert_invariants`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ainkrad_core::audit::AuditActor;
use ainkrad_core::exec::{NewRunner, Run, RunEvent, RunnerId, RunnerStatus, StuckKind};
use ainkrad_core::org::{AgentId, AgentStatus, CompanyId, Harness, NewAgent, OrgRole};
use ainkrad_core::work::{
    IssueId, IssueKind, IssueState, IssueTransition, NewIssue, NewProject, NextActor, ProjectId,
    ProjectMode, SprintApproval, UserId,
};
use ainkrad_core_server::store::connect;
use ainkrad_core_server::store::exec::{
    create_runner, get_runner, start_run, stuck_report, transition_run, update_runner,
};
use ainkrad_core_server::store::org::{create_agent, create_company};
use ainkrad_core_server::store::work::{create_issue, create_project, transition_issue};
use sqlx::SqlitePool;

/// A migrated database file in its own temp dir, removed on drop.
pub struct Db {
    pub pool: SqlitePool,
    pub path: PathBuf,
    dir: PathBuf,
}

impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Db {
    pub async fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("citadel-faults-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("citadel.db");
        let pool = connect(&path).await.unwrap();
        Db { pool, path, dir }
    }

    /// The server dies without closing anything, then starts again on the same file.
    /// Whatever was not committed is gone; the new pool has no in-memory state.
    pub async fn restart(&mut self) {
        let fresh = connect(&self.path).await.unwrap();
        drop(std::mem::replace(&mut self.pool, fresh));
    }
}

/// Fake time: a base taken from the real clock once (rows the database stamps itself, such
/// as `created_at`, are near it), plus whole seconds the test moves on.
pub struct Clock {
    base_ms: i64,
    pub secs: i64,
}

impl Clock {
    pub fn new() -> Self {
        let ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        Clock {
            base_ms: ms.as_millis() as i64,
            secs: 0,
        }
    }

    pub fn now(&self) -> String {
        self.at(self.secs)
    }

    /// The base plus `secs`.
    pub fn at(&self, secs: i64) -> String {
        iso8601(self.base_ms + secs * 1000)
    }

    pub fn advance(&mut self, secs: i64) -> String {
        self.secs += secs;
        self.now()
    }
}

/// `ms` since the epoch as ISO-8601 UTC with milliseconds (Hinnant's civil-from-days).
fn iso8601(ms: i64) -> String {
    let (days, ms) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let (h, m, s) = (ms / 3_600_000, ms / 60_000 % 60, ms / 1000 % 60);
    format!(
        "{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{:03}Z",
        ms % 1000
    )
}

/// xorshift64*: deterministic for a seed, no dependency.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-enough in `0..n`.
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

// --- fixtures ---------------------------------------------------------------

pub async fn company(pool: &SqlitePool, name: &str) -> (CompanyId, ProjectId) {
    let c = create_company(pool, name).await.unwrap().id;
    let p = NewProject {
        company_id: c,
        team_id: None,
        name: "Citadel".to_owned(),
        key: "CIT".to_owned(),
        mode: ProjectMode::Kanban,
        sprint_approval: SprintApproval::Owner,
    };
    (c, create_project(pool, &p).await.unwrap().id)
}

/// An active agent needing `tags`; with a `lead`, a member of the lead's team (created on first
/// use and owning every project of the company), so its escalations go to the lead (E6.3).
pub async fn agent(
    pool: &SqlitePool,
    company_id: CompanyId,
    name: &str,
    tags: &[&str],
    lead: Option<AgentId>,
) -> AgentId {
    use ainkrad_core::org::TeamRole;
    use ainkrad_core_server::store::org::seat_member;
    use ainkrad_core_server::store::org::{add_department, add_team, list_departments, list_teams};
    let a = NewAgent {
        company_id,
        name: name.to_owned(),
        role: "Developer".to_owned(),
        org_role: OrgRole::None,
        reports_to: lead,
        harness: Harness::Claude,
        model: "claude-opus".to_owned(),
        runner_tags: tags.iter().map(|t| t.to_string()).collect(),
        status: AgentStatus::Active,
    };
    let id = create_agent(pool, &a).await.unwrap().id;
    if let Some(lead) = lead {
        let by = AuditActor::System;
        let team = match list_departments(pool, company_id).await.unwrap().first() {
            Some(d) => list_teams(pool, d.id).await.unwrap()[0].id,
            None => {
                let d = add_department(pool, company_id, "Engineering", by)
                    .await
                    .unwrap();
                let t = add_team(pool, d.id, "Core", by).await.unwrap().id;
                seat_member(pool, t, lead, TeamRole::TeamLead, None, by)
                    .await
                    .unwrap();
                sqlx::query("UPDATE projects SET team_id = ? WHERE company_id = ?")
                    .bind(t.0)
                    .bind(company_id.0)
                    .execute(pool)
                    .await
                    .unwrap();
                t
            }
        };
        seat_member(pool, team, id, TeamRole::Member, None, by)
            .await
            .unwrap();
    }
    id
}

/// A `todo` issue waiting on the admin, with `body`.
pub async fn issue_with(pool: &SqlitePool, project_id: ProjectId, body: &str) -> IssueId {
    let i = NewIssue {
        project_id,
        epic_id: None,
        parent_id: None,
        kind: IssueKind::Task,
        title: "Work".to_owned(),
        body: body.to_owned(),
        state: IssueState::Todo,
        owner: None,
        next_actor: Some(NextActor::Human(UserId(1))),
        points: None,
        sprint_id: None,
    };
    create_issue(pool, &i).await.unwrap().id
}

pub async fn issue(pool: &SqlitePool, project_id: ProjectId) -> IssueId {
    issue_with(pool, project_id, "").await
}

/// Hands the issue to `agent`, which enqueues its assignment wake.
pub async fn assign(pool: &SqlitePool, issue: IssueId, agent: AgentId) {
    let to = IssueTransition::Reassign {
        next: NextActor::Agent(agent),
    };
    transition_issue(pool, issue, &to, AuditActor::System)
        .await
        .unwrap();
}

/// An online runner holding `tags`.
pub async fn runner(pool: &SqlitePool, name: &str, tags: &[&str]) -> RunnerId {
    let new = NewRunner {
        name: name.to_owned(),
        tags: tags.iter().map(|t| t.to_string()).collect(),
    };
    let id = create_runner(pool, &new, name).await.unwrap().id;
    let mut r = get_runner(pool, id).await.unwrap().unwrap();
    r.status = RunnerStatus::Online;
    assert!(update_runner(pool, &r).await.unwrap());
    id
}

/// Applies `event` to the run as its runner would.
pub async fn step(pool: &SqlitePool, run: &Run, event: RunEvent, now: &str) -> Run {
    let by = AuditActor::Runner(run.runner_id.unwrap());
    if let RunEvent::Start { session } = event {
        return start_run(pool, run.id, by, session, now).await.unwrap().0;
    }
    transition_run(pool, run.id, by, &event, now).await.unwrap()
}

pub fn fail(fingerprint: &str) -> RunEvent {
    RunEvent::Fail {
        reason: format!("failed at {fingerprint}"),
        fingerprint: Some(fingerprint.to_owned()),
    }
}

pub async fn count(pool: &SqlitePool, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn ids(pool: &SqlitePool, sql: &str) -> Vec<i64> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_all(pool)
        .await
        .unwrap()
}

// --- invariants -------------------------------------------------------------

const LIVE: &str = "('queued', 'claimed', 'running')";

/// The engine's known-state invariants at `now`. `expected` lists the stuck kinds this
/// scenario documents as legitimate (each still carries a reason and an action); anything
/// else the stuck detector reports fails the scenario.
///
/// - Every run is terminal with a reason and an end time, or claimed/running with a lease
///   held by its runner. Nothing leaves a run `queued`: dispatch inserts and claims it in
///   one transaction. No lease outlives its run; at most one live run per agent and issue.
/// - No issue is checked out by a run that is not live; every open issue has a next actor.
/// - No wake is lost: each is dispatched (and has its run), coalesced into a survivor of the
///   same agent and issue that is itself pending, dispatched or dropped, pending for an
///   active agent (or one the loop breaker or the admin paused, on record: it fires on
///   resume), or
///   dropped with a reason; at most one wake per agent and issue is pending.
pub async fn assert_invariants(pool: &SqlitePool, now: &str, expected: &[StuckKind]) {
    let checks: [(&str, String); 9] = [
        (
            "terminal run without a reason or end",
            format!(
                "SELECT id FROM runs WHERE state NOT IN {LIVE} AND (terminal_reason IS NULL \
                 OR trim(terminal_reason) = '' OR ended_at IS NULL)"
            ),
        ),
        (
            "live run without its runner's lease",
            "SELECT id FROM runs r WHERE state IN ('claimed', 'running') AND NOT EXISTS \
             (SELECT 1 FROM leases l WHERE l.run_id = r.id AND l.runner_id IS r.runner_id)"
                .to_owned(),
        ),
        (
            "queued run (no lease, nothing will claim it)",
            "SELECT id FROM runs WHERE state = 'queued'".to_owned(),
        ),
        (
            "lease on an ended run",
            format!(
                "SELECT l.run_id FROM leases l JOIN runs r ON r.id = l.run_id \
                 WHERE r.state NOT IN {LIVE}"
            ),
        ),
        (
            "two live runs on one agent and issue",
            format!(
                "SELECT min(id) FROM runs WHERE state IN {LIVE} \
                 GROUP BY agent_id, issue_id HAVING count(*) > 1"
            ),
        ),
        (
            "issue checked out by a run that is not live",
            format!(
                "SELECT i.id FROM issues i WHERE i.checkout_run_id IS NOT NULL AND NOT EXISTS \
                 (SELECT 1 FROM runs r WHERE r.id = i.checkout_run_id AND r.state IN {LIVE})"
            ),
        ),
        (
            "open issue without a next actor",
            "SELECT id FROM issues WHERE state NOT IN ('done', 'cancelled') \
             AND next_agent_id IS NULL AND next_user_id IS NULL AND next_at IS NULL"
                .to_owned(),
        ),
        (
            "lost wake",
            "SELECT w.id FROM wake_requests w WHERE NOT ( \
             (w.status = 'dispatched' AND EXISTS \
                 (SELECT 1 FROM runs r WHERE r.wake_request_id = w.id)) \
             OR (w.status = 'coalesced' AND EXISTS (SELECT 1 FROM wake_requests s \
                 WHERE s.id = w.coalesced_into AND s.agent_id = w.agent_id \
                 AND s.issue_id IS w.issue_id \
                 AND s.status IN ('pending', 'dispatched', 'dropped'))) \
             OR (w.status = 'dropped' AND trim(coalesce(w.dropped_reason, '')) <> '') \
             OR (w.status = 'pending' AND EXISTS (SELECT 1 FROM agents a \
                 WHERE a.id = w.agent_id AND (a.status = 'active' OR a.paused_at IS NOT NULL \
                 OR EXISTS (SELECT 1 FROM audit_events e \
                     WHERE e.action = 'agent.paused_by_breaker' \
                     AND e.entity_kind = 'agent' AND e.entity_id = a.id)))))"
                .to_owned(),
        ),
        (
            "two pending wakes on one agent and issue",
            "SELECT min(id) FROM wake_requests WHERE status = 'pending' \
             GROUP BY agent_id, issue_id HAVING count(*) > 1"
                .to_owned(),
        ),
    ];
    for (what, sql) in &checks {
        let bad = ids(pool, sql).await;
        assert!(bad.is_empty(), "at {now}: {what}: {bad:?}");
    }

    let stuck = stuck_report(pool, now).await.unwrap();
    for s in &stuck {
        assert!(
            expected.contains(&s.kind),
            "at {now}: unexpected stuck entry {s:?}"
        );
        assert!(!s.reason.is_empty() && !s.action.is_empty(), "{s:?}");
    }
}

/// Scenario-documented stuck kinds.
pub const NONE: &[StuckKind] = &[];
