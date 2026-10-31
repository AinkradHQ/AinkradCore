//! Dispatch (E2.2): a due wake becomes a run on an online runner, and the run's session is
//! started on the platform. The pull protocol of the monolith (runners asking for work) is a push
//! here: the engine walks the wakes and asks the platform for a session.
//!
//! One wake at a time, in three steps so no write transaction is held across the runner:
//! 1. in a transaction: drop stale wakes, pick the oldest due candidate whose budgets admit it
//!    (`admit_in`: an exhausted hard-stop budget keeps the wake pending and opens one overrun
//!    approval per period);
//! 2. choose a runner (`Host::runners`), then in a transaction re-check the wake, mark it
//!    `dispatched`, insert the run and claim it;
//! 3. start the session (`Host::start`); a runner too busy hands the wake back, any other
//!    refusal fails the run (and schedules its retry).
//!
//! A crash between 2 and 3 leaves a claimed run with no session: `reconcile` fails it after a
//! grace and the retry wake runs it again.

use std::future::Future;

use ainkrad_core_server::agents::ModuleAgents;
use ainkrad_core_server::api::App;
use ainkrad_core_server::store::agents as sessions;
use ainkrad_proto::v2::{AgentDecide, AgentSend, AgentStop, Command, ErrorCode};
use serde_json::json;

use super::prompt::brief;
use super::route::{chain_in, task_tier_in};
use super::*;
use crate::domain::exec::RunEvent;
use crate::domain::org::{ModelRoute, Tier};
use crate::store::audit::{self, Event};
use crate::store::gov::admit_in;
use crate::store::work::requirements::plan_held;

/// What the engine does to a session it owns.
#[derive(Debug, Clone)]
pub enum Instruction {
    Stop {
        kill: bool,
    },
    Send(String),
    Decide {
        request: String,
        approved: bool,
        reply: Option<String>,
    },
}

/// What a session is started with.
#[derive(Debug, Clone)]
pub struct StartSpec {
    /// The run this session is for: the platform's pointer back to it (`owner_ref`), so a
    /// resumed session finds its run and is handed a fresh token (`mcp::credentials`).
    pub run: RunId,
    pub runner: String,
    pub harness: String,
    pub model: String,
    pub prompt: String,
    pub workspace: Option<serde_json::Value>,
    pub policy: serde_json::Value,
    /// The device that enabled the engine.
    pub by_device: String,
}

/// Why a session did not start.
#[derive(Debug)]
pub enum StartFailure {
    /// The runner is gone or full: nothing was started, the wake goes back to the queue.
    Busy(String),
    /// The session cannot start (a refusal retrying will not fix): the run fails.
    Failed(String),
}

/// The platform as the engine uses it; the production one is [`Platform`], tests bring their own.
pub trait Host: Send + Sync {
    /// Runners that can take one more `harness` session now, best first.
    fn runners(&self, app: &App, harness: &str) -> impl Future<Output = Vec<String>> + Send;
    /// Creates and starts the session; its id.
    fn start(
        &self,
        app: &App,
        spec: &StartSpec,
    ) -> impl Future<Output = Result<String, StartFailure>> + Send;
    /// Tells the session something; a refusal says why (never a value).
    fn instruct(
        &self,
        app: &App,
        session: &str,
        what: Instruction,
    ) -> impl Future<Output = Result<(), String>> + Send;
}

/// The module's handle on the Core's agent sessions: its id comes from the module itself.
fn agents() -> ModuleAgents {
    ModuleAgents::of(&crate::Citadel)
}

/// The Core's agent-session service.
pub struct Platform;

impl Host for Platform {
    async fn runners(&self, app: &App, harness: &str) -> Vec<String> {
        let mut ids: Vec<(usize, String)> = Vec::new();
        for (id, r) in app.hub.runners() {
            let offers = r.online
                && r.drivers
                    .iter()
                    .any(|d| d.name == ainkrad_proto::v2::AGENT_DRIVER);
            if offers
                && ainkrad_core_server::agents::admit(app, &id, harness)
                    .await
                    .is_ok()
            {
                ids.push((r.load, id));
            }
        }
        ids.sort();
        ids.into_iter().map(|(_, id)| id).collect()
    }

    async fn start(&self, app: &App, spec: &StartSpec) -> Result<String, StartFailure> {
        use ainkrad_core_server::agents::{Refusal, describe};
        let new = sessions::NewSession {
            runner: &spec.runner,
            harness: &spec.harness,
            model: Some(&spec.model),
            prompt: Some(&spec.prompt),
            workspace: spec.workspace.as_ref(),
            policy: &spec.policy,
            secrets: &[],
            created_by: &spec.by_device,
        };
        let owner_ref = format!("run:{}", spec.run.0);
        match agents().create_ref(app, &new, Some(&owner_ref)).await {
            Ok(s) => Ok(s.id),
            Err(Refusal::Runner(e)) if matches!(e.code, ErrorCode::Busy | ErrorCode::Offline) => {
                Err(StartFailure::Busy(e.message))
            }
            Err(e) => Err(StartFailure::Failed(describe(&e))),
        }
    }

    async fn instruct(&self, app: &App, session: &str, what: Instruction) -> Result<(), String> {
        use ainkrad_core_server::agents::describe;
        let id = session.to_owned();
        let command = match what {
            Instruction::Stop { kill } => Command::AgentStop(AgentStop { session: id, kill }),
            Instruction::Send(text) => Command::AgentSend(AgentSend { session: id, text }),
            Instruction::Decide {
                request,
                approved,
                reply,
            } => Command::AgentDecide(AgentDecide {
                session: id,
                request,
                approved,
                reply,
            }),
        };
        agents()
            .instruct(app, session, command)
            .await
            .map_err(|e| describe(&e))
    }
}

/// How many due wakes one dispatch looks at past budget-blocked ones.
// ponytail: a backlog of more blocked wakes than this starves the ones behind it until approvals
// clear; a per-agent skip list is the upgrade if that ever bites.
const ADMISSION_CANDIDATES: i64 = 16;

struct Candidate {
    wake: i64,
    agent: AgentId,
    issue: Option<IssueId>,
    /// The task's tier, and where it may start: the agent's model for the tier, its own, its
    /// fallbacks (`route::chain_in`).
    tier: Tier,
    chain: Vec<ModelRoute>,
    reason: String,
}

/// Takes the oldest due `pending` wake the engine may serve and starts its run; `None` when
/// there is nothing to do (the engine is off, no wake is due, a budget blocks it, no runner is
/// free). A wake is served when its agent is `active`, no run for its issue is live (for an
/// issue-less wake, none of that agent's), its issue's project has fewer live runs than its
/// `max_parallel_runs`, and its requirement's plan does not hold it back; a wake a hard-stop
/// budget would block stays pending, with the budget's `budget_overrun` approval opened once
/// per period.
pub async fn dispatch_next<H: Host>(app: &App, host: &H, now: &str) -> Result<Option<Run>, Error> {
    let Some(by_device) = engine_device(&app.pool).await? else {
        return Ok(None);
    };
    let Some(c) = pick(&app.pool, now).await? else {
        return Ok(None);
    };
    // The first entry of the chain a runner can take now.
    let mut chosen = None;
    for route in &c.chain {
        if let Some(runner) = host
            .runners(app, route.harness.as_str())
            .await
            .into_iter()
            .next()
        {
            chosen = Some((runner, route.clone()));
            break;
        }
    }
    let Some((runner, route)) = chosen else {
        return Ok(None);
    };
    let Some((run, brief)) = claim(&app.pool, &c, &route, &runner, now).await? else {
        return Ok(None);
    };
    let spec = StartSpec {
        run: run.id,
        runner,
        harness: route.harness.as_str().to_owned(),
        model: route.model.clone(),
        prompt: brief.prompt,
        workspace: brief.workspace,
        policy: brief.policy,
        by_device,
    };
    let started = match &spec.workspace {
        Some(w)
            if serde_json::from_value::<ainkrad_proto::runner::Workspace>(w.clone())
                .is_ok_and(|w| w.problem().is_some()) =>
        {
            Err(StartFailure::Failed(
                "the project's repo is not a legal workspace".into(),
            ))
        }
        _ => host.start(app, &spec).await,
    };
    match started {
        Ok(session) => {
            sqlx::query(
                "UPDATE citadel_runs SET session_id = ? WHERE id = ? AND session_id IS NULL",
            )
            .bind(&session)
            .bind(run.id.0)
            .execute(&app.pool)
            .await?;
            // The run may be over already (cancelled while the session was starting): nothing
            // may keep working unaccounted, so the session is killed now and its usage counted.
            let now_run = get_run(&app.pool, run.id)
                .await?
                .ok_or(Error::RowNotFound)?;
            if now_run.state.is_terminal() {
                if let Err(why) = host
                    .instruct(app, &session, Instruction::Stop { kill: true })
                    .await
                {
                    tracing::warn!(
                        run = run.id.0,
                        why,
                        "stopping a session of an ended run failed; the sweeper retries"
                    );
                }
                if let Some(s) = sessions::get(&app.pool, &session).await? {
                    super::reconcile::record_usage(
                        &app.pool,
                        &now_run,
                        &s,
                        now,
                        &mut Default::default(),
                    )
                    .await?;
                }
            }
        }
        Err(StartFailure::Busy(why)) => give_back(&app.pool, &run, &why, now).await?,
        Err(StartFailure::Failed(why)) => {
            let fail = RunEvent::Fail {
                reason: format!(
                    "start failed: {}",
                    ainkrad_proto::redact::Redactor::new().text(&why)
                ),
                fingerprint: None,
            };
            transition_run(&app.pool, run.id, SYSTEM, &fail, now)
                .await
                .map_err(into_db)?;
        }
    }
    get_run(&app.pool, run.id).await
}

pub(crate) fn into_db(e: TransitionError) -> Error {
    match e {
        TransitionError::Db(e) => e,
        other => Error::Protocol(other.to_string()),
    }
}

/// Step 1: the candidate whose budgets admit it.
async fn pick(pool: &sqlx::SqlitePool, now: &str) -> Result<Option<Candidate>, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    super::wake::drop_stale_in(&mut tx, now).await?;
    let rows = sqlx::query(concat!(
        "SELECT w.id, w.agent_id, w.issue_id, w.reason, a.company_id \
         FROM citadel_wake_requests w JOIN citadel_agents a ON a.id = w.agent_id \
         WHERE w.status = 'pending' AND a.status = 'active' \
         AND (w.not_before IS NULL OR julianday(w.not_before) <= julianday(?1)) \
         AND NOT EXISTS (SELECT 1 FROM citadel_issues wi JOIN citadel_projects wp \
                 ON wp.id = wi.project_id WHERE wi.id = w.issue_id \
             AND wp.max_parallel_runs IS NOT NULL \
             AND wp.max_parallel_runs <= (SELECT count(*) FROM citadel_runs pr \
                 JOIN citadel_issues pi ON pi.id = pr.issue_id WHERE pi.project_id = wi.project_id \
                 AND pr.state IN ('queued', 'claimed', 'running'))) \
         AND NOT EXISTS (SELECT 1 FROM citadel_runs r WHERE r.state IN ('queued', 'claimed', 'running') \
             AND CASE WHEN w.issue_id IS NULL THEN r.agent_id = w.agent_id AND r.issue_id IS NULL \
                 ELSE r.issue_id = w.issue_id END) \
         AND NOT ",
        plan_held!("w.agent_id", "w.issue_id"),
        " ORDER BY coalesce((SELECT priority FROM citadel_issues WHERE id = w.issue_id), 0) DESC, \
         w.id LIMIT ?2"
    ))
    .bind(now)
    .bind(ADMISSION_CANDIDATES)
    .fetch_all(&mut *tx)
    .await?;
    let mut picked = None;
    for row in rows {
        let agent = AgentId(row.try_get("agent_id")?);
        let company = crate::domain::org::CompanyId(row.try_get("company_id")?);
        let issue = row.try_get::<Option<i64>, _>("issue_id")?.map(IssueId);
        if admit_in(&mut tx, agent, company, issue, now).await? {
            let tier = task_tier_in(&mut tx, issue).await?;
            picked = Some(Candidate {
                wake: row.try_get("id")?,
                agent,
                issue,
                tier,
                chain: chain_in(&mut tx, agent, tier).await?,
                reason: row.try_get("reason")?,
            });
            break;
        }
    }
    // Keeps the overrun approvals admission opened.
    tx.commit().await?;
    Ok(picked)
}

/// Step 2: the wake becomes `dispatched` and its run is inserted and claimed, if the wake is
/// still pending and nothing else took its place since step 1.
async fn claim(
    pool: &sqlx::SqlitePool,
    c: &Candidate,
    route: &ModelRoute,
    runner: &str,
    now: &str,
) -> Result<Option<(Run, prompt::Brief)>, Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let took = sqlx::query(
        "UPDATE citadel_wake_requests SET status = 'dispatched' WHERE id = ? AND status = 'pending'",
    )
    .bind(c.wake)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM citadel_runs r WHERE r.state IN ('queued', 'claimed', 'running') \
         AND CASE WHEN ?2 IS NULL THEN r.agent_id = ?1 AND r.issue_id IS NULL ELSE r.issue_id = ?2 END)",
    )
    .bind(c.agent.0)
    .bind(c.issue.map(|i| i.0))
    .fetch_one(&mut *tx)
    .await?;
    if took == 0 || busy {
        return Ok(None); // dropped by the rollback
    }
    let brief = brief(&mut tx, c.agent, c.issue, &c.reason).await?;
    let queued = sqlx::query(concat!(
        "INSERT INTO citadel_runs (agent_id, issue_id, wake_request_id, harness, model_used, queued_at) \
         VALUES (?, ?, ?, ?, ?, ?) RETURNING ",
        run_columns!()
    ))
    .bind(c.agent.0)
    .bind(c.issue.map(|i| i.0))
    .bind(c.wake)
    .bind(route.harness.as_str())
    .bind(&route.model)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .and_then(run)?;
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
        .bind(c.agent.0)
        .fetch_one(&mut *tx)
        .await?;
    audit::append(
        &mut tx,
        Event::new(SYSTEM, "wake.dispatched")
            .entity("wake_request", c.wake)
            .company(company)
            .run(queued.id.0)
            .details(
                json!({"model": route.model, "harness": route.harness.as_str(),
                "tier": c.tier.as_str(), "runner": runner}),
            ),
    )
    .await?;
    let claim = RunEvent::Claim {
        runner: runner.to_owned(),
    };
    let claimed = transition_in(&mut tx, &queued, SYSTEM, &claim, now)
        .await
        .map_err(into_db)?;
    tx.commit().await?;
    Ok(Some((claimed, brief)))
}

/// The runner could not take the session after all: the run is cancelled (not a failure, never
/// retried) and its wake goes back to `pending`.
async fn give_back(pool: &sqlx::SqlitePool, run: &Run, why: &str, now: &str) -> Result<(), Error> {
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    let current = run_in(&mut tx, run.id).await?.ok_or(Error::RowNotFound)?;
    let cancel = RunEvent::Cancel {
        reason: format!("no runner took it: {why}"),
    };
    transition_in(&mut tx, &current, SYSTEM, &cancel, now)
        .await
        .map_err(into_db)?;
    sqlx::query("UPDATE citadel_wake_requests SET status = 'pending' WHERE id = ? AND status = 'dispatched'")
        .bind(run.wake_request_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await
}
