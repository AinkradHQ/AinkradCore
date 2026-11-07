//! The broker (C4; design `2026-11-06-core-connections-design` §4, §5, decision 7): a session's
//! harness calls a typed tool (`github.get_issue`), the runner forwards it over `agent.tools`
//! (`ainkrad_proto::v2::tools`), and the Core makes the upstream call with the sealed credential.
//! The credential never leaves this process: not to the runner, the sandbox, a log, an audit row,
//! an event or an error.
//!
//! **One call, in order** ([`Broker::handle`]):
//! 1. The tool is a known operation of a registered kind (else `unknown_tool`).
//! 2. The session is read from the Core's own rows (`store::connections::access`): it exists, is
//!    live and is placed on the runner that called. The user, the agent and the allowlist come
//!    from there and nowhere else; the call carries a tool and arguments. An agent's session with
//!    no allowlist is refused by `resolve` (`allowlist_required`).
//! 3. `secrets.mode` is on, the arguments are bounded, the session's rate and concurrency
//!    allow it (`rate_limited`).
//! 4. The adapter names the resource (`github::ops::build`, `jira::resource_of`): a bad argument
//!    is `bad_args`, before any decision.
//! 5. `store::connections::resolve::resolve` decides: effective limits, the default wins, an
//!    ambiguous use refuses, and a refusal never names a connection the caller is not granted.
//! 6. The connection's own rate, then the call under a timeout (`run`), with the exact
//!    `Resolved::limits`; the answer is scrubbed and bounded.
//! 7. Health is told only what the adapter says is about the credential or service (`health`).
//! 8. `record_use` writes `connection.used` for EVERY call that got this far, refusals included:
//!    validated names and codes only, never a payload. A call refused before it names a known
//!    tool is audited without an operation.
//!
//! The result is plain data or a plain refusal code with a fixed sentence.
//!
//! **The tool list** ([`Broker::tools`]) is the dry run: the operations of the capabilities the
//! session could use on some connection of a kind (user grant, narrowed by the agent's, inside the
//! allowlist). None when `secrets.mode` is off, the session is over, or it is an agent's with no
//! allowlist.
//! The supervisor sends it with the first poll and again whenever it changes.

mod fail;
mod gate;
mod health;
mod run;
mod schemas;
mod scrub;
mod supervise;
mod tools;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use ainkrad_core::settings::{Key, Scope};
use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::{MAX_ARGS_BYTES, ToolCall, ToolResult};
use serde_json::Value;
use sqlx::sqlite::SqlitePool;

use self::fail::{Fail, of_store, refuse};
pub use self::gate::Limits;
use self::gate::{Busy, Rate};
pub use self::supervise::{set_access, supervise};
use super::adapter::Registry;
use super::github::{self, Built, Github};
use super::jira::{self, Jira};
use crate::ops::secretbox::SecretBox;
use crate::store::connections::access::{self, Access, Granted};
use crate::store::connections::resolve::{self, Context};

/// What a call needs from the process: the store, the master key (`None`: no connection is ever
/// opened) and the clock.
pub struct Env<'a> {
    pub pool: &'a SqlitePool,
    pub sealer: Option<&'a Arc<SecretBox>>,
    pub now: &'a str,
}

pub struct Broker {
    reg: Registry,
    github: Github,
    jira: Arc<Jira>,
    gate: Arc<gate::Gate>,
    redactor: Redactor,
    supervised: std::sync::Mutex<std::collections::HashSet<String>>,
    /// Serialises the taking of calls off a poll answer (cursor advance), never their execution.
    intake: tokio::sync::Mutex<()>,
    /// Finished calls' results waiting to go to their runner, by session, and the sessions with a
    /// drainer open (one delivery stream each at most).
    outbox: std::sync::Mutex<
        std::collections::HashMap<String, std::collections::VecDeque<supervise::Pending>>,
    >,
    /// The last finished results per session, to answer a call the runner sends again.
    done: std::sync::Mutex<
        std::collections::HashMap<
            String,
            std::collections::VecDeque<(std::time::Instant, ToolResult)>,
        >,
    >,
    delivering: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl Broker {
    /// The server's broker: THE registry (`Registry::builtin_with` over the one shared `Jira`).
    pub fn new(jira: Arc<Jira>) -> Self {
        let github = Github::strict();
        let reg = Registry::builtin_with_github(github.clone(), Arc::clone(&jira));
        Self::with(reg, github, jira, Limits::default())
    }

    /// A broker over the given adapters (the tests' loopback ones).
    pub fn with(reg: Registry, github: Github, jira: Arc<Jira>, limits: Limits) -> Self {
        Self {
            reg,
            github,
            jira,
            gate: gate::Gate::new(limits),
            redactor: Redactor::new(),
            supervised: std::sync::Mutex::default(),
            intake: tokio::sync::Mutex::new(()),
            outbox: std::sync::Mutex::default(),
            done: std::sync::Mutex::default(),
            delivering: std::sync::Mutex::default(),
        }
    }

    /// The allowlist `g` really has. An explicit one is itself. A plain session with none gets the
    /// READ-class capabilities only: write is an explicit grant (design §4). An agent's session
    /// with none gets `None`, which `resolve` refuses (`allowlist_required`).
    fn allowlist(&self, g: &Granted) -> Option<Vec<String>> {
        match (&g.allowlist, &g.agent) {
            (Some(list), _) => Some(list.clone()),
            (None, Some(_)) => None,
            (None, None) => Some(
                self.reg
                    .descriptors()
                    .iter()
                    .flat_map(|d| d.capabilities.iter().filter(|c| !c.write))
                    .map(|c| c.name.to_owned())
                    .collect(),
            ),
        }
    }

    /// Writes the one audit row of a flood when its window ends, with the exact counts.
    fn schedule_flood(&self, pool: SqlitePool, session: String) {
        let gate = Arc::clone(&self.gate);
        let wait = gate.limits().flood_window;
        tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            let Some(flood) = gate.flood(&session) else {
                return;
            };
            let user = access::load(&pool, &session).await.ok().flatten();
            let user = user.map_or(0, |a| a.user);
            let row = access::audit_flood(&pool, user, &session, flood.count, &flood.ops).await;
            if let Err(e) = row {
                tracing::error!(error = ?e, "auditing a flood of tool calls failed");
            }
        });
    }

    /// Whether a supervisor of session `id`'s tool channel runs in this process.
    pub fn is_supervised(&self, id: &str) -> bool {
        let held = self.supervised.lock().unwrap_or_else(|e| e.into_inner());
        held.contains(id)
    }

    pub fn registry(&self) -> &Registry {
        &self.reg
    }

    /// The one shared GitHub adapter (its App key holder): the API (C5) uses this one.
    pub fn github(&self) -> &Github {
        &self.github
    }

    /// The one shared Jira (its OAuth app, flows and refresh locks): the API (C5) uses this one.
    pub fn jira(&self) -> &Arc<Jira> {
        &self.jira
    }
}

/// What a kind's operation touches, found by the adapter before any decision.
struct Prepared {
    built: Option<Built>,
    resource: Option<(&'static str, String)>,
}

fn prepare(kind: &str, op: &str, args: &Value) -> Result<Prepared, Fail> {
    match kind {
        "github" => {
            let built = github::build(op, args).map_err(|e| refuse("bad_args", &e.to_string()))?;
            let resource = Some(("repos", built.resource().to_owned()));
            Ok(Prepared {
                built: Some(built),
                resource,
            })
        }
        "jira" => {
            let p = jira::resource_of(op, args).map_err(|e| refuse("bad_args", &e))?;
            Ok(Prepared {
                built: None,
                resource: p.map(|p| ("projects", p)),
            })
        }
        _ => Err(refuse("unknown_kind", "no such kind")),
    }
}

pub(crate) async fn secrets_on(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    Ok(crate::store::settings::value_in(&mut conn, Key::SecretsMode, Scope::Server).await? != 0)
}

async fn load(env: &Env<'_>, session: &str) -> Result<Option<Access>, Fail> {
    access::load(env.pool, session)
        .await
        .map_err(|e| of_store(e.into()))
}

impl Broker {
    /// The refusal of a call about a session that does not exist, counted in its RUNNER's flood
    /// row (exact count, registered operation names only; the invented name is never kept).
    fn stranger(&self, env: &Env<'_>, runner: &str, op: Option<&str>) -> Fail {
        if self.gate.stranger(runner, op) {
            self.schedule_flood(env.pool.clone(), gate::Gate::runner_key(runner));
        }
        refuse("session", "no such session on this runner")
    }

    /// Runs one call and answers it. Never panics on caller input; every exit is audited.
    pub async fn handle(
        &self,
        env: &Env<'_>,
        runner: &str,
        session: &str,
        call: &ToolCall,
    ) -> ToolResult {
        let id = call.id.clone();
        match self.run_call(env, runner, session, call).await {
            Ok(v) => ToolResult {
                id,
                ok: true,
                result: Some(v),
                code: None,
                message: None,
            },
            Err(f) => ToolResult {
                id,
                ok: false,
                result: None,
                code: Some(f.code),
                message: Some(f.message),
            },
        }
    }

    async fn run_call(
        &self,
        env: &Env<'_>,
        runner: &str,
        session: &str,
        call: &ToolCall,
    ) -> Result<Value, Fail> {
        let known = call
            .tool
            .split_once('.')
            .and_then(|(kind, _)| self.reg.get(kind))
            .and_then(|a| {
                let d = a.descriptor();
                d.capability_of(&call.tool).map(|c| (d.kind, c.name))
            });
        let key: String = session.chars().take(64).collect();
        let op = known.map(|_| call.tool.as_str());
        // A session with a minute window here was seen to exist: its floods are refused without
        // a read. Any other name is looked up FIRST: one that does not exist has nobody to
        // attribute a row to and gets no window, however many a runner invents.
        let seen = match self.gate.has_window(&key) {
            true => None,
            false => Some(load(env, session).await?),
        };
        if matches!(seen, Some(None)) {
            return Err(self.stranger(env, runner, op));
        }
        // Every call of a session, known or not, refused or not, counts against its minute FIRST;
        // past it a call costs nothing but its share of the flood's one audit row, written when
        // the window ends with the exact count.
        if let Rate::Over { first } = self.gate.rate(&key, op) {
            if first {
                self.schedule_flood(env.pool.clone(), key);
            }
            return Err(refuse("rate_limited", "too many calls from this session"));
        }
        let acc = match seen {
            Some(acc) => acc,
            None => load(env, session).await?,
        };
        if acc.is_none() {
            return Err(self.stranger(env, runner, op));
        }
        let Some((kind, cap)) = known else {
            let user = acc.as_ref().map_or(0, |a| a.user);
            let session = acc.as_ref().map(|a| a.session.as_str());
            let audited = access::audit_unknown(env.pool, user, session, "unknown_tool").await;
            if let Err(e) = audited {
                tracing::error!(error = ?e, "auditing an unknown tool call failed");
            }
            return Err(refuse("unknown_tool", "no such tool"));
        };
        let mut used: Option<i64> = None;
        let out = self
            .decide(env, runner, acc.as_ref(), call, (kind, cap), &mut used)
            .await;
        // Every call that names a known tool is recorded, whatever the end.
        let (result, code) = match &out {
            Ok(_) => ("ok", None),
            Err(f) => (f.result, Some(f.code.as_str())),
        };
        let granted = acc.as_ref().map(|a| &a.grant);
        let allow = granted.and_then(|g| self.allowlist(g));
        let cx = Context {
            workspace: acc.as_ref().map_or(0, |a| a.user),
            user: acc.as_ref().map_or(0, |a| a.user),
            role: "member",
            agent: granted.and_then(|g| g.agent.as_deref()),
            session: acc.as_ref().map(|a| a.session.as_str()),
            capability: cap,
            operation: Some(&call.tool),
            resource: None,
            allowlist: allow.as_deref(),
        };
        let rec = resolve::record_use(
            env.pool,
            &self.reg,
            used,
            kind,
            (&call.tool, result, code),
            &cx,
        )
        .await;
        if let Err(e) = rec {
            tracing::error!(error = ?e, "recording a connection use failed");
        }
        out
    }

    /// Whether this call may run NOW: the session is live and on this runner, `secrets.mode` is on,
    /// and `resolve` finds a connection (grants, limits, health). Run before a call waits for its
    /// place and again after, so a call that queued while a grant was revoked, a session ended or
    /// the broker was switched off does not run.
    async fn admit(
        &self,
        env: &Env<'_>,
        runner: &str,
        acc: Option<&Access>,
        call: &ToolCall,
        (kind, cap): (&'static str, &'static str),
        prep: &Prepared,
    ) -> Result<resolve::Resolved, Fail> {
        // The runner that calls must be the one the session is on.
        let acc = acc
            .filter(|a| a.runner == runner)
            .ok_or_else(|| refuse("session", "no such session on this runner"))?;
        if !acc.live {
            return Err(refuse("session_over", "the session is over"));
        }
        if env.sealer.is_none() {
            return Err(refuse(
                "secrets_unavailable",
                "connections are not available",
            ));
        }
        if !secrets_on(env.pool).await.map_err(|e| of_store(e.into()))? {
            return Err(refuse("secrets_disabled", "connections are off"));
        }
        let g = &acc.grant;
        let allow = self.allowlist(g);
        let cx = Context {
            workspace: acc.user,
            user: acc.user,
            role: "member",
            agent: g.agent.as_deref(),
            session: Some(&acc.session),
            capability: cap,
            operation: Some(&call.tool),
            resource: prep.resource.as_ref().map(|(k, v)| (*k, v.as_str())),
            allowlist: allow.as_deref(),
        };
        resolve::resolve(env.pool, &self.reg, kind, &cx, env.now)
            .await
            .map_err(of_store)
    }

    async fn decide(
        &self,
        env: &Env<'_>,
        runner: &str,
        acc: Option<&Access>,
        call: &ToolCall,
        (kind, cap): (&'static str, &'static str),
        used: &mut Option<i64>,
    ) -> Result<Value, Fail> {
        let size = serde_json::to_string(&call.args).map_or(usize::MAX, |s| s.len());
        if size > MAX_ARGS_BYTES {
            return Err(refuse("bad_args", "the arguments are too large"));
        }
        let prep = prepare(kind, &call.tool, &call.args)?;
        // Early: refuse what is already refused without waiting for a place.
        let first = self
            .admit(env, runner, acc, call, (kind, cap), &prep)
            .await?;
        *used = Some(first.connection.id);
        let acc = acc.ok_or_else(|| refuse("session", "no such session on this runner"))?;
        // A place among the session's, the user's and everyone's calls: waits (bounded) when they
        // are taken, and is refused when the session's queue is full.
        let placed = tokio::time::timeout(
            self.gate.limits().queue_wait,
            self.gate.acquire(&acc.session, acc.user),
        )
        .await;
        let _permit = match placed {
            Err(_) => return Err(refuse("queue_timeout", "no place came free in time")),
            Ok(None) => return Err(refuse("rate_limited", "too many calls are waiting")),
            Ok(Some(p)) => p,
        };
        // Late: everything may have changed while it waited.
        let fresh = access::load(env.pool, &acc.session)
            .await
            .map_err(|e| of_store(e.into()))?;
        let r = self
            .admit(env, runner, fresh.as_ref(), call, (kind, cap), &prep)
            .await?;
        *used = Some(r.connection.id);
        let acc = fresh.as_ref().unwrap_or(acc);
        let g = &acc.grant;
        let sealer = env
            .sealer
            .ok_or_else(|| refuse("secrets_unavailable", "connections are not available"))?;
        let d = self.reg.get(kind).map(|a| a.descriptor());
        let hourly = d.map_or(1, |d| d.hourly_calls);
        let write = d.and_then(|d| d.capability(cap)).is_some_and(|c| c.write);
        // Only now that the call WILL run does it use any of the connection's budget.
        if let Err(busy) = self
            .gate
            .connection(r.connection.id, &acc.session, acc.user, hourly)
        {
            return Err(match busy {
                Busy::Rate => refuse("rate_limited", "too many calls on this connection"),
                Busy::Share => refuse(
                    "connection_busy",
                    "this session or user has used its share of the connection's hour",
                ),
                Busy::Until(at) => refuse(
                    "connection_busy",
                    &match at {
                        Some(t) => format!(
                            "the connection is busy and can be used again at {}",
                            crate::scheduler::iso_of_unix(t)
                        ),
                        None => "the connection has used its budget for this hour".to_owned(),
                    },
                ),
            });
        }
        let job = run::Job {
            github: self.github.clone(),
            jira: Arc::clone(&self.jira),
            redactor: self.redactor.clone(),
            pool: env.pool.clone(),
            sealer: Arc::clone(sealer),
            now: env.now.to_owned(),
            device: runner.to_owned(),
            user: acc.user,
            op: call.tool.clone(),
            args: call.args.clone(),
            built: prep.built,
            resolved: r.clone(),
        };
        let mut task = tokio::spawn(run::execute(job));
        let limit = self.gate.limits().timeout;
        let ran = match tokio::time::timeout(limit, &mut task).await {
            Ok(Ok(ran)) => ran,
            Ok(Err(_)) => run::Ran {
                out: Err(refuse("internal", "the call did not finish")),
                quota: None,
            },
            Err(_) if write => {
                // The upstream write may still land: it finishes in its own task and is audited
                // there. The agent is told the truth, not "timed out" (a retry would repeat it).
                let late = Late {
                    pool: env.pool.clone(),
                    reg: self.reg.clone(),
                    gate: Arc::clone(&self.gate),
                    now: env.now.to_owned(),
                    user: acc.user,
                    agent: g.agent.clone(),
                    session: acc.session.clone(),
                    allowlist: self.allowlist(g),
                    connection: r.connection.id,
                    kind,
                    cap,
                    op: call.tool.clone(),
                };
                tokio::spawn(late.finish(task));
                return Err(Fail {
                    code: "outcome_unknown".to_owned(),
                    message: "the call may have been applied; check before retrying".to_owned(),
                    result: "error",
                    feed: None,
                });
            }
            Err(_) => {
                task.abort();
                run::Ran {
                    out: Err(Fail {
                        code: "timed_out".to_owned(),
                        message: "the service did not answer in time".to_owned(),
                        result: "error",
                        feed: None,
                    }),
                    quota: None,
                }
            }
        };
        self.after(
            env.pool,
            env.now,
            (acc.user, g.agent.as_deref(), r.connection.id),
            &ran,
        )
        .await;
        ran.out
    }

    /// What a finished call tells the gate (the service's own budget) and health.
    async fn after(
        &self,
        pool: &SqlitePool,
        now: &str,
        (user, agent, id): (i64, Option<&str>, i64),
        ran: &run::Ran,
    ) {
        after(&self.gate, pool, now, (user, agent, id), ran).await;
    }
}

async fn after(
    gate: &gate::Gate,
    pool: &SqlitePool,
    now: &str,
    (user, agent, id): (i64, Option<&str>, i64),
    ran: &run::Ran,
) {
    if let Some((remaining, reset, retry)) = ran.quota {
        gate.note_upstream(id, remaining, reset, retry);
    }
    // Only a call that reached the service says anything about it: a refusal of ours, and an
    // end the adapter says is not about the credential or the service (a 404, a refused
    // input, a huge answer), tell health nothing at all.
    let feed = ran.out.as_ref().err().and_then(|f| f.feed.as_ref());
    if (ran.out.is_ok() || feed.is_some())
        && let Err(e) = health::forward(pool, user, id, agent, feed, now).await
    {
        tracing::warn!(error = %e, "telling a connection's health failed");
    }
}

/// A write whose caller stopped waiting: it finishes here, tells health, and is audited.
struct Late {
    pool: SqlitePool,
    reg: Registry,
    gate: Arc<gate::Gate>,
    now: String,
    user: i64,
    agent: Option<String>,
    session: String,
    allowlist: Option<Vec<String>>,
    connection: i64,
    kind: &'static str,
    cap: &'static str,
    op: String,
}

impl Late {
    async fn finish(self, task: tokio::task::JoinHandle<run::Ran>) {
        let Ok(ran) = task.await else { return };
        after(
            &self.gate,
            &self.pool,
            &self.now,
            (self.user, self.agent.as_deref(), self.connection),
            &ran,
        )
        .await;
        let (result, code) = match &ran.out {
            Ok(_) => ("ok", "late_ok".to_owned()),
            Err(f) => (f.result, format!("late_{}", f.code)),
        };
        let cx = Context {
            workspace: self.user,
            user: self.user,
            role: "member",
            agent: self.agent.as_deref(),
            session: Some(&self.session),
            capability: self.cap,
            operation: Some(&self.op),
            resource: None,
            allowlist: self.allowlist.as_deref(),
        };
        let rec = resolve::record_use(
            &self.pool,
            &self.reg,
            Some(self.connection),
            self.kind,
            (&self.op, result, Some(&code)),
            &cx,
        )
        .await;
        if let Err(e) = rec {
            tracing::error!(error = ?e, "recording a late connection use failed");
        }
    }
}
