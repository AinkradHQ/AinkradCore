//! The broker (C4; design `2026-11-06-core-connections-design` §4, §5, decision 7): a session's
//! harness calls a typed tool (`github.get_issue`), the runner forwards it over `agent.tools`
//! (`ainkrad_proto::v2::tools`), and the Core makes the upstream call with the sealed credential.
//! The credential never leaves this process: not to the runner, the sandbox, a log, an audit row,
//! an event or an error.
//!
//! **One call, in order** ([`Broker::handle`]):
//! 1. The tool is a known operation of a registered kind (else `unknown_tool`).
//! 2. The session is read from the Core's own rows (`store::connections::access`): it exists, is
//!    live, is placed on the runner that called, and has connection access. The user, the agent
//!    and the allowlist come from there and nowhere else; the call carries a tool and arguments.
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
//! allowlist). None when `secrets.mode` is off, the session has no access row, or it is over.
//! The supervisor sends it with the first poll and again whenever it changes.

mod fail;
mod gate;
mod health;
mod run;
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
pub use self::supervise::supervise;
use super::adapter::Registry;
use super::github::{self, Built, Github};
use super::jira::{self, Jira};
use crate::ops::secretbox::SecretBox;
use crate::store::connections::access::{self, Access};
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
}

impl Broker {
    /// The server's broker: THE registry (`Registry::builtin_with` over the one shared `Jira`).
    pub fn new(jira: Arc<Jira>) -> Self {
        let reg = Registry::builtin_with(Arc::clone(&jira));
        Self::with(reg, Github::strict(), jira, Limits::default())
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
        }
    }

    pub fn registry(&self) -> &Registry {
        &self.reg
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

impl Broker {
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
        let acc = access::load(env.pool, session)
            .await
            .map_err(|e| of_store(e.into()))?;
        let Some((kind, cap)) = known else {
            let user = acc.as_ref().map_or(0, |a| a.user);
            let session = acc.as_ref().map(|a| a.session.as_str());
            // Counted against the session's rate like any call, so a flood of unknown names
            // cannot flood the audit log.
            if self
                .gate
                .enter(&acc.as_ref().map_or_else(String::new, |a| a.session.clone()))
                .is_some()
            {
                let audited = access::audit_unknown(env.pool, user, session, "unknown_tool").await;
                if let Err(e) = audited {
                    tracing::error!(error = ?e, "auditing an unknown tool call failed");
                }
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
        let empty: [String; 0] = [];
        let granted = acc.as_ref().and_then(|a| a.grant.as_ref());
        let cx = Context {
            workspace: acc.as_ref().map_or(0, |a| a.user),
            user: acc.as_ref().map_or(0, |a| a.user),
            role: "member",
            agent: granted.and_then(|g| g.agent.as_deref()),
            session: acc.as_ref().map(|a| a.session.as_str()),
            capability: cap,
            operation: Some(&call.tool),
            resource: None,
            allowlist: Some(granted.map_or(&empty[..], |g| &g.allowlist[..])),
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

    #[allow(clippy::too_many_arguments)]
    async fn decide(
        &self,
        env: &Env<'_>,
        runner: &str,
        acc: Option<&Access>,
        call: &ToolCall,
        (kind, cap): (&'static str, &'static str),
        used: &mut Option<i64>,
    ) -> Result<Value, Fail> {
        // The runner that calls must be the one the session is on.
        let acc = acc
            .filter(|a| a.runner == runner)
            .ok_or_else(|| refuse("session", "no such session on this runner"))?;
        if !acc.live {
            return Err(refuse("session_over", "the session is over"));
        }
        let g = acc
            .grant
            .as_ref()
            .ok_or_else(|| refuse("no_access", "this session has no connection tools"))?;
        let sealer = env
            .sealer
            .ok_or_else(|| refuse("secrets_unavailable", "connections are not available"))?;
        if !secrets_on(env.pool).await.map_err(|e| of_store(e.into()))? {
            return Err(refuse("secrets_disabled", "connections are off"));
        }
        let size = serde_json::to_string(&call.args).map_or(usize::MAX, |s| s.len());
        if size > MAX_ARGS_BYTES {
            return Err(refuse("bad_args", "the arguments are too large"));
        }
        let _permit = self
            .gate
            .enter(&acc.session)
            .ok_or_else(|| refuse("rate_limited", "too many calls from this session"))?;
        let prep = prepare(kind, &call.tool, &call.args)?;
        let cx = Context {
            workspace: acc.user,
            user: acc.user,
            role: "member",
            agent: g.agent.as_deref(),
            session: Some(&acc.session),
            capability: cap,
            operation: Some(&call.tool),
            resource: prep.resource.as_ref().map(|(k, v)| (*k, v.as_str())),
            allowlist: Some(&g.allowlist[..]),
        };
        let r = resolve::resolve(env.pool, &self.reg, kind, &cx, env.now)
            .await
            .map_err(of_store)?;
        *used = Some(r.connection.id);
        if !self.gate.connection(r.connection.id) {
            return Err(refuse("rate_limited", "too many calls on this connection"));
        }
        let c = run::Call {
            pool: env.pool,
            sealer,
            now: env.now,
            device: runner,
            user: acc.user,
            op: &call.tool,
            args: &call.args,
            built: prep.built.as_ref(),
        };
        let ran = tokio::time::timeout(self.gate.limits().timeout, async {
            match kind {
                "github" => run::github(self, &c, &r).await,
                _ => run::jira(self, &c, &r).await,
            }
        })
        .await
        .unwrap_or_else(|_| {
            Err(Fail {
                code: "timed_out".to_owned(),
                message: "the service did not answer in time".to_owned(),
                result: "error",
                feed: None,
            })
        });
        // Only a call that reached the service says anything about it: a refusal of ours, and an
        // end the adapter says is not about the credential or the service (a 404, a refused
        // input, a huge answer), tell health nothing at all.
        let feed = ran.as_ref().err().and_then(|f| f.feed.as_ref());
        if ran.is_ok() || feed.is_some() {
            let agent = g.agent.as_deref();
            let sent = health::forward(env.pool, acc.user, r.connection.id, agent, feed, env.now);
            if let Err(e) = sent.await {
                tracing::warn!(error = %e, "telling a connection's health failed");
            }
        }
        ran
    }
}
