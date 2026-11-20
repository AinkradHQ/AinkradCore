//! A read-only call a module makes for the workspace owner, with no AI session (the Brain's
//! collectors of Jira issues and GitHub pull requests). It goes through the same steps as a
//! session's call: the operation is a known read, the adapter names the resource, `resolve`
//! decides by the owner's grants and the connection's health, the connection's budget is counted,
//! the credential is opened only for the call, and the answer is scrubbed and bounded. A write
//! operation is never run here. Every call is recorded (`connection.used`).

use std::sync::Arc;

use ainkrad_proto::v2::MAX_ARGS_BYTES;
use serde_json::Value;

use super::fail::{Fail, of_store, refuse};
use super::gate::Busy;
use super::prepare::prepare;
use super::{Broker, Env, run};
use crate::store::connections::resolve::{self, Context, Resolved};
use crate::store::connections::{self as connection};

/// Why a read did not return data: a plain code and a fixed sentence, as a tool call's refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadError {
    pub code: String,
    pub message: String,
}

impl From<Fail> for ReadError {
    fn from(f: Fail) -> Self {
        Self {
            code: f.code,
            message: f.message,
        }
    }
}

/// The key the gate counts a module's calls under (`Gate::connection`'s "session").
const WHO: &str = "module-brain";

impl Broker {
    /// Runs the read operation `op` (`jira.search_issues`) for `user`, the workspace owner.
    pub async fn read(
        &self,
        env: &Env<'_>,
        user: i64,
        device: &str,
        op: &str,
        args: &Value,
    ) -> Result<Value, ReadError> {
        self.read_on(env, user, device, op, args, None).await
    }

    /// Runs the read operation `op` on connection `connection` itself, for an admin choosing what
    /// to let AI reach (the Connections picker): it is asked before any grant exists, so no grant
    /// is looked up and the call is unlimited. The connection must be the workspace's, of the
    /// operation's kind and not turned off; a write operation is still never run.
    pub async fn pick(
        &self,
        env: &Env<'_>,
        user: i64,
        device: &str,
        connection: i64,
        op: &str,
        args: &Value,
    ) -> Result<Value, ReadError> {
        self.read_on(env, user, device, op, args, Some(connection))
            .await
    }

    async fn read_on(
        &self,
        env: &Env<'_>,
        user: i64,
        device: &str,
        op: &str,
        args: &Value,
        only: Option<i64>,
    ) -> Result<Value, ReadError> {
        let (kind, cap, write) = op
            .split_once('.')
            .and_then(|(kind, _)| self.reg.get(kind))
            .and_then(|a| {
                let d = a.descriptor();
                d.capability_of(op).map(|c| (d.kind, c.name, c.write))
            })
            .ok_or_else(|| ReadError::from(refuse("unknown_tool", "no such tool")))?;
        if write {
            return Err(refuse("not_a_read", "only a read operation may be run here").into());
        }
        let out = self
            .read_in(env, user, device, op, args, (kind, cap), only)
            .await;
        let (result, code) = match &out {
            Ok(_) => ("ok", None),
            Err((f, _)) => (f.result, Some(f.code.as_str())),
        };
        let cx = ctx(user, cap, op, None);
        let used = out
            .as_ref()
            .err()
            .and_then(|(_, id)| *id)
            .or_else(|| out.as_ref().ok().map(|(_, id)| *id));
        if let Err(e) =
            resolve::record_use(env.pool, &self.reg, used, kind, (op, result, code), &cx).await
        {
            tracing::error!(error = ?e, "recording a connection use failed");
        }
        out.map(|(v, _)| v).map_err(|(f, _)| f.into())
    }

    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    async fn read_in(
        &self,
        env: &Env<'_>,
        user: i64,
        device: &str,
        op: &str,
        args: &Value,
        (kind, cap): (&'static str, &'static str),
        only: Option<i64>,
    ) -> Result<(Value, i64), (Fail, Option<i64>)> {
        let fail = |f: Fail| (f, None);
        if serde_json::to_string(args).map_or(usize::MAX, |s| s.len()) > MAX_ARGS_BYTES {
            return Err(fail(refuse("bad_args", "the arguments are too large")));
        }
        let sealer = env.sealer.ok_or_else(|| {
            fail(refuse(
                "secrets_unavailable",
                "connections are not available",
            ))
        })?;
        if !super::secrets_on(env.pool)
            .await
            .map_err(|e| fail(of_store(e.into())))?
        {
            return Err(fail(refuse("secrets_disabled", "connections are off")));
        }
        let prep = prepare(kind, op, args).map_err(fail)?;
        let resource = prep.resource.as_ref().map(|(k, v)| (*k, v.as_str()));
        let r = match only {
            Some(id) => managed(env, user, id, kind).await.map_err(fail)?,
            None => resolve::resolve(
                env.pool,
                &self.reg,
                kind,
                &ctx(user, cap, op, resource),
                env.now,
            )
            .await
            .map_err(|e| fail(of_store(e)))?,
        };
        let id = r.connection.id;
        let hourly = self
            .reg
            .get(kind)
            .map_or(1, |a| a.descriptor().hourly_calls);
        if let Err(busy) = self.gate.connection(id, WHO, user, hourly) {
            let why = match busy {
                Busy::Rate => "too many calls on this connection".to_owned(),
                Busy::Share | Busy::Until(_) => {
                    "the connection has used its budget for this hour".to_owned()
                }
            };
            return Err((refuse("connection_busy", &why), Some(id)));
        }
        let job = run::Job {
            github: self.github.clone(),
            jira: Arc::clone(&self.jira),
            linear: Arc::clone(&self.linear),
            slack: Arc::clone(&self.slack),
            teams: Arc::clone(&self.teams),
            redactor: self.redactor.clone(),
            pool: env.pool.clone(),
            sealer: Arc::clone(sealer),
            now: env.now.to_owned(),
            device: device.to_owned(),
            user,
            op: op.to_owned(),
            args: args.clone(),
            built: prep.built,
            resolved: r,
        };
        let mut task = tokio::spawn(run::execute(job));
        let ran = match tokio::time::timeout(self.gate.limits().timeout, &mut task).await {
            Ok(Ok(ran)) => ran,
            Ok(Err(_)) => run::Ran {
                out: Err(refuse("internal", "the call did not finish")),
                quota: None,
            },
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
        self.after(env.pool, env.now, (user, None, id), &ran).await;
        match ran.out {
            Ok(v) => Ok((v, id)),
            Err(f) => Err((f, Some(id))),
        }
    }
}

/// The connection an admin manages, as a call's resolution with no grant and no limit.
async fn managed(env: &Env<'_>, user: i64, id: i64, kind: &str) -> Result<Resolved, Fail> {
    let c = connection::get(env.pool, user, id)
        .await
        .map_err(of_store)?;
    if c.kind != kind {
        return Err(refuse("wrong_kind", "that connection is not of this kind"));
    }
    if c.disabled {
        return Err(refuse("disabled", "that connection is turned off"));
    }
    Ok(Resolved {
        connection: c,
        via: "manage",
        grant: 0,
        limits: Default::default(),
    })
}

fn ctx<'a>(
    user: i64,
    cap: &'a str,
    op: &'a str,
    resource: Option<(&'a str, &'a str)>,
) -> Context<'a> {
    Context {
        workspace: user,
        user,
        role: "admin",
        agent: None,
        session: None,
        capability: cap,
        operation: Some(op),
        resource,
        allowlist: None,
    }
}
