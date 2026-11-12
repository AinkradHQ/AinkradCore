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
use crate::store::connections::resolve::{self, Context};

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
        let out = self.read_in(env, user, device, op, args, kind, cap).await;
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

    #[allow(clippy::too_many_arguments)]
    async fn read_in(
        &self,
        env: &Env<'_>,
        user: i64,
        device: &str,
        op: &str,
        args: &Value,
        kind: &'static str,
        cap: &'static str,
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
        let r = resolve::resolve(
            env.pool,
            &self.reg,
            kind,
            &ctx(user, cap, op, resource),
            env.now,
        )
        .await
        .map_err(|e| fail(of_store(e)))?;
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
