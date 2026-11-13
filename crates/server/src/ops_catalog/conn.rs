//! Connection operations in the Code Mode catalogue (E5): the operations a session's grants allow
//! (`github.get_issue`, ...) appear as `connections.<kind>.<op>`, with the broker's own tool
//! descriptors as the schema source and the broker's `handle` as the only way to run one, so
//! grants, credential leasing, health, scrubbing, the untrusted fence, size bounds and the
//! `connection.used` audit stay exactly what the old per-connection tools get.
//!
//! The list is the broker's dry run for THIS session, so a session without a grant never sees an
//! op and cannot call one (`unknown_op`). A write op carries `risky` (it reaches outside the Core)
//! and is not run here: E6's dispatcher runs those behind an approval.

use ainkrad_proto::v2::{ConnTool, ToolCall, ToolResult};
use serde_json::{Value, json};

use super::{Catalogue, Op, Param, Risk};
use crate::api::App;
use crate::connections::broker::{Broker, Env};

pub const PREFIX: &str = "connections.";
pub const GROUP: &str = "connections";

/// `t` as a catalogue op. The id is `connections.` + the tool name.
fn op_of(t: &ConnTool) -> Op {
    let schema = t.input_schema.clone().unwrap_or(Value::Null);
    let req: Vec<&str> = schema["required"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let params = schema["properties"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, v)| Param {
            name: k.clone(),
            location: "arg".to_owned(),
            required: req.contains(&k.as_str()),
            schema: v.clone(),
        })
        .collect();
    Op {
        id: format!("{PREFIX}{}", t.name),
        group: GROUP.to_owned(),
        method: "CALL".to_owned(),
        path: t.name.clone(),
        params,
        body: None,
        response: None,
        scope: GROUP.to_owned(),
        risk: if t.write { Risk::Risky } else { Risk::Read },
        summary: t
            .description
            .split(". Arguments")
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned(),
    }
}

/// Whether the switch hiding the old per-connection tools is on (`code_mode.hide_connection_tools`,
/// default off). A store error leaves them listed.
pub async fn hidden(pool: &sqlx::SqlitePool) -> bool {
    crate::store::settings::value(
        pool,
        ainkrad_core::settings::Key::CodeModeHideConnTools,
        ainkrad_core::settings::Scope::Server,
    )
    .await
    .unwrap_or(0)
        == 1
}

/// The ops session `session`'s grants allow now (none when it has no grant, secrets are off or
/// the session is over).
pub async fn ops(broker: &Broker, env: &Env<'_>, session: &str) -> Result<Vec<Op>, sqlx::Error> {
    Ok(broker
        .tools(env, session)
        .await?
        .iter()
        .map(op_of)
        .collect())
}

/// The catalogue plus this session's connection ops, for `ainkrad.search`. The scope the search
/// filters on is [`GROUP`]; add it to the session's scopes.
pub async fn merged(app: &App, session: &str) -> Catalogue {
    let base = app.catalogue();
    let mut all = base.ops.clone();
    let now = app.clock.now();
    let env = Env {
        pool: &app.pool,
        sealer: app.secrets.as_ref(),
        now: &now,
    };
    match ops(&app.connections, &env, session).await {
        Ok(more) => all.extend(more.into_iter().map(|o| (o.id.clone(), o))),
        Err(e) => tracing::error!(session, error = %e, "listing connection operations failed"),
    }
    Catalogue {
        ops: all,
        warnings: Vec::new(),
    }
}

/// How a connection op call ended before or at the broker.
pub enum Ran {
    /// Not an op of this session (no grant, no such tool).
    Unknown,
    /// An op that is not a read: left to the write dispatcher (E6).
    NotRead(Op),
    /// The broker's own answer (fenced and scrubbed when ok), with the op it was.
    Done(Op, ToolResult),
}

/// Runs connection op `op_id` (`connections.github.get_issue`) with `args` for `session`, through
/// the broker.
pub async fn run(
    broker: &Broker,
    env: &Env<'_>,
    runner: &str,
    session: &str,
    op_id: &str,
    args: &Value,
    call: &ToolCall,
) -> Result<Ran, sqlx::Error> {
    let found = ops(broker, env, session)
        .await?
        .into_iter()
        .find(|o| o.id == op_id);
    let Some(op) = found else {
        return Ok(Ran::Unknown);
    };
    if op.risk != Risk::Read {
        return Ok(Ran::NotRead(op));
    }
    let tool = ToolCall {
        tc_seq: call.tc_seq,
        id: call.id.clone(),
        tool: op.path.clone(),
        args: if args.is_null() {
            json!({})
        } else {
            args.clone()
        },
    };
    let result = broker.handle(env, runner, session, &tool).await;
    Ok(Ran::Done(op, result))
}
