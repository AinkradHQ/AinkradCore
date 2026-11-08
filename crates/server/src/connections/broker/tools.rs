//! The tool list a session sees: the dry run of `resolve` over its grants (see the module docs).

use ainkrad_proto::v2::ConnTool;

use super::{Broker, Env, secrets_on};
use crate::connections::adapter::Descriptor;
use crate::store::connections::access;

/// What a kind's arguments look like, for the model: the adapters refuse any other name.
fn arguments(kind: &str) -> &'static str {
    match kind {
        "github" => {
            "Arguments (an object): repo as owner/name, and as the operation needs number, path, \
             query (an object of plain values) or body (an object). Any other name is refused."
        }
        "jira" => {
            "Arguments (an object): the issue key, project key, text and ids this operation \
             takes. Any other name is refused."
        }
        "linear" => {
            "Arguments (an object): the issue identifier (ENG-12), team key, text and ids this \
             operation takes. Any other name is refused."
        }
        "slack" => {
            "Arguments (an object): the channel ID (C0123456789, never a name), message \
             timestamp, user ID and text this operation takes. Any other name is refused."
        }
        "teams" => {
            "Arguments (an object): the team id (a lower-case GUID), the channel id \
             (19:...@thread.tacv2, never a name; list_channels gives it), message id and text this \
             operation takes. Any other name is refused."
        }
        _ => "Arguments: an object.",
    }
}

fn tools_of(d: &Descriptor, caps: &[String], out: &mut Vec<ConnTool>) {
    for cap in d
        .capabilities
        .iter()
        .filter(|c| caps.iter().any(|n| n == c.name))
    {
        for op in cap.operations {
            out.push(ConnTool {
                name: (*op).to_owned(),
                description: format!("{}: {op}. {}", cap.title, arguments(d.kind)),
                write: cap.write,
                input_schema: super::schemas::input_schema(op),
            });
        }
    }
}

impl Broker {
    /// The tools session `session` sees now; empty when it may use none (see the module docs).
    pub async fn tools(&self, env: &Env<'_>, session: &str) -> Result<Vec<ConnTool>, sqlx::Error> {
        let Some(acc) = access::load(env.pool, session).await? else {
            return Ok(Vec::new());
        };
        if !acc.live || env.sealer.is_none() || !secrets_on(env.pool).await? {
            return Ok(Vec::new());
        }
        let allow = self.allowlist(&acc.grant);
        let mut out = Vec::new();
        for d in self.reg.descriptors() {
            let caps = access::usable_caps(env.pool, &acc, d.kind, allow.as_deref()).await?;
            tools_of(d, &caps, &mut out);
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}
