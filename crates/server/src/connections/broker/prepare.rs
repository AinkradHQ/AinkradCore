//! What a kind's operation touches, found by the adapter before any decision (step 4 of the
//! module docs): a bad argument is `bad_args`, before anything is asked of the store.

use serde_json::Value;

use super::fail::{Fail, refuse};
use crate::connections::github::{self, Built};
use crate::connections::jira;
use crate::connections::linear;
use crate::connections::slack;

/// What a kind's operation touches, found by the adapter before any decision.
pub(super) struct Prepared {
    pub(super) built: Option<Built>,
    pub(super) resource: Option<(&'static str, String)>,
}

pub(super) fn prepare(kind: &str, op: &str, args: &Value) -> Result<Prepared, Fail> {
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
        "linear" => {
            let p = linear::resource_of(op, args).map_err(|e| refuse("bad_args", &e))?;
            Ok(Prepared {
                built: None,
                resource: p.map(|p| ("teams", p)),
            })
        }
        "slack" => {
            let c = slack::resource_of(op, args).map_err(|e| refuse("bad_args", &e))?;
            Ok(Prepared {
                built: None,
                resource: c.map(|c| ("channels", c)),
            })
        }
        _ => Err(refuse("unknown_kind", "no such kind")),
    }
}
