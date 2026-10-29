//! The hub tools (E15.11, pain #9): `ask_human`, for any agent, asks the admin from the run's
//! issue (a card in its requirement's thread, the issue waits on the admin, the answer comes
//! back to this agent); `post_to_requirement`, for the requirement's owner, planners or CEO.

use ainkrad_core::auth::RunScope;
use rmcp::model::JsonObject;
use serde_json::{Value, json};

use super::args::{MAX_TEXT, MAX_TITLE, Result, ToolError, int, required};
use super::requirements::requirement;
use super::tools::target;
use crate::api::App;
use crate::store::work::{
    HubError, MAX_OPTIONS, agent_post_to_requirement, ask_human as ask, get_requirement,
};

fn refused(e: HubError) -> ToolError {
    match e {
        HubError::Db(sqlx::Error::InvalidArgument(why)) => ToolError::Invalid(why),
        HubError::Db(e) => e.into(),
        e => ToolError::Refused(e.to_string()),
    }
}

pub(super) async fn ask_human(app: &App, scope: RunScope, args: &JsonObject) -> Result<Value> {
    let issue = target(app, scope, None).await?;
    let question = required(args, "question", MAX_TEXT)?;
    let options = match args.get("options") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(a)) if a.len() <= MAX_OPTIONS => a
            .iter()
            .map(|o| match o.as_str() {
                Some(s) if s.len() <= MAX_TITLE => Ok(s.to_owned()),
                _ => Err(ToolError::Invalid(format!(
                    "each option is a string of at most {MAX_TITLE} bytes"
                ))),
            })
            .collect::<Result<_>>()?,
        Some(_) => {
            return Err(ToolError::Invalid(format!(
                "options is a list of at most {MAX_OPTIONS} strings"
            )));
        }
    };
    let q = ask(
        &app.pool,
        scope.agent_id,
        Some(scope.run_id),
        issue.id,
        question,
        &options,
    )
    .await
    .map_err(refused)?;
    let key = match q.requirement_id {
        Some(r) => get_requirement(&app.pool, r).await?.map(|r| r.key()),
        None => None,
    };
    Ok(
        json!({"question_id": q.id.0, "requirement": key, "status": "waiting_on_human",
              "next": "End your turn now. You are woken on this issue with the answer."}),
    )
}

pub(super) async fn post_to_requirement(
    app: &App,
    scope: RunScope,
    args: &JsonObject,
) -> Result<Value> {
    let r = requirement(app, scope, int(args, "requirement_id")?).await?;
    let body = required(args, "body", MAX_TEXT)?;
    let c = agent_post_to_requirement(&app.pool, r.id, scope.agent_id, Some(scope.run_id), body)
        .await
        .map_err(refused)?;
    Ok(json!({"comment_id": c.0, "requirement": r.key()}))
}
