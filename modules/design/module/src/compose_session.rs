//! The composer's AI session: starting it, reading its answer, saying in plain words why it failed (a provider's
//! quota, rate limit or refused sign-in is the session's outcome, not its text), and the reaper that fails a compose
//! whose AI stopped answering (on every read and every minute) and stops its session.

use std::sync::Arc;

use ainkrad_core_server::agents::{self, Refusal};
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, BY};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Run, Schedule};
use ainkrad_core_server::store::agents::{self as agent_store, NewSession};
use ainkrad_core_server::store::alloc;
use ainkrad_core_server::store::chains::{self as ch, Request};
use serde_json::{Value, json};

use crate::compose_answer::clip;

/// The chain the session draws its account from, by agent name (like the Brain's `brain-distil`).
const AGENT: &str = "design-compose";
/// A compose still drawing (or placing) this long after it started has stopped: it fails.
pub(crate) const STUCK_MINUTES: i64 = 6;
pub(crate) const STUCK: &str = "the AI stopped answering";
const REAP_EVERY_SECS: u64 = 60;

fn session_policy() -> Value {
    json!({"mode": "ask", "min_isolation": "process"})
}

/// The first online runner that offers agent sessions in a sandbox meeting the policy.
fn pick_runner(app: &App) -> Option<String> {
    let policy = session_policy();
    let mut all: Vec<_> = app
        .hub
        .runners()
        .into_iter()
        .filter(|(_, r)| {
            r.online
                && r.drivers
                    .iter()
                    .any(|d| d.name == ainkrad_proto::v2::AGENT_DRIVER)
                && agents::tier_refusal(r, &policy).is_none()
        })
        .map(|(id, _)| id)
        .collect();
    all.sort();
    all.into_iter().next()
}

pub(crate) async fn launch(app: &App, by: &str, prompt: &str) -> Result<String, ApiError> {
    let user = ch::user_of(&app.pool, by).await?;
    let entries = {
        let mut conn = app.pool.acquire().await?;
        match ch::resolve_for(&mut conn, user, None, Some(AGENT)).await? {
            Some(id) => ch::load(&mut conn, id).await?,
            None => vec![],
        }
    };
    if entries.is_empty() {
        return Err(ApiError::conflict(
            "connect an AI account first: no account can draw yet",
        ));
    }
    let Some(runner) = pick_runner(app) else {
        return Err(ApiError::conflict("no runner is online to run the AI"));
    };
    let policy = session_policy();
    let new = NewSession {
        runner: &runner,
        harness: "",
        model: None,
        prompt: Some(prompt),
        workspace: None,
        policy: &policy,
        secrets: &[],
        created_by: by,
    };
    let req = Request {
        user_id: user,
        chain: None,
        agent: Some(AGENT),
    };
    let s = ch::create_session(&app.pool, &new, None, None, req, BY, &app.clock.now())
        .await
        .map_err(ApiError::from)?;
    agents::authorize_module_session(app, &s.id);
    if let Err(r) = agents::start(app, &s).await {
        alloc::end_unstarted_why(&app.pool, &s.id, &app.clock.now(), "it could not start").await?;
        return Err(ApiError::conflict(match r {
            Refusal::Runner(e) => e.message,
            Refusal::Secrets(e) => e.to_string(),
            Refusal::Db(e) => e.to_string(),
        }));
    }
    Ok(s.id.clone())
}

/// What the model said: every `assistant_text` block of the session, joined.
pub(crate) async fn answer_of(app: &App, session: &str) -> Result<String, sqlx::Error> {
    let (mut after, mut out) = (0i64, Vec::<String>::new());
    loop {
        let page = agent_store::transcript(&app.pool, session, after, 500).await?;
        let Some(end) = page.last() else { break };
        after = i64::try_from(end.seq).unwrap_or(i64::MAX);
        out.extend(
            page.iter()
                .filter(|e| e.body["type"] == "assistant_text")
                .filter_map(|e| e.body["text"].as_str().map(str::to_owned)),
        );
    }
    Ok(out.join("\n"))
}

/// `thinking` until the model has written anything, then `drawing`.
pub(crate) async fn stage_of(app: &App, session: &str) -> Result<&'static str, sqlx::Error> {
    let page = agent_store::transcript(&app.pool, session, 0, 500).await?;
    Ok(if page.iter().any(|e| e.body["type"] == "assistant_text") {
        "drawing"
    } else {
        "thinking"
    })
}

/// Why a session that is over did not answer, in plain words: its account's budget stop, or its outcome's failure
/// class (a fingerprint is a class or `<harness>:<code>`). `None` for a session that ended well.
pub(crate) fn failure_reason(outcome: Option<&Value>, gw_stop: Option<&str>) -> Option<String> {
    if gw_stop.is_some() {
        return Some("the AI account reached its spending limit".into());
    }
    let o = outcome?;
    let kind = o["kind"].as_str().unwrap_or("failed");
    if kind == "succeeded" {
        return None;
    }
    let class = o["fingerprint"].as_str().unwrap_or("");
    let class = class.rsplit(':').next().unwrap_or(class);
    Some(
        match class {
            "quota" | "limit_reached" => {
                "the AI account's plan or credit is used up: top it up or pick another account"
            }
            "rate_limited" => "the AI account is being rate limited: try again in a few minutes",
            "auth" | "token_expired" => {
                "the AI account's sign-in was refused: reconnect it in Accounts"
            }
            "model_unavailable" => "the AI model is not available to this account",
            "transient" | "unhealthy" | "unreachable" => {
                "the AI provider dropped the answer: try again"
            }
            _ => match o["reason"].as_str().map(str::trim) {
                Some(r) if !r.is_empty() => {
                    return Some(format!("the AI stopped: {}", clip(r, 160)));
                }
                _ if kind == "lost" => "the AI's runner lost the session",
                _ => "the AI session failed",
            },
        }
        .to_owned(),
    )
}

/// Fails every compose drawing or placing for longer than [`STUCK_MINUTES`] and stops its session; how many.
pub async fn reap(app: &App) -> Result<usize, sqlx::Error> {
    let stuck: Vec<(String, Option<String>)> = sqlx::query_as(
        "UPDATE design_composes SET state = 'failed', reason = ?1 \
         WHERE state IN ('drawing', 'applying') \
           AND created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?2) \
         RETURNING id, session",
    )
    .bind(STUCK)
    .bind(format!("-{STUCK_MINUTES} minutes"))
    .fetch_all(&app.pool)
    .await?;
    for (_, session) in &stuck {
        let Some(s) = session else { continue };
        let newest = ainkrad_core_server::store::failover::newest(&app.pool, s).await?;
        if let Err(e) = agents::stop_module_session(app, &newest).await {
            tracing::info!(error = %agents::describe(&e), "a stuck design compose's session did not stop");
        }
    }
    Ok(stuck.len())
}

struct ReapJob;

impl JobHandler for ReapJob {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let Some(app) = crate::checks::APP.get() else {
                return Ok(());
            };
            if reap(app).await.map_err(|e| e.to_string())? == 0 {
                run.idle();
            }
            Ok(())
        })
    }
}

pub(crate) fn job() -> Job {
    Job::new(
        "design_compose_reaper",
        Schedule::Every(REAP_EVERY_SECS),
        Arc::new(ReapJob),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_session_says_why_in_plain_words() {
        let r = |o: Value| failure_reason(Some(&o), None).unwrap();
        assert!(r(json!({"kind": "failed", "fingerprint": "quota"})).contains("credit is used up"));
        assert!(
            r(json!({"kind": "failed", "fingerprint": "rate_limited"})).contains("rate limited")
        );
        assert!(r(json!({"kind": "failed", "fingerprint": "auth"})).contains("reconnect"));
        assert!(
            r(json!({"kind": "failed", "fingerprint": "claude:model_unavailable"}))
                .contains("not available")
        );
        assert_eq!(
            r(json!({"kind": "failed", "reason": "build broke", "fingerprint": "claude:weird"})),
            "the AI stopped: build broke"
        );
        assert_eq!(
            r(json!({"kind": "lost"})),
            "the AI's runner lost the session"
        );
        assert!(failure_reason(Some(&json!({"kind": "succeeded"})), None).is_none());
        assert!(failure_reason(None, None).is_none());
        assert!(
            failure_reason(None, Some("day cap"))
                .unwrap()
                .contains("spending limit")
        );
    }
}
