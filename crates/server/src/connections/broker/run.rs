//! One upstream call per kind, with the credential opened only here and only for the call.
//!
//! - GitHub: the sealed token is opened, an expired one refused (no health signal: an agent did
//!   not cause it), `Github::execute` runs the request `ops::build` made.
//! - Jira: `Jira::call` opens the credential itself (renewing it first, single flight, before
//!   it is used) and enforces the project limit it is handed on the request and the answer.
//!
//! - Slack: `Slack::call` the same way, with the channel limit.
//! - Linear: `Linear::call` the same way, with the team limit.
//!
//! The answer is cleaned (`scrub`) and bounded before it leaves. A [`Job`] owns everything it
//! needs, so a call can run in a task of its own that outlives the caller's wait (a write whose
//! answer is late must still finish and be audited, never be dropped half done).

use std::sync::Arc;

use ainkrad_core::audit::AuditActor;
use ainkrad_proto::redact::Redactor;
use ainkrad_proto::v2::MAX_RESULT_BYTES;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use super::fail::{Fail, of_store, refuse};
use super::scrub::clean;
use crate::connections::github::{Built, Github};
use crate::connections::jira::{self, Jira, Limit};
use crate::connections::linear::{self, Linear};
use crate::connections::material::Material;
use crate::connections::slack::{self, Slack};
use crate::ops::secretbox::SecretBox;
use crate::scheduler::unix_secs;
use crate::store::connections::grants::value_matches;
use crate::store::connections::resolve::Resolved;
use crate::store::connections::{Who, secret};

/// A token this close to its end is not used.
const EXPIRY_SKEW_SECS: i64 = 60;

/// What the service said about its own budget: remaining calls, the unix second it resets, a
/// `Retry-After` in seconds.
pub type Quota = (Option<u64>, Option<i64>, Option<u64>);

/// One call, owned.
pub struct Job {
    pub github: Github,
    pub jira: Arc<Jira>,
    pub linear: Arc<Linear>,
    pub slack: Arc<Slack>,
    pub redactor: Redactor,
    pub pool: sqlx::sqlite::SqlitePool,
    pub sealer: Arc<SecretBox>,
    pub now: String,
    pub device: String,
    pub user: i64,
    pub op: String,
    pub args: Value,
    pub built: Option<Built>,
    pub resolved: Resolved,
}

/// How a job ended, and what the service said about its budget on the way.
pub struct Ran {
    pub out: Result<Value, Fail>,
    pub quota: Option<Quota>,
}

fn scrubbed(v: Value, secrets: &[String], redactor: &Redactor) -> Value {
    let refs: Vec<&str> = secrets.iter().map(String::as_str).collect();
    clean(v, &refs, redactor)
}

fn bounded(v: Value) -> Result<Value, Fail> {
    match serde_json::to_string(&v) {
        Ok(s) if s.len() <= MAX_RESULT_BYTES => Ok(v),
        _ => Err(refuse(
            "too_large",
            "the result is too large; ask for less (a smaller page, fewer fields)",
        )),
    }
}

pub async fn execute(j: Job) -> Ran {
    match j.resolved.connection.kind.as_str() {
        "github" => github(&j).await,
        "jira" => Ran {
            out: jira(&j).await,
            quota: None,
        },
        "linear" => {
            let out = linear(&j).await;
            // What Linear said about its budget, for the local `connection_busy` refusal.
            let quota = j.linear.quota(j.resolved.connection.id);
            Ran { out, quota }
        }
        // Slack says nothing about a budget beyond a 429's Retry-After (health carries that).
        "slack" => Ran {
            out: slack(&j).await,
            quota: None,
        },
        // Never another kind's adapter by default: a kind with no arm here is refused.
        _ => Ran {
            out: Err(refuse("unknown_kind", "no such kind")),
            quota: None,
        },
    }
}

async fn github(j: &Job) -> Ran {
    let none = |out| Ran { out, quota: None };
    let Some(built) = j.built.as_ref() else {
        return none(Err(refuse("internal", "no request was built")));
    };
    let r = &j.resolved;
    // `Resolved::limits` are what the use is allowed; the repository must be inside them (the
    // adapter takes no limits: its operations all carry a repository, which `resolve` judged).
    if let Some(allowed) = r.limits.get("repos")
        && !value_matches(allowed, built.resource())
    {
        return none(Err(refuse(
            "resource_denied",
            "the repository is outside the grant",
        )));
    }
    // An installation token is minted again before it ends; a failure here leaves the old token,
    // which the expiry check below then refuses.
    let who = Who {
        workspace: j.user,
        by_device: &j.device,
        actor: AuditActor::System,
        now: &j.now,
    };
    let _ = j
        .github
        .renew_installation(&j.pool, &j.sealer, who, r.connection.id)
        .await;
    let m = match secret::open(&j.pool, &j.sealer, j.user, r.connection.id).await {
        Ok((m, _)) => m,
        Err(e) => return none(Err(of_store(e))),
    };
    let now = unix_secs(&j.now).unwrap_or(0);
    if m.expires_at
        .as_deref()
        .and_then(unix_secs)
        .is_some_and(|e| e <= now + EXPIRY_SKEW_SECS)
    {
        return none(Err(refuse(
            "credential_expired",
            "the connection's token has expired and needs to be renewed",
        )));
    }
    match j.github.execute(&m, built).await {
        Ok(done) => {
            let v = serde_json::from_slice::<Value>(&done.body).unwrap_or_else(|_| {
                Value::String(String::from_utf8_lossy(&done.body).into_owned())
            });
            Ran {
                out: bounded(scrubbed(v, &secrets_of(&m), &j.redactor)),
                quota: Some((done.rate.remaining, done.rate.reset, done.rate.retry_after)),
            }
        }
        Err(o) => {
            let f = Fail::of_github(&o);
            let quota = f.feed.as_ref().map(|f| (None, None, f.retry_after));
            Ran { out: Err(f), quota }
        }
    }
}

async fn jira(j: &Job) -> Result<Value, Fail> {
    let r = &j.resolved;
    let cx = jira::Ctx {
        pool: &j.pool,
        sealer: &j.sealer,
        who: Who {
            workspace: j.user,
            by_device: &j.device,
            actor: AuditActor::System,
            now: &j.now,
        },
    };
    let limit = Limit::from_grant(&r.limits);
    let v = j
        .jira
        .call(&cx, &r.connection, &limit, &j.op, &j.args)
        .await
        .map_err(|e| Fail::of_jira(&e))?;
    // The renewed token, if the call renewed it, is the one the answer could echo.
    let secrets = match secret::open(&j.pool, &j.sealer, j.user, r.connection.id).await {
        Ok((m, _)) => secrets_of(&m),
        Err(_) => Vec::new(),
    };
    bounded(scrubbed(v, &secrets, &j.redactor))
}

async fn linear(j: &Job) -> Result<Value, Fail> {
    let r = &j.resolved;
    let cx = linear::Ctx {
        pool: &j.pool,
        sealer: &j.sealer,
        who: Who {
            workspace: j.user,
            by_device: &j.device,
            actor: AuditActor::System,
            now: &j.now,
        },
    };
    let limit = linear::Limit::from_grant(&r.limits);
    let v = j
        .linear
        .call(&cx, &r.connection, &limit, &j.op, &j.args)
        .await
        .map_err(|e| Fail::of_linear(&e))?;
    // The renewed token, if the call renewed it, is the one the answer could echo.
    let secrets = match secret::open(&j.pool, &j.sealer, j.user, r.connection.id).await {
        Ok((m, _)) => secrets_of(&m),
        Err(_) => Vec::new(),
    };
    bounded(scrubbed(v, &secrets, &j.redactor))
}

async fn slack(j: &Job) -> Result<Value, Fail> {
    let r = &j.resolved;
    let cx = slack::Ctx {
        pool: &j.pool,
        sealer: &j.sealer,
        who: Who {
            workspace: j.user,
            by_device: &j.device,
            actor: AuditActor::System,
            now: &j.now,
        },
    };
    let limit = slack::Limit::from_grant(&r.limits);
    let v = j
        .slack
        .call(&cx, &r.connection, &limit, &j.op, &j.args)
        .await
        .map_err(|e| Fail::of_slack(&e))?;
    // The renewed token, if the call renewed it, is the one the answer could echo.
    let secrets = match secret::open(&j.pool, &j.sealer, j.user, r.connection.id).await {
        Ok((m, _)) => secrets_of(&m),
        Err(_) => Vec::new(),
    };
    bounded(scrubbed(v, &secrets, &j.redactor))
}

/// Every string of a credential an answer must not carry: its access and refresh tokens, the
/// token inside a Jira envelope, and the header forms an upstream or a proxy could echo (`Bearer
/// <token>`, `Basic <base64 of email:token>` and that base64 on its own).
fn secrets_of(m: &Material) -> Vec<String> {
    let mut v = vec![m.access().to_owned()];
    v.extend(m.refresh().map(str::to_owned));
    match jira::unpack(m) {
        Some(jira::Cred::Oauth { token, .. }) => v.push(token.to_string()),
        Some(jira::Cred::Basic { email, token, .. }) => {
            let b64 = STANDARD.encode(format!("{email}:{}", token.as_str()));
            v.extend([token.to_string(), format!("Basic {b64}"), b64]);
        }
        None => {}
    }
    let bearers: Vec<String> = v.iter().map(|t| format!("Bearer {t}")).collect();
    v.extend(bearers);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::jira::{oauth_material, token_material};

    #[test]
    fn the_header_forms_of_a_credential_are_in_the_scrub_set() {
        let m = token_material(
            "acme.atlassian.net",
            "ann@example.com",
            "apitok-5d2e8b0c7a41",
        )
        .unwrap();
        let set = secrets_of(&m);
        let b64 = STANDARD.encode("ann@example.com:apitok-5d2e8b0c7a41");
        for want in [
            "apitok-5d2e8b0c7a41",
            &b64,
            &format!("Basic {b64}"),
            "Bearer apitok-5d2e8b0c7a41",
        ] {
            assert!(set.iter().any(|s| s == want), "{want} is not in {set:?}");
        }
        let o = oauth_material(
            "1324a887-451d-4b3e-b3a5-0bfbb4c7d8f1",
            "https://acme.atlassian.net",
            "acc1-7f3a9d41e0b2",
            Some("ref1-91c4d2b7a6e1"),
            None,
        )
        .unwrap();
        assert!(
            secrets_of(&o)
                .iter()
                .any(|s| s == "Bearer ref1-91c4d2b7a6e1")
        );
    }
}
