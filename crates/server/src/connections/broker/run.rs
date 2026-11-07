//! One upstream call per kind, with the credential opened only here and only for the call.
//!
//! - GitHub: the sealed token is opened, an expired one refused (no health signal: an agent did
//!   not cause it), `Github::execute` runs the request `ops::build` made.
//! - Jira: `Jira::call` opens the credential itself (renewing it first, single-flight, before
//!   it is used) and enforces the project limit it is handed on the request and the answer.
//!
//! The answer is cleaned (`scrub`) and bounded before it leaves.

use std::sync::Arc;

use ainkrad_core::audit::AuditActor;
use ainkrad_proto::v2::MAX_RESULT_BYTES;
use serde_json::Value;

use super::Broker;
use super::fail::{Fail, of_store, refuse};
use super::scrub::clean;
use crate::connections::github::Built;
use crate::connections::jira::{self, Limit};
use crate::connections::material::Material;
use crate::ops::secretbox::SecretBox;
use crate::scheduler::unix_secs;
use crate::store::connections::grants::value_matches;
use crate::store::connections::resolve::Resolved;
use crate::store::connections::{Who, secret};

/// A token this close to its end is not used.
const EXPIRY_SKEW_SECS: i64 = 60;

/// The pieces of one call, owned for the call's duration.
pub struct Call<'a> {
    pub pool: &'a sqlx::sqlite::SqlitePool,
    pub sealer: &'a Arc<SecretBox>,
    pub now: &'a str,
    pub device: &'a str,
    pub user: i64,
    pub op: &'a str,
    pub args: &'a Value,
    pub built: Option<&'a Built>,
}

fn scrubbed(v: Value, secrets: &[String], b: &Broker) -> Value {
    let refs: Vec<&str> = secrets.iter().map(String::as_str).collect();
    clean(v, &refs, &b.redactor)
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

pub async fn github(b: &Broker, c: &Call<'_>, r: &Resolved) -> Result<Value, Fail> {
    let built = c
        .built
        .ok_or_else(|| refuse("internal", "no request was built"))?;
    // `Resolved::limits` are what the use is allowed; the repository must be inside them (the
    // adapter takes no limits: its operations all carry a repository, which `resolve` judged).
    if let Some(allowed) = r.limits.get("repos")
        && !value_matches(allowed, built.resource())
    {
        return Err(refuse(
            "resource_denied",
            "the repository is outside the grant",
        ));
    }
    let (m, _) = secret::open(c.pool, c.sealer, c.user, r.connection.id)
        .await
        .map_err(of_store)?;
    let now = unix_secs(c.now).unwrap_or(0);
    if m.expires_at
        .as_deref()
        .and_then(unix_secs)
        .is_some_and(|e| e <= now + EXPIRY_SKEW_SECS)
    {
        return Err(refuse(
            "credential_expired",
            "the connection's token has expired and needs to be renewed",
        ));
    }
    let done = b
        .github
        .execute(&m, built)
        .await
        .map_err(|o| Fail::of_github(&o))?;
    let v = serde_json::from_slice::<Value>(&done.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&done.body).into_owned()));
    bounded(scrubbed(v, &secrets_of(&m), b))
}

pub async fn jira(b: &Broker, c: &Call<'_>, r: &Resolved) -> Result<Value, Fail> {
    let cx = jira::Ctx {
        pool: c.pool,
        sealer: c.sealer,
        who: Who {
            workspace: c.user,
            by_device: c.device,
            actor: AuditActor::System,
            now: c.now,
        },
    };
    let limit = Limit::from_grant(&r.limits);
    let v = b
        .jira
        .call(&cx, &r.connection, &limit, c.op, c.args)
        .await
        .map_err(|e| Fail::of_jira(&e))?;
    // The renewed token, if the call renewed it, is the one the answer could echo.
    let secrets = match secret::open(c.pool, c.sealer, c.user, r.connection.id).await {
        Ok((m, _)) => secrets_of(&m),
        Err(_) => Vec::new(),
    };
    bounded(scrubbed(v, &secrets, b))
}

/// Every string of a credential an answer must not carry: its access and refresh tokens, and for
/// a Jira envelope the token inside it.
fn secrets_of(m: &Material) -> Vec<String> {
    let mut v = vec![m.access().to_owned()];
    v.extend(m.refresh().map(str::to_owned));
    if let Some(jira::Cred::Oauth { token, .. } | jira::Cred::Basic { token, .. }) = jira::unpack(m)
    {
        v.push(token.to_string());
    }
    v
}
