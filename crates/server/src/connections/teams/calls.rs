//! Running a [`Plan`]: the fixed Graph request each operation makes, and the typed answer. Every
//! refusal by the adapter's own rules is [`CallError::Refused`] with fixed text. The path holds
//! fixed words and validated ids only; the query is `$top` and `$skiptoken`, built here.

use reqwest::Method;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::answer;
use super::cred::{Cred, unpack};
use super::http::{CallError, Req};
use super::ops::{self, Limit, Plan};
use super::{Ctx, Teams};
use crate::store::connections::Connection;

/// The most Graph requests ONE call makes, a renewal's retry included. The descriptor's hourly
/// budget is counted in these units.
pub const MAX_REQUESTS: u32 = 2;

fn refused(why: String) -> CallError {
    CallError::Refused(why)
}

fn segs(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|p| (*p).to_owned()).collect()
}

fn get(path: Vec<String>, query: Option<String>) -> Req {
    Req {
        method: Method::GET,
        path,
        query,
        body: None,
    }
}

/// `value` as a query value, percent-encoded.
fn enc(value: &str) -> Result<String, CallError> {
    let broke = CallError::Internal("the query could not be made");
    let mut u = reqwest::Url::parse("http://form.invalid/").map_err(|_| broke.clone())?;
    u.query_pairs_mut().append_pair("v", value);
    let q = u.query().and_then(|q| q.strip_prefix("v="));
    q.map(str::to_owned).ok_or(broke)
}

/// `$top=<n>` and, when the caller gave a cursor, `$skiptoken=<its token>`. Nothing else is ever
/// a query parameter: no `$filter`, `$expand`, `$select`, `$orderby` or `$search`.
fn page(top: u64, cursor: Option<&str>) -> Result<String, CallError> {
    let mut q = format!("$top={top}");
    if let Some(c) = cursor {
        let token = answer::skip_token(c)
            .ok_or_else(|| refused("cursor is what a previous page gave".into()))?;
        q.push_str("&$skiptoken=");
        q.push_str(&enc(&token)?);
    }
    Ok(q)
}

fn messages_path(team: &str, channel: &str) -> Vec<String> {
    segs(&["teams", team, "channels", channel, "messages"])
}

fn text_body(text: &str) -> Value {
    json!({"body": {"contentType": "text", "content": text}})
}

impl Teams {
    async fn send(&self, cred: &Cred, req: &Req) -> Result<Value, CallError> {
        let auth = cred
            .authorization()
            .ok_or(CallError::Internal("the stored credential is unusable"))?;
        self.http.graph(auth, req).await?.into_ok()
    }

    /// One request with a stored credential: a refusal renews the token once (single-flight) and
    /// retries once. A second refusal is [`CallError::AuthFailed`]. Returns the 2xx body.
    async fn run(&self, cx: &Ctx<'_>, id: i64, req: &Req) -> Result<Value, CallError> {
        let not_teams = CallError::Internal("the credential is not a usable Microsoft one");
        let m = self.fresh(cx, id).await?;
        let cred = unpack(&m).ok_or(not_teams.clone())?;
        match self.send(&cred, req).await {
            Err(CallError::AuthFailed) => {
                let rejected = Zeroizing::new(m.access().to_owned());
                let m = self.renew(cx, id, Some(rejected.as_str())).await?;
                let cred = unpack(&m).ok_or(not_teams)?;
                self.send(&cred, req).await
            }
            other => other,
        }
    }

    /// Runs operation `op` (`teams.list_messages`) of connection `c` for `limit` (from the grant
    /// that let the call through, see [`Limit::from_grant`]). The caller (the broker) has already
    /// resolved the connection and its grant; this enforces the channel limit on top, on the
    /// request and on the answer. Errors are [`CallError`]; none carries a credential.
    pub async fn call(
        &self,
        cx: &Ctx<'_>,
        c: &Connection,
        limit: &Limit,
        op: &str,
        args: &Value,
    ) -> Result<Value, CallError> {
        if c.kind != "teams" {
            return Err(CallError::Internal("not a Teams connection"));
        }
        let plan = ops::plan(op, args, limit).map_err(refused)?;
        match self.exec(cx, c.id, limit, &plan).await {
            // A cursor is the caller's text: a 5xx that follows one says nothing about Microsoft.
            Err(CallError::Upstream(s)) if plan.has_cursor() && (500..600).contains(&s) => {
                Err(CallError::BadRequest(s))
            }
            other => other,
        }
    }

    async fn exec(
        &self,
        cx: &Ctx<'_>,
        id: i64,
        limit: &Limit,
        plan: &Plan,
    ) -> Result<Value, CallError> {
        match plan {
            Plan::ListTeams => {
                let v = self
                    .run(cx, id, &get(segs(&["me", "joinedTeams"]), None))
                    .await?;
                answer::teams(&v, limit)
            }
            Plan::ListChannels { team } => {
                let v = self
                    .run(cx, id, &get(segs(&["teams", team, "channels"]), None))
                    .await?;
                answer::channels(&v, team, limit)
            }
            Plan::ListMessages {
                team,
                channel,
                top,
                cursor,
            } => {
                let req = get(
                    messages_path(team, channel),
                    Some(page(*top, cursor.as_deref())?),
                );
                answer::messages(&self.run(cx, id, &req).await?, team, channel)
            }
            Plan::GetMessage {
                team,
                channel,
                message,
            } => {
                let mut path = messages_path(team, channel);
                path.push(message.clone());
                let v = self.run(cx, id, &get(path, None)).await?;
                answer::one_message(&v, team, channel, message)
            }
            Plan::ListReplies {
                team,
                channel,
                message,
                top,
                cursor,
            } => {
                let mut path = messages_path(team, channel);
                path.extend([message.clone(), "replies".to_owned()]);
                let req = get(path, Some(page(*top, cursor.as_deref())?));
                answer::messages(&self.run(cx, id, &req).await?, team, channel)
            }
            Plan::Post {
                team,
                channel,
                text,
            } => {
                let req = Req {
                    method: Method::POST,
                    path: messages_path(team, channel),
                    query: None,
                    body: Some(text_body(text)),
                };
                // Checked on the ANSWER: the message is posted by now.
                answer::posted(&self.run(cx, id, &req).await?, team, channel)
            }
            Plan::Reply {
                team,
                channel,
                message,
                text,
            } => {
                let mut path = messages_path(team, channel);
                path.extend([message.clone(), "replies".to_owned()]);
                let req = Req {
                    method: Method::POST,
                    path,
                    query: None,
                    body: Some(text_body(text)),
                };
                answer::posted(&self.run(cx, id, &req).await?, team, channel)
            }
        }
    }
}
