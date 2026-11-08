//! Running a [`Plan`]: the fixed Graph request each operation makes, and the typed answer. Every
//! refusal by the adapter's own rules is [`CallError::Refused`] with fixed text. The path holds
//! fixed words and validated ids only; the query is `$top` and `$skiptoken`, built here.

use reqwest::Method;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::answer;
use super::cred::{Cred, channel_key, unpack};
use super::http::{CallError, Req};
use super::ops::{self, Limit, Plan};
use super::pace::Scope;
use super::{Ctx, Teams};
use crate::store::connections::Connection;

/// The most Graph requests ONE call makes: the channel confirmation, the operation, a renewal's
/// retry and `/me` after a refusal that survives it. The descriptor's hourly budget is counted in
/// these units (most calls make one or two: a confirmed channel is remembered).
pub const MAX_REQUESTS: u32 = 5;

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

fn chan(team: &str, channel: &str) -> Result<Scope, CallError> {
    let key = channel_key(team, channel);
    key.map(Scope::Channel)
        .ok_or_else(|| refused("channel is not a channel id".into()))
}

impl Teams {
    async fn send(&self, cred: &Cred, req: &Req) -> Result<Value, CallError> {
        let auth = cred
            .authorization()
            .ok_or(CallError::Internal("the stored credential is unusable"))?;
        self.http.graph(auth, req).await?.into_ok()
    }

    /// One request with a stored credential: a refusal renews the token once (single-flight) and
    /// retries once. A refusal that survives that is raised as [`CallError::AuthFailed`] only when
    /// `/me` is refused too: a 401 to one resource while the account itself is fine says nothing
    /// about the credential.
    async fn authed(&self, cx: &Ctx<'_>, id: i64, req: &Req) -> Result<Value, CallError> {
        let not_teams = CallError::Internal("the credential is not a usable Microsoft one");
        let m = self.fresh(cx, id).await?;
        let cred = unpack(&m).ok_or(not_teams.clone())?;
        let first = self.send(&cred, req).await;
        let (cred, out) = if matches!(first, Err(CallError::AuthFailed)) {
            let rejected = Zeroizing::new(m.access().to_owned());
            let m = match self.renew(cx, id, Some(rejected.as_str())).await {
                Ok(m) => m,
                Err(CallError::AuthFailed) => return self.still_refused(&cred).await,
                Err(e) => return Err(e),
            };
            let cred = unpack(&m).ok_or(not_teams)?;
            let again = self.send(&cred, req).await;
            (cred, again)
        } else {
            (cred, first)
        };
        if matches!(out, Err(CallError::AuthFailed)) {
            return self.still_refused(&cred).await;
        }
        out
    }

    /// A token was refused for one resource and could not be renewed (or the renewal did not
    /// help): `/me` decides. Refused there too, the credential is suspect; answered, the account is
    /// fine and the resource is not for it; unanswered, nothing is known.
    async fn still_refused(&self, cred: &Cred) -> Result<Value, CallError> {
        match self.viewer(cred).await {
            Ok(_) => Err(CallError::Forbidden),
            Err(CallError::AuthFailed) => Err(CallError::AuthFailed),
            Err(_) => Err(CallError::Broken),
        }
    }

    /// A request an agent drives, in `scope`: refused here while the scope is cooling, and what
    /// Microsoft says about the scope stays in it. A 429 cools the scope (no health, no
    /// connection-wide wait); a 5xx on a resource an agent chose is not Microsoft's outage.
    async fn run(
        &self,
        cx: &Ctx<'_>,
        id: i64,
        scope: &Scope,
        req: &Req,
    ) -> Result<Value, CallError> {
        if let Some(wait_secs) = self.pace.wait(id, scope) {
            return Err(CallError::Cooling { wait_secs });
        }
        match self.authed(cx, id, req).await {
            Err(CallError::RateLimited { retry_after }) => Err(CallError::Cooling {
                wait_secs: self.pace.cool(id, scope, retry_after),
            }),
            Err(CallError::Upstream(s)) if (500..600).contains(&s) => Err(CallError::BadRequest(s)),
            other => other,
        }
    }

    /// EVERY channel is confirmed before it is read or posted to: `GET /teams/{t}/channels/{c}`
    /// must say it is that channel, in this connection's tenant, of the plain kind. Graph does not
    /// refuse a channel id asked under another team of the same tenant (`<team>/*` would then reach
    /// any channel by its id), and a shared-in channel belongs to another team and tenant. Fails
    /// closed on any error or cooling. A positive answer is remembered a few minutes.
    async fn confirm(
        &self,
        cx: &Ctx<'_>,
        id: i64,
        team: &str,
        channel: &str,
    ) -> Result<(), CallError> {
        let scope = chan(team, channel)?;
        let Scope::Channel(key) = &scope else {
            return Err(refused("channel is not a channel id".into()));
        };
        if self.pace.is_confirmed(id, key) {
            return Ok(());
        }
        let m = self.fresh(cx, id).await?;
        let tenant = unpack(&m)
            .ok_or(CallError::Internal(
                "the credential is not a usable Microsoft one",
            ))?
            .tenant()
            .to_owned();
        let req = get(segs(&["teams", team, "channels", channel]), None);
        let body = self.run(cx, id, &scope, &req).await?;
        answer::channel_ok(&body, team, channel, &tenant).map_err(refused)?;
        self.pace.confirm(id, key);
        Ok(())
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
        self.exec(cx, c.id, limit, &plan).await
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
                let req = get(segs(&["me", "joinedTeams"]), None);
                let v = self.run(cx, id, &Scope::Teams, &req).await?;
                answer::teams(&v, limit)
            }
            Plan::ListChannels { team } => {
                let req = get(segs(&["teams", team, "channels"]), None);
                let v = self
                    .run(cx, id, &Scope::Channels(team.clone()), &req)
                    .await?;
                answer::channels(&v, team, limit)
            }
            Plan::ListMessages {
                team,
                channel,
                top,
                cursor,
            } => {
                self.confirm(cx, id, team, channel).await?;
                let req = get(
                    messages_path(team, channel),
                    Some(page(*top, cursor.as_deref())?),
                );
                let v = self.run(cx, id, &chan(team, channel)?, &req).await?;
                answer::messages(&v, team, channel)
            }
            Plan::GetMessage {
                team,
                channel,
                message,
            } => {
                self.confirm(cx, id, team, channel).await?;
                let mut path = messages_path(team, channel);
                path.push(message.clone());
                let v = self
                    .run(cx, id, &chan(team, channel)?, &get(path, None))
                    .await?;
                answer::one_message(&v, team, channel, message)
            }
            Plan::ListReplies {
                team,
                channel,
                message,
                top,
                cursor,
            } => {
                self.confirm(cx, id, team, channel).await?;
                let mut path = messages_path(team, channel);
                path.extend([message.clone(), "replies".to_owned()]);
                let req = get(path, Some(page(*top, cursor.as_deref())?));
                let v = self.run(cx, id, &chan(team, channel)?, &req).await?;
                answer::messages(&v, team, channel)
            }
            Plan::Post {
                team,
                channel,
                text,
            } => {
                self.confirm(cx, id, team, channel).await?;
                let req = Req {
                    method: Method::POST,
                    path: messages_path(team, channel),
                    query: None,
                    body: Some(text_body(text)),
                };
                self.write(cx, id, (team, channel), &req).await
            }
            Plan::Reply {
                team,
                channel,
                message,
                text,
            } => {
                self.confirm(cx, id, team, channel).await?;
                let mut path = messages_path(team, channel);
                path.extend([message.clone(), "replies".to_owned()]);
                let req = Req {
                    method: Method::POST,
                    path,
                    query: None,
                    body: Some(text_body(text)),
                };
                self.write(cx, id, (team, channel), &req).await
            }
        }
    }

    /// A POST. Once Microsoft answered 2xx the message is LIVE: whatever its answer then looks
    /// like (a channel that is not the one asked for, an id that is odd, a body that is not JSON)
    /// is reported as a success with `unverified: true`, never as a failure, so the agent does
    /// not post it twice. Only a refusal BEFORE the message exists is an error.
    async fn write(
        &self,
        cx: &Ctx<'_>,
        id: i64,
        (team, channel): (&str, &str),
        req: &Req,
    ) -> Result<Value, CallError> {
        match self.run(cx, id, &chan(team, channel)?, req).await {
            Ok(body) => Ok(answer::posted(&body, team, channel)),
            Err(CallError::Upstream(s)) if (200..300).contains(&s) => Ok(answer::unverified()),
            Err(e) => Err(e),
        }
    }
}
