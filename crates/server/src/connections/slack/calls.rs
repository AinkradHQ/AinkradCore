//! Running a [`Plan`]: the pre-read a private `G…` channel needs, the fixed method and form, and
//! the typed answer. Every refusal by the adapter's own rules is [`CallError::Refused`] with
//! fixed text.

use serde_json::{Value, json};

use super::answer;
use super::http::{CallError, Method};
use super::ops::{self, Limit, Plan};
use super::pace::Family;
use super::{Ctx, Slack};
use crate::store::connections::Connection;

/// The most requests ONE call makes, a renewal's retry included: a `list_channels` of a limited
/// connection reads up to [`MAX_LIST_PAGES`] pages (and one retry after a renewal). The
/// descriptor's hourly budget is counted in these units.
pub const MAX_REQUESTS: u32 = 6;
/// Pages of 200 channels a limited `list_channels` reads looking for the permitted ones.
const MAX_LIST_PAGES: usize = 5;
const LIST_PAGE: &str = "200";

fn refused(why: String) -> CallError {
    CallError::Refused(why)
}

impl Slack {
    /// One request with a stored credential: a refusal of a rotating token renews it once
    /// (single-flight) and retries once. A second refusal is [`CallError::AuthFailed`]. Returns the
    /// `ok:true` body.
    async fn run(
        &self,
        cx: &Ctx<'_>,
        id: i64,
        method: Method,
        form: &[(&str, &str)],
    ) -> Result<Value, CallError> {
        let family = Family::of(method);
        if let Some(wait_secs) = family.and_then(|f| self.pace.wait(id, f)) {
            return Err(CallError::Cooling { wait_secs });
        }
        let not_slack = CallError::Internal("the credential is not a usable Slack one");
        let m = self.fresh(cx, id).await?;
        let cred = super::cred::unpack(&m).ok_or(not_slack.clone())?;
        let send = |cred: &super::cred::Cred| {
            let auth = cred
                .authorization()
                .ok_or(CallError::Internal("the stored credential is unusable"));
            let http = self.http.clone();
            async move { http.call(Some(auth?), method, form).await?.into_ok() }
        };
        let out = match send(&cred).await {
            Err(CallError::AuthFailed) if cred.is_rotating() => {
                let rejected = zeroize::Zeroizing::new(m.access().to_owned());
                let m = self.renew(cx, id, Some(rejected.as_str())).await?;
                let cred = super::cred::unpack(&m).ok_or(not_slack)?;
                send(&cred).await
            }
            other => other,
        };
        // A 429 to a method an agent drives cools that family here and says nothing to health.
        match (out, family) {
            (Err(CallError::RateLimited { retry_after }), Some(f)) => Err(CallError::Cooling {
                wait_secs: self.pace.cool(id, f, retry_after),
            }),
            (other, _) => other,
        }
    }

    /// EVERY channel id is confirmed with `conversations.info`, which fails closed: a `G…` id may
    /// be a private channel or a multi-person DM, and nothing here assumes a `C…` id cannot be a
    /// group DM either. A positive answer is remembered for a few minutes ([`super::pace`]).
    async fn confirm(&self, cx: &Ctx<'_>, id: i64, channel: &str) -> Result<(), CallError> {
        if self.pace.is_confirmed(id, channel) {
            return Ok(());
        }
        let body = self
            .run(cx, id, Method::ConversationsInfo, &[("channel", channel)])
            .await?;
        answer::channel_ok(&body, channel).map_err(refused)?;
        self.pace.confirm(id, channel);
        Ok(())
    }

    /// Runs operation `op` (`slack.read_channel`) of connection `c` for `limit` (from the grant
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
        if c.kind != "slack" {
            return Err(CallError::Internal("not a Slack connection"));
        }
        let plan = ops::plan(op, args, limit).map_err(refused)?;
        let id = c.id;
        match plan {
            Plan::ListChannels { limit: n, cursor } => self.list(cx, id, limit, n, cursor).await,
            Plan::ReadChannel {
                channel,
                limit: n,
                cursor,
                oldest,
                latest,
            } => {
                self.confirm(cx, id, &channel).await?;
                let n = n.to_string();
                let mut form = vec![("channel", channel.as_str()), ("limit", n.as_str())];
                form.extend(cursor.as_deref().map(|c| ("cursor", c)));
                form.extend(oldest.as_deref().map(|c| ("oldest", c)));
                form.extend(latest.as_deref().map(|c| ("latest", c)));
                let body = self
                    .run(cx, id, Method::ConversationsHistory, &form)
                    .await?;
                answer::messages(&body)
            }
            Plan::ReadThread {
                channel,
                ts,
                limit: n,
                cursor,
            } => {
                self.confirm(cx, id, &channel).await?;
                let n = n.to_string();
                let mut form = vec![
                    ("channel", channel.as_str()),
                    ("ts", ts.as_str()),
                    ("limit", n.as_str()),
                ];
                form.extend(cursor.as_deref().map(|c| ("cursor", c)));
                let body = self
                    .run(cx, id, Method::ConversationsReplies, &form)
                    .await?;
                answer::messages(&body)
            }
            Plan::GetUser { user } => {
                let body = self
                    .run(cx, id, Method::UsersInfo, &[("user", user.as_str())])
                    .await?;
                answer::user(&body, &user)
            }
            Plan::Post {
                channel,
                text,
                thread_ts,
            } => {
                self.confirm(cx, id, &channel).await?;
                // No `blocks`, `attachments`, `metadata`, `username`, `icon_*`, `as_user`,
                // `reply_broadcast` or `link_names`: the text is plain and nothing is unfurled.
                let mut form = vec![
                    ("channel", channel.as_str()),
                    ("text", text.as_str()),
                    ("parse", "none"),
                    ("unfurl_links", "false"),
                    ("unfurl_media", "false"),
                ];
                form.extend(thread_ts.as_deref().map(|t| ("thread_ts", t)));
                let body = self.run(cx, id, Method::ChatPostMessage, &form).await?;
                // Checked on the ANSWER: the message is posted by now, so a channel that is not
                // the one asked for is refused loudly.
                answer::posted(&body, &channel).map_err(refused)
            }
            Plan::React { channel, ts, name } => {
                self.confirm(cx, id, &channel).await?;
                let form = [
                    ("channel", channel.as_str()),
                    ("timestamp", ts.as_str()),
                    ("name", name.as_str()),
                ];
                self.run(cx, id, Method::ReactionsAdd, &form).await?;
                Ok(json!({"ok": true}))
            }
        }
    }

    /// The channels the limit permits. A limited connection reads up to [`MAX_LIST_PAGES`] pages
    /// of 200 looking for them (Slack filters after paging, so a page may hold none); when pages
    /// remain unread the answer says `truncated` and carries the `next_cursor` to go on from.
    async fn list(
        &self,
        cx: &Ctx<'_>,
        id: i64,
        limit: &Limit,
        n: u64,
        mut cursor: Option<String>,
    ) -> Result<Value, CallError> {
        let limited = limit.limited();
        let (pages, size) = if limited {
            (MAX_LIST_PAGES, LIST_PAGE.to_owned())
        } else {
            (1, n.to_string())
        };
        let mut found: Vec<Value> = Vec::new();
        let mut more: Option<String> = None;
        for read in 0..pages {
            let mut form = vec![
                ("types", "public_channel,private_channel"),
                ("exclude_archived", "true"),
                ("limit", size.as_str()),
            ];
            form.extend(cursor.as_deref().map(|c| ("cursor", c)));
            let body = match self.run(cx, id, Method::ConversationsList, &form).await {
                Ok(b) => b,
                // The first Slack-says-slow ends the paging: what was read is returned, cut, with
                // the cursor to go on from. A first page that is refused is the error.
                Err(CallError::Cooling { .. }) if read > 0 => {
                    more = cursor.clone();
                    break;
                }
                Err(e) => return Err(e),
            };
            found.extend(answer::channels(&body, limit)?);
            more = answer::next_cursor(&body);
            let all = limit.keys().is_some_and(|k| found.len() >= k.len());
            if more.is_none() || all {
                more = more.filter(|_| !all);
                break;
            }
            cursor = more.clone();
        }
        let mut out = json!({"channels": found, "truncated": more.is_some()});
        if let (Some(c), Some(o)) = (more, out.as_object_mut()) {
            o.insert("next_cursor".into(), json!(c));
        }
        Ok(out)
    }
}
