//! Running a [`Plan`]: the pre-reads a change needs, the fixed document, and the answer scan.
//! Every refusal by the adapter's own rules is [`CallError::Refused`] with fixed text.

use serde_json::{Value, json};

use super::answer::{check_issue, check_ref, nodes, outside, retain_teams};
use super::cred::{team_key, unpack, uuid};
use super::docs::{self, Doc};
use super::http::CallError;
use super::ops::{self, Limit, Plan};
use super::{Ctx, Linear};
use crate::store::connections::Connection;

fn refused(why: String) -> CallError {
    CallError::Refused(why)
}

/// Pages `list_teams` reads at most.
const MAX_PAGES: usize = 5;

/// Whether a connection answer says there is more after it.
fn has_next(page: &Value) -> bool {
    let more = page.get("pageInfo").and_then(|p| p.get("hasNextPage"));
    more.and_then(Value::as_bool).unwrap_or(false)
}

/// The cursor to the next page, when there is one and it can be followed.
fn next_cursor(page: &Value) -> Option<&str> {
    let cursor = page.get("pageInfo")?.get("endCursor")?.as_str();
    cursor.filter(|c| has_next(page) && !c.is_empty() && c.len() <= 200)
}

/// A field of the GraphQL `data`, or an unreadable answer.
fn field<'a>(data: &'a Value, name: &str) -> Result<&'a Value, CallError> {
    data.get(name).ok_or(CallError::Upstream(200))
}

/// `success: true` of a mutation's payload; anything else is not accepted.
fn succeeded(p: &Value) -> Result<(), CallError> {
    match p.get("success").and_then(Value::as_bool) {
        Some(true) => Ok(()),
        _ => Err(CallError::BadRequest(200)),
    }
}

impl Linear {
    /// One request with a stored credential: an OAuth refusal renews the token once (single-flight)
    /// and retries once. A second refusal is [`CallError::AuthFailed`]. Returns the GraphQL `data`.
    async fn run(&self, cx: &Ctx<'_>, id: i64, doc: Doc, vars: &Value) -> Result<Value, CallError> {
        let not_linear = CallError::Internal("the credential is not a usable Linear one");
        let m = self.fresh(cx, id).await?;
        let cred = unpack(&m).ok_or(not_linear.clone())?;
        let send = |cred: &super::cred::Cred| {
            let auth = cred
                .authorization()
                .ok_or(CallError::Internal("the stored credential is unusable"));
            let http = self.http.clone();
            let vars = vars.clone();
            async move {
                let res = http.graphql(auth?, doc.query, doc.name, &vars).await?;
                self.note_quota(id, res.quota());
                res.into_data()
            }
        };
        match send(&cred).await {
            Err(CallError::AuthFailed) if cred.is_oauth() => {
                let rejected = zeroize::Zeroizing::new(m.access().to_owned());
                let m = self.renew(cx, id, Some(rejected.as_str())).await?;
                let cred = unpack(&m).ok_or(not_linear)?;
                send(&cred).await
            }
            other => other,
        }
    }

    /// The pre-read of a change: the issue's UUID and the team it is in NOW, checked.
    async fn preread(
        &self,
        cx: &Ctx<'_>,
        conn: i64,
        ident: &str,
        limit: &Limit,
    ) -> Result<(String, String), CallError> {
        let data = self
            .run(cx, conn, docs::ISSUE_REF, &json!({"id": ident}))
            .await?;
        let issue = field(&data, "issue")?;
        if issue.is_null() {
            return Err(CallError::NotFound);
        }
        check_ref(issue, limit).map_err(refused)
    }

    /// Runs operation `op` (`linear.get_issue`) of connection `c` for `limit` (from the grant that
    /// let the call through, see [`Limit::from_grant`]). The caller (the broker) has already
    /// resolved the connection and its grant; this enforces the team limit on top, on the request
    /// and on the answer. Errors are [`CallError`]; none carries a credential.
    ///
    /// Known limit, accepted: a change is a pre-read of the issue's team and then the write, two
    /// requests, so an issue moved between them is written in its new team (Linear has no
    /// conditional write on the team); the write's own answer is checked too, so the move is at
    /// least refused loudly.
    pub async fn call(
        &self,
        cx: &Ctx<'_>,
        c: &Connection,
        limit: &Limit,
        op: &str,
        args: &Value,
    ) -> Result<Value, CallError> {
        if c.kind != "linear" {
            return Err(CallError::Internal("not a Linear connection"));
        }
        let plan = ops::plan(op, args, limit).map_err(refused)?;
        let id = c.id;
        match plan {
            Plan::GetIssue { ident, .. } => {
                let data = self.run(cx, id, docs::ISSUE, &json!({"id": ident})).await?;
                let issue = field(&data, "issue")?;
                if issue.is_null() {
                    return Err(CallError::NotFound);
                }
                check_issue(issue, limit).map_err(refused)?;
                Ok(issue.clone())
            }
            Plan::Search { vars, .. } => {
                let data = self.run(cx, id, docs::SEARCH, &vars).await?;
                let page = field(&data, "issues")?;
                let list = nodes(page, "search").map_err(refused)?;
                for i in list {
                    check_issue(i, limit).map_err(refused)?;
                }
                Ok(json!({"issues": list, "page_info": page.get("pageInfo")}))
            }
            Plan::Comment { ident, body, .. } => {
                let (uuid, _) = self.preread(cx, id, &ident, limit).await?;
                let input = json!({"issueId": uuid, "body": body});
                let data = self
                    .run(cx, id, docs::COMMENT_CREATE, &json!({"input": input}))
                    .await?;
                let p = field(&data, "commentCreate")?;
                succeeded(p)?;
                // The comment says which issue it landed on: an issue that moved between the
                // pre-read and the write is refused, and nothing of it (its identifier, its url)
                // is returned.
                let comment = p.get("comment").ok_or(CallError::Upstream(200))?;
                check_issue(comment.get("issue").unwrap_or(&Value::Null), limit)
                    .map_err(refused)?;
                let mut shown = comment.clone();
                if let Some(o) = shown.as_object_mut() {
                    o.remove("issue");
                }
                Ok(shown)
            }
            Plan::Update {
                ident,
                mut input,
                state,
                ..
            } => {
                let (uuid, team) = self.preread(cx, id, &ident, limit).await?;
                if let Some(s) = state {
                    // A state of another team is refused on a limited connection; an unlimited one
                    // has no boundary to cross and Linear itself refuses a foreign state.
                    if limit.limited() {
                        self.same_team_state(cx, id, &s, &team).await?;
                    }
                    input.insert("stateId".into(), json!(s));
                }
                let vars = json!({"id": uuid, "input": input});
                let data = self.run(cx, id, docs::ISSUE_UPDATE, &vars).await?;
                let p = field(&data, "issueUpdate")?;
                succeeded(p)?;
                self.written(p, limit)
            }
            Plan::Create { team, mut input } => {
                let team_id = self.team_id(cx, id, &team, limit).await?;
                input.insert("teamId".into(), json!(team_id));
                let data = self
                    .run(cx, id, docs::ISSUE_CREATE, &json!({"input": input}))
                    .await?;
                let p = field(&data, "issueCreate")?;
                succeeded(p)?;
                let made = self.written(p, limit)?;
                match made
                    .get("team")
                    .and_then(|t| t.get("key"))
                    .and_then(Value::as_str)
                {
                    Some(k) if k == team => Ok(made),
                    _ => Err(refused(outside())),
                }
            }
            Plan::Teams { filter } => {
                let (mut after, mut more, mut all) = (Value::Null, false, Vec::new());
                for _ in 0..MAX_PAGES {
                    let vars = json!({"filter": filter, "after": after});
                    let data = self.run(cx, id, docs::TEAMS, &vars).await?;
                    let teams = field(&data, "teams")?;
                    all.extend(nodes(teams, "team").map_err(refused)?.iter().cloned());
                    (more, after) = match next_cursor(teams) {
                        Some(c) => (true, json!(c)),
                        None => (has_next(teams), Value::Null),
                    };
                    if after.is_null() {
                        break;
                    }
                }
                retain_teams(&mut all, limit);
                Ok(json!({"count": all.len(), "teams": all, "truncated": more}))
            }
            Plan::States { team } => {
                let data = self
                    .run(cx, id, docs::STATES, &json!({"key": team}))
                    .await?;
                let page = field(&data, "workflowStates")?;
                let list = nodes(page, "state").map_err(refused)?;
                // Every state must say it is in the team asked for (and so in the limit).
                let in_team = |s: &Value| {
                    let key = s
                        .get("team")
                        .and_then(|t| t.get("key"))
                        .and_then(Value::as_str);
                    key == Some(team.as_str()) && limit.permits(&team)
                };
                if !list.iter().all(in_team) {
                    return Err(refused(outside()));
                }
                Ok(json!({"states": list, "truncated": has_next(page)}))
            }
            Plan::Projects { filter, first, .. } => {
                let vars = json!({"filter": filter, "first": first});
                let data = self.run(cx, id, docs::PROJECTS, &vars).await?;
                let page = field(&data, "teams")?;
                let mut teams = nodes(page, "project").map_err(refused)?.clone();
                retain_teams(&mut teams, limit);
                // Cut when Linear has more teams, or one of the teams SHOWN has more projects
                // (what is said of teams that were cut stays unsaid).
                let more_projects = teams
                    .iter()
                    .any(|t| t.get("projects").is_some_and(has_next));
                let projects = flatten(&teams);
                let truncated = has_next(page) || more_projects;
                Ok(json!({"count": projects.len(), "projects": projects, "truncated": truncated}))
            }
        }
    }

    /// The issue a mutation returned: checked against the limit and returned as is.
    fn written(&self, payload: &Value, limit: &Limit) -> Result<Value, CallError> {
        let issue = payload.get("issue").ok_or(CallError::Upstream(200))?;
        check_issue(issue, limit).map_err(refused)?;
        Ok(issue.clone())
    }

    /// A workflow state must belong to the issue's team.
    async fn same_team_state(
        &self,
        cx: &Ctx<'_>,
        conn: i64,
        state: &str,
        team: &str,
    ) -> Result<(), CallError> {
        let data = self
            .run(cx, conn, docs::STATE_REF, &json!({"id": state}))
            .await?;
        let s = field(&data, "workflowState")?;
        if s.is_null() {
            return Err(CallError::NotFound);
        }
        let key = s
            .get("team")
            .and_then(|t| t.get("key"))
            .and_then(Value::as_str);
        if key == Some(team) {
            Ok(())
        } else {
            Err(refused(outside()))
        }
    }

    /// The UUID of team `key`, which must exist, be that team and be permitted.
    async fn team_id(
        &self,
        cx: &Ctx<'_>,
        conn: i64,
        key: &str,
        limit: &Limit,
    ) -> Result<String, CallError> {
        let data = self
            .run(cx, conn, docs::TEAM_REF, &json!({"key": key}))
            .await?;
        let list = nodes(field(&data, "teams")?, "team").map_err(refused)?;
        let found = list.iter().find_map(|t| {
            let same = t.get("key").and_then(Value::as_str) == Some(key);
            let id = t.get("id").and_then(Value::as_str).filter(|i| uuid(i));
            id.filter(|_| same && team_key(key) && limit.permits(key))
        });
        found.map(str::to_owned).ok_or(CallError::NotFound)
    }
}

/// The projects of the teams, each tagged with its team's key, once per project id.
fn flatten(teams: &[Value]) -> Vec<Value> {
    let mut seen: Vec<&str> = Vec::new();
    let mut out = Vec::new();
    for t in teams {
        let key = t.get("key").cloned().unwrap_or(Value::Null);
        let list = t
            .get("projects")
            .and_then(|p| p.get("nodes"))
            .and_then(Value::as_array);
        for p in list.into_iter().flatten() {
            let id = p.get("id").and_then(Value::as_str);
            if id.is_some_and(|i| seen.contains(&i)) {
                continue;
            }
            seen.extend(id);
            let mut one = p.clone();
            if let Some(o) = one.as_object_mut() {
                o.insert("team".into(), key.clone());
            }
            out.push(one);
        }
    }
    out
}
