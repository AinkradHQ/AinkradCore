//! What a connection can reach, for the guided Add's "Which repositories / projects / teams /
//! channels" step and "Choose repositories…" later (`GET /connections/{id}/resources`). `admin`
//! only: it reads the service with the connection's own credential, which stays in the Core.
//!
//! Trust decisions. (1) No grant is needed or looked at: the person is choosing the grant's
//! limits, and managing a connection is the admin's job (the same as `listGithubRepos`). The call
//! is unlimited but only a LIST read: GitHub's repositories directly, the others through the
//! broker's `pick`, which runs only read operations and records each use. (2) Names and ids are
//! the service's, cut and cleaned by the adapters; nothing else of what the service said is kept.
//! (3) Another workspace's connection is 404, a turned-off one is 409.

use axum::Json;
use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};
use utoipa::IntoParams;

use super::types::{ConnectionResource, ConnectionResources};
use super::{num, workspace};
use crate::api::App;
use crate::api::v1::projects_github::{pick as github_pick, upstream as github_upstream};
use crate::api::v1::types::Timestamp;
use crate::api::v1::{ApiError, ApiResult, Caller};
use crate::connections::broker::{Env, ReadError};
use crate::store::connections as store;

/// The most things one answer carries.
const MAX: usize = 200;
/// Pages of a service's list read for one answer.
const PAGES: u32 = 4;
/// Teams whose channels are listed (each is one more call).
const TEAMS: usize = 5;

#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ResourcesQuery {
    /// Case-insensitive text in the name or id.
    pub q: Option<String>,
}

#[utoipa::path(get, path = "/api/v1/connections/{id}/resources",
    operation_id = "listConnectionResources", tag = "connections",
    params(("id" = String, Path, description = "The connection's id"), ResourcesQuery),
    responses((status = 200, description = "The repositories (GitHub), projects (Jira), teams \
        (Linear) or channels (Slack, Teams) the connection's sign-in can see, newest or by name, \
        at most 200, filtered by `q`. Each `id` is what a grant's limit takes. 404 for another \
        workspace's connection, 409 when it is turned off or connections are off, 429 when the \
        service or the connection's budget says slow down, 502 when the service could not be \
        reached", body = ConnectionResources)))]
pub async fn list(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Path(id): Path<String>,
    Query(q): Query<ResourcesQuery>,
) -> ApiResult<ConnectionResources> {
    let user = workspace(&app, &me).await?;
    let id = num(&id)?;
    let c = store::get(&app.pool, user, id).await?;
    let key = limit_key(&c.kind);
    let (mut all, truncated) = match c.kind.as_str() {
        "github" => github(&app, &me, user, id).await?,
        kind => {
            let now = app.clock.now();
            let ask = Asker {
                app: &app,
                env: Env {
                    pool: &app.pool,
                    sealer: app.secrets.as_ref(),
                    now: &now,
                },
                user,
                device: &me.device.id,
                id,
            };
            match kind {
                "jira" => jira(&ask).await?,
                "linear" => (
                    linear(&ask.run("linear.list_teams", json!({})).await?),
                    false,
                ),
                "slack" => slack(&ask.run("slack.list_channels", json!({})).await?),
                "teams" => teams(&ask).await?,
                _ => return Err(ApiError::bad_request("no such kind of connection")),
            }
        }
    };
    narrow(&mut all, q.q.as_deref().unwrap_or(""));
    let cut = all.len() > MAX;
    all.truncate(MAX);
    Ok(Json(ConnectionResources {
        key: key.to_owned(),
        resources: all,
        truncated: truncated || cut,
    }))
}

/// The limit key a kind's picker fills (`Descriptor::limits`, first).
fn limit_key(kind: &str) -> &'static str {
    crate::connections::adapter::builtin_descriptor(kind)
        .and_then(|d| d.limits.first())
        .map_or("resources", |l| l.key)
}

fn narrow(all: &mut Vec<ConnectionResource>, q: &str) {
    let q = q.trim().to_lowercase();
    if !q.is_empty() {
        all.retain(|r| r.name.to_lowercase().contains(&q) || r.id.to_lowercase().contains(&q));
    }
}

/// A refused or failed read as an API answer, with a fixed code.
fn refused(e: ReadError) -> ApiError {
    let (status, code) = match e.code.as_str() {
        "secrets_disabled" => (StatusCode::CONFLICT, "secrets_disabled"),
        "secrets_unavailable" => (StatusCode::SERVICE_UNAVAILABLE, "secrets_unavailable"),
        "disabled" | "wrong_kind" => (StatusCode::CONFLICT, "conflict"),
        "not_found" => (StatusCode::NOT_FOUND, "not_found"),
        "connection_busy" | "rate_limited" => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
        _ => (StatusCode::BAD_GATEWAY, "upstream_failed"),
    };
    ApiError::new(status, code, e.message)
}

async fn github(
    app: &App,
    me: &Caller,
    user: i64,
    id: i64,
) -> Result<(Vec<ConnectionResource>, bool), ApiError> {
    let now = app.clock.now();
    let (c, m, version) = github_pick(app, super::who(me, user, &now), Some(id), None).await?;
    let listed = app
        .connections
        .github()
        .all_repos(c.id, version, &m, c.auth_method == "app_install")
        .await
        .map_err(|o| github_upstream(&o))?;
    let mut repos = listed.0.clone();
    repos.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    let rows = repos
        .into_iter()
        .map(|r| ConnectionResource {
            id: format!("{}/{}", r.owner, r.name),
            name: format!("{}/{}", r.owner, r.name),
            detail: (!r.description.is_empty()).then_some(r.description),
            updated_at: (!r.updated_at.is_empty()).then(|| Timestamp::new(&r.updated_at)),
        })
        .collect();
    Ok((rows, listed.1))
}

fn text(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn rows<'a>(v: &'a Value, k: &str) -> impl Iterator<Item = &'a Value> {
    v.get(k).and_then(Value::as_array).into_iter().flatten()
}

/// One connection's reads, through the broker's `pick`.
struct Asker<'a> {
    app: &'a App,
    env: Env<'a>,
    user: i64,
    device: &'a str,
    id: i64,
}

impl Asker<'_> {
    async fn run(&self, op: &str, args: Value) -> Result<Value, ApiError> {
        let (user, device, id) = (self.user, self.device, self.id);
        let read = self
            .app
            .connections
            .pick(&self.env, user, device, id, op, &args);
        read.await.map_err(refused)
    }
}

async fn jira(ask: &Asker<'_>) -> Result<(Vec<ConnectionResource>, bool), ApiError> {
    let (mut out, mut more) = (Vec::new(), false);
    for page in 0..PAGES {
        let args = json!({"start_at": page * 50, "max_results": 50});
        let v = ask.run("jira.list_projects", args).await?;
        out.extend(jira_projects(&v));
        more = v.get("isLast").and_then(Value::as_bool) == Some(false);
        if !more {
            break;
        }
    }
    Ok((out, more))
}

pub(crate) fn jira_projects(v: &Value) -> Vec<ConnectionResource> {
    rows(v, "values")
        .filter_map(|p| {
            let key = text(p, "key")?;
            Some(ConnectionResource {
                name: text(p, "name").unwrap_or_else(|| key.clone()),
                detail: Some(key.clone()),
                id: key,
                updated_at: None,
            })
        })
        .collect()
}

pub(crate) fn linear(v: &Value) -> Vec<ConnectionResource> {
    rows(v, "teams")
        .filter_map(|t| {
            let key = text(t, "key")?;
            Some(ConnectionResource {
                name: text(t, "name").unwrap_or_else(|| key.clone()),
                detail: Some(key.clone()),
                id: key,
                updated_at: None,
            })
        })
        .collect()
}

pub(crate) fn slack(v: &Value) -> (Vec<ConnectionResource>, bool) {
    let out = rows(v, "channels")
        .filter_map(|c| {
            let id = text(c, "id")?;
            let private = c.get("is_private").and_then(Value::as_bool) == Some(true);
            let people = c.get("num_members").and_then(Value::as_u64);
            let detail = match (private, people) {
                (true, _) => "Private channel".to_owned(),
                (false, Some(1)) => "1 person".to_owned(),
                (false, Some(n)) => format!("{n} people"),
                (false, None) => "Public channel".to_owned(),
            };
            Some(ConnectionResource {
                name: format!("#{}", text(c, "name").unwrap_or_else(|| id.clone())),
                detail: Some(detail),
                id,
                updated_at: None,
            })
        })
        .collect();
    (
        out,
        v.get("truncated").and_then(Value::as_bool) == Some(true),
    )
}

async fn teams(ask: &Asker<'_>) -> Result<(Vec<ConnectionResource>, bool), ApiError> {
    let list = ask.run("teams.list_teams", json!({})).await?;
    let mut more = list.get("truncated").and_then(Value::as_bool) == Some(true);
    let mut out = Vec::new();
    for (i, t) in rows(&list, "teams").enumerate() {
        let (Some(team), Some(name)) = (text(t, "id"), text(t, "name")) else {
            continue;
        };
        if i >= TEAMS {
            more = true;
            break;
        }
        let v = ask
            .run("teams.list_channels", json!({"team": team}))
            .await?;
        more |= v.get("truncated").and_then(Value::as_bool) == Some(true);
        out.extend(team_channels(&name, &v));
    }
    Ok((out, more))
}

pub(crate) fn team_channels(team: &str, v: &Value) -> Vec<ConnectionResource> {
    rows(v, "channels")
        // A shared channel is not supported by the adapter, so it is not offered.
        .filter(|c| text(c, "membership_type").as_deref() != Some("shared"))
        .filter_map(|c| {
            Some(ConnectionResource {
                id: text(c, "key")?,
                name: text(c, "name").unwrap_or_else(|| "Channel".to_owned()),
                detail: Some(team.to_owned()),
                updated_at: None,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jira_projects_are_named_by_key_and_name() {
        let v = json!({"values": [{"key": "HAR", "name": "Harbor"}, {"name": "no key"}, {"key": "KIT"}]});
        let got = jira_projects(&v);
        assert_eq!(got.len(), 2);
        assert_eq!(
            (got[0].id.as_str(), got[0].name.as_str()),
            ("HAR", "Harbor")
        );
        assert_eq!(got[1].name, "KIT");
    }

    #[test]
    fn linear_teams_are_named_by_key() {
        let v = json!({"teams": [{"id": "u1", "key": "PRO", "name": "Product"}]});
        assert_eq!(linear(&v)[0].id, "PRO");
        assert_eq!(linear(&v)[0].name, "Product");
    }

    #[test]
    fn slack_channels_say_who_is_in_them_and_never_a_direct_message() {
        let v = json!({"channels": [
            {"id": "C1", "name": "build", "num_members": 14},
            {"id": "C2", "name": "secret", "is_private": true},
            {"id": "C3", "name": "alone", "num_members": 1},
            {"name": "no id"}], "truncated": true});
        let (got, more) = slack(&v);
        assert!(more);
        let said: Vec<_> = got
            .iter()
            .map(|r| (r.name.as_str(), r.detail.as_deref()))
            .collect();
        assert_eq!(
            said,
            [
                ("#build", Some("14 people")),
                ("#secret", Some("Private channel")),
                ("#alone", Some("1 person")),
            ]
        );
    }

    #[test]
    fn teams_channels_carry_the_limit_key_and_skip_shared_ones() {
        let v = json!({"channels": [
            {"id": "19:a@thread.tacv2", "key": "t1/a", "name": "General", "membership_type": "standard"},
            {"id": "19:b@thread.tacv2", "key": "t1/b", "name": "Shared", "membership_type": "shared"}]});
        let got = team_channels("Build team", &v);
        assert_eq!(got.len(), 1);
        assert_eq!(
            (got[0].id.as_str(), got[0].detail.as_deref()),
            ("t1/a", Some("Build team"))
        );
    }

    #[test]
    fn search_matches_the_name_or_the_id_in_any_case() {
        let mut all = linear(&json!({"teams": [
            {"key": "PRO", "name": "Product"}, {"key": "DES", "name": "Design"}]}));
        narrow(&mut all, " des ");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "DES");
    }

    #[test]
    fn a_refusal_keeps_a_fixed_code() {
        let e = refused(ReadError {
            code: "connection_busy".into(),
            message: "too many".into(),
        });
        assert_eq!(
            (e.status, e.code),
            (StatusCode::TOO_MANY_REQUESTS, "rate_limited")
        );
    }
}
