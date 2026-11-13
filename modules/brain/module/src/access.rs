//! Who may see a room through Code Mode (plan D3, E4.1 and E4.2). A room is visible to an AI
//! session only when (a) the session's project matches the room, or an access row names the
//! session, its runner or its project, AND (b) the session's WHOLE fallback chain is inside the
//! room's model policy, checked now (not only while the session is `starting`). A room that is
//! not visible does not exist for the session: the same 404 as an unknown id.
//!
//! A project matches when the room's name is one of the session's project keys (its repo's
//! folder name, its workspace name, the Citadel key of its branch), when an enabled
//! `route_to_room` rule for this room hits the session's repo (the import rules' own words:
//! `project` is a path component, `path` a substring), or when an access row of kind `project`
//! names one of those keys.

use std::collections::{BTreeSet, HashSet};

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::store::{agents, alloc, begin_write};
use axum::extract::{Path, State};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use utoipa::ToSchema;

use crate::claim::check_chain;
use crate::{Brain, policy, record};

/// A room a session may see. The name is the person's own, never outside text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Visible {
    pub id: String,
    pub name: String,
    pub kind: String,
}

/// What the session is, read from the Core's own rows.
struct Who {
    session: String,
    runner: String,
    /// Project keys, lowercase.
    keys: BTreeSet<String>,
    /// Repo URLs or paths, lowercase, for `path` rules.
    repos: Vec<String>,
    chain: Vec<alloc::Entry>,
}

/// The last folder of a repo URL or path, without `.git`.
fn base_of(repo: &str) -> Option<String> {
    let last = repo
        .trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\', ':'])
        .next()?;
    let last = last.strip_suffix(".git").unwrap_or(last);
    (!last.is_empty()).then(|| last.to_lowercase())
}

/// The Citadel key of a branch `citadel/<KEY>-<number>`.
fn branch_key(branch: &str) -> Option<String> {
    let rest = branch.strip_prefix("citadel/")?;
    let (key, n) = rest.rsplit_once('-')?;
    (!key.is_empty() && n.bytes().all(|b| b.is_ascii_digit())).then(|| key.to_lowercase())
}

/// Project keys and repos of a session's workspace (and the repos it also touches).
fn project_of(workspace: &Value, keys: &mut BTreeSet<String>, repos: &mut Vec<String>) {
    if let Some(repo) = workspace["repo"].as_str() {
        repos.push(repo.to_lowercase());
        keys.extend(base_of(repo));
    }
    if let Some(n) = workspace["name"].as_str().filter(|n| !n.is_empty()) {
        keys.insert(n.to_lowercase());
    }
    keys.extend(workspace["branch"].as_str().and_then(branch_key));
    for w in workspace["also"].as_array().into_iter().flatten() {
        project_of(w, keys, repos);
    }
}

async fn who(app: &App, session: &str) -> Result<Option<Who>, sqlx::Error> {
    let Some(s) = agents::get(&app.pool, session).await? else {
        return Ok(None);
    };
    if !s.live() {
        return Ok(None);
    }
    let (mut keys, mut repos) = (BTreeSet::new(), vec![]);
    if let Some(w) = &s.workspace {
        project_of(w, &mut keys, &mut repos);
    }
    let chain = alloc::view(&app.pool, session)
        .await?
        .and_then(|v| v.chain)
        .unwrap_or_default();
    Ok(Some(Who {
        session: s.id,
        runner: s.runner,
        keys,
        repos,
        chain,
    }))
}

/// Whether an enabled `route_to_room` rule `(kind, pattern)` hits the session's repos.
fn rule_hits(kind: &str, pattern: &str, w: &Who) -> bool {
    let p = pattern.to_lowercase();
    match kind {
        "project" => {
            w.keys.contains(&p)
                || w.repos
                    .iter()
                    .any(|r| r.split(['/', '\\', ':']).any(|c| c == p))
        }
        "path" => w.repos.iter().any(|r| r.contains(&p)),
        _ => false,
    }
}

/// The rooms `session` may see, by name. A session that is gone, or ended, sees none.
pub(crate) async fn visible_rooms(app: &App, session: &str) -> Result<Vec<Visible>, ApiError> {
    let Some(w) = who(app, session).await? else {
        return Ok(vec![]);
    };
    let rooms = sqlx::query(
        "SELECT id, name, kind FROM brain_rooms WHERE state = 'active' ORDER BY lower(name), id",
    )
    .fetch_all(&app.pool)
    .await?;
    let rules: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT kind, pattern, room FROM brain_rules \
         WHERE action = 'route_to_room' AND enabled = 1 AND room IS NOT NULL",
    )
    .fetch_all(&app.pool)
    .await?;
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT room, kind, value FROM brain_room_access")
            .fetch_all(&app.pool)
            .await?;
    let named: HashSet<(&str, &str, &str)> = rows
        .iter()
        .map(|(r, k, v)| (r.as_str(), k.as_str(), v.as_str()))
        .collect();
    let mut out = vec![];
    for r in rooms {
        let (id, name): (String, String) = (r.try_get("id")?, r.try_get("name")?);
        let by_project = w.keys.contains(&name.to_lowercase())
            || rules
                .iter()
                .any(|(k, p, room)| room == &id && rule_hits(k, p, &w))
            || rows.iter().any(|(room, k, v)| {
                room == &id && k == "project" && w.keys.contains(&v.to_lowercase())
            });
        let by_row = named.contains(&(id.as_str(), "session", w.session.as_str()))
            || named.contains(&(id.as_str(), "runner", w.runner.as_str()));
        if !(by_project || by_row) {
            continue;
        }
        let Ok(p) = policy::load(app, &id).await else {
            continue;
        };
        if check_chain(&w.chain, &p).is_ok() {
            out.push(Visible {
                id,
                name,
                kind: r.try_get("kind")?,
            });
        }
    }
    Ok(out)
}

/// The room `room` when `session` may see it, else `None`: never a reason.
pub(crate) async fn visible_room(
    app: &App,
    session: &str,
    room: &str,
) -> Result<Option<Visible>, ApiError> {
    Ok(visible_rooms(app, session)
        .await?
        .into_iter()
        .find(|v| v.id == room))
}

#[derive(Serialize, Deserialize, ToSchema, Default)]
pub struct RoomAccess {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub room: Option<String>,
    /// Project keys (a repo folder, a workspace name or a Citadel key) that may see the room.
    #[serde(default)]
    pub project: Vec<String>,
    /// Runner ids whose AI sessions may see the room.
    #[serde(default)]
    pub runner: Vec<String>,
    /// AI session ids that may see the room.
    #[serde(default)]
    pub session: Vec<String>,
}

async fn load(app: &App, room: &str) -> Result<RoomAccess, ApiError> {
    let known: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_rooms WHERE id = ?")
        .bind(room)
        .fetch_one(&app.pool)
        .await?;
    if known == 0 {
        return Err(ApiError::not_found("no such room"));
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT kind, value FROM brain_room_access WHERE room = ? ORDER BY kind, value",
    )
    .bind(room)
    .fetch_all(&app.pool)
    .await?;
    let mut a = RoomAccess {
        room: Some(room.to_owned()),
        ..RoomAccess::default()
    };
    for (k, v) in rows {
        match k.as_str() {
            "project" => a.project.push(v),
            "runner" => a.runner.push(v),
            _ => a.session.push(v),
        }
    }
    Ok(a)
}

#[utoipa::path(get, path = "/rooms/{room}/access", operation_id = "brainRoomAccess", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    responses((status = 200, description = "Who besides the matching project may see the room through Code Mode (empty: project match only)", body = RoomAccess)))]
pub(crate) async fn get(State(app): State<App>, Path(room): Path<String>) -> ApiResult<RoomAccess> {
    Ok(Json(load(&app, &room).await?))
}

fn clean(list: &[String], what: &str) -> Result<Vec<String>, ApiError> {
    let mut out: Vec<String> = list.iter().map(|v| v.trim().to_owned()).collect();
    if out.len() > 50
        || out
            .iter()
            .any(|v| v.is_empty() || v.chars().count() > 200 || v.chars().any(char::is_control))
    {
        return Err(ApiError::bad_request(format!(
            "{what}: at most 50 names of 1 to 200 characters"
        )));
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[utoipa::path(put, path = "/rooms/{room}/access", operation_id = "brainPutRoomAccess", tag = "brain",
    params(("room" = String, Path, description = "Room id")),
    request_body = RoomAccess,
    responses((status = 200, description = "The access list after the change; a list left out stays as it was (step-up; audited as `brain.room.access`)", body = RoomAccess)))]
pub(crate) async fn put(
    State(app): State<App>,
    Extension(_b): Extension<Brain>,
    Path(room): Path<String>,
    Json(req): Json<Value>,
) -> ApiResult<RoomAccess> {
    let mut now = load(&app, &room).await?;
    let known = ["room", "project", "runner", "session"];
    if req
        .as_object()
        .is_none_or(|m| m.keys().any(|k| !known.contains(&k.as_str())))
    {
        return Err(ApiError::bad_request(
            "an object with project, runner and session lists",
        ));
    }
    for (kind, slot) in [
        ("project", &mut now.project),
        ("runner", &mut now.runner),
        ("session", &mut now.session),
    ] {
        if req.get(kind).is_some() {
            let list: Vec<String> = serde_json::from_value(req[kind].clone())
                .map_err(|_| ApiError::bad_request(format!("{kind} is a list of names")))?;
            *slot = clean(&list, kind)?;
        }
    }
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query("DELETE FROM brain_room_access WHERE room = ?")
        .bind(&room)
        .execute(&mut *tx)
        .await?;
    for (kind, list) in [
        ("project", &now.project),
        ("runner", &now.runner),
        ("session", &now.session),
    ] {
        for v in list {
            sqlx::query("INSERT INTO brain_room_access (room, kind, value) VALUES (?, ?, ?)")
                .bind(&room)
                .bind(kind)
                .bind(v)
                .execute(&mut *tx)
                .await?;
        }
    }
    // Counts only: the names are the person's, but an audit row holds ids and counts (Q-15).
    record(
        &mut tx,
        "brain.room.access",
        json!({"room": room, "project": now.project.len(), "runner": now.runner.len(), "session": now.session.len()}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(now))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_keys_come_from_the_repo_name_and_branch() {
        let mut keys = BTreeSet::new();
        let mut repos = vec![];
        project_of(
            &json!({"repo": "git@github.com:Acme/Alpha.git", "name": "Web", "branch": "citadel/ALP-12",
                    "also": [{"repo": "/home/x/Beta/"}]}),
            &mut keys,
            &mut repos,
        );
        assert_eq!(
            keys.into_iter().collect::<Vec<_>>(),
            ["alp", "alpha", "beta", "web"]
        );
        assert_eq!(repos.len(), 2);
        assert_eq!(branch_key("citadel/ALP-x"), None);
        assert_eq!(branch_key("feature/ALP-1"), None);
    }
}
