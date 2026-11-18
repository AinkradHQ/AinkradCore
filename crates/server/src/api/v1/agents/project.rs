//! Sessions of a project (Projects P3-02): the workspace the Core builds from the project's repos,
//! and what happens to a session once it has one. The repo copies are leased at launch
//! (`agents::launch`, `crate::mirrors::for_session`), never here: this only names them.

use ainkrad_proto::runner::Workspace;
use axum::http::StatusCode;
use serde_json::Value;

use super::super::{ApiError, Caller};
use crate::api::App;
use crate::store::agents::{self as store, Session};
use crate::store::projects;

/// What only the Core may write into a workspace: a mirror (a repo copy the runner clones from).
/// A client's own `workspace` may name none, or it could ask the Core to lease what it likes.
pub(in crate::api::v1) fn no_mirror(workspace: Option<&Value>) -> Result<(), ApiError> {
    let named = workspace
        .and_then(|w| serde_json::from_value::<Workspace>(w.clone()).ok())
        .is_some_and(|w| w.mirror.is_some() || w.also.iter().any(|a| a.mirror.is_some()));
    match named {
        false => Ok(()),
        true => Err(ApiError::bad_request(
            "a workspace names no mirror: it is set for a session of a project (project_id)",
        )),
    }
}

/// The workspace of a new session of `project`: its primary repo first, the rest in `also`, each
/// cloned from the Core's copy (`mirror`) and checked out on one new session branch. A single
/// repo is the session folder itself; several are `<folder>/<repo name>`.
pub(in crate::api::v1) async fn workspace_for(app: &App, project: i64) -> Result<Value, ApiError> {
    let mut conn = app.pool.acquire().await?;
    let p = projects::get(&mut conn, project).await?;
    let repos = projects::repos(&mut conn, project).await?;
    drop(conn);
    if p.state != "active" {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "project_archived",
            "the project is archived",
        ));
    }
    let branch = format!(
        "ainkrad/{}",
        crate::auth::crypto::random_id("").to_lowercase()[..10].to_owned()
    );
    let mut all = repos.into_iter().map(|r| Workspace {
        repo: r.remote_url,
        base: r.default_branch,
        branch: branch.clone(),
        push: false,
        name: r.name,
        also: Vec::new(),
        expected_head: None,
        mirror: Some(r.id),
    });
    let Some(mut first) = all.next() else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "project_has_no_repos",
            "the project has no repos to work in",
        ));
    };
    first.also = all.collect();
    Ok(serde_json::to_value(first).expect("a workspace serializes"))
}

/// Ties the new, not yet started session `s` to `project`, then lets the modules act for it (the
/// Brain claims the project's room). A refusal ends the session, which never started, and says why.
pub(super) async fn attach(
    app: &App,
    me: &Caller,
    s: &Session,
    project: i64,
) -> Result<(), ApiError> {
    // A session that is not `starting` any more (or already has a project) cannot take one: it is
    // ended unstarted, never left without the project its workspace was built for.
    if !store::set_project(&app.pool, &s.id, project).await? {
        let now = app.clock.now();
        let why = "the session could not be tied to its project";
        store::set_state(&app.pool, &s.id, "ended", why, false, &now).await?;
        return Err(ApiError::new(StatusCode::CONFLICT, "session_started", why));
    }
    for module in app.modules.iter() {
        if let Err(why) = module
            .project_session(app, &s.id, project, &me.device.id)
            .await
        {
            let now = app.clock.now();
            store::set_state(&app.pool, &s.id, "ended", &why, false, &now).await?;
            return Err(why_to_error(&why));
        }
    }
    Ok(())
}

fn why_to_error(why: &str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, "claim_refused", why.to_owned())
}
