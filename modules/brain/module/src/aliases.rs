//! "Same project as": the person says a room is another project's (`dvxmotive` is `AutomotiveAi`).
//! The answer merges the two in the run's proposal now and is kept (`<brain dir>/aliases.db`,
//! encrypted with the brain key like every other Brain file), so every later discovery and re-sort
//! files the one as the other and the employer guard counts them as one employer. Each run keeps a
//! copy in its staging file, which the guard reads.
//! ponytail: one brain key is one owner, so the list is the brain's; a per-user list waits for a
//! Brain shared by several people.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::store::begin_write;
use axum::extract::{Path, State};
use axum::{Extension, Json};
use brain_model::group::{Aliases, norm};
use serde::Serialize;
use serde_json::json;
use sqlx::{SqliteConnection, SqlitePool};
use utoipa::ToSchema;

use crate::files::{self, ALIASES};
use crate::review::{MergeInto, ProposalCard};
use crate::{Brain, code, record};

async fn pool(app: &App, b: &Brain) -> Result<SqlitePool, ApiError> {
    let key = b.key(app).await?;
    files::open_migrated(&files::aliases_path(&files::root(app)), &key, true, ALIASES)
        .await
        .map_err(|e| code(500, "aliases_unavailable", e.to_string()))
}

/// The kept aliases.
pub(crate) async fn load(app: &App, b: &Brain) -> Result<Aliases, ApiError> {
    // None kept yet: no file is made for nothing.
    if !files::aliases_path(&files::root(app)).exists() {
        return Ok(Aliases::new());
    }
    let p = pool(app, b).await?;
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT from_key, to_name FROM room_aliases")
        .fetch_all(&p)
        .await?;
    p.close().await;
    Ok(rows.into_iter().collect())
}

/// The copy a run keeps.
pub(crate) async fn of_run(st: &SqlitePool) -> Result<Aliases, ApiError> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT from_key, to_name FROM aliases")
        .fetch_all(st)
        .await?;
    Ok(rows.into_iter().collect())
}

/// Replaces the run's copy with `a`.
pub(crate) async fn into_run(tx: &mut SqliteConnection, a: &Aliases) -> Result<(), ApiError> {
    sqlx::query("DELETE FROM aliases").execute(&mut *tx).await?;
    for (f, t) in a {
        sqlx::query("INSERT INTO aliases (from_key, to_name) VALUES (?, ?)")
            .bind(f)
            .bind(t)
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}

/// `from` is `to` from now on. The list stays one hop deep: what pointed at `from` points at `to`,
/// and an alias of `to` itself (the other way round) is dropped.
fn set(a: &mut Aliases, from: &str, to: &str) {
    let f = norm(from);
    let to = match a.get(&norm(to)) {
        Some(x) if norm(x) != f => x.clone(),
        _ => to.to_owned(),
    };
    a.remove(&norm(&to));
    for v in a.values_mut() {
        if norm(v) == f {
            *v = to.clone();
        }
    }
    a.insert(f, to);
}

async fn save(app: &App, b: &Brain, a: &Aliases) -> Result<(), ApiError> {
    let p = pool(app, b).await?;
    let mut tx = p.begin().await?;
    sqlx::query("DELETE FROM room_aliases")
        .execute(&mut *tx)
        .await?;
    for (f, t) in a {
        sqlx::query("INSERT INTO room_aliases (from_key, to_name, created_at) VALUES (?, ?, ?)")
            .bind(f)
            .bind(t)
            .bind(app.clock.now())
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    p.close().await;
    Ok(())
}

#[utoipa::path(post, path = "/imports/{run}/proposals/{p}/same-project", operation_id = "brainSameProject", tag = "brain",
    params(("run" = String, Path, description = "Run id"), ("p" = String, Path, description = "Proposal id: the room that is another project's")),
    request_body = MergeInto,
    responses((status = 200, description = "\"Same project as\": proposal `p` is merged into `into` now, and the alias (p's name is into's name) is kept, encrypted, so every later import and re-sort files the one as the other and counts their employers as one. Audited as `brain.alias.set`", body = ProposalCard)))]
pub(crate) async fn same_project(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path((run, p)): Path<(String, String)>,
    Json(req): Json<MergeInto>,
) -> ApiResult<ProposalCard> {
    let (state, _) = crate::imports::run_state(&app, &run).await?;
    if state != "review" {
        return Err(ApiError::conflict("the run is not in review"));
    }
    let st = crate::imports::staging(&app, &b, &run, false).await?;
    let name = |id: &str| {
        sqlx::query_scalar::<_, String>("SELECT name FROM proposals WHERE id = ?")
            .bind(id.to_owned())
            .fetch_optional(&st)
    };
    let (Some(from), Some(to)) = (name(&p).await?, name(&req.into).await?) else {
        return Err(ApiError::not_found("no such proposal"));
    };
    if p == brain_model::group::UNSORTED || norm(&from).is_empty() || norm(&to).is_empty() {
        return Err(ApiError::bad_request("Unsorted is no project"));
    }
    // The alias first: the merged room's two employers are then one, for the guard and the card.
    let mut a = load(&app, &b).await?;
    if norm(&from) != norm(&to) {
        set(&mut a, &from, &to);
    }
    let mut tx = st.begin().await?;
    into_run(&mut tx, &a).await?;
    tx.commit().await?;
    let out = crate::review::merge_in(&st, &p, &req.into).await?;
    st.close().await;
    save(&app, &b, &a).await?;
    let mut tx = begin_write(&app.pool).await?;
    record(
        &mut tx,
        "brain.alias.set",
        json!({"run": run, "proposal": p, "into": req.into, "aliases": a.len()}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(out))
}

/// One "same project as" answer: rooms named `from` (normalized: lowercase letters and digits)
/// are filed as `to`.
#[derive(Serialize, ToSchema)]
pub struct RoomAlias {
    pub from: String,
    pub to: String,
}

fn view(a: &Aliases) -> Vec<RoomAlias> {
    a.iter()
        .map(|(f, t)| RoomAlias {
            from: f.clone(),
            to: t.clone(),
        })
        .collect()
}

#[utoipa::path(get, path = "/aliases", operation_id = "brainAliases", tag = "brain",
    responses((status = 200, description = "The kept \"same project as\" answers", body = Vec<RoomAlias>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
) -> ApiResult<Vec<RoomAlias>> {
    Ok(Json(view(&load(&app, &b).await?)))
}

#[utoipa::path(delete, path = "/aliases/{from}", operation_id = "brainRemoveAlias", tag = "brain",
    params(("from" = String, Path, description = "The alias's `from`")),
    responses((status = 200, description = "The alias is gone (the next re-sort keeps the two apart again); the list as it is now. Audited as `brain.alias.removed`", body = Vec<RoomAlias>)))]
pub(crate) async fn remove(
    State(app): State<App>,
    Extension(b): Extension<Brain>,
    Path(from): Path<String>,
) -> ApiResult<Vec<RoomAlias>> {
    let mut a = load(&app, &b).await?;
    if a.remove(&from).is_none() {
        return Err(ApiError::not_found("no such alias"));
    }
    save(&app, &b, &a).await?;
    let mut tx = begin_write(&app.pool).await?;
    record(
        &mut tx,
        "brain.alias.removed",
        json!({"aliases": a.len()}),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(Json(view(&a)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_stays_one_hop_and_has_no_loops() {
        let mut a = Aliases::new();
        set(&mut a, "dvxmotive", "AutomotiveAi");
        set(&mut a, "Old Name", "dvxmotive");
        assert_eq!(a["oldname"], "AutomotiveAi", "to what dvxmotive is");
        set(&mut a, "AutomotiveAi", "Motors");
        assert_eq!(
            (a["dvxmotive"].as_str(), a["oldname"].as_str()),
            ("Motors", "Motors")
        );
        assert!(!a.contains_key("motors"));
        set(&mut a, "Motors", "AutomotiveAi");
        assert!(
            !a.contains_key("automotiveai"),
            "the other way round replaces it"
        );
        assert_eq!(a["motors"], "AutomotiveAi");
        assert_eq!(a["dvxmotive"], "AutomotiveAi");
    }
}
