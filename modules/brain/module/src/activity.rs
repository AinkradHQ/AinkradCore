//! What the Brain is doing, in one call (E9-2): the data behind the top-bar Brain icon and its
//! panel. It reads only the Core's own tables (no room file is opened), so the app can poll it.
//! Ids, counts and the Core's own wording only: no room name, source or record text.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiResult;
use axum::Json;
use axum::extract::State;
use serde::Serialize;
use sqlx::Row;
use utoipa::ToSchema;

use crate::key;

#[derive(Serialize, ToSchema, Debug, PartialEq)]
pub struct Need {
    /// `unlock`, `ai_account`, `runner` or `local_model`.
    pub kind: String,
    /// How many rooms wait for it.
    pub rooms: i64,
}

#[derive(Serialize, ToSchema, Debug, PartialEq)]
pub struct BrainActivity {
    /// `locked` (no key), `needs_you`, `working` or `idle`. The icon shows this.
    pub state: String,
    /// `ok`, or `attention` when a distil or an overview failed in the last day.
    pub health: String,
    /// Active rooms.
    pub rooms: i64,
    /// Distils running now, and queued behind them.
    pub distilling: i64,
    pub queued: i64,
    /// Overviews being written or queued.
    pub overviews: i64,
    /// Distils and overview writes that failed in the last day.
    pub failed: i64,
    /// What Brain waits on from the person (only ever an AI account, a runner, a local model or the unlock).
    pub needs: Vec<Need>,
    /// When the last distil finished, if any.
    pub last_done_at: Option<String>,
}

/// The state of the icon from its parts: a need beats work, work beats idle.
pub(crate) fn state_of(locked: bool, needs: &[Need], working: i64) -> &'static str {
    if locked {
        "locked"
    } else if !needs.is_empty() {
        "needs_you"
    } else if working > 0 {
        "working"
    } else {
        "idle"
    }
}

/// The need a waiting distil's `detail` names (the Core's own words from `distil::launch`).
pub(crate) fn need_of(state: &str, detail: &str) -> Option<&'static str> {
    match state {
        "needs_local_model" => Some("local_model"),
        "waiting" if detail.contains("no runner") => Some("runner"),
        // No chain, or a chain the room refuses: both are fixed in the AI accounts.
        "waiting" => Some("ai_account"),
        _ => None,
    }
}

#[utoipa::path(get, path = "/activity", operation_id = "brainActivity", tag = "brain",
    responses((status = 200, description = "What the Brain is doing, its health and what it needs, in one call (counts only). The top-bar Brain icon polls it", body = BrainActivity)))]
pub(crate) async fn get(State(app): State<App>) -> ApiResult<BrainActivity> {
    // `Missing` is only "no import yet", not locked.
    let locked = matches!(
        key::state(&app).await,
        key::KeyState::LockedMode0 | key::KeyState::Unavailable
    );
    let rooms: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_rooms WHERE state = 'active'")
        .fetch_one(&app.pool)
        .await?;
    let open = sqlx::query(
        "SELECT state, detail, count(*) AS n FROM brain_distils \
         WHERE state IN ('queued','needs_local_model','waiting','running') GROUP BY state, detail",
    )
    .fetch_all(&app.pool)
    .await?;
    let (mut distilling, mut queued) = (0, 0);
    let mut needs: Vec<Need> = vec![];
    for r in &open {
        let (state, detail, n): (String, String, i64) =
            (r.try_get("state")?, r.try_get("detail")?, r.try_get("n")?);
        match state.as_str() {
            "running" => distilling += n,
            "queued" => queued += n,
            _ => {}
        }
        if let Some(kind) = need_of(&state, &detail) {
            match needs.iter_mut().find(|x| x.kind == kind) {
                Some(x) => x.rooms += n,
                None => needs.push(Need {
                    kind: kind.to_owned(),
                    rooms: n,
                }),
            }
        }
    }
    let overviews: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM brain_overview_queue WHERE state IN ('queued','running')",
    )
    .fetch_one(&app.pool)
    .await?;
    let failed: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM brain_distils WHERE state = 'failed' \
                 AND updated_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')) \
              + (SELECT count(*) FROM brain_overview_queue WHERE state = 'failed' \
                 AND updated_at >= strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day'))",
    )
    .fetch_one(&app.pool)
    .await?;
    let last_done_at: Option<String> =
        sqlx::query_scalar("SELECT max(updated_at) FROM brain_distils WHERE state = 'done'")
            .fetch_one(&app.pool)
            .await?;
    needs.sort_by(|a, b| a.kind.cmp(&b.kind));
    Ok(Json(BrainActivity {
        state: state_of(locked, &needs, distilling + queued + overviews).to_owned(),
        health: if failed > 0 { "attention" } else { "ok" }.to_owned(),
        rooms,
        distilling,
        queued,
        overviews,
        failed,
        needs,
        last_done_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_need_beats_work_and_work_beats_idle() {
        let need = [Need {
            kind: "ai_account".into(),
            rooms: 1,
        }];
        assert_eq!(state_of(true, &need, 3), "locked");
        assert_eq!(state_of(false, &need, 3), "needs_you");
        assert_eq!(state_of(false, &[], 3), "working");
        assert_eq!(state_of(false, &[], 0), "idle");
    }

    #[test]
    fn a_waiting_distil_names_what_it_needs() {
        assert_eq!(need_of("waiting", "the session has no fallback chain: x"), Some("ai_account"));
        assert_eq!(need_of("waiting", "no runner with a sandbox is online"), Some("runner"));
        assert_eq!(need_of("needs_local_model", ""), Some("local_model"));
        assert_eq!(need_of("running", ""), None);
    }
}
