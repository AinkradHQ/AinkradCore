//! `org_chart` (E6): the run's own company's agents, departments, teams and seats, and its
//! projects, read-only. Not ported as tools: `route_intake` and `request_hire` (they create
//! projects and agents, which stay with the signed client API and its approvals).

use serde_json::{Value, json};

use super::args::{Result, ToolError};
use crate::store::exec::RunScope;
use crate::store::org::org_chart as chart;
use ainkrad_core_server::api::App;

pub(super) async fn org_chart(app: &App, scope: RunScope) -> Result<Value> {
    let mut v = chart(&app.pool, scope.company_id)
        .await?
        .ok_or_else(|| ToolError::Refused("the run's company is gone".to_owned()))?;
    let projects: Vec<(i64, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT id, key, name, team_id FROM citadel_projects WHERE company_id = ? AND intake = 0 \
         ORDER BY id",
    )
    .bind(scope.company_id.0)
    .fetch_all(&app.pool)
    .await?;
    v["projects"] = projects
        .into_iter()
        .map(|(id, key, name, team)| json!({"id": id, "key": key, "name": name, "team_id": team}))
        .collect();
    Ok(v)
}
