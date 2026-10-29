//! Working in one company (E15.14, pain #12: two companies' data must never mix). A client
//! names the company it works in with `X-Citadel-Company: <id>`, and switches by sending
//! another. With it, every route refuses what belongs to another company:
//!
//! - a path naming another company's company, project, issue, epic, sprint, agent, run, approval,
//!   department, team, repo, requirement, artifact, budget or knowledge entry, or another company's (or its
//!   project's) settings scope, is a 404, as if it were not there (`owner`);
//! - lists that span companies (`/stuck`, `/events`, `/audit`, `/accounts`, `/requirements`,
//!   `/artifacts`) keep only its own (`Acting`).
//!
//! What belongs to no company (runners, devices, the account pool's own settings, the server's
//! settings, the company list itself) is the admin's and stays reachable. Without the header the
//! admin sees every company, as before.

use ainkrad_core::org::CompanyId;
use ainkrad_core::settings::Scope;
use axum::extract::{MatchedPath, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::ApiError;
use crate::api::App;

pub const COMPANY_HEADER: &str = "x-citadel-company";

/// The company a request works in, when it names one.
#[derive(Debug, Clone, Copy, Default)]
pub struct Acting(pub Option<CompanyId>);

impl Acting {
    /// Whether something of `company` (`None`: of no company) may be shown.
    pub fn sees(self, company: Option<i64>) -> bool {
        match self.0 {
            Some(c) => company == Some(c.0),
            None => true,
        }
    }
}

/// The company that owns what `segment/{value}` names; `None` for what no company owns (or
/// what does not exist: the route says so itself).
async fn owner(app: &App, segment: &str, value: &str) -> Result<Option<i64>, sqlx::Error> {
    if segment == "settings" {
        return match value.parse::<Scope>() {
            Ok(Scope::Company(c)) => Ok(Some(c.0)),
            Ok(Scope::Project(p)) => {
                company_of(app, "SELECT company_id FROM projects WHERE id = ?", p.0).await
            }
            _ => Ok(None),
        };
    }
    let Ok(id) = value.parse::<i64>() else {
        return Ok(None);
    };
    let sql = match segment {
        "companies" => return Ok(Some(id)),
        "projects" => "SELECT company_id FROM projects WHERE id = ?",
        "issues" | "blockers" => {
            "SELECT p.company_id FROM issues i JOIN projects p ON p.id = i.project_id \
             WHERE i.id = ?"
        }
        "epics" => {
            "SELECT p.company_id FROM epics e JOIN projects p ON p.id = e.project_id \
             WHERE e.id = ?"
        }
        "sprints" => {
            "SELECT p.company_id FROM sprints s JOIN projects p ON p.id = s.project_id \
             WHERE s.id = ?"
        }
        "repos" => {
            "SELECT p.company_id FROM project_repos r JOIN projects p ON p.id = r.project_id \
             WHERE r.id = ?"
        }
        "agents" => "SELECT company_id FROM agents WHERE id = ?",
        "departments" => "SELECT company_id FROM departments WHERE id = ?",
        "teams" => {
            "SELECT d.company_id FROM teams t JOIN departments d ON d.id = t.department_id \
             WHERE t.id = ?"
        }
        "runs" => {
            "SELECT a.company_id FROM runs r JOIN agents a ON a.id = r.agent_id WHERE r.id = ?"
        }
        "approvals" => "SELECT company_id FROM approvals WHERE id = ?",
        "requirements" => "SELECT company_id FROM requirements WHERE id = ?",
        "artifacts" => "SELECT company_id FROM artifacts WHERE id = ?",
        "budgets" => crate::store::gov::BUDGET_COMPANY,
        "roles" => "SELECT company_id FROM roles WHERE id = ?",
        "chain-presets" => "SELECT company_id FROM chain_presets WHERE id = ?",
        "knowledge" => {
            "SELECT p.company_id FROM knowledge_entries k JOIN projects p ON p.id = k.project_id \
             WHERE k.id = ?"
        }
        _ => return Ok(None),
    };
    company_of(app, sql, id).await
}

async fn company_of(app: &App, sql: &'static str, id: i64) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_optional(&app.pool)
        .await
}

/// The segments of `template` that name a parameter, each with the literal before it and the
/// value `path` has there: `/api/v1/projects/{id}` and `/api/v1/projects/3` → `[("projects",
/// "3")]`.
pub fn params<'a>(template: &'a str, path: &'a str) -> Vec<(&'a str, &'a str)> {
    let t: Vec<&str> = template.split('/').collect();
    let p: Vec<&str> = path.split('/').collect();
    (1..t.len().min(p.len()))
        .filter(|&i| t[i].starts_with('{'))
        .map(|i| (t[i - 1], p[i]))
        .collect()
}

pub(super) async fn company_scope(
    State(app): State<App>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(raw) = req.headers().get(COMPANY_HEADER) else {
        req.extensions_mut().insert(Acting(None));
        return next.run(req).await;
    };
    let Some(acting) = raw.to_str().ok().and_then(|v| v.trim().parse::<i64>().ok()) else {
        return ApiError::bad_request("X-Citadel-Company is a company id").into_response();
    };
    match crate::store::org::get_company(&app.pool, CompanyId(acting)).await {
        Ok(Some(_)) => {}
        Ok(None) => return ApiError::not_found(format!("no company {acting}")).into_response(),
        Err(e) => return ApiError::from(e).into_response(),
    }
    let template = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default();
    let path = req.uri().path().to_owned();
    for (segment, value) in params(&template, &path) {
        match owner(&app, segment, value).await {
            Ok(Some(c)) if c != acting => {
                let what = match segment {
                    "companies" => "company",
                    s => s.trim_end_matches('s'),
                };
                let why = format!("no {what} {value} in company {acting}");
                return ApiError::not_found(why).into_response();
            }
            Ok(_) => {}
            Err(e) => return ApiError::from(e).into_response(),
        }
    }
    req.extensions_mut().insert(Acting(Some(CompanyId(acting))));
    next.run(req).await
}
