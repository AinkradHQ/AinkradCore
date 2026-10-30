//! Working in one company (E15.14, pain #12: two companies' data must never mix). A client names
//! the company it works in with `X-Citadel-Company: <id>`, and switches by sending another. With
//! it, every route that takes [`Acting`] refuses what belongs to another company:
//!
//! - a path naming another company's company, project, issue, epic, sprint, agent, approval,
//!   department, team, repo, requirement, artifact, budget, role, chain preset or knowledge
//!   entry is a 404, as if it were not there (`owner`);
//! - lists that span companies keep only its own (`Acting::sees`).
//!
//! What belongs to no company stays reachable. Without the header the admin sees every company.
//!
//! The monolith ran this as a middleware over every route. A module's router has no state at
//! build time (`Module::routes`), so it is an extractor here: **every handler that takes a path
//! id or lists company data takes `Acting` first**. `tests/scope.rs` walks the contract and
//! sends every operation a malformed `X-Citadel-Company`: one that does not answer 400 forgot it.

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;
use axum::extract::{FromRequestParts, MatchedPath};
use axum::http::request::Parts;

use crate::domain::org::CompanyId;
use crate::store::org;

pub const COMPANY_HEADER: &str = "x-citadel-company";

/// `/modules/citadel/v1`: what the router nests the module under.
const PREFIX: &str = "/modules/citadel/v1";

/// The company a request works in, when it names one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

/// `(path segment, SQL)`: the company that owns what `segment/{id}` names. A slice that adds a
/// resource adds its line (append-only). The query binds the id and yields the company id (or
/// NULL), no row when there is no such row.
pub const OWNERS: &[(&str, &str)] = &[
    (
        "projects",
        "SELECT company_id FROM citadel_projects WHERE id = ?",
    ),
    (
        "issues",
        "SELECT p.company_id FROM citadel_issues i JOIN citadel_projects p ON p.id = i.project_id \
         WHERE i.id = ?",
    ),
    (
        "blockers",
        "SELECT p.company_id FROM citadel_issues i JOIN citadel_projects p ON p.id = i.project_id \
         WHERE i.id = ?",
    ),
    (
        "epics",
        "SELECT p.company_id FROM citadel_epics e JOIN citadel_projects p ON p.id = e.project_id \
         WHERE e.id = ?",
    ),
    (
        "sprints",
        "SELECT p.company_id FROM citadel_sprints s JOIN citadel_projects p ON p.id = s.project_id \
         WHERE s.id = ?",
    ),
    (
        "repos",
        "SELECT p.company_id FROM citadel_project_repos r JOIN citadel_projects p \
         ON p.id = r.project_id WHERE r.id = ?",
    ),
    (
        "agents",
        "SELECT company_id FROM citadel_agents WHERE id = ?",
    ),
    (
        "departments",
        "SELECT company_id FROM citadel_departments WHERE id = ?",
    ),
    (
        "teams",
        "SELECT d.company_id FROM citadel_teams t JOIN citadel_departments d \
         ON d.id = t.department_id WHERE t.id = ?",
    ),
    (
        "approvals",
        "SELECT company_id FROM citadel_approvals WHERE id = ?",
    ),
    (
        "requirements",
        "SELECT company_id FROM citadel_requirements WHERE id = ?",
    ),
    (
        "artifacts",
        "SELECT company_id FROM citadel_artifacts WHERE id = ?",
    ),
    ("roles", "SELECT company_id FROM citadel_roles WHERE id = ?"),
    (
        "chain-presets",
        "SELECT company_id FROM citadel_chain_presets WHERE id = ?",
    ),
    (
        "knowledge",
        "SELECT p.company_id FROM citadel_knowledge_entries k JOIN citadel_projects p \
         ON p.id = k.project_id WHERE k.id = ?",
    ),
];

/// The company that owns what `segment/{value}` names; `None` for what no company owns (or what
/// does not exist: the route says so itself).
async fn owner(app: &App, segment: &str, value: &str) -> Result<Option<i64>, sqlx::Error> {
    let Ok(id) = value.parse::<i64>() else {
        return Ok(None);
    };
    if segment == "companies" {
        return Ok(Some(id));
    }
    let rows = OWNERS
        .iter()
        .chain(super::org_admin::OWNERS)
        .chain(super::work::OWNERS)
        .chain(super::governance::OWNERS);
    let Some((_, sql)) = rows.clone().find(|(s, _)| *s == segment) else {
        return Ok(None);
    };
    let company: Option<Option<i64>> = sqlx::query_scalar(*sql)
        .bind(id)
        .fetch_optional(&app.pool)
        .await?;
    Ok(company.flatten())
}

/// The segments of `template` that name a parameter, each with the literal before it and the
/// value `path` has there: `/projects/{id}` and `/projects/3` → `[("projects", "3")]`.
pub fn params<'a>(template: &'a str, path: &'a str) -> Vec<(&'a str, &'a str)> {
    let t: Vec<&str> = template.split('/').collect();
    let p: Vec<&str> = path.split('/').collect();
    (1..t.len().min(p.len()))
        .filter(|&i| t[i].starts_with('{'))
        .map(|i| (t[i - 1], p[i]))
        .collect()
}

impl FromRequestParts<App> for Acting {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, app: &App) -> Result<Self, ApiError> {
        let Some(raw) = parts.headers.get(COMPANY_HEADER) else {
            return Ok(Self(None));
        };
        let Some(acting) = raw.to_str().ok().and_then(|v| v.trim().parse::<i64>().ok()) else {
            return Err(ApiError::bad_request("X-Citadel-Company is a company id"));
        };
        if org::get_company(&app.pool, CompanyId(acting))
            .await?
            .is_none()
        {
            return Err(ApiError::not_found(format!("no company {acting}")));
        }
        let template = parts
            .extensions
            .get::<MatchedPath>()
            .map_or("", |m| m.as_str());
        let path = parts.uri.path();
        // Nested under the module's prefix, the matched path may or may not carry it.
        let template = template.strip_prefix(PREFIX).unwrap_or(template);
        let path = path.strip_prefix(PREFIX).unwrap_or(path);
        for (segment, value) in params(template, path) {
            if let Some(c) = owner(app, segment, value).await?
                && c != acting
            {
                let what = match segment {
                    "companies" => "company",
                    s => s.trim_end_matches('s'),
                };
                return Err(ApiError::not_found(format!(
                    "no {what} {value} in company {acting}"
                )));
            }
        }
        Ok(Self(Some(CompanyId(acting))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_are_read_with_the_segment_before_them() {
        assert_eq!(params("/projects/{id}", "/projects/3"), [("projects", "3")]);
        assert_eq!(
            params("/projects/{id}/issues/{n}", "/projects/3/issues/9"),
            [("projects", "3"), ("issues", "9")]
        );
        assert!(params("/companies", "/companies").is_empty());
    }

    #[test]
    fn acting_sees_its_own_company_and_what_has_none() {
        let a = Acting(Some(CompanyId(2)));
        assert!(a.sees(Some(2)) && !a.sees(Some(3)) && !a.sees(None));
        assert!(Acting(None).sees(Some(3)) && Acting(None).sees(None));
    }
}
