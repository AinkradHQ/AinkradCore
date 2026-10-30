//! The module's OpenAPI document (`Module::openapi`): the `#[utoipa::path]` routes of every
//! ported handler, relative to `/modules/citadel/v1`. The Core merges it into the contract
//! (`api::v1::spec::json_for`) and sets each operation's `x-ainkrad-scope` and
//! `x-ainkrad-destructive` from the module's own tables, so nothing here claims a scope.
//!
//! Operation ids are the monolith's, prefixed `citadel` (`listCompanies` -> `citadelListCompanies`):
//! the Core's contract has one id space, and the platform has its own `listRunners`, `listAudit`
//! and `listSettings`.

use serde_json::Value;
use utoipa::OpenApi;

use super::{accounts, model, org};

#[derive(OpenApi)]
#[openapi(
    paths(
        org::list_companies,
        org::get_company,
        org::create_company,
        org::update_company,
        org::list_departments,
        org::add_department,
        org::rename_department,
        org::remove_department,
        org::list_teams,
        org::add_team,
        org::rename_team,
        org::remove_team,
        org::list_agents,
        org::get_agent,
    ),
    components(schemas(
        model::Company,
        model::Agent,
        model::Department,
        model::Team,
        model::Deleted
    ))
)]
struct ApiDoc;

/// `citadelListCompanies` for `listCompanies`.
fn prefixed(id: &str) -> String {
    let mut chars = id.chars();
    chars.next().map_or_else(String::new, |c| {
        format!("citadel{}{}", c.to_ascii_uppercase(), chars.as_str())
    })
}

/// The document as JSON, with prefixed operation ids.
pub fn document() -> Value {
    let mut api = ApiDoc::openapi();
    for other in [
        accounts::Doc::openapi(),
        super::org_admin::Doc::openapi(),
        super::work::Doc::openapi(),
        super::planning::Doc::openapi(),
        super::governance::Doc::openapi(),
        super::runs::Doc::openapi(),
    ] {
        api.merge(other);
    }
    let mut doc = serde_json::to_value(api).expect("spec serialises");
    for item in doc["paths"]
        .as_object_mut()
        .into_iter()
        .flatten()
        .map(|(_, v)| v)
    {
        for op in item
            .as_object_mut()
            .into_iter()
            .flat_map(|o| o.values_mut())
        {
            if let Some(id) = op["operationId"].as_str().map(prefixed) {
                op["operationId"] = Value::String(id);
            }
        }
    }
    doc
}
