//! The repositories a connection can see (P2-01): `GET /user/repos` for a sign-in or token, or
//! `GET /installation/repositories` for a GitHub App install, one page at a time. Only the fields
//! a project picker needs are kept; nothing else GitHub said survives.

use serde_json::Value;

use super::http::{Host, Req};
use super::{Github, Material, Outcome, outcome};

/// GitHub's page size limit.
pub const PER_PAGE: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoSummary {
    pub owner: String,
    pub name: String,
    pub default_branch: String,
    pub private: bool,
    pub description: String,
}

fn text(v: &Value, max: usize) -> String {
    let s: String = v.as_str().unwrap_or("").chars().take(max).collect();
    s.chars().filter(|c| !c.is_control()).collect()
}

impl Github {
    /// Page `page` (from 1) of the repositories visible to `m`, by full name. A page shorter than
    /// [`PER_PAGE`] is the last.
    pub async fn list_repos(
        &self,
        m: &Material,
        installation: bool,
        page: u32,
    ) -> Result<Vec<RepoSummary>, Outcome> {
        let path = match installation {
            true => format!("/installation/repositories?per_page={PER_PAGE}&page={page}"),
            false => format!("/user/repos?per_page={PER_PAGE}&page={page}&sort=full_name"),
        };
        let resp = self
            .transport
            .send(&Req::get(Host::Api, path), Some(m.access()))
            .await?;
        outcome::classify(&resp)?;
        let v: Value = serde_json::from_slice(&resp.body).map_err(|_| Outcome::Unexpected)?;
        let list = match installation {
            true => &v["repositories"],
            false => &v,
        };
        let list = list.as_array().ok_or(Outcome::Unexpected)?;
        Ok(list
            .iter()
            .filter_map(|r| {
                let (owner, name) = (text(&r["owner"]["login"], 64), text(&r["name"], 100));
                (!owner.is_empty() && !name.is_empty()).then(|| RepoSummary {
                    owner,
                    name,
                    default_branch: text(&r["default_branch"], 255),
                    private: r["private"].as_bool().unwrap_or(false),
                    description: text(&r["description"], 200),
                })
            })
            .collect())
    }
}
