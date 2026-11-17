//! The repositories a connection can see (P2-01): `GET /user/repos` for a sign-in or token, or
//! `GET /installation/repositories` for a GitHub App install, one page at a time. Only the fields
//! a project picker needs are kept; nothing else GitHub said survives.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::http::{Host, Req};
use super::{Github, Material, Outcome, outcome};

/// GitHub's page size limit.
pub const PER_PAGE: usize = 100;
/// Pages of [`PER_PAGE`] read per listing: at most this many pages are searchable.
const MAX_PAGES: u32 = 10;
const TTL: Duration = Duration::from_secs(60);

/// A connection's full repo list and whether GitHub has more than was read, with when it was read.
/// ponytail: one entry per connection id, replaced on expiry; never pruned (a handful of rows).
pub(super) type Cache = Arc<Mutex<HashMap<i64, (Instant, Arc<(Vec<RepoSummary>, bool)>)>>>;

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
    /// Every repo `m` can see (up to [`MAX_PAGES`] pages) and whether GitHub has more, cached per
    /// connection for 60 s so searching and paging do not re-read GitHub.
    pub async fn all_repos(
        &self,
        connection_id: i64,
        m: &Material,
        installation: bool,
    ) -> Result<Arc<(Vec<RepoSummary>, bool)>, Outcome> {
        let hit = self
            .repo_cache
            .lock()
            .ok()
            .and_then(|c| c.get(&connection_id).cloned())
            .filter(|(at, _)| at.elapsed() < TTL);
        if let Some((_, v)) = hit {
            return Ok(v);
        }
        let mut all = Vec::new();
        let mut truncated = false;
        for page in 1..=MAX_PAGES {
            let (got, last) = self.list_repos(m, installation, page).await?;
            all.extend(got);
            truncated = !last && page == MAX_PAGES;
            if last {
                break;
            }
        }
        let v = Arc::new((all, truncated));
        if let Ok(mut c) = self.repo_cache.lock() {
            c.insert(connection_id, (Instant::now(), v.clone()));
        }
        Ok(v)
    }

    /// Page `page` (from 1) of the repositories visible to `m`, by full name, and whether it is the
    /// last: GitHub returned fewer than [`PER_PAGE`] rows (counted before unusable rows are dropped).
    async fn list_repos(
        &self,
        m: &Material,
        installation: bool,
        page: u32,
    ) -> Result<(Vec<RepoSummary>, bool), Outcome> {
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
        let last = list.len() < PER_PAGE;
        let rows = list
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
            .collect();
        Ok((rows, last))
    }
}
