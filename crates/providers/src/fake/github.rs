//! A fake GitHub REST API for one or more repositories: pull requests, branches, check runs,
//! Actions workflow runs, combined statuses, merges and comments. Its state (`Hub`) serves the fake GitLab too.

use std::collections::{BTreeMap, HashMap};

use axum::extract::State;
use serde_json::json;

use super::*;

/// A pull request the fake holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakePr {
    pub repo: String,
    pub number: u64,
    pub title: String,
    pub body: String,
    pub head: String,
    pub base: String,
    pub head_sha: String,
    pub open: bool,
    pub merged: bool,
}

#[derive(Debug, Default)]
pub struct Hub {
    /// The bearer every request must carry.
    pub token: String,
    /// When set, a PR's head must be a branch of this bare repo, and its sha is the head's.
    pub git: Option<std::path::PathBuf>,
    pub prs: BTreeMap<u64, FakePr>,
    /// Check runs per commit sha: (name, status, conclusion).
    pub check_runs: HashMap<String, Vec<(String, String, Option<String>)>>,
    /// Actions workflow runs per head sha: (name, status, conclusion).
    pub workflow_runs: HashMap<String, Vec<(String, String, Option<String>)>>,
    /// Endpoints answering 403, as to a token without their scope: `check-runs` (Checks) and
    /// `runs` (Actions).
    pub forbidden: Vec<&'static str>,
    /// Commit statuses per sha: (context, state).
    pub statuses: HashMap<String, Vec<(String, String)>>,
    /// GitLab only: the head pipeline's status per sha.
    pub pipelines: HashMap<String, String>,
    /// PRs that refuse to merge (405, as GitHub does on conflicts).
    pub unmergeable: Vec<u64>,
    /// (PR, merge method) of each merge.
    pub merges: Vec<(u64, String)>,
    /// (PR, merge commit title) of each merge.
    pub merge_titles: Vec<(u64, String)>,
    /// The branches deleted, in order; deleting one again answers 404.
    pub deleted: Vec<String>,
    /// (PR, body) of each comment.
    pub comments: Vec<(u64, String)>,
    /// "METHOD /path" of every request, in order.
    pub requests: Vec<String>,
}

/// Starts a fake GitHub that wants `token`; its API base URL and its state.
pub async fn github(token: &str) -> (String, Shared<Hub>) {
    let hub = Arc::new(Mutex::new(Hub {
        token: token.to_owned(),
        ..Hub::default()
    }));
    let router = axum::Router::new().fallback(handle).with_state(hub.clone());
    (serve(router).await, hub)
}

fn pr_json(p: &FakePr) -> Value {
    json!({"number": p.number, "html_url": format!("https://github.test/{}/pull/{}", p.repo, p.number),
           "state": if p.open { "open" } else { "closed" }, "merged": p.merged,
           "title": p.title, "head": {"ref": p.head, "sha": p.head_sha},
           "base": {"ref": p.base}})
}

async fn handle(
    State(hub): State<Shared<Hub>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut hub = hub.lock().unwrap();
    hub.requests.push(format!("{method} {}", uri.path()));
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    if auth != Some(&format!("Bearer {}", hub.token)) {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({"message": "Bad credentials"}),
        );
    }
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let parts: Vec<&str> = uri.path().trim_matches('/').split('/').collect();
    let (repo, rest) = match parts.as_slice() {
        ["repos", owner, name, rest @ ..] => (format!("{owner}/{name}"), rest.to_vec()),
        _ => return reply(StatusCode::NOT_FOUND, json!({"message": "Not Found"})),
    };
    let not_found = || reply(StatusCode::NOT_FOUND, json!({"message": "Not Found"}));
    let number = |s: &str| s.parse::<u64>().ok();
    match (method.as_str(), rest.as_slice()) {
        ("POST", ["pulls"]) => {
            let head = body["head"].as_str().unwrap_or_default().to_owned();
            let base = body["base"].as_str().unwrap_or_default();
            let title = body["title"].as_str().unwrap_or_default();
            let text = body["body"].as_str().unwrap_or_default();
            let Some(p) = hub.create(&repo, &head, base, title, text) else {
                let why = json!({"message": "Validation Failed",
                                 "errors": [{"field": "head", "code": "invalid"}]});
                return reply(StatusCode::UNPROCESSABLE_ENTITY, why);
            };
            reply(StatusCode::CREATED, pr_json(&p))
        }
        ("GET", ["pulls", n]) => match number(n).and_then(|n| hub.prs.get(&n)) {
            Some(p) => reply(StatusCode::OK, pr_json(p)),
            None => not_found(),
        },
        ("PUT", ["pulls", n, "merge"]) => {
            let Some(n) = number(n) else {
                return not_found();
            };
            if hub.unmergeable.contains(&n) {
                let why = json!({"message": "Pull Request is not mergeable"});
                return reply(StatusCode::METHOD_NOT_ALLOWED, why);
            }
            let sha = body["sha"].as_str().map(str::to_owned);
            let method = body["merge_method"].as_str().unwrap_or("merge").to_owned();
            let title = body["commit_title"].as_str().unwrap_or_default().to_owned();
            let Some(p) = hub.prs.get_mut(&n) else {
                return not_found();
            };
            if sha.as_deref() != Some(p.head_sha.as_str()) {
                let why =
                    json!({"message": "Head branch was modified. Review and try the merge again."});
                return reply(StatusCode::CONFLICT, why);
            }
            p.open = false;
            p.merged = true;
            hub.merges.push((n, method));
            hub.merge_titles.push((n, title));
            reply(
                StatusCode::OK,
                json!({"merged": true, "sha": "merge-commit"}),
            )
        }
        ("POST", ["issues", n, "comments"]) => {
            let Some(n) = number(n) else {
                return not_found();
            };
            let text = body["body"].as_str().unwrap_or_default().to_owned();
            hub.comments.push((n, text));
            reply(StatusCode::CREATED, json!({"id": hub.comments.len()}))
        }
        ("DELETE", ["git", "refs", "heads", branch @ ..]) => {
            let branch = branch.join("/");
            if hub.deleted.contains(&branch) {
                return not_found();
            }
            hub.deleted.push(branch);
            reply(StatusCode::NO_CONTENT, Value::Null)
        }
        ("GET", ["branches", branch @ ..]) => {
            let branch = branch.join("/");
            match &hub.git {
                Some(git) if branch_sha(git, &branch).is_none() => reply(
                    StatusCode::NOT_FOUND,
                    json!({"message": "Branch not found"}),
                ),
                _ => reply(StatusCode::OK, json!({"name": branch})),
            }
        }
        ("GET", ["commits", _, "check-runs"]) | ("GET", ["actions", "runs"])
            if rest.last().is_some_and(|e| hub.forbidden.contains(e)) =>
        {
            let why = json!({"message": "Resource not accessible by personal access token"});
            reply(StatusCode::FORBIDDEN, why)
        }
        ("GET", ["actions", "runs"]) => {
            let sha = uri
                .query()
                .unwrap_or_default()
                .split('&')
                .find_map(|kv| kv.strip_prefix("head_sha="))
                .unwrap_or_default();
            let runs: Vec<Value> = hub
                .workflow_runs
                .get(sha)
                .into_iter()
                .flatten()
                .map(|(name, status, conclusion)| {
                    json!({"name": name, "status": status, "conclusion": conclusion,
                           "head_sha": sha})
                })
                .collect();
            reply(
                StatusCode::OK,
                json!({"total_count": runs.len(), "workflow_runs": runs}),
            )
        }
        ("GET", ["commits", sha, "check-runs"]) => {
            let runs: Vec<Value> = hub
                .check_runs
                .get(*sha)
                .into_iter()
                .flatten()
                .map(|(name, status, conclusion)| {
                    json!({"name": name, "status": status, "conclusion": conclusion})
                })
                .collect();
            reply(
                StatusCode::OK,
                json!({"total_count": runs.len(), "check_runs": runs}),
            )
        }
        ("GET", ["commits", sha, "status"]) => {
            let statuses: Vec<Value> = hub
                .statuses
                .get(*sha)
                .into_iter()
                .flatten()
                .map(|(context, state)| json!({"context": context, "state": state}))
                .collect();
            reply(StatusCode::OK, json!({"statuses": statuses}))
        }
        _ => not_found(),
    }
}

impl Hub {
    /// Opens a PR of `head` into `base`; `None` when `git` is set and has no such branch.
    pub(super) fn create(
        &mut self,
        repo: &str,
        head: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Option<FakePr> {
        let n = self.prs.len() as u64 + 1;
        let head_sha = match &self.git {
            Some(git) => branch_sha(git, head)?,
            None => format!("{n:040}"),
        };
        let p = FakePr {
            repo: repo.to_owned(),
            number: n,
            title: title.to_owned(),
            body: body.to_owned(),
            head: head.to_owned(),
            base: base.to_owned(),
            head_sha,
            open: true,
            merged: false,
        };
        self.prs.insert(n, p.clone());
        Some(p)
    }

    /// Sets the check runs on PR `n`'s head: `(name, status, conclusion)`.
    pub fn checks(&mut self, n: u64, runs: &[(&str, &str, Option<&str>)]) {
        let sha = self.prs[&n].head_sha.clone();
        let runs = runs
            .iter()
            .map(|(a, b, c)| ((*a).to_owned(), (*b).to_owned(), c.map(str::to_owned)))
            .collect();
        self.check_runs.insert(sha, runs);
    }
}
