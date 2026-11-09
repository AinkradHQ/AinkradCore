//! GitHub's REST API v3 (`X-GitHub-Api-Version: 2022-11-28`), for one repository:
//!
//! - open: `POST /repos/{repo}/pulls`; refused (422) with no head branch on the forge
//!   (`GET /repos/{repo}/branches/{head}` is 404), `Error::MissingBranch`
//! - status: `GET /repos/{repo}/pulls/{n}`, then the head commit's check runs
//!   (`GET /repos/{repo}/commits/{sha}/check-runs`) and combined commit status
//!   (`GET /repos/{repo}/commits/{sha}/status`), folded into one `Checks`. A token that may not
//!   read check runs (403/404, e.g. a fine-grained PAT without Checks) falls back to the head's
//!   Actions workflow runs (`GET /repos/{repo}/actions/runs?head_sha=`), then to the statuses
//!   alone, and says so in `PrStatus::note`
//! - merge: `PUT /repos/{repo}/pulls/{n}/merge` with `merge_method: merge`, the head `sha` and
//!   the merge commit's `commit_title`
//! - delete branch: `DELETE /repos/{repo}/git/refs/heads/{branch}` (404: already gone, fine)
//! - comment: `POST /repos/{repo}/issues/{n}/comments`
//!
//! The token is a bearer (a fine-grained PAT or an app installation token with pull requests,
//! contents and checks/statuses read).

use serde_json::{Value, json};

use super::*;

pub struct GitHub {
    client: reqwest::Client,
    /// `https://api.github.com`, or a GitHub Enterprise `https://<host>/api/v3`.
    api: String,
    /// `owner/name`.
    repo: String,
    token: Secret,
}

impl GitHub {
    pub fn new(client: reqwest::Client, api: &str, repo: &str, token: Secret) -> Self {
        Self {
            client,
            api: api.trim_end_matches('/').to_owned(),
            repo: repo.to_owned(),
            token,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/repos/{}/{path}", self.api, self.repo)
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let mut req = self
            .client
            .request(method, self.url(path))
            .bearer_auth(self.token.expose())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(body) = body {
            req = req.json(&body);
        }
        send(req, &self.token).await
    }
}

impl GitHub {
    /// The repository's default branch and whether the token may push.
    pub async fn access(&self) -> Result<RepoAccess> {
        let req = self
            .client
            .get(format!("{}/repos/{}", self.api, self.repo))
            .bearer_auth(self.token.expose())
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        send(req, &self.token).await.map(|v| github_access(&v))
    }
}

/// A pull request from GitHub's JSON.
fn pr(v: &Value) -> Result<Pr> {
    let state = match (text(v, "state")?.as_str(), v["merged"].as_bool()) {
        (_, Some(true)) => PrState::Merged,
        ("open", _) => PrState::Open,
        _ => PrState::Closed,
    };
    Ok(Pr {
        number: number(v, "number")?,
        url: text(v, "html_url")?,
        state,
        head_sha: text(v, "head.sha")?,
    })
}

/// One check run's (or Actions workflow run's: the same fields) verdict: still running, or
/// its conclusion.
fn check_run(run: &Value) -> Checks {
    if run["status"].as_str() != Some("completed") {
        return Checks::Pending;
    }
    match run["conclusion"].as_str() {
        Some("success" | "neutral" | "skipped") => Checks::Success,
        _ => Checks::Failure,
    }
}

/// Check runs (or workflow runs) the token may not read: forbidden, or hidden as not found.
fn unreadable(e: &Error) -> bool {
    matches!(
        e,
        Error::Http {
            status: 403 | 404,
            ..
        }
    )
}

/// `PrStatus::note` when the check runs cannot be read but Actions runs can.
pub const ACTIONS_ONLY: &str = "CI check runs can't be read with this token (needs Checks \
                                read); showing GitHub Actions runs and commit statuses only";
/// `PrStatus::note` when neither check runs nor Actions runs can be read.
pub const STATUSES_ONLY: &str = "CI checks can't be read with this token (needs Checks or \
                                 Actions read); showing commit statuses only";

/// One commit status's verdict.
fn status(state: Option<&str>) -> Checks {
    match state {
        Some("success") => Checks::Success,
        Some("pending") => Checks::Pending,
        _ => Checks::Failure,
    }
}

impl Forge for GitHub {
    async fn open_pr(&self, new: &NewPr) -> Result<Pr> {
        let body = json!({"title": new.title, "body": new.body, "head": new.head,
                          "base": new.base});
        let opened = self.call(reqwest::Method::POST, "pulls", Some(body)).await;
        if let Err(Error::Http { status: 422, .. }) = &opened {
            let branch = format!("branches/{}", new.head);
            if let Err(Error::Http { status: 404, .. }) =
                self.call(reqwest::Method::GET, &branch, None).await
            {
                return Err(Error::MissingBranch(new.head.clone()));
            }
        }
        pr(&opened?)
    }

    // ponytail: the first 100 check runs and statuses only; page when a repo runs more.
    async fn pr_status(&self, number: u64) -> Result<PrStatus> {
        let pr = pr(&self
            .call(reqwest::Method::GET, &format!("pulls/{number}"), None)
            .await?)?;
        let sha = &pr.head_sha;
        let get = async |path: String| self.call(reqwest::Method::GET, &path, None).await;
        // ponytail: an unreadable token costs one or two refused requests every poll.
        let (runs, note) = match get(format!("commits/{sha}/check-runs?per_page=100")).await {
            Ok(v) => (v["check_runs"].clone(), None),
            Err(e) if unreadable(&e) => {
                match get(format!("actions/runs?head_sha={sha}&per_page=100")).await {
                    Ok(v) => (v["workflow_runs"].clone(), Some(ACTIONS_ONLY)),
                    Err(e) if unreadable(&e) => (Value::Null, Some(STATUSES_ONLY)),
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        };
        let combined = self
            .call(reqwest::Method::GET, &format!("commits/{sha}/status"), None)
            .await?;
        let mut each = vec![];
        let mut failed = vec![];
        for run in runs.as_array().into_iter().flatten() {
            let verdict = check_run(run);
            if verdict == Checks::Failure {
                failed.push(run["name"].as_str().unwrap_or("?").to_owned());
            }
            each.push(verdict);
        }
        for s in combined["statuses"].as_array().into_iter().flatten() {
            let verdict = status(s["state"].as_str());
            if verdict == Checks::Failure {
                failed.push(s["context"].as_str().unwrap_or("?").to_owned());
            }
            each.push(verdict);
        }
        Ok(PrStatus {
            pr,
            checks: Checks::all(each),
            failed,
            note: note.map(str::to_owned),
        })
    }

    async fn merge(&self, number: u64, sha: &str, title: &str) -> Result<()> {
        let body = json!({"merge_method": "merge", "sha": sha, "commit_title": title});
        let merged = self
            .call(
                reqwest::Method::PUT,
                &format!("pulls/{number}/merge"),
                Some(body),
            )
            .await?;
        match merged["merged"].as_bool() {
            Some(true) => Ok(()),
            _ => Err(Error::Decode(format!(
                "not merged: {}",
                merged.to_string().chars().take(200).collect::<String>()
            ))),
        }
    }

    async fn delete_branch(&self, branch: &str) -> Result<()> {
        let path = format!("git/refs/heads/{branch}");
        match self.call(reqwest::Method::DELETE, &path, None).await {
            Err(Error::Http { status: 404, .. }) => Ok(()),
            other => other.map(drop),
        }
    }

    async fn comment(&self, number: u64, body: &str) -> Result<()> {
        let body = json!({"body": body});
        self.call(
            reqwest::Method::POST,
            &format!("issues/{number}/comments"),
            Some(body),
        )
        .await
        .map(drop)
    }
}

#[cfg(test)]
mod tests;
