//! GitLab's REST API v4, for one project (its path URL-encoded as the id); a PR is a merge
//! request and its number the MR's `iid`:
//!
//! - open: `POST /projects/{id}/merge_requests`
//! - status: `GET /projects/{id}/merge_requests/{iid}` (its `head_pipeline`), then the head
//!   commit's statuses (`GET /projects/{id}/repository/commits/{sha}/statuses`), folded into
//!   one `Checks`
//! - merge: `PUT /projects/{id}/merge_requests/{iid}/merge` with the head `sha` and
//!   `squash: false` and the merge commit's `merge_commit_message`. Whether GitLab writes a merge
//!   commit is the project's merge method: it must be "Merge commit" (the default), which
//!   Citadel cannot set from here.
//! - delete branch: `DELETE /projects/{id}/repository/branches/{branch}` (404: already gone)
//! - comment: `POST /projects/{id}/merge_requests/{iid}/notes`
//!
//! The token (a project or personal access token with `api`) goes in `PRIVATE-TOKEN`.

use serde_json::{Value, json};

use super::*;

pub struct GitLab {
    client: reqwest::Client,
    /// `https://gitlab.com/api/v4`, or a self-hosted `https://<host>/api/v4`.
    api: String,
    /// The project's path, URL-encoded: `group%2Fsub%2Fname`.
    project: String,
    token: Secret,
}

impl GitLab {
    pub fn new(client: reqwest::Client, api: &str, repo: &str, token: Secret) -> Self {
        Self {
            client,
            api: api.trim_end_matches('/').to_owned(),
            project: repo.replace('/', "%2F"),
            token,
        }
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value> {
        let url = format!("{}/projects/{}/{path}", self.api, self.project);
        let mut req = self
            .client
            .request(method, url)
            .header("PRIVATE-TOKEN", self.token.expose());
        if let Some(body) = body {
            req = req.json(&body);
        }
        send(req, &self.token).await
    }
}

impl GitLab {
    /// The project's default branch and whether the token may push.
    pub async fn access(&self) -> Result<RepoAccess> {
        let req = self
            .client
            .get(format!("{}/projects/{}", self.api, self.project))
            .header("PRIVATE-TOKEN", self.token.expose());
        send(req, &self.token).await.map(|v| gitlab_access(&v))
    }
}

/// `s` percent-encoded for a URL path segment: every byte but the unreserved ones (so a branch's
/// `/` becomes `%2F`).
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A merge request from GitLab's JSON.
fn mr(v: &Value) -> Result<Pr> {
    let state = match text(v, "state")?.as_str() {
        "opened" | "locked" => PrState::Open,
        "merged" => PrState::Merged,
        _ => PrState::Closed,
    };
    Ok(Pr {
        number: number(v, "iid")?,
        url: text(v, "web_url")?,
        state,
        head_sha: text(v, "sha")?,
    })
}

/// A pipeline's or commit status's verdict.
fn verdict(status: &str) -> Checks {
    match status {
        "success" => Checks::Success,
        "failed" | "canceled" => Checks::Failure,
        "skipped" => Checks::None,
        // created, waiting_for_resource, preparing, pending, running, scheduled, manual
        _ => Checks::Pending,
    }
}

impl Forge for GitLab {
    async fn open_pr(&self, new: &NewPr) -> Result<Pr> {
        let body = json!({"source_branch": new.head, "target_branch": new.base,
                          "title": new.title, "description": new.body});
        mr(&self
            .call(reqwest::Method::POST, "merge_requests", Some(body))
            .await?)
    }

    // ponytail: the first 100 commit statuses only; page when a pipeline runs more jobs.
    async fn pr_status(&self, number: u64) -> Result<PrStatus> {
        let v = self
            .call(
                reqwest::Method::GET,
                &format!("merge_requests/{number}"),
                None,
            )
            .await?;
        let pr = mr(&v)?;
        let mut each = vec![];
        let mut failed = vec![];
        if let Some(status) = v["head_pipeline"]["status"].as_str() {
            let c = verdict(status);
            if c == Checks::Failure {
                failed.push("pipeline".to_owned());
            }
            each.push(c);
        }
        let path = format!("repository/commits/{}/statuses?per_page=100", pr.head_sha);
        let statuses = self.call(reqwest::Method::GET, &path, None).await?;
        for s in statuses.as_array().into_iter().flatten() {
            let c = verdict(s["status"].as_str().unwrap_or(""));
            if c == Checks::Failure {
                failed.push(s["name"].as_str().unwrap_or("?").to_owned());
            }
            each.push(c);
        }
        Ok(PrStatus {
            pr,
            checks: Checks::all(each),
            failed,
            note: None,
        })
    }

    async fn merge(&self, number: u64, sha: &str, title: &str) -> Result<()> {
        let body = json!({"sha": sha, "squash": false, "should_remove_source_branch": false,
                          "merge_commit_message": title});
        let merged = self
            .call(
                reqwest::Method::PUT,
                &format!("merge_requests/{number}/merge"),
                Some(body),
            )
            .await?;
        match merged["state"].as_str() {
            Some("merged") => Ok(()),
            _ => Err(Error::Decode(format!(
                "not merged: {}",
                merged.to_string().chars().take(200).collect::<String>()
            ))),
        }
    }

    async fn delete_branch(&self, branch: &str) -> Result<()> {
        let path = format!("repository/branches/{}", encode(branch));
        match self.call(reqwest::Method::DELETE, &path, None).await {
            Err(Error::Http { status: 404, .. }) => Ok(()),
            other => other.map(drop),
        }
    }

    async fn comment(&self, number: u64, body: &str) -> Result<()> {
        let body = json!({"body": body});
        self.call(
            reqwest::Method::POST,
            &format!("merge_requests/{number}/notes"),
            Some(body),
        )
        .await
        .map(drop)
    }
}

#[cfg(test)]
mod tests;
