//! The GitHub kind (C2; design §3, §6). Auth methods in order of preference: Sign in with GitHub
//! (the device flow, [`device`]), a GitHub App install ([`app`]), a personal access token
//! (Advanced). Typed operations are data ([`ops`]); the one door to GitHub is [`http`]; replies
//! end as plain codes ([`outcome`]).
//!
//! The method ids are C1's `AUTH_METHODS`: the device flow is `oauth`.
//!
//! What the broker (C4) and the API (C5) use: [`GITHUB`] (via the registry), [`Github::execute`],
//! [`ops::build`] / [`ops::Built`], [`Outcome::health`], [`device::start`] / [`device::Pending`],
//! [`app::mint`], [`Github::whoami`].

use std::sync::Arc;

use futures_util::future::{BoxFuture, FutureExt};
use serde_json::Value;

use super::adapter::{
    AuthMethodSpec, Capability, Descriptor, Identity, KindAdapter, LimitKey, TestError,
};
use super::material::Material;

mod addr;
pub mod app;
pub mod device;
mod guard;
pub mod http;
pub mod ops;
pub mod outcome;

pub use guard::BuildError;
pub use http::{Rate, Transport};
pub use ops::{Built, Op, build};
pub use outcome::Outcome;

use http::{Host, Req};

pub const GITHUB: Descriptor = Descriptor {
    kind: "github",
    title: "GitHub",
    summary: "Repositories, issues and pull requests on github.com.",
    auth_methods: &[
        AuthMethodSpec {
            id: "oauth",
            title: "Sign in with GitHub",
            help: "Core shows a short code. Type it on github.com and approve. Nothing to copy or paste.",
            steps: &[
                "Core shows a short code",
                "Open the GitHub page and type the code",
                "Approve the request on GitHub",
                "Come back here: you are connected",
            ],
            advanced: false,
        },
        AuthMethodSpec {
            id: "app_install",
            title: "Choose repositories (GitHub App)",
            help: "Install the Ainkrad GitHub App on your account and pick the repositories Core may reach.",
            steps: &[
                "Open the GitHub App page",
                "Choose the account and the repositories",
                "Approve the installation",
                "Come back here: you are connected",
            ],
            advanced: false,
        },
        AuthMethodSpec {
            id: "token",
            title: "Personal access token",
            help: "Paste a token you made in GitHub's developer settings.",
            steps: &[
                "Open GitHub, Settings, Developer settings, Personal access tokens",
                "Make a token with the access you want Core to have",
                "Paste it here",
            ],
            advanced: true,
        },
    ],
    capabilities: &[
        Capability {
            name: "read_repo",
            title: "Read repositories, issues and pull requests",
            write: false,
            operations: &[
                "github.get_repo",
                "github.list_branches",
                "github.read_file",
                "github.list_issues",
                "github.get_issue",
                "github.list_issue_comments",
                "github.list_prs",
                "github.get_pr",
                "github.list_pr_files",
            ],
        },
        Capability {
            name: "issues_write",
            title: "Create and edit issues and comment on them",
            write: true,
            operations: &[
                "github.create_issue",
                "github.update_issue",
                "github.comment_issue",
            ],
        },
        Capability {
            name: "pr_write",
            title: "Open pull requests and comment on them",
            write: true,
            operations: &["github.create_pr", "github.update_pr", "github.comment_pr"],
        },
        Capability {
            name: "push",
            title: "Create branches and commit files",
            write: true,
            operations: &["github.create_branch", "github.put_file"],
        },
    ],
    hosts: &["api.github.com", "github.com"],
    limits: &[LimitKey {
        key: "repos",
        title: "Repositories",
        help: "`owner/name`, or `owner/*` for every repository of an owner.",
    }],
    // The redactor's name for `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` and `github_pat_` tokens.
    token_shapes: &["github_token"],
    // `github_token` also matches `ghr_` refresh tokens; those are never the access token.
    refresh_prefixes: &["ghr_"],
    // Every GitHub operation carries a repository, so none judges its own limits.
    self_limited: &[],
};

/// Who a token is, as GitHub says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Whoami {
    pub login: String,
    pub id: Option<u64>,
    /// `X-OAuth-Scopes` of a classic token or sign-in; empty for a fine-grained one.
    pub scopes: Option<String>,
    pub rate: Rate,
}

/// A finished call: only a 2xx gets here (anything else is an [`Outcome`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Done {
    pub status: u16,
    /// The reply, with the credential cut out of it if GitHub echoed it.
    pub body: Vec<u8>,
    pub rate: Rate,
}

#[derive(Clone)]
pub struct Github {
    transport: Arc<Transport>,
}

fn scrub(mut body: Vec<u8>, secrets: &[&str]) -> Vec<u8> {
    for s in secrets.iter().filter(|s| !s.is_empty()) {
        let n = s.as_bytes();
        let mut i = 0;
        while i + n.len() <= body.len() {
            if &body[i..i + n.len()] == n {
                drop(body.splice(i..i + n.len(), b"[redacted]".iter().copied()));
                i += 10;
            } else {
                i += 1;
            }
        }
    }
    body
}

impl Github {
    pub fn new(transport: Arc<Transport>) -> Self {
        Self { transport }
    }

    pub fn strict() -> Self {
        Self::new(Arc::new(Transport::strict()))
    }

    pub fn transport(&self) -> &Arc<Transport> {
        &self.transport
    }

    /// Makes a built request with `m`'s token. An operation that must reach an issue, not a pull
    /// request (or the reverse) first reads the number and refuses with `is_pull_request` or
    /// `not_pull_request`: GitHub treats a pull request as an issue, and the two capabilities are
    /// not the same permission.
    pub async fn execute(&self, m: &Material, b: &Built) -> Result<Done, Outcome> {
        self.verify(m, b).await?;
        let resp = self.transport.send(b.req(), Some(m.access())).await?;
        outcome::classify(&resp)?;
        Ok(Done {
            status: resp.status,
            body: scrub(resp.body.to_vec(), &[m.access(), m.refresh().unwrap_or("")]),
            rate: resp.rate,
        })
    }

    async fn verify(&self, m: &Material, b: &Built) -> Result<(), Outcome> {
        let want = guard::check_of(b.op().name);
        if want == guard::Check::Nothing {
            return Ok(());
        }
        let n = b.number().ok_or(Outcome::Invalid)?;
        let path = format!("/repos/{}/issues/{n}", b.resource());
        let resp = self
            .transport
            .send(&Req::get(Host::Api, path), Some(m.access()))
            .await?;
        outcome::classify(&resp)?;
        let v: Value = serde_json::from_slice(&resp.body).map_err(|_| Outcome::Unexpected)?;
        let is_pull = v.get("pull_request").is_some_and(|p| !p.is_null());
        match (want, is_pull) {
            (guard::Check::NotPull, true) => Err(Outcome::IsPullRequest),
            (guard::Check::IsPull, false) => Err(Outcome::NotPullRequest),
            _ => Ok(()),
        }
    }

    /// `GET /user`: whose token this is. An installation token (the GitHub App) cannot read
    /// `/user`; it is asked for its repositories instead and named by their owner.
    pub async fn whoami(&self, m: &Material) -> Result<Whoami, Outcome> {
        let req = Req::get(Host::Api, "/user".to_owned());
        let resp = self.transport.send(&req, Some(m.access())).await?;
        match outcome::classify(&resp) {
            Ok(()) => {
                let v: Value =
                    serde_json::from_slice(&resp.body).map_err(|_| Outcome::Unexpected)?;
                let login = v["login"]
                    .as_str()
                    .filter(|l| !l.is_empty())
                    .ok_or(Outcome::Unexpected)?;
                Ok(Whoami {
                    login: login.chars().take(64).collect(),
                    id: v["id"].as_u64(),
                    scopes: resp.scopes,
                    rate: resp.rate,
                })
            }
            Err(Outcome::Forbidden) => self.installation(m).await,
            Err(e) => Err(e),
        }
    }

    async fn installation(&self, m: &Material) -> Result<Whoami, Outcome> {
        let req = Req::get(
            Host::Api,
            "/installation/repositories?per_page=1".to_owned(),
        );
        let resp = self.transport.send(&req, Some(m.access())).await?;
        outcome::classify(&resp)?;
        let v: Value = serde_json::from_slice(&resp.body).map_err(|_| Outcome::Unexpected)?;
        let owner = &v["repositories"][0]["owner"];
        Ok(Whoami {
            login: owner["login"]
                .as_str()
                .unwrap_or("installation")
                .chars()
                .take(64)
                .collect(),
            id: owner["id"].as_u64(),
            scopes: None,
            rate: resp.rate,
        })
    }
}

impl KindAdapter for Github {
    fn descriptor(&self) -> &Descriptor {
        &GITHUB
    }

    /// A 401 is a confirmed refusal; anything else that is not an identity (rate limit, 5xx,
    /// no network) says nothing about the token.
    fn test<'a>(&'a self, m: &'a Material) -> BoxFuture<'a, Result<Identity, TestError>> {
        async move {
            match self.whoami(m).await {
                Ok(w) => Ok(Identity { subject: w.login }),
                Err(Outcome::AuthFailed) => Err(TestError::Rejected),
                Err(_) => Err(TestError::Inconclusive),
            }
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests;
