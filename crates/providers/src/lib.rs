//! Git host and tracker providers (E9, decisions #20, #26): GitHub and GitLab behind one
//! `Forge` trait (open a pull request for an issue's branch, read its status and checks, merge
//! it with a merge commit, comment on it), and Linear's issues for the two-way sync (`linear`).
//!
//! Only HTTP lives here; the server decides when to call (the merge only after a `pr_merge`
//! approval) and records what comes back. Branches are pushed by the runner (E9.1), not here.
//!
//! Credentials: a provider is given a `Secret` read from a server-side file. It travels only in
//! the request's auth header; its `Debug` is redacted, and it is cut out of any error text, so
//! no log line can carry it.

use std::fmt;
use std::future::Future;
use std::path::Path;
use std::time::Duration;

pub mod github;
pub mod gitlab;
pub mod guard;
pub mod linear;

pub use reqwest::Client;

#[cfg(feature = "fake")]
pub mod fake;

/// An API token. `Debug` never shows it; `expose` is the one way to read it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(raw: impl Into<String>) -> Self {
        Self(raw.into())
    }

    /// The token in `path`, trimmed; why it cannot be read otherwise (never the content).
    pub fn from_file(path: &Path) -> std::result::Result<Self, String> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("reading the token file {}: {e}", path.display()))?;
        match raw.trim() {
            "" => Err(format!("the token file {} is empty", path.display())),
            token => Ok(Self(token.to_owned())),
        }
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Why a provider call failed. Its text never holds the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The API answered with an error status; `message` is what it said.
    Http { status: u16, message: String },
    /// No answer: connection, TLS or timeout.
    Transport(String),
    /// An answer we could not read.
    Decode(String),
    /// The PR's head branch is not on the forge: it was never pushed.
    MissingBranch(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { status, message } => write!(f, "HTTP {status}: {message}"),
            Self::Transport(why) => write!(f, "unreachable: {why}"),
            Self::Decode(why) => write!(f, "unreadable answer: {why}"),
            Self::MissingBranch(b) => {
                write!(f, "the branch {b} is not on the forge (not pushed yet)")
            }
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// A pull (merge) request to open: `head` into `base`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPr {
    pub head: String,
    pub base: String,
    pub title: String,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrState {
    Open,
    Merged,
    /// Closed without merging.
    Closed,
}

/// What the checks on a PR's head commit say, all together: any failure fails them, any still
/// running keeps them pending; `None` when there are no checks at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checks {
    None,
    Pending,
    Success,
    Failure,
}

impl Checks {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pending => "pending",
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }

    /// The overall verdict of several.
    pub fn all(each: impl IntoIterator<Item = Checks>) -> Checks {
        each.into_iter()
            .fold(Checks::None, |acc, c| match (acc, c) {
                (Checks::Failure, _) | (_, Checks::Failure) => Checks::Failure,
                (Checks::Pending, _) | (_, Checks::Pending) => Checks::Pending,
                (Checks::Success, _) | (_, Checks::Success) => Checks::Success,
                _ => Checks::None,
            })
    }
}

/// A pull request as the host has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pr {
    pub number: u64,
    pub url: String,
    pub state: PrState,
    pub head_sha: String,
}

/// A pull request with its checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrStatus {
    pub pr: Pr,
    pub checks: Checks,
    /// The names of the checks that failed.
    pub failed: Vec<String>,
    /// Set when some checks could not be read (the token lacks the scope): what `checks` is
    /// made of instead.
    pub note: Option<String>,
}

/// A git host's pull requests, for one repository.
pub trait Forge {
    /// Opens a pull request; the head branch must already be pushed.
    fn open_pr(&self, pr: &NewPr) -> impl Future<Output = Result<Pr>> + Send;

    /// The pull request and the checks on its head commit.
    fn pr_status(&self, number: u64) -> impl Future<Output = Result<PrStatus>> + Send;

    /// Merges it with a merge commit titled `title` (never squash or rebase), only if its head is
    /// still `sha`.
    fn merge(&self, number: u64, sha: &str, title: &str)
    -> impl Future<Output = Result<()>> + Send;

    /// Deletes branch `branch` of the repository. A branch already gone is not an error.
    fn delete_branch(&self, branch: &str) -> impl Future<Output = Result<()>> + Send;

    /// Posts `body` as a comment on it.
    fn comment(&self, number: u64, body: &str) -> impl Future<Output = Result<()>> + Send;
}

/// What a token may do to a repository: its default branch, and whether it may push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoAccess {
    pub default_branch: Option<String>,
    pub can_push: bool,
}

/// GitHub's `GET /repos/{repo}` as access: `permissions.push` (absent: no).
pub fn github_access(v: &serde_json::Value) -> RepoAccess {
    RepoAccess {
        default_branch: v["default_branch"].as_str().map(str::to_owned),
        can_push: v["permissions"]["push"].as_bool().unwrap_or(false),
    }
}

/// GitLab's `GET /projects/{id}` as access: a Developer (30) or above on the project or its
/// group may push.
pub fn gitlab_access(v: &serde_json::Value) -> RepoAccess {
    let level = |k: &str| v["permissions"][k]["access_level"].as_i64().unwrap_or(0);
    RepoAccess {
        default_branch: v["default_branch"].as_str().map(str::to_owned),
        can_push: level("project_access").max(level("group_access")) >= 30,
    }
}

/// Which host a project's repository lives on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    GitHub,
    GitLab,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
        }
    }

    /// The public API's base URL.
    pub fn default_api(self) -> &'static str {
        match self {
            Self::GitHub => "https://api.github.com",
            Self::GitLab => "https://gitlab.com/api/v4",
        }
    }
}

impl std::str::FromStr for Kind {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, String> {
        match s {
            "github" => Ok(Self::GitHub),
            "gitlab" => Ok(Self::GitLab),
            other => Err(format!("unknown forge {other:?}: github or gitlab")),
        }
    }
}

/// Either host, chosen per project at run time.
pub enum AnyForge {
    GitHub(github::GitHub),
    GitLab(gitlab::GitLab),
}

impl AnyForge {
    /// The forge of `kind` at `api` for repository `repo` (`owner/name`, or a GitLab project
    /// path), authenticated with `token`.
    pub fn new(client: &reqwest::Client, kind: Kind, api: &str, repo: &str, token: Secret) -> Self {
        match kind {
            Kind::GitHub => Self::GitHub(github::GitHub::new(client.clone(), api, repo, token)),
            Kind::GitLab => Self::GitLab(gitlab::GitLab::new(client.clone(), api, repo, token)),
        }
    }
}

impl AnyForge {
    /// The repository's default branch and whether the token may push to it.
    pub async fn repo_access(&self) -> Result<RepoAccess> {
        match self {
            Self::GitHub(f) => f.access().await,
            Self::GitLab(f) => f.access().await,
        }
    }
}

impl Forge for AnyForge {
    async fn open_pr(&self, pr: &NewPr) -> Result<Pr> {
        match self {
            Self::GitHub(f) => f.open_pr(pr).await,
            Self::GitLab(f) => f.open_pr(pr).await,
        }
    }

    async fn pr_status(&self, number: u64) -> Result<PrStatus> {
        match self {
            Self::GitHub(f) => f.pr_status(number).await,
            Self::GitLab(f) => f.pr_status(number).await,
        }
    }

    async fn merge(&self, number: u64, sha: &str, title: &str) -> Result<()> {
        match self {
            Self::GitHub(f) => f.merge(number, sha, title).await,
            Self::GitLab(f) => f.merge(number, sha, title).await,
        }
    }

    async fn delete_branch(&self, branch: &str) -> Result<()> {
        match self {
            Self::GitHub(f) => f.delete_branch(branch).await,
            Self::GitLab(f) => f.delete_branch(branch).await,
        }
    }

    async fn comment(&self, number: u64, body: &str) -> Result<()> {
        match self {
            Self::GitHub(f) => f.comment(number, body).await,
            Self::GitLab(f) => f.comment(number, body).await,
        }
    }
}

/// The HTTP client every provider shares: a 30 s timeout and Citadel's user agent (GitHub
/// refuses requests without one).
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("citadel/", env!("CARGO_PKG_VERSION")))
        .build()
        .expect("a client with a timeout and user agent builds")
}

/// Sends `req` and reads its JSON answer; an error status becomes `Error::Http` with the API's
/// message, every error's text with `token` cut out.
async fn send(req: reqwest::RequestBuilder, token: &Secret) -> Result<serde_json::Value> {
    let scrub = |text: String| text.replace(token.expose(), "<redacted>");
    let res = req
        .send()
        .await
        .map_err(|e| Error::Transport(scrub(e.without_url().to_string())))?;
    let status = res.status();
    let text = read_capped(res, &scrub).await?;
    let body: serde_json::Value = if text.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&text).map_err(|e| Error::Decode(scrub(e.to_string())))?
    };
    if !status.is_success() {
        let message = body["message"]
            .as_str()
            .or(body["error"].as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| text.chars().take(300).collect());
        return Err(Error::Http {
            status: status.as_u16(),
            message: scrub(message),
        });
    }
    Ok(body)
}

/// The most of an answer read: a hostile or broken host cannot fill memory.
pub const MAX_ANSWER_BYTES: usize = 4 * 1024 * 1024;

async fn read_capped(
    mut res: reqwest::Response,
    scrub: &impl Fn(String) -> String,
) -> Result<String> {
    let too_big = || Error::Transport(format!("the answer is over {MAX_ANSWER_BYTES} bytes"));
    if res
        .content_length()
        .is_some_and(|n| n > MAX_ANSWER_BYTES as u64)
    {
        return Err(too_big());
    }
    let mut body = Vec::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|e| Error::Transport(scrub(e.without_url().to_string())))?
    {
        if body.len() + chunk.len() > MAX_ANSWER_BYTES {
            return Err(too_big());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// A field of an API answer, or `Error::Decode` naming it.
fn field<'a>(v: &'a serde_json::Value, path: &str) -> Result<&'a serde_json::Value> {
    let mut at = v;
    for key in path.split('.') {
        at = &at[key];
    }
    match at {
        serde_json::Value::Null => Err(Error::Decode(format!("no {path} in the answer"))),
        found => Ok(found),
    }
}

fn text(v: &serde_json::Value, path: &str) -> Result<String> {
    field(v, path)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| Error::Decode(format!("{path} is not text")))
}

fn number(v: &serde_json::Value, path: &str) -> Result<u64> {
    field(v, path)?
        .as_u64()
        .ok_or_else(|| Error::Decode(format!("{path} is not a number")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_fold_failure_over_pending_over_success() {
        use Checks::*;
        assert_eq!(Checks::all([]), None);
        assert_eq!(Checks::all([Success, Pending]), Pending);
        assert_eq!(Checks::all([Pending, Failure, Success]), Failure);
        assert_eq!(Checks::all([None, Success]), Success);
    }

    #[test]
    fn access_reads_the_branch_and_the_push_right() {
        let gh = serde_json::json!({"default_branch": "trunk", "permissions": {"push": true}});
        assert_eq!(
            github_access(&gh),
            RepoAccess {
                default_branch: Some("trunk".into()),
                can_push: true
            }
        );
        assert!(!github_access(&serde_json::json!({})).can_push);
        let lab = |p, g| {
            serde_json::json!({"default_branch": "main", "permissions":
            {"project_access": {"access_level": p}, "group_access": {"access_level": g}}})
        };
        assert!(!gitlab_access(&lab(20, 20)).can_push, "reporter");
        assert!(
            gitlab_access(&lab(0, 30)).can_push,
            "developer through the group"
        );
        assert!(
            !gitlab_access(&serde_json::json!({"permissions": {"project_access": null}})).can_push
        );
    }

    #[test]
    fn a_secret_never_shows_in_debug() {
        let s = Secret::new("ghp_s3cret");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert_eq!(s.expose(), "ghp_s3cret");
        let dir = std::env::temp_dir().join(format!("citadel-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("t"), "ghp_s3cret\n").unwrap();
        assert_eq!(Secret::from_file(&dir.join("t")).unwrap(), s);
        std::fs::write(dir.join("t"), " \n").unwrap();
        let empty = Secret::from_file(&dir.join("t")).unwrap_err();
        assert!(empty.contains("empty"), "{empty}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
