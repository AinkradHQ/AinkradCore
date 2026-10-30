//! What `repos` needs of a forge, as plain data: the forge columns of a repo row, their
//! validation, and the audit and comment helpers its writes use. The forge itself (the PR
//! poller, push and done flows, the provider clients) is S6's and E2-10's.

use ainkrad_core::audit::AuditActor;
use sqlx::{Error, SqliteConnection};

use crate::domain::work::{IssueId, ProjectId};
use crate::store::audit::{self, Event};

/// A project's repository on a forge. `kind` is `github` or `gitlab` (the `forge_kind` column).
// ponytail: a text kind until S6 brings the providers crate's `Kind`; the column allows two values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectForge {
    pub project_id: ProjectId,
    pub kind: String,
    /// The API's base URL, e.g. `https://api.github.com`.
    pub api_url: String,
    /// The repository's path on the forge: `owner/name`, or a GitLab project path.
    pub repo: String,
    /// The broker secret holding the API token (`citadel.<name>`); never the token.
    pub secret: String,
}

/// The public API of a forge `kind` (`github` or `gitlab`); `None` for another kind.
pub fn default_api(kind: &str) -> Option<&'static str> {
    match kind {
        "github" => Some("https://api.github.com"),
        "gitlab" => Some("https://gitlab.com/api/v4"),
        _ => None,
    }
}

/// Why `f` cannot be stored: an unknown kind, an API URL that is not http(s), a repository path
/// with anything but `[A-Za-z0-9._/-]` (or an empty or absolute one), or a secret that is not a `citadel.` broker name.
pub(crate) fn forge_problem(f: &ProjectForge) -> Option<String> {
    if default_api(&f.kind).is_none() {
        return Some(format!("unknown forge kind {:?}", f.kind));
    }
    let api = &f.api_url;
    if !(api.starts_with("https://") || api.starts_with("http://")) || api.contains('@') {
        return Some(format!(
            "the API URL {api:?} must be http(s) and hold no credentials"
        ));
    }
    let repo_ok = !f.repo.is_empty()
        && !f.repo.starts_with('/')
        && !f.repo.contains("..")
        && f.repo
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b));
    if !repo_ok {
        return Some(format!("bad repository path {:?}", f.repo));
    }
    if !secret_name_ok(&f.secret) {
        return Some("the secret must be a broker secret named citadel.forge.<name>".to_owned());
    }
    None
}

/// Whether `name` may be a forge's credential: a broker secret in the module's `citadel.forge.`
/// namespace (`secrets::open_for_module` opens nothing outside `citadel.`, and provider accounts
/// live elsewhere in it).
pub(crate) fn secret_name_ok(name: &str) -> bool {
    ainkrad_core_server::store::secrets::valid_name(name) && name.starts_with("citadel.forge.")
}

/// The same for a project's Linear link: `citadel.linear.`.
pub(crate) fn linear_secret_name_ok(name: &str) -> bool {
    ainkrad_core_server::store::secrets::valid_name(name) && name.starts_with("citadel.linear.")
}

/// Appends `action` about `entity` (`(kind, id)`) of `company` by `actor`.
pub(crate) async fn append(
    conn: &mut SqliteConnection,
    company: i64,
    actor: AuditActor,
    action: &str,
    entity: (&str, i64),
    details: serde_json::Value,
) -> Result<(), Error> {
    let event = Event::new(actor, action)
        .entity(entity.0, entity.1)
        .company(company)
        .details(details);
    audit::append(conn, event).await
}

/// A comment on the issue, written as the admin (the user every row defaults to).
pub(crate) async fn note(
    conn: &mut SqliteConnection,
    issue: IssueId,
    body: &str,
) -> Result<(), Error> {
    sqlx::query("INSERT INTO citadel_comments (issue_id, author_user_id, body) VALUES (?, 1, ?)")
        .bind(issue.0)
        .bind(body)
        .execute(&mut *conn)
        .await
        .map(drop)
}
