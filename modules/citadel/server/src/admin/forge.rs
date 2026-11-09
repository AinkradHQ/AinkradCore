//! Forge commands (E9), as the admin: put a project's repository on a git host.

use std::path::{Path, PathBuf};

use citadel_core::audit::AuditActor;
use citadel_core::work::ProjectId;
use citadel_server::store::{self, forge};
use ainkrad_providers::Kind;

use super::{ADMIN, flags, id};
use crate::Result_;

pub const USAGE: &str =
    "  citadel-server forge set <db> <project-id> <github|gitlab> <owner/repo>
                 --token-file <path> [--api <url>]
  citadel-server forge show <db> <project-id>
forge set puts a project (which needs a --repo) on a git host: agents' open_pr requests become
pull requests there, opened from the issue branch the runner pushes, and their status and checks
come back as issue comments (the forge.poll_secs setting). The token stays in its file (read on each
poll, never stored or logged); --api defaults to the host's public API. On GitLab the repo is
the project path, and the project's merge method must stay \"Merge commit\".";

/// Runs a forge command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["forge", "set", db, project, kind, repo, rest @ ..] => {
            let f = flags(rest, &["--token-file", "--api"])?;
            let kind: Kind = kind.parse().ok()?;
            let set = forge::ProjectForge {
                project_id: ProjectId(id(project).ok()?),
                kind,
                api_url: f.get("--api").unwrap_or(&kind.default_api()).to_string(),
                repo: repo.to_string(),
                token_file: PathBuf::from(f.get("--token-file")?),
            };
            set_forge(Path::new(db), &set).await
        }
        ["forge", "show", db, project] => show(Path::new(db), ProjectId(id(project).ok()?)).await,
        _ => return None,
    })
}

async fn set_forge(db: &Path, f: &forge::ProjectForge) -> Result_ {
    let pool = store::connect(db).await?;
    if !forge::set_project_forge(&pool, f, AuditActor::User(ADMIN)).await? {
        return Err(format!("no project {}", f.project_id.0).into());
    }
    if !f.token_file.is_file() {
        eprintln!("warning: {} does not exist yet", f.token_file.display());
    }
    eprintln!(
        "project {} on {} {}",
        f.project_id.0,
        f.kind.as_str(),
        f.repo
    );
    println!("{}", f.project_id.0);
    Ok(())
}

async fn show(db: &Path, project: ProjectId) -> Result_ {
    let pool = store::connect(db).await?;
    let f = forge::project_forge(&pool, project)
        .await?
        .ok_or_else(|| format!("project {} has no forge", project.0))?;
    println!(
        "{}\t{}\t{}\t{}",
        f.kind.as_str(),
        f.api_url,
        f.repo,
        f.token_file.display()
    );
    Ok(())
}
