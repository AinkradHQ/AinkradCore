//! Linear commands (E9.4), as the admin: sync a project with a Linear team.

use std::path::{Path, PathBuf};

use ainkrad_core::audit::AuditActor;
use ainkrad_core::work::ProjectId;
use ainkrad_core_server::store::{self, linear};

use super::{ADMIN, flags, id};
use crate::Result_;

pub const USAGE: &str =
    "  ainkrad-core-server linear set <db> <project-id> <team-id> --token-file <path> [--api <url>]
  ainkrad-core-server linear show <db> <project-id>
  ainkrad-core-server linear sync <db>
linear set syncs a project's issues both ways with a Linear team (its id, not its key): titles,
descriptions, states by type, and assignees an agent and a Linear member share by name; on a
field both sides changed, the later write wins (audited). It runs with the forge poll
(the forge.poll_secs setting); linear sync runs one pass now. The API key stays in its file.";

/// Runs a Linear command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["linear", "set", db, project, team, rest @ ..] => {
            let f = flags(rest, &["--token-file", "--api"])?;
            let set = linear::ProjectLinear {
                project_id: ProjectId(id(project).ok()?),
                team_id: team.to_string(),
                api_url: f.get("--api").unwrap_or(&linear::LINEAR_API).to_string(),
                token_file: PathBuf::from(f.get("--token-file")?),
                cursor: None,
            };
            set_linear(Path::new(db), &set).await
        }
        ["linear", "show", db, project] => show(Path::new(db), ProjectId(id(project).ok()?)).await,
        ["linear", "sync", db] => sync(Path::new(db)).await,
        _ => return None,
    })
}

async fn set_linear(db: &Path, l: &linear::ProjectLinear) -> Result_ {
    let pool = store::connect(db).await?;
    if !linear::set_project_linear(&pool, l, AuditActor::User(ADMIN)).await? {
        return Err(format!("no project {}", l.project_id.0).into());
    }
    eprintln!(
        "project {} syncs with Linear team {}",
        l.project_id.0, l.team_id
    );
    println!("{}", l.project_id.0);
    Ok(())
}

async fn show(db: &Path, project: ProjectId) -> Result_ {
    let pool = store::connect(db).await?;
    let l = linear::project_linear(&pool, project)
        .await?
        .ok_or_else(|| format!("project {} is not synced with Linear", project.0))?;
    println!(
        "{}\t{}\t{}\t{}",
        l.team_id,
        l.api_url,
        l.token_file.display(),
        l.cursor.unwrap_or_else(|| "-".to_owned())
    );
    Ok(())
}

async fn sync(db: &Path) -> Result_ {
    let pool = store::connect(db).await?;
    ainkrad_core_server::linear::sync(&pool, &ainkrad_providers::client()).await?;
    Ok(())
}
