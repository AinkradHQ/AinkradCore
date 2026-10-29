//! Repo commands (E15.16), as the admin: a project's repositories, each with its forge and
//! commands, their order and primary; the repos an issue touches; and agents' requests for more.

use std::path::{Path, PathBuf};

use ainkrad_core::audit::AuditActor;
use ainkrad_core::work::{IssueId, ProjectId};
use ainkrad_core_server::store;
use ainkrad_core_server::store::forge::ProjectForge;
use ainkrad_core_server::store::work::{self, Commands, Repo};
use ainkrad_providers::Kind;

use super::{ADMIN, flags, id};
use crate::Result_;

pub const USAGE: &str =
    "  ainkrad-core-server repo add <db> <project-id> <name> <url> [--branch <b>]
                 [--forge <github|gitlab> --forge-repo <owner/repo> --token-file <path>
                 [--api <url>]] [--build <cmd>] [--test <cmd>] [--lint <cmd>] [--format <cmd>]
  ainkrad-core-server repo set <db> <repo-id> <same flags as add, each replacing its value>
  ainkrad-core-server repo list <db> <project-id>
  ainkrad-core-server repo remove <db> <repo-id>
  ainkrad-core-server repo primary <db> <repo-id>
  ainkrad-core-server repo order <db> <project-id> <name>…
  ainkrad-core-server issue repos <db> <issue-id> [<name>…]
  ainkrad-core-server repo approve|reject <db> <issue-id> <name> [--reason <text>]
A project's first repo is its primary: an issue touches it unless its repos are set (issue
repos; none goes back to the primary). Each touched repo gets its own worktree and PR on the
issue's one branch; PRs merge in the project's repo order. An agent asks for another repo
mid-task (MCP request_repo); its team lead, or the admin here, approves or rejects it. A repo is
not removed while an open issue touches it.";

const FLAGS: &[&str] = &[
    "--branch",
    "--forge",
    "--forge-repo",
    "--token-file",
    "--api",
    "--build",
    "--test",
    "--lint",
    "--format",
];

pub async fn run(args: &[&str]) -> Option<Result_> {
    let by = AuditActor::User(ADMIN);
    Some(match args {
        ["repo", "add", db, project, name, url, rest @ ..] => {
            let f = flags(rest, FLAGS)?;
            let project = ProjectId(id(project).ok()?);
            let r = repo(project, name, url, &f, None)?;
            add(Path::new(db), r).await
        }
        ["repo", "set", db, repo_id, rest @ ..] => {
            let f = flags(rest, FLAGS)?;
            set(Path::new(db), id(repo_id).ok()?, &f).await
        }
        ["repo", "list", db, project] => list(Path::new(db), ProjectId(id(project).ok()?)).await,
        ["repo", "remove", db, repo_id] => {
            let pool = store::connect(Path::new(db)).await;
            done(
                async { Ok(work::remove_repo(&pool?, id(repo_id)?, by).await?) },
                repo_id,
            )
            .await
        }
        ["repo", "primary", db, repo_id] => {
            let pool = store::connect(Path::new(db)).await;
            done(
                async { Ok(work::set_primary_repo(&pool?, id(repo_id)?, by).await?) },
                repo_id,
            )
            .await
        }
        ["repo", "order", db, project, names @ ..] => {
            let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
            let pool = store::connect(Path::new(db)).await;
            let project_id = ProjectId(id(project).ok()?);
            let ordered = async { Ok(work::order_repos(&pool?, project_id, &names, by).await?) };
            done(ordered, project).await
        }
        ["issue", "repos", db, issue, names @ ..] => {
            let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
            issue_repos(Path::new(db), IssueId(id(issue).ok()?), &names).await
        }
        [
            "repo",
            verb @ ("approve" | "reject"),
            db,
            issue,
            name,
            rest @ ..,
        ] => {
            let f = flags(rest, &["--reason"])?;
            let pool = store::connect(Path::new(db)).await;
            let issue = IssueId(id(issue).ok()?);
            let reason = f.get("--reason").copied();
            let approve = *verb == "approve";
            let decided = async {
                work::decide_repo(&pool?, issue, name, approve, by, reason).await?;
                Ok(true)
            };
            done(decided, name).await
        }
        _ => return None,
    })
}

/// Prints `what` when `f` changed something; an error when it matched nothing.
async fn done(
    f: impl Future<Output = Result<bool, Box<dyn std::error::Error>>>,
    what: &str,
) -> Result_ {
    match f.await? {
        true => {
            println!("{what}");
            Ok(())
        }
        false => Err(format!("no such {what}").into()),
    }
}

/// A repo from the flags, over `base` when given.
fn repo(
    project: ProjectId,
    name: &str,
    url: &str,
    f: &std::collections::HashMap<&str, &str>,
    base: Option<Repo>,
) -> Option<Repo> {
    let mut r = base.unwrap_or(Repo {
        id: 0,
        project_id: project,
        name: name.to_owned(),
        url: url.to_owned(),
        default_branch: "main".to_owned(),
        position: 0,
        primary: false,
        forge: None,
        commands: Commands::default(),
    });
    let text = |k: &str, v: &mut String| {
        if let Some(x) = f.get(k) {
            *v = x.to_string();
        }
    };
    text("--branch", &mut r.default_branch);
    text("--build", &mut r.commands.build);
    text("--test", &mut r.commands.test);
    text("--lint", &mut r.commands.lint);
    text("--format", &mut r.commands.format);
    if let Some(kind) = f.get("--forge") {
        let kind: Kind = kind.parse().ok()?;
        r.forge = Some(ProjectForge {
            project_id: r.project_id,
            kind,
            api_url: f.get("--api").unwrap_or(&kind.default_api()).to_string(),
            repo: f.get("--forge-repo")?.to_string(),
            token_file: PathBuf::from(f.get("--token-file")?),
        });
    }
    Some(r)
}

async fn add(db: &Path, r: Repo) -> Result_ {
    let pool = store::connect(db).await?;
    let added = work::add_repo(&pool, &r, AuditActor::User(ADMIN))
        .await?
        .ok_or_else(|| format!("no project {}", r.project_id.0))?;
    eprintln!(
        "repo {} (id {}){}",
        added.name,
        added.id,
        if added.primary { ", primary" } else { "" }
    );
    println!("{}", added.id);
    Ok(())
}

async fn set(db: &Path, repo_id: i64, f: &std::collections::HashMap<&str, &str>) -> Result_ {
    let pool = store::connect(db).await?;
    let current = work::get_repo(&pool, repo_id)
        .await?
        .ok_or_else(|| format!("no repo {repo_id}"))?;
    let (project, name, url) = (
        current.project_id,
        current.name.clone(),
        current.url.clone(),
    );
    let r = repo(project, &name, &url, f, Some(current)).ok_or("bad --forge flags")?;
    work::update_repo(&pool, &r, AuditActor::User(ADMIN)).await?;
    println!("{repo_id}");
    Ok(())
}

async fn list(db: &Path, project: ProjectId) -> Result_ {
    let pool = store::connect(db).await?;
    for r in work::list_repos(&pool, project).await? {
        let forge = r.forge.as_ref().map_or("-".to_owned(), |f| {
            format!("{} {}", f.kind.as_str(), f.repo)
        });
        let primary = if r.primary { "\tprimary" } else { "" };
        println!(
            "{}\t{}\t{}\t{}\t{forge}{primary}",
            r.id, r.name, r.url, r.default_branch
        );
    }
    Ok(())
}

async fn issue_repos(db: &Path, issue: IssueId, names: &[String]) -> Result_ {
    let pool = store::connect(db).await?;
    let now = work::set_issue_repos(&pool, issue, names, AuditActor::User(ADMIN)).await?;
    let names: Vec<&str> = now.iter().map(|r| r.name.as_str()).collect();
    println!("{}", names.join(" "));
    Ok(())
}
