//! The forge poller (E9.1): one pass over the PRs with work (`store::forge::due_prs`). A pass
//! opens the PRs requested whose branch is pushed, follows those open (head, checks, merged or
//! closed elsewhere), and merges those approved (E9.3: a merge commit at the head the approval
//! named). A PR whose branch is not on the forge yet waits for the next confirmed push
//! (`pr_unpushed`), or, when its push was refused for good (`push_held`, #103), for anyone to
//! push it (checked every pass, quietly). What it sees is recorded by `store::forge`.
//!
//! ponytail: polling, one to five requests per PR per pass; a webhook needs a route outside the
//! client gate, which the Core does not offer a module.

use std::collections::HashSet;
use std::sync::Arc;

use ainkrad_providers::{AnyForge, Error, Forge, Kind, NewPr, PrState};
use sqlx::SqlitePool;

use super::{MAX_PRS_PER_PASS, Runtime};
use crate::domain::work::{IssueId, ProjectId};
use crate::store::forge::{
    PrPhase, due_prs, issue_title, pr_branch_deleted, pr_finished, pr_followed, pr_merge_refused,
    pr_merged, pr_opened, pr_refused, pr_unpushed,
};
use crate::store::work::project_profile;

/// Branches never deleted after a merge, whatever the profile protects.
const DEFAULT_PROTECTED: [&str; 3] = ["main", "development", "staging"];

fn now() -> String {
    ainkrad_core_server::scheduler::Clock::now(&ainkrad_core_server::scheduler::SystemClock)
}

/// Reads open PR `n` (`at`: its issue and repo) and records what changed.
async fn follow(
    pool: &SqlitePool,
    forge: &AnyForge,
    at: (IssueId, i64),
    n: u64,
) -> Result<Result<(), Error>, sqlx::Error> {
    Ok(match forge.pr_status(n).await {
        Ok(s) => {
            match s.pr.state {
                PrState::Merged => pr_finished(pool, at, true).await?,
                PrState::Closed => pr_finished(pool, at, false).await?,
                PrState::Open => {
                    let checks = (s.checks, s.failed.as_slice());
                    pr_followed(pool, at, &s.pr.head_sha, checks, s.note.as_deref()).await?;
                }
            }
            Ok(())
        }
        Err(e) => {
            pr_refused(pool, at, &e.to_string()).await?;
            Err(e)
        }
    })
}

/// Deletes `head`, the head branch of the PR just merged on `forge`, unless it is protected: the
/// project's profile protects it, or it is a default branch. Either way it is audited, and the
/// merge stands.
async fn delete_head(
    pool: &SqlitePool,
    forge: &AnyForge,
    (project, at): (ProjectId, (IssueId, i64)),
    head: &str,
) -> Result<(), sqlx::Error> {
    let protected = match project_profile(pool, project).await {
        Ok(p) => p.map(|p| p.profile.protected_branches).unwrap_or_default(),
        Err(e) => {
            let why = format!("profile unreadable: {e}");
            return pr_branch_deleted(pool, at, head, Err(why)).await;
        }
    };
    if DEFAULT_PROTECTED.contains(&head) || protected.iter().any(|b| b == head) {
        return pr_branch_deleted(pool, at, head, Err("protected".to_owned())).await;
    }
    let outcome = forge.delete_branch(head).await.map_err(|e| e.to_string());
    pr_branch_deleted(pool, at, head, outcome).await
}

/// One pass over the PRs with work. An issue's approved PRs merge in its project's repo order
/// (E15.16, #54): one waits while an earlier one of its issue is still merging or failed.
pub async fn sync(rt: &Arc<Runtime>) -> Result<(), sqlx::Error> {
    let pool = &rt.pool;
    let mut due = due_prs(pool).await?;
    if due.is_empty() {
        return Ok(());
    }
    // ponytail: the first PRs by issue order; the rest wait for the next pass.
    due.truncate(MAX_PRS_PER_PASS);
    let mut pass = rt.pass().await?;
    let mut held: HashSet<IssueId> = HashSet::new();
    for (pr, f) in due {
        let at = (pr.issue_id, pr.repo_id);
        if pr.phase == PrPhase::Merging && !held.insert(pr.issue_id) {
            continue;
        }
        // A refused URL or a resting host is quiet (the next pass tries again); a refused URL is
        // said once on the PR (`pr_refused` repeats nothing).
        let host = match pass.host(&f.api_url) {
            Ok(host) => host,
            Err(why) if why.ends_with("resting") => continue,
            Err(why) => {
                pr_refused(pool, at, &why).await?;
                continue;
            }
        };
        let Ok(kind) = f.kind.parse::<Kind>() else {
            pr_refused(pool, at, "unknown forge kind").await?;
            continue;
        };
        let token = match pass.token(&f.secret, "forge poll").await {
            Ok(token) => token,
            Err(why) => {
                pr_refused(pool, at, &why).await?;
                continue;
            }
        };
        let forge = AnyForge::new(&pass.client, kind, &f.api_url, &f.repo, token);
        match (pr.phase, pr.number) {
            (PrPhase::Requested, _) => {
                let new = NewPr {
                    head: pr.head.clone(),
                    base: pr.base.clone(),
                    title: pr.title.clone(),
                    body: pr.body.clone(),
                };
                match forge.open_pr(&new).await {
                    Ok(p) => {
                        pr_opened(pool, at, p.number, &p.url, &p.head_sha).await?;
                        if let Err(e) = follow(pool, &forge, at, p.number).await? {
                            pass.failed(&host, &e);
                        }
                    }
                    // Held (#103): its push was refused, a human pushes it; quiet until then.
                    // ponytail: one refused open per pass while held; a branch check first
                    // (`branches/{head}`) if the rate limit ever bites.
                    Err(Error::MissingBranch(_)) if pr.push_held.is_some() => {}
                    Err(e @ Error::MissingBranch(_)) => {
                        pr_unpushed(pool, at, &e.to_string()).await?;
                    }
                    Err(e) => {
                        pass.failed(&host, &e);
                        pr_refused(pool, at, &e.to_string()).await?;
                    }
                }
            }
            (PrPhase::Open, Some(n)) => {
                if let Err(e) = follow(pool, &forge, at, n).await? {
                    pass.failed(&host, &e);
                }
            }
            (PrPhase::Merging, Some(n)) => {
                // The approval named this head; with none on record nothing is bound, so
                // nothing merges.
                let sha = pr.head_sha.clone().unwrap_or_default();
                if sha.is_empty() {
                    let why = "no head to bind the merge to; nothing was merged";
                    pr_merge_refused(pool, at, why, &now()).await?;
                    continue;
                }
                // The merge commit's title, from the profile's template: `Merge <head>: <title>`.
                let title = format!(
                    "Merge {}: {}",
                    pr.head,
                    issue_title(pool, pr.issue_id).await?
                );
                match forge.merge(n, &sha, &title).await {
                    // The next one of its issue may go.
                    Ok(()) => {
                        pr_merged(pool, at).await?;
                        held.remove(&pr.issue_id);
                        delete_head(pool, &forge, (f.project_id, at), &pr.head).await?;
                    }
                    Err(e) => {
                        pass.failed(&host, &e);
                        pr_merge_refused(pool, at, &e.to_string(), &now()).await?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
