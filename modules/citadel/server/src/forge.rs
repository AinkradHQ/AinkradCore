//! The forge poller (E9.1): every `every`, one pass (`sync`) over the PRs with work
//! (`store::forge::due_prs`), then the Linear sync (E9.4, `crate::linear`). A pass opens the
//! PRs requested whose run has ended (its branch pushed), follows those open (head, checks,
//! merged or closed elsewhere), and merges those approved (E9.3: a merge commit at the head QA
//! passed). A PR whose branch is not on the forge yet waits for the issue's next run to push
//! it (`pr_unpushed`), or, when its push was refused for good, for anyone to push it
//! (`push_held`, #103: checked every pass, quietly). What it sees is recorded by `store::forge` (row, issue comment, audit).
//! The API token is read from the project's token file on each pass, so rotating it needs no
//! restart; it is never logged.
//!
//! ponytail: polling, one request to five per PR per pass. A webhook endpoint (HMAC-verified)
//! is the upgrade when there are many PRs or the rate limit bites.

use std::collections::HashSet;
use std::future::Future;
use std::time::Duration;

use citadel_core::work::{IssueId, ProjectId};
use ainkrad_providers::{AnyForge, Client, Error, Forge, NewPr, PrState, Secret};
use sqlx::SqlitePool;

use crate::scheduler::{Clock, SystemClock};
use crate::store::forge::{
    PrPhase, due_prs, issue_title, pr_branch_deleted, pr_finished, pr_followed, pr_merge_refused,
    pr_merged, pr_opened, pr_refused, pr_unpushed,
};
use crate::store::work::project_profile;

/// Branches never deleted after a merge, whatever the profile protects.
const DEFAULT_PROTECTED: [&str; 3] = ["main", "development", "staging"];

pub struct Poller {
    pub pool: SqlitePool,
    pub client: Client,
    pub every: Duration,
}

impl Poller {
    /// Polls at once, then every `every`, until `shutdown`; a failed pass is logged and the
    /// next one retries (every step is idempotent).
    pub async fn run(&self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        let mut every = tokio::time::interval(self.every);
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => return,
                _ = every.tick() => {
                    if let Err(e) = sync(&self.pool, &self.client).await {
                        tracing::error!(error = %e, "forge poll failed");
                    }
                    if let Err(e) = crate::linear::sync(&self.pool, &self.client).await {
                        tracing::error!(error = %e, "Linear sync failed");
                    }
                }
            }
        }
    }
}

/// Reads open PR `n` (`at`: its issue and repo) and records what changed.
async fn follow(
    pool: &SqlitePool,
    forge: &AnyForge,
    at: (IssueId, i64),
    n: u64,
) -> Result<(), sqlx::Error> {
    match forge.pr_status(n).await {
        Ok(s) => match s.pr.state {
            PrState::Merged => pr_finished(pool, at, true).await,
            PrState::Closed => pr_finished(pool, at, false).await,
            PrState::Open => {
                let checks = (s.checks, s.failed.as_slice());
                pr_followed(pool, at, &s.pr.head_sha, checks, s.note.as_deref()).await
            }
        },
        Err(e) => pr_refused(pool, at, &e.to_string()).await,
    }
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
pub async fn sync(pool: &SqlitePool, client: &Client) -> Result<(), sqlx::Error> {
    let mut held: HashSet<IssueId> = HashSet::new();
    for (pr, f) in due_prs(pool).await? {
        let at = (pr.issue_id, pr.repo_id);
        if pr.phase == PrPhase::Merging && !held.insert(pr.issue_id) {
            continue;
        }
        let token = match Secret::from_file(&f.token_file) {
            Ok(token) => token,
            Err(why) => {
                pr_refused(pool, at, &why).await?;
                continue;
            }
        };
        let forge = AnyForge::new(client, f.kind, &f.api_url, &f.repo, token);
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
                        follow(pool, &forge, at, p.number).await?;
                    }
                    // Held (#103): its push was refused, a human pushes it; quiet until then.
                    // ponytail: one refused open per pass while held; a branch check first
                    // (`branches/{head}`) if the rate limit ever bites.
                    Err(Error::MissingBranch(_)) if pr.push_held.is_some() => {}
                    Err(e @ Error::MissingBranch(_)) => {
                        pr_unpushed(pool, at, &e.to_string()).await?
                    }
                    Err(e) => pr_refused(pool, at, &e.to_string()).await?,
                }
            }
            (PrPhase::Open, Some(n)) => follow(pool, &forge, at, n).await?,
            (PrPhase::Merging, Some(n)) => {
                let sha = pr.head_sha.clone().unwrap_or_default();
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
                        let now = SystemClock.now();
                        pr_merge_refused(pool, at, &e.to_string(), &now).await?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}
