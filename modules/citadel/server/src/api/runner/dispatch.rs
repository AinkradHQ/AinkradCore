//! Dispatch on a runner connection: the next due run, as an `Assign`.

use citadel_core::settings::{Key, Scope};
use ainkrad_proto::runner::{
    Account, Policy, Route, RunLimits, ServerMessage, TokenCaps, Workspace,
};

use super::{Session, error};
use crate::store::exec::{
    dispatch_next, fallback_routes, get_runner, live_runs, resume_session, run_prompt,
    run_token_caps,
};
use citadel_core::exec::RunId;
use citadel_core::work::IssueId;
use sqlx::SqlitePool;

use crate::store::forge::pushed_head;
use crate::store::gov::{project_knowledge, run_account, skills_for_run};
use crate::store::org::get_agent;
use crate::store::work::{get_issue, issue_key, issue_policy, issue_repos, run_profile};

impl Session {
    /// Claims the next run for this runner, if one is due.
    pub(super) async fn dispatch(&mut self) -> Option<ServerMessage> {
        let pool = &self.app.pool;
        let now = self.now();
        // A runner revoked while connected is closed here, so its key's last socket goes too.
        match get_runner(pool, self.runner.id).await {
            Ok(None) => {
                self.closing = true;
                return Some(error("this runner was revoked".to_owned()));
            }
            // Drained by the admin: its runs finish, it takes no new one.
            Ok(Some(r)) if r.drained_at.is_some() => return None,
            _ => {}
        }
        let run = dispatch_next(
            pool,
            self.runner.id,
            &self.runner.tags,
            &self.harnesses,
            &now,
        );
        let run = match run.await {
            Ok(Some(run)) => run,
            Ok(None) => return None,
            Err(e) => {
                tracing::error!(error = %e, "dispatch failed");
                return None;
            }
        };
        self.wanted -= 1;
        let model = match (&run.model_used, get_agent(pool, run.agent_id).await) {
            (Some(model), _) => model.clone(),
            (None, Ok(Some(agent))) => agent.model,
            _ => String::new(),
        };
        // Without its fallbacks the run still works its first entry; a fallback is a bonus.
        let fallbacks = fallback_routes(pool, &run, &self.harnesses, &now)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(run = run.id.0, error = %e, "reading the run's fallbacks failed");
                vec![]
            });
        // A worktree per repo the issue touches (E15.16), each on its one branch; a repo on a
        // forge gets its branch pushed for a PR (E9.1).
        let repos = match run.issue_id {
            Some(issue) => match (
                issue_repos(pool, issue).await,
                crate::store::work::issue_branch(pool, issue).await,
            ) {
                (Ok(repos), Ok(Some(branch))) => {
                    let mut trees = Vec::with_capacity(repos.len());
                    for r in repos {
                        // The head its branch was last pushed at (1.28): the push leases on it.
                        let expected_head = pushed_head(pool, issue, r.id).await.unwrap_or_else(|e| {
                            tracing::error!(run = run.id.0, error = %e, "reading the branch's head failed");
                            None
                        });
                        trees.push(Workspace {
                            push: r.forge.is_some(),
                            repo: r.url,
                            base: r.default_branch,
                            branch: branch.clone(),
                            name: r.name,
                            also: vec![],
                            expected_head,
                        });
                    }
                    trees
                }
                (Ok(_), Ok(None)) => vec![],
                (Err(e), _) | (_, Err(e)) => {
                    // ponytail: the run is already claimed; it works in a scratch dir
                    // rather than being dropped. Fail it instead if that ever misleads.
                    tracing::error!(run = run.id.0, error = %e, "reading the issue's repos failed");
                    vec![]
                }
            },
            None => vec![],
        };
        let mut repos = repos.into_iter();
        let workspace = repos.next().map(|first| {
            Box::new(Workspace {
                also: repos.collect(),
                ..first
            })
        });
        let policy = match run.issue_id {
            Some(issue) => run_policy(pool, issue, &now).await.unwrap_or_else(|e| {
                tracing::error!(run = run.id.0, error = %e, "reading the policy failed; it asks");
                Default::default()
            }),
            None => Default::default(),
        };
        self.policies_sent.insert(run.id.0, policy.clone());
        // The run's settings (E15.17): its project's (else its company's), and this runner's.
        let at = crate::store::settings::scope_of_run(pool, run.id)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(run = run.id.0, error = %e, "reading the run's scope failed");
                Scope::Server
            });
        let default = self.setting(Key::RunTokenCap, at).await as u64;
        let divisor = self.setting(Key::RunCacheWeightDivisor, at).await as u64;
        let mine = Scope::Runner(self.runner.id);
        let limits = RunLimits {
            approval_timeout_secs: self.setting(Key::DeadlinePermissionEscalation, at).await as u64,
            max_resumes: self.setting(Key::MaxResumes, mine).await as u32,
            resume_backoff_ms: self.setting(Key::ResumeBackoffMs, mine).await as u64,
            resume_backoff_max_ms: self.setting(Key::ResumeBackoffMaxMs, mine).await as u64,
            warm_max: self.setting(Key::WarmMax, mine).await as u32,
            stall_after_secs: self.setting(Key::StallAfterSecs, at).await as u64,
            tool_output_bytes: self.setting(Key::ToolOutputBytes, at).await as u64,
            fallback_on_model_unavailable: self.setting(Key::FallbackOnModelUnavailable, at).await
                == 1,
            fallback_on_rate_limited: self.setting(Key::FallbackOnRateLimited, at).await == 1,
            fallback_on_quota: self.setting(Key::FallbackOnQuota, at).await == 1,
            fallback_on_unhealthy: self.setting(Key::FallbackOnUnhealthy, at).await == 1,
        };
        let caps = match run_token_caps(pool, &run, default, divisor, &now).await {
            Ok(caps) => caps,
            Err(e) => {
                tracing::error!(run = run.id.0, error = %e, "computing the token caps failed");
                TokenCaps {
                    exact: None,
                    run: default,
                    cache_weight_divisor: 1,
                }
            }
        };
        let issue_key = match run.issue_id {
            Some(issue) => issue_key(pool, issue).await.unwrap_or_else(|e| {
                tracing::error!(run = run.id.0, error = %e, "reading the issue's key failed");
                None
            }),
            None => None,
        };
        let instructions = instructions(pool, run.id, run.issue_id).await;
        // Without its prompt the run still starts, on the runner's own short one.
        let prompt = run_prompt(pool, run.id).await.unwrap_or_else(|e| {
            tracing::error!(run = run.id.0, error = %e, "building the run's prompt failed");
            None
        });
        // Unlike the repo above, an unreadable account is never guessed (another login would
        // bill the wrong account): no `Assign`, so the lease lapses and the run is retried.
        let account = match run_account(pool, run.id).await {
            Ok(account) => account,
            Err(e) => {
                tracing::error!(run = run.id.0, error = %e, "reading the run's account failed");
                return None;
            }
        };
        // A fresh session unless the settings allow continuing an unfinished one (E15.5).
        let resume_session = resume_session(pool, &run).await.unwrap_or_else(|e| {
            tracing::error!(run = run.id.0, error = %e, "reading the session to resume failed");
            None
        });
        tracing::info!(
            runner = self.runner.id.0,
            run = run.id.0,
            tier = run.tier.map(|t| t.as_str()),
            caps = ?caps,
            account = account.as_ref().map(|a| a.label.as_str()),
            "run assigned"
        );
        Some(ServerMessage::Assign {
            run: run.id.0,
            agent: run.agent_id.0,
            issue: run.issue_id.map(|i| i.0),
            harness: run.harness.as_str().to_owned(),
            model,
            context_ref: format!("citadel://runs/{}/context", run.id.0),
            workspace,
            token_cap: Some(caps.least()),
            token_caps: Some(Box::new(caps)),
            policy,
            issue_key,
            instructions: instructions.map(Box::new),
            account: account.map(|a| Box::new(wire(a))),
            fallbacks: fallbacks
                .into_iter()
                .map(|(r, a)| Route {
                    harness: r.harness.as_str().to_owned(),
                    model: r.model,
                    account: a.map(wire),
                })
                .collect(),
            limits: Some(Box::new(limits)),
            resume_session: resume_session.map(Box::new),
            prompt: prompt.map(Box::new),
        })
    }
}

impl Session {
    /// A `PolicyUpdate` (1.24) for each of this runner's live runs whose policy changed since
    /// it was last sent: the admin set its project's, or its issue's rules changed. After a
    /// reconnect each live run gets its policy once. Nothing for an older runner.
    pub(super) async fn policy_updates(&mut self) -> Vec<ServerMessage> {
        if !self.speaks_1_24 {
            return vec![];
        }
        let pool = &self.app.pool;
        let live = match live_runs(pool, self.runner.id).await {
            Ok(live) => live,
            Err(e) => {
                tracing::error!(error = %e, "reading the runner's live runs failed");
                return vec![];
            }
        };
        let sent = &mut self.policies_sent;
        sent.retain(|run, _| live.iter().any(|(id, _)| id == run));
        let now = self.app.clock.now();
        let mut out = vec![];
        // A run without an issue keeps the default policy its `Assign` carried.
        for (run, issue) in live.into_iter().filter_map(|(r, i)| Some((r, i?))) {
            // An unreadable policy is tried again on the next tick.
            let Ok(policy) = run_policy(pool, IssueId(issue), &now).await else {
                continue;
            };
            if sent.get(&run) != Some(&policy) {
                sent.insert(run, policy.clone());
                out.push(ServerMessage::PolicyUpdate { run, policy });
            }
        }
        out
    }
}

/// The policy of a run on `issue`: its project's, with the issue's live "allow for this issue"
/// rules (decision #34) joining the allowlist.
async fn run_policy(pool: &SqlitePool, issue: IssueId, now: &str) -> Result<Policy, sqlx::Error> {
    let mut policy = issue_policy(pool, issue).await?;
    policy
        .allow
        .extend(crate::store::gov::issue_allow_rules(pool, issue, now).await?);
    Ok(policy)
}

/// An account as the runner gets it: by reference only.
fn wire(a: citadel_core::gov::Account) -> Account {
    Account {
        id: a.id.0,
        label: a.label,
        config_dir: a.config_dir,
        credential_ref: a.credential_ref,
        credential_env: a.credential_env,
    }
}

/// The run's instructions: its skills, then its project's profile (E15.13), then its knowledge
/// (E8.1), as markdown; `None` when it has none of them.
// ponytail: a run whose skills, profile or knowledge cannot be read starts without them; the
// agent still reaches them through `get_context`.
pub(super) async fn instructions(
    pool: &SqlitePool,
    run: RunId,
    issue: Option<IssueId>,
) -> Option<String> {
    let skills = match skills_for_run(pool, run).await {
        Ok(skills) => skills.render(),
        Err(e) => {
            tracing::error!(run = run.0, error = %e, "reading the run's skills failed");
            None
        }
    };
    let project = match issue {
        Some(issue) => get_issue(pool, issue)
            .await
            .ok()
            .flatten()
            .map(|i| i.project_id),
        None => None,
    };
    let profile = match project {
        Some(project) => match run_profile(pool, project).await {
            Ok((p, _)) => p.text,
            Err(e) => {
                tracing::error!(run = run.0, error = %e, "reading the project's profile failed");
                None
            }
        },
        None => None,
    };
    let knowledge = match project {
        Some(project) => match project_knowledge(pool, project).await {
            Ok(k) => k.render(),
            Err(e) => {
                tracing::error!(run = run.0, error = %e, "reading the project's knowledge failed");
                None
            }
        },
        None => None,
    };
    let parts: Vec<String> = [skills, profile, knowledge].into_iter().flatten().collect();
    (!parts.is_empty()).then(|| parts.concat())
}
