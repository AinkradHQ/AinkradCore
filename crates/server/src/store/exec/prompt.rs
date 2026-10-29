//! A run's prompt (protocol 1.22): its first turn, built here from the agent's role, the issue
//! and why the agent was woken. It names the agent's job on this wake and the done rule: a
//! run ends by changing the issue or asking the human, never with a summary alone (a run that
//! does not is caught at its end, `no_action`).
//!
//! One template (`render`), fed by one read (`run_prompt`). It stays short (`PROMPT_MAX`):
//! the issue, the project's profile, knowledge and skills reach the agent through
//! `get_issue`, `get_context` and its instructions, each under its own budget.

use ainkrad_core::exec::WakeSource;
use ainkrad_core::work::{IssueKind, IssueState};

use super::*;

/// The longest prompt `render` makes, in bytes.
pub const PROMPT_MAX: usize = 2048;
/// The most of the issue's title and of the wake's reason a prompt quotes, in chars.
const TITLE_MAX: usize = 160;
const REASON_MAX: usize = 400;

/// The agent's role on this run, by its org role, its team seats and its title.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Ceo,
    Cto,
    ProductOwner,
    TeamLead,
    Qa,
    DevOps,
    Developer,
}

impl Role {
    /// From the agent's org role, its team seats (`product_owner,member`, …) and its title.
    pub fn of(org_role: &str, seats: &str, title: &str) -> Self {
        let seat = |s: &str| seats.split(',').any(|x| x == s);
        match (org_role, title.to_lowercase().as_str()) {
            ("ceo", _) => Self::Ceo,
            ("cto", _) => Self::Cto,
            _ if seat("product_owner") => Self::ProductOwner,
            _ if seat("team_lead") => Self::TeamLead,
            (_, "qa") => Self::Qa,
            (_, "devops") => Self::DevOps,
            _ => Self::Developer,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Ceo => "CEO",
            Self::Cto => "CTO",
            Self::ProductOwner => "product owner",
            Self::TeamLead => "team lead",
            Self::Qa => "QA reviewer",
            Self::DevOps => "DevOps engineer",
            Self::Developer => "developer",
        }
    }
}

/// What the prompt is made from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub agent: String,
    pub role: Role,
    pub key: String,
    pub title: String,
    pub kind: IssueKind,
    pub state: IssueState,
    /// The issue is a request in the company's intake project.
    pub intake: bool,
    /// The issue carries a requirement (a kickoff or a planned task).
    pub requirement: bool,
    /// Why the agent was woken: the wake's source and reason; `None` without a wake.
    pub wake: Option<(WakeSource, String)>,
}

/// The run's prompt for these facts.
pub fn render(f: &Facts) -> String {
    let title = cut(&f.title, TITLE_MAX);
    let why = match &f.wake {
        Some((source, reason)) => {
            let reason = cut(reason, REASON_MAX);
            let what = match source {
                WakeSource::Assignment => "it was handed to you",
                WakeSource::Comment => "a new comment or answer on it",
                WakeSource::BlockerClosed => "a blocker of it closed, so it can move",
                WakeSource::Approval => "an approval on it was decided",
                WakeSource::Escalation => "it was escalated to you",
                WakeSource::Retry => "a retry: an earlier run on it did not finish",
                WakeSource::Timer => "a scheduled check or repair",
                WakeSource::Manual => "the admin woke you",
            };
            match reason.is_empty() {
                true => format!("{what}."),
                false => format!("{what} ({reason})."),
            }
        }
        None => "it waits on you.".to_owned(),
    };
    format!(
        "You are {agent}, the {role}, on {key} ({kind}, {state}): \"{title}\".\n\
         Why you were woken: {why}\n\
         Your job on this wake: {job}\n\
         {waits}Read the issue (get_issue) and your context (get_context) first.\n\
         Done rule: do the next action this issue needs from you with the citadel tools. Do \
         not end your turn until you have changed the issue (transition, route, plan, a \
         comment and hand-off, a PR, a verdict) or asked the human (ask_human). A summary \
         alone is not done: a run that ends without acting is woken again, then escalated.",
        agent = cut(&f.agent, 60),
        role = f.role.label(),
        key = f.key,
        kind = f.kind.as_str(),
        state = f.state.as_str(),
        job = job(f),
        waits = match f.role {
            Role::Developer | Role::DevOps | Role::Qa => WAITS,
            _ => "",
        },
    )
}

/// How the roles that run long jobs wait for them: a shell call times out after about 2
/// minutes, and every re-sent long wait is another approval for the human.
const WAITS: &str = "Long jobs (builds, test suites, the Definition of Done): run them in the \
                     background with output to a log file, then check back with short polls \
                     of at most 2 minutes each (sleep 60; tail the log), never one long \
                     blocking wait.\n";

/// The agent's job on this wake, by its role and the issue.
fn job(f: &Facts) -> &'static str {
    use Role as R;
    match f.role {
        R::Ceo | R::Cto if f.intake => {
            "this is an intake request: route it with route_intake. Read org_chart first; \
             when the request names or clearly concerns one of its projects, route to that \
             project ({project_id}); otherwise to a department as a new project."
        }
        R::Ceo | R::Cto => {
            "decide who owns this and hand it to that team's product owner or lead (comment \
             and transition), or ask_human when only a person can decide."
        }
        R::Qa => {
            "verify its PR against the Definition of Done in the project profile, then give \
             your verdict with qa_verdict (pass, or fail with notes)."
        }
        _ if f.state == IssueState::InReview => {
            "review it: transition it done when it passes, or comment what must change and \
             hand it back."
        }
        R::ProductOwner if f.requirement => {
            "plan the requirement: file the whole plan with apply_plan (or plan_requirement): \
             epics and tasks with estimates (points), assignees and repos, and submit it for \
             approval (submit: true). Once the plan is approved, plan and commit the sprint."
        }
        R::ProductOwner => {
            "groom it: give it a clear body, estimate, assignee and sprint, then hand it to \
             whoever works it next."
        }
        R::TeamLead => {
            "keep the work moving: assign and estimate its tasks (assign_issue, \
             estimate_issue), decide repo requests (decide_repo), review pending knowledge \
             (review_knowledge), then hand it on."
        }
        R::DevOps => {
            "do the environment or infrastructure work it asks for in your worktree, never \
             touching production unless the issue or the project profile allows it; run the \
             Definition of Done from the profile, open the PR (open_pr), then transition it \
             done. A change to .github/workflows needs a human to push it (workflow_push)."
        }
        R::Developer => {
            "implement it in your worktree and commit; run the Definition of Done from the \
             project profile, open the PR (open_pr), then transition it done. Do not change \
             .github/workflows unless the issue asks: such a push needs a human (workflow_push)."
        }
    }
}

/// `s` on one line, cut to `max` chars with an ellipsis.
pub(super) fn cut(s: &str, max: usize) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    match s.char_indices().nth(max) {
        Some((at, _)) => format!("{}…", &s[..at]),
        None => s,
    }
}

/// The prompt of `run`, `None` for a run with no issue (the runner's own prompt then).
pub async fn run_prompt(pool: &SqlitePool, run: RunId) -> Result<Option<String>, Error> {
    let Some(row) = sqlx::query(
        "SELECT a.name, a.org_role, a.role, (SELECT group_concat(team_role) FROM \
         team_memberships WHERE agent_id = a.id) AS seats, i.kind, i.state, i.title, \
         p.key || '-' || i.number AS key, p.intake, i.requirement_id IS NOT NULL AS req, \
         w.source, w.reason, (SELECT c.reason FROM wake_requests c WHERE c.coalesced_into = w.id \
         AND c.source = 'comment' ORDER BY c.id DESC LIMIT 1) AS comment \
         FROM runs r JOIN agents a ON a.id = r.agent_id \
         JOIN issues i ON i.id = r.issue_id JOIN projects p ON p.id = i.project_id \
         LEFT JOIN wake_requests w ON w.id = r.wake_request_id WHERE r.id = ?",
    )
    .bind(run.0)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };
    let seats: Option<String> = row.try_get("seats")?;
    let source: Option<String> = row.try_get("source")?;
    let reason: String = row
        .try_get::<Option<String>, _>("reason")?
        .unwrap_or_default();
    // A comment folded into another wake still reaches the run, first: it is the newest word.
    let reason = match row.try_get::<Option<String>, _>("comment")? {
        Some(c) => format!("{c}; {reason}"),
        None => reason,
    };
    let facts = Facts {
        agent: row.try_get("name")?,
        role: Role::of(
            row.try_get("org_role")?,
            seats.as_deref().unwrap_or(""),
            row.try_get("role")?,
        ),
        key: row.try_get("key")?,
        title: row.try_get("title")?,
        kind: text(&row, "kind")?,
        state: text(&row, "state")?,
        intake: row.try_get("intake")?,
        requirement: row.try_get("req")?,
        wake: match source {
            Some(s) => Some((
                s.parse()
                    .map_err(|_| Error::Decode(format!("bad wake source `{s}`").into()))?,
                reason,
            )),
            None => None,
        },
    };
    Ok(Some(render(&facts)))
}
