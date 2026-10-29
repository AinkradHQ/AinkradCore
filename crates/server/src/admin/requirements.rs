//! Requirements (E15.10): what was asked for, and its plan, live.

use std::path::Path;

use ainkrad_core::org::CompanyId;
use ainkrad_core::work::{Actor, QuestionId, RequirementId, UserId};
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{self, gov, work};
use serde_json::{Value, json};

use super::id;
use crate::Result_;

pub const USAGE: &str = "  ainkrad-core-server requirement list <db> [<company-id>]
  ainkrad-core-server requirement show <db> <requirement-id>
  ainkrad-core-server requirement tree <db> <requirement-id>
  ainkrad-core-server requirement thread <db> <requirement-id>
  ainkrad-core-server requirement post <db> <requirement-id> <body> [--question <id> | --to-owner]
list prints one line per requirement, newest first: id, key, state, plan version, owner agent,
title. show prints it as JSON; tree prints its plan as JSON: epics and tasks (state, assignee,
points, time, tokens), % done by points, burndown, ETA, spend, and the diff since the approved
plan. thread prints its thread (messages, agent questions, approvals), one JSON item per line,
oldest first, with artifact cards (E15.12). post writes in it as the admin: it answers the newest open question (or the one
named), which wakes the agent that asked; --to-owner sends it to the owner instead (E15.11).";

/// Runs a requirement command; `None` when `args` is not one.
pub async fn run(args: &[&str]) -> Option<Result_> {
    Some(match args {
        ["requirement", "list", db, rest @ ..] => {
            let company = match rest {
                [] => None,
                [c] => Some(CompanyId(id(c).ok()?)),
                _ => return None,
            };
            list(Path::new(db), company).await
        }
        ["requirement", "show", db, r] => show(Path::new(db), RequirementId(id(r).ok()?)).await,
        ["requirement", "tree", db, r] => tree(Path::new(db), RequirementId(id(r).ok()?)).await,
        ["requirement", "thread", db, r] => thread(Path::new(db), RequirementId(id(r).ok()?)).await,
        ["requirement", "post", db, r, body, rest @ ..] => {
            let to = match rest {
                [] => work::To::Auto,
                ["--to-owner"] => work::To::Owner,
                ["--question", q] => work::To::Question(QuestionId(id(q).ok()?)),
                _ => return None,
            };
            post(Path::new(db), RequirementId(id(r).ok()?), body, to).await
        }
        _ => return None,
    })
}

fn requirement_json(r: &work::Requirement) -> Value {
    json!({"id": r.id.0, "key": r.key(), "company_id": r.company_id.0, "title": r.title,
           "body": r.body, "state": r.state.as_str(), "plan_version": r.plan_version,
           "owner_agent_id": r.owner_agent_id.map(|a| a.0),
           "intake_issue_id": r.intake_issue_id.map(|i| i.0), "created_at": r.created_at})
}

async fn list(db: &Path, company: Option<CompanyId>) -> Result_ {
    let pool = store::connect(db).await?;
    for r in work::list_requirements(&pool, company).await? {
        let owner = r.owner_agent_id.map_or("-".to_owned(), |a| a.0.to_string());
        println!(
            "{}\t{}\t{}\tv{}\t{owner}\t{}",
            r.id.0,
            r.key(),
            r.state.as_str(),
            r.plan_version,
            r.title
        );
    }
    Ok(())
}

async fn show(db: &Path, id: RequirementId) -> Result_ {
    let pool = store::connect(db).await?;
    let r = work::get_requirement(&pool, id)
        .await?
        .ok_or_else(|| format!("no requirement {}", id.0))?;
    println!("{}", requirement_json(&r));
    Ok(())
}

fn task_json(t: &work::TreeTask) -> Value {
    let assignee = match t.assignee {
        Some(Actor::Agent(a)) => json!({"agent": a.0}),
        Some(Actor::Human(u)) => json!({"user": u.0}),
        None => Value::Null,
    };
    json!({"issue_id": t.id.0, "key": t.key, "title": t.title, "state": t.state.as_str(),
           "assignee": assignee, "points": t.points, "time_secs": t.time_secs,
           "tokens": t.tokens, "prs": t.prs})
}

async fn tree(db: &Path, id: RequirementId) -> Result_ {
    let pool = store::connect(db).await?;
    let t = work::requirement_tree(&pool, id, &SystemClock.now())
        .await?
        .ok_or_else(|| format!("no requirement {}", id.0))?;
    let epics: Vec<Value> = t
        .epics
        .iter()
        .map(|e| {
            json!({"epic_id": e.id.0, "title": e.title, "points": e.points,
                   "done_points": e.done_points,
                   "tasks": e.tasks.iter().map(task_json).collect::<Vec<_>>()})
        })
        .collect();
    let refs = |v: &[work::PlannedTaskRef]| -> Vec<Value> {
        v.iter()
            .map(|t| json!({"issue_id": t.id, "key": t.key, "points": t.points}))
            .collect()
    };
    let diff = t.diff.as_ref().map(|d| {
        json!({"version": d.version, "added": refs(&d.added), "removed": refs(&d.removed),
               "points_approved": d.points_approved, "points_now": d.points_now})
    });
    let burndown: Vec<Value> = t
        .burndown
        .iter()
        .map(|(day, left, scope)| json!({"day": day, "left": left, "scope": scope}))
        .collect();
    let out = json!({"requirement": requirement_json(&t.requirement), "epics": epics,
        "other": t.other.iter().map(task_json).collect::<Vec<_>>(), "points": t.points,
        "done_points": t.done_points, "percent_done": t.percent_done, "tasks": t.tasks,
        "done_tasks": t.done_tasks, "burndown": burndown, "points_per_day": t.points_per_day,
        "eta": t.eta, "cost": gov::cost_json(&t.cost), "diff": diff});
    println!("{out}");
    Ok(())
}

fn question_json(q: &work::Question) -> Value {
    json!({"id": q.id.0, "issue_id": q.issue_id.0, "asked_by_agent_id": q.agent_id.0,
           "question": q.question, "options": q.options, "state": q.state.as_str(),
           "answer": q.answer, "answered_in": q.answered_in})
}

async fn thread(db: &Path, id: RequirementId) -> Result_ {
    let pool = store::connect(db).await?;
    let items = work::requirement_thread(&pool, id)
        .await?
        .ok_or_else(|| format!("no requirement {}", id.0))?;
    for item in items {
        let line = match item {
            work::ThreadItem::Message { comment, at } => {
                let author = match comment.author {
                    Actor::Agent(a) => json!({"agent": a.0}),
                    Actor::Human(u) => json!({"user": u.0}),
                };
                json!({"kind": "message", "at": at, "author": author, "body": comment.body})
            }
            work::ThreadItem::Question {
                question,
                issue_key,
            } => {
                let mut q = question_json(&question);
                q["issue_key"] = issue_key.into();
                json!({"kind": "question", "at": question.created_at, "question": q})
            }
            work::ThreadItem::Approval { approval, at } => {
                json!({"kind": "approval", "at": at, "approval_id": approval.id.0,
                       "approval_kind": approval.kind.as_str(),
                       "status": approval.status.as_str()})
            }
            work::ThreadItem::Artifact { artifact: a } => {
                json!({"kind": "artifact", "at": a.created_at, "artifact_id": a.id.0,
                       "name": a.name, "mime": a.mime, "size": a.size,
                       "issue_id": a.issue_id.map(|i| i.0), "agent_id": a.agent_id.map(|g| g.0)})
            }
        };
        println!("{line}");
    }
    Ok(())
}

async fn post(db: &Path, id: RequirementId, body: &str, to: work::To) -> Result_ {
    let pool = store::connect(db).await?;
    let out = match work::post_to_requirement(&pool, id, UserId(1), body, to).await {
        Ok(work::Posted::Answered(q)) => {
            json!({"answered": question_json(&q), "woke_agent_id": q.agent_id.0})
        }
        Ok(work::Posted::ToOwner(c, woke)) => {
            json!({"comment_id": c.0, "woke_agent_id": woke.map(|(a, _)| a.0)})
        }
        Err(e) => return Err(e.to_string().into()),
    };
    println!("{out}");
    Ok(())
}
