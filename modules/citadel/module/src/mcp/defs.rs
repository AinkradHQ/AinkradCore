//! Every tool's definition: its name, what it does and its input schema, as `tools/list` serves
//! them. One entry per name of `tools::TOOLS`; a test keeps the two lists equal.

use std::sync::Arc;

use rmcp::model::Tool;
use serde_json::{Value, json};

/// `spec`, then `profile.<field>` for every profile field.
fn profile_targets() -> Vec<String> {
    let fields = crate::profile::FIELDS
        .iter()
        .map(|f| format!("profile.{f}"));
    std::iter::once("spec".to_owned()).chain(fields).collect()
}

/// A task of `plan_requirement`, under an existing epic when `epic`.
fn plan_task(epic: bool) -> Value {
    let mut properties = json!({"title": {"type": "string"}, "body": {"type": "string"},
        "points": {"type": "integer", "minimum": 0, "maximum": 1000},
        "assignee_agent_id": {"type": "integer"}});
    let mut required = vec!["title"];
    if epic {
        properties["epic_id"] = json!({"type": "integer"});
        required.push("epic_id");
    }
    json!({"type": "object", "properties": properties, "required": required})
}

/// A task of `apply_plan`.
fn apply_task() -> Value {
    json!({"type": "object", "properties": {"title": {"type": "string"},
        "body": {"type": "string"},
        "points": {"type": "integer", "minimum": 0, "maximum": 1000},
        "assignee_agent_id": {"type": "integer"},
        "repos": {"type": "array", "items": {"type": "string"}},
        "sprint": {"type": "boolean"}}, "required": ["title"]})
}

pub(super) fn list() -> Vec<Tool> {
    let issue = json!({"type": "integer",
        "description": "Your run's issue (the default) or one of its subtasks."});
    let person = |what: &str| json!({"type": "integer", "description": what});
    let tools = [
        (
            "get_issue",
            "Read your issue (or a subtask): its fields, its newest comments, its blockers and \
             subtasks. Older comments: comments_before (older_comments_before); forward from a \
             comment you saw: comments_after.",
            json!({"issue_id": issue, "comments_after": {"type": "integer"},
                   "comments_before": {"type": "integer"},
                   "limit": {"type": "integer", "minimum": 1, "maximum": 50}}),
            vec![],
        ),
        (
            "get_context",
            "Read your project (with its spec) and its profile.",
            json!({}),
            vec![],
        ),
        (
            "comment",
            "Write a comment on your issue (or a subtask). idempotency_key makes a retry safe.",
            json!({"issue_id": issue, "body": {"type": "string"},
                   "idempotency_key": {"type": "string"}}),
            vec!["body"],
        ),
        (
            "transition",
            "Move your issue while you are its next actor: start, submit_for_review (with \
             reviewer_agent_id or reviewer_user_id), block (optionally blocker_issue_id) or done.",
            json!({"issue_id": issue,
                   "transition": {"type": "string",
                       "enum": ["start", "submit_for_review", "block", "done"]},
                   "reviewer_agent_id": person("An agent of your company."),
                   "reviewer_user_id": person("A user."),
                   "blocker_issue_id": person("An issue of your company that blocks this one.")}),
            vec!["transition"],
        ),
        (
            "create_subtask",
            "Split off a subtask of your issue, owned by you.",
            json!({"title": {"type": "string"}, "body": {"type": "string"}}),
            vec!["title"],
        ),
        (
            "report_blocker",
            "Link an existing issue of your company (blocker_issue_id), or a new task (title, \
             optional body and assignee_agent_id or assignee_user_id), as a blocker of your issue.",
            json!({"issue_id": issue, "blocker_issue_id": {"type": "integer"},
                   "title": {"type": "string"}, "body": {"type": "string"},
                   "assignee_agent_id": person("An agent of your company."),
                   "assignee_user_id": person("A user.")}),
            vec![],
        ),
        (
            "request_approval",
            "Ask a human to approve something about your issue. You are woken with the decision; \
             get_approval reads it. You cannot decide it.",
            json!({"issue_id": issue,
                   "kind": {"type": "string",
                       "enum": ["pr_merge", "permission_escalation", "budget_overrun"]},
                   "summary": {"type": "string"}, "details": {"type": "string"}}),
            vec!["kind", "summary"],
        ),
        (
            "get_approval",
            "Read an approval you asked for: its status, the decider's reply and its deadline.",
            json!({"approval_id": {"type": "integer"}}),
            vec!["approval_id"],
        ),
        (
            "list_backlog",
            "Read a page of a project's backlog (default: your issue's project), by rank. Only \
             for its product owner or team lead, or the CEO or CTO. Filter by epic_id, \
             label_id, kind, state, assignee_agent_id or assignee_user_id; page with offset \
             (next_offset) and limit.",
            json!({"project_id": {"type": "integer"}, "epic_id": {"type": "integer"},
                   "label_id": {"type": "integer"},
                   "kind": {"type": "string", "enum": ["story", "task", "bug"]},
                   "state": {"type": "string", "enum":
                       ["backlog", "todo", "in_progress", "in_review", "blocked"]},
                   "assignee_agent_id": {"type": "integer"},
                   "assignee_user_id": {"type": "integer"},
                   "offset": {"type": "integer", "minimum": 0},
                   "limit": {"type": "integer", "minimum": 1, "maximum": 200}}),
            vec![],
        ),
        (
            "propose_knowledge",
            "Propose a knowledge entry for your project; its team lead or a human accepts or \
             rejects it, and accepted entries reach every later run. A state entry with target \
             spec proposes a new project spec (the whole body); accepting it replaces the spec. \
             Target profile.<field> proposes a new value (the body: JSON, or plain text for a \
             text field) of a project profile field (get_context shows the profile); a human \
             decides it, and it is never applied before. Rationale: why, in one line.",
            json!({"kind": {"type": "string",
                       "enum": ["decision", "landmine", "state", "retro"]},
                   "title": {"type": "string"}, "body": {"type": "string"},
                   "target": {"type": "string", "enum": profile_targets()},
                   "rationale": {"type": "string"}}),
            vec!["kind", "title", "body"],
        ),
        (
            "plan_sprint",
            "Plan a sprint of a project you plan (default: your issue's project): a name, \
             a goal and its dates (YYYY-MM-DD). It starts planned; fill it with \
             sprint_add_issue.",
            json!({"project_id": {"type": "integer"}, "name": {"type": "string"},
                   "goal": {"type": "string"}, "starts_on": {"type": "string"},
                   "ends_on": {"type": "string"}}),
            vec!["name", "starts_on", "ends_on"],
        ),
        (
            "sprint_add_issue",
            "Add an open top-level issue to a planned sprint of its project.",
            json!({"sprint_id": {"type": "integer"}, "issue_id": {"type": "integer"}}),
            vec!["sprint_id", "issue_id"],
        ),
        (
            "sprint_remove_issue",
            "Take an issue out of its planned sprint, back to the backlog.",
            json!({"issue_id": {"type": "integer"}}),
            vec!["issue_id"],
        ),
        (
            "set_sprint_issues",
            "Make a planned sprint hold exactly these issues in one call: the listed ones join, \
             any other issue of the sprint goes back to the backlog. All or nothing.",
            json!({"sprint_id": {"type": "integer"},
                   "issue_ids": {"type": "array", "maxItems": 200, "items": {"type": "integer"}}}),
            vec!["sprint_id", "issue_ids"],
        ),
        (
            "estimate_issue",
            "Set an issue's story points (omit points to clear them).",
            json!({"issue_id": {"type": "integer"},
                   "points": {"type": "integer", "minimum": 0, "maximum": 1000}}),
            vec!["issue_id"],
        ),
        (
            "propose_retro_items",
            "Propose what a closed sprint taught as knowledge entries of its project: \
             decisions, landmines or retro notes. They stay proposed until a human accepts \
             them.",
            json!({"sprint_id": {"type": "integer"}, "items": {"type": "array",
                   "minItems": 1, "maxItems": 20, "items": {"type": "object",
                       "properties": {"kind": {"type": "string",
                                               "enum": ["decision", "landmine", "retro"]},
                                      "title": {"type": "string"}, "body": {"type": "string"}},
                       "required": ["kind", "title", "body"]}}}),
            vec!["sprint_id", "items"],
        ),
        (
            "sprint_report",
            "Read a sprint's numbers (committed and completed points, capacity, burndown), its \
             review once closed (carried issues, velocity delta, blockers, escalations), its \
             cost (dollars of priced runs; unpriced and subscription runs counted apart, in \
             tokens) and its proposed retro items.",
            json!({"sprint_id": {"type": "integer"}}),
            vec!["sprint_id"],
        ),
        (
            "org_chart",
            "Read your company's org chart: its agents (role, org role, manager, status), its \
             departments, their teams and each team's seats (product owner, team lead, \
             members, with capacity).",
            json!({}),
            vec![],
        ),
        (
            "plan_requirement",
            "As a planner of a requirement (default: your issue's), file its plan: epics (each \
             in project_id, default your issue's project, with tasks) and tasks under its \
             existing epics. A task has a title, body, points and assignee_agent_id (its owner \
             once work starts; nobody is woken now). No dev work on the requirement starts \
             until its plan is complete (every epic has tasks, every task points and an \
             assignee) and approved: submit: true asks for that, per the project's sprint \
             approval policy (the owner, or at once for a product-owner policy); the reply \
             comes back to your issue. The answer lists what still keeps the plan incomplete.",
            json!({"requirement_id": {"type": "integer"},
                   "epics": {"type": "array", "maxItems": 50, "items": {"type": "object",
                       "properties": {"title": {"type": "string"},
                                      "project_id": {"type": "integer"},
                                      "tasks": {"type": "array", "maxItems": 50,
                                                "items": plan_task(false)}},
                       "required": ["title"]}},
                   "tasks": {"type": "array", "maxItems": 50, "items": plan_task(true)},
                   "submit": {"type": "boolean"}}),
            vec![],
        ),
        (
            "apply_plan",
            "As a planner of a requirement (default: your issue's), file its whole plan in one \
             call: epics (new, with a title and project_id defaulting to your issue's \
             project, or existing by epic_id), each with tasks (title, body, points, \
             assignee_agent_id, repos: the project's repo names it touches); a sprint for them \
             (sprint_id of a planned one, or name, goal, starts_on, ends_on for a new one in \
             project_id; when that project already has a planned sprint open for issues, the \
             tasks join it instead, its name and dates kept: one sprint per project, not one \
             per plan), which every task joins unless it says sprint: false; and submit: \
             true to ask for the plan's approval. All or nothing: any invalid item and nothing \
             is filed, every problem listed. Reusing an idempotency_key returns the first \
             result instead of filing twice.",
            json!({"requirement_id": {"type": "integer"},
                   "idempotency_key": {"type": "string"},
                   "sprint": {"type": "object", "properties": {
                       "sprint_id": {"type": "integer"}, "project_id": {"type": "integer"},
                       "name": {"type": "string"}, "goal": {"type": "string"},
                       "starts_on": {"type": "string"}, "ends_on": {"type": "string"}}},
                   "epics": {"type": "array", "maxItems": 50, "items": {"type": "object",
                       "properties": {"title": {"type": "string"},
                                      "project_id": {"type": "integer"},
                                      "epic_id": {"type": "integer"},
                                      "tasks": {"type": "array", "maxItems": 50,
                                                "items": apply_task()}}}},
                   "submit": {"type": "boolean"}}),
            vec!["epics"],
        ),
        (
            "ask_human",
            "Ask the admin a question you cannot answer yourself (a decision, a credential, \
             something only a person can do), with up to 6 short options. It shows in your \
             requirement's thread with your name and issue, and your issue waits on the admin: \
             end your turn after asking. You are woken on this issue with the answer.",
            json!({"question": {"type": "string"}, "options": {"type": "array", "maxItems": 6,
                   "items": {"type": "string"}}}),
            vec!["question"],
        ),
        (
            "post_to_requirement",
            "As a requirement's owner (the CEO, or the product owner it was handed to), one of \
             its planners, or the CEO, write in its thread with the admin (default: your \
             issue's requirement).",
            json!({"body": {"type": "string"}, "requirement_id": {"type": "integer"}}),
            vec!["body"],
        ),
        (
            "publish_artifact",
            "Publish a report, file or screenshot of your work for the admin to see without \
             opening your conversation: a file name with its extension (md, txt, log, csv, \
             json, yaml, diff, html, svg, png, jpg, gif, webp, pdf, zip) and its content (standard base64). It is listed on your \
             issue and its requirement; over the size limit or the company's storage it is \
             refused, with the reason.",
            json!({"name": {"type": "string"}, "content": {"type": "string"},
                   "kind": {"type": "string",
                       "enum": ["report", "file", "screenshot", "other"]}}),
            vec!["name", "content"],
        ),
        (
            "get_artifact",
            "Read an artifact published on your requirement (or issue): its metadata and, for \
             text types, its content (first 64 KiB). Without artifact_id, list the \
             requirement's artifacts, newest first.",
            json!({"artifact_id": {"type": "integer"}}),
            vec![],
        ),
        (
            "request_repo",
            "Ask for another of your project's repos on your issue, saying why. The team lead \
             decides; approved, your next run has its worktree too.",
            json!({"repo": {"type": "string"}, "reason": {"type": "string"}}),
            vec!["repo", "reason"],
        ),
    ];
    tools
        .into_iter()
        .map(|(name, description, properties, required)| {
            let schema = json!({"type": "object", "properties": properties,
                                "required": required, "additionalProperties": false});
            let Value::Object(schema) = schema else {
                unreachable!("a schema is an object")
            };
            Tool::new(name, description, Arc::new(schema))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listed_tools_are_the_dispatched_tools() {
        let listed: Vec<String> = list().into_iter().map(|t| t.name.to_string()).collect();
        let mut want: Vec<&str> = super::super::tools::TOOLS.to_vec();
        want.sort_unstable();
        let mut got: Vec<&str> = listed.iter().map(String::as_str).collect();
        got.sort_unstable();
        assert_eq!(got, want);
    }
}
