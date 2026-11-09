//! Every tool's definition: its name, what it does and its input schema, as `tools/list`
//! serves them (E4.2), and what `search_tools`, `describe_tool` and `citadel schema` read.

use std::sync::Arc;

use rmcp::model::Tool;
use serde_json::{Value, json};

/// Every tool, with its input schema.
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
        "description": "Your run's issue (the default), one of its subtasks, or any issue of its requirement."});
    let tools = [
        (
            "get_issue",
            "Read your issue (or a subtask, or any issue of its requirement): its fields, its newest comments, its blockers and \
             subtasks. Older comments: comments_before (older_comments_before); forward from a \
             comment you saw: comments_after.",
            json!({"issue_id": issue, "comments_after": {"type": "integer"},
                   "comments_before": {"type": "integer"},
                   "limit": {"type": "integer", "minimum": 1, "maximum": 50}}),
            vec![],
        ),
        (
            "get_context",
            "Read your project (with its spec, what planners plan from), its accepted \
             knowledge (landmines, decisions, state, retros, most relevant first within a 16 KiB \
             budget; dropped_knowledge lists what was left out), for its team lead the pending \
             knowledge proposals, and the skills given to this run, with any left out for size.",
            json!({}),
            vec![],
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
            "comment",
            "Add a comment to your issue (or a subtask). Reusing an idempotency_key returns \
             the first comment instead of posting twice.",
            json!({"body": {"type": "string"}, "idempotency_key": {"type": "string"},
                   "issue_id": issue}),
            vec!["body"],
        ),
        (
            "transition",
            "Move your issue (or a subtask) while you are its next actor: start, \
             submit_for_review (with reviewer_agent_id or reviewer_user_id, not yourself), \
             block (link blocker_issue_id first, or have one already), or done (with a PR, done \
             goes to your project's QA reviewer first). done is refused while the issue has \
             nothing to show for it: no change in its worktree, no PR and no comment from this \
             run; a second such done escalates the issue.",
            json!({"transition": {"type": "string",
                       "enum": ["start", "submit_for_review", "block", "done"]},
                   "reviewer_agent_id": {"type": "integer"},
                   "reviewer_user_id": {"type": "integer"},
                   "blocker_issue_id": {"type": "integer"}, "issue_id": issue}),
            vec!["transition"],
        ),
        (
            "create_subtask",
            "Create a subtask of your issue, owned by you and waiting on you.",
            json!({"title": {"type": "string"}, "body": {"type": "string"}}),
            vec!["title"],
        ),
        (
            "report_blocker",
            "Link a blocker to your issue (or a subtask): an existing issue \
             (blocker_issue_id), or a new one (title, body) handed to assignee_agent_id or \
             assignee_user_id (default: the admin). Then transition block if you cannot go on.",
            json!({"blocker_issue_id": {"type": "integer"}, "title": {"type": "string"},
                   "body": {"type": "string"}, "assignee_agent_id": {"type": "integer"},
                   "assignee_user_id": {"type": "integer"}, "issue_id": issue}),
            vec![],
        ),
        (
            "open_pr",
            "Ask for your issue's pull request on one of its repos, from its branch into that \
             repo's default branch, on the repo's forge (GitHub or GitLab). An issue touching \
             several repos has one worktree each (named after the repo) and one PR per repo you \
             changed: name the repo. It is opened once this run ends and the branch is pushed, \
             so commit first; asking again before then updates the title and body. get_issue \
             shows them (number, URL, checks).",
            json!({"title": {"type": "string"}, "body": {"type": "string"},
                   "repo": {"type": "string"}}),
            vec!["title"],
        ),
        (
            "request_repo",
            "Ask for another of your project's repos on your issue, saying why. The team lead \
             decides; approved, your next run has its worktree too.",
            json!({"repo": {"type": "string"}, "reason": {"type": "string"}}),
            vec!["repo", "reason"],
        ),
        (
            "decide_repo",
            "As the project's team lead, approve or reject an agent's request_repo on an issue \
             (default: your run's), with a reason.",
            json!({"repo": {"type": "string"},
                   "verdict": {"type": "string", "enum": ["approve", "reject"]},
                   "reason": {"type": "string"}, "issue_id": issue}),
            vec!["repo", "verdict"],
        ),
        (
            "set_repos",
            "As a planner of its project (product owner or team lead), set the repos an issue \
             touches (default: your run's issue); an empty list means the project's primary repo.",
            json!({"repos": {"type": "array", "items": {"type": "string"}}, "issue_id": issue}),
            vec!["repos"],
        ),
        (
            "qa_verdict",
            "As the QA reviewer of an issue in review (it waits on you), pass or fail it with \
             notes. Pass needs its PR open and its checks passed, and asks the owner to approve \
             the merge; fail sends it back to its developer with your notes.",
            json!({"verdict": {"type": "string", "enum": ["pass", "fail"]},
                   "notes": {"type": "string"}}),
            vec!["verdict", "notes"],
        ),
        (
            "request_approval",
            "Ask a human to approve something about your issue. It starts pending.",
            json!({"kind": {"type": "string", "enum":
                       ["pr_merge", "permission_escalation", "budget_overrun"]},
                   "summary": {"type": "string"}, "details": {"type": "string"},
                   "issue_id": issue}),
            vec!["kind", "summary"],
        ),
        (
            "get_approval",
            "Read an approval you asked for: its status (pending, approved, rejected or \
             expired), the reviewer's reply (or why it expired) and its deadline. You are also \
             woken with the reply when it is decided.",
            json!({"approval_id": {"type": "integer"}}),
            vec!["approval_id"],
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
            "review_knowledge",
            "As your project's team lead, accept or reject a pending knowledge proposal \
             (get_context lists them under proposals); a rejection needs a reason. You do not \
             decide your own proposals.",
            json!({"entry_id": {"type": "integer"},
                   "verdict": {"type": "string", "enum": ["accept", "reject"]},
                   "reason": {"type": "string"}}),
            vec!["entry_id", "verdict"],
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
            "assign_issue",
            "Hand an open issue to an agent on the project's team; it becomes the next actor \
             and is woken.",
            json!({"issue_id": {"type": "integer"}, "agent_id": {"type": "integer"}}),
            vec!["issue_id", "agent_id"],
        ),
        (
            "commit_sprint",
            "Commit a planned sprint, as the product owner of the project's team. It starts, \
             or, when the project's owner approves sprints, waits on that approval (the reply \
             comes back to your issue). Over the team's capacity, give an override_reason.",
            json!({"sprint_id": {"type": "integer"}, "override_reason": {"type": "string"}}),
            vec!["sprint_id"],
        ),
        (
            "close_sprint",
            "Close an active sprint, as the product owner of the project's team. Its open \
             issues go to the planned sprint carry_to_sprint_id, or back to the backlog; done \
             ones stay.",
            json!({"sprint_id": {"type": "integer"},
                   "carry_to_sprint_id": {"type": "integer"}}),
            vec!["sprint_id"],
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
            "route_intake",
            "As the CEO, route an intake request (default: your issue) along 1 to 10 routes. \
             When the request is about a project the company has (org_chart lists its \
             projects), prefer routing to it: {project_id}, and its team's product owner gets \
             a kickoff issue there (the project and its spec are left as they are). Otherwise \
             route to a department, {department_id, name, key}: it gets a new project (key: \
             capital letters and digits, not taken) owned by its team (team_id, default the \
             department's first), whose product owner gets the kickoff. Routes may mix both. \
             The request closes; the teams take it from there.",
            json!({"issue_id": {"type": "integer"}, "routes": {"type": "array",
                   "minItems": 1, "maxItems": 10, "items": {"type": "object",
                       "properties": {"project_id": {"type": "integer"},
                                      "department_id": {"type": "integer"},
                                      "team_id": {"type": "integer"},
                                      "name": {"type": "string"}, "key": {"type": "string"},
                                      "mode": {"type": "string", "enum": ["scrum", "kanban"]}}}}}),
            vec!["routes"],
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
            "search_tools",
            "Find a tool that is not in your list, by words of its name or purpose. Any tool \
             can be called; each checks your permission.",
            json!({"query": {"type": "string"}}),
            vec!["query"],
        ),
        (
            "describe_tool",
            "Read one tool's description and arguments (its input schema).",
            json!({"name": {"type": "string"}}),
            vec!["name"],
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
             json, yaml, diff, html, svg, png, jpg, gif, webp, pdf, zip) and either content \
             (standard base64) or path (relative, inside your worktree). It is listed on your \
             issue and its requirement; over the size limit or the company's storage it is \
             refused, with the reason.",
            json!({"name": {"type": "string"}, "content": {"type": "string"},
                   "path": {"type": "string"}, "kind": {"type": "string",
                       "enum": ["report", "file", "screenshot", "other"]}}),
            vec!["name"],
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
            "request_hire",
            "As a product owner, team lead, CTO or CEO, ask a human to hire an agent: its \
             name, role (job title), harness, model and runner tags, and why it is needed. It \
             is added pending approval and never runs until a human approves the hire.",
            json!({"name": {"type": "string"}, "role": {"type": "string"},
                   "harness": {"type": "string",
                       "enum": ["claude", "codex", "opencode", "agy"]},
                   "model": {"type": "string"},
                   "runner_tags": {"type": "array", "maxItems": 10,
                       "items": {"type": "string"}},
                   "justification": {"type": "string"}}),
            vec!["name", "role", "harness", "justification"],
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
