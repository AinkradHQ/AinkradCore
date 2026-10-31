//! Every tool's definition: its name, what it does and its input schema, as `tools/list` serves
//! them. One entry per name of `tools::TOOLS`; a test keeps the two lists equal.

use std::sync::Arc;

use rmcp::model::Tool;
use serde_json::{Value, json};

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
             reviewer_agent_id or reviewer_user_id), block (optionally blocker_issue_id). A reviewer closes the issue: done is refused.",
            json!({"issue_id": issue,
                   "transition": {"type": "string",
                       "enum": ["start", "submit_for_review", "block"]},
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
