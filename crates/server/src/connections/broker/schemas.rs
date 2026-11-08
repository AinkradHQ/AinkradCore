//! The JSON Schema of each operation's arguments, for the tool list a harness shows its model.
//!
//! The adapters refuse any argument name they do not know, so each schema is closed
//! (`additionalProperties: false`) and its `properties` are exactly the names the adapter reads;
//! the tests hold the two together. GitHub's follow from the operation's path template and method
//! (`github::ops::OPS`), Jira's and Linear's are listed per operation.

use serde_json::{Value, json};

use crate::connections::github::{http::Method, ops};

fn object(properties: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": properties, "required": required,
        "additionalProperties": false})
}

fn github(op: &ops::Op) -> Value {
    let mut p = serde_json::Map::new();
    let mut required = vec!["repo"];
    p.insert(
        "repo".into(),
        json!({"type": "string", "description": "The repository as owner/name"}),
    );
    if op.path.contains("{number}") {
        required.push("number");
        p.insert(
            "number".into(),
            json!({"type": "integer", "minimum": 1,
                "description": "The issue or pull request number"}),
        );
    }
    if op.path.contains("{path}") {
        required.push("path");
        p.insert(
            "path".into(),
            json!({"type": "string", "description": "A file path inside the repository"}),
        );
    }
    p.insert(
        "query".into(),
        json!({"type": "object", "description": "Query parameters: plain values (text, number, \
            boolean), at most 16",
            "additionalProperties": {"type": ["string", "number", "boolean"]}}),
    );
    if op.method != Method::Get {
        required.push("body");
        p.insert(
            "body".into(),
            json!({"type": "object", "description": "The JSON body GitHub's API takes for this operation"}),
        );
    }
    object(Value::Object(p), &required)
}

fn text(max: usize, what: &str) -> Value {
    json!({"type": "string", "minLength": 1, "maxLength": max, "description": what})
}

fn fields() -> Value {
    json!({"type": "array", "items": {"type": "string"}, "maxItems": 30,
        "description": "Field names to return, like summary or customfield_10010"})
}

fn labels() -> Value {
    json!({"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 255,
        "pattern": "^\\S+$"}, "maxItems": 20, "description": "Labels (no spaces)"})
}

fn key() -> Value {
    text(32, "The issue key, like ABC-12")
}

fn jira(op: &str) -> Option<Value> {
    Some(match op {
        "jira.get_issue" => object(json!({"key": key(), "fields": fields()}), &["key"]),
        "jira.list_transitions" => object(json!({"key": key()}), &["key"]),
        "jira.transition_issue" => object(
            json!({"key": key(), "transition_id": {"type": "string", "pattern": "^[0-9]{1,10}$",
                "description": "The id list_transitions gave"}}),
            &["key", "transition_id"],
        ),
        "jira.add_comment" => object(
            json!({"key": key(), "body": text(30_000, "The comment, as plain text")}),
            &["key", "body"],
        ),
        "jira.update_issue" => object(
            json!({"key": key(), "summary": text(255, "The new summary"),
                "description": text(30_000, "The new description, as plain text"),
                "labels": labels()}),
            &["key"],
        ),
        "jira.create_issue" => object(
            json!({"project": text(10, "The project key, like ABC"),
                "summary": text(255, "The summary"),
                "issue_type": text(60, "The issue type's name, like Task"),
                "description": text(30_000, "The description, as plain text"),
                "labels": labels()}),
            &["project", "summary", "issue_type"],
        ),
        "jira.list_projects" => object(
            json!({"start_at": {"type": "integer", "minimum": 0, "maximum": 1_000_000},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 50}}),
            &[],
        ),
        "jira.search_issues" => object(
            json!({"jql": text(4000, "A JQL query"),
                "project": text(10, "Limit the search to this project key"),
                "fields": fields(),
                "order_by": {"type": "array", "items": {"type": "string"}, "maxItems": 5,
                    "description": "Terms like \"created desc\""},
                "max_results": {"type": "integer", "minimum": 1, "maximum": 100},
                "next_page_token": text(4000, "The token a previous page gave")}),
            &[],
        ),
        _ => return None,
    })
}

fn linear(op: &str) -> Option<Value> {
    let id = || text(32, "The issue identifier, like ENG-12 (not a UUID)");
    let team = |what: &str| text(7, what);
    let priority = || {
        json!({"type": "integer", "minimum": 0, "maximum": 4,
            "description": "0 none, 1 urgent, 2 high, 3 medium, 4 low"})
    };
    let first = |max: u64| json!({"type": "integer", "minimum": 1, "maximum": max});
    Some(match op {
        "linear.get_issue" => object(json!({"id": id()}), &["id"]),
        "linear.add_comment" => object(
            json!({"id": id(), "body": text(30_000, "The comment, as Markdown")}),
            &["id", "body"],
        ),
        "linear.update_issue" => object(
            json!({"id": id(), "title": text(255, "The new title"),
                "description": text(30_000, "The new description, as Markdown"),
                "priority": priority(),
                "state_id": text(36, "The id list_workflow_states gave")}),
            &["id"],
        ),
        "linear.create_issue" => object(
            json!({"team": team("The team key, like ENG"), "title": text(255, "The title"),
                "description": text(30_000, "The description, as Markdown"),
                "priority": priority()}),
            &["team", "title"],
        ),
        "linear.list_workflow_states" => {
            object(json!({"team": team("The team key, like ENG")}), &["team"])
        }
        "linear.list_teams" => object(json!({}), &[]),
        "linear.list_projects" => object(
            json!({"team": team("List this team's projects (no team: the first 10 teams')"),
                "first": first(50)}),
            &[],
        ),
        "linear.search_issues" => object(
            json!({"team": team("Search only this team (key)"),
                "text": text(200, "Words in the title or description"),
                "state": text(80, "A workflow state's name, like In Progress"),
                "state_type": {"type": "string", "enum": ["triage", "backlog", "unstarted",
                    "started", "completed", "canceled"]},
                "assignee": {"type": "string", "enum": ["me"]},
                "priority": priority(),
                "label": text(80, "A label's name"),
                "order_by": {"type": "string", "enum": ["updated", "created"]},
                "first": first(50),
                "after": text(200, "The cursor a previous page gave")}),
            &[],
        ),
        _ => return None,
    })
}

fn slack(op: &str) -> Option<Value> {
    let channel = || {
        json!({"type": "string", "pattern": "^[CG][A-Z0-9]{8,11}$",
            "description": "The channel ID, like C0123456789 (never a name; list_channels gives it)"})
    };
    let ts = |what: &str| json!({"type": "string", "pattern": "^[0-9]{10,11}\\.[0-9]{6}$", "description": what});
    let cursor = || text(200, "The next_cursor a previous page gave");
    let page = || json!({"type": "integer", "minimum": 1, "maximum": 15});
    Some(match op {
        "slack.list_channels" => object(
            json!({"limit": {"type": "integer", "minimum": 1, "maximum": 100}, "cursor": cursor()}),
            &[],
        ),
        "slack.read_channel" => object(
            json!({"channel": channel(), "limit": page(), "cursor": cursor(),
                "oldest": ts("Only messages after this timestamp"),
                "latest": ts("Only messages before this timestamp")}),
            &["channel"],
        ),
        "slack.read_thread" => object(
            json!({"channel": channel(), "ts": ts("The thread's parent message timestamp"),
                "limit": page(), "cursor": cursor()}),
            &["channel", "ts"],
        ),
        "slack.get_user" => object(
            json!({"user": {"type": "string", "pattern": "^[UW][A-Z0-9]{8,11}$",
                "description": "The user ID, like U0123456789"}}),
            &["user"],
        ),
        "slack.post_message" => object(
            json!({"channel": channel(),
                "text": text(4000, "The message as plain text. & < > are escaped; @here, \
                    @channel and @everyone are refused"),
                "thread_ts": ts("Reply in the thread of this message")}),
            &["channel", "text"],
        ),
        "slack.add_reaction" => object(
            json!({"channel": channel(), "ts": ts("The message timestamp"),
                "name": {"type": "string", "pattern": "^[a-z0-9_+-]{1,100}$",
                    "description": "The emoji name without colons, like thumbsup"}}),
            &["channel", "ts", "name"],
        ),
        _ => return None,
    })
}

fn teams(op: &str) -> Option<Value> {
    let team = || {
        json!({"type": "string", "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            "description": "The team id, a lower-case GUID (never a name; list_teams gives it)"})
    };
    let channel = || {
        json!({"type": "string", "pattern": "^19:[A-Za-z0-9_-]{8,80}@thread\\.(tacv2|skype)$",
            "description": "The channel id, like 19:...@thread.tacv2 (never a name; list_channels gives it)"})
    };
    let message = || {
        json!({"type": "string", "pattern": "^[0-9]{10,20}$",
            "description": "The message id a read gave"})
    };
    let top = || json!({"type": "integer", "minimum": 1, "maximum": 50});
    let cursor = || text(4096, "The next_cursor a previous page gave");
    let body = || {
        text(
            4000,
            "The message as plain text. Mentions (<at>) and @channel, @team, @everyone and @here \
             are refused",
        )
    };
    Some(match op {
        "teams.list_teams" => object(json!({}), &[]),
        "teams.list_channels" => object(json!({"team": team()}), &["team"]),
        "teams.list_messages" => object(
            json!({"team": team(), "channel": channel(), "top": top(), "cursor": cursor()}),
            &["team", "channel"],
        ),
        "teams.get_message" => object(
            json!({"team": team(), "channel": channel(), "message": message()}),
            &["team", "channel", "message"],
        ),
        "teams.list_replies" => object(
            json!({"team": team(), "channel": channel(), "message": message(), "top": top(),
                "cursor": cursor()}),
            &["team", "channel", "message"],
        ),
        "teams.post_message" => object(
            json!({"team": team(), "channel": channel(), "text": body()}),
            &["team", "channel", "text"],
        ),
        "teams.reply_message" => object(
            json!({"team": team(), "channel": channel(), "message": message(), "text": body()}),
            &["team", "channel", "message", "text"],
        ),
        _ => return None,
    })
}

/// The argument schema of `operation`, when one is known.
pub fn input_schema(operation: &str) -> Option<Value> {
    ops::find(operation)
        .map(github)
        .or_else(|| jira(operation))
        .or_else(|| linear(operation))
        .or_else(|| slack(operation))
        .or_else(|| teams(operation))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::adapter::builtin_descriptor;
    use crate::connections::github::build;
    use crate::connections::jira::resource_of;
    use crate::connections::linear::resource_of as linear_resource_of;
    use crate::connections::slack::resource_of as slack_resource_of;
    use crate::connections::teams::resource_of as teams_resource_of;

    /// The adapter's own check of `op`'s arguments: Jira's, Linear's or Slack's resource finder.
    fn resource(op: &str, args: &Value) -> Result<(), String> {
        if op.starts_with("linear.") {
            linear_resource_of(op, args).map(drop)
        } else if op.starts_with("slack.") {
            slack_resource_of(op, args).map(drop)
        } else if op.starts_with("teams.") {
            teams_resource_of(op, args).map(drop)
        } else {
            resource_of(op, args).map(drop)
        }
    }

    fn all_ops() -> Vec<String> {
        ["github", "jira", "linear", "slack", "teams"]
            .iter()
            .flat_map(|k| builtin_descriptor(k).expect("a built-in kind").capabilities)
            .flat_map(|c| c.operations.iter().map(|o| (*o).to_owned()))
            .collect()
    }

    fn names(schema: &Value) -> Vec<String> {
        schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    #[test]
    fn every_operation_has_a_closed_object_schema_that_fits_a_tool_list() {
        for op in all_ops() {
            let s = input_schema(&op).unwrap_or_else(|| panic!("{op} has no schema"));
            assert_eq!(s["type"], "object", "{op}");
            assert_eq!(s["additionalProperties"], false, "{op}");
            let required = s["required"].as_array().unwrap();
            assert!(
                required
                    .iter()
                    .all(|r| s["properties"].get(r.as_str().unwrap()).is_some()),
                "{op}: a required name is not a property"
            );
            assert!(
                s.to_string().len() <= ainkrad_proto::v2::MAX_SCHEMA_BYTES,
                "{op}"
            );
        }
        assert!(input_schema("github.drop_repo").is_none());
    }

    /// The schema's names are the names the adapter accepts, no more and no fewer: a name the
    /// adapter refuses as unknown is not in a schema, and every schema name is one it reads.
    #[test]
    fn the_schemas_name_exactly_what_the_adapters_read() {
        for op in all_ops() {
            let s = input_schema(&op).unwrap();
            let known = names(&s);
            for name in &known {
                let args = Value::Object(serde_json::Map::from_iter([(name.clone(), Value::Null)]));
                let refused = if op.starts_with("github.") {
                    // `null` is a wrong value for every GitHub field: only an unknown name is
                    // refused as one.
                    build(&op, &args).err().map(|e| format!("{e:?}"))
                } else {
                    resource(&op, &args).err()
                };
                let unknown = refused
                    .as_deref()
                    .is_some_and(|e| e.contains("UnknownField") || e.contains("no argument named"));
                assert!(!unknown, "{op}: the adapter does not read {name}");
            }
            let bogus = json!({"zz_not_an_argument": 1, "repo": "o/r"});
            let refused = if op.starts_with("github.") {
                format!("{:?}", build(&op, &bogus).unwrap_err())
            } else {
                resource(&op, &bogus).unwrap_err()
            };
            assert!(
                refused.contains("UnknownField") || refused.contains("no argument named"),
                "{op}: {refused}"
            );
        }
    }

    /// A GitHub schema's required names are the ones `build` insists on.
    #[test]
    fn github_required_names_are_the_ones_build_insists_on() {
        for op in ops::OPS {
            let s = github(op);
            let required: Vec<&str> = s["required"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_str().unwrap())
                .collect();
            let mut args = serde_json::Map::new();
            args.insert("repo".into(), json!("o/r"));
            args.insert("number".into(), json!(1));
            args.insert("path".into(), json!("a.md"));
            args.insert("body".into(), json!({}));
            for want in ["number", "path", "body"] {
                let mut less = args.clone();
                less.remove(want);
                if !required.contains(&want) {
                    // Not required: left out, `build` does not call it missing.
                    let err = build(op.name, &Value::Object(less)).err();
                    assert!(
                        !matches!(err, Some(crate::connections::github::BuildError::Missing(m)) if m == want),
                        "{}: {want} is optional in the schema but required by build",
                        op.name
                    );
                }
            }
        }
    }
}
