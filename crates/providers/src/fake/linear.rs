//! A fake Linear GraphQL API for one team: the operations the sync sends (`Team`, `Issues`,
//! `IssueCreate`, `IssueUpdate`), told apart by `operationName`. `updatedAt` is the wall clock,
//! strictly increasing, so it orders against Citadel's own timestamps.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use serde_json::json;

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeIssue {
    pub id: String,
    pub identifier: String,
    pub title: String,
    pub description: String,
    pub state_id: String,
    pub assignee_id: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Default)]
pub struct Board {
    pub token: String,
    pub team: String,
    /// (id, name, type, position).
    pub states: Vec<(String, String, String, f64)>,
    /// (id, name).
    pub members: Vec<(String, String)>,
    /// By id.
    pub issues: BTreeMap<String, FakeIssue>,
    /// The operation name of each mutation, in order.
    pub mutations: Vec<String>,
    last_ms: i64,
}

/// Starts a fake Linear for team `team` wanting `token`, with the default workflow (Backlog,
/// Todo, In Progress, In Review, Done, Canceled) and members `members`; its URL and state.
pub async fn linear(token: &str, team: &str, members: &[&str]) -> (String, Shared<Board>) {
    let states = [
        ("Backlog", "backlog"),
        ("Todo", "unstarted"),
        ("In Progress", "started"),
        ("In Review", "started"),
        ("Done", "completed"),
        ("Canceled", "canceled"),
    ];
    let board = Board {
        token: token.to_owned(),
        team: team.to_owned(),
        states: states
            .iter()
            .enumerate()
            .map(|(i, (name, kind))| {
                (
                    format!("st-{i}"),
                    name.to_string(),
                    kind.to_string(),
                    i as f64,
                )
            })
            .collect(),
        members: members
            .iter()
            .enumerate()
            .map(|(i, name)| (format!("u-{i}"), name.to_string()))
            .collect(),
        ..Board::default()
    };
    let board = Arc::new(Mutex::new(board));
    let router = axum::Router::new()
        .fallback(handle)
        .with_state(board.clone());
    (format!("{}/graphql", serve(router).await), board)
}

/// `ms` since the epoch as `2026-10-22T10:00:00.000Z`.
fn iso(ms: i64) -> String {
    let (days, ms) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let (h, m, s) = (ms / 3_600_000, ms / 60_000 % 60, ms / 1000 % 60);
    format!(
        "{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{:03}Z",
        ms % 1000
    )
}

impl Board {
    /// Now, after every timestamp handed out before.
    fn tick(&mut self) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        self.last_ms = now.max(self.last_ms + 1);
        iso(self.last_ms)
    }

    pub fn state_id(&self, name: &str) -> String {
        self.states
            .iter()
            .find(|s| s.1 == name)
            .map(|s| s.0.clone())
            .unwrap_or_else(|| panic!("no state {name}"))
    }

    pub fn by_identifier(&self, identifier: &str) -> FakeIssue {
        self.issues
            .values()
            .find(|i| i.identifier == identifier)
            .cloned()
            .unwrap_or_else(|| panic!("no issue {identifier}"))
    }

    /// A person's edit in Linear, as of now.
    pub fn edit(&mut self, identifier: &str, change: impl FnOnce(&mut FakeIssue)) {
        let at = self.tick();
        let issue = self
            .issues
            .values_mut()
            .find(|i| i.identifier == identifier)
            .unwrap_or_else(|| panic!("no issue {identifier}"));
        change(issue);
        issue.updated_at = at;
    }

    /// A new issue a person filed in Linear, in state `state`; its identifier.
    pub fn file(&mut self, title: &str, state: &str) -> String {
        let n = self.issues.len() + 1;
        let (id, identifier) = (format!("lin-{n}"), format!("ENG-{n}"));
        let at = self.tick();
        let state_id = self.state_id(state);
        self.issues.insert(
            id.clone(),
            FakeIssue {
                id,
                identifier: identifier.clone(),
                title: title.to_owned(),
                description: String::new(),
                state_id,
                assignee_id: None,
                updated_at: at,
            },
        );
        identifier
    }

    fn json(&self, i: &FakeIssue) -> Value {
        let state = self.states.iter().find(|s| s.0 == i.state_id).unwrap();
        let assignee = i.assignee_id.as_ref().map(|a| {
            let name = self.members.iter().find(|m| &m.0 == a).map(|m| m.1.clone());
            json!({"id": a, "name": name})
        });
        json!({"id": i.id, "identifier": i.identifier, "title": i.title,
               "description": i.description, "updatedAt": i.updated_at,
               "state": {"id": state.0, "name": state.1, "type": state.2},
               "assignee": assignee})
    }

    fn apply(&mut self, id: &str, input: &Value) {
        let at = self.tick();
        let issue = self.issues.get_mut(id).unwrap();
        if let Some(t) = input["title"].as_str() {
            issue.title = t.to_owned();
        }
        if let Some(d) = input["description"].as_str() {
            issue.description = d.to_owned();
        }
        if let Some(s) = input["stateId"].as_str() {
            issue.state_id = s.to_owned();
        }
        if let Some(a) = input["assigneeId"].as_str() {
            issue.assignee_id = Some(a.to_owned());
        }
        issue.updated_at = at;
    }
}

async fn handle(State(board): State<Shared<Board>>, headers: HeaderMap, body: Bytes) -> Response {
    let mut b = board.lock().unwrap();
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok());
    if auth != Some(b.token.as_str()) {
        let why = json!({"errors": [{"message": "Authentication required, not authenticated"}]});
        return reply(StatusCode::BAD_REQUEST, why);
    }
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let vars = &body["variables"];
    let data = match body["operationName"].as_str().unwrap_or("") {
        "Team" => {
            let states: Vec<Value> = b
                .states
                .iter()
                .map(|s| json!({"id": s.0, "name": s.1, "type": s.2, "position": s.3}))
                .collect();
            let members: Vec<Value> = b
                .members
                .iter()
                .map(|m| json!({"id": m.0, "name": m.1}))
                .collect();
            json!({"team": {"states": {"nodes": states}, "members": {"nodes": members}}})
        }
        "Issues" => {
            let since = vars["filter"]["updatedAt"]["gt"].as_str().unwrap_or("");
            let team = vars["filter"]["team"]["id"]["eq"].as_str().unwrap_or("");
            let mut nodes: Vec<&FakeIssue> = if team == b.team {
                b.issues
                    .values()
                    .filter(|i| i.updated_at.as_str() > since)
                    .collect()
            } else {
                vec![]
            };
            nodes.sort_by(|a, c| c.updated_at.cmp(&a.updated_at));
            let nodes: Vec<Value> = nodes.into_iter().map(|i| b.json(i)).collect();
            json!({"issues": {"nodes": nodes,
                              "pageInfo": {"hasNextPage": false, "endCursor": null}}})
        }
        "IssueCreate" => {
            b.mutations.push("IssueCreate".to_owned());
            let input = &vars["input"];
            let n = b.issues.len() + 1;
            let id = format!("lin-{n}");
            let fallback = b.state_id("Todo");
            b.issues.insert(
                id.clone(),
                FakeIssue {
                    id: id.clone(),
                    identifier: format!("ENG-{n}"),
                    title: String::new(),
                    description: String::new(),
                    state_id: input["stateId"].as_str().map_or(fallback, str::to_owned),
                    assignee_id: None,
                    updated_at: String::new(),
                },
            );
            b.apply(&id, input);
            json!({"issueCreate": {"success": true, "issue": b.json(&b.issues[&id])}})
        }
        "IssueUpdate" => {
            b.mutations.push("IssueUpdate".to_owned());
            let id = vars["id"].as_str().unwrap_or("").to_owned();
            if !b.issues.contains_key(&id) {
                let why = json!({"errors": [{"message": "Entity not found"}]});
                return reply(StatusCode::OK, why);
            }
            b.apply(&id, &vars["input"]);
            json!({"issueUpdate": {"success": true, "issue": b.json(&b.issues[&id])}})
        }
        other => {
            let why = json!({"errors": [{"message": format!("unknown operation {other}")}]});
            return reply(StatusCode::OK, why);
        }
    };
    reply(StatusCode::OK, json!({"data": data}))
}
