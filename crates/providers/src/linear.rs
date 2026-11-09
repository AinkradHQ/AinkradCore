//! Linear's GraphQL API (E9.4, #26), what the issue sync needs: a team's workflow states and
//! members, its issues changed since a cursor (`updatedAt`), and creating and updating issues.
//! Every request is a named operation (`Team`, `Issues`, `IssueCreate`, `IssueUpdate`).
//!
//! The token is a Linear API key, sent as `Authorization: <key>`. A GraphQL error (an HTTP 200
//! with `errors`) is an `Error::Http` with the API's message.

use serde_json::{Value, json};

/// The most pages `issues_since` reads.
pub const MAX_PAGES: usize = 20;

use super::*;

/// The GraphQL endpoint of linear.app.
pub const API: &str = "https://api.linear.app/graphql";

pub struct Linear {
    client: reqwest::Client,
    api: String,
    token: Secret,
}

/// A workflow state: its id, name and type (`backlog`, `unstarted`, `started`, `completed`,
/// `canceled`, `triage`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub id: String,
    pub name: String,
    pub kind: String,
}

/// A team's states (by position) and members `(id, name)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Team {
    pub states: Vec<State>,
    pub members: Vec<(String, String)>,
}

/// An issue as Linear has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub id: String,
    /// `ENG-12`.
    pub identifier: String,
    pub title: String,
    pub description: String,
    /// ISO-8601, e.g. `2026-10-22T10:00:00.000Z`.
    pub updated_at: String,
    pub state: State,
    /// `(id, name)`.
    pub assignee: Option<(String, String)>,
}

/// What an update changes; `None` leaves a field as it is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    pub title: Option<String>,
    pub description: Option<String>,
    pub state_id: Option<String>,
    pub assignee_id: Option<String>,
}

const ISSUE_FIELDS: &str = "id identifier title description updatedAt \
    state { id name type } assignee { id name }";

fn issue(v: &Value) -> Result<Issue> {
    let assignee = match &v["assignee"] {
        Value::Null => None,
        a => Some((text(a, "id")?, text(a, "name")?)),
    };
    Ok(Issue {
        id: text(v, "id")?,
        identifier: text(v, "identifier")?,
        title: text(v, "title")?,
        description: v["description"].as_str().unwrap_or_default().to_owned(),
        updated_at: text(v, "updatedAt")?,
        state: State {
            id: text(v, "state.id")?,
            name: text(v, "state.name")?,
            kind: text(v, "state.type")?,
        },
        assignee,
    })
}

impl Linear {
    pub fn new(client: reqwest::Client, api: &str, token: Secret) -> Self {
        Self {
            client,
            api: api.to_owned(),
            token,
        }
    }

    /// Runs operation `name`; its `data`.
    async fn run(&self, name: &str, query: &str, variables: Value) -> Result<Value> {
        let body = json!({"operationName": name, "query": query, "variables": variables});
        let req = self
            .client
            .post(&self.api)
            .header("Authorization", self.token.expose())
            .json(&body);
        let mut v = send(req, &self.token).await?;
        if let Some(errors) = v["errors"].as_array().filter(|e| !e.is_empty()) {
            let message = errors[0]["message"].as_str().unwrap_or("GraphQL error");
            return Err(Error::Http {
                status: 200,
                message: message.replace(self.token.expose(), "<redacted>"),
            });
        }
        Ok(v["data"].take())
    }

    pub async fn team(&self, team: &str) -> Result<Team> {
        let query = "query Team($id: String!) { team(id: $id) { \
            states { nodes { id name type position } } members { nodes { id name } } } }";
        let data = self.run("Team", query, json!({"id": team})).await?;
        let mut states: Vec<(f64, State)> = vec![];
        for s in data["team"]["states"]["nodes"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let state = State {
                id: text(s, "id")?,
                name: text(s, "name")?,
                kind: text(s, "type")?,
            };
            states.push((s["position"].as_f64().unwrap_or(0.0), state));
        }
        states.sort_by(|a, b| a.0.total_cmp(&b.0));
        let mut members = vec![];
        for m in data["team"]["members"]["nodes"]
            .as_array()
            .into_iter()
            .flatten()
        {
            members.push((text(m, "id")?, text(m, "name")?));
        }
        Ok(Team {
            states: states.into_iter().map(|(_, s)| s).collect(),
            members,
        })
    }

    /// The team's issues updated after `since` (all of them without one), oldest change first,
    /// every page.
    pub async fn issues_since(&self, team: &str, since: Option<&str>) -> Result<Vec<Issue>> {
        let query = format!(
            "query Issues($filter: IssueFilter, $after: String) {{ issues(filter: $filter, \
             first: 100, after: $after, orderBy: updatedAt) {{ nodes {{ {ISSUE_FIELDS} }} \
             pageInfo {{ hasNextPage endCursor }} }} }}"
        );
        let mut filter = json!({"team": {"id": {"eq": team}}});
        if let Some(since) = since {
            filter["updatedAt"] = json!({"gt": since});
        }
        let (mut found, mut after) = (vec![], Value::Null);
        // Bounded: a team (or an endpoint that always says there is more) cannot run a pass for
        // ever or fill memory. ponytail: 20 pages of 100; a cursor that resumes across passes if a
        // team ever has more changed issues than that between two syncs.
        for page in 0.. {
            if page == MAX_PAGES {
                return Err(Error::Decode(format!(
                    "more than {MAX_PAGES} pages of issues; refusing to read on"
                )));
            }
            let vars = json!({"filter": filter, "after": after});
            let data = self.run("Issues", &query, vars).await?;
            for n in data["issues"]["nodes"].as_array().into_iter().flatten() {
                found.push(issue(n)?);
            }
            match data["issues"]["pageInfo"]["hasNextPage"].as_bool() {
                Some(true) => after = data["issues"]["pageInfo"]["endCursor"].clone(),
                _ => break,
            }
        }
        found.sort_by(|a, b| a.updated_at.cmp(&b.updated_at));
        Ok(found)
    }

    pub async fn create(&self, team: &str, c: &Changes) -> Result<Issue> {
        let query = format!(
            "mutation IssueCreate($input: IssueCreateInput!) {{ issueCreate(input: $input) \
             {{ success issue {{ {ISSUE_FIELDS} }} }} }}"
        );
        let mut input = input(c);
        input["teamId"] = team.into();
        let data = self
            .run("IssueCreate", &query, json!({"input": input}))
            .await?;
        issue(&data["issueCreate"]["issue"])
    }

    pub async fn update(&self, id: &str, c: &Changes) -> Result<Issue> {
        let query = format!(
            "mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) {{ \
             issueUpdate(id: $id, input: $input) {{ success issue {{ {ISSUE_FIELDS} }} }} }}"
        );
        let vars = json!({"id": id, "input": input(c)});
        let data = self.run("IssueUpdate", &query, vars).await?;
        issue(&data["issueUpdate"]["issue"])
    }
}

/// The GraphQL input for `c`: only the fields it changes.
fn input(c: &Changes) -> Value {
    let mut input = json!({});
    for (key, value) in [
        ("title", &c.title),
        ("description", &c.description),
        ("stateId", &c.state_id),
        ("assigneeId", &c.assignee_id),
    ] {
        if let Some(value) = value {
            input[key] = value.clone().into();
        }
    }
    input
}

#[cfg(test)]
mod tests;
