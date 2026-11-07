//! Every GraphQL document this adapter ever sends. Each is a constant: the operation is fixed, and
//! a caller's values travel only in `variables`, never in the text. There is no alias, no batch,
//! no fragment spread and no field a caller can add. Selections are fixed too: an issue never
//! selects `parent`, `children` or `relations` (they name other teams' issues), and no connection
//! is nested deeper than the budget below.
//!
//! Complexity (Linear: 10,000 points per query, a connection multiplies its children by `first`):
//! the worst document is a search of at most 50 issues of about 18 points each (900), and the
//! project list (10 teams x 50 projects x 1.4 = 700): far under the limit by construction, so a
//! complexity refusal cannot be provoked.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Doc {
    pub name: &'static str,
    pub query: &'static str,
}

/// The fields of an issue that are returned. `team { key }` is what the team limit is checked on.
macro_rules! issue_fields {
    () => {
        "id identifier title description priority priorityLabel url createdAt updatedAt dueDate \
         state { name type } assignee { name displayName } team { key name } project { name } \
         labels(first: 10) { nodes { name } }"
    };
}

pub const VIEWER: Doc = Doc {
    name: "Viewer",
    query: "query Viewer { viewer { id name email organization { id urlKey name } } }",
};

pub const ISSUE: Doc = Doc {
    name: "Issue",
    query: concat!(
        "query Issue($id: String!) { issue(id: $id) { ",
        issue_fields!(),
        " } }"
    ),
};

/// The pre-read of a change: the issue's id, identifier and team, nothing else.
pub const ISSUE_REF: Doc = Doc {
    name: "IssueRef",
    query: "query IssueRef($id: String!) { issue(id: $id) { id identifier team { key } } }",
};

pub const STATE_REF: Doc = Doc {
    name: "StateRef",
    query: "query StateRef($id: String!) { workflowState(id: $id) { id team { key } } }",
};

pub const TEAM_REF: Doc = Doc {
    name: "TeamRef",
    query: "query TeamRef($key: String!) { teams(first: 1, filter: { key: { eq: $key } }) { \
            nodes { id key } } }",
};

pub const SEARCH: Doc = Doc {
    name: "Issues",
    query: concat!(
        "query Issues($first: Int!, $after: String, $filter: IssueFilter, \
         $orderBy: PaginationOrderBy) { issues(first: $first, after: $after, filter: $filter, \
         orderBy: $orderBy) { nodes { ",
        issue_fields!(),
        " } pageInfo { hasNextPage endCursor } } }"
    ),
};

pub const TEAMS: Doc = Doc {
    name: "Teams",
    query: "query Teams($filter: TeamFilter, $after: String) { teams(first: 50, after: $after, \
            filter: $filter) { nodes { id key name } pageInfo { hasNextPage endCursor } } }",
};

pub const STATES: Doc = Doc {
    name: "States",
    query: "query States($key: String!) { workflowStates(first: 50, filter: { team: { key: \
            { eq: $key } } }) { nodes { id name type position team { key } } \
            pageInfo { hasNextPage } } }",
};

/// Projects are read THROUGH their teams, so every project returned belongs to a team that was
/// asked for (and checked); no `teams` of a project is selected.
pub const PROJECTS: Doc = Doc {
    name: "Projects",
    query: "query Projects($filter: TeamFilter, $first: Int!) { teams(first: 10, \
            filter: $filter) { nodes { key projects(first: $first) { nodes { id name state \
            url } pageInfo { hasNextPage } } } pageInfo { hasNextPage } } }",
};

pub const ISSUE_UPDATE: Doc = Doc {
    name: "IssueUpdate",
    query: "mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) { \
            issueUpdate(id: $id, input: $input) { success issue { id identifier title url \
            state { name } team { key } } } }",
};

pub const ISSUE_CREATE: Doc = Doc {
    name: "IssueCreate",
    query: "mutation IssueCreate($input: IssueCreateInput!) { issueCreate(input: $input) { \
            success issue { id identifier title url team { key } } } }",
};

pub const COMMENT_CREATE: Doc = Doc {
    name: "CommentCreate",
    query: "mutation CommentCreate($input: CommentCreateInput!) { commentCreate(input: $input) { \
            success comment { id url createdAt issue { identifier team { key } } } } }",
};

/// Every document, for the tests that hold the fake to them.
#[cfg(test)]
pub const ALL: [Doc; 12] = [
    VIEWER,
    ISSUE,
    ISSUE_REF,
    STATE_REF,
    TEAM_REF,
    SEARCH,
    TEAMS,
    STATES,
    PROJECTS,
    ISSUE_UPDATE,
    ISSUE_CREATE,
    COMMENT_CREATE,
];
