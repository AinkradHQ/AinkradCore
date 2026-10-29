//! A fake GitLab REST API v4: merge requests (with their head pipeline), commit statuses,
//! merges and notes, on the same state as the fake GitHub (`Hub`; a PR's number is the MR's
//! iid).

use axum::extract::State;
use serde_json::json;

use super::*;

/// Starts a fake GitLab that wants `token` in `PRIVATE-TOKEN`; its API base URL and state.
pub async fn gitlab(token: &str) -> (String, Shared<Hub>) {
    let hub = Arc::new(Mutex::new(Hub {
        token: token.to_owned(),
        ..Hub::default()
    }));
    let router = axum::Router::new().fallback(handle).with_state(hub.clone());
    (serve(router).await, hub)
}

fn mr_json(hub: &Hub, p: &FakePr) -> Value {
    let state = match (p.open, p.merged) {
        (_, true) => "merged",
        (true, false) => "opened",
        (false, false) => "closed",
    };
    let pipeline = hub
        .pipelines
        .get(&p.head_sha)
        .map(|status| json!({"status": status}));
    json!({"iid": p.number, "web_url": format!("https://gitlab.test/{}/-/merge_requests/{}", p.repo, p.number),
           "state": state, "sha": p.head_sha, "source_branch": p.head,
           "target_branch": p.base, "title": p.title, "head_pipeline": pipeline})
}

async fn handle(
    State(hub): State<Shared<Hub>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let mut hub = hub.lock().unwrap();
    hub.requests.push(format!("{method} {}", uri.path()));
    let token = headers.get("private-token").and_then(|v| v.to_str().ok());
    if token != Some(hub.token.as_str()) {
        return reply(
            StatusCode::UNAUTHORIZED,
            json!({"message": "401 Unauthorized"}),
        );
    }
    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let parts: Vec<&str> = uri.path().trim_matches('/').split('/').collect();
    let (repo, rest) = match parts.as_slice() {
        ["projects", id, rest @ ..] => (id.replace("%2F", "/"), rest.to_vec()),
        _ => return reply(StatusCode::NOT_FOUND, json!({"message": "404 Not Found"})),
    };
    let not_found = || reply(StatusCode::NOT_FOUND, json!({"message": "404 Not found"}));
    let iid = |s: &str| s.parse::<u64>().ok();
    match (method.as_str(), rest.as_slice()) {
        ("DELETE", ["repository", "branches", branch]) => {
            let branch = branch.replace("%2F", "/");
            if hub.deleted.contains(&branch) {
                return not_found();
            }
            hub.deleted.push(branch);
            reply(StatusCode::NO_CONTENT, Value::Null)
        }
        ("POST", ["merge_requests"]) => {
            let head = body["source_branch"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let base = body["target_branch"].as_str().unwrap_or_default();
            let title = body["title"].as_str().unwrap_or_default();
            let text = body["description"].as_str().unwrap_or_default();
            match hub.create(&repo, &head, base, title, text) {
                Some(p) => reply(StatusCode::CREATED, mr_json(&hub, &p)),
                None => {
                    let why = json!({"message": ["Source branch does not exist"]});
                    reply(StatusCode::BAD_REQUEST, why)
                }
            }
        }
        ("GET", ["merge_requests", n]) => match iid(n).and_then(|n| hub.prs.get(&n)) {
            Some(p) => reply(StatusCode::OK, mr_json(&hub, p)),
            None => not_found(),
        },
        ("PUT", ["merge_requests", n, "merge"]) => {
            let Some(n) = iid(n) else {
                return not_found();
            };
            if hub.unmergeable.contains(&n) {
                let why = json!({"message": "405 Method Not Allowed"});
                return reply(StatusCode::METHOD_NOT_ALLOWED, why);
            }
            let squash = body["squash"].as_bool().unwrap_or(false);
            let title = body["merge_commit_message"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let sha = body["sha"].as_str().map(str::to_owned);
            let Some(p) = hub.prs.get_mut(&n) else {
                return not_found();
            };
            if sha.as_deref() != Some(p.head_sha.as_str()) {
                let why = json!({"message": "SHA does not match HEAD of source branch"});
                return reply(StatusCode::CONFLICT, why);
            }
            p.open = false;
            p.merged = true;
            let p = p.clone();
            let how = if squash { "squash" } else { "merge" };
            hub.merges.push((n, how.to_owned()));
            hub.merge_titles.push((n, title));
            reply(StatusCode::OK, mr_json(&hub, &p))
        }
        ("POST", ["merge_requests", n, "notes"]) => {
            let Some(n) = iid(n) else {
                return not_found();
            };
            let text = body["body"].as_str().unwrap_or_default().to_owned();
            hub.comments.push((n, text));
            reply(StatusCode::CREATED, json!({"id": hub.comments.len()}))
        }
        ("GET", ["repository", "commits", sha, "statuses"]) => {
            let statuses: Vec<Value> = hub
                .statuses
                .get(*sha)
                .into_iter()
                .flatten()
                .map(|(name, status)| json!({"name": name, "status": status}))
                .collect();
            reply(StatusCode::OK, Value::Array(statuses))
        }
        _ => not_found(),
    }
}
