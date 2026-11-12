//! The Core's connections collectors (E5-2): Jira issues and GitHub pull requests with their
//! reviews, read through the existing connection accounts (`Broker::read`: the owner's grants,
//! GitHub App installation tokens, Jira through the sign-in service) and turned into the one item
//! format. Both are off until the user switches them on and, for GitHub, names the repositories.
//! Tracker keys and the repository's org become the signals room discovery reads. A cursor per
//! project or repository moves forward only when its run is committed, like the transcript
//! collector's. Nothing here holds a token: the broker opens it for the call.
//! ponytail: a first sync takes the newest issues and pull requests (capped), not the full
//! history; a backfill is a loop over older pages. Linear joins as one more kind of fetch.

use std::future::Future;
use std::pin::Pin;

use ainkrad_core_server::agents::history::read_history;
use ainkrad_core_server::api::App;
use ainkrad_core_server::connections::broker::Env;
use ainkrad_core_server::scheduler::{iso_of_unix, unix_secs};
use ainkrad_proto::v2::{HistoryChunk, HistoryRead, MAX_HISTORY_BYTES};
use brain_model::item::{Author, AuthorKind, Item, Origin, SourceKind, hash_of};
use serde_json::{Value, json};

use crate::transcripts::ulid;

pub const JIRA_SOURCE: &str = "jira";
pub const GITHUB_SOURCE: &str = "github";
const PAGE: usize = 50;
const MAX_PAGES: usize = 4;
const MAX_PRS: usize = 90;
/// Jira reads times in the user's zone; ask a day early and filter exactly here.
const JQL_SLACK_SECS: i64 = 86_400;

pub type Fut<'a> = Pin<Box<dyn Future<Output = Result<Value, String>> + Send + 'a>>;

/// One read of a connection (`jira.search_issues`, `github.list_prs`): the Core's broker in
/// production, canned data in tests. The error is `code: sentence`.
pub trait Fetch: Send + Sync {
    fn call<'a>(&'a self, op: &'a str, args: Value) -> Fut<'a>;
}

/// The broker, for the owner `user` (the schedule has no device: the owner is user 1).
pub(crate) struct Live {
    pub app: App,
    pub user: i64,
    pub device: String,
}

impl Fetch for Live {
    fn call<'a>(&'a self, op: &'a str, args: Value) -> Fut<'a> {
        Box::pin(async move {
            let now = self.app.clock.now();
            let env = Env {
                pool: &self.app.pool,
                sealer: self.app.secrets.as_ref(),
                now: &now,
            };
            self.app
                .connections
                .read(&env, self.user, &self.device, op, &args)
                .await
                .map_err(|e| format!("{}: {}", e.code, e.message))
        })
    }
}

/// A source id that names a runner: `runner-<runner id>`, the runner's own harness history.
pub const RUNNER_PREFIX: &str = "runner-";
/// Chunks one sync asks of a runner; the rest waits for the next sync (the cursor is per session).
const MAX_CHUNKS: usize = 3;

pub type HistFut<'a> = Pin<Box<dyn Future<Output = Result<HistoryChunk, String>> + Send + 'a>>;

/// One `history.read` of a runner: the Core's hub in production, canned chunks in tests. The
/// error is a plain code (`not_offered` when the runner did not switch sharing on).
pub trait RunnerHistory: Send + Sync {
    fn read<'a>(&'a self, runner: &'a str, req: HistoryRead) -> HistFut<'a>;
}

pub(crate) struct LiveHistory {
    pub app: App,
}

impl RunnerHistory for LiveHistory {
    fn read<'a>(&'a self, runner: &'a str, req: HistoryRead) -> HistFut<'a> {
        Box::pin(async move {
            read_history(&self.app, runner, req)
                .await
                .map_err(|e| e.0.to_owned())
        })
    }
}

/// Whether a read's refusal means "no connection to use" (nothing to collect, not a failure).
pub(crate) fn no_connection(e: &str) -> bool {
    [
        "not_granted",
        "no_connection",
        "secrets_disabled",
        "secrets_unavailable",
        "ambiguous",
        "disabled",
        "not_offered",
    ]
    .iter()
    .any(|c| e.starts_with(c))
}

/// An ISO time with or without a colon in the offset (`+0000`, Jira's), as unix seconds.
fn secs(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    let fixed;
    let t = if b.len() > 5
        && matches!(b[b.len() - 5], b'+' | b'-')
        && b[b.len() - 4..].iter().all(u8::is_ascii_digit)
    {
        fixed = format!("{}:{}", &t[..t.len() - 2], &t[t.len() - 2..]);
        fixed.as_str()
    } else {
        t
    };
    unix_secs(t)
}

fn str_of<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(v, |v, k| v.get(*k))?.as_str()
}

/// Plain text of an Atlassian document (or a plain string).
pub(crate) fn adf_text(v: &Value, out: &mut String) {
    match v {
        Value::String(s) => out.push_str(s),
        Value::Object(m) => {
            if let Some(t) = m.get("text").and_then(Value::as_str) {
                out.push_str(t);
            }
            if let Some(c) = m.get("content") {
                adf_text(c, out);
            }
            if matches!(
                m.get("type").and_then(Value::as_str),
                Some("paragraph" | "heading" | "listItem" | "codeBlock")
            ) {
                out.push('\n');
            }
        }
        Value::Array(a) => a.iter().for_each(|x| adf_text(x, out)),
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn item(
    kind: SourceKind,
    path: String,
    hint: Option<String>,
    author: &str,
    title: String,
    text: String,
    links: Vec<String>,
    (started, ended): (i64, Option<i64>),
    now_ms: u64,
) -> Item {
    Item {
        item_id: ulid(now_ms),
        source_kind: kind,
        content_hash: hash_of(&text),
        origin: Origin {
            device: "core".to_owned(),
            path,
            range: None,
        },
        project_hint: hint,
        author: Author {
            kind: AuthorKind::Person,
            name: author.chars().take(100).collect(),
        },
        title: title.chars().take(200).collect(),
        text,
        links,
        started_at: iso_of_unix(started),
        ended_at: ended.map(iso_of_unix),
    }
}

/// What a collector took: its items and its cursor after them (only what moved).
pub struct Taken {
    pub items: Vec<Item>,
    pub cursor: Value,
}

fn since_of(cursor: &Value, group: &str, key: &str) -> i64 {
    cursor[group][key].as_i64().unwrap_or(0)
}

/// Jira issues of `projects` (all visible when empty) updated after the cursor, oldest first.
pub async fn collect_jira(
    f: &dyn Fetch,
    projects: &[String],
    cursor: &Value,
    now_ms: u64,
) -> Result<Taken, String> {
    let keys: Vec<Option<&String>> = if projects.is_empty() {
        vec![None]
    } else {
        projects.iter().map(Some).collect()
    };
    let (mut items, mut next) = (vec![], json!({"projects": {}}));
    for p in keys {
        let key = p.map_or("*", String::as_str);
        let since = since_of(cursor, "projects", key);
        let mut newest = since;
        let mut token: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let mut args = json!({
                "max_results": PAGE,
                "order_by": ["updated asc"],
                "fields": ["summary", "status", "assignee", "reporter", "priority", "issuetype", "labels", "created", "updated", "description"],
            });
            if let Some(p) = p {
                args["project"] = json!(p);
            }
            if since > 0 {
                let ask = iso_of_unix(since - JQL_SLACK_SECS);
                args["jql"] = json!(format!("updated >= \"{} {}\"", &ask[..10], &ask[11..16]));
            }
            if let Some(t) = &token {
                args["next_page_token"] = json!(t);
            }
            let page = f.call("jira.search_issues", args).await?;
            for issue in page["issues"].as_array().map_or(&[][..], Vec::as_slice) {
                let Some(up) = str_of(issue, &["fields", "updated"]).and_then(secs) else {
                    continue;
                };
                if up <= since {
                    continue;
                }
                newest = newest.max(up);
                if let Some(i) = jira_item(issue, up, now_ms) {
                    items.push(i);
                }
            }
            token = page["nextPageToken"].as_str().map(str::to_owned);
            if token.is_none() || page["isLast"] == json!(true) {
                break;
            }
        }
        if newest > since {
            next["projects"][key] = json!(newest);
        }
    }
    Ok(Taken {
        items,
        cursor: next,
    })
}

fn jira_item(issue: &Value, updated: i64, now_ms: u64) -> Option<Item> {
    let key = issue["key"].as_str()?;
    let f = &issue["fields"];
    let summary = f["summary"].as_str().unwrap_or("(no summary)");
    let name = |p: &[&str]| str_of(f, p).unwrap_or("-").to_owned();
    let labels = f["labels"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    let mut body = String::new();
    adf_text(&f["description"], &mut body);
    let text = format!(
        "{key}: {summary}\nType: {} | Status: {} | Priority: {}\nAssignee: {} | Reporter: {} | Labels: {labels}\nUpdated: {}\n\n{}",
        name(&["issuetype", "name"]),
        name(&["status", "name"]),
        name(&["priority", "name"]),
        name(&["assignee", "displayName"]),
        name(&["reporter", "displayName"]),
        iso_of_unix(updated),
        body.trim()
    );
    let created = str_of(f, &["created"]).and_then(secs).unwrap_or(updated);
    Some(item(
        SourceKind::Jira,
        format!("jira://issue/{key}"),
        None,
        &name(&["reporter", "displayName"]),
        format!("{key} {summary}"),
        text,
        vec![],
        (created, Some(updated)),
        now_ms,
    ))
}

/// Pull requests of `repos` (`owner/name`) updated after the cursor, with their reviews.
pub async fn collect_github(
    f: &dyn Fetch,
    repos: &[String],
    cursor: &Value,
    now_ms: u64,
) -> Result<Taken, String> {
    let (mut items, mut next) = (vec![], json!({"repos": {}}));
    for repo in repos {
        let since = since_of(cursor, "repos", repo);
        let mut newest = since;
        let (mut seen, mut page) = (0, 1);
        // Newest first: stop at the first pull request the cursor already passed.
        'pages: while seen < MAX_PRS {
            let args = json!({"repo": repo, "query": {"state": "all", "sort": "updated", "direction": "desc", "per_page": 30, "page": page}});
            let prs = f.call("github.list_prs", args).await?;
            let list = prs.as_array().map_or(&[][..], Vec::as_slice);
            if list.is_empty() {
                break;
            }
            for pr in list {
                let Some(up) = str_of(pr, &["updated_at"]).and_then(secs) else {
                    continue;
                };
                if up <= since {
                    break 'pages;
                }
                seen += 1;
                newest = newest.max(up);
                let Some(number) = pr["number"].as_u64() else {
                    continue;
                };
                let reviews = f
                    .call(
                        "github.list_pr_reviews",
                        json!({"repo": repo, "number": number}),
                    )
                    .await?;
                items.push(pr_item(repo, pr, &reviews, up, now_ms));
            }
            page += 1;
        }
        if newest > since {
            next["repos"][repo.as_str()] = json!(newest);
        }
    }
    Ok(Taken {
        items,
        cursor: next,
    })
}

fn pr_item(repo: &str, pr: &Value, reviews: &Value, updated: i64, now_ms: u64) -> Item {
    let number = pr["number"].as_u64().unwrap_or(0);
    let title = pr["title"].as_str().unwrap_or("(no title)");
    let author = str_of(pr, &["user", "login"]).unwrap_or("-");
    let state = if pr["merged_at"].is_string() {
        "merged"
    } else {
        pr["state"].as_str().unwrap_or("open")
    };
    let mut text = format!(
        "{repo}#{number}: {title}\nState: {state} | Author: {author} | Base: {}\nUpdated: {}\n\n{}",
        str_of(pr, &["base", "ref"]).unwrap_or("-"),
        iso_of_unix(updated),
        pr["body"].as_str().unwrap_or("").trim()
    );
    let mut reviewed = String::new();
    for r in reviews.as_array().map_or(&[][..], Vec::as_slice) {
        let body = r["body"].as_str().unwrap_or("").trim();
        reviewed.push_str(&format!(
            "- {} ({}){}{body}\n",
            str_of(r, &["user", "login"]).unwrap_or("-"),
            r["state"].as_str().unwrap_or("COMMENTED"),
            if body.is_empty() { "" } else { ": " }
        ));
    }
    if !reviewed.is_empty() {
        text.push_str("\n\nReviews:\n");
        text.push_str(&reviewed);
    }
    let created = str_of(pr, &["created_at"])
        .and_then(secs)
        .unwrap_or(updated);
    let ended = ["merged_at", "closed_at"]
        .iter()
        .find_map(|k| str_of(pr, &[k]).and_then(secs));
    item(
        SourceKind::Github,
        format!("github://{repo}/pull/{number}"),
        Some(format!("github.com/{repo}")),
        author,
        format!("{repo}#{number} {title}"),
        text,
        pr["html_url"]
            .as_str()
            .map(str::to_owned)
            .into_iter()
            .collect(),
        (created, ended),
        now_ms,
    )
}

/// Claude Code names a project folder for the path it ran in (`-Users-x-contracts-nda`). The origin
/// path shows it as the path, so the Core's rules (restricted folders, deprecated projects) match
/// its components; a real dash in a name only costs display fidelity.
fn decode_dirs(path: &str) -> String {
    match path
        .split_once('/')
        .and_then(|(h, r)| r.rsplit_once('/').map(|(d, f)| (h, d, f)))
    {
        Some((harness, dir, file)) => format!(
            "{harness}/{}/{file}",
            dir.trim_start_matches('-').replace('-', "/")
        ),
        None => path.to_owned(),
    }
}

/// The new parts of a runner's harness history (E5-3), in the one item format. The runner read
/// only what it may and redacted it; the Core's intake cleans it again and applies the rules.
pub async fn collect_runner(
    h: &dyn RunnerHistory,
    runner: &str,
    cursor: &Value,
    now_ms: u64,
) -> Result<Taken, String> {
    let mut sessions: std::collections::BTreeMap<String, u64> = cursor["sessions"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_u64()?)))
                .collect()
        })
        .unwrap_or_default();
    let (mut items, mut next) = (vec![], json!({"sessions": {}}));
    for _ in 0..MAX_CHUNKS {
        let req = HistoryRead {
            harness: "claude".to_owned(),
            cursor: sessions.clone(),
            max_bytes: MAX_HISTORY_BYTES,
        };
        let chunk = h.read(runner, req).await?;
        for (id, line) in &chunk.cursor {
            sessions.insert(id.clone(), *line);
            next["sessions"][id.as_str()] = json!(line);
        }
        for it in chunk.items {
            let i = Item {
                item_id: ulid(now_ms),
                source_kind: SourceKind::ClaudeCode,
                content_hash: hash_of(&it.text),
                origin: Origin {
                    device: runner.to_owned(),
                    path: format!("runner://{runner}/{}", decode_dirs(&it.path)),
                    range: Some((it.first, it.last)),
                },
                project_hint: it.project,
                author: Author {
                    kind: AuthorKind::Agent,
                    name: "claude".to_owned(),
                },
                title: it.title.chars().take(200).collect(),
                text: it.text,
                links: vec![],
                started_at: it.started_at,
                ended_at: it.ended_at,
            };
            if i.validate().is_ok() {
                items.push(i);
            }
        }
        if !chunk.more {
            break;
        }
    }
    Ok(Taken {
        items,
        cursor: next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_project_folder_name_is_shown_as_the_path_it_stands_for() {
        assert_eq!(
            decode_dirs("claude/-Users-x-contracts-nda/s9.jsonl"),
            "claude/Users/x/contracts/nda/s9.jsonl"
        );
        assert_eq!(decode_dirs("odd"), "odd");
    }

    #[test]
    fn jira_times_with_and_without_a_colon_agree() {
        assert_eq!(
            secs("2026-11-12T08:00:00.000+0000"),
            secs("2026-11-12T08:00:00.000+00:00")
        );
        assert_eq!(
            secs("2026-11-12T11:00:00.000+0300"),
            secs("2026-11-12T08:00:00Z")
        );
    }

    #[test]
    fn an_atlassian_document_becomes_plain_lines() {
        let doc = json!({"type": "doc", "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": "First"}]},
            {"type": "paragraph", "content": [{"type": "text", "text": "Second"}]}]});
        let mut out = String::new();
        adf_text(&doc, &mut out);
        assert_eq!(out, "First\nSecond\n");
    }
}
