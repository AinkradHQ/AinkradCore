//! The typed operations of the GitHub kind and the builder that turns an operation and its input
//! into a request (C2; design §3, §5). Each operation is data: a method, a URL template, the
//! capability that allows it. Every one touches exactly one repository, so the resource a grant's
//! `repos` limit is judged against is always `owner/name`.
//!
//! The builder is the only way a request is made. The repository is a validated `owner/name`;
//! every other path part is percent-encoded; a `.` or `..` segment, an empty one, an unknown
//! field or an unknown query key is refused, so a request cannot leave `/repos/{owner}/{repo}`.

use serde_json::Value;

use super::guard;
pub use super::guard::BuildError;
use super::http::{Body, Host, Method, Req, encode, safe_path};

/// One operation: what it is called to the broker, and what it asks GitHub.
#[derive(Debug, Clone, Copy)]
pub struct Op {
    /// `github.get_issue`.
    pub name: &'static str,
    pub method: Method,
    /// `{owner}` and `{repo}` always; `{number}` and `{path}` when it needs them.
    pub path: &'static str,
    pub capability: &'static str,
}

const fn op(
    name: &'static str,
    method: Method,
    path: &'static str,
    capability: &'static str,
) -> Op {
    Op {
        name,
        method,
        path,
        capability,
    }
}

use Method::{Get, Patch, Post, Put};

pub const OPS: &[Op] = &[
    op("github.get_repo", Get, "/repos/{owner}/{repo}", "read_repo"),
    op(
        "github.list_branches",
        Get,
        "/repos/{owner}/{repo}/branches",
        "read_repo",
    ),
    op(
        "github.read_file",
        Get,
        "/repos/{owner}/{repo}/contents/{path}",
        "read_repo",
    ),
    op(
        "github.list_issues",
        Get,
        "/repos/{owner}/{repo}/issues",
        "read_repo",
    ),
    op(
        "github.get_issue",
        Get,
        "/repos/{owner}/{repo}/issues/{number}",
        "read_repo",
    ),
    op(
        "github.list_issue_comments",
        Get,
        "/repos/{owner}/{repo}/issues/{number}/comments",
        "read_repo",
    ),
    op(
        "github.list_prs",
        Get,
        "/repos/{owner}/{repo}/pulls",
        "read_repo",
    ),
    op(
        "github.get_pr",
        Get,
        "/repos/{owner}/{repo}/pulls/{number}",
        "read_repo",
    ),
    op(
        "github.list_pr_files",
        Get,
        "/repos/{owner}/{repo}/pulls/{number}/files",
        "read_repo",
    ),
    op(
        "github.list_pr_reviews",
        Get,
        "/repos/{owner}/{repo}/pulls/{number}/reviews",
        "read_repo",
    ),
    op(
        "github.create_issue",
        Post,
        "/repos/{owner}/{repo}/issues",
        "issues_write",
    ),
    op(
        "github.update_issue",
        Patch,
        "/repos/{owner}/{repo}/issues/{number}",
        "issues_write",
    ),
    op(
        "github.comment_issue",
        Post,
        "/repos/{owner}/{repo}/issues/{number}/comments",
        "issues_write",
    ),
    op(
        "github.update_pr",
        Patch,
        "/repos/{owner}/{repo}/pulls/{number}",
        "pr_write",
    ),
    op(
        "github.create_pr",
        Post,
        "/repos/{owner}/{repo}/pulls",
        "pr_write",
    ),
    // A pull request's conversation comments are issue comments on GitHub.
    op(
        "github.comment_pr",
        Post,
        "/repos/{owner}/{repo}/issues/{number}/comments",
        "pr_write",
    ),
    op(
        "github.create_branch",
        Post,
        "/repos/{owner}/{repo}/git/refs",
        "push",
    ),
    op(
        "github.put_file",
        Put,
        "/repos/{owner}/{repo}/contents/{path}",
        "push",
    ),
];

pub fn find(name: &str) -> Option<&'static Op> {
    OPS.iter().find(|o| o.name == name)
}

/// A built request and what the broker needs to judge it. [`build`] is the only way to make one.
#[derive(Debug, Clone)]
pub struct Built {
    op: &'static Op,
    resource: String,
    number: Option<u64>,
    req: Req,
}

impl Built {
    pub fn op(&self) -> &'static Op {
        self.op
    }

    /// `owner/name`: the value of the `repos` limit this call is checked against.
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// The issue or pull request number, when the operation has one.
    pub fn number(&self) -> Option<u64> {
        self.number
    }

    pub fn req(&self) -> &Req {
        &self.req
    }
}

const MAX_BODY: usize = 256 * 1024;
const MAX_QUERY: usize = 16;

fn owner_ok(s: &str) -> bool {
    (1..=39).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn repo_ok(s: &str) -> bool {
    (1..=100).contains(&s.len())
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// `owner/name`, validated.
pub fn split_repo(s: &str) -> Option<(&str, &str)> {
    let (o, r) = s.split_once('/')?;
    (owner_ok(o) && repo_ok(r)).then_some((o, r))
}

fn file_path(s: &str) -> Option<String> {
    let segs: Vec<&str> = s.split('/').collect();
    let ok = s.len() <= 1024
        && segs.len() <= 64
        && segs.iter().all(|g| {
            !g.is_empty()
                && *g != "."
                && *g != ".."
                && !g.chars().any(char::is_control)
                && !g.contains('\\')
        });
    ok.then(|| segs.iter().map(|g| encode(g)).collect::<Vec<_>>().join("/"))
}

fn query(v: &Value) -> Result<String, BuildError> {
    let m = v.as_object().ok_or(BuildError::BadQuery)?;
    if m.len() > MAX_QUERY {
        return Err(BuildError::BadQuery);
    }
    let mut parts = Vec::new();
    for (k, val) in m {
        let text = match val {
            Value::String(s) if s.len() <= 256 => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => return Err(BuildError::BadQuery),
        };
        let key_ok =
            (1..=32).contains(&k.len()) && k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
        if !key_ok {
            return Err(BuildError::BadQuery);
        }
        parts.push(format!("{}={}", encode(k), encode(&text)));
    }
    Ok(parts.join("&"))
}

/// Builds `operation` from `input`, a JSON object with `repo` (`owner/name`) and, as the
/// operation needs, `number`, `path`, `query` (an object of plain values) and `body` (an object).
pub fn build(operation: &str, input: &Value) -> Result<Built, BuildError> {
    let op = find(operation).ok_or(BuildError::UnknownOperation)?;
    let obj = input.as_object().ok_or(BuildError::BadBody)?;
    if obj
        .keys()
        .any(|k| !["repo", "number", "path", "query", "body"].contains(&k.as_str()))
    {
        return Err(BuildError::UnknownField);
    }
    let repo = obj
        .get("repo")
        .ok_or(BuildError::Missing("repo"))?
        .as_str()
        .and_then(split_repo)
        .ok_or(BuildError::BadRepo)?;
    let mut path = op.path.replace("{owner}", repo.0).replace("{repo}", repo.1);
    let mut number = None;
    if path.contains("{number}") {
        let n = obj
            .get("number")
            .ok_or(BuildError::Missing("number"))?
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or(BuildError::BadNumber)?;
        number = Some(n);
        path = path.replace("{number}", &n.to_string());
    }
    if path.contains("{path}") {
        let raw = obj
            .get("path")
            .ok_or(BuildError::Missing("path"))?
            .as_str()
            .ok_or(BuildError::BadPath)?;
        let p = file_path(raw).ok_or(BuildError::BadPath)?;
        if op.method != Method::Get && guard::protected_path(raw) {
            return Err(BuildError::ProtectedPath);
        }
        path = path.replace("{path}", &p);
    }
    if let Some(q) = obj.get("query") {
        let q = query(q)?;
        if !q.is_empty() {
            path = format!("{path}?{q}");
        }
    }
    let body = match (obj.get("body"), op.method) {
        (Some(Value::Object(m)), Method::Post | Method::Patch | Method::Put) => {
            guard::body(op.name, repo.0, m)?;
            let bytes = serde_json::to_vec(m).map_err(|_| BuildError::BadBody)?;
            if bytes.len() > MAX_BODY {
                return Err(BuildError::BadBody);
            }
            Some(Body::json(bytes))
        }
        (None, Method::Get) => None,
        (None, _) => return Err(BuildError::Missing("body")),
        _ => return Err(BuildError::BadBody),
    };
    // Belt and braces: the assembled path is held to the same rule as any other.
    if !safe_path(&path) || !path.starts_with(&format!("/repos/{}/{}", repo.0, repo.1)) {
        return Err(BuildError::BadPath);
    }
    Ok(Built {
        op,
        resource: format!("{}/{}", repo.0, repo.1),
        number,
        req: Req::new(Host::Api, op.method, path, body),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn builds_a_read_with_a_number_and_a_query() {
        let b = build(
            "github.list_issues",
            &json!({"repo": "acme/web", "query": {"state": "open", "per_page": 5}}),
        )
        .unwrap();
        assert_eq!(b.resource(), "acme/web");
        assert_eq!(b.op().capability, "read_repo");
        assert_eq!(b.req().method(), Method::Get);
        assert_eq!(b.req().host(), Host::Api);
        assert_eq!(
            b.req().path(),
            "/repos/acme/web/issues?per_page=5&state=open"
        );
        let b = build("github.get_pr", &json!({"repo": "acme/web", "number": 12})).unwrap();
        assert_eq!(b.req().path(), "/repos/acme/web/pulls/12");
    }

    #[test]
    fn a_file_path_is_encoded_per_segment() {
        let v = json!({"repo": "acme/web", "path": "docs/a b/é#?.md", "query": {"ref": "x/y"}});
        let b = build("github.read_file", &v).unwrap();
        assert_eq!(
            b.req().path(),
            "/repos/acme/web/contents/docs/a%20b/%C3%A9%23%3F.md?ref=x%2Fy"
        );
    }

    #[test]
    fn writes_need_a_body_and_pick_their_capability() {
        let b = build(
            "github.create_issue",
            &json!({"repo": "acme/web", "body": {"title": "t"}}),
        )
        .unwrap();
        assert_eq!(
            (b.op().capability, b.req().method()),
            ("issues_write", Method::Post)
        );
        assert_eq!(b.req().body().unwrap().bytes(), br#"{"title":"t"}"#);
        assert_eq!(
            build("github.create_issue", &json!({"repo": "acme/web"})).unwrap_err(),
            BuildError::Missing("body")
        );
        assert_eq!(
            build("github.get_repo", &json!({"repo": "acme/web", "body": {}})).unwrap_err(),
            BuildError::BadBody
        );
        assert_eq!(
            build(
                "github.comment_pr",
                &json!({"repo": "a/b", "number": 3, "body": {"body": "x"}})
            )
            .unwrap()
            .op
            .capability,
            "pr_write"
        );
        assert_eq!(
            build(
                "github.put_file",
                &json!({"repo": "a/b", "path": "x.txt", "body": {"message": "m"}})
            )
            .unwrap()
            .op
            .capability,
            "push"
        );
    }

    #[test]
    fn nothing_escapes_the_repository() {
        let r = |v: Value| build("github.get_repo", &v).unwrap_err();
        for repo in [
            "",
            "acme",
            "acme/",
            "/web",
            "acme/..",
            "acme/.",
            "../web",
            "a/b/c",
            "a/b?x",
            "a b/c",
            "a/b#",
            "a%2Fb/c",
            "a/b\\c",
            "acme/web\n",
            "-x/é",
        ] {
            let e = r(json!({"repo": repo}));
            assert_eq!(e, BuildError::BadRepo, "{repo:?}");
        }
        assert_eq!(
            r(json!({"repo": "a/b", "extra": 1})),
            BuildError::UnknownField
        );
        assert_eq!(r(json!({"repo": 7})), BuildError::BadRepo);
        for path in [
            "../x", "a/../x", "a/./x", "a//x", "/x", "a/", "%2e%2e/x", "a\\b", "",
        ] {
            let e = build("github.read_file", &json!({"repo": "a/b", "path": path}));
            // `%2e%2e` has no dot segment as a literal: it is encoded to `%252e`, harmless.
            if path == "%2e%2e/x" {
                assert!(e.unwrap().req().path().contains("%252e%252e"));
            } else {
                assert_eq!(e.unwrap_err(), BuildError::BadPath, "{path:?}");
            }
        }
        for n in [
            json!(0),
            json!(-1),
            json!("1/../2"),
            json!(1.5),
            json!(null),
        ] {
            assert_eq!(
                build("github.get_issue", &json!({"repo": "a/b", "number": n})).unwrap_err(),
                BuildError::BadNumber
            );
        }
        for q in [
            json!({"A": "x"}),
            json!({"a/b": "x"}),
            json!({"a": ["x"]}),
            json!("x"),
        ] {
            assert_eq!(
                build("github.get_repo", &json!({"repo": "a/b", "query": q})).unwrap_err(),
                BuildError::BadQuery
            );
        }
        assert_eq!(
            build("github.delete_repo", &json!({"repo": "a/b"})).unwrap_err(),
            BuildError::UnknownOperation
        );
        // A query value with every separator stays one value.
        let b = build(
            "github.get_repo",
            &json!({"repo": "a/b", "query": {"q": "x&y=1#../z"}}),
        )
        .unwrap();
        assert_eq!(b.req().path(), "/repos/a/b?q=x%26y%3D1%23..%2Fz");
    }

    #[test]
    fn every_operation_is_in_the_descriptor_under_its_capability() {
        let d = &super::super::GITHUB;
        for o in OPS {
            assert_eq!(
                d.capability_of(o.name).map(|c| c.name),
                Some(o.capability),
                "{}",
                o.name
            );
            assert!(o.path.starts_with("/repos/{owner}/{repo}"), "{}", o.name);
        }
        let listed: usize = d.capabilities.iter().map(|c| c.operations.len()).sum();
        assert_eq!(listed, OPS.len());
    }
}
