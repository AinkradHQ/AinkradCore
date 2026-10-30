//! Worktrees against local bare repos, with the user's git config kept out.

use std::os::unix::fs::PermissionsExt;
use std::process::Command as Std;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

/// A fresh dir by its real path (`/var` is `/private/var` on macOS).
pub(crate) fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("citadel-ws-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.canonicalize().unwrap()
}

/// `git args…` in `dir` for the test's own setup, with no user or system config.
pub(crate) fn git(dir: &Path, args: &[&str]) -> String {
    let out = Std::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(out.status.success(), "git {args:?}: {out:?}");
    String::from_utf8(out.stdout).unwrap()
}

/// A bare repo `origin.git` in `dir` with one commit on `main`.
pub(crate) fn origin(dir: &Path) -> String {
    let seed = dir.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q"]);
    std::fs::write(seed.join("README.md"), "hello\n").unwrap();
    git(&seed, &["add", "."]);
    git(&seed, &["commit", "-qm", "init"]);
    git(dir, &["clone", "-q", "--bare", "seed", "origin.git"]);
    dir.join("origin.git").display().to_string()
}

pub(crate) fn ws(repo: &str, n: i64) -> Workspace {
    Workspace {
        repo: repo.to_owned(),
        base: "main".to_owned(),
        branch: format!("citadel/CIT-{n}"),
        push: false,
        name: String::new(),
        also: vec![],
        expected_head: None,
    }
}

fn workspaces(dir: &Path) -> Workspaces {
    Workspaces::new(dir.join("work"), dir.join("git-home"))
}

#[test]
fn a_new_runner_reaps_session_worktrees_after_a_crash() {
    let dir = scratch("reap");
    let stale = dir.join("work/worktrees/sessions/as_stale");
    std::fs::create_dir_all(&stale).unwrap();
    assert!(stale.exists());
    let _ = workspaces(&dir);
    assert!(!stale.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A second run of an issue gets its worktree back as it was left; a deleted one is rebuilt
/// on the issue's branch, so its commits survive.
#[tokio::test]
async fn a_later_run_reuses_the_issue_worktree() {
    let dir = scratch("reuse");
    let repo = origin(&dir);
    let w = workspaces(&dir);

    let path = w.prepare(1, &[ws(&repo, 1)]).await.unwrap();
    assert_eq!(path, dir.join("work/worktrees/issue-1"));
    assert!(path.join("README.md").is_file());
    let head = git(&path, &["rev-parse", "--abbrev-ref", "HEAD"]);
    assert_eq!(head.trim(), "citadel/CIT-1");
    std::fs::write(path.join("notes.txt"), "half done").unwrap();
    w.release(1);

    assert_eq!(w.prepare(1, &[ws(&repo, 1)]).await.unwrap(), path);
    assert!(path.join("notes.txt").is_file(), "the worktree was rebuilt");
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "work"]);
    w.release(1);

    std::fs::remove_dir_all(&path).unwrap();
    assert_eq!(w.prepare(1, &[ws(&repo, 1)]).await.unwrap(), path);
    assert_eq!(
        std::fs::read_to_string(path.join("notes.txt")).unwrap(),
        "half done"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A push the remote refuses says why (the hook's reason), names the workflow files the
/// branch changes, and leaks nothing secret.
#[tokio::test]
async fn a_refused_push_carries_the_remote_reason() {
    let dir = scratch("push-refused");
    let repo = origin(&dir);
    let hook = PathBuf::from(&repo).join("hooks/pre-receive");
    std::fs::write(
        &hook,
        "#!/bin/sh\necho 'refusing to allow a token to update workflow without workflow scope' \
         >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    let w = workspaces(&dir);
    let path = w.prepare(1, &[ws(&repo, 1)]).await.unwrap();
    std::fs::create_dir_all(path.join(".github/workflows")).unwrap();
    std::fs::write(path.join(".github/workflows/images.yml"), "on: push\n").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "ci"]);
    let f = w.push(&ws(&repo, 1), Some("CIT-1")).await.unwrap_err();
    assert_eq!(f.rejected.len(), 1, "{f:?}");
    assert_eq!(f.rejected[0].0, "refs/heads/citadel/CIT-1");
    assert!(
        f.rejected[0].1.contains("pre-receive hook declined"),
        "{f:?}"
    );
    assert!(f.reason.contains("without workflow scope"), "{}", f.reason);
    assert_eq!(f.workflow_files, [".github/workflows/images.yml"]);
    let head = git(&path, &["rev-parse", "HEAD"]);
    assert_eq!(f.sha.as_deref(), Some(head.trim()));
    w.release(1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A branch with commits is pushed to origin (E9.1); one with nothing new is not.
#[tokio::test]
async fn pushes_the_issue_branch_to_origin() {
    let dir = scratch("push");
    let repo = origin(&dir);
    let w = workspaces(&dir);
    let path = w.prepare(1, &[ws(&repo, 1)]).await.unwrap();
    assert_eq!(
        w.push(&ws(&repo, 1), Some("CIT-1")).await.unwrap(),
        None,
        "nothing to push"
    );
    std::fs::write(path.join("feature.txt"), "done").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "feature"]);
    let sha = w
        .push(&ws(&repo, 1), Some("CIT-1"))
        .await
        .unwrap()
        .expect("pushed");
    let origin = PathBuf::from(&repo);
    let there = git(&origin, &["rev-parse", "refs/heads/citadel/CIT-1"]);
    assert_eq!(there.trim(), sha);
    // Again with nothing new: the same sha, no error.
    assert_eq!(
        w.push(&ws(&repo, 1), Some("CIT-1")).await.unwrap(),
        Some(sha)
    );
    w.release(1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A rewritten branch lands over the head the server last saw (`expected_head`), and never
/// over one it did not: a lease that does not match is refused, and no lease is a plain push.
#[tokio::test]
async fn a_rewritten_branch_lands_only_over_its_expected_head() {
    let dir = scratch("lease");
    let repo = origin(&dir);
    let w = workspaces(&dir);
    let path = w.prepare(1, &[ws(&repo, 1)]).await.unwrap();
    std::fs::write(path.join("a.txt"), "first").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "first"]);
    let first = w.push(&ws(&repo, 1), Some("CIT-1")).await.unwrap().unwrap();
    // Rewrite: the same work on a new commit off the base, which is not a fast-forward.
    git(&path, &["reset", "-q", "--hard", "HEAD~1"]);
    std::fs::write(path.join("a.txt"), "rewritten").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "rewritten"]);
    let rewritten = git(&path, &["rev-parse", "HEAD"]).trim().to_owned();
    let origin = PathBuf::from(&repo);

    let plain = w.push(&ws(&repo, 1), Some("CIT-1")).await.unwrap_err();
    assert!(
        plain.reason.contains("non-fast-forward") || plain.reason.contains("rejected"),
        "{plain:?}"
    );

    let stale = Workspace {
        expected_head: Some("0".repeat(40)),
        ..ws(&repo, 1)
    };
    let f = w.push(&stale, Some("CIT-1")).await.unwrap_err();
    assert!(f.reason.starts_with("remote branch moved"), "{f:?}");
    assert_eq!(
        git(&origin, &["rev-parse", "refs/heads/citadel/CIT-1"]).trim(),
        first
    );

    let leased = Workspace {
        expected_head: Some(first.clone()),
        ..ws(&repo, 1)
    };
    assert_eq!(
        w.push(&leased, Some("CIT-1")).await.unwrap(),
        Some(rewritten.clone())
    );
    assert_eq!(
        git(&origin, &["rev-parse", "refs/heads/citadel/CIT-1"]).trim(),
        rewritten
    );
    w.release(1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A push is only ever of the issue's own branch: another issue's, or none, is refused before
/// git runs, so the remote never sees it.
#[tokio::test]
async fn a_foreign_branch_is_refused_before_git_runs() {
    let dir = scratch("foreign");
    let repo = origin(&dir);
    let w = workspaces(&dir);
    let path = w.prepare(1, &[ws(&repo, 1)]).await.unwrap();
    std::fs::write(path.join("a.txt"), "x").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "x"]);
    let other = Workspace {
        branch: "citadel/CIT-2".to_owned(),
        ..ws(&repo, 1)
    };
    let f = w.push(&other, Some("CIT-1")).await.unwrap_err();
    assert!(f.reason.contains("not this issue's branch"), "{f:?}");
    assert!(f.rejected.is_empty() && f.sha.is_none(), "{f:?}");
    let f = w.push(&ws(&repo, 1), None).await.unwrap_err();
    assert!(f.reason.contains("not this issue's branch"), "{f:?}");
    let origin = PathBuf::from(&repo);
    let there = git(&origin, &["branch", "--list", "citadel/*"]);
    assert!(there.trim().is_empty(), "{there}");
    w.release(1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_branch_is_the_issue_only_when_the_key_is_a_whole_segment() {
    use super::push::is_issue_branch;
    assert!(is_issue_branch("citadel/CIT-1", "CIT-1"));
    assert!(is_issue_branch("feat/cit-1-add-login", "CIT-1"));
    assert!(!is_issue_branch("feat/cit-12", "CIT-1"));
    assert!(!is_issue_branch("feat/x-cit-1", "CIT-1"));
    assert!(!is_issue_branch("citadel/CIT-2", "CIT-1"));
    assert!(!is_issue_branch("main", "CIT-1"));
    assert!(!is_issue_branch("citadel/CIT-1", ""));
}

/// Pruning removes the worktree from disk and from git, but never one in use.
#[tokio::test]
async fn prune_removes_closed_worktrees_but_not_busy_ones() {
    let dir = scratch("prune");
    let repo = origin(&dir);
    let w = workspaces(&dir);
    for issue in [1, 2] {
        w.prepare(issue, &[ws(&repo, issue)]).await.unwrap();
    }
    w.release(1);
    assert_eq!(w.held(), vec![1, 2]);

    w.prune(vec![1, 2]).await;
    assert_eq!(w.held(), vec![2], "issue 2 is still in use");
    assert!(!w.path(1).exists());
    let mirror = w.mirror(&repo);
    let listed = git(&mirror, &["worktree", "list"]);
    assert!(!listed.contains("issue-1"), "{listed}");
    assert!(listed.contains("issue-2"), "{listed}");
    let branches = git(&mirror, &["branch", "--list", "citadel/*"]);
    assert!(branches.contains("citadel/CIT-1"), "the branch stays");

    w.release(2);
    w.prune(vec![2]).await;
    assert!(w.held().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn git_errors_surface_with_their_stderr() {
    let dir = scratch("errors");
    let w = workspaces(&dir);
    let missing = dir.join("nowhere.git").display().to_string();
    let why = w.prepare(1, &[ws(&missing, 1)]).await.unwrap_err();
    assert!(why.starts_with("git clone failed"), "{why}");
    assert!(why.contains("does not exist"), "{why}");
    assert!(!dir.join("work/mirrors/nowhere.cloning").exists());
    let repo = origin(&dir);
    let bad_base = Workspace {
        base: "trunk".to_owned(),
        ..ws(&repo, 1)
    };
    let why = w.prepare(1, &[bad_base]).await.unwrap_err();
    assert!(why.starts_with("git fetch failed"), "{why}");
    assert!(why.contains("trunk"), "{why}");
    let creds = ws("https://t0ken@example.com/a.git", 1);
    assert!(
        w.prepare(1, &[creds])
            .await
            .unwrap_err()
            .contains("credentials")
    );
    assert!(w.held().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

/// An HTTP server that answers every request `401 Basic`, keeping the requests' text.
async fn auth_wall() -> (String, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/private.git", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(String::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let (mut conn, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = conn.read(&mut buf).await.unwrap_or(0);
            log.lock()
                .unwrap()
                .push_str(&String::from_utf8_lossy(&buf[..n]));
            let reply = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"r\"\r\n\
                         Content-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = conn.write_all(reply.as_bytes()).await;
        }
    });
    (url, seen)
}

fn script(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A repo that needs auth: without an askpass the run fails saying so; with one, the
/// credentials travel by the askpass and the HTTP header only, never in git's argv.
#[tokio::test]
async fn credentials_come_from_the_askpass_and_never_from_argv() {
    let dir = scratch("auth");
    let (url, seen) = auth_wall().await;
    let mut w = workspaces(&dir);
    let argv = dir.join("argv.log");
    let shim = dir.join("git-shim");
    script(
        &shim,
        &format!(
            "printf '%s\\n' \"$@\" >> {}\nexec git \"$@\"",
            argv.display()
        ),
    );
    w.git = shim;

    let why = w.prepare(1, &[ws(&url, 1)]).await.unwrap_err();
    assert!(
        why.contains("needs credentials and this runner has none"),
        "{why}"
    );

    let askpass = dir.join("askpass");
    script(
        &askpass,
        "case \"$1\" in Username*) echo citadel ;; *) echo s3cr3t ;; esac",
    );
    w.askpass = Some(askpass);
    let why = w.prepare(1, &[ws(&url, 1)]).await.unwrap_err();
    assert!(why.contains("Authentication failed"), "{why}");
    // base64("citadel:s3cr3t")
    let requests = seen.lock().unwrap().clone();
    assert!(
        requests.contains("Basic Y2l0YWRlbDpzM2NyM3Q="),
        "{requests}"
    );
    let argv = std::fs::read_to_string(&argv).unwrap();
    assert!(argv.contains(&url), "{argv}");
    assert!(
        !argv.contains("s3cr3t") && !argv.contains("citadel@"),
        "{argv}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// No identity, no start; once set, an agent's commit in its worktree carries it, read from
/// the runner-owned config the way a harness's git reads it (its env, a stranger's `HOME`).
#[tokio::test]
async fn agent_commits_carry_the_runner_identity() {
    let dir = scratch("identity");
    let repo = origin(&dir);
    let w = workspaces(&dir);
    let why = w.set_identity(None, None).await.unwrap_err();
    assert!(why.contains("--git-name"), "{why}");
    assert!(w.set_identity(Some("a\nb"), Some("x@y")).await.is_err());

    let set = w.set_identity(Some("Citadel Bot"), Some("bot@citadel.lan"));
    let expected = ("Citadel Bot".to_owned(), "bot@citadel.lan".to_owned());
    assert_eq!(set.await.unwrap(), expected);
    // Later starts read it back from the file.
    assert_eq!(w.set_identity(None, None).await.unwrap(), expected);

    let path = w.prepare(1, &[ws(&repo, 1)]).await.unwrap();
    std::fs::write(path.join("agent.txt"), "done").unwrap();
    let agent_git = |args: &[&str]| {
        let out = Std::new("git")
            .args(args)
            .current_dir(&path)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", dir.join("agent-home"))
            .envs(w.env())
            .output()
            .unwrap();
        assert!(out.status.success(), "git {args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    };
    agent_git(&["add", "."]);
    agent_git(&["commit", "-qm", "agent work"]);
    let author = agent_git(&["log", "-1", "--format=%an <%ae> / %cn <%ce>"]);
    assert_eq!(
        author.trim(),
        "Citadel Bot <bot@citadel.lan> / Citadel Bot <bot@citadel.lan>"
    );
    w.release(1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An issue that gains a second repo (E15.16) gets a worktree per repo under its dir, on the
/// same branch, with the first repo's uncommitted work carried over; each pushes on its own;
/// the diff counts both, each sized on its own; prune removes both.
#[tokio::test]
async fn a_second_repo_nests_both_worktrees_and_keeps_the_work() {
    let dir = scratch("multi");
    let core = origin(&dir);
    let other = dir.join("other");
    std::fs::create_dir_all(&other).unwrap();
    let plugin = origin(&other);
    let w = workspaces(&dir);
    let one = Workspace {
        name: "core".to_owned(),
        ..ws(&core, 1)
    };
    let path = w.prepare(1, std::slice::from_ref(&one)).await.unwrap();
    std::fs::write(path.join("draft.txt"), "half done").unwrap();
    w.release(1);

    let two = [
        one.clone(),
        Workspace {
            name: "plugin".to_owned(),
            ..ws(&plugin, 1)
        },
    ];
    assert_eq!(w.prepare(1, &two).await.unwrap(), path);
    let (c, p) = (path.join("core"), path.join("plugin"));
    assert!(c.join(".git").is_file() && p.join(".git").is_file());
    assert_eq!(
        std::fs::read_to_string(c.join("draft.txt")).unwrap(),
        "half done"
    );
    for tree in [&c, &p] {
        let head = git(tree, &["rev-parse", "--abbrev-ref", "HEAD"]);
        assert_eq!(head.trim(), "citadel/CIT-1");
    }
    std::fs::write(p.join("client.txt"), "x").unwrap();
    assert_eq!(w.diff_files(1, &two).await.unwrap(), 2);
    git(&p, &["add", "."]);
    git(
        &p,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qm",
            "client",
        ],
    );
    // Each repo's size (1.18): core's new file, plugin's committed one.
    let stats = w.diff_stats(1, &two).await.unwrap();
    let sizes: Vec<_> = stats
        .iter()
        .map(|d| (d.repo.as_str(), d.files, d.insertions, d.deletions))
        .collect();
    assert_eq!(sizes, [("core", 1, 1, 0), ("plugin", 1, 1, 0)]);
    w.release(1);
    assert_eq!(
        w.push(&two[0], Some("CIT-1")).await.unwrap(),
        None,
        "nothing committed in core"
    );
    assert!(w.push(&two[1], Some("CIT-1")).await.unwrap().is_some());
    git(
        Path::new(&plugin),
        &["rev-parse", "--verify", "refs/heads/citadel/CIT-1"],
    );

    w.prune(vec![1]).await;
    assert!(!path.exists());
    assert!(w.held().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn agent_sessions_get_private_worktrees_and_cleanup() {
    let dir = scratch("sessions");
    let repo = origin(&dir);
    let w = workspaces(&dir);
    let request = |session: &str| SessionWorkspace {
        repo: repo.clone(),
        reference: "main".to_owned(),
        branch: format!("agent/{session}"),
        name: String::new(),
    };
    let first = w
        .prepare_session("as_first", &[request("first")])
        .await
        .unwrap();
    let second = w
        .prepare_session("as_second", &[request("second")])
        .await
        .unwrap();
    assert_ne!(first, second);
    assert!(first.join(".git").is_file());
    assert!(second.join(".git").is_file());
    std::fs::write(first.join("private.txt"), "one").unwrap();
    assert!(!second.join("private.txt").exists());
    w.cleanup_session("as_first").await.unwrap();
    assert!(!first.exists());
    assert!(second.join(".git").is_file());
    w.cleanup_session("as_second").await.unwrap();
    assert!(!second.exists());
}

#[test]
fn session_and_git_inputs_reject_traversal_and_special_transports() {
    assert!(ainkrad_proto::runner::repo_url_problem("file:///tmp/repo").is_some());
    assert!(ainkrad_proto::runner::repo_url_problem("ext::sh -c evil").is_some());
    assert!(ainkrad_proto::runner::repo_url_problem("../outside").is_some());
    assert!(!ainkrad_proto::runner::branch_name_ok("--upload-pack=evil"));
    assert!(!ainkrad_proto::runner::branch_name_ok("refs/heads/../main"));
    assert!(!ainkrad_proto::runner::branch_name_ok(
        "refs/heads/main@{0}"
    ));
}

mod layout;

mod read;
