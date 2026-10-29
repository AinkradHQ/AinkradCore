//! Disk (E15.9), in temp dirs against local bare repos: one build cache per repo, idle
//! worktrees removed and recreated with their work, the cap enforced oldest idle first and
//! never on a worktree in use, and the report's numbers. Time is passed in.

use std::time::{Duration, SystemTime};

use ainkrad_proto::runner::RunnerLimits;

use super::super::tests::{git, origin, scratch, ws};
use super::*;

const DAY: Duration = Duration::from_secs(86_400);

fn workspaces(dir: &Path) -> Workspaces {
    Workspaces::new(dir.join("work"), dir.join("git-home"))
}

/// A bare `origin.git` in `dir` holding a Rust crate on `main`.
fn rust_origin(dir: &Path) -> String {
    let seed = dir.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q"]);
    std::fs::write(seed.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    git(&seed, &["add", "."]);
    git(&seed, &["commit", "-qm", "init"]);
    git(dir, &["clone", "-q", "--bare", "seed", "origin.git"]);
    dir.join("origin.git").display().to_string()
}

fn limits(cap: u64) -> RunnerLimits {
    RunnerLimits {
        disk_cap_bytes: cap,
        disk_evict_percent: 100,
        workspace_idle_secs: DAY.as_secs(),
        warm_idle_secs: 900,
    }
}

/// Marks the issue's worktree last used `ago` before now.
fn used(w: &Workspaces, issue: i64, ago: Duration) {
    let marker = std::fs::File::options()
        .write(true)
        .open(w.marker(issue))
        .unwrap();
    marker.set_modified(SystemTime::now() - ago).unwrap();
}

fn var(env: &[(String, OsString)], name: &str) -> Option<PathBuf> {
    env.iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| PathBuf::from(v))
}

#[tokio::test]
async fn twenty_issues_of_one_rust_repo_share_one_target_dir() {
    let dir = scratch("disk-share");
    let repo = rust_origin(&dir);
    let w = workspaces(&dir);
    let mut targets = vec![];
    for issue in 1..=20 {
        w.prepare(issue, &[ws(&repo, issue)]).await.unwrap();
        let env = w.cache_env(issue, &[ws(&repo, issue)]);
        targets.push(var(&env, "CARGO_TARGET_DIR").expect("a Rust repo"));
        assert_eq!(var(&env, "npm_config_cache"), None, "not a node repo");
        w.release(issue);
    }
    targets.dedup();
    assert_eq!(targets.len(), 1, "one target dir: {targets:?}");
    assert!(
        targets[0].starts_with(dir.join("work/caches")),
        "{targets:?}"
    );
    assert!(!targets[0].starts_with(dir.join("work/worktrees")));

    // Another repo gets its own.
    let other = dir.join("other");
    std::fs::create_dir_all(&other).unwrap();
    let repo2 = rust_origin(&other);
    w.prepare(21, &[ws(&repo2, 21)]).await.unwrap();
    let env = w.cache_env(21, &[ws(&repo2, 21)]);
    assert_ne!(var(&env, "CARGO_TARGET_DIR").unwrap(), targets[0]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn an_idle_worktree_goes_and_comes_back_with_its_commits_and_its_uncommitted_work() {
    let dir = scratch("disk-idle");
    let repo = origin(&dir);
    let w = workspaces(&dir);
    let path = w.prepare(1, &[ws(&repo, 1)]).await.unwrap();
    std::fs::write(path.join("done.txt"), "committed").unwrap();
    git(&path, &["add", "."]);
    git(&path, &["commit", "-qm", "work"]);
    std::fs::write(path.join("README.md"), "edited, not committed\n").unwrap();
    std::fs::write(path.join("draft.txt"), "new, not committed").unwrap();
    w.release(1);

    // Not idle long enough.
    let report = w.gc(SystemTime::now() + DAY / 2, &limits(u64::MAX)).await;
    assert!(report.removed.is_empty() && path.exists());
    let report = w.gc(SystemTime::now() + DAY * 2, &limits(u64::MAX)).await;
    assert_eq!(report.removed, vec![1]);
    assert!(!path.exists(), "removed");
    assert_eq!(w.held(), Vec::<i64>::new());
    let mirror = dir.join("work/mirrors").read_dir().unwrap().next().unwrap();
    let mirror = mirror.unwrap().path();
    git(&mirror, &["rev-parse", "--verify", "refs/citadel/wip/1"]);
    let branch = git(&mirror, &["log", "--format=%s", "citadel/CIT-1"]);
    assert!(
        branch.starts_with("work\n"),
        "the branch is unmoved: {branch}"
    );

    // Recreated on demand: the commit from the branch, the rest as uncommitted changes.
    let again = w.prepare(1, &[ws(&repo, 1)]).await.unwrap();
    assert_eq!(again, path);
    assert_eq!(
        std::fs::read_to_string(path.join("done.txt")).unwrap(),
        "committed"
    );
    assert_eq!(
        std::fs::read_to_string(path.join("README.md")).unwrap(),
        "edited, not committed\n"
    );
    let status = git(&path, &["status", "--porcelain"]);
    assert!(status.contains(" M README.md"), "{status}");
    assert!(status.contains("?? draft.txt"), "{status}");
    assert!(
        git(&mirror, &["for-each-ref", "refs/citadel/wip"]).is_empty(),
        "the ref is dropped once restored"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_cap_evicts_the_oldest_idle_worktree_never_one_in_use() {
    let dir = scratch("disk-cap");
    let repo = origin(&dir);
    let w = workspaces(&dir);
    for issue in 1..=3 {
        let path = w.prepare(issue, &[ws(&repo, issue)]).await.unwrap();
        std::fs::write(path.join("big.bin"), vec![0u8; 1_000_000]).unwrap();
        git(&path, &["add", "."]);
        git(&path, &["commit", "-qm", "big"]);
    }
    w.release(1);
    w.release(2);
    used(&w, 1, Duration::from_secs(3 * 3600));
    used(&w, 2, Duration::from_secs(3600));
    // Issue 3 is in use.
    let now = SystemTime::now();
    let before = w.gc(now, &limits(u64::MAX)).await;
    assert!(before.removed.is_empty());
    let order: Vec<i64> = before.worktrees.iter().map(|w| w.issue).collect();
    assert_eq!(order, vec![1, 2, 3], "oldest use first");
    assert!(before.worktrees[2].active && !before.worktrees[0].active);

    // Room for all but about one worktree: the oldest idle goes.
    let cap = before.used_bytes - 500_000;
    let after = w.gc(now, &limits(cap)).await;
    assert_eq!(after.removed, vec![1]);
    assert!(!after.full);
    assert!(after.used_bytes <= cap);

    // No room at all: every idle one goes, never the one in use, and the disk is full.
    let full = w.gc(now, &limits(1)).await;
    assert_eq!(full.removed, vec![2]);
    assert!(full.full);
    assert!(w.path(3).join("big.bin").exists(), "in use: never evicted");
    assert_eq!(w.held(), vec![3]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn the_report_splits_caches_mirrors_and_worktrees() {
    let dir = scratch("disk-report");
    let repo = rust_origin(&dir);
    let w = workspaces(&dir);
    w.prepare(1, &[ws(&repo, 1)]).await.unwrap();
    let env = w.cache_env(1, &[ws(&repo, 1)]);
    let target = var(&env, "CARGO_TARGET_DIR").unwrap();
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("lib.rlib"), vec![1u8; 300_000]).unwrap();
    std::fs::write(w.path(1).join("notes.txt"), vec![b'x'; 50_000]).unwrap();

    let r = w.gc(SystemTime::now(), &limits(10_000_000)).await;
    assert_eq!(r.caches_bytes, 300_000);
    assert!(r.mirrors_bytes > 0);
    assert_eq!(r.worktrees.len(), 1);
    let tree = &r.worktrees[0];
    assert!(tree.active && tree.bytes >= 50_000, "{tree:?}");
    assert!(r.used_bytes >= r.caches_bytes + r.mirrors_bytes + tree.bytes);
    assert_eq!((r.cap_bytes, r.full), (10_000_000, false));

    // Over the cap with only the in-use repo's cache and worktree: nothing to evict.
    let r = w.gc(SystemTime::now(), &limits(1_000)).await;
    assert!(r.full && r.removed.is_empty());
    assert!(
        target.join("lib.rlib").exists(),
        "its repo's worktree is in use"
    );
    // Once idle, its worktree goes first, then its cache.
    w.release(1);
    let r = w.gc(SystemTime::now(), &limits(1_000)).await;
    assert_eq!(r.removed, vec![1]);
    assert!(!target.exists(), "the cache went last");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two Rust repos in one issue (E15.16) each build into their own cache: no process-wide
/// `CARGO_TARGET_DIR`, a `target` link per worktree that git does not see, and per-repo
/// variables for the other kinds.
#[tokio::test]
async fn two_rust_repos_in_one_issue_each_get_their_own_target_dir() {
    let dir = scratch("disk-two");
    let a = rust_origin(&dir);
    let other = dir.join("other");
    std::fs::create_dir_all(&other).unwrap();
    let b = rust_origin(&other);
    let w = workspaces(&dir);
    let trees = [
        Workspace {
            name: "core".to_owned(),
            ..ws(&a, 1)
        },
        Workspace {
            name: "plugin-x".to_owned(),
            ..ws(&b, 1)
        },
    ];
    w.prepare(1, &trees).await.unwrap();
    let env = w.cache_env(1, &trees);
    assert_eq!(
        var(&env, "CARGO_TARGET_DIR"),
        None,
        "one value cannot serve both"
    );
    let target = |name: &str| std::fs::read_link(w.path(1).join(name).join("target")).unwrap();
    let (ta, tb) = (target("core"), target("plugin-x"));
    assert_ne!(ta, tb);
    assert!(ta.starts_with(dir.join("work/caches")), "{ta:?}");
    let caches = (
        var(&env, "CITADEL_BUILD_CACHE_CORE").unwrap(),
        var(&env, "CITADEL_BUILD_CACHE_PLUGIN_X").unwrap(),
    );
    assert_ne!(caches.0, caches.1);
    assert_eq!(ta, caches.0.join("cargo-target"));
    for name in ["core", "plugin-x"] {
        let status = git(&w.path(1).join(name), &["status", "--porcelain"]);
        assert!(status.is_empty(), "the link is not a change: {status}");
    }
    assert_eq!(w.diff_files(1, &trees).await.unwrap(), 0);
    // Asked again: the links stay, the exclude line is not repeated.
    w.cache_env(1, &trees);
    let mirror = w.mirror(&a).join("info/exclude");
    let text = std::fs::read_to_string(mirror).unwrap();
    assert_eq!(text.matches("/target").count(), 1, "{text}");
    w.release(1);
    let _ = std::fs::remove_dir_all(&dir);
}
