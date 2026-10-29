//! The plan's Mac runner acceptance (E3.11): a Swift package build job runs end to end on a
//! `macos`-tagged runner, in the issue's git worktree, through a process-style fake harness
//! (a shell script running `swift build`). Live: it needs a Mac with Swift, so it runs only
//! with `CITADEL_LIVE_MAC=1`. The build runs with a temp `HOME`, never the user's.

use std::path::{Path, PathBuf};
use std::process::Command;

use citadel_core::exec::RunState;
use citadel_core::work::ProjectRepo;
use citadel_server::store::exec::{get_run, list_run_events, list_runs};
use citadel_server::store::work::set_project_repo;
use ainkrad_proto::runner::{Outcome, RunToken};
use ainkrad_runner::{Executor, Job, Report, Workspaces, mac};
use tokio::sync::mpsc;

use super::support::*;
use crate::harness::{agent, assign, company, issue, runner};

/// Runs `script` with `sh` in the job's worktree, from a cleared environment.
struct Script {
    workspaces: Workspaces,
    script: PathBuf,
    home: PathBuf,
}

impl Executor for Script {
    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        let (Some(_), Some(issue)) = (&job.workspace, job.issue) else {
            return Err("a build job needs a worktree".to_owned());
        };
        self.workspaces
            .prepare(issue, &job.trees())
            .await
            .map(|_| None)
    }

    async fn run(&self, job: &Job, _: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        let issue = job.issue.expect("an issue");
        let out = tokio::process::Command::new("/bin/sh")
            .arg(&self.script)
            .current_dir(self.workspaces.path(issue))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.home)
            .envs(self.workspaces.env())
            .output()
            .await;
        self.workspaces.release(issue);
        let out = match out {
            Ok(out) => out,
            Err(e) => {
                let reason = format!("sh: {e}");
                return Outcome::Failed {
                    reason,
                    fingerprint: None,
                };
            }
        };
        let log = String::from_utf8_lossy(&out.stdout).into_owned();
        let chunk = serde_json::json!({"type": "process_output", "text": log});
        let _ = reports.send(Report::Event(chunk)).await;
        match out.status.success() {
            true => Outcome::Succeeded,
            false => Outcome::Failed {
                reason: format!(
                    "swift build failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                ),
                fingerprint: Some("swift_build".to_owned()),
            },
        }
    }
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
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
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

/// A bare repo in `dir` holding a one-file Swift package on `main`.
fn swift_package(dir: &Path) -> String {
    let seed = dir.join("seed");
    std::fs::create_dir_all(seed.join("Sources/Hello")).unwrap();
    std::fs::write(
        seed.join("Package.swift"),
        "// swift-tools-version: 5.9\nimport PackageDescription\n\n\
         let package = Package(name: \"Hello\", targets: [.executableTarget(name: \"Hello\")])\n",
    )
    .unwrap();
    std::fs::write(
        seed.join("Sources/Hello/main.swift"),
        "print(\"hello from citadel\")\n",
    )
    .unwrap();
    git(&seed, &["init", "-q"]);
    git(&seed, &["add", "."]);
    git(&seed, &["commit", "-qm", "package"]);
    git(dir, &["clone", "-q", "--bare", "seed", "origin.git"]);
    dir.join("origin.git").display().to_string()
}

#[tokio::test]
async fn a_swift_package_builds_on_the_mac_runner() {
    if std::env::var("CITADEL_LIVE_MAC").as_deref() != Ok("1") {
        eprintln!("skipped: set CITADEL_LIVE_MAC=1 on a Mac with Swift");
        return;
    }
    let dir = std::env::temp_dir().join(format!("citadel-live-mac-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("home")).unwrap();
    let dir = dir.canonicalize().unwrap();
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let builder = agent(pool, c, "Builder", &["macos"], None).await;
    let repo = ProjectRepo {
        project_id: p,
        url: swift_package(&dir),
        default_branch: "main".to_owned(),
    };
    set_project_repo(pool, &repo).await.unwrap();
    let i = issue(pool, p).await;
    assign(pool, i, builder).await;
    runner(pool, "mac", &[]).await;

    std::fs::write(dir.join("build.sh"), "swift build 2>&1\n").unwrap();
    let executor = Script {
        workspaces: Workspaces::new(dir.join("work"), dir.join("git-home")),
        script: dir.join("build.sh"),
        home: dir.join("home"),
    };
    let tags = mac::default_tags();
    assert!(tags.contains(&"macos".to_owned()), "{tags:?}");
    let tags: Vec<&str> = tags.iter().map(String::as_str).collect();
    stack.runner("mac", &tags, executor);

    let ended = "SELECT count(*) FROM runs WHERE state IN ('succeeded', 'failed')";
    for _ in 0..300 {
        if crate::harness::count(pool, ended).await > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    let run = list_runs(pool, builder).await.unwrap().remove(0);
    let run = get_run(pool, run.id).await.unwrap().unwrap();
    assert_eq!(run.state, RunState::Succeeded, "{:?}", run.terminal_reason);
    let log = list_run_events(pool, run.id).await.unwrap();
    let text = log[0].payload["text"].as_str().unwrap();
    eprintln!("swift build on the mac runner:\n{text}");
    assert!(text.contains("Build complete"), "{text}");
    let worktree = dir.join(format!("work/worktrees/issue-{}", i.0));
    assert!(worktree.join(".build").is_dir());
    let branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(&worktree)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&branch.stdout).starts_with("citadel/"));
    let _ = std::fs::remove_dir_all(&dir);
}
