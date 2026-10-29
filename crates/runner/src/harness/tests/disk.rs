//! Shared build caches through the harness (E15.9): 20 runs, each on its own issue of one Rust
//! repo, see one `CARGO_TARGET_DIR` in their environment, under the runner's caches.

use crate::workspace::tests::{git, ws};

use super::*;

#[tokio::test]
async fn twenty_runs_on_one_rust_repo_build_into_one_target_dir() {
    let dir = scratch("disk-env").canonicalize().unwrap();
    let seed = dir.join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    git(&seed, &["init", "-q"]);
    std::fs::write(seed.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
    git(&seed, &["add", "."]);
    git(&seed, &["commit", "-qm", "init"]);
    git(&dir, &["clone", "-q", "--bare", "seed", "origin.git"]);
    let repo = dir.join("origin.git").display().to_string();

    std::fs::write(dir.join("fixture.ndjson"), FIXTURE).unwrap();
    let bin = dir.join("claude");
    let d = dir.display();
    let script = format!(
        "#!/bin/sh\necho \"$CARGO_TARGET_DIR\" >> {d}/targets\nhead -n 2 > /dev/null\n\
         sed '/\"type\":\"result\"/q' {d}/fixture.ndjson\n"
    );
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut ex = HarnessExecutor::new(dir.join("work"), dir.join("config"));
    ex.bins.insert("claude".to_owned(), bin);
    ex.approval_timeout = Duration::from_millis(10);
    for n in 1..=20 {
        let job = Job {
            run: n,
            issue: Some(n),
            workspace: Some(ws(&repo, n)),
            ..job("claude")
        };
        ex.start(&job).await.unwrap();
        let (tx, _rx) = mpsc::channel(1024);
        ex.run(&job, RunToken::new("t".to_owned()), tx).await;
    }
    let targets = std::fs::read_to_string(dir.join("targets")).unwrap();
    let mut seen: Vec<&str> = targets.lines().collect();
    assert_eq!(seen.len(), 20, "{targets}");
    seen.dedup();
    assert_eq!(seen.len(), 1, "one target dir: {seen:?}");
    let caches = dir.join("work/caches");
    assert!(seen[0].starts_with(caches.to_str().unwrap()), "{seen:?}");
    assert_eq!(ex.workspaces(), (1..=20).collect::<Vec<_>>());
    let _ = std::fs::remove_dir_all(&dir);
}
