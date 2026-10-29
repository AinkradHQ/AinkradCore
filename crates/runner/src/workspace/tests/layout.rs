//! Layout changes (E15.16) keep every file: a worktree moves whole into the multi-repo layout,
//! git-ignored and loose files included; loose top-level files come back at the top of the
//! single layout, or to the preserved folder when the repo has a file of that name.

use super::*;

fn named(name: &str, repo: &str) -> Workspace {
    Workspace {
        name: name.to_owned(),
        ..ws(repo, 1)
    }
}

#[tokio::test]
async fn loose_and_ignored_files_survive_every_layout_change() {
    let dir = scratch("relayout");
    let core = origin(&dir);
    let other = dir.join("other");
    std::fs::create_dir_all(&other).unwrap();
    let plugin = origin(&other);
    let w = workspaces(&dir);
    let one = [named("core", &core)];
    let path = w.prepare(1, &one).await.unwrap();
    std::fs::write(path.join(".gitignore"), "secret.env\n").unwrap();
    std::fs::write(path.join("secret.env"), "TOKEN=x").unwrap();
    std::fs::write(path.join("notes.md"), "loose").unwrap();
    w.release(1);

    // Single → multi-repo: the worktree moves whole, ignored file and all.
    let two = [named("core", &core), named("plugin", &plugin)];
    w.prepare(1, &two).await.unwrap();
    let c = path.join("core");
    for (file, text) in [("secret.env", "TOKEN=x"), ("notes.md", "loose")] {
        assert_eq!(
            std::fs::read_to_string(c.join(file)).unwrap(),
            text,
            "{file}"
        );
    }
    assert!(path.join("plugin/.git").is_file());
    // Loose files at the top of the multi-repo layout.
    std::fs::write(path.join("plan.txt"), "top").unwrap();
    std::fs::write(path.join("README.md"), "mine").unwrap();
    w.release(1);

    // Multi-repo → single: the core worktree moves up; loose files stay on top.
    w.prepare(1, &one).await.unwrap();
    assert!(path.join(".git").is_file() && !path.join("plugin").exists());
    assert_eq!(
        std::fs::read_to_string(path.join("plan.txt")).unwrap(),
        "top"
    );
    assert_eq!(
        std::fs::read_to_string(path.join("secret.env")).unwrap(),
        "TOKEN=x"
    );
    assert_eq!(
        std::fs::read_to_string(path.join("README.md")).unwrap(),
        "hello\n"
    );
    let kept = dir.join("work/preserved/issue-1/README.md");
    assert_eq!(
        std::fs::read_to_string(kept).unwrap(),
        "mine",
        "never overwritten"
    );
    let status = git(&path, &["status", "--porcelain"]);
    assert!(status.contains("?? plan.txt"), "{status}");
    assert!(!dir.join("work/worktrees/.relayout/issue-1").exists());
    w.release(1);
    let _ = std::fs::remove_dir_all(&dir);
}
