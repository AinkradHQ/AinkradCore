//! PR 321 review: a project run's clone is deleted, not saved under `session-wip` (which nothing
//! ever cleans), and the runner start sweeps what a crash left.
use super::*;

fn put(dir: &Path, rel: &str) {
    std::fs::create_dir_all(dir.join("work").join(rel)).unwrap();
    std::fs::write(dir.join("work").join(rel).join("f"), "x").unwrap();
}

#[test]
fn discarding_run_sessions_removes_live_and_saved_dirs_and_spares_the_rest() {
    let dir = scratch("discard-run");
    for rel in [
        "worktrees/sessions/as_run1abc/0",
        "session-wip/as_run1abc/0",
        "worktrees/sessions/as_run2def/0",
        "worktrees/sessions/as_agent/1",
        "session-wip/as_agent/1",
    ] {
        put(&dir, rel);
    }
    let w = workspaces(&dir);
    // One run only (its whole id is the prefix).
    w.discard_sessions("as_run1abc", false, &[]);
    assert!(!dir.join("work/worktrees/sessions/as_run1abc").exists());
    assert!(!dir.join("work/session-wip/as_run1abc").exists());
    assert!(dir.join("work/worktrees/sessions/as_run2def").exists());
    // Exact: `as_run1` is not a prefix match of `as_run1abc`'s sibling `as_run1abcd`.
    put(&dir, "worktrees/sessions/as_run1abcd/0");
    w.discard_sessions("as_run1abc", false, &[]);
    assert!(dir.join("work/worktrees/sessions/as_run1abcd").exists());
    // The start sweep: every run clone, but not one a session adopted.
    w.discard_sessions("as_run", true, &["as_run2def".to_owned()]);
    assert!(dir.join("work/worktrees/sessions/as_run2def").exists());
    w.discard_sessions("as_run", true, &[]);
    assert!(!dir.join("work/worktrees/sessions/as_run2def").exists());
    assert!(dir.join("work/worktrees/sessions/as_agent/1/f").exists());
    assert!(dir.join("work/session-wip/as_agent/1/f").exists());
}
