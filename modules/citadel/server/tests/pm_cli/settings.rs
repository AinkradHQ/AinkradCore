//! `citadel-server setting …` (E15.17): list, get, set, reset and history, with a scope, and
//! the refusals.

use crate::{cli, db, ok};

#[test]
fn settings_are_set_per_scope_refused_reset_and_their_history_listed() {
    let db = db("settings");
    let c = ok(&db, &["company", "add", "A"]);
    let p = ok(&db, &["project", "add", &c, "CIT", "Citadel"]);
    let (company, project) = (format!("company:{c}"), format!("project:{p}"));
    let list = ok(&db, &["setting", "list"]);
    assert!(
        list.lines().any(|l| l
            == "run.stuck_after_secs\t600\tseconds\tdefault\t60..=604800\tserver,company,project"),
        "{list}"
    );
    let key = "run.stuck_after_secs";
    ok(&db, &["setting", "set", key, "1200", "--scope", &company]);
    let got = ok(&db, &["setting", "get", key, "--scope", &project]);
    assert!(
        got.starts_with(&format!("{key}\t1200\tseconds\t{company}\t")),
        "{got}"
    );
    ok(&db, &["setting", "set", key, "300", "--scope", &project]);
    let got = ok(&db, &["setting", "get", key, "--scope", &project]);
    assert!(
        got.starts_with(&format!("{key}\t300\tseconds\t{project}")),
        "{got}"
    );
    for (args, why) in [
        (
            vec!["setting", "set", key, "5", "--scope", &project],
            "out of bounds",
        ),
        (
            vec!["setting", "set", key, "300", "--scope", "runner:1"],
            "cannot be set per runner",
        ),
        (vec!["setting", "set", "no.such", "1"], "no setting"),
        (
            vec!["setting", "set", key, "300", "--scope", "project:99"],
            "no project:99",
        ),
    ] {
        let e = cli(&db, &args).unwrap_err();
        assert!(e.contains(why), "{args:?}: {e}");
    }
    let reset = ok(&db, &["setting", "reset", key, "--scope", &project]);
    assert!(
        reset.starts_with(&format!("{key}\t1200\tseconds\t{company}")),
        "{reset}"
    );
    let history = ok(&db, &["setting", "history", key]);
    let lines: Vec<&str> = history.lines().collect();
    assert_eq!(lines.len(), 3, "{history}");
    assert!(
        lines[0].contains(&format!("{project}\t300 -> inherited")),
        "{history}"
    );
    assert!(
        lines[2].contains(&format!("{company}\tinherited -> 1200")),
        "{history}"
    );
    let only = ok(&db, &["setting", "history", key, "--scope", &company]);
    assert_eq!(only.lines().count(), 1);
    // The old approval command writes the same setting.
    ok(&db, &["approval", "deadline", "pr_merge", "3600"]);
    let got = ok(&db, &["setting", "get", "approval.deadline.pr_merge"]);
    assert!(
        got.starts_with("approval.deadline.pr_merge\t3600\tseconds\tserver"),
        "{got}"
    );
}
