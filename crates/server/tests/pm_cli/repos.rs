//! The repo commands (E15.16): add two repos, list them, set an issue's repos.

use std::process::Command;

use crate::{Db, db, ok};

/// `ainkrad-core-server <words…> <db> <rest…>`: stdout, or stderr on failure.
fn run(db: &Db, words: &[&str], rest: &[&str]) -> Result<String, String> {
    let out = Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(words)
        .arg(&db.0)
        .args(rest)
        .output()
        .unwrap();
    match out.status.success() {
        true => Ok(String::from_utf8(out.stdout).unwrap().trim().to_owned()),
        false => Err(String::from_utf8(out.stderr).unwrap()),
    }
}

#[test]
fn adds_lists_and_assigns_repos() {
    let db = db("repos");
    let c = ok(&db, &["company", "add", "A"]);
    let p = ok(
        &db,
        &[
            "project",
            "add",
            &c,
            "REP",
            "Repos",
            "--repo",
            "/srv/core.git",
        ],
    );
    let forge = [
        "--forge",
        "gitlab",
        "--forge-repo",
        "acme/app",
        "--token-file",
        "/etc/t",
    ];
    let app = run(
        &db,
        &["repo", "add"],
        &[
            &[p.as_str(), "app", "/srv/app.git", "--test", "make test"][..],
            &forge[..],
        ]
        .concat(),
    )
    .unwrap();
    let listed = run(&db, &["repo", "list"], &[&p]).unwrap();
    let lines: Vec<&str> = listed.lines().collect();
    assert!(
        lines[0].ends_with("\trep\t/srv/core.git\tmain\t-\tprimary"),
        "{listed}"
    );
    assert_eq!(
        lines[1],
        format!("{app}\tapp\t/srv/app.git\tmain\tgitlab acme/app")
    );
    let issue = ok(&db, &["issue", "add", &p, "Both"]);
    let set = run(&db, &["issue", "repos"], &[&issue, "app", "rep"]).unwrap();
    assert_eq!(set, "rep app");
    assert!(
        run(&db, &["repo", "remove"], &[&app]).is_err(),
        "an open issue touches it"
    );
    assert!(run(&db, &["repo", "add"], &[&p, "bad name", "/srv/x.git"]).is_err());
}
