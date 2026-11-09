//! The Linear commands (E9.4): sync a project with a team, never storing a key.

use crate::{cli, db, ok};

#[test]
fn sets_and_shows_a_projects_linear_team() {
    let db = db("linear");
    let c = ok(&db, &["company", "add", "A"]);
    let p = ok(&db, &["project", "add", &c, "LIN", "Lin"]);
    assert!(cli(&db, &["linear", "show", &p]).is_err());
    ok(
        &db,
        &[
            "linear",
            "set",
            &p,
            "team-uuid",
            "--token-file",
            "/etc/citadel/linear",
        ],
    );
    assert_eq!(
        ok(&db, &["linear", "show", &p]),
        "team-uuid\thttps://api.linear.app/graphql\t/etc/citadel/linear\t-"
    );
    let relative = ["linear", "set", &p, "team-uuid", "--token-file", "key.txt"];
    assert!(cli(&db, &relative).unwrap_err().contains("absolute"));
    ok(&db, &["linear", "sync"]);
}
