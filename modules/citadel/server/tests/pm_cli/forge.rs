//! The forge commands (E9): put a project on a host, never storing a token.

use crate::{cli, db, ok};

#[test]
fn sets_and_shows_a_projects_forge() {
    let db = db("forge");
    let c = ok(&db, &["company", "add", "A"]);
    let p = ok(
        &db,
        &[
            "project",
            "add",
            &c,
            "FRG",
            "Forge",
            "--repo",
            "https://example.test/git/f.git",
        ],
    );
    let set = [
        "forge",
        "set",
        &p,
        "github",
        "acme/f",
        "--token-file",
        "/etc/citadel/gh",
    ];
    assert_eq!(ok(&db, &set), p);
    assert_eq!(
        ok(&db, &["forge", "show", &p]),
        "github\thttps://api.github.com\tacme/f\t/etc/citadel/gh"
    );
    let gone = [
        "forge",
        "set",
        "99",
        "github",
        "acme/f",
        "--token-file",
        "/t",
    ];
    assert!(cli(&db, &gone).unwrap_err().contains("no project"));
    let host = [
        "forge",
        "set",
        &p,
        "bitbucket",
        "acme/f",
        "--token-file",
        "/t",
    ];
    assert!(cli(&db, &host).is_err());
    assert!(cli(&db, &["forge", "show", "99"]).is_err());
}
