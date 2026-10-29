//! The knowledge commands (E8): the admin adds entries, accepted at once, and lists them with
//! what a run is given.

use crate::{cli, db, ok};

#[test]
fn adds_and_lists_knowledge() {
    let db = db("knowledge");
    let c = ok(&db, &["company", "add", "A"]);
    let p = ok(&db, &["project", "add", &c, "KNO", "Know"]);
    let body = ["--body", "Run migrations down before up."];
    let mut add = vec!["knowledge", "add", &p, "landmine", "Migrations"];
    add.extend(body);
    let k = ok(&db, &add);
    assert_eq!(k, "1");
    let listed = ok(&db, &["knowledge", "list", &p]);
    assert_eq!(listed, "1\tlandmine\taccepted\tMigrations");
    let mut bad = vec!["knowledge", "add", &p, "rumour", "X"];
    bad.extend(body);
    assert!(cli(&db, &bad).is_err(), "unknown kind");
    assert!(cli(&db, &["knowledge", "add", &p, "decision", "No body"]).is_err());
}

/// The admin accepts and rejects agents' proposals; a rejection needs a reason, and an accepted
/// spec proposal replaces the spec.
#[tokio::test]
async fn accepts_and_rejects_proposals() {
    use ainkrad_core::gov::KnowledgeKind;
    use ainkrad_core::org::AgentId;
    use ainkrad_core::work::ProjectId;
    use ainkrad_core_server::store::{self, gov, work};

    let db = db("knowledge-review");
    let c = ok(&db, &["company", "add", "A"]);
    let p = ok(&db, &["project", "add", &c, "KNO", "Know"]);
    let ceo = [
        "agent",
        "add",
        &c,
        "Ceo",
        "--harness",
        "claude",
        "--org-role",
        "ceo",
    ];
    let agent: i64 = ok(&db, &[&ceo[..], &["--active"]].concat())
        .parse()
        .unwrap();
    let pool = store::connect(&db.0).await.unwrap();
    let project = ProjectId(p.parse().unwrap());
    let proposal = |title: &str, kind, spec| gov::Proposal {
        project,
        kind,
        title: title.to_owned(),
        body: "Spec v2.".to_owned(),
        spec,
        profile_field: None,
        rationale: None,
    };
    let landmine = gov::propose(
        &pool,
        &proposal("Ports", KnowledgeKind::Landmine, false),
        AgentId(agent),
    )
    .await
    .unwrap();
    let spec = gov::propose(
        &pool,
        &proposal("Spec", KnowledgeKind::State, true),
        AgentId(agent),
    )
    .await
    .unwrap();
    let (l, s) = (landmine.id.0.to_string(), spec.id.0.to_string());

    assert!(cli(&db, &["knowledge", "reject", &l]).is_err(), "no reason");
    ok(&db, &["knowledge", "reject", &l, "--reason", "Not ours"]);
    assert!(
        cli(&db, &["knowledge", "accept", &l]).is_err(),
        "decided already"
    );
    ok(&db, &["knowledge", "accept", &s]);
    let spec_now = work::project_spec(&pool, project).await.unwrap().unwrap();
    assert_eq!(spec_now, "Spec v2.");
    let listed = ok(&db, &["knowledge", "list", &p]);
    assert_eq!(
        listed,
        format!("{l}\tlandmine\trejected\tPorts\n{s}\tstate\taccepted\tSpec\tspec")
    );
}

/// The admin retires an accepted entry, or supersedes it with a new version; both are kept.
#[test]
fn retires_and_supersedes_knowledge() {
    let db = db("knowledge-retire");
    let c = ok(&db, &["company", "add", "A"]);
    let p = ok(&db, &["project", "add", &c, "KNO", "Know"]);
    let add = |title: &str| {
        ok(
            &db,
            &[
                "knowledge",
                "add",
                &p,
                "decision",
                title,
                "--body",
                "Use Pest.",
            ],
        )
    };
    let (old, gone) = (add("Tests"), add("Docker"));
    assert!(
        cli(&db, &["knowledge", "retire", &gone]).is_err(),
        "no reason"
    );
    ok(
        &db,
        &["knowledge", "retire", &gone, "--reason", "we left Docker"],
    );
    let retire_again = cli(&db, &["knowledge", "retire", &gone, "--reason", "x"]);
    assert!(retire_again.unwrap_err().contains("retired already"));
    let new = ok(
        &db,
        &[
            "knowledge",
            "supersede",
            &old,
            "--body",
            "Use Pest, not PHPUnit.",
            "--kind",
            "landmine",
        ],
    );
    let listed = ok(&db, &["knowledge", "list", &p]);
    assert_eq!(
        listed,
        format!(
            "{old}\tdecision\tretired\tTests\n{gone}\tdecision\tretired\tDocker\n\
             {new}\tlandmine\taccepted\tTests"
        )
    );
}

/// Skills are published from a file as new versions, attached within the company, and listed.
#[test]
fn publishes_and_lists_skills() {
    let db = db("skills");
    let c = ok(&db, &["company", "add", "A"]);
    let other = ok(&db, &["company", "add", "B"]);
    let p = ok(&db, &["project", "add", &c, "SKL", "Skilled"]);
    let theirs = ok(&db, &["project", "add", &other, "OTH", "Theirs"]);
    let file = db.0.with_file_name("laravel.md");
    std::fs::write(&file, "# Laravel\nRun Pint.").unwrap();
    let file = file.to_str().unwrap();
    let to_project = format!("project:{p}");
    let publish = |attach: &str| {
        cli(
            &db,
            &[
                "skill", "publish", &c, "laravel", "--file", file, "--attach", attach,
            ],
        )
    };
    let one = publish(&to_project).unwrap();
    let two = publish("role:Developer").unwrap();
    assert!(
        publish(&format!("project:{theirs}")).is_err(),
        "another company's project"
    );
    assert!(publish("team:1").is_err());
    let listed = ok(&db, &["skill", "list", &c]);
    assert_eq!(
        listed,
        format!(
            "{one}\tlaravel\tv1\tproject:{p}\t19 bytes\n{two}\tlaravel\tv2\trole:Developer\t19 bytes"
        )
    );
}
