//! Multi-repo projects (E15.16): repos are validated, ordered, one primary; an issue touches
//! the primary unless set; a repo an open issue touches stays; the migration folds the single
//! repo and its forge into one row and back.

use super::*;

const BY: AuditActor = core_user(ADMIN);

fn repo(project: ProjectId, name: &str) -> Repo {
    Repo {
        id: 0,
        project_id: project,
        name: name.to_owned(),
        url: format!("https://example.test/{name}.git"),
        default_branch: "main".to_owned(),
        position: 0,
        primary: false,
        forge: None,
        commands: Commands {
            test: "make test".to_owned(),
            ..Commands::default()
        },
    }
}

#[tokio::test]
async fn repos_are_validated_ordered_and_one_is_primary() {
    let db = db().await;
    let pool = &db.pool;
    let (_, p) = project_fixture(pool).await;
    let core = add_repo(pool, &repo(p.id, "core"), BY)
        .await
        .unwrap()
        .unwrap();
    let app = add_repo(pool, &repo(p.id, "app"), BY)
        .await
        .unwrap()
        .unwrap();
    assert!(core.primary && !app.primary);
    assert_eq!((core.position, app.position), (0, 1));
    assert_eq!(core.commands.test, "make test");
    for bad in [
        Repo {
            name: ".hidden".to_owned(),
            ..repo(p.id, "x")
        },
        Repo {
            name: "a/b".to_owned(),
            ..repo(p.id, "x")
        },
        Repo {
            url: "https://u:p@h/x.git".to_owned(),
            ..repo(p.id, "x")
        },
        Repo {
            default_branch: "-f".to_owned(),
            ..repo(p.id, "x")
        },
        repo(p.id, "core"),
    ] {
        let refused = add_repo(pool, &bad, BY).await;
        assert!(matches!(refused, Err(Error::InvalidArgument(_))), "{bad:?}");
    }
    let names = |all: Vec<Repo>| all.into_iter().map(|r| r.name).collect::<Vec<_>>();
    let order = ["app".to_owned(), "core".to_owned()];
    assert!(order_repos(pool, p.id, &order, BY).await.unwrap());
    assert_eq!(names(list_repos(pool, p.id).await.unwrap()), order);
    let short = order_repos(pool, p.id, &order[..1], BY).await;
    assert!(matches!(short, Err(Error::InvalidArgument(_))));

    // The primary moves; it goes only last.
    assert!(matches!(
        remove_repo(pool, core.id, BY).await,
        Err(Error::InvalidArgument(_))
    ));
    assert!(set_primary_repo(pool, app.id, BY).await.unwrap());
    let primary: Vec<_> = list_repos(pool, p.id)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.primary)
        .collect();
    assert_eq!(names(primary), ["app"]);
    assert_eq!(
        get_project_repo(pool, p.id).await.unwrap().unwrap().url,
        "https://example.test/app.git"
    );

    // An issue touches the primary unless set; a repo an open issue touches stays.
    let issue = create_issue(pool, &new_issue(p.id, "a")).await.unwrap();
    assert_eq!(names(issue_repos(pool, issue.id).await.unwrap()), ["app"]);
    let both = ["core".to_owned(), "app".to_owned()];
    let set = set_issue_repos(pool, issue.id, &both, BY).await.unwrap();
    assert_eq!(names(set), ["app", "core"], "in the project's order");
    let nope = set_issue_repos(pool, issue.id, &["nope".to_owned()], BY).await;
    assert!(matches!(nope, Err(Error::InvalidArgument(_))));
    let kept = remove_repo(pool, core.id, BY).await.unwrap_err();
    assert!(kept.to_string().contains("CIT-1"), "{kept}");
    set_issue_repos(pool, issue.id, &[], BY).await.unwrap();
    assert!(remove_repo(pool, core.id, BY).await.unwrap());
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action LIKE 'citadel.project.repo%' \
         OR action = 'citadel.issue.repos_set'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(audited, 7, "added ×2, ordered, primary, set ×2, removed");
}

/// The monolith folded the old `project_repo` and `project_forges` tables into one row, and back,
/// with a migration (`MIGRATOR.undo` / `run`). The module's baseline starts from the folded
/// shape (`citadel_0001`), so there is no migration to run either way.
#[tokio::test]
#[ignore = "the baseline replaced the monolith's repo-folding migration; the forge reads are S6"]
async fn the_migration_folds_the_repo_and_its_forge_and_back() {
    unimplemented!("fold: citadel_project_repos holds the forge columns from citadel_0001");
}

/// The issue's branch follows the profile's pattern once, then stays for the issue's life; a
/// project without a pattern keeps `citadel/<KEY>-<n>`.
#[tokio::test]
async fn the_branch_is_named_from_the_profile_once() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "Acme").await.unwrap().id;
    let p = create_project(pool, &new_project(c, "WKS"))
        .await
        .unwrap()
        .id;
    let plain = create_project(pool, &new_project(c, "OLD"))
        .await
        .unwrap()
        .id;
    let mut bug = new_issue(p, "Invoice PDF: totals are off");
    bug.kind = IssueKind::Bug;
    let bug = create_issue(pool, &bug).await.unwrap().id;
    let other = create_issue(pool, &new_issue(plain, "x")).await.unwrap().id;
    let set = |pattern: &str| {
        let patch: crate::profile::ProfilePatch =
            serde_json::from_value(serde_json::json!({"branch_pattern": pattern})).unwrap();
        async move { update_profile(pool, p, &patch, core_user(ADMIN)).await }
    };
    set("<type>/<key>-<slug>").await.unwrap().unwrap();
    let named = issue_branch(pool, bug).await.unwrap().unwrap();
    assert_eq!(named, "fix/wks-1-invoice-pdf-totals-are-off");
    set("<KEY>").await.unwrap().unwrap();
    assert_eq!(
        issue_branch(pool, bug).await.unwrap().unwrap(),
        named,
        "kept"
    );
    assert_eq!(
        issue_branch(pool, other).await.unwrap().as_deref(),
        Some("citadel/OLD-1")
    );
    assert_eq!(issue_branch(pool, IssueId(999)).await.unwrap(), None);
}
