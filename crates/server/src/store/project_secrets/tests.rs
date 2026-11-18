use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

use super::fixtures::{VALUE, broker, seed, who};
use super::*;
use crate::store::{connect, run_specs};

struct Fx {
    pool: SqlitePool,
    dir: PathBuf,
    project: i64,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-psec-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let p = projects::create(&pool, "shop", "Shop", "", "manual", who())
        .await
        .unwrap();
    Fx {
        pool,
        dir,
        project: p.id,
    }
}

fn input(value: &str) -> Input<'_> {
    Input {
        value,
        kind: None,
        description: None,
        file_name: None,
        file_mode: None,
    }
}

fn code<T>(r: Result<T, Error>) -> (&'static str, String) {
    match r {
        Err(Error::Refused { code, message }) => (code, message),
        Err(Error::Db(e)) => panic!("db error {e}"),
        Ok(_) => panic!("expected a refusal"),
    }
}

#[tokio::test]
async fn a_new_project_gets_its_group_and_a_secret_lands_in_it() {
    let fx = fx().await;
    let p = projects::get(&mut *fx.pool.acquire().await.unwrap(), fx.project)
        .await
        .unwrap();
    assert!(p.secret_group.is_some());
    assert!(list(&fx.pool, fx.project).await.unwrap().is_empty());
    seed(&fx.pool, fx.project, &["db_password"]).await;
    let all = list(&fx.pool, fx.project).await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!((all[0].name.as_str(), all[0].version), ("db_password", 1));
    // The broker holds it as `<slug>.<name>`, in the project's group.
    let g: String = sqlx::query_scalar(
        "SELECT g.name FROM core_secrets s JOIN core_secret_groups g ON g.id = s.group_id \
         WHERE s.name = 'shop.db_password'",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap();
    assert_eq!(g, "project-shop");
}

#[tokio::test]
async fn setting_again_rotates_and_no_value_is_ever_listed() {
    let fx = fx().await;
    let sealer = broker(&fx.pool).await;
    set(&fx.pool, &sealer, fx.project, "k", &input(VALUE), who())
        .await
        .unwrap();
    let again = set(
        &fx.pool,
        &sealer,
        fx.project,
        "k",
        &input("throwaway-second-value-91ab"),
        who(),
    )
    .await
    .unwrap();
    assert_eq!(again.version, 2);
    // Nothing the listing type can carry is the value.
    let shown = format!("{:?}", list(&fx.pool, fx.project).await.unwrap());
    assert!(!shown.contains("throwaway"), "{shown}");
    let at_rest: Vec<u8> =
        sqlx::query_scalar("SELECT sealed FROM core_secrets WHERE name = 'shop.k'")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert!(!String::from_utf8_lossy(&at_rest).contains("throwaway"));
}

#[tokio::test]
async fn names_are_checked_and_cannot_become_an_account_secret() {
    let fx = fx().await;
    let sealer = broker(&fx.pool).await;
    for bad in ["", "Bad", "a b", "../x", &"a".repeat(64)] {
        let r = set(&fx.pool, &sealer, fx.project, bad, &input(VALUE), who()).await;
        assert_eq!(code(r).0, "bad_request", "{bad:?}");
    }
    // A project called `acct` must not be able to mint `acct.anthropic.main`.
    let p = projects::create(&fx.pool, "acct", "A", "", "manual", who())
        .await
        .unwrap();
    let r = set(
        &fx.pool,
        &sealer,
        p.id,
        "anthropic.main",
        &input(VALUE),
        who(),
    )
    .await;
    assert_eq!(code(r).0, "bad_request");
}

#[tokio::test]
async fn projects_do_not_share_names_and_cannot_take_a_foreign_secret() {
    let fx = fx().await;
    let blog = projects::create(&fx.pool, "blog", "Blog", "", "manual", who())
        .await
        .unwrap();
    seed(&fx.pool, fx.project, &["token"]).await;
    seed(&fx.pool, blog.id, &["token"]).await;
    assert_eq!(list(&fx.pool, blog.id).await.unwrap().len(), 1);
    // A global secret that happens to be called `shop.other` is not the project's to take over.
    let sealer = broker(&fx.pool).await;
    secrets::create(
        &fx.pool,
        &sealer,
        "shop.other",
        &NewValue {
            value: VALUE,
            ..NewValue::default()
        },
        super::fixtures::DEVICE,
        who().actor,
        who().now,
    )
    .await
    .unwrap();
    let r = set(&fx.pool, &sealer, fx.project, "other", &input(VALUE), who()).await;
    assert_eq!(code(r).0, "conflict");
    assert!(
        !list(&fx.pool, fx.project)
            .await
            .unwrap()
            .iter()
            .any(|s| s.name == "other")
    );
    let blog_names = list(&fx.pool, blog.id).await.unwrap();
    assert_eq!(blog_names[0].name, "token");
}

fn spec_using(name: &str) -> serde_json::Value {
    json!({"services": {"db": {"image": "postgres:17",
        "env": {"PW": format!("${{secret:{name}}}")}}}})
}

#[tokio::test]
async fn deleting_a_used_secret_warns_naming_the_spec_version() {
    let fx = fx().await;
    seed(&fx.pool, fx.project, &["pw", "spare"]).await;
    let w = who();
    run_specs::save(&fx.pool, fx.project, &spec_using("pw"), "manual", w)
        .await
        .unwrap();
    run_specs::save(&fx.pool, fx.project, &spec_using("pw"), "manual", w)
        .await
        .unwrap();
    // Version 3 no longer uses it, so the newest user is version 2, an older one.
    run_specs::save(&fx.pool, fx.project, &spec_using("spare"), "manual", w)
        .await
        .unwrap();
    let (c, msg) = code(delete(&fx.pool, fx.project, "pw", false, w).await);
    assert_eq!(c, "conflict");
    assert!(
        msg.contains("spec version 2") && msg.contains("1 older"),
        "{msg}"
    );
    assert!(!msg.contains("the current one"), "{msg}");
    // The current version is named as such.
    let (_, msg) = code(delete(&fx.pool, fx.project, "spare", false, w).await);
    assert!(msg.contains("spec version 3, the current one"), "{msg}");
    // Nothing was deleted, then force removes it and leaves the specs alone.
    assert_eq!(list(&fx.pool, fx.project).await.unwrap().len(), 2);
    delete(&fx.pool, fx.project, "spare", true, w)
        .await
        .unwrap();
    assert_eq!(list(&fx.pool, fx.project).await.unwrap().len(), 1);
    assert_eq!(
        run_specs::versions(&fx.pool, fx.project)
            .await
            .unwrap()
            .len(),
        3
    );
    // An unused secret goes without a warning; a missing one is a 404.
    seed(&fx.pool, fx.project, &["free"]).await;
    delete(&fx.pool, fx.project, "free", false, w)
        .await
        .unwrap();
    assert_eq!(
        code(delete(&fx.pool, fx.project, "free", false, w).await).0,
        "not_found"
    );
}

#[tokio::test]
async fn an_archived_project_takes_no_new_secret_values() {
    let fx = fx().await;
    seed(&fx.pool, fx.project, &["k"]).await;
    projects::archive(&fx.pool, fx.project, who())
        .await
        .unwrap();
    let sealer = broker(&fx.pool).await;
    let r = set(&fx.pool, &sealer, fx.project, "k", &input(VALUE), who()).await;
    assert_eq!(code(r).0, "conflict");
    // Deleting stays possible, so a leaked credential can be revoked (see review_tests).
    delete(&fx.pool, fx.project, "k", true, who())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_project_from_before_this_story_gets_its_group_on_first_use() {
    let fx = fx().await;
    sqlx::query("UPDATE core_projects SET secret_group = NULL WHERE id = ?")
        .bind(fx.project)
        .execute(&fx.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM core_secret_groups")
        .execute(&fx.pool)
        .await
        .unwrap();
    assert!(list(&fx.pool, fx.project).await.unwrap().is_empty());
    seed(&fx.pool, fx.project, &["k"]).await;
    assert_eq!(list(&fx.pool, fx.project).await.unwrap().len(), 1);
}
