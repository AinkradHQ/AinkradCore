use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::store::connect;
use crate::store::migrate::{CORE, CORE_MIGRATIONS, migrate_core, undo};

const NOW: &str = "2026-11-17T10:00:00.000Z";
const W: Who<'static> = Who {
    by_device: "d_test",
    actor: AuditActor::System,
    now: NOW,
};

struct Fx {
    pool: SqlitePool,
    dir: PathBuf,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-proj-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    Fx { pool, dir }
}

async fn mk(fx: &Fx, slug: &str) -> Result<Project, Error> {
    create(&fx.pool, slug, "Shop", "", "manual", W).await
}

async fn add(fx: &Fx, p: i64, name: &str, primary: bool) -> Result<Repo, Error> {
    let url = format!("https://github.com/acme/{name}.git");
    add_repo(&fx.pool, p, name, &url, "main", primary, W).await
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    match r {
        Err(Error::Refused { code, .. }) => code,
        Err(Error::Db(e)) => panic!("db error {e}"),
        Ok(_) => panic!("expected a refusal"),
    }
}

async fn project_id_column(fx: &Fx) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pragma_table_info('core_agent_sessions') WHERE name = 'project_id'",
    )
    .fetch_one(&fx.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn bad_and_reserved_slugs_are_refused_and_good_ones_work() {
    let fx = fx().await;
    for bad in [
        "",
        "a",
        "A1",
        "1ab",
        "a_b",
        "ab-",
        "a b",
        "é",
        &"a".repeat(41),
    ] {
        assert_eq!(code(mk(&fx, bad).await), "bad_request", "{bad}");
    }
    for r in RESERVED {
        assert_eq!(code(mk(&fx, r).await), "bad_request", "{r}");
    }
    assert!(mk(&fx, "shop-1").await.is_ok());
    assert_eq!(code(mk(&fx, "shop-1").await), "conflict");
    // The table's own CHECK holds even for a writer that skips the Rust check.
    for bad in ["A1", "ab-", "1ab", "a_b", "a"] {
        let r = sqlx::query(
            "INSERT INTO core_projects (slug, name, source, created_at, updated_at) \
             VALUES (?, 'x', 'manual', 'n', 'n')",
        )
        .bind(bad)
        .execute(&fx.pool)
        .await;
        assert!(r.is_err(), "{bad}");
    }
    let r = sqlx::query(
        "INSERT INTO core_projects (slug, name, source, created_at, updated_at) \
         VALUES ('okay', 'x', 'gitlab', 'n', 'n')",
    )
    .execute(&fx.pool)
    .await;
    assert!(r.is_err(), "source is manual or github");
}

#[tokio::test]
async fn defaults_update_and_archive_keeps_every_row() {
    let fx = fx().await;
    let p = mk(&fx, "shop").await.unwrap();
    assert!(p.expose && p.state == "active" && p.idle_minutes == 30);
    let r = add(&fx, p.id, "web", false).await.unwrap();
    set_mirror(&fx.pool, r.id, Some("abc"), Some(NOW), None)
        .await
        .unwrap();
    let u = update(&fx.pool, p.id, Some("Shop 2"), None, Some(false), W)
        .await
        .unwrap();
    assert_eq!((u.name.as_str(), u.expose), ("Shop 2", false));
    let a = archive(&fx.pool, p.id, W).await.unwrap();
    assert_eq!(a.state, "archived");
    assert_eq!(code(archive(&fx.pool, p.id, W).await), "conflict");
    let upd = update(&fx.pool, p.id, Some("x"), None, None, W).await;
    assert_eq!(code(upd), "conflict");
    assert_eq!(code(add(&fx, p.id, "api", false).await), "conflict");
    let mut c = fx.pool.acquire().await.unwrap();
    assert_eq!(repos(&mut c, p.id).await.unwrap().len(), 1);
    assert!(mirror(&fx.pool, r.id).await.unwrap().is_some());
    assert!(list(&fx.pool, false).await.unwrap().is_empty());
    assert_eq!(list(&fx.pool, true).await.unwrap().len(), 1);
}

#[tokio::test]
async fn one_primary_repo_and_remotes_are_checked() {
    let fx = fx().await;
    let p = mk(&fx, "shop").await.unwrap();
    let a = add(&fx, p.id, "web", false).await.unwrap();
    assert!(a.is_primary, "the first repo is primary");
    let b = add(&fx, p.id, "api", false).await.unwrap();
    assert!(!b.is_primary);
    let c = add(&fx, p.id, "docs", true).await.unwrap();
    assert!(c.is_primary);
    set_primary(&fx.pool, p.id, b.id, W).await.unwrap();
    let mut conn = fx.pool.acquire().await.unwrap();
    let all = repos(&mut conn, p.id).await.unwrap();
    assert_eq!(all.iter().filter(|r| r.is_primary).count(), 1);
    assert_eq!(all[0].id, b.id);
    // The index refuses a second primary outright.
    let r = sqlx::query("UPDATE core_project_repos SET is_primary = 1 WHERE id = ?")
        .bind(a.id)
        .execute(&fx.pool)
        .await;
    assert!(r.is_err());
    // The primary cannot be removed while others remain.
    let rm = remove_repo(&fx.pool, p.id, b.id, W).await;
    assert_eq!(code(rm), "conflict");
    remove_repo(&fx.pool, p.id, a.id, W).await.unwrap();
    assert!(
        add(&fx, p.id, "web", false).await.is_ok(),
        "the name is free again"
    );
    for url in [
        "/tmp/repo",
        "-oProxy=x",
        "https://user:pw@github.com/a/b",
        "file:///x",
    ] {
        let e = add_repo(&fx.pool, p.id, "bad", url, "main", false, W).await;
        assert_eq!(code(e), "bad_request", "{url}");
    }
    let e = add_repo(
        &fx.pool,
        p.id,
        "bad",
        "git@github.com:a/b.git",
        "--x",
        false,
        W,
    )
    .await;
    assert_eq!(code(e), "bad_request");
    let url = "https://github.com/acme/api.git";
    let dup = add_repo(&fx.pool, p.id, "other", url, "main", false, W).await;
    assert_eq!(code(dup), "conflict");
}

#[tokio::test]
async fn mirror_state_is_upserted_per_repo() {
    let fx = fx().await;
    let p = mk(&fx, "shop").await.unwrap();
    let r = add(&fx, p.id, "web", false).await.unwrap();
    assert_eq!(mirror(&fx.pool, r.id).await.unwrap(), None);
    set_mirror(&fx.pool, r.id, None, None, Some("auth failed"))
        .await
        .unwrap();
    set_mirror(&fx.pool, r.id, Some("abc"), Some(NOW), None)
        .await
        .unwrap();
    let m = mirror(&fx.pool, r.id).await.unwrap().unwrap();
    assert_eq!((m.head.as_deref(), m.error), (Some("abc"), None));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_project_mirrors")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn events_and_audit_rows_are_written_and_replay() {
    let fx = fx().await;
    let p = mk(&fx, "shop").await.unwrap();
    add(&fx, p.id, "web", false).await.unwrap();
    update(&fx.pool, p.id, Some("S"), None, None, W)
        .await
        .unwrap();
    archive(&fx.pool, p.id, W).await.unwrap();
    let got = crate::store::events::replay(&fx.pool, 0, 100)
        .await
        .unwrap()
        .unwrap();
    let kinds: Vec<&str> = got
        .iter()
        .map(|e| e.kind.as_str())
        .filter(|k| k.starts_with("project."))
        .collect();
    assert_eq!(
        kinds,
        ["project.created", "project.updated", "project.archived"]
    );
    let created = got.iter().find(|e| e.kind == "project.created").unwrap();
    assert_eq!(created.payload.0["id"], p.id);
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE entity_kind = 'project' ORDER BY seq",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "project.created",
            "project.repo_added",
            "project.updated",
            "project.archived"
        ]
    );
}

#[tokio::test]
async fn migration_round_trips_over_data() {
    let fx = fx().await;
    let p = mk(&fx, "shop").await.unwrap();
    add(&fx, p.id, "web", false).await.unwrap();
    let q = "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name GLOB 'core_project*' ORDER BY name";
    let tables = sqlx::query_scalar::<_, String>(q)
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    assert_eq!(
        tables,
        [
            "core_project_mirrors",
            "core_project_repos",
            "core_projects"
        ]
    );
    assert_eq!(project_id_column(&fx).await, 1);
    undo(&fx.pool, CORE, CORE_MIGRATIONS, 38).await.unwrap();
    let after = sqlx::query_scalar::<_, String>(q)
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    assert!(after.is_empty());
    assert_eq!(project_id_column(&fx).await, 0);
    migrate_core(&fx.pool).await.unwrap();
    let again = sqlx::query_scalar::<_, String>(q)
        .fetch_all(&fx.pool)
        .await
        .unwrap();
    assert_eq!(again, tables);
    assert_eq!(project_id_column(&fx).await, 1);
}

#[tokio::test]
async fn a_refused_binding_leaves_no_project() {
    use crate::store::connections::Who as CW;
    let fx = fx().await;
    let repos = [NewGithubRepo {
        name: "shop".into(),
        remote_url: "https://github.com/acme/shop.git".into(),
        default_branch: "main".into(),
    }];
    let cw = CW {
        workspace: 1,
        by_device: "d_test",
        actor: AuditActor::System,
        now: NOW,
    };
    // No such connection: the binding is refused inside the transaction.
    let r = create_from_github(&fx.pool, None, "Shop", &repos, W, Some((999, cw))).await;
    assert_eq!(code(r), "not_found");
    assert!(list(&fx.pool, false).await.unwrap().is_empty());
    assert!(list(&fx.pool, true).await.unwrap().is_empty());
}
