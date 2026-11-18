//! The eval harness on a made-up room (everything here is invented): metrics, the live-dir
//! refusal, and the migration dry run.

use brain_module::eval::{Corpus, QuestionSet, check_copy, dry_run_migrations, run_questions};
use brain_module::files;

const KEY: [u8; 32] = [7; 32];

async fn fixture(dir: &std::path::Path) -> sqlx::SqlitePool {
    let pool = files::open_migrated(
        &files::room_path(dir, "fixture-room"),
        &KEY,
        true,
        files::CANON,
    )
    .await
    .unwrap();
    for (id, body) in [
        ("rec-deploy", "Deploy to staging with the green button"),
        ("rec-backup", "Database backups run nightly"),
        ("rec-other", "Database migrations need a review"),
    ] {
        sqlx::query("INSERT INTO records (id, type, status, body, created_at) VALUES (?, 'fact', 'accepted', ?, '2026-01-01')")
            .bind(id)
            .bind(body)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO sources (item_id, content_hash, source_kind, device, path, author_kind, author_name, title, text, started_at, run, assigned_by) VALUES ('src-backup', 'h', 'note', 'd', 'p', 'person', 'a', 'Backup notes', 'database backups are kept 14 days', '2026-01-01', 'r', 'user')")
        .execute(&pool)
        .await
        .unwrap();
    pool
}

#[tokio::test]
async fn metrics_on_the_fixture_room() {
    let dir = tempfile::tempdir().unwrap();
    let pool = fixture(dir.path()).await;
    let corpus = Corpus::load(&pool).await.unwrap();
    let set: QuestionSet =
        serde_json::from_str(include_str!("fixtures/eval/fixture-room.json")).unwrap();
    let r = run_questions(&set, &corpus).await.unwrap();
    assert_eq!((r.questions, r.skipped), (3, 1));
    assert_eq!(r.missed, vec![3]);
    assert_eq!(r.unknown_labels, vec!["rec-nothing".to_owned()]);
    // Q1 finds its one answer, Q2 finds both of its two (rec-other also matches no AND query).
    assert!((r.hit_at_k - 2.0 / 3.0).abs() < 1e-9);
    assert!(r.recall_at_k > 0.6 && r.noise < 0.5);
}

#[tokio::test]
async fn migrations_dry_run_leaves_the_copy_alone() {
    let dir = tempfile::tempdir().unwrap();
    fixture(dir.path()).await.close().await;
    let scratch = tempfile::tempdir().unwrap();
    let file = files::room_path(dir.path(), "fixture-room");
    let before = std::fs::read(&file).unwrap();
    let r = dry_run_migrations(dir.path(), &KEY, &["fixture-room".into()], scratch.path()).await;
    assert!(r[0].failure.is_none());
    assert_eq!(std::fs::read(&file).unwrap(), before);
    // A wrong key is a reported failure, not a panic.
    let r = dry_run_migrations(
        dir.path(),
        &[9; 32],
        &["fixture-room".into()],
        scratch.path(),
    )
    .await;
    assert!(r[0].failure.is_some());
}

#[test]
fn the_live_dir_is_refused() {
    let out = tempfile::tempdir().unwrap();
    assert!(check_copy(std::path::Path::new("/var/lib/ainkrad/core"), out.path()).is_err());
    assert!(check_copy(out.path(), out.path()).is_err()); // no core.db
}
