//! E0-1: SQLCipher-class whole-file encryption and FTS5 with the Core's database library.

use brain_module::cipher::open;
use sqlx::Row;

const KEY: [u8; 32] = [7; 32];

#[tokio::test]
async fn encrypted_file_round_trip_and_wrong_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("canon.db");
    let pool = open(&path, &KEY, true).await.unwrap();
    sqlx::query("CREATE TABLE t (v TEXT)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO t VALUES ('needle-secret-text')")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    // The bytes on disk hold no SQLite header and no plaintext.
    let raw = std::fs::read(&path).unwrap();
    assert!(!raw.starts_with(b"SQLite format 3"));
    assert!(!raw.windows(6).any(|w| w == b"needle"));

    let pool = open(&path, &KEY, false).await.unwrap();
    let v: String = sqlx::query("SELECT v FROM t")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(v, "needle-secret-text");
    pool.close().await;

    assert!(
        open(&path, &[8; 32], false).await.is_err(),
        "wrong key must fail"
    );

    // No key at all: a plain connection cannot read it either.
    let plain = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
        .await
        .unwrap();
    assert!(
        sqlx::query("SELECT count(*) FROM sqlite_master")
            .execute(&plain)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn fts5_works_inside_an_encrypted_file() {
    let dir = tempfile::tempdir().unwrap();
    let pool = open(&dir.path().join("index.db"), &KEY, true)
        .await
        .unwrap();
    sqlx::query("CREATE VIRTUAL TABLE docs USING fts5(title, body)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO docs VALUES ('one','the quick brown fox'),('two','lazy dogs sleep')")
        .execute(&pool)
        .await
        .unwrap();
    let t: String = sqlx::query("SELECT title FROM docs WHERE docs MATCH 'fox'")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get(0);
    assert_eq!(t, "one");
}

#[tokio::test]
async fn plain_sqlite_still_opens_in_the_same_build() {
    // The Core's own database stays an ordinary file: no key means no encryption.
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}?mode=rwc", dir.path().join("core.db").display());
    let pool = sqlx::SqlitePool::connect(&url).await.unwrap();
    sqlx::query("CREATE TABLE t (v)")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let raw = std::fs::read(dir.path().join("core.db")).unwrap();
    assert!(raw.starts_with(b"SQLite format 3"));
}
