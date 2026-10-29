use super::*;

#[test]
fn encodes_like_sigv4() {
    assert_eq!(
        encode("core/20261029T100000Z-ab.age", true),
        "core/20261029T100000Z-ab.age"
    );
    assert_eq!(encode("a b/c+d:e", true), "a%20b/c%2Bd%3Ae");
    assert_eq!(encode("core/", false), "core%2F");
    assert_eq!(
        tag("<Error><Code>NoSuchBucket</Code></Error>", "Code").as_deref(),
        Some("NoSuchBucket")
    );
}

#[test]
fn debug_never_shows_the_credentials() {
    let b = Bucket::new(
        "https://ns.compat.objectstorage.example",
        "b",
        "r",
        "core/",
        "AKIDPLANTED".into(),
        "SECRETPLANTED".into(),
    )
    .unwrap();
    let shown = format!("{b:?}");
    assert!(!shown.contains("PLANTED"), "{shown}");
    assert!(
        Bucket::new("http://example.com", "b", "r", "p", "a".into(), "s".into()).is_err(),
        "plain HTTP only to loopback"
    );
}

/// Against a real S3 API, from the `AINKRAD_BACKUP_*` environment: a local MinIO with
/// `AINKRAD_MINIO=1`, or the real create-only bucket with `AINKRAD_S3_LIVE=1`, where a second
/// PUT of the same key must be refused. Writes one object and leaves it (the backup key cannot
/// delete): the operator deletes it with an admin key.
#[tokio::test]
async fn put_get_list_and_overwrite_against_a_bucket() {
    let live = std::env::var("AINKRAD_S3_LIVE").is_ok_and(|v| v == "1");
    if !live && !std::env::var("AINKRAD_MINIO").is_ok_and(|v| v == "1") {
        eprintln!("skipped: set AINKRAD_MINIO=1 or AINKRAD_S3_LIVE=1 with AINKRAD_BACKUP_*");
        return;
    }
    let bucket = Bucket::from_env()
        .unwrap()
        .expect("AINKRAD_BACKUP_ENDPOINT");
    let dir = std::env::temp_dir().join(format!("core-s3-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("probe");
    std::fs::write(&src, b"ainkrad s3 probe, safe to delete").unwrap();
    let key = format!(
        "{}probe-{}-{}",
        bucket.prefix,
        crate::ops::compact(&SystemClock.now()),
        crate::ops::random_hex().unwrap()
    );

    bucket.put_new(&key, &src).await.unwrap();
    println!("PUT {key}: ok");
    let n = bucket.get(&key, &dir.join("back")).await.unwrap();
    assert_eq!(
        std::fs::read(dir.join("back")).unwrap(),
        std::fs::read(&src).unwrap()
    );
    println!("GET {key}: {n} bytes, equal");
    let keys = bucket.list(&bucket.prefix).await.unwrap();
    assert!(keys.contains(&key), "{keys:?}");
    println!(
        "LIST {}: {} keys, ours among them",
        bucket.prefix,
        keys.len()
    );

    std::fs::write(&src, b"an overwrite attempt").unwrap();
    match bucket.put_new(&key, &src).await {
        Ok(()) => {
            println!("overwrite of {key}: ACCEPTED");
            assert!(!live, "the live bucket must refuse an overwrite");
        }
        Err(e) => {
            println!("overwrite of {key}: refused: {e}");
            let back = dir.join("after");
            bucket.get(&key, &back).await.unwrap();
            assert_eq!(
                std::fs::read(&back).unwrap(),
                b"ainkrad s3 probe, safe to delete",
                "the object is unchanged"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
