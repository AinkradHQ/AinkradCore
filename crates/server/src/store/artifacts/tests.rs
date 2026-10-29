//! The artifact store (E15.12): content-addressed blobs (one file per content), the allowlist,
//! the per-file limit and the company quota as settings (refused with the reason, audited),
//! and the listing filters.

use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::audit::AuditActor;
use ainkrad_core::work::UserId;

use super::*;
use crate::store::connect;
use crate::store::org::create_company;
use crate::store::settings::set;

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
    let dir = std::env::temp_dir().join(format!("citadel-art-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("citadel.db")).await.unwrap();
    Fx { pool, dir }
}

fn new(company: CompanyId, name: &str, kind: ArtifactKind) -> NewArtifact {
    NewArtifact {
        company,
        issue: None,
        requirement: None,
        run: None,
        agent: None,
        name: name.to_owned(),
        kind,
        user: None,
    }
}

async fn setting(pool: &SqlitePool, key: Key, company: CompanyId, v: i64) {
    let by = AuditActor::User(UserId(1));
    set(
        pool,
        key,
        Scope::Company(company),
        &v.to_string(),
        by,
        "2026-10-22T10:00:00.000Z",
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn one_blob_per_content_and_the_usage_counts_it_once() {
    let fx = fx().await;
    let (pool, root) = (&fx.pool, fx.dir.join("artifacts"));
    let c = create_company(pool, "A").await.unwrap().id;
    let report = b"# QA\npass";
    let a = publish_artifact(
        pool,
        &root,
        &new(c, "qa.md", ArtifactKind::Report),
        report,
        &Redactor::new(),
    )
    .await
    .unwrap();
    assert_eq!((a.mime.as_str(), a.size), ("text/markdown", 9));
    let b = publish_artifact(
        pool,
        &root,
        &new(c, "again.md", ArtifactKind::Report),
        report,
        &Redactor::new(),
    )
    .await
    .unwrap();
    assert_eq!(a.sha256, b.sha256);
    let blob = blob_path(&root, &a.sha256);
    assert_eq!(std::fs::read(&blob).unwrap(), report);
    let blobs = std::fs::read_dir(blob.parent().unwrap()).unwrap().count();
    assert_eq!(blobs, 1, "one file for one content");
    assert_eq!(artifact_usage(pool, c).await.unwrap().0, 9, "counted once");
    let published: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'artifact.published'")
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(published, 2);
}

#[tokio::test]
async fn names_types_size_and_quota_are_refused_with_the_reason() {
    let fx = fx().await;
    let (pool, root) = (&fx.pool, fx.dir.join("artifacts"));
    let c = create_company(pool, "A").await.unwrap().id;
    let file = |name: &str| new(c, name, ArtifactKind::File);
    for bad in ["../x.md", "a/b.md", ".env.md", ""] {
        let e = publish_artifact(pool, &root, &file(bad), b"x", &Redactor::new())
            .await
            .unwrap_err();
        assert!(matches!(e, ArtifactError::BadName), "{bad}: {e}");
    }
    let e = publish_artifact(pool, &root, &file("run.exe"), b"MZ", &Redactor::new())
        .await
        .unwrap_err();
    assert!(e.to_string().contains("type not allowed"), "{e}");

    setting(pool, Key::ArtifactMaxFileBytes, c, 1_000).await;
    let e = publish_artifact(
        pool,
        &root,
        &file("big.txt"),
        &[b'x'; 1_001],
        &Redactor::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            e,
            ArtifactError::TooLarge {
                size: 1_001,
                max: 1_000
            }
        ),
        "{e}"
    );

    setting(pool, Key::ArtifactCompanyQuotaBytes, c, 1_000_000).await;
    setting(pool, Key::ArtifactMaxFileBytes, c, 900_000).await;
    publish_artifact(
        pool,
        &root,
        &file("a.txt"),
        &[b'a'; 600_000],
        &Redactor::new(),
    )
    .await
    .unwrap();
    let e = publish_artifact(
        pool,
        &root,
        &file("b.txt"),
        &[b'b'; 600_000],
        &Redactor::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            e,
            ArtifactError::OverQuota {
                used: 600_000,
                size: 600_000,
                quota: 1_000_000
            }
        ),
        "{e}"
    );
    assert!(e.to_string().contains("storage is full"), "{e}");
    // The same content again is no new storage: allowed.
    publish_artifact(
        pool,
        &root,
        &file("a2.txt"),
        &[b'a'; 600_000],
        &Redactor::new(),
    )
    .await
    .unwrap();
    // Another company has its own quota.
    let d = create_company(pool, "B").await.unwrap().id;
    let theirs = new(d, "b.txt", ArtifactKind::File);
    publish_artifact(pool, &root, &theirs, &[b'b'; 600_000], &Redactor::new())
        .await
        .unwrap();

    record_refusal(pool, &file("b.txt"), &e.to_string())
        .await
        .unwrap();
    let reason: String = sqlx::query_scalar(
        "SELECT json_extract(details, '$.reason') FROM audit_events \
         WHERE action = 'artifact.refused'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(reason.contains("storage is full"), "{reason}");
}

#[tokio::test]
async fn listings_filter_by_company_kind_and_agent() {
    let fx = fx().await;
    let (pool, root) = (&fx.pool, fx.dir.join("artifacts"));
    let c = create_company(pool, "A").await.unwrap().id;
    let d = create_company(pool, "B").await.unwrap().id;
    let shot = new(c, "s.png", ArtifactKind::Screenshot);
    let png = publish_artifact(pool, &root, &shot, b"\x89PNG", &Redactor::new())
        .await
        .unwrap();
    let rep = publish_artifact(
        pool,
        &root,
        &new(c, "r.md", ArtifactKind::Report),
        b"r",
        &Redactor::new(),
    )
    .await
    .unwrap();
    publish_artifact(
        pool,
        &root,
        &new(d, "x.md", ArtifactKind::Report),
        b"x",
        &Redactor::new(),
    )
    .await
    .unwrap();
    let ids = |v: Vec<Artifact>| v.into_iter().map(|a| a.id).collect::<Vec<_>>();
    let mine = ArtifactFilter {
        company: Some(c),
        ..ArtifactFilter::default()
    };
    assert_eq!(
        ids(list_artifacts(pool, &mine, None, 50).await.unwrap()),
        [rep.id, png.id]
    );
    let reports = ArtifactFilter {
        kind: Some(ArtifactKind::Report),
        ..mine.clone()
    };
    assert_eq!(
        ids(list_artifacts(pool, &reports, None, 50).await.unwrap()),
        [rep.id]
    );
    let paged = list_artifacts(pool, &mine, Some(rep.id.0), 50)
        .await
        .unwrap();
    assert_eq!(ids(paged), [png.id]);
    assert_eq!(preview_of(&png.mime), Preview::Image);
    assert_eq!(preview_of("text/html"), Preview::None);
    assert_eq!(mime_of("diagram.SVG"), Some("image/svg+xml"));
}

/// Every allowed type is either scanned for secrets (text) or marked unscanned (binary): the
/// redactor's list of text extensions agrees with the allowlist (E15.18).
#[test]
fn every_text_type_is_scanned_and_only_those() {
    for (ext, mime) in TYPES {
        let text = mime.starts_with("text/")
            || ["application/json", "application/yaml", "image/svg+xml"].contains(mime);
        let name = format!("f.{ext}");
        assert_eq!(ainkrad_proto::redact::is_text(&name), text, "{name}");
    }
}
