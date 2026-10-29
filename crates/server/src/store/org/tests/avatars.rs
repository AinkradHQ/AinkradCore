//! Agent avatars (decision #61): palettes given at hire (stable, spread, unique while they
//! last), changed by the admin; an uploaded image checked by its bytes, stored, removed.

use std::collections::HashSet;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core::work::UserId;

use super::*;
use crate::store::artifacts::blob_path;
use crate::store::org::avatars::{
    AvatarError, avatar_image, list_palettes, reset_avatar, set_appearance, sniff, upload_avatar,
};

const BY: AuditActor = AuditActor::User(UserId(1));
pub(crate) const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0";
pub(crate) const WEBP: &[u8] = b"RIFF\x1a\0\0\0WEBPVP8L\x0d\0\0\0\x2f\0\0\0\x10\x07\x10\x11\x11";

async fn hire(pool: &SqlitePool, c: CompanyId, n: usize) -> Vec<Agent> {
    let mut out = vec![];
    for i in 0..n {
        let a = new_agent(c, &format!("a{i}"), OrgRole::None);
        out.push(create_agent(pool, &a).await.unwrap());
    }
    out
}

#[tokio::test]
async fn new_agents_get_stable_palettes_spread_within_their_company() {
    let db = db().await;
    let pool = &db.pool;
    let n = list_palettes(pool).await.unwrap().len();
    assert_eq!(n, 17);
    let names = list_palettes(pool).await.unwrap();
    assert_eq!(names[0], ("neon-tide".to_owned(), "Neon Tide".to_owned()));
    assert_eq!(names[13].0, "lime-circuit");
    assert!(
        names.iter().all(|(id, _)| id != "muted"),
        "muted is never assigned"
    );
    let a = create_company(pool, "A").await.unwrap().id;
    let b = create_company(pool, "B").await.unwrap().id;

    let first = hire(pool, a, n).await;
    let palettes: HashSet<&str> = first.iter().map(|g| g.palette_id.as_str()).collect();
    assert_eq!(palettes.len(), n, "no repeat while palettes last");
    assert!(first.iter().all(|g| g.figure_version == "v1"));
    // Past the palettes, each is used twice before any thrice.
    let more = hire(pool, a, n).await;
    let twice: HashSet<&str> = more.iter().map(|g| g.palette_id.as_str()).collect();
    assert_eq!(twice.len(), n);

    // Deterministic: the same company in a fresh database gets the same sequence; another
    // company starts elsewhere.
    let other = db_with_companies(2).await;
    let again = hire(&other.pool, a, 3).await;
    let ids = |v: &[Agent]| v.iter().map(|g| g.palette_id.clone()).collect::<Vec<_>>();
    assert_eq!(ids(&again), ids(&first[..3]));
    let theirs = hire(pool, b, 1).await;
    assert_ne!(theirs[0].palette_id, first[0].palette_id);

    // Stable: what is stored is what is read, whatever is hired or removed later.
    delete_agent(pool, first[1].id).await.unwrap();
    hire(pool, a, 1).await;
    let kept = get_agent(pool, first[2].id).await.unwrap().unwrap();
    assert_eq!(kept.palette_id, first[2].palette_id);
    // The freed palette is the least used, so the next hire takes it.
    let fresh = db_with_companies(1).await;
    let three = hire(&fresh.pool, a, 3).await;
    delete_agent(&fresh.pool, three[1].id).await.unwrap();
    let next = hire(&fresh.pool, a, 1).await;
    assert_eq!(next[0].palette_id, three[1].palette_id);
}

/// A database with `n` companies, ids 1..=n.
async fn db_with_companies(n: usize) -> Db {
    let db = db().await;
    for i in 0..n {
        create_company(&db.pool, &format!("C{i}")).await.unwrap();
    }
    db
}

#[tokio::test]
async fn the_admin_changes_the_palette_and_figure_with_an_audit() {
    let db = db().await;
    let pool = &db.pool;
    let c = create_company(pool, "A").await.unwrap().id;
    let a = hire(pool, c, 1).await.remove(0);
    let got = set_appearance(pool, a.id, "sakura", None, BY)
        .await
        .unwrap();
    assert_eq!(
        (got.palette_id.as_str(), got.figure_version.as_str()),
        ("sakura", "v1")
    );
    let got = set_appearance(pool, a.id, "cobalt", Some("v1"), BY)
        .await
        .unwrap();
    assert_eq!(got.palette_id, "cobalt");
    let bad = set_appearance(pool, a.id, "muted", None, BY).await;
    assert!(
        matches!(bad, Err(AvatarError::UnknownPalette(_))),
        "{bad:?}"
    );
    let bad = set_appearance(pool, a.id, "cobalt", Some("v9"), BY).await;
    assert!(matches!(bad, Err(AvatarError::UnknownFigure(_))), "{bad:?}");
    let gone = set_appearance(pool, AgentId(999), "cobalt", None, BY).await;
    assert!(matches!(gone, Err(AvatarError::NoAgent(_))), "{gone:?}");
    let audited: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'agent.appearance_set'",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(audited, 2);
}

#[tokio::test]
async fn an_upload_is_checked_by_its_bytes_stored_and_removed() {
    let db = db().await;
    let pool = &db.pool;
    let root = db.dir.join("artifacts");
    let c = create_company(pool, "A").await.unwrap().id;
    let a = hire(pool, c, 1).await.remove(0);
    assert_eq!(avatar_image(pool, &root, a.id).await.unwrap(), None);

    assert_eq!(sniff(PNG), Some("image/png"));
    assert_eq!(sniff(WEBP), Some("image/webp"));
    assert_eq!(sniff(b"\xFF\xD8\xFF\xE0"), Some("image/jpeg"));
    let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>";
    for refused in [
        &svg[..],
        b"<!doctype html><p>hi",
        b"GIF89a....",
        b"RIFF\0\0\0\0WAVE",
    ] {
        let r = upload_avatar(pool, &root, a.id, refused, BY).await;
        assert!(matches!(r, Err(AvatarError::NotAnImage)), "{r:?}");
    }

    let up = upload_avatar(pool, &root, a.id, PNG, BY).await.unwrap();
    let sha = up.avatar_sha256.clone().unwrap();
    assert!(blob_path(&root, &sha).exists());
    let img = avatar_image(pool, &root, a.id).await.unwrap().unwrap();
    assert_eq!((img.mime, img.bytes.as_slice()), ("image/png", PNG));
    let up = upload_avatar(pool, &root, a.id, WEBP, BY).await.unwrap();
    let img = avatar_image(pool, &root, a.id).await.unwrap().unwrap();
    assert_eq!(img.mime, "image/webp");
    assert_eq!(Some(img.sha256), up.avatar_sha256);
    assert_eq!(up.palette_id, a.palette_id, "the figure is kept underneath");

    let at = Scope::Company(c);
    crate::store::settings::set(
        pool,
        Key::AvatarMaxBytes,
        at,
        "1024",
        BY,
        "2026-10-22T10:00:00Z",
    )
    .await
    .unwrap();
    let big = [PNG, &[0u8; 1024]].concat();
    let r = upload_avatar(pool, &root, a.id, &big, BY).await;
    assert!(
        matches!(r, Err(AvatarError::TooLarge { max: 1024, .. })),
        "{r:?}"
    );

    let back = reset_avatar(pool, a.id, BY).await.unwrap();
    assert_eq!(back.avatar_sha256, None);
    assert_eq!(avatar_image(pool, &root, a.id).await.unwrap(), None);
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'agent.avatar_%' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        ["agent.avatar_set", "agent.avatar_set", "agent.avatar_reset"]
    );
}
