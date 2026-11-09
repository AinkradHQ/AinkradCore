//! The avatar commands (decision #61): list palettes, change one, upload an image (refused
//! unless PNG, JPEG or WebP), remove it.

use std::process::Command;

use crate::{Db, db, ok};

/// `citadel-server agent <noun> <verb> <db> <rest…>`: stdout, or stderr on failure.
fn agent(db: &Db, noun: &str, verb: &str, rest: &[&str]) -> Result<String, String> {
    let out = Command::new(env!("CARGO_BIN_EXE_citadel-server"))
        .args(["agent", noun, verb])
        .arg(&db.0)
        .args(rest)
        .output()
        .unwrap();
    match out.status.success() {
        true => Ok(String::from_utf8(out.stdout).unwrap().trim().to_owned()),
        false => Err(String::from_utf8(out.stderr).unwrap()),
    }
}

#[tokio::test]
async fn sets_a_palette_uploads_and_resets_an_image() {
    let db = db("avatars");
    let c = ok(&db, &["company", "add", "A"]);
    let a = ok(&db, &["agent", "add", &c, "Dev", "--harness", "claude"]);
    let palettes = agent(&db, "appearance", "palettes", &[]).unwrap();
    assert_eq!(palettes.lines().count(), 17);
    assert!(
        palettes.starts_with("neon-tide\tNeon Tide") && palettes.ends_with("steel\tSteel"),
        "{palettes}"
    );
    assert_eq!(
        agent(&db, "appearance", "set", &[&a, "--palette", "sakura"]).unwrap(),
        a
    );
    assert!(agent(&db, "appearance", "set", &[&a, "--palette", "muted"]).is_err());

    let dir = db.0.parent().unwrap();
    let png = dir.join("me.png");
    std::fs::write(&png, b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR").unwrap();
    let svg = dir.join("me.svg");
    std::fs::write(&svg, b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>").unwrap();
    let refused = agent(&db, "avatar", "set", &[&a, "--file", svg.to_str().unwrap()]);
    assert!(refused.unwrap_err().contains("PNG, JPEG or WebP"));
    let file = png.to_str().unwrap();
    assert_eq!(
        agent(&db, "avatar", "set", &[&a, "--file", file]).unwrap(),
        a
    );

    let pool = citadel_server::store::connect(&db.0).await.unwrap();
    let id = citadel_core::org::AgentId(a.parse().unwrap());
    let got = citadel_server::store::org::get_agent(&pool, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.palette_id, "sakura");
    let sha = got.avatar_sha256.unwrap();
    let blob = dir.join("artifacts/blobs").join(&sha[..2]).join(&sha);
    assert!(
        blob.exists(),
        "stored with the artifacts next to the database"
    );

    assert_eq!(agent(&db, "avatar", "reset", &[&a]).unwrap(), a);
    let got = citadel_server::store::org::get_agent(&pool, id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.avatar_sha256, None);
}
