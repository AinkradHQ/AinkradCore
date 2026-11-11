use ainkrad_core_server::ops::secretbox::SecretBox;
use ainkrad_core_server::store::{events, secrets};
use axum::http::{Method, StatusCode};
use brain_module::Brain;
use serde_json::json;

use super::common::*;

#[tokio::test]
async fn status_reports_the_key_state_and_mode_zero_locks_the_brain() {
    let fx = fx().await;
    let v = ok(&fx, Method::GET, "/status", None).await;
    assert_eq!(
        (v["present"].as_bool(), v["key"].as_str()),
        (Some(true), Some("missing"))
    );
    start(&fx).await;
    assert_eq!(ok(&fx, Method::GET, "/status", None).await["key"], "ok");

    let locked = fx_with(Brain::default(), 0).await;
    assert_eq!(
        ok(&locked, Method::GET, "/status", None).await["key"],
        "locked_mode0"
    );
    let (s, v) = call(
        &locked,
        &locked.admin,
        Method::POST,
        "/imports",
        Some(json!({"kind": "full", "sources": ["claude_code"]})),
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("brain_locked"))
    );
}

#[tokio::test]
async fn the_key_is_made_once_reused_after_a_restart_and_never_logged() {
    let fx = fx().await;
    let run = start(&fx).await;
    send(
        &fx,
        &run,
        vec![item(1, "/h/Projects/Alpha/x", "t", "hello")],
    )
    .await;
    let one: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secrets WHERE name = 'brain.key'")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(one, 1);
    // A restarted process (nothing cached) opens the same key from the sealed secret, and with it the same file.
    let key = key_of(&fx).await;
    let st = brain_module::files::open_migrated(
        &brain_module::files::staging_path(&brain_module::files::root(&fx.app), &run),
        &key,
        false,
        brain_module::files::STAGING,
    )
    .await
    .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM items")
        .fetch_one(&st)
        .await
        .unwrap();
    assert_eq!(n, 1);
    // No key bytes in audit rows or events.
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let audit: Vec<(String,)> = sqlx::query_as("SELECT details FROM audit_events")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    let evs = format!(
        "{:?}",
        events::list_events(&fx.app.pool, 0, 1000).await.unwrap()
    );
    assert!(!evs.contains(&hex) && !audit.iter().any(|(d,)| d.contains(&hex)));
}

#[tokio::test]
async fn a_master_key_rotation_re_seals_the_brain_key_and_the_files_still_open() {
    let fx = fx().await;
    let run = start(&fx).await;
    send(
        &fx,
        &run,
        vec![item(1, "/h/Projects/Alpha/x", "t", "hello")],
    )
    .await;
    let before = key_of(&fx).await;
    let old = SecretBox::new(&[7; 32]);
    let new = SecretBox::new(&[9; 32]);
    secrets::reseal_all(
        &fx.app.pool,
        &SecretBox::new(&[9; 32]).with_extra(vec![old]),
        &new,
        false,
    )
    .await
    .unwrap();
    let v = secrets::open_for_module(&fx.app.pool, &new, "brain", "brain.key", "test")
        .await
        .unwrap();
    assert_eq!(v.len(), 64);
    let hex: String = before.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(*v, hex, "the same key, sealed under the new master key");
}
