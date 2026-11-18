//! B8-02: the session-start bundle rides in the instructions P3-03 writes (the harness side, for claude,
//! codex and agy alike, is `AgentStart.instructions`: the harness crate tests cover each one's file).
//! Every item here is synthetic.

use ainkrad_core::untrusted::{CLOSE, OPEN};
use ainkrad_core_server::module::Module;

use super::ai::{ALPHA, open_room, put_record, session, session_unlinked};
use super::common::*;

const TEXT: &str = "Use tabs. Run the linter first.";

/// A claimed session of room Alpha, with approved instructions and two records.
async fn setup() -> (Fx, String, String) {
    let fx = fx().await;
    let alpha = committed_room_named(&fx, "Alpha", &[("Notes", "alpha notes ang=20 ")]).await;
    let s = session(&fx, ALPHA, &["anthropic"]).await;
    sqlx::query(
        "INSERT INTO brain_session_rooms (session, room, chain, claimed_by) VALUES (?, ?, '[]', ?)",
    )
    .bind(&s)
    .bind(&alpha)
    .bind(&fx.admin.id)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    put_record(
        &fx,
        &alpha,
        "r1",
        "fact",
        "accepted",
        "rotate the signing keys ang=10 ",
    )
    .await;
    put_record(
        &fx,
        &alpha,
        "r2",
        "rule",
        "accepted",
        "never push to main ang=50 ",
    )
    .await;
    let p = canon_pool(&fx, &alpha).await;
    sqlx::query(
        "INSERT OR REPLACE INTO room_overview (id, instructions, instructions_approved_at, updated_at) \
         VALUES (1, ?, '2026-11-18T10:00:00.000Z', '2026-11-18T10:00:00.000Z')",
    )
    .bind(TEXT)
    .execute(&p)
    .await
    .unwrap();
    p.close().await;
    open_room(&fx, &alpha).await;
    (fx, alpha, s)
}

async fn loaded(fx: &Fx, s: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT record FROM brain_session_loaded WHERE session = ? ORDER BY record")
        .bind(s)
        .fetch_all(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_bundle_follows_the_approved_text_inside_one_envelope_and_the_ids_are_recorded() {
    let (fx, _alpha, s) = setup().await;
    let text = fx.brain.session_instructions(&fx.app, &s).await.unwrap();
    // The approved text first, plain; then exactly one envelope holding the records.
    assert!(text.starts_with(TEXT), "{text}");
    assert_eq!(text.matches(OPEN).count(), 1, "{text}");
    assert!(text.ends_with(CLOSE), "{text}");
    let (plain, bundle) = text.split_at(text.find(OPEN).unwrap());
    assert_eq!(plain.trim_end(), TEXT);
    assert!(
        bundle.contains("[r1]") && bundle.contains("[r2]"),
        "{bundle}"
    );
    // Not said twice: the bundle leaves the approved instructions to the plain part.
    assert!(!bundle.contains(TEXT), "{bundle}");
    assert_eq!(loaded(&fx, &s).await, ["r1", "r2"]);
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_events WHERE action = 'brain.ai.context'")
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].contains("signing keys"), "{}", rows[0]);
}

#[tokio::test]
async fn a_session_that_can_no_longer_see_the_room_gets_nothing() {
    let (fx, _alpha, s) = setup().await;
    // A session that is over no longer sees the room: the op refuses it, and the approved text is
    // withheld too (it goes only to a session the room is visible to, #370 review).
    sqlx::query("UPDATE core_agent_sessions SET state = 'ended' WHERE id = ?")
        .bind(&s)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let text = fx.brain.session_instructions(&fx.app, &s).await;
    assert_eq!(text, None);
    assert!(loaded(&fx, &s).await.is_empty());
}

#[tokio::test]
async fn a_session_with_no_claim_gets_no_room_records() {
    let (fx, _alpha, _s) = setup().await;
    let free = session_unlinked(&fx, ALPHA, &["anthropic"]).await;
    let text = fx.brain.session_instructions(&fx.app, &free).await;
    assert!(
        text.as_deref().is_none_or(|t| !t.contains("[r1]")),
        "{text:?}"
    );
    assert!(loaded(&fx, &free).await.is_empty());
}

#[tokio::test]
async fn the_bundle_stays_inside_the_start_budget() {
    let (fx, alpha, s) = setup().await;
    for n in 0..40 {
        put_record(
            &fx,
            &alpha,
            &format!("w{n:02}"),
            "fact",
            "accepted",
            &format!("{n} {}", "word ".repeat(80)),
        )
        .await;
    }
    let text = fx.brain.session_instructions(&fx.app, &s).await.unwrap();
    let bundle = &text[text.find(OPEN).unwrap()..];
    // 1,500 tokens of body at 4 characters each, plus the envelope's own few lines.
    assert!(
        bundle.chars().count() <= 1500 * 4 + 800,
        "{}",
        bundle.chars().count()
    );
    assert!(loaded(&fx, &s).await.len() <= 10);
}
