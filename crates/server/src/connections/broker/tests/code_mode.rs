//! Code Mode search (E1.4): what a session may see follows its creator device's scopes NOW.

use super::*;
use crate::ops_catalog::session_scopes;

#[tokio::test]
async fn a_sessions_scopes_are_its_creator_devices_current_ones() {
    let f = fx().await;
    let s = f.bare_session(RUNNER).await;
    let set = |scopes: &'static str, status: &'static str| {
        let pool = f.j.pool.clone();
        async move {
            sqlx::query("UPDATE core_devices SET scopes = ?, status = ? WHERE id = ?")
                .bind(scopes)
                .bind(status)
                .bind(RUNNER)
                .execute(&pool)
                .await
                .unwrap();
        }
    };
    set(r#"["read","agent"]"#, "active").await;
    assert_eq!(
        session_scopes(&f.j.pool, &s).await.unwrap(),
        ["read", "agent"]
    );
    // A scope taken away shows on the next call.
    set(r#"["read"]"#, "active").await;
    assert_eq!(session_scopes(&f.j.pool, &s).await.unwrap(), ["read"]);
    // A revoked device sees nothing; so does an unknown session.
    set(r#"["read"]"#, "rejected").await;
    assert!(session_scopes(&f.j.pool, &s).await.unwrap().is_empty());
    assert!(
        session_scopes(&f.j.pool, "as_nope")
            .await
            .unwrap()
            .is_empty()
    );
}
