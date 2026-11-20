//! E15 security review regressions that need the database.

use super::*;
use crate::store::gov;

/// A runner device paired with `sas` (`bundled`: the attested This Mac), or with no pairing row.
async fn runner(fx: &Fx, name: &str, pairing: Option<(&str, bool)>) -> String {
    let r = TestDevice::enroll(
        &fx.app.pool,
        name,
        "runner",
        &["runner"],
        &fx.app.auth.identity.fp,
        fx.clock.clone(),
    )
    .await;
    if let Some((sas, bundled)) = pairing {
        let id = format!("p_{:0>26}", name);
        sqlx::query(
            "INSERT INTO core_pairings (id, code_hash, secret_hash, kind, name, scopes, bootstrap, \
             invite, created_at, expires_at, status, device_id, sas, bundled) \
             VALUES (?, randomblob(32), randomblob(32), 'runner', ?, '[\"runner\"]', 0, 0, \
             '2026-01-01T00:00:00Z', '2026-01-01T00:05:00Z', 'approved', ?, ?, ?)",
        )
        .bind(id)
        .bind(name)
        .bind(&r.id)
        .bind(sas)
        .bind(bundled)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    }
    r.id
}

/// M6: the Core itself refuses a terminal on a plain paired runner; the Core's own runner and
/// the attested This Mac keep theirs.
#[tokio::test]
async fn only_the_core_and_this_mac_host_terminals() {
    let fx = fx().await;
    let core = runner(&fx, "core", Some((gov::LOCAL_ENROL_SAS, false))).await;
    let mac = runner(&fx, "mac", Some(("123456", true))).await;
    let remote = runner(&fx, "remote", Some(("654321", false))).await;
    let ok = |d: String| {
        let pool = fx.app.pool.clone();
        async move {
            crate::hardware::view::hosts_terminals(&pool, &d)
                .await
                .unwrap()
        }
    };
    assert!(ok(core).await);
    assert!(ok(mac).await);
    assert!(!ok(remote).await);
}

/// E15-2 §4.1 (e2e round 1): a session with no project on the Core's own runner is told its place
/// in the workspace, `u/<user>/s/<session>`, and once the runner reports that folder its `ws_path`
/// is set; a session on another runner, or a folder anywhere else, keeps `ws_path` NULL.
#[tokio::test]
async fn a_built_in_runners_session_gets_its_workspace_folder_and_ws_path() {
    use crate::workspace::adopt::{bind_folder, core_folder, workspace};
    use crate::workspace::paths::SessionKey;
    let fx = fx().await;
    let core = runner(&fx, "core", Some((gov::LOCAL_ENROL_SAS, false))).await;
    let remote = runner(&fx, "remote", Some(("654321", false))).await;
    let policy = serde_json::json!({"mode": "ask"});
    let make = |runner: String| {
        let (pool, dev, policy) = (fx.app.pool.clone(), fx.dev.id.clone(), policy.clone());
        async move {
            let new = crate::store::agents::NewSession {
                runner: &runner,
                harness: "claude",
                model: None,
                prompt: None,
                workspace: None,
                policy: &policy,
                secrets: &[],
                created_by: &dev,
            };
            crate::store::agents::create(&pool, &new, super::super::BY, NOW)
                .await
                .unwrap()
        }
    };
    let (mine, theirs) = (make(core.clone()).await, make(remote.clone()).await);
    let want = workspace()
        .session_dir(&SessionKey {
            id: &mine.id,
            user: ainkrad_core::ids::UserId(1),
            project: None,
        })
        .unwrap();
    let want = want.to_string_lossy().into_owned();
    assert!(want.ends_with(&format!("/u/1/s/{}", mine.id)), "{want}");
    let p = &fx.app.pool;
    assert_eq!(
        core_folder(p, &mine.id, &core).await.unwrap().as_deref(),
        Some(want.as_str())
    );
    assert_eq!(core_folder(p, &theirs.id, &remote).await.unwrap(), None);
    let ws_path = |id: String| {
        let p = p.clone();
        async move {
            sqlx::query_scalar::<_, Option<String>>(
                "SELECT ws_path FROM core_agent_sessions WHERE id = ?",
            )
            .bind(id)
            .fetch_one(&p)
            .await
            .unwrap()
        }
    };
    let mut conn = p.acquire().await.unwrap();
    // The runner's own scratch folder is not the Core's: nothing is bound.
    let scratch = format!("/var/lib/akrw/ainkrad-agent-runs-x/session-{}", mine.id);
    assert_eq!(
        bind_folder(&mut conn, &mine.id, &scratch).await.unwrap(),
        None
    );
    assert_eq!(ws_path(mine.id.clone()).await, None);
    assert!(
        bind_folder(&mut conn, &mine.id, &want)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        ws_path(mine.id.clone()).await.as_deref(),
        Some(want.as_str())
    );
    assert_eq!(
        bind_folder(&mut conn, &theirs.id, &want).await.unwrap(),
        None
    );
    assert_eq!(ws_path(theirs.id.clone()).await, None);
}
