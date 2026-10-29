//! Per-run tokens: scoped to their run's issue and company, dead after the run ends or
//! expires, one per run, and never stored raw.

use citadel_core::audit::AuditActor;
use citadel_core::auth::{RunScope, RunToken};
use citadel_core::exec::RunEvent;

use super::flow::sibling;
use super::lease::assigned;
use super::wake::{dispatch, runner};
use super::*;

const NOW: &str = "2026-10-21T10:00:00.000Z";

/// `dev`'s run on its issue `i`, started at `NOW`, with its token.
async fn started(pool: &SqlitePool, name: &str) -> (Run, RunToken) {
    let (_, _) = assigned(pool, name).await;
    let mac = runner(pool, &format!("{name}-mac")).await;
    let run = dispatch(pool, mac, NOW).await.unwrap();
    start_run(pool, run.id, AuditActor::Runner(mac), None, NOW)
        .await
        .unwrap()
}

async fn authorize(pool: &SqlitePool, t: &RunToken, now: &str) -> Result<RunScope, AuthError> {
    authorize_run_token(pool, t.expose(), now).await
}

#[tokio::test]
async fn a_token_reaches_its_own_issue_only() {
    let db = db().await;
    let pool = &db.pool;
    let (a, ta) = started(pool, "A").await;
    let i = a.issue_id.unwrap();
    let other = sibling(pool, i).await;

    assert_eq!(a.state, RunState::Running);
    assert!(ta.expose().starts_with("cit_run_") && ta.expose().len() == 8 + 64);
    let scope = authorize(pool, &ta, NOW).await.unwrap();
    assert_eq!(
        (scope.run_id, scope.agent_id, scope.issue_id),
        (a.id, a.agent_id, Some(i))
    );
    assert_eq!(scope.require_issue(i), Ok(()));
    assert!(scope.require_issue(other).is_err());
    assert!(matches!(
        authorize_run_token(pool, "cit_run_guess", NOW).await,
        Err(AuthError::Unknown)
    ));
}

#[tokio::test]
async fn a_token_dies_when_its_run_ends_by_any_path() {
    let db = db().await;
    let pool = &db.pool;
    let (a, ta) = started(pool, "A").await;
    let by = AuditActor::Runner(a.runner_id.unwrap());
    transition_run(pool, a.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
    assert!(matches!(
        authorize(pool, &ta, NOW).await,
        Err(AuthError::Revoked)
    ));

    // Runner loss ends the run through the reaper: the same terminal path revokes it.
    let (b, tb) = started(pool, "B").await;
    let later = "2026-10-21T11:00:00.000Z";
    reap_expired_leases(pool, later).await.unwrap();
    let lost = get_run(pool, b.id).await.unwrap().unwrap();
    assert_eq!(lost.state, RunState::RunnerLost);
    assert!(matches!(
        authorize(pool, &tb, later).await,
        Err(AuthError::Revoked)
    ));
    // A run ended behind the engine's back (a raw write) still kills its token.
    let (c, tc) = started(pool, "C").await;
    sqlx::query("UPDATE runs SET state = 'cancelled', terminal_reason = 'raw' WHERE id = ?")
        .bind(c.id.0)
        .execute(pool)
        .await
        .unwrap();
    assert!(matches!(
        authorize(pool, &tc, NOW).await,
        Err(AuthError::RunNotLive)
    ));
    // A claimed run that never started never held a token, and one cannot be issued now.
    assert!(matches!(
        rotate_run_token(pool, b.id, AuditActor::System, later).await,
        Err(AuthError::RunNotLive)
    ));
}

#[tokio::test]
async fn a_token_expires_after_its_ttl_even_while_the_run_lives() {
    let db = db().await;
    let pool = &db.pool;
    let (_, t) = started(pool, "A").await;
    // NOW + RUN_TOKEN_TTL_SECS (12 h).
    assert!(
        authorize(pool, &t, "2026-10-21T21:59:59.000Z")
            .await
            .is_ok()
    );
    assert!(matches!(
        authorize(pool, &t, "2026-10-21T22:00:00.000Z").await,
        Err(AuthError::Expired)
    ));
}

#[tokio::test]
async fn a_run_holds_one_token_and_reissuing_revokes_the_old() {
    let db = db().await;
    let pool = &db.pool;
    let (a, old) = started(pool, "A").await;
    let new = rotate_run_token(pool, a.id, AuditActor::System, NOW)
        .await
        .unwrap();
    assert_ne!(old, new);
    assert!(matches!(
        authorize(pool, &old, NOW).await,
        Err(AuthError::Revoked)
    ));
    assert_eq!(authorize(pool, &new, NOW).await.unwrap().run_id, a.id);
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM run_tokens WHERE run_id = ? AND revoked_at IS NULL",
    )
    .bind(a.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(live, 1);
    let issued: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action = 'run.token_issued' AND run_id = ?",
    )
    .bind(a.id.0)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(issued, 2);
}

#[tokio::test]
async fn the_raw_token_never_reaches_the_database_file() {
    let db = db().await;
    let pool = &db.pool;
    let (_, t) = started(pool, "A").await;
    let hex = t.expose().strip_prefix("cit_run_").unwrap().to_owned();
    // Everything SQLite wrote: the database, its WAL and shared memory.
    let mut bytes = vec![];
    for entry in std::fs::read_dir(&db.dir).unwrap() {
        bytes.extend(std::fs::read(entry.unwrap().path()).unwrap());
    }
    let found = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(found(&key_hash(t.expose())), "the hash should be on disk");
    assert!(!found(hex.as_bytes()), "raw token on disk");
    assert!(
        !found(&hex.as_bytes()[..16]),
        "part of the raw token on disk"
    );
    let audited: String = sqlx::query_scalar("SELECT group_concat(details) FROM audit_events")
        .fetch_one(pool)
        .await
        .unwrap();
    assert!(!audited.contains(&hex));
}

#[tokio::test]
async fn a_token_never_reaches_another_company() {
    let db = db().await;
    let pool = &db.pool;
    let (a, ta) = started(pool, "A").await;
    let (b, tb) = started(pool, "B").await;
    let company = |r: &Run| {
        let agent = r.agent_id.0;
        async move {
            sqlx::query_scalar::<_, i64>("SELECT company_id FROM agents WHERE id = ?")
                .bind(agent)
                .fetch_one(pool)
                .await
                .map(CompanyId)
                .unwrap()
        }
    };
    let (ca, cb) = (company(&a).await, company(&b).await);
    assert_ne!(ca, cb);
    let sa = authorize(pool, &ta, NOW).await.unwrap();
    let sb = authorize(pool, &tb, NOW).await.unwrap();
    assert_eq!((sa.company_id, sb.company_id), (ca, cb));
    assert!(sa.require_company(cb).is_err());
    assert!(sa.require_issue(b.issue_id.unwrap()).is_err());
    assert!(sb.require_issue(a.issue_id.unwrap()).is_err());
}
