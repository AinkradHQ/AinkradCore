//! Delta review: operation/capability pairs, workspace membership, secure_delete scope.

use super::*;

#[tokio::test]
async fn a_use_record_needs_the_operation_to_belong_to_the_capability() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let rec = |cap: &'static str, op: &'static str| {
        let (pool, reg, id) = (fx.pool.clone(), fx.reg.clone(), c.id);
        async move {
            let cx = cx(cap);
            resolve::record_use(&pool, &reg, Some(id), "fake", (op, "ok", None), &cx).await
        }
    };
    assert!(rec("read_items", "fake.get_item").await.is_ok());
    assert!(rec("write_items", "fake.create_item").await.is_ok());
    // A write operation recorded as a read use (or the reverse) is refused.
    assert_eq!(
        code(rec("read_items", "fake.create_item").await),
        "bad_request"
    );
    assert_eq!(
        code(rec("write_items", "fake.get_item").await),
        "bad_request"
    );
    let rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'connection.used'")
            .fetch_one(&fx.pool)
            .await
            .unwrap();
    assert_eq!(rows, 2);
}

#[tokio::test]
async fn a_caller_must_belong_to_the_workspace_it_asks_in() {
    let fx = fx().await;
    second_user(&fx).await;
    let c = make(&fx, "fake", "a").await;
    grant_role(&fx, c.id, "member", None).await;
    let ok = cx("read_items");
    assert!(
        resolve::resolve(&fx.pool, &fx.reg, "fake", &ok, NOW)
            .await
            .is_ok()
    );
    // User 2 holds the role but is not a member of workspace 1; nor is user 1 of workspace 2.
    for bad in [
        Context { user: 2, ..ok },
        Context {
            workspace: 2,
            user: 1,
            ..ok
        },
    ] {
        let r = resolve::resolve(&fx.pool, &fx.reg, "fake", &bad, NOW).await;
        assert_eq!(code(r), "not_a_member");
    }
}

#[tokio::test]
async fn secure_delete_is_off_again_on_every_pooled_connection() {
    let fx = fx().await;
    let c = make(&fx, "fake", "a").await;
    let fresh = Material::new("c1probe-fresh-0009", None, None).unwrap();
    secret::replace(&fx.pool, &fx.sealer, c.id, &fresh, w(NOW))
        .await
        .unwrap();
    delete(&fx.pool, c.id, w(NOW)).await.unwrap();
    // Hold every connection of the pool at once, so each one is looked at.
    let mut held = Vec::new();
    for _ in 0..4 {
        let mut conn = fx.pool.acquire().await.unwrap();
        let on: i64 = sqlx::query_scalar("PRAGMA secure_delete")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(on, 0, "secure_delete leaked into an unrelated connection");
        held.push(conn);
    }
}
