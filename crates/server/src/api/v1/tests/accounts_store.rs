//! The Core account store (KAN-428): an account and its key are stored, replaced and deleted
//! together, the key never leaves the broker, and every change is audited without it. The gate
//! `secrets.provider_accounts` stays at its default (0) throughout: only throwaway values with
//! no key shape are stored.

use ainkrad_core::settings::Key;

use super::*;
use crate::ops::secretbox::SecretBox;
use crate::store::accounts as acc;
use crate::store::secrets as st;

pub(super) const V1: &str = "throwaway-account-value-one-5a91c3";
pub(super) const V2: &str = "throwaway-account-value-two-77d0be";

pub(super) async fn setup() -> (Fx, TestDevice, SecretBox) {
    let fx = fx().await;
    let vm = super::secrets::runner(&fx, "vm").await;
    let sealer = SecretBox::new(&[7; 32]);
    crate::store::settings::set(
        &fx.app.pool,
        Key::SecretsMode,
        ainkrad_core::settings::Scope::Server,
        "1",
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    (fx, vm, sealer)
}

fn new<'a>(label: &'a str, value: &'a str, runners: &'a [String]) -> acc::NewAccount<'a> {
    acc::NewAccount {
        provider: "anthropic",
        label,
        value,
        runners,
        cap: None,
    }
}

pub(super) async fn make(
    fx: &Fx,
    s: &SecretBox,
    label: &str,
    value: &str,
    runners: &[String],
) -> acc::Account {
    acc::create(
        &fx.app.pool,
        s,
        &new(label, value, runners),
        &fx.dev.id,
        super::super::BY,
        NOW,
    )
    .await
    .unwrap()
}

pub(super) fn code<T>(r: Result<T, st::Error>) -> &'static str {
    match r {
        Err(st::Error::Refused { code, .. }) => code,
        Err(e) => panic!("not a refusal: {e}"),
        Ok(_) => panic!("accepted"),
    }
}

#[tokio::test]
async fn an_account_stores_its_row_and_key_together_with_a_cap_of_four() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "claude-main", V1, std::slice::from_ref(&vm.id)).await;
    assert_eq!((a.cap, a.state.as_str()), (4, "active"));
    assert_eq!(a.masked_tail, &V1[V1.len() - 4..]);
    assert_eq!(a.runners, vec![vm.id.clone()]);
    assert_eq!(a.secret_name, format!("acct.anthropic.{}", a.id));
    // The broker holds the key under that name, in the account's scope.
    let secrets = st::list(&fx.app.pool).await.unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(
        (secrets[0].name.as_str(), secrets[0].runners.clone()),
        (a.secret_name.as_str(), vec![vm.id])
    );
    assert_eq!(acc::get(&fx.app.pool, a.id).await.unwrap(), a);
}

#[tokio::test]
async fn no_account_column_or_audit_row_holds_the_value() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "claude-main", V1, std::slice::from_ref(&vm.id)).await;
    acc::replace_secret(
        &fx.app.pool,
        &s,
        a.id,
        V2,
        None,
        &fx.dev.id,
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    acc::set_state(
        &fx.app.pool,
        a.id,
        "disabled",
        Some("test"),
        None,
        &fx.dev.id,
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    acc::delete(&fx.app.pool, a.id, &fx.dev.id, super::super::BY)
        .await
        .unwrap();
    let audit: Vec<String> = sqlx::query_scalar("SELECT details FROM audit_events")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    assert!(audit.iter().any(|d| d.contains("claude-main")));
    for d in &audit {
        assert!(!d.contains(V1) && !d.contains(V2), "{d}");
    }
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'account.%' ORDER BY seq",
    )
    .fetch_all(&fx.app.pool)
    .await
    .unwrap();
    assert_eq!(
        actions,
        [
            "account.created",
            "account.secret_replaced",
            "account.state_set",
            "account.deleted"
        ]
    );
    let cols: Vec<String> =
        sqlx::query_scalar("SELECT name FROM pragma_table_info('core_accounts')")
            .fetch_all(&fx.app.pool)
            .await
            .unwrap();
    assert!(
        !cols
            .iter()
            .any(|c| c.contains("value") || c.contains("sealed") || c.contains("token"))
    );
    assert!(
        !cols.contains(&"company_id".to_owned()),
        "accounts are global"
    );
}

#[tokio::test]
async fn replacing_the_key_cuts_a_new_tail_and_drops_the_old_leases() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "claude-main", V1, std::slice::from_ref(&vm.id)).await;
    st::lease(
        &fx.app.pool,
        &a.secret_name,
        &vm.id,
        None,
        &fx.dev.id,
        super::super::BY,
        NOW,
        fx.clock.unix(),
    )
    .await
    .unwrap();
    let b = acc::replace_secret(
        &fx.app.pool,
        &s,
        a.id,
        V2,
        None,
        &fx.dev.id,
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(b.masked_tail, &V2[V2.len() - 4..]);
    assert_eq!(
        b.runners,
        vec![vm.id],
        "the scope is kept when none is given"
    );
    let leases: i64 = sqlx::query_scalar("SELECT count(*) FROM core_secret_leases")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(leases, 0);
    let v: i64 = sqlx::query_scalar("SELECT version FROM core_secrets")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(v, 2);
}

#[tokio::test]
async fn deleting_removes_the_row_the_key_and_its_leases() {
    let (fx, vm, s) = setup().await;
    let a = make(&fx, &s, "claude-main", V1, std::slice::from_ref(&vm.id)).await;
    acc::delete(&fx.app.pool, a.id, &fx.dev.id, super::super::BY)
        .await
        .unwrap();
    assert!(st::list(&fx.app.pool).await.unwrap().is_empty());
    assert!(acc::list(&fx.app.pool).await.unwrap().is_empty());
    assert_eq!(code(acc::get(&fx.app.pool, a.id).await), "not_found");
    assert_eq!(
        code(acc::delete(&fx.app.pool, a.id, &fx.dev.id, super::super::BY).await),
        "not_found"
    );
}

#[tokio::test]
async fn a_refused_store_leaves_neither_half_behind() {
    let (fx, _vm, s) = setup().await;
    // A real key shape with the narrow gate off is refused by the broker; the row must go too.
    let real = "sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let r = acc::create(
        &fx.app.pool,
        &s,
        &new("claude-main", real, &[]),
        &fx.dev.id,
        super::super::BY,
        NOW,
    )
    .await;
    assert_eq!(code(r), "real_secret_refused");
    // The broker off (mode 0) refuses everything.
    crate::store::settings::set(
        &fx.app.pool,
        Key::SecretsMode,
        ainkrad_core::settings::Scope::Server,
        "0",
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    let r = acc::create(
        &fx.app.pool,
        &s,
        &new("claude-main", V1, &[]),
        &fx.dev.id,
        super::super::BY,
        NOW,
    )
    .await;
    assert_eq!(code(r), "secrets_disabled");
    assert!(acc::list(&fx.app.pool).await.unwrap().is_empty());
    assert!(st::list(&fx.app.pool).await.unwrap().is_empty());
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action LIKE 'account.%'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn input_is_validated_at_the_boundary() {
    let (fx, vm, s) = setup().await;
    let p = &fx.app.pool;
    let mk = |provider: &'static str, label: &'static str, runners: Vec<String>, cap| {
        let s = &s;
        let id = &fx.dev.id;
        async move {
            let n = acc::NewAccount {
                provider,
                label,
                value: V1,
                runners: &runners,
                cap,
            };
            acc::create(p, s, &n, id, super::super::BY, NOW).await
        }
    };
    assert_eq!(
        code(mk("openrouter", "a", vec![], None).await),
        "bad_request"
    );
    assert_eq!(
        code(mk("anthropic", "Bad Label", vec![], None).await),
        "bad_request"
    );
    assert_eq!(
        code(mk("anthropic", "a", vec![], Some(65)).await),
        "bad_request"
    );
    assert_eq!(
        code(mk("anthropic", "a", vec![], Some(-1)).await),
        "bad_request"
    );
    assert_eq!(
        code(mk("anthropic", "a", vec!["*".into()], None).await),
        "bad_request",
        "no wildcard scope"
    );
    assert_eq!(
        code(mk("anthropic", "a", vec![vm.id.clone(), vm.id.clone()], None).await),
        "bad_request"
    );
    let ok = mk("anthropic", "a", vec![], Some(0)).await.unwrap();
    assert_eq!(ok.cap, 0, "0 turns the cap off");
    assert_eq!(
        code(mk("openai", "a", vec![], None).await),
        "conflict",
        "labels are unique"
    );
    // Every refusal rolled back: only the one account exists.
    assert_eq!(acc::list(p).await.unwrap().len(), 1);
    assert_eq!(st::list(p).await.unwrap().len(), 1);
}

#[tokio::test]
async fn state_and_cap_changes_are_audited_and_bounded() {
    let (fx, _vm, s) = setup().await;
    let a = make(&fx, &s, "claude-main", V1, &[]).await;
    let p = &fx.app.pool;
    let by = &fx.dev.id;
    let d = acc::set_state(
        p,
        a.id,
        "disabled",
        Some("  rotated by hand "),
        Some("2026-10-22T11:00:00.000Z"),
        by,
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(
        (d.state.as_str(), d.state_reason.as_deref()),
        ("disabled", Some("rotated by hand"))
    );
    let e = acc::set_state(
        p,
        a.id,
        "active",
        Some("ignored"),
        Some("2026-10-22T11:00:00.000Z"),
        by,
        super::super::BY,
        NOW,
    )
    .await
    .unwrap();
    assert_eq!((e.state_reason, e.state_until), (None, None));
    assert_eq!(
        code(acc::set_state(p, a.id, "gone", None, None, by, super::super::BY, NOW).await),
        "bad_request"
    );
    assert_eq!(
        code(
            acc::set_state(
                p,
                a.id,
                "cooling",
                None,
                Some("soon"),
                by,
                super::super::BY,
                NOW
            )
            .await
        ),
        "bad_request"
    );
    assert_eq!(
        code(acc::set_state(p, 999, "active", None, None, by, super::super::BY, NOW).await),
        "not_found"
    );
    assert_eq!(
        acc::set_cap(p, a.id, 8, by, super::super::BY, NOW)
            .await
            .unwrap()
            .cap,
        8
    );
    assert_eq!(
        code(acc::set_cap(p, a.id, 65, by, super::super::BY, NOW).await),
        "bad_request"
    );
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action IN ('account.state_set', 'account.cap_set')",
    )
    .fetch_one(p)
    .await
    .unwrap();
    assert_eq!(n, 3);
}
