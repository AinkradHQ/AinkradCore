//! Provider definitions (KAN-429): the built-ins are fixed, a user definition is validated data,
//! an account is bound to its provider's base URL when stored, and an edit never moves it.

use ainkrad_core::settings::{Key, Scope};

use super::*;
use crate::ops::secretbox::SecretBox;
use crate::store::providers as prov;
use crate::store::secrets::Error;
use crate::store::{accounts as acc, providers::Definition};

const BY: ainkrad_core::audit::AuditActor = super::super::BY;

fn def(id: &str) -> Definition {
    Definition {
        id: id.to_owned(),
        name: "Example router".to_owned(),
        harness: "codex".to_owned(),
        auth_var: "OPENAI_API_KEY".to_owned(),
        base_url: "https://router.example.com/api/v1".to_owned(),
        usage_parser: "openai".to_owned(),
        delivery: vec!["env".to_owned(), "gateway".to_owned()],
        login_methods: vec!["paste".to_owned()],
        models: vec![prov::Model {
            id: "vendor/model-1".to_owned(),
            input_per_mtok_micro: 3_000_000,
            output_per_mtok_micro: 15_000_000,
        }],
        priced_at: Some("2026-11-01".to_owned()),
        wire: String::new(),
        key_prefix: None,
        test_path: None,
        builtin: false,
        version: 0,
    }
}

fn code<T>(r: Result<T, Error>) -> &'static str {
    match r {
        Err(Error::Refused { code, .. }) => code,
        Err(e) => panic!("not a refusal: {e}"),
        Ok(_) => panic!("accepted"),
    }
}

#[test]
fn a_definition_is_validated_field_by_field() {
    assert_eq!(prov::problem(&def("router")), None);
    let bad = |f: &dyn Fn(&mut Definition)| {
        let mut d = def("router");
        f(&mut d);
        prov::problem(&d).unwrap_or_else(|| panic!("accepted {d:?}"))
    };
    for url in [
        "http://router.example.com",
        "https://192.0.2.7/v1",
        "https://localhost/v1",
        "https://router.local",
        "https://user:pw@router.example.com",
        "https://router.example.com/?x=1",
        "https://router.example.com:8443",
        "https://router.example.com/../x",
        "https://[2001:db8::1]/",
        "https://router",
        "https://203.0.113.9.5",
        "https://ROUTER.example.com",
        "ftp://router.example.com",
    ] {
        bad(&|d| d.base_url = url.to_owned());
    }
    // Only the harness's own authentication variables; never a redirecting one.
    for var in [
        "HTTPS_PROXY",
        "OPENAI_BASE_URL",
        "PATH",
        "ANTHROPIC_API_KEY",
        "LD_PRELOAD",
        "openai_api_key",
    ] {
        bad(&|d| d.auth_var = var.to_owned());
    }
    bad(&|d| d.harness = "opencode".to_owned());
    bad(&|d| d.id = "anthropic".to_owned());
    bad(&|d| d.id = "Bad Id".to_owned());
    bad(&|d| d.usage_parser = "mine".to_owned());
    bad(&|d| d.delivery = vec!["file".to_owned()]);
    bad(&|d| d.delivery = vec![]);
    bad(&|d| d.login_methods = vec!["device_code".to_owned()]);
    bad(&|d| d.models[0].input_per_mtok_micro = -1);
    bad(&|d| d.models[0].output_per_mtok_micro = i64::MAX);
    bad(&|d| d.models.push(d.models[0].clone()));
    bad(&|d| d.models[0].id = "a b".to_owned());
    bad(&|d| d.name = String::new());
    // A codex definition may use CODEX_API_KEY; a claude one its OAuth variable too.
    let mut d = def("router");
    d.auth_var = "CODEX_API_KEY".to_owned();
    assert_eq!(prov::problem(&d), None);
}

#[tokio::test]
async fn the_built_ins_are_fixed_and_a_user_definition_is_stored_audited_and_versioned() {
    let fx = fx().await;
    let p = &fx.app.pool;
    let ids: Vec<_> = prov::list(p)
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.id)
        .collect();
    assert_eq!(ids, ["anthropic", "openai", "google", "claude-sub"]);
    assert_eq!(
        code(prov::create(p, &def("openai"), "d_x", BY, NOW).await),
        "bad_request"
    );
    assert_eq!(
        code(prov::delete(p, "openai", "d_x", BY).await),
        "bad_request"
    );
    let a = prov::create(p, &def("router"), "d_x", BY, NOW)
        .await
        .unwrap();
    assert_eq!((a.version, a.builtin), (1, false));
    assert_eq!(
        code(prov::create(p, &def("router"), "d_x", BY, NOW).await),
        "conflict"
    );
    let mut changed = def("router");
    changed.base_url = "https://other.example.com".to_owned();
    assert_eq!(
        prov::replace(p, &changed, "d_x", BY, NOW)
            .await
            .unwrap()
            .version,
        2
    );
    assert_eq!(
        prov::get(p, "router").await.unwrap().base_url,
        "https://other.example.com"
    );
    assert_eq!(
        code(prov::replace(p, &def("nope"), "d_x", BY, NOW).await),
        "not_found"
    );
    let mut invalid = def("router");
    invalid.auth_var = "HTTPS_PROXY".to_owned();
    assert_eq!(
        code(prov::replace(p, &invalid, "d_x", BY, NOW).await),
        "bad_request"
    );
    assert_eq!(
        prov::get(p, "router").await.unwrap().auth_var,
        "OPENAI_API_KEY",
        "a refused edit changes nothing"
    );
    prov::delete(p, "router", "d_x", BY).await.unwrap();
    assert_eq!(prov::list(p).await.unwrap().len(), 3);
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE action LIKE 'provider.%' ORDER BY seq",
    )
    .fetch_all(p)
    .await
    .unwrap();
    assert_eq!(
        actions,
        ["provider.created", "provider.updated", "provider.deleted"]
    );
}

#[tokio::test]
async fn the_number_of_user_definitions_is_bounded() {
    let fx = fx().await;
    for i in 0..32 {
        prov::create(&fx.app.pool, &def(&format!("p{i}")), "d_x", BY, NOW)
            .await
            .unwrap();
    }
    assert_eq!(
        code(prov::create(&fx.app.pool, &def("one-more"), "d_x", BY, NOW).await),
        "limit_reached"
    );
}

#[tokio::test]
async fn an_account_is_bound_to_its_providers_base_url_when_stored() {
    let fx = fx().await;
    let s = SecretBox::new(&[7; 32]);
    crate::store::settings::set(&fx.app.pool, Key::SecretsMode, Scope::Server, "1", BY, NOW)
        .await
        .unwrap();
    let new = acc::NewAccount {
        provider: "openai",
        label: "codex-main",
        value: "throwaway-provider-value-aa11bb22",
        runners: &[],
        cap: None,
    };
    let a = acc::create(&fx.app.pool, &s, &new, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    assert_eq!(a.base_url, "https://api.openai.com/v1");
    assert_eq!(
        acc::get(&fx.app.pool, a.id).await.unwrap().base_url,
        a.base_url
    );
    // A user definition that declares no key_prefix holds no key: its keys could not be bound to its host.
    prov::create(&fx.app.pool, &def("router"), "d_x", BY, NOW)
        .await
        .unwrap();
    let mut n = acc::NewAccount {
        provider: "router",
        ..new
    };
    n.label = "router-main";
    assert_eq!(
        code(acc::create(&fx.app.pool, &s, &n, &fx.dev.id, BY, NOW).await),
        "bad_request"
    );
}
