//! Provider presets (E7-3, D-19): code-defined OpenAI-wire providers where the user only pastes a
//! key. A key is bound to the account and its frozen host, not to a prefix; a preset cannot be
//! edited; an unpriced model on a preset account is accepted; the model list is kept per account.

use axum::http::{Method, StatusCode};
use serde_json::json;

use super::accounts_gateway::{open_gate, router};
use super::accounts_store::setup;
use super::chains::{BY, code, spec};
use super::*;
use crate::store::chains as ch;
use crate::store::providers as prov;
use crate::store::secrets::Error;
use crate::store::{account_keys, account_models, accounts as acc};

/// Dummy keys: none is a real credential. A preset's keys have no shape of their own.
const GROQ: &str = "gsk_TESTONLY0123456789abcdefghijklmnopqrstuv";
const MISTRAL: &str = "TESTONLYmistralkey0123456789abcdefghij";
const OR: &str = "sk-or-v1-0123456789abcdefghijklmnopqrstuvwxyzTESTONLY";
const ANT: &str = "sk-ant-api03-0123456789abcdefghijklmnopqrstuvwxyzTESTONLY";
const PROJ: &str = "sk-proj-0123456789abcdefghijklmnopqrstuvwxyzTESTONLY";

async fn store(
    fx: &Fx,
    s: &crate::ops::secretbox::SecretBox,
    provider: &str,
    label: &str,
    value: &str,
) -> Result<acc::Account, Error> {
    let new = acc::NewAccount {
        provider,
        label,
        value,
        runners: &[],
        cap: None,
        display_name: None,
    };
    acc::create(&fx.app.pool, s, &new, &fx.dev.id, BY, NOW).await
}

#[test]
fn the_presets_are_valid_openai_wire_gateway_providers_with_a_frozen_https_host() {
    let all = prov::presets();
    let ids: Vec<_> = all.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "openrouter",
            "aimlapi",
            "groq",
            "deepseek",
            "mistral",
            "xai",
            "apinex"
        ]
    );
    for p in all {
        // Every field passes the validation a user definition does (URL, wire, variable, ...).
        assert_eq!(prov::problem(&p), None, "{}", p.id);
        assert!(p.preset && !p.builtin, "{}", p.id);
        assert_eq!(
            (
                p.wire.as_str(),
                p.delivery.as_slice(),
                p.key_prefix.as_ref()
            ),
            ("openai-responses", ["gateway".to_owned()].as_slice(), None),
            "{}",
            p.id
        );
        assert_eq!(p.login_methods, ["paste"], "{}", p.id);
        // No invented model or price.
        assert!(p.models.is_empty() && p.priced_at.is_none(), "{}", p.id);
        // A preset holds keys with no key_prefix; a user definition still needs one.
        assert_eq!(account_keys::holds_keys_problem(&p), None, "{}", p.id);
    }
    assert!(account_keys::holds_keys_problem(&router("r", None)).is_some());
}

#[tokio::test]
async fn a_preset_is_listed_and_cannot_be_edited_deleted_or_made_by_a_user() {
    let fx = fx().await;
    let p = &fx.app.pool;
    let groq = prov::get(p, "groq").await.unwrap();
    assert!(groq.preset);
    assert_eq!(groq.base_url, "https://api.groq.com/openai/v1");
    let mut edited = groq.clone();
    edited.base_url = "https://evil.example.com".to_owned();
    assert_eq!(
        code(prov::replace(p, &edited, "d_x", BY, NOW).await),
        "bad_request"
    );
    assert_eq!(
        code(prov::delete(p, "groq", "d_x", BY).await),
        "bad_request"
    );
    assert_eq!(
        prov::get(p, "groq").await.unwrap().base_url,
        "https://api.groq.com/openai/v1",
        "a refused edit changes nothing"
    );
}

#[tokio::test]
async fn a_user_definition_cannot_take_a_preset_id_once_accounts_use_it() {
    let (fx, _vm, s) = setup().await;
    open_gate(&fx).await;
    let a = store(&fx, &s, "groq", "groq-main", GROQ).await.unwrap();
    assert_eq!(a.base_url, "https://api.groq.com/openai/v1");
    assert_eq!(
        code(
            prov::create(
                &fx.app.pool,
                &router("groq", Some("gsk_test_")),
                "d_x",
                BY,
                NOW
            )
            .await
        ),
        "conflict"
    );
}

#[tokio::test]
async fn a_preset_account_needs_no_key_prefix_and_is_bound_to_its_frozen_host() {
    let (fx, _vm, s) = setup().await;
    open_gate(&fx).await;
    // Only the key is pasted: no prefix, no definition row.
    let a = store(&fx, &s, "groq", "groq-main", GROQ).await.unwrap();
    assert_eq!(a.secret_name, format!("acct.groq.{}", a.id));
    let m = store(&fx, &s, "mistral", "mistral-main", MISTRAL)
        .await
        .unwrap();
    assert_eq!(m.base_url, "https://api.mistral.ai/v1");
    // Another provider's keys are refused under a preset: a key is not sent to a third party.
    for key in [ANT, PROJ] {
        assert_eq!(
            code(store(&fx, &s, "groq", "groq-bad", key).await),
            "bad_request",
            "{key}"
        );
    }
    // A key replaced is held to the same rule, and the host stays the frozen one.
    assert_eq!(
        code(acc::replace_secret(&fx.app.pool, &s, a.id, ANT, None, &fx.dev.id, BY, NOW).await),
        "bad_request"
    );
    let b = acc::replace_secret(&fx.app.pool, &s, a.id, MISTRAL, None, &fx.dev.id, BY, NOW)
        .await
        .unwrap();
    assert_eq!(b.base_url, "https://api.groq.com/openai/v1");
    // A user definition still needs its prefix.
    prov::create(&fx.app.pool, &router("router", None), "d_x", BY, NOW)
        .await
        .unwrap();
    assert_eq!(
        code(store(&fx, &s, "router", "r-main", GROQ).await),
        "bad_request"
    );
}

/// Stores `provider`'s account the way the API does (its own order pool) and returns that pool.
async fn placed(fx: &Fx, s: &crate::ops::secretbox::SecretBox, provider: &str, key: &str) -> i64 {
    let new = acc::NewAccount {
        provider,
        // The label is unique across providers.
        label: provider,
        value: key,
        runners: &[],
        cap: None,
        display_name: None,
    };
    let place = crate::store::placement::Placement {
        user: 1,
        ..Default::default()
    };
    let (_, (pool, _)) =
        acc::create_placed(&fx.app.pool, s, &new, "key", &fx.dev.id, BY, NOW, &place)
            .await
            .unwrap();
    pool
}

#[tokio::test]
async fn an_unpriced_model_is_accepted_on_a_preset_pool_but_not_on_a_user_definition() {
    let (fx, _vm, s) = setup().await;
    open_gate(&fx).await;
    let p = &fx.app.pool;
    let preset = placed(&fx, &s, "groq", GROQ).await;
    let mut e = spec(preset);
    e.model = Some("llama-3.3-70b-versatile");
    assert!(ch::create(p, 1, "c1", &[e], "d_x", BY, NOW).await.is_ok());
    prov::create(p, &router("router", Some("sk-or-v1-")), "d_x", BY, NOW)
        .await
        .unwrap();
    let user = placed(&fx, &s, "router", OR).await;
    let mut e = spec(user);
    e.model = Some("vendor/unlisted");
    assert_eq!(
        code(ch::create(p, 1, "c2", &[e], "d_x", BY, NOW).await),
        "bad_request"
    );
}

#[tokio::test]
async fn the_model_list_is_kept_per_account_filtered_and_served_on_the_read_scope() {
    let (fx, _vm, s) = setup().await;
    open_gate(&fx).await;
    let a = store(&fx, &s, "groq", "groq-main", GROQ).await.unwrap();
    let uri = format!("/api/v1/accounts/{}/models", a.id);
    let get = |dev: &TestDevice| send(&fx.app, req(Method::GET, &uri, Some(dev), None));
    let (st, b) = get(&fx.dev).await;
    assert_eq!(
        (st, b["models"].clone()),
        (StatusCode::OK, json!([])),
        "{b}"
    );
    assert!(b.get("fetched_at").is_none());
    let kept = account_models::save(
        &fx.app.pool,
        a.id,
        ["a/b", "m:online", "bad id", "c"]
            .map(str::to_owned)
            .to_vec(),
        NOW,
    )
    .await
    .unwrap();
    assert_eq!(kept, 2);
    // An empty read never wipes a good list.
    account_models::save(&fx.app.pool, a.id, Vec::new(), NOW)
        .await
        .unwrap();
    let (st, b) = get(&fx.dev).await;
    assert_eq!(
        (st, &b["models"]),
        (StatusCode::OK, &json!(["a/b", "c"])),
        "{b}"
    );
    assert!(b["fetched_at"].is_string());
    let (st, _) = send(
        &fx.app,
        req(
            Method::GET,
            "/api/v1/accounts/999/models",
            Some(&fx.dev),
            None,
        ),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    // The list goes with the account.
    acc::delete(&fx.app.pool, a.id, &fx.dev.id, BY)
        .await
        .unwrap();
    assert!(
        account_models::get(&fx.app.pool, a.id)
            .await
            .unwrap()
            .0
            .is_empty()
    );
}
