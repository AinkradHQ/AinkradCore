use super::*;

// Shapes only; none of these is a real key.
const ANT: &str = "sk-ant-api03-TESTTESTTESTTESTTESTTEST";
const GOOG: &str = "AIzaTESTTESTTESTTESTTESTTESTTESTTEST";
const PROJ: &str = "sk-proj-TESTTESTTESTTESTTESTTEST";
const BARE: &str = "sk-TESTTESTTESTTESTTESTTEST";
const OR: &str = "sk-or-v1-TESTTESTTESTTESTTESTTEST";
const OR_HOST: UserKeyHost = UserKeyHost {
    provider: "openrouter",
    prefix: "sk-or-v1-",
    host: "openrouter.ai",
};

#[test]
fn each_builtin_class_goes_to_its_own_host_only() {
    let hosts = [
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        "api.openai.com",
    ];
    for (key, provider, host) in [
        (ANT, "anthropic", hosts[0]),
        (GOOG, "google", hosts[1]),
        (PROJ, "openai", hosts[2]),
        ("sk-svcacct-TESTTESTTEST", "openai", hosts[2]),
        ("sk-admin-TESTTESTTEST", "openai", hosts[2]),
        (BARE, "openai", hosts[2]),
    ] {
        assert_eq!(key_host_problem(key, provider, host, &[]), None, "{key}");
        assert_eq!(
            key_host_problem(key, provider, &host.to_uppercase(), &[]),
            None
        );
        for other in hosts.iter().filter(|h| **h != host) {
            assert!(
                key_host_problem(key, provider, other, &[]).is_some(),
                "{key} to {other}"
            );
        }
        // The right host under the wrong provider, and look-alike hosts.
        assert!(key_host_problem(key, "evil", host, &[]).is_some());
        for bad in [
            format!("{host}."),
            format!("x.{host}"),
            format!("{host}.evil.com"),
            String::new(),
        ] {
            assert!(
                key_host_problem(key, provider, &bad, &[]).is_some(),
                "{bad}"
            );
        }
    }
    // Spec case: an Anthropic key to OpenAI's host.
    assert!(key_host_problem(ANT, "anthropic", "api.openai.com", &[]).is_some());
}

#[test]
fn a_user_prefix_binds_its_key_to_its_host_and_no_other() {
    let user = [OR_HOST];
    assert_eq!(
        key_host_problem(OR, "openrouter", "openrouter.ai", &user),
        None
    );
    // Not to OpenAI's host, nor under the openai provider (the bare `sk-` catch-all).
    assert!(key_host_problem(OR, "openrouter", "api.openai.com", &user).is_some());
    assert!(key_host_problem(OR, "openai", "api.openai.com", &user).is_some());
    // Without the declaration it is just a bare `sk-` key: OpenAI's only.
    assert_eq!(key_host_problem(OR, "openai", "api.openai.com", &[]), None);
    // A built-in-shaped key never goes to a user host.
    assert!(key_host_problem(ANT, "openrouter", "openrouter.ai", &user).is_some());
    assert!(key_host_problem(PROJ, "openrouter", "openrouter.ai", &user).is_some());
    // A shape nothing knows is refused.
    assert!(key_host_problem("zz-TESTTESTTEST", "openrouter", "openrouter.ai", &user).is_some());
    // The longest declared prefix wins.
    let longer = UserKeyHost {
        provider: "other",
        prefix: "sk-or-v1-x",
        host: "other.example",
    };
    let both = [OR_HOST, longer];
    assert_eq!(
        key_host_problem("sk-or-v1-xTEST", "other", "other.example", &both),
        None
    );
    assert!(key_host_problem("sk-or-v1-xTEST", "openrouter", "openrouter.ai", &both).is_some());
}

#[test]
fn a_user_prefix_must_be_long_and_must_not_touch_a_builtin_shape() {
    assert_eq!(key_prefix_problem("sk-or-v1-"), None);
    assert_eq!(key_prefix_problem("tok_live_"), None);
    for bad in [
        "sk-or",
        "",
        "sk-",
        "AIza",
        "sk-ant-",
        "sk-proj-",
        "sk-ant-x1",
        "AIzaSy",
        "sk-svcacct-a",
        "sk-adm",
        "tok live",
    ] {
        assert!(key_prefix_problem(bad).is_some(), "{bad:?}");
    }
}

#[test]
fn grants_and_ops_round_trip_and_hide_the_lease() {
    let grant = GatewayGrant {
        lease: "l_secretlease".into(),
        account: 7,
        provider: "anthropic".into(),
        user_key: None,
        prices: vec![ModelPrice {
            model: "claude-x".into(),
            input: 3_000_000,
            output: 15_000_000,
            cache_read: 300_000,
            cache_write: 3_750_000,
        }],
        upstream: Upstream {
            host: "api.anthropic.com".into(),
            base_path: String::new(),
            wire: Wire::AnthropicMessages,
            auth: Wire::AnthropicMessages.auth(),
        },
        models: vec!["claude-x".into()],
        ceiling: Ceiling {
            tokens: 1000,
            usd_micros: 5_000_000,
        },
        rate: Rate {
            per_minute: 60,
            concurrent: 2,
        },
    };
    let json = serde_json::to_value(&grant).unwrap();
    assert_eq!(json["upstream"]["wire"], "anthropic-messages");
    assert_eq!(json["upstream"]["auth"], "x_api_key");
    assert_eq!(serde_json::from_value::<GatewayGrant>(json).unwrap(), grant);
    assert!(!format!("{grant:?}").contains("secretlease"));
    let test = GatewayTest {
        lease: "l_secretlease".into(),
        provider: "anthropic".into(),
        user_key: None,
        upstream: grant.upstream.clone(),
    };
    assert!(!format!("{test:?}").contains("secretlease"));
    let cmd = crate::v2::Command::AgentLimit(AgentLimit {
        session: "as_a".into(),
        ceiling: Ceiling {
            tokens: 0,
            usd_micros: 0,
        },
    });
    assert_eq!(cmd.op(), OP_AGENT_LIMIT);
    let back: crate::v2::Command =
        serde_json::from_value(serde_json::to_value(&cmd).unwrap()).unwrap();
    assert_eq!(back, cmd);
    assert_eq!(crate::v2::Command::GatewayTest(test).op(), OP_GATEWAY_TEST);
}

#[test]
fn a_grant_carries_what_the_runner_needs_to_run_the_key_rule() {
    let def = UserKeyDef {
        prefix: "sk-or-v1-".into(),
        host: "openrouter.ai".into(),
    };
    let user = [def.of("openrouter")];
    assert_eq!(
        key_host_problem(OR, "openrouter", "openrouter.ai", &user),
        None
    );
    assert!(key_host_problem(OR, "openrouter", "api.openai.com", &user).is_some());
    // A frame from before the fields existed reads with an empty provider, which no key passes.
    let old = serde_json::json!({
        "lease": "l_x", "account": 1,
        "upstream": {"host": "api.anthropic.com", "wire": "anthropic-messages", "auth": "x_api_key"},
        "models": [], "ceiling": {"tokens": 1, "usd_micros": 1}, "rate": {"per_minute": 1, "concurrent": 1}
    });
    let grant: GatewayGrant = serde_json::from_value(old).unwrap();
    assert_eq!(grant.provider, "");
    assert!(grant.user_key.is_none() && grant.prices.is_empty());
    assert!(key_host_problem(ANT, &grant.provider, "api.anthropic.com", &[]).is_some());
}

#[test]
fn a_test_result_is_a_status_class_and_nothing_else() {
    let ok = GatewayTested {
        result: UpstreamStatus::RefusedAddress,
        latency_ms: 3,
    };
    let json = serde_json::to_value(&ok).unwrap();
    assert_eq!(json["result"], "refused_address");
    assert!(
        serde_json::from_value::<GatewayTested>(
            serde_json::json!({"result": "free text", "latency_ms": 1})
        )
        .unwrap()
        .result
            == UpstreamStatus::Unknown
    );
}
