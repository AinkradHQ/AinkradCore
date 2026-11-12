//! Requests the gateway refuses on the harness's behalf (KAN-435 G6), each shaped from a real
//! capture: Codex's defaults, stored state, a request that does not say `store: false`, tools the
//! provider would run, and the websocket upgrade. A refusal is a 403 before anything is dialled.

use serde_json::{Value, json};

use super::harness_wiring::{Captured, SANDBOX, SHAPES, sse};
use super::*;
use crate::gateway::wiring::{gateway_port, wire};
use crate::gateway::{GW_PORT, sandbox_env};

fn env(pairs: &[(&str, &str)]) -> Vec<(String, std::ffi::OsString)> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).into()))
        .collect()
}

async fn codex_rig() -> Rig {
    let s = &SHAPES[1];
    rig(Opts::of(
        s.wire,
        s.host,
        s.base,
        s.provider,
        s.prefix,
        sse(s.reply),
    ))
    .await
}

#[test]
fn the_slot_marks_a_gateway_session_and_a_slot_without_a_valid_port_is_an_error() {
    let slot = sandbox_env(
        std::path::Path::new("/s/gateway.sock"),
        std::path::Path::new("/r"),
    );
    // Linux: the fixed port inside the session's own network namespace. macOS has no network
    // namespace, so each session gets its own free loopback port (#197): any valid port.
    if cfg!(target_os = "macos") {
        assert!(matches!(gateway_port(&slot), Ok(Some(p)) if p != 0));
    } else {
        assert_eq!(gateway_port(&slot), Ok(Some(GW_PORT)));
    }
    assert_eq!(gateway_port(&env(&[("PATH", "/bin")])), Ok(None));
    // Any of the slot's variables marks the session; then the port must be valid.
    for slot in [
        env(&[("AINKRAD_SANDBOX_GW_SOCK", "/s")]),
        env(&[("AINKRAD_SANDBOX_GW_FWD", "/r")]),
        env(&[("AINKRAD_SANDBOX_GW_PORT", "x")]),
        env(&[("AINKRAD_SANDBOX_GW_PORT", "0")]),
        env(&[("AINKRAD_SANDBOX_GW_PORT", "99999")]),
        env(&[
            ("AINKRAD_SANDBOX_GW_SOCK", "/s"),
            ("AINKRAD_SANDBOX_GW_PORT", ""),
        ]),
    ] {
        assert!(gateway_port(&slot).is_err(), "{slot:?}");
    }
    // The last value wins, as it does for the child.
    let twice = env(&[
        ("AINKRAD_SANDBOX_GW_PORT", "1111"),
        ("AINKRAD_SANDBOX_GW_PORT", "2222"),
    ]);
    assert_eq!(gateway_port(&twice), Ok(Some(2222)));
}

#[test]
fn a_session_that_is_not_sandboxed_is_never_wired_and_nothing_is_written() {
    let dir = std::env::temp_dir().join(format!("gw-unsandboxed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for harness in ["claude", "codex", "agy"] {
        let mut e = env(&[("PATH", "/bin"), ("OPENAI_API_KEY", "own")]);
        let why = wire(harness, 47833, &dir, &mut e, &mut vec![]).unwrap_err();
        assert!(why.contains("sandbox"), "{why}");
        assert_eq!(e.len(), 2, "the environment was changed");
    }
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "a file was written"
    );
    // The same call in a sandboxed session writes Codex's file.
    let mut e = env(&[SANDBOX]);
    wire("codex", 47833, &dir, &mut e, &mut vec![]).unwrap();
    assert!(dir.join("config.toml").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// What Codex would send with its defaults: the provider-side web search tool.
#[tokio::test]
async fn codex_without_web_search_disabled_is_refused_which_is_why_the_config_disables_it() {
    let r = codex_rig().await;
    let mut c = Captured::of(SHAPES[1].fixture);
    c.body["tools"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type": "web_search"}));
    let resp = c.send(&r).await;
    assert_eq!(status(&resp), 403);
    assert!(body_of(&resp).contains("tool_not_allowed"));
    assert_eq!(r.up.count(), 0);
}

#[tokio::test]
async fn a_responses_request_that_names_stored_state_is_refused_before_anything_is_dialled() {
    let r = codex_rig().await;
    for (key, value) in [
        ("previous_response_id", json!("resp_abc")),
        ("conversation", json!("conv_abc")),
        ("conversation", json!({"id": "conv_abc"})),
        ("prompt", json!({"id": "pmpt_abc"})),
        (
            "input",
            json!([{"role": "user", "content": "x"}, {"type": "item_reference", "id": "msg_1"}]),
        ),
        ("input", json!([{"id": "msg_1"}])),
        ("input", json!([{"type": null, "id": "msg_1"}])),
    ] {
        let mut c = Captured::of(SHAPES[1].fixture);
        c.body[key] = value.clone();
        let resp = c.send(&r).await;
        assert_eq!(status(&resp), 403, "{key}={value}");
        assert!(body_of(&resp).contains("param_not_allowed"), "{key}");
    }
    assert_eq!(r.up.count(), 0, "a refusal spends nothing");
    // What Codex sends (the whole input, `store: false`) is served; null means absent.
    let c = Captured::of(SHAPES[1].fixture);
    assert_eq!(c.body["store"], false);
    assert!(c.body.get("previous_response_id").is_none());
    assert_eq!(status(&c.send(&r).await), 200);
    assert_eq!(r.up.count(), 1);
    let mut c = Captured::of(SHAPES[1].fixture);
    c.body["previous_response_id"] = Value::Null;
    assert_eq!(status(&c.send(&r).await), 200);
}

#[tokio::test]
async fn a_responses_request_must_say_store_false() {
    let r = codex_rig().await;
    for store in [
        None,
        Some(json!(true)),
        Some(json!(null)),
        Some(json!("false")),
    ] {
        let mut c = Captured::of(SHAPES[1].fixture);
        match &store {
            Some(v) => c.body["store"] = v.clone(),
            None => {
                c.body.as_object_mut().unwrap().remove("store");
            }
        }
        let resp = c.send(&r).await;
        assert_eq!(status(&resp), 403, "{store:?}");
        assert!(body_of(&resp).contains("param_not_allowed"), "{store:?}");
    }
    assert_eq!(r.up.count(), 0);
}

#[tokio::test]
async fn tools_the_provider_would_run_are_refused_on_every_wire_and_the_real_ones_pass() {
    // The captured request of each harness is served as it is; one provider-side tool added to
    // it is refused, however the wire spells it.
    let extra = [
        json!({"type": "code_interpreter", "container": {"type": "auto"}}),
        json!({"type": "image_generation"}),
        json!({"type": "file_search", "vector_store_ids": ["vs_1"]}),
        json!({"googleMaps": {}}),
        json!({"googleSearch": {}}),
    ];
    for s in &SHAPES {
        let r = rig(Opts::of(
            s.wire,
            s.host,
            s.base,
            s.provider,
            s.prefix,
            sse(s.reply),
        ))
        .await;
        let c = Captured::of(s.fixture);
        assert_eq!(
            status(&c.send(&r).await),
            200,
            "{}: its own tools",
            s.provider
        );
        for tool in &extra {
            let mut c = Captured::of(s.fixture);
            c.body["tools"].as_array_mut().unwrap().push(tool.clone());
            let resp = c.send(&r).await;
            assert_eq!(status(&resp), 403, "{}: {tool}", s.provider);
            assert!(
                body_of(&resp).contains("tool_not_allowed"),
                "{}: {tool}",
                s.provider
            );
        }
        assert_eq!(
            r.up.count(),
            1,
            "{}: only the first was dialled",
            s.provider
        );
    }
}

#[tokio::test]
async fn a_web_search_hidden_in_codexs_namespace_tool_is_refused_and_its_real_one_passes() {
    let r = codex_rig().await;
    // The captured request has a `namespace` tool with function tools in it, and is served.
    let c = Captured::of(SHAPES[1].fixture);
    assert!(
        c.body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["type"] == "namespace")
    );
    assert_eq!(status(&c.send(&r).await), 200);
    let mut c = Captured::of(SHAPES[1].fixture);
    for t in c.body["tools"].as_array_mut().unwrap() {
        if t["type"] == "namespace" {
            t["tools"]
                .as_array_mut()
                .unwrap()
                .push(json!({"type": "web_search"}));
        }
    }
    let resp = c.send(&r).await;
    assert_eq!(status(&resp), 403);
    assert!(body_of(&resp).contains("tool_not_allowed"));
    assert_eq!(r.up.count(), 1, "only the first request was dialled");
}

#[tokio::test]
async fn the_websocket_transport_codex_would_otherwise_try_is_refused() {
    let r = codex_rig().await;
    let mut c = Captured::of(SHAPES[1].fixture);
    c.heads.push("Upgrade: websocket".to_owned());
    c.heads.push("Connection: Upgrade".to_owned());
    assert_eq!(status(&c.send(&r).await), 426);
    assert_eq!(r.up.count(), 0);
}
