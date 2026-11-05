//! The harness side of the gateway (KAN-435 G6): what the runner writes for each harness, and the
//! request each real harness makes, replayed through the gateway against the fake upstream.
//!
//! The replays are requests captured from the real binaries on a Mac on 2026-11-05, each run
//! under macOS `sandbox-exec` (outbound network denied but for localhost) against a local Python
//! listener, with a dummy key and an empty home (`fixtures/*.json`; prompts, schemas and ids
//! trimmed, every header and field the gateway reads kept): Claude Code 2.1.318 (`claude -p` in
//! the adapter's stream-json mode), Codex 0.166.0 (`codex app-server`, the mode the runner runs)
//! and agy 1.5.1 (`agy -p` in the adapter's stream-json mode). No Rust gateway or forwarder was in
//! the loop for those runs, and nothing here runs a real harness binary: the gateway path is
//! replay only, and a real binary inside bubblewrap is a gap (CI has none; see the PR).

use std::ffi::OsString;

use ainkrad_proto::v2::{UpstreamStatus, Wire};
use serde_json::Value;

use super::*;
use crate::gateway::wiring::{PLACEHOLDER, wire};

/// What marks a session as sandboxed, which wiring requires.
pub(super) const SANDBOX: (&str, &str) = ("AINKRAD_SANDBOX", "1");

fn env(pairs: &[(&str, &str)]) -> Vec<(String, OsString)> {
    pairs
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).into()))
        .collect()
}

fn get<'a>(env: &'a [(String, OsString)], name: &str) -> Option<&'a str> {
    ainkrad_harness::last_env(env, name).and_then(|v| v.to_str())
}

fn names(env: &[(String, OsString)]) -> Vec<&str> {
    env.iter().map(|(n, _)| n.as_str()).collect()
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("gw-wiring-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn each_harness_is_given_its_base_url_and_the_placeholder_and_no_other_provider_variable() {
    // What an agent's grants, or the runner's `--env`, might have put there.
    let planted = [
        ("ANTHROPIC_API_KEY", "planted-1"),
        ("ANTHROPIC_AUTH_TOKEN", "planted-2"),
        ("ANTHROPIC_UNIX_SOCKET", "/planted"),
        ("CLAUDE_CODE_OAUTH_TOKEN", "planted-3"),
        ("CLAUDE_CODE_USE_BEDROCK", "1"),
        ("OPENAI_API_KEY", "planted-4"),
        ("OPENAI_BASE_URL", "http://planted.invalid"),
        ("CODEX_API_KEY", "planted-5"),
        ("GEMINI_API_KEY", "planted-6"),
        ("GOOGLE_GEMINI_BASE_URL", "http://planted.invalid"),
        ("GOOGLE_API_KEY", "planted-7"),
    ];
    let dir = scratch("each");
    for (harness, want) in [
        (
            "claude",
            vec![
                ("ANTHROPIC_BASE_URL", "http://127.0.0.1:47833"),
                ("ANTHROPIC_API_KEY", PLACEHOLDER),
            ],
        ),
        (
            "agy",
            vec![
                ("GOOGLE_GEMINI_BASE_URL", "http://127.0.0.1:47833"),
                ("GEMINI_API_KEY", PLACEHOLDER),
            ],
        ),
        ("codex", vec![("OPENAI_API_KEY", PLACEHOLDER)]),
    ] {
        let mut e = env(&[("PATH", "/bin"), ("GIT_AUTHOR_NAME", "a"), SANDBOX]);
        e.extend(env(&planted));
        let mut allow: Vec<String> = ["PATH", "HTTPS_PROXY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY"]
            .map(str::to_owned)
            .into();
        wire(harness, 47833, &dir, &mut e, &mut allow).unwrap();
        let provider: Vec<_> = names(&e).into_iter().filter(|n| provider_name(n)).collect();
        let mut named: Vec<_> = want.iter().map(|w| w.0).collect();
        named.sort_unstable();
        let mut got = provider.clone();
        got.sort_unstable();
        assert_eq!(
            got, named,
            "{harness}: only the wiring's own variables stay"
        );
        for (n, v) in &want {
            assert_eq!(get(&e, n), Some(*v), "{harness} {n}");
        }
        // Nothing the session already had is lost but the provider's.
        assert_eq!(get(&e, "PATH"), Some("/bin"));
        assert_eq!(get(&e, "GIT_AUTHOR_NAME"), Some("a"));
        // And the runner's own variables the child may inherit lose theirs.
        assert_eq!(allow, ["PATH", "HTTPS_PROXY"], "{harness}");
        // Every value is the placeholder or a loopback URL: a key cannot be in any.
        for (n, v) in &e {
            let v = v.to_str().unwrap();
            if provider_name(n) {
                assert!(
                    v == PLACEHOLDER || v.starts_with("http://127.0.0.1:"),
                    "{n}={v}"
                );
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn provider_name(n: &str) -> bool {
    [
        "ANTHROPIC_",
        "CLAUDE_CODE_",
        "OPENAI_",
        "CODEX_",
        "GEMINI_",
        "GOOGLE_",
    ]
    .iter()
    .any(|p| n.starts_with(p))
}

#[test]
fn codex_gets_its_config_in_codex_home_and_the_others_write_no_file() {
    let dir = scratch("codex");
    let mut e = env(&[SANDBOX]);
    wire("codex", 47833, &dir, &mut e, &mut vec![]).unwrap();
    let text = std::fs::read_to_string(dir.join("config.toml")).unwrap();
    assert_eq!(text, crate::codex_config::gateway(47833));
    for line in [
        "model_provider = \"gw\"",
        "base_url = \"http://127.0.0.1:47833/v1\"",
        "env_key = \"OPENAI_API_KEY\"",
        "wire_api = \"responses\"",
        "supports_websockets = false",
        "web_search = \"disabled\"",
    ] {
        assert!(text.lines().any(|l| l == line), "{line}:\n{text}");
    }
    assert!(
        !text.contains(PLACEHOLDER),
        "the key is in the env, not the file"
    );
    let other = scratch("claude-agy");
    for harness in ["claude", "agy"] {
        wire(harness, 47833, &other, &mut env(&[SANDBOX]), &mut vec![]).unwrap();
    }
    assert_eq!(std::fs::read_dir(&other).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&other);
}

#[test]
fn a_harness_with_no_wiring_is_refused_and_leaves_the_session_as_it_was() {
    let dir = scratch("opencode");
    let mut e = env(&[("OPENAI_API_KEY", "own"), ("PATH", "/bin"), SANDBOX]);
    let before = names(&e).len();
    let why = wire("opencode", 47833, &dir, &mut e, &mut vec![]).unwrap_err();
    assert!(
        why.contains("no wiring") && why.contains("opencode"),
        "{why}"
    );
    assert_eq!(names(&e).len(), before);
    assert_eq!(get(&e, "OPENAI_API_KEY"), Some("own"));
    let _ = std::fs::remove_dir_all(&dir);
}

// What each provider's fake answers: a streamed reply with usage 10 in, 2 out.
const ANTHROPIC_SSE: &str = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\",\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n\
     event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n\
     event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n\
     event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
const RESPONSES_SSE: &str = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r\",\"status\":\"in_progress\"}}\n\n\
     event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"hello\"}]}}\n\n\
     event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r\",\"status\":\"completed\",\"usage\":{\"input_tokens\":10,\"input_tokens_details\":{\"cached_tokens\":0},\"output_tokens\":2,\"total_tokens\":12}}}\n\n";
const GEMINI_SSE: &str = "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"hello\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":2,\"totalTokenCount\":12}}\n\n";

pub(super) fn sse(body: &str) -> Vec<Step> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    vec![Step::Send(head.into_bytes())]
}

/// A captured request ready to send: the request line, the header lines, the body.
pub(super) struct Captured {
    pub line: String,
    pub heads: Vec<String>,
    pub body: Value,
}

impl Captured {
    /// `fixture` with its model swapped for the grant's (in the body, or in the Gemini path).
    pub(super) fn of(fixture: &str) -> Captured {
        let v: Value = serde_json::from_str(fixture).unwrap();
        let mut body = v["body"].clone();
        let mut target = v["target"].as_str().unwrap().to_owned();
        if body.get("model").is_some() {
            body["model"] = MODEL.into();
        } else {
            let (pre, rest) = target.split_once("/models/").unwrap();
            let (_, action) = rest.split_once(':').unwrap();
            target = format!("{pre}/models/{MODEL}:{action}");
        }
        let mut heads: Vec<String> = v["headers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| format!("{k}: {}", v.as_str().unwrap()))
            .collect();
        heads.push("Connection: keep-alive".to_owned());
        heads.push("Accept-Encoding: gzip, deflate, br, zstd".to_owned());
        Captured {
            line: format!("{} {target} HTTP/1.1", v["method"].as_str().unwrap()),
            heads,
            body,
        }
    }

    pub(super) async fn send(&self, r: &Rig) -> Vec<u8> {
        let heads: Vec<&str> = self.heads.iter().map(String::as_str).collect();
        raw(
            &r.sock,
            &request(&self.line, &heads, &self.body.to_string()),
        )
        .await
    }
}

pub(super) struct Shape {
    pub fixture: &'static str,
    pub wire: Wire,
    pub host: &'static str,
    pub base: &'static str,
    pub provider: &'static str,
    pub prefix: &'static str,
    pub reply: &'static str,
    /// The request line and the key's header the upstream must see.
    upstream: &'static str,
    auth: &'static str,
}

pub(super) const SHAPES: [Shape; 3] = [
    Shape {
        fixture: include_str!("fixtures/claude.json"),
        wire: Wire::AnthropicMessages,
        host: "api.anthropic.com",
        base: "",
        provider: "anthropic",
        prefix: "sk-ant-",
        reply: ANTHROPIC_SSE,
        upstream: "POST /v1/messages?beta=true HTTP/1.1",
        auth: "x-api-key: ",
    },
    Shape {
        fixture: include_str!("fixtures/codex.json"),
        wire: Wire::OpenaiResponses,
        host: "api.openai.com",
        base: "/v1",
        provider: "openai",
        prefix: "sk-proj-",
        reply: RESPONSES_SSE,
        upstream: "POST /v1/responses HTTP/1.1",
        auth: "authorization: bearer ",
    },
    Shape {
        fixture: include_str!("fixtures/agy.json"),
        wire: Wire::GeminiGenerate,
        host: "generativelanguage.googleapis.com",
        base: "",
        provider: "google",
        prefix: "AIza",
        reply: GEMINI_SSE,
        upstream: "POST /v1beta/models/model-a:streamGenerateContent?alt=sse HTTP/1.1",
        auth: "x-goog-api-key: ",
    },
];

#[tokio::test]
async fn each_real_harness_request_is_served_with_the_real_key_and_metered() {
    for s in SHAPES {
        let mut r = rig(Opts::of(
            s.wire,
            s.host,
            s.base,
            s.provider,
            s.prefix,
            sse(s.reply),
        ))
        .await;
        let resp = Captured::of(s.fixture).send(&r).await;
        let text = String::from_utf8_lossy(&resp).into_owned();
        assert_eq!(status(&resp), 200, "{}: {text}", s.provider);
        assert!(text.contains("hello"), "{}: {text}", s.provider);
        assert_eq!(r.up.count(), 1);
        // The upstream got a fresh request with the real key and not the placeholder.
        let head = r.up.head(0);
        let lower = head.to_ascii_lowercase();
        assert!(head.starts_with(s.upstream), "{}: {head}", s.provider);
        assert!(
            lower.contains(&format!("{}{}", s.auth, r.key.to_ascii_lowercase())),
            "{}: {head}",
            s.provider
        );
        assert!(!lower.contains(PLACEHOLDER), "{}: {head}", s.provider);
        assert!(!head.contains("gzip"), "{}: {head}", s.provider);
        assert_eq!(head.matches(&r.key).count(), 1, "{}: {head}", s.provider);
        // The body the harness sent is what the upstream got, whole.
        let seen = r.up.seen.lock().unwrap()[0].body.clone();
        let sent: Value = serde_json::from_slice(&seen).unwrap();
        assert_eq!(sent, Captured::of(s.fixture).body, "{}", s.provider);
        // And the stream was counted: 10 in, 2 out, from the provider's own usage.
        let report = r.report().await;
        assert_eq!(report.status, UpstreamStatus::Ok, "{}", s.provider);
        assert_eq!(report.model.as_deref(), Some(MODEL));
        assert_eq!(
            (report.input, report.output, report.approximate),
            (10, 2, false),
            "{}",
            s.provider
        );
    }
}

#[tokio::test]
async fn the_anthropic_betas_claude_sends_are_all_kept() {
    let s = &SHAPES[0];
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
    let sent = c
        .heads
        .iter()
        .find_map(|h| h.strip_prefix("anthropic-beta: "))
        .unwrap();
    assert_eq!(status(&c.send(&r).await), 200);
    let head = r.up.head(0).to_ascii_lowercase();
    let kept = head
        .lines()
        .find_map(|l| l.strip_prefix("anthropic-beta: "))
        .unwrap_or_default();
    assert_eq!(
        kept.trim_end(),
        sent,
        "a beta Claude Code sends was dropped"
    );
}
