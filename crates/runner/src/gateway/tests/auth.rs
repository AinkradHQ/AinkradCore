//! Auth strip and inject, the route tables, the model allowlist, both header allowlists, and
//! what must never carry the key.

use ainkrad_proto::v2::Wire;

use super::*;

/// The auth names an agent might send: all of them are replaced, none reaches the upstream.
const AGENT_AUTH: [&str; 4] = [
    "x-api-key: agent-one",
    "Authorization: Bearer agent-two",
    "x-goog-api-key: agent-three",
    "Cookie: session=agent-four",
];

struct Shape {
    wire: Wire,
    host: &'static str,
    base: &'static str,
    provider: &'static str,
    prefix: &'static str,
    /// What the agent calls, and what the upstream must see.
    agent: &'static str,
    upstream: &'static str,
    /// The header that carries the real key, lower-case, up to the value.
    auth: &'static str,
}

const SHAPES: [Shape; 3] = [
    Shape {
        wire: Wire::AnthropicMessages,
        host: "api.anthropic.com",
        base: "",
        provider: "anthropic",
        prefix: "sk-ant-",
        agent: "POST /v1/messages?beta=true&key=agent-q HTTP/1.1",
        upstream: "POST /v1/messages?beta=true HTTP/1.1",
        auth: "x-api-key: ",
    },
    Shape {
        wire: Wire::OpenaiResponses,
        host: "api.openai.com",
        base: "/v1",
        provider: "openai",
        prefix: "sk-proj-",
        agent: "POST /v1/responses?key=agent-q HTTP/1.1",
        upstream: "POST /v1/responses HTTP/1.1",
        auth: "authorization: bearer ",
    },
    Shape {
        wire: Wire::GeminiGenerate,
        host: "generativelanguage.googleapis.com",
        base: "",
        provider: "google",
        prefix: "AIza",
        agent: "POST /v1beta/models/model-a:streamGenerateContent?alt=sse&key=agent-q HTTP/1.1",
        upstream: "POST /v1beta/models/model-a:streamGenerateContent?alt=sse HTTP/1.1",
        auth: "x-goog-api-key: ",
    },
];

#[tokio::test]
async fn the_agents_auth_is_stripped_and_the_real_key_is_put_on_each_wires_own_header() {
    for s in SHAPES {
        let r = rig(Opts::of(
            s.wire,
            s.host,
            s.base,
            s.provider,
            s.prefix,
            ok_script(),
        ))
        .await;
        let mut heads = vec![
            "anthropic-version: 2023-06-01",
            "User-Agent: harness/1",
            "x-stainless-os: Linux",
            "X-Forwarded-For: 203.0.113.5",
            "x-claude-code-session-id: abc",
            "Accept-Encoding: gzip",
        ];
        heads.extend(AGENT_AUTH);
        let body = model_body();
        let resp = raw(&r.sock, &request(s.agent, &heads, &body)).await;
        assert_eq!(status(&resp), 200, "{}", String::from_utf8_lossy(&resp));
        assert_eq!(body_of(&resp), "{}");
        assert_eq!(r.up.count(), 1);
        let head = r.up.head(0);
        let lower = head.to_ascii_lowercase();
        assert!(head.starts_with(s.upstream), "{head}");
        assert!(lower.contains(&format!("host: {}\r\n", s.host)), "{head}");
        let auth = format!("{}{}", s.auth, r.key.to_ascii_lowercase());
        assert!(lower.contains(&auth), "{head}");
        // The key rides on exactly one header line.
        assert_eq!(head.matches(&r.key).count(), 1, "{head}");
        for gone in [
            "agent-",
            "cookie",
            "x-forwarded-for",
            "x-claude-code",
            "gzip",
            "key=agent",
        ] {
            assert!(!lower.contains(gone), "{gone} reached the upstream: {head}");
        }
        // What the allow-list keeps.
        for kept in [
            "anthropic-version: 2023-06-01",
            "user-agent: harness/1",
            "x-stainless-os: linux",
        ] {
            assert!(lower.contains(kept), "{kept} missing: {head}");
        }
        assert!(
            lower.contains("accept-encoding: identity\r\n")
                && lower.contains("connection: close\r\n")
        );
        assert_eq!(r.up.seen.lock().unwrap()[0].body, body.as_bytes());
    }
}

#[tokio::test]
async fn a_user_defined_provider_serves_its_own_host_and_base_path_with_a_bearer_key() {
    let mut o = Opts::of(
        Wire::OpenaiResponses,
        "openrouter.example.test",
        "/api/v1",
        "openrouter",
        "sk-or-v1-",
        ok_script(),
    );
    o.grant.user_key = Some(user_def());
    let r = rig(o).await;
    let resp = raw(
        &r.sock,
        &request("POST /v1/responses HTTP/1.1", &[], &model_body()),
    )
    .await;
    assert_eq!(status(&resp), 200);
    let head = r.up.head(0);
    assert!(
        head.starts_with("POST /api/v1/responses HTTP/1.1"),
        "{head}"
    );
    assert!(
        head.contains(&format!("authorization: Bearer {}", r.key)),
        "{head}"
    );
}

#[tokio::test]
async fn only_the_wires_routes_pass_and_everything_else_is_refused_before_the_upstream() {
    let r = rig(Opts::anthropic(ok_script())).await;
    let cases: [(&str, u16); 16] = [
        ("GET /v1/models HTTP/1.1", 403),
        ("POST /v1/models HTTP/1.1", 403),
        ("POST /v1/messages/ HTTP/1.1", 403),
        ("POST /v1/messages/../models HTTP/1.1", 403),
        ("POST /v1/%6dessages HTTP/1.1", 403),
        ("POST /v1/messages%2f HTTP/1.1", 403),
        ("POST //v1/messages HTTP/1.1", 403),
        ("POST /v1/./messages HTTP/1.1", 403),
        ("POST /V1/messages HTTP/1.1", 403),
        ("POST /v1/files HTTP/1.1", 403),
        ("POST /v1/organizations/x/api_keys HTTP/1.1", 403),
        ("POST /v1/messages/batches HTTP/1.1", 403),
        ("POST /v1/messages?stream=true HTTP/1.1", 403),
        ("POST /v1/messages?beta=true&beta=true HTTP/1.1", 403),
        ("GET /v1/messages HTTP/1.1", 405),
        ("DELETE /v1/messages HTTP/1.1", 405),
    ];
    for (line, want) in cases {
        let resp = raw(&r.sock, &request(line, &[], &model_body())).await;
        assert_eq!(
            status(&resp),
            want,
            "{line}: {}",
            String::from_utf8_lossy(&resp)
        );
    }
    assert_eq!(r.up.count(), 0);
    // The OpenAI and Gemini tables, too.
    let o = rig(Opts::of(
        Wire::OpenaiResponses,
        "api.openai.com",
        "/v1",
        "openai",
        "sk-proj-",
        ok_script(),
    ))
    .await;
    for line in [
        "POST /v1/messages HTTP/1.1",
        "POST /responses HTTP/1.1",
        "POST /v1/responses?x=1 HTTP/1.1",
        "POST /v1/embeddings HTTP/1.1",
    ] {
        assert_eq!(
            status(&raw(&o.sock, &request(line, &[], &model_body())).await),
            403,
            "{line}"
        );
    }
    let g = rig(Opts::of(
        Wire::GeminiGenerate,
        "generativelanguage.googleapis.com",
        "",
        "google",
        "AIza",
        ok_script(),
    ))
    .await;
    for line in [
        "POST /v1beta/models/model-a:countTokens HTTP/1.1",
        "POST /v1beta/models/model-a:generateContent?alt=sse HTTP/1.1",
        "POST /v1beta/models/../x:generateContent HTTP/1.1",
        "POST /v1beta/models/a%2fb:generateContent HTTP/1.1",
        "POST /v1beta/models/:generateContent HTTP/1.1",
        "POST /v1/models/model-a:generateContent HTTP/1.1",
        "GET /v1beta/models HTTP/1.1",
    ] {
        assert_eq!(
            status(&raw(&g.sock, &request(line, &[], "{}")).await),
            403,
            "{line}"
        );
    }
    assert_eq!(o.up.count() + g.up.count(), 0);
}

#[tokio::test]
async fn a_model_outside_the_priced_grant_is_refused_and_the_body_must_be_one_object() {
    let r = rig(Opts::anthropic(ok_script())).await;
    let cases: [(&str, u16); 11] = [
        ("{\"model\":\"other\"}", 403),
        ("{\"model\":\"unpriced\"}", 403),
        ("{\"model\":\"Model-A\"}", 403),
        ("{\"model\":\"model-a \"}", 403),
        ("{}", 403),
        ("{\"model\":null}", 403),
        ("{\"model\":1}", 400),
        // Two `model` keys: refused, so the model checked is the one the upstream reads.
        ("{\"model\":\"model-a\",\"model\":\"other\"}", 400),
        ("{\"model\":\"other\",\"mod\\u0065l\":\"model-a\"}", 400),
        ("[\"model-a\"]", 400),
        ("not json", 400),
    ];
    for (body, want) in cases {
        let resp = raw(&r.sock, &request("POST /v1/messages HTTP/1.1", &[], body)).await;
        assert_eq!(
            status(&resp),
            want,
            "{body}: {}",
            String::from_utf8_lossy(&resp)
        );
    }
    assert_eq!(r.up.count(), 0);
    let ok = raw(
        &r.sock,
        &request("POST /v1/messages HTTP/1.1", &[], "{\"model\":\"model-a\"}"),
    )
    .await;
    assert_eq!(status(&ok), 200);
    // A Gemini model is the path's.
    let g = rig(Opts::of(
        Wire::GeminiGenerate,
        "generativelanguage.googleapis.com",
        "",
        "google",
        "AIza",
        ok_script(),
    ))
    .await;
    for m in ["other", "unpriced"] {
        let line = format!("POST /v1beta/models/{m}:generateContent HTTP/1.1");
        assert_eq!(status(&raw(&g.sock, &request(&line, &[], "{}")).await), 403);
    }
    assert_eq!(g.up.count(), 0);
    let yes = raw(
        &g.sock,
        &request(
            "POST /v1beta/models/model-a:generateContent HTTP/1.1",
            &[],
            "{}",
        ),
    )
    .await;
    assert_eq!(status(&yes), 200);
}

#[tokio::test]
async fn only_allow_listed_response_headers_reach_the_agent_and_none_carries_the_key() {
    let key = key_of("sk-ant-");
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: a=b\r\nLocation: http://x.test/\r\n\
         anthropic-organization-id: org-1\r\nX-Echo: hello\r\nretry-after: 3\r\nrequest-id: req_1\r\n\
         anthropic-ratelimit-requests-remaining: 9\r\nx-ratelimit-limit: 10\r\nx-request-id: {key}\r\n\
         Content-Length: 2\r\n\r\n{{}}"
    );
    let r = rig(Opts::anthropic(vec![Step::Send(reply.into_bytes())])).await;
    let resp = raw(
        &r.sock,
        &request("POST /v1/messages HTTP/1.1", &[], &model_body()),
    )
    .await;
    assert_eq!(status(&resp), 200);
    let head = String::from_utf8_lossy(&resp)
        .split("\r\n\r\n")
        .next()
        .unwrap()
        .to_ascii_lowercase();
    for kept in [
        "content-type: application/json",
        "retry-after: 3",
        "request-id: req_1",
        "anthropic-ratelimit-requests-remaining: 9",
        "x-ratelimit-limit: 10",
        "content-length: 2",
        "connection: close",
    ] {
        assert!(head.contains(kept), "{kept}: {head}");
    }
    for gone in [
        "set-cookie",
        "location",
        "organization",
        "x-echo",
        "x-request-id",
        "sk-ant",
    ] {
        assert!(!head.contains(gone), "{gone}: {head}");
    }
}

#[tokio::test]
async fn a_redirect_is_not_followed_and_its_location_is_dropped() {
    let r = rig(Opts::anthropic(vec![Step::Send(
        b"HTTP/1.1 302 Found\r\nLocation: https://api.anthropic.com/elsewhere\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
    )]))
    .await;
    let resp = raw(
        &r.sock,
        &request("POST /v1/messages HTTP/1.1", &[], &model_body()),
    )
    .await;
    assert_eq!(status(&resp), 302);
    assert!(
        !String::from_utf8_lossy(&resp)
            .to_ascii_lowercase()
            .contains("location")
    );
    assert_eq!(r.up.count(), 1);
}
