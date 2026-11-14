//! No path shows a credential: every result, the whole runner-bound message stream, every audit
//! row, every log line and every Debug text is scanned for the secret text. The tokens are
//! shapeless, so the redactor is never what hides a leak.

use std::io::Write;
use std::sync::{Arc, Mutex};

use ainkrad_proto::v2::{ConnTool, ToolsPoll};

use super::*;

/// A log writer the test can read back.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Write for Logs {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn get(n: u64) -> Value {
    json!({"repo": "acme/app", "number": n})
}

/// Every tool of the session, then a spread of calls: ok, echoing the token, refused in each way,
/// upstream errors that carry the token in their body, and Jira. Returns what the runner would be
/// sent (the poll frames), and every ToolResult's Debug.
async fn run_all(f: &Fx, s: &str) -> (String, String) {
    let mut results: Vec<ToolResult> = Vec::new();
    // An upstream that echoes the credential in a field, in a key, and in an error body.
    f.gh.push(
        200,
        &[],
        &format!(r#"{{"title":"{GH_TOKEN}","{GH_TOKEN}":1,"n":[{{"t":"x {GH_TOKEN} y"}}]}}"#),
    );
    results.push(f.ask(s, "github.get_issue", get(1)).await);
    f.gh.push(
        404,
        &[],
        &format!(r#"{{"message":"{GH_TOKEN} not found"}}"#),
    );
    results.push(f.ask(s, "github.get_issue", get(2)).await);
    f.gh.push(500, &[], &format!("boom {GH_TOKEN}"));
    results.push(f.ask(s, "github.get_issue", get(3)).await);
    f.gh.push(401, &[], GH_TOKEN);
    results.push(f.ask(s, "github.get_issue", get(4)).await);
    results.push(
        f.ask(s, "github.get_issue", json!({"repo": GH_TOKEN}))
            .await,
    );
    results.push(f.ask(s, "github.nope", get(5)).await);
    results.push(
        f.ask(s, "github.create_issue", json!({"repo": "acme/app"}))
            .await,
    );
    results.push(f.ask("as_nosuchsession", "github.get_issue", get(6)).await);
    results.push(f.call(OTHER_RUNNER, s, "github.get_issue", get(7)).await);
    // Jira: the answer echoes the API token and the account's email.
    let one = format!("GET {}", jt::site_path("/issue/ABC-1"));
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("{}:{}", jt::EMAIL, jt::API_TOKEN),
    );
    f.j.fake.reply(
        &one,
        200,
        json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"},
            "summary": format!("tok {} hdr Basic {b64} raw {b64} bearer Bearer {}", jt::API_TOKEN, jt::API_TOKEN)}}),
    );
    results.push(f.ask(s, "jira.get_issue", json!({"key": "ABC-1"})).await);
    let tools: Vec<ConnTool> = f.b.tools(&f.env(), s).await.unwrap();
    // The poll frames of the session's channel: the list, and each result in a poll of its own.
    let mut frames = vec![
        serde_json::to_string(&ToolsPoll {
            session: s.to_owned(),
            after: 0,
            wait_ms: None,
            results: Vec::new(),
            tools: Some(tools),
        })
        .unwrap(),
    ];
    for r in &results {
        let poll = ToolsPoll {
            session: s.to_owned(),
            after: 1,
            wait_ms: None,
            results: vec![r.clone()],
            tools: None,
        };
        frames.push(serde_json::to_string(&poll).unwrap());
    }
    (frames.join("\n"), format!("{results:?}"))
}

#[tokio::test]
async fn no_credential_is_in_any_message_audit_row_log_or_debug_text() {
    let logs = Logs::default();
    let writer = logs.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    // With one live dispatcher, tracing-core caches each callsite's interest from whichever
    // thread hits it first; a parallel test with no subscriber would cache `never` and drop our
    // lines. A second registered dispatcher makes the cache ask every live one instead.
    let _second = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let _guard = tracing::subscriber::set_default(sub);
    let f = fx().await;
    let g = f.github("main", GH_TOKEN).await;
    let j = f.jira("acme").await;
    f.member(g.id, &["read_repo", "issues_write"], &[]).await;
    f.grant(g.id, ("agent", "bot"), &["read_repo", "issues_write"], &[])
        .await;
    f.member(j.id, &["read_issues"], &[]).await;
    f.grant(j.id, ("agent", "bot"), &["read_issues"], &[]).await;
    let s = f
        .session(&["read_repo", "issues_write", "read_issues"])
        .await;
    let (stream, debug) = run_all(&f, &s).await;
    let b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        format!("{}:{}", jt::EMAIL, jt::API_TOKEN),
    );
    let secrets = [
        GH_TOKEN,
        jt::API_TOKEN,
        "7f3a9d41e0b2",
        "5d2e8b0c7a41",
        b64.as_str(),
    ];
    let audit = f.audit_text().await;
    let state: String = sqlx::query_scalar("SELECT group_concat(details, ' ') FROM audit_events")
        .fetch_one(&f.j.pool)
        .await
        .unwrap();
    let log = String::from_utf8_lossy(&logs.0.lock().unwrap()).into_owned();
    let conns = format!(
        "{:?}{:?}",
        crate::store::connections::list(&f.j.pool, 1, None)
            .await
            .unwrap(),
        crate::store::connections::access::load(&f.j.pool, &s)
            .await
            .unwrap()
    );
    for (what, text) in [
        ("the runner-bound stream", &stream),
        ("Debug of the results", &debug),
        ("the audit rows", &audit),
        ("the audit table", &state),
        ("the log", &log),
        ("the rows' Debug", &conns),
    ] {
        for secret in secrets {
            assert!(!text.contains(secret), "{what} carries {secret}: {text}");
        }
    }
    assert!(
        stream.contains("[redacted]"),
        "the echoed token was cut, not dropped: {stream}"
    );
    assert!(f.uses().await.len() >= 9, "every call is a row");
}

#[tokio::test]
async fn the_token_is_not_in_a_url_header_or_error_of_a_refusal() {
    let f = fx().await;
    let c = f.github("main", GH_TOKEN).await;
    f.member(c.id, &["read_repo"], &[("repos", &["acme/*"])])
        .await;
    f.grant(c.id, ("agent", "bot"), &["read_repo"], &[]).await;
    let s = f.session(&["read_repo"]).await;
    let r = f
        .ask(
            &s,
            "github.get_issue",
            json!({"repo": "evil/x", "number": 1}),
        )
        .await;
    let text = serde_json::to_string(&r).unwrap();
    assert!(
        !text.contains(GH_TOKEN) && !text.contains("api.github.com") && !text.contains("http"),
        "{text}"
    );
}
