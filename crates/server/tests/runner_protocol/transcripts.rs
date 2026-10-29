//! Transcripts end to end (E3.9): a planted secret of every kind never reaches the database
//! file, its WAL, or any log line; chunks are stored in order, once, and only from the
//! runner holding the run.

use ainkrad_core::exec::{NewRunner, RunId, RunState};
use ainkrad_core_server::store::exec::{create_runner, get_run, list_run_events, list_runs};
use ainkrad_harness::claude;
use ainkrad_proto::redact::PLANTED;
use ainkrad_proto::runner::{Outcome, PROTOCOL_VERSION, RunToken, RunnerMessage, ServerMessage};
use ainkrad_runner::{Executor, Job, Report};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::{Message, http::header};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use super::support::*;
use crate::harness::{agent, assign, company, count, issue};

/// A runner whose name is not its key (the suite's `runner` names it by its key).
async fn keyed(pool: &sqlx::SqlitePool, name: &str, key: &str) {
    let new = NewRunner {
        name: name.to_owned(),
        tags: vec![],
    };
    create_runner(pool, &new, key).await.unwrap();
}

const RUNNER_KEY: &str = "runner-key-planted-0042";
const ENV_SECRET: &str = "env-secret-value-planted-0042";

/// Leaks every kind of secret into its chunks and its failure reason.
struct Leaky;

/// The secrets a run leaks: every shape, plus the ones only known by value.
fn leaks(token: &RunToken) -> Vec<String> {
    let mut all: Vec<String> = PLANTED.iter().map(|(_, s)| s.to_string()).collect();
    all.extend([token.expose(), RUNNER_KEY, ENV_SECRET].map(str::to_owned));
    all
}

impl Executor for Leaky {
    async fn secrets(&self) -> Vec<(String, String)> {
        vec![("env:ANTHROPIC_API_KEY".to_owned(), ENV_SECRET.to_owned())]
    }

    async fn start(&self, job: &Job) -> Result<Option<String>, String> {
        Ok(Some(format!("leaky-{}", job.run)))
    }

    async fn run(&self, _: &Job, token: RunToken, reports: mpsc::Sender<Report>) -> Outcome {
        for leak in leaks(&token) {
            let chunk = serde_json::json!({"type": "tool_use", "input": {"command": leak}});
            let _ = reports.send(Report::Event(chunk)).await;
        }
        Outcome::Failed {
            reason: format!("git said: {}", leaks(&token).join(" ")),
            fingerprint: None,
        }
    }
}

/// The bytes of the database file and its WAL.
fn on_disk(stack: &Stack) -> Vec<u8> {
    let mut bytes = std::fs::read(&stack.db.path).unwrap();
    let wal = stack.db.path.with_extension("db-wal");
    bytes.extend(std::fs::read(wal).unwrap_or_default());
    bytes
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[tokio::test]
async fn a_planted_secret_never_reaches_the_db_the_wal_or_a_log() {
    let logs = logs();
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    let dev = agent(pool, c, "Dev", &[], None).await;
    assign(pool, issue(pool, p).await, dev).await;
    keyed(pool, "box", RUNNER_KEY).await;

    stack.runner(RUNNER_KEY, &["linux"], Leaky);
    let failed = "SELECT count(*) FROM runs WHERE state = 'failed'";
    until(pool, "the leaky run to fail", failed).await;

    let run = list_runs(pool, dev).await.unwrap().remove(0);
    let events = list_run_events(pool, run.id).await.unwrap();
    let seqs: Vec<i64> = events.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, (1..=PLANTED.len() as i64 + 3).collect::<Vec<_>>());
    for (event, (kind, _)) in events.iter().zip(PLANTED) {
        let redacted = format!("[redacted:{kind}]");
        assert_eq!(event.payload["input"]["command"], redacted.as_str());
        assert_eq!(event.kind, "tool_use");
    }
    let by_value: Vec<&str> = events[PLANTED.len()..]
        .iter()
        .map(|e| e.payload["input"]["command"].as_str().unwrap())
        .collect();
    assert_eq!(
        by_value,
        [
            "[redacted:run_token]",
            "[redacted:runner_key]",
            "[redacted:env:ANTHROPIC_API_KEY]"
        ]
    );
    let reason = get_run(pool, run.id)
        .await
        .unwrap()
        .unwrap()
        .terminal_reason;
    assert!(
        reason
            .unwrap()
            .starts_with("git said: [redacted:anthropic_key]")
    );

    // The token is gone with its run; the secrets it and the others were are on no disk
    // page and in no log line. The run token is checked by its shape, as it was never seen.
    let disk = on_disk(&stack);
    let logged = logs.text();
    assert!(contains(&logged, "[redacted:"), "the chunks were logged");
    for secret in PLANTED
        .iter()
        .map(|(_, s)| *s)
        .chain([RUNNER_KEY, ENV_SECRET])
    {
        assert!(!contains(&disk, secret), "{secret} reached the database");
        assert!(!contains(&logged, secret), "{secret} reached the logs");
    }
    for haystack in [&disk, &logged] {
        let text = String::from_utf8_lossy(haystack);
        assert!(!text.contains("cit_run_"), "a run token was written");
    }
}

type Raw = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// A raw runner: hello said and welcomed.
async fn raw(stack: &Stack, key: &str) -> Raw {
    let mut req = stack.url().into_client_request().unwrap();
    let auth = format!("Bearer {key}").parse().unwrap();
    req.headers_mut().insert(header::AUTHORIZATION, auth);
    let (mut ws, _) = connect_async(req).await.unwrap();
    let hello = RunnerMessage::Hello {
        protocol: PROTOCOL_VERSION.to_owned(),
        runner_version: "raw".to_owned(),
        tags: vec![],
        harnesses: [("claude".to_owned(), claude::VERSION.to_owned())].into(),
        runs: vec![],
        disk: None,
        info: None,
        os: None,
        arch: None,
    };
    say(&mut ws, &hello).await;
    assert!(matches!(hear(&mut ws).await, ServerMessage::Welcome { .. }));
    ws
}

async fn say(ws: &mut Raw, msg: &RunnerMessage) {
    let text = serde_json::to_string(msg).unwrap();
    ws.send(Message::Text(text.into())).await.unwrap();
}

async fn hear(ws: &mut Raw) -> ServerMessage {
    loop {
        if let Message::Text(text) = ws.next().await.unwrap().unwrap() {
            return serde_json::from_str(&text).unwrap();
        }
    }
}

/// A runner that does not redact: the server still does, before it logs or writes. A
/// runner that does not hold the run has its chunks refused.
#[tokio::test]
async fn the_server_redacts_again_and_refuses_chunks_from_a_non_holder() {
    let stack = Stack::new().await;
    let pool = stack.pool();
    let (c, p) = company(pool, "A").await;
    assign(
        pool,
        issue(pool, p).await,
        agent(pool, c, "Dev", &[], None).await,
    )
    .await;
    keyed(pool, "box", RUNNER_KEY).await;
    keyed(pool, "other", "other-runner-key").await;

    let mut ws = raw(&stack, RUNNER_KEY).await;
    say(&mut ws, &RunnerMessage::Ready { workspaces: vec![] }).await;
    let ServerMessage::Assign { run, .. } = hear(&mut ws).await else {
        panic!("no assign");
    };
    let started = RunnerMessage::RunStarted { run, session: None };
    say(&mut ws, &started).await;
    let ServerMessage::Token { token, .. } = hear(&mut ws).await else {
        panic!("no token");
    };

    let mut other = raw(&stack, "other-runner-key").await;
    let stolen = serde_json::json!({"type": "assistant_text", "text": "not mine"});
    let event = |seq, payload| RunnerMessage::RunEvent { run, seq, payload };
    say(&mut other, &event(1, stolen)).await;
    assert!(matches!(
        hear(&mut other).await,
        ServerMessage::Cancel { .. }
    ));

    let leak = format!("{} {RUNNER_KEY} {}", token.expose(), PLANTED[0].1);
    let chunk =
        |n: u64| serde_json::json!({"type": "assistant_text", "text": format!("{n} {leak}")});
    // Out of order and resent: stored once each, read back by seq.
    for seq in [2, 1, 2, 3] {
        say(&mut ws, &event(seq, chunk(seq))).await;
    }
    let ended = RunnerMessage::RunEnded {
        run,
        outcome: Outcome::Cancelled {
            reason: format!("stopped: {leak}"),
        },
    };
    say(&mut ws, &ended).await;
    assert_eq!(hear(&mut ws).await, ServerMessage::Ack { run });

    let events = list_run_events(pool, RunId(run)).await.unwrap();
    let texts: Vec<&str> = events
        .iter()
        .map(|e| e.payload["text"].as_str().unwrap())
        .collect();
    let redacted = "[redacted:run_token] [redacted:runner_key] [redacted:anthropic_key]";
    assert_eq!(
        texts,
        [1, 2, 3].map(|n| format!("{n} {redacted}")),
        "in seq order, once each, redacted"
    );
    let stored = get_run(pool, RunId(run)).await.unwrap().unwrap();
    assert_eq!(stored.state, RunState::Cancelled);
    assert_eq!(
        stored.terminal_reason.as_deref(),
        Some(&*format!("stopped: {redacted}"))
    );
    let disk = on_disk(&stack);
    for secret in [token.expose(), RUNNER_KEY, PLANTED[0].1] {
        assert!(!contains(&disk, secret), "{secret} reached the database");
    }
    assert_eq!(count(pool, "SELECT count(*) FROM run_events").await, 3);
}
