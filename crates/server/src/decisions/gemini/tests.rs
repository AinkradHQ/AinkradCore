//! Tests against payloads shaped as the reference documents them (field names and limits from
//! aistudio.google.com/docs/decisions-api). They were written from the docs, not captured from a
//! live call: the lane never calls the API with a real key.

use std::collections::BTreeMap;
use std::sync::Mutex;

use ainkrad_core::ids::UserId;
use ainkrad_proto::v2::{CallUsage, GatewayCalled, UpstreamStatus};
use serde_json::{Value, json};

use super::*;
use crate::decisions::Consumer;
use crate::decisions::provider::Called;

/// A response for two questions over the options `heavy` and `light`: `probabilities` by key.
const RECORDED_MAP: &str = r#"{
  "answers": {
    "q0": {"type": "choice", "choice": "heavy", "probabilities": {"heavy": 0.91, "light": 0.09}, "confidence": 0.91},
    "q1": {"type": "choice", "choice": "light", "probabilities": {"heavy": 0.2, "light": 0.8}, "confidence": 0.8}
  },
  "usage": {"total_input_tokens": 812, "input_tokens_by_modality": [{"modality": "text", "tokens": 812}], "total_output_tokens": 0, "total_tokens": 812}
}"#;

/// The same answers with `probabilities` as arrays in the sent (sorted) order: heavy, light.
const RECORDED_ARRAY: &str = r#"{
  "answers": {
    "q0": {"type": "choice", "choice": "heavy", "probabilities": [0.91, 0.09], "confidence": 0.91},
    "q1": {"type": "choice", "choice": "light", "probabilities": [0.2, 0.8], "confidence": 0.8}
  },
  "usage": {"total_input_tokens": 812, "total_output_tokens": 0, "total_tokens": 812}
}"#;

fn call() -> ProviderCall {
    ProviderCall {
        consumer: Consumer::HeavyJob,
        user: UserId(1),
        options: vec!["light".to_owned(), "heavy".to_owned()],
        questions: vec!["cargo build --release".to_owned(), "ls".to_owned()],
        facts: vec![
            BTreeMap::from([("cwd".to_owned(), "$WS/p/7".to_owned())]),
            BTreeMap::new(),
        ],
        context: BTreeMap::from([
            ("task".to_owned(), "Is this command heavy?".to_owned()),
            (
                "option:heavy".to_owned(),
                "Takes minutes of CPU.".to_owned(),
            ),
            ("project".to_owned(), "rust".to_owned()),
        ]),
        timeout_ms: 8000,
    }
}

#[test]
fn the_request_is_the_documented_shape() {
    let v: Value = serde_json::from_str(&request_body(&call()).unwrap()).unwrap();
    assert_eq!(v["model"], "gemini-decision-1");
    assert_eq!(v["input"], "Is this command heavy?\nproject: rust");
    let q0 = &v["questions"]["q0"];
    assert_eq!(q0["type"], "choice");
    assert_eq!(q0["instructions"], "cargo build --release\ncwd: $WS/p/7");
    assert_eq!(
        q0["criteria"],
        json!({"heavy": "Takes minutes of CPU.", "light": ""})
    );
    assert_eq!(v["questions"].as_object().unwrap().len(), 2);
    assert_eq!(v["questions"]["q1"]["instructions"], "ls");
}

#[test]
fn an_option_the_api_would_refuse_is_refused_before_sending() {
    let mut c = call();
    c.options[0] = "x".repeat(129);
    assert!(matches!(request_body(&c), Err(ProviderError::Failed(_))));
    c.options[0] = String::new();
    assert!(matches!(request_body(&c), Err(ProviderError::Failed(_))));
}

#[test]
fn a_recorded_answer_is_read_in_option_order_with_the_tokens() {
    let (scores, tokens) = parse_response(RECORDED_MAP, &call()).unwrap();
    // Options were [light, heavy].
    let want = [[0.09, 0.91], [0.8, 0.2]];
    for (got, want) in scores.iter().zip(want) {
        assert!(
            got.iter().zip(want).all(|(g, w)| (g - w).abs() < 1e-6),
            "{got:?}"
        );
    }
    assert_eq!(tokens, 812);
    let (array, _) = parse_response(RECORDED_ARRAY, &call()).unwrap();
    assert_eq!(array, scores);
}

#[test]
fn an_answer_with_only_the_winner_spreads_what_is_left() {
    let body = r#"{"answers":{"q0":{"type":"choice","choice":"heavy","confidence":0.8},
                               "q1":{"type":"choice","choice":"light","confidence":1.0}}}"#;
    let (scores, tokens) = parse_response(body, &call()).unwrap();
    assert!((scores[0][1] - 0.8).abs() < 1e-6 && (scores[0][0] - 0.2).abs() < 1e-6);
    assert_eq!(scores[1], vec![1.0, 0.0]);
    assert_eq!(tokens, 0);
}

#[test]
fn a_malformed_answer_is_a_failure_never_a_panic() {
    for body in [
        "not json",
        "{}",
        r#"{"answers":{}}"#,
        r#"{"answers":{"q0":{"probabilities":{"heavy":0.5}}}}"#,
        r#"{"answers":{"q0":{"probabilities":{"heavy":"x","light":1}},"q1":{}}}"#,
        r#"{"answers":{"q0":{"probabilities":{"heavy":9,"light":-1}},"q1":{}}}"#,
    ] {
        assert!(
            matches!(parse_response(body, &call()), Err(ProviderError::Failed(_))),
            "{body}"
        );
    }
}

/// A transport that answers from a script and records what it was sent.
struct Script {
    answers: Mutex<Vec<Result<GatewayCalled, ProviderError>>>,
    sent: Mutex<Vec<(String, String)>>,
}

impl Script {
    fn new(answers: Vec<Result<GatewayCalled, ProviderError>>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers),
            sent: Mutex::default(),
        })
    }
}

impl Transport for Script {
    fn call<'a>(
        &'a self,
        _user: UserId,
        path: &'a str,
        body: String,
        _timeout_ms: u64,
    ) -> BoxFuture<'a, Result<Called, ProviderError>> {
        self.sent.lock().unwrap().push((path.to_owned(), body));
        let next = self.answers.lock().unwrap().remove(0);
        async move { next.map(|answer| Called { answer, account: 7 }) }.boxed()
    }
}

fn ok(body: &str) -> GatewayCalled {
    GatewayCalled {
        result: UpstreamStatus::Ok,
        http_status: 200,
        body: body.to_owned(),
        usage: CallUsage::default(),
        ..GatewayCalled::default()
    }
}

fn status(result: UpstreamStatus, http: u16) -> GatewayCalled {
    GatewayCalled {
        result,
        http_status: http,
        // No pause before the retry.
        retry_after: Some(0),
        ..GatewayCalled::default()
    }
}

#[tokio::test]
async fn a_call_posts_to_the_decisions_path_and_reports_the_account_and_tokens() {
    let t = Script::new(vec![Ok(ok(RECORDED_MAP))]);
    let m = Gemini::new(t.clone()).score_metered(&call()).await.unwrap();
    assert_eq!(m.scores.len(), 2);
    assert_eq!(
        (
            m.usage.input_tokens,
            m.usage.account,
            m.usage.model.as_str()
        ),
        (812, Some(7), "gemini-decision-1")
    );
    assert_eq!(t.sent.lock().unwrap()[0].0, "/v1beta/decisions");
}

#[tokio::test]
async fn overload_is_retried_once_and_only_overload() {
    let t = Script::new(vec![
        Ok(status(UpstreamStatus::RateLimited, 429)),
        Ok(ok(RECORDED_MAP)),
    ]);
    assert!(Gemini::new(t.clone()).score_metered(&call()).await.is_ok());
    assert_eq!(t.sent.lock().unwrap().len(), 2);

    let t = Script::new(vec![
        Ok(status(UpstreamStatus::ServerError, 503)),
        Ok(status(UpstreamStatus::ServerError, 503)),
    ]);
    let e = Gemini::new(t.clone())
        .score_metered(&call())
        .await
        .unwrap_err();
    assert_eq!(e, ProviderError::Overloaded);
    assert_eq!(t.sent.lock().unwrap().len(), 2, "one retry, no more");

    // A refusal (HTTP 400: a limit or a safety block) is not retried.
    let t = Script::new(vec![Ok(status(UpstreamStatus::Unknown, 400))]);
    let e = Gemini::new(t.clone())
        .score_metered(&call())
        .await
        .unwrap_err();
    assert!(matches!(e, ProviderError::Failed(_)));
    assert_eq!(t.sent.lock().unwrap().len(), 1);

    let t = Script::new(vec![Err(ProviderError::Unavailable)]);
    let e = Gemini::new(t).score_metered(&call()).await.unwrap_err();
    assert_eq!(e, ProviderError::Unavailable);
}
