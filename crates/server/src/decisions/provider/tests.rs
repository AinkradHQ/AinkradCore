//! The service against a fake provider and a real (temp) database: cache, fallback, cap, timeout,
//! overload, ledger and audit rows, and the shape checks.

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_proto::v2::Wire;

use super::*;

const NOW: &str = "2026-11-20T10:00:00.000Z";
const BY: AuditActor = AuditActor::User(UserId(1));

struct Fixed;
impl Clock for Fixed {
    fn now(&self) -> String {
        NOW.to_owned()
    }
}

struct Db(SqlitePool, PathBuf);
impl Drop for Db {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.1);
    }
}

async fn db() -> Db {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-decisions-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Db(store::connect(&dir.join("core.db")).await.unwrap(), dir)
}

/// Answers `heavy` 0.9 for every question, or what it was told to fail with; counts its calls.
struct Fake {
    fail: Mutex<Option<ProviderError>>,
    calls: AtomicUsize,
    scores: Vec<f32>,
}

impl Fake {
    fn answering(scores: &[f32]) -> Arc<Self> {
        Arc::new(Self {
            fail: Mutex::new(None),
            calls: AtomicUsize::new(0),
            scores: scores.to_vec(),
        })
    }
    fn failing(e: ProviderError) -> Arc<Self> {
        let f = Self::answering(&[0.1, 0.9]);
        *f.fail.lock().unwrap() = Some(e);
        f
    }
}

impl DecisionProvider for Fake {
    fn id(&self) -> &'static str {
        "fake-decision"
    }
    fn score<'a>(
        &'a self,
        call: &'a ProviderCall,
    ) -> BoxFuture<'a, Result<Vec<Vec<f32>>, ProviderError>> {
        async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            match self.fail.lock().unwrap().clone() {
                Some(e) => Err(e),
                None => Ok(call.questions.iter().map(|_| self.scores.clone()).collect()),
            }
        }
        .boxed()
    }
}

/// Reports 1000 input tokens and an account, so a call is charged.
impl MeteredProvider for Fake {
    fn score_metered<'a>(
        &'a self,
        call: &'a ProviderCall,
    ) -> BoxFuture<'a, Result<Metered, ProviderError>> {
        async move {
            let scores = self.score(call).await?;
            Ok(Metered {
                scores,
                usage: Usage {
                    input_tokens: 1000,
                    account: Some(7),
                    model: "fake-decision".to_owned(),
                },
            })
        }
        .boxed()
    }
}

struct Rule;
impl Fallback for Rule {
    fn score(&self, q: &Question) -> Option<Vec<(String, f32)>> {
        (q.key == "known").then(|| vec![("light".to_owned(), 1.0), ("heavy".to_owned(), 0.0)])
    }
}

fn service(db: &Db, p: &Arc<Fake>) -> Service {
    Service::new(
        db.0.clone(),
        Arc::new(Fixed),
        vec![p.clone() as Arc<dyn MeteredProvider>],
        Redactor::new(Path::new("/var/lib/ainkrad-ws"), None),
    )
}

fn req(keys: &[&str], text: &str) -> DecideRequest {
    DecideRequest {
        consumer: Consumer::HeavyJob,
        user: UserId(1),
        options: vec!["light".to_owned(), "heavy".to_owned()],
        questions: keys
            .iter()
            .map(|k| Question {
                key: (*k).to_owned(),
                text: text.to_owned(),
                facts: BTreeMap::new(),
            })
            .collect(),
        context: BTreeMap::new(),
    }
}

async fn audits(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'decision.asked' ORDER BY seq",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_miss_asks_the_model_once_and_the_next_ask_is_the_cache() {
    let db = db().await;
    let p = Fake::answering(&[0.1, 0.9]);
    let s = service(&db, &p);
    let first = s
        .decide(req(&["a", "b"], "cargo build"), &Rule)
        .await
        .unwrap();
    assert!(matches!(
        first[0].source,
        Source::Model {
            provider: "fake-decision",
            ..
        }
    ));
    assert_eq!(first[0].scores[1], ("heavy".to_owned(), 0.9));
    let again = s
        .decide(req(&["a", "b"], "cargo build"), &Rule)
        .await
        .unwrap();
    assert_eq!(again[0].source, Source::Cache);
    assert_eq!(again[1].scores, first[1].scores);
    assert_eq!(
        p.calls.load(Ordering::Relaxed),
        1,
        "one batched call, then the cache"
    );
    // A different question is a miss again, and only it is asked.
    let other = s
        .decide(req(&["a", "c"], "cargo test"), &Rule)
        .await
        .unwrap();
    assert!(matches!(other[1].source, Source::Model { .. }));
    assert_eq!(p.calls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn a_call_leaves_one_ledger_row_and_one_audit_row_without_text() {
    let db = db().await;
    let p = Fake::answering(&[0.1, 0.9]);
    let s = service(&db, &p);
    s.decide(
        req(
            &["a", "b"],
            "cargo build /var/lib/ainkrad-ws/secret-project",
        ),
        &Rule,
    )
    .await
    .unwrap();
    let rows: Vec<(String, i64, Option<i64>)> =
        sqlx::query_as("SELECT session, input_tokens, cost_usd_micros FROM core_cost_events")
            .fetch_all(&db.0)
            .await
            .unwrap();
    // 1000 tokens at the default $0.10 per million: 100 micro-dollars.
    assert_eq!(
        rows,
        vec![("decisions:heavy_job".to_owned(), 1000, Some(100))]
    );
    let a = audits(&db.0).await;
    assert_eq!(a.len(), 1);
    let v: serde_json::Value = serde_json::from_str(&a[0]).unwrap();
    assert_eq!(v["consumer"], "heavy_job");
    assert_eq!(v["questions"], 2);
    assert_eq!(v["cached"], 0);
    assert_eq!(v["usd_micros"], 100);
    assert_eq!(v["outcome"], "ok");
    assert!(
        !a[0].contains("cargo") && !a[0].contains("secret-project"),
        "{}",
        a[0]
    );
    // A cache hit is not a provider call: no new audit row.
    s.decide(
        req(
            &["a", "b"],
            "cargo build /var/lib/ainkrad-ws/secret-project",
        ),
        &Rule,
    )
    .await
    .unwrap();
    assert_eq!(audits(&db.0).await.len(), 1);
}

#[tokio::test]
async fn every_failure_is_the_fallback_then_equal_scores() {
    for (e, why) in [
        (ProviderError::Timeout, "timeout"),
        (ProviderError::Overloaded, "overloaded"),
        (ProviderError::Unavailable, "no_provider"),
        (ProviderError::Failed("x".to_owned()), "failed"),
    ] {
        let db = db().await;
        let p = Fake::failing(e);
        let got = service(&db, &p)
            .decide(req(&["known", "other"], "ls"), &Rule)
            .await
            .unwrap();
        assert_eq!(got[0].source, Source::Fallback(why));
        assert_eq!(got[0].scores[0], ("light".to_owned(), 1.0));
        assert_eq!(got[1].source, Source::None, "{why}");
        assert_eq!(
            got[1].scores,
            equal(&["light".to_owned(), "heavy".to_owned()])
        );
        assert_eq!(
            audits(&db.0).await.len(),
            1,
            "{why}: one audit row per provider call"
        );
    }
}

#[tokio::test]
async fn the_cap_stops_the_provider_until_the_next_day() {
    let db = db().await;
    let p = Fake::answering(&[0.1, 0.9]);
    let s = service(&db, &p);
    settings::set(&db.0, DAILY_CAP, Scope::Server, "100", BY, NOW)
        .await
        .unwrap();
    // The first call costs 100 and reaches the cap; the next distinct question is a fallback.
    s.decide(req(&["a"], "one"), &Rule).await.unwrap();
    let got = s.decide(req(&["known", "b"], "two"), &Rule).await.unwrap();
    assert_eq!(got[0].source, Source::Fallback("cap_reached"));
    assert_eq!(got[1].source, Source::None);
    assert_eq!(p.calls.load(Ordering::Relaxed), 1);
    assert_eq!(budget::spent_today(&db.0, NOW).await.unwrap(), 100);
    // Yesterday's spend does not count today.
    assert_eq!(
        budget::spent_today(&db.0, "2026-11-21T00:00:00.000Z")
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn a_disabled_consumer_and_no_provider_go_straight_to_the_fallback() {
    let db = db().await;
    let p = Fake::answering(&[0.1, 0.9]);
    settings::set(
        &db.0,
        SettingKey::DecisionsHeavyJobEnabled,
        Scope::Server,
        "0",
        BY,
        NOW,
    )
    .await
    .unwrap();
    let got = service(&db, &p)
        .decide(req(&["known"], "ls"), &Rule)
        .await
        .unwrap();
    assert_eq!(got[0].source, Source::Fallback("disabled"));
    assert_eq!(p.calls.load(Ordering::Relaxed), 0);

    // Enabled again, but with no provider at all.
    settings::set(
        &db.0,
        SettingKey::DecisionsHeavyJobEnabled,
        Scope::Server,
        "1",
        BY,
        NOW,
    )
    .await
    .unwrap();
    let none = Service::new(
        db.0.clone(),
        Arc::new(Fixed),
        vec![],
        Redactor::new(Path::new("/w"), None),
    );
    let got = none
        .decide(req(&["known", "x"], "ls"), &Rule)
        .await
        .unwrap();
    assert_eq!(got[0].source, Source::Fallback("no_provider"));
    assert_eq!(got[1].source, Source::None);
}

#[tokio::test]
async fn an_unsure_model_answer_defers_to_the_fallback_when_it_has_one() {
    let db = db().await;
    // The best score is 0.55, under the default 0.7.
    let p = Fake::answering(&[0.45, 0.55]);
    let got = service(&db, &p)
        .decide(req(&["known", "other"], "ls"), &Rule)
        .await
        .unwrap();
    assert_eq!(got[0].source, Source::Fallback("low_confidence"));
    assert!(
        matches!(got[1].source, Source::Model { .. }),
        "no rule: the model's answer stays"
    );
}

#[tokio::test]
async fn a_provider_that_answers_the_wrong_shape_is_a_failure() {
    let db = db().await;
    let p = Fake::answering(&[1.0]); // one score for two options
    let got = service(&db, &p)
        .decide(req(&["known"], "ls"), &Rule)
        .await
        .unwrap();
    assert_eq!(got[0].source, Source::Fallback("failed"));
}

#[tokio::test]
async fn the_shape_is_checked_before_anything_is_asked() {
    let db = db().await;
    let p = Fake::answering(&[0.1, 0.9]);
    let s = service(&db, &p);
    let many: Vec<String> = (0..1001).map(|i| format!("q{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    assert_eq!(
        s.decide(req(&many, "x"), &Rule).await.unwrap_err(),
        DecideError::TooMany
    );
    let mut bad = req(&["a"], "x");
    bad.options = vec!["only".to_owned()];
    assert_eq!(
        s.decide(bad, &Rule).await.unwrap_err(),
        DecideError::BadOptions
    );
    assert_eq!(p.calls.load(Ordering::Relaxed), 0);
}

#[test]
fn the_registry_holds_one_live_provider_and_two_reserved_ids() {
    let live: Vec<_> = REGISTRY.iter().filter(|(_, s)| *s == State::Live).collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].0, "gemini-decision-1");
    assert!(
        REGISTRY
            .iter()
            .any(|(id, s)| *id == "openai-decisions" && *s == State::Reserved)
    );
    assert!(
        REGISTRY
            .iter()
            .any(|(id, s)| *id == "microsoft-decision-1" && *s == State::Reserved)
    );
}

#[test]
fn an_account_url_becomes_the_upstream_or_nothing() {
    let up = upstream_of("https://generativelanguage.googleapis.com").unwrap();
    assert_eq!(
        (up.host.as_str(), up.base_path.as_str()),
        ("generativelanguage.googleapis.com", "")
    );
    assert_eq!(up.wire, Wire::GeminiGenerate);
    assert_eq!(
        upstream_of("https://h.example.com:443/proxy/")
            .unwrap()
            .base_path,
        "/proxy"
    );
    assert!(upstream_of("http://h.example.com").is_none());
}

#[tokio::test]
async fn a_failed_call_is_charged_its_estimate_so_the_cap_still_trips() {
    // M11: timeouts and bad answers used to be free, so the cap never tripped while they lasted.
    let db = db().await;
    let p = Fake::failing(ProviderError::Timeout);
    let s = service(&db, &p);
    settings::set(&db.0, DAILY_CAP, Scope::Server, "50", BY, NOW)
        .await
        .unwrap();
    for i in 0..5 {
        s.decide(req(&["x"], &format!("q{i}")), &Rule)
            .await
            .unwrap();
    }
    // Each estimate is (2 + 10) / 4 + 200 = 203 tokens, 21 micro-dollars: two fit under 50.
    assert_eq!(p.calls.load(Ordering::Relaxed), 2);
    assert_eq!(budget::spent_today(&db.0, NOW).await.unwrap(), 42);
}

/// Answers after a pause, with no usage of its own: what parallel calls look like.
struct Slow(AtomicUsize);
impl DecisionProvider for Slow {
    fn id(&self) -> &'static str {
        "fake-decision"
    }
    fn score<'a>(
        &'a self,
        call: &'a ProviderCall,
    ) -> BoxFuture<'a, Result<Vec<Vec<f32>>, ProviderError>> {
        async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(call.questions.iter().map(|_| vec![0.1, 0.9]).collect())
        }
        .boxed()
    }
}
impl MeteredProvider for Slow {}

#[tokio::test]
async fn parallel_calls_cannot_all_pass_the_cap_check() {
    // M12: the check and the charge were apart, so N parallel calls all passed it.
    let db = db().await;
    let p = Arc::new(Slow(AtomicUsize::new(0)));
    let s = Service::new(
        db.0.clone(),
        Arc::new(Fixed),
        vec![p.clone() as Arc<dyn MeteredProvider>],
        Redactor::new(Path::new("/w"), None),
    );
    settings::set(&db.0, DAILY_CAP, Scope::Server, "50", BY, NOW)
        .await
        .unwrap();
    let asks: Vec<_> = (0..8)
        .map(|i| s.decide(req(&["x"], &format!("p{i}")), &Rule))
        .collect();
    futures_util::future::join_all(asks).await;
    let calls = p.0.load(Ordering::Relaxed);
    assert!(calls <= 2, "{calls} calls passed a cap that holds two");
    assert!(calls <= budget::MAX_IN_FLIGHT);
    // A 2xx with no reported usage is charged its estimate, never 0.
    assert_eq!(
        budget::spent_today(&db.0, NOW).await.unwrap(),
        21 * i64::try_from(calls).unwrap()
    );
}
