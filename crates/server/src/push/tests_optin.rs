//! Per-kind opt-in, bounded retries and the send timeout (E2-12.3, E2-12.4): everything runs
//! against fakes and a gateway that never answers; nothing leaves the machine.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::apns::{ApnsNotifier, SecretSource};
use super::stub::Fake;
use super::tests_apns::{Fx, fx};
use super::*;
use crate::store::gov::{get_kinds, push_targets, set_kinds};

fn quick() -> Retry {
    Retry {
        attempts: 3,
        backoff: Duration::from_millis(1),
        budget: Duration::from_secs(5),
    }
}

/// Answers each send from a script, counting how often it was asked.
struct Scripted {
    calls: AtomicUsize,
    script: Vec<Result<(), PushError>>,
    hang: bool,
}

impl Scripted {
    fn new(script: Vec<Result<(), PushError>>) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            script,
            hang: false,
        })
    }
}

impl PushProvider for Scripted {
    fn name(&self) -> &'static str {
        "apns"
    }

    fn send<'a>(&'a self, _: &'a PushTarget, _: &'a Notification) -> Sent<'a> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let answer = self.script.get(n).or(self.script.last()).cloned();
        let hang = self.hang;
        Box::pin(async move {
            if hang {
                std::future::pending::<()>().await;
            }
            answer.unwrap_or(Ok(()))
        })
    }
}

async fn run(fx: &Fx, p: &Arc<Scripted>, retry: Retry) -> (Value, Vec<PushTarget>) {
    let mut pusher = fx.pusher(vec![p.clone()]);
    pusher.retry = retry;
    pusher
        .deliver(vec![Notification::approval_needed("a1")])
        .await
        .unwrap();
    let last = fx.deliveries().await.pop().expect("a delivery event");
    (last, push_targets(&fx.pool).await.unwrap())
}

#[tokio::test]
async fn a_device_is_pushed_only_the_kinds_it_opted_into() {
    let fx = fx("optin").await;
    let fake = Arc::new(Fake::new("apns"));
    let (all, _) = fx.device("everything", &["approve", "agent"], 1).await;
    let (some, _) = fx.device("some", &["approve", "agent"], 2).await;
    let (none, _) = fx.device("none", &["approve", "agent"], 3).await;
    assert_eq!(
        get_kinds(&fx.pool, &all).await.unwrap(),
        None,
        "default is all"
    );
    for (id, kinds) in [(&some, vec!["agent_finished"]), (&none, vec![])] {
        let kinds: Vec<String> = kinds.into_iter().map(str::to_owned).collect();
        assert!(set_kinds(&fx.pool, id, Some(&kinds)).await.unwrap());
    }
    // Malformed lists are refused, and nothing changed.
    for bad in [
        vec!["has space".to_owned()],
        vec![String::new()],
        vec!["x".repeat(65)],
    ] {
        let r = set_kinds(&fx.pool, &some, Some(&bad)).await;
        assert!(matches!(r, Err(sqlx::Error::InvalidArgument(_))), "{bad:?}");
    }
    let r = set_kinds(&fx.pool, &some, Some(&vec!["k".to_owned(); 33])).await;
    assert!(matches!(r, Err(sqlx::Error::InvalidArgument(_))));
    assert_eq!(
        get_kinds(&fx.pool, &some).await.unwrap(),
        Some(vec!["agent_finished".to_owned()])
    );

    let pusher = fx.pusher(vec![fake.clone()]);
    pusher
        .deliver(vec![
            Notification::approval_needed("a1"),
            Notification::agent_finished("s1"),
        ])
        .await
        .unwrap();
    let mut got: Vec<(String, &str)> = fake.take().into_iter().map(|(d, n)| (d, n.kind)).collect();
    got.sort();
    let mut want = vec![
        (all.clone(), "agent_finished"),
        (all.clone(), "approval_needed"),
        (some.clone(), "agent_finished"),
    ];
    want.sort();
    assert_eq!(got, want, "`some` got no approval, `none` got nothing");

    // Clearing the choice goes back to every kind.
    assert!(set_kinds(&fx.pool, &none, None).await.unwrap());
    assert_eq!(get_kinds(&fx.pool, &none).await.unwrap(), None);
    fx.done().await;
}

#[tokio::test]
async fn a_failure_that_may_pass_is_retried_within_bounds() {
    let fx = fx("retry").await;
    fx.device("phone", &["approve"], 1).await;

    // Twice unlucky, then through: three calls, one `sent` event, no failure counted.
    let p = Scripted::new(vec![
        Err(PushError::Failed("503".into())),
        Err(PushError::Failed("503".into())),
        Ok(()),
    ]);
    let (event, targets) = run(&fx, &p, quick()).await;
    assert_eq!(p.calls.load(Ordering::SeqCst), 3);
    assert_eq!(event["status"], "sent");
    assert_eq!(targets.len(), 1);

    // Always failing: exactly `attempts` calls, then one failure against the token.
    let p = Scripted::new(vec![Err(PushError::Failed("503".into()))]);
    let (event, _) = run(&fx, &p, quick()).await;
    assert_eq!(p.calls.load(Ordering::SeqCst), 3, "bounded, not endless");
    assert_eq!(event["status"], "failed");
    let failures: i64 = sqlx::query_scalar("SELECT failures FROM core_push_tokens")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(
        failures, 1,
        "one notification is one failure, however many tries"
    );

    // A dead token and a provider without transport are tried once.
    let p = Scripted::new(vec![Err(PushError::Unsupported)]);
    run(&fx, &p, quick()).await;
    assert_eq!(p.calls.load(Ordering::SeqCst), 1);
    let p = Scripted::new(vec![Err(PushError::InvalidToken("410".into()))]);
    let (event, targets) = run(&fx, &p, quick()).await;
    assert_eq!(
        p.calls.load(Ordering::SeqCst),
        1,
        "a dead token is not retried"
    );
    assert_eq!(event["pruned"], true);
    assert!(targets.is_empty(), "and it is gone");
    fx.done().await;
}

#[tokio::test]
async fn a_provider_that_never_answers_fails_the_send_within_the_budget() {
    let fx = fx("budget").await;
    fx.device("phone", &["approve"], 1).await;
    let p = Arc::new(Scripted {
        calls: AtomicUsize::new(0),
        script: vec![],
        hang: true,
    });
    let retry = Retry {
        budget: Duration::from_millis(100),
        ..quick()
    };
    let started = Instant::now();
    let (event, _) = run(&fx, &p, retry).await;
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(event["status"], "failed");
    assert!(event["reason"].as_str().unwrap().contains("timed out"));
    fx.done().await;
}

struct Key(String);

impl SecretSource for Key {
    fn get(&self, _: &str) -> Option<String> {
        Some(self.0.clone())
    }
}

#[tokio::test]
async fn an_apns_gateway_that_never_answers_times_out() {
    // Accepts connections and says nothing, the way a hung gateway does.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = vec![];
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    let (pem, _) = super::tests::p8();
    let apns = ApnsNotifier::from_secret(&Key(pem), "k", "KEY1", "TEAM1", "com.ainkrad.app")
        .unwrap()
        .with_gateways(&url, &url)
        .with_timeout(Duration::from_millis(300))
        .unwrap();
    let fx = fx("hang").await;
    fx.device("phone", &["approve"], 1).await;
    let to = push_targets(&fx.pool).await.unwrap().remove(0);
    let started = Instant::now();
    let r = apns.send(&to, &Notification::approval_needed("a1")).await;
    assert!(matches!(r, Err(PushError::Failed(_))), "{r:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    fx.done().await;
}
