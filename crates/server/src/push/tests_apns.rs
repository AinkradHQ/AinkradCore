//! The notifications service end to end: the APNs transport against a local fake gateway that
//! speaks HTTP/2, token registration and its revocation cascade, the payload and scope rules,
//! coalescing and rate limits, and pruning. No key here is real and nothing leaves the machine.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ainkrad_core::audit::{AuditActor, AuditFilter};
use ainkrad_core::ids::UserId;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use sqlx::SqlitePool;

use super::apns::{ApnsNotifier, SecretSource};
use super::stub::{Fake, Unimplemented};
use super::*;
use crate::auth::testing::TestDevice;
use crate::scheduler::SystemClock;
use crate::store::connect;
use crate::store::gov::{push_targets, revoke_device, set_kinds, set_push_token, set_token};

/// What the fake gateway saw.
#[derive(Debug, Clone)]
struct Seen {
    path: String,
    authorization: String,
    topic: String,
    collapse: Option<String>,
    body: Value,
}

/// A local APNs: HTTP/2 without TLS, answering by the device token in the path (200 unless told).
struct Gateway {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    answers: Arc<Mutex<HashMap<String, (u16, &'static str)>>>,
}

async fn gateway() -> Gateway {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
    let answers: Arc<Mutex<HashMap<String, (u16, &'static str)>>> = Arc::default();
    let (s, a) = (seen.clone(), answers.clone());
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let (s, a) = (s.clone(), a.clone());
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (s, a) = (s.clone(), a.clone());
                    async move {
                        let header = |n: &str| {
                            let v = req.headers().get(n).and_then(|v| v.to_str().ok());
                            v.map(str::to_owned)
                        };
                        let path = req.uri().path().to_owned();
                        let seen = (
                            header("authorization").unwrap_or_default(),
                            header("apns-topic").unwrap_or_default(),
                            header("apns-collapse-id"),
                        );
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let token = path.rsplit('/').next().unwrap().to_owned();
                        s.lock().unwrap().push(Seen {
                            path,
                            authorization: seen.0,
                            topic: seen.1,
                            collapse: seen.2,
                            body: serde_json::from_slice(&body).unwrap_or_default(),
                        });
                        let (status, reason) =
                            a.lock().unwrap().get(&token).copied().unwrap_or((200, ""));
                        let body = if reason.is_empty() {
                            String::new()
                        } else {
                            json!({"reason": reason}).to_string()
                        };
                        let res = Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::from(body)));
                        Ok::<_, Infallible>(res.unwrap())
                    }
                });
                let conn = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                let _ = conn.serve_connection(TokioIo::new(sock), svc).await;
            });
        }
    });
    Gateway {
        url: format!("http://{addr}"),
        seen,
        answers,
    }
}

struct Secrets(HashMap<String, String>);

impl SecretSource for Secrets {
    fn get(&self, name: &str) -> Option<String> {
        self.0.get(name).cloned()
    }
}

pub(super) struct Fx {
    pub(super) pool: SqlitePool,
    dir: std::path::PathBuf,
}

pub(super) async fn fx(name: &str) -> Fx {
    let dir = std::env::temp_dir().join(format!("core-notify-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Fx {
        pool: connect(&dir.join("core.db")).await.unwrap(),
        dir,
    }
}

impl Fx {
    /// A device with `scopes` and an APNs token made from `n`, returning its id and token.
    pub(super) async fn device(&self, name: &str, scopes: &[&str], n: u8) -> (String, String) {
        let clock = Arc::new(SystemClock);
        let d = TestDevice::enroll(&self.pool, name, "device", scopes, "fp", clock).await;
        let token = format!("{n:02x}").repeat(32);
        assert!(
            set_push_token(&self.pool, &d.id, Some((&token, false)))
                .await
                .unwrap()
        );
        (d.id, token)
    }

    pub(super) fn pusher(&self, providers: Vec<Arc<dyn PushProvider>>) -> Pusher {
        let every = Duration::from_secs(1);
        Pusher::new(
            self.pool.clone(),
            providers,
            Arc::new(Silent),
            every,
            Arc::new(SystemClock),
        )
    }

    pub(super) async fn deliveries(&self) -> Vec<Value> {
        let all = crate::store::events::list_events(&self.pool, 0, 1000)
            .await
            .unwrap();
        all.into_iter()
            .filter(|e| e.kind == "notify.delivery")
            .map(|e| e.payload.0)
            .collect()
    }

    async fn actions(&self) -> Vec<String> {
        let filter = AuditFilter::default();
        let all = crate::store::audit::list(&self.pool, &filter, None, 100).await;
        all.unwrap().into_iter().map(|e| e.action).collect()
    }

    pub(super) async fn done(self) {
        self.pool.close().await;
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

#[tokio::test]
async fn apns_pushes_over_http2_with_an_es256_token_and_prunes_a_dead_token() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    let fx = fx("apns").await;
    let (sandbox, prod) = (gateway().await, gateway().await);
    let (pem, public) = super::tests::p8();
    let secrets = Secrets(HashMap::from([("apns.key".to_owned(), pem)]));
    assert!(ApnsNotifier::from_secret(&secrets, "missing", "K", "T", "com.ainkrad.app").is_err());
    let apns = ApnsNotifier::from_secret(&secrets, "apns.key", "KEY1", "TEAM1", "com.ainkrad.app")
        .unwrap()
        .with_gateways(&sandbox.url, &prod.url);

    let (_, live) = fx.device("phone", &["approve"], 1).await;
    let (dead_id, dead) = fx.device("old phone", &["approve"], 2).await;
    let (_, bad) = fx.device("bad", &["approve"], 3).await;
    let (_, flaky) = fx.device("flaky", &["approve"], 4).await;
    let (dev_id, dev) = fx.device("dev build", &["approve"], 5).await;
    set_push_token(&fx.pool, &dev_id, Some((&dev, true)))
        .await
        .unwrap();
    prod.answers
        .lock()
        .unwrap()
        .insert(dead.clone(), (410, "Unregistered"));
    prod.answers
        .lock()
        .unwrap()
        .insert(bad.clone(), (400, "BadDeviceToken"));
    prod.answers
        .lock()
        .unwrap()
        .insert(flaky.clone(), (503, "ServiceUnavailable"));

    let pusher = fx.pusher(vec![Arc::new(apns)]);
    assert_eq!(
        pusher
            .deliver(vec![Notification::approval_needed("a1")])
            .await
            .unwrap(),
        1
    );

    let seen = prod.seen.lock().unwrap().clone();
    let mut paths: Vec<&str> = seen.iter().map(|s| s.path.as_str()).collect();
    paths.sort_unstable();
    let mut want: Vec<String> = [&live, &dead, &bad, &flaky]
        .iter()
        .map(|t| format!("/3/device/{t}"))
        .collect();
    want.sort_unstable();
    assert_eq!(
        paths, want,
        "production devices go to the production gateway"
    );
    assert_eq!(
        sandbox.seen.lock().unwrap().len(),
        1,
        "the development build to the sandbox"
    );
    let first = &seen[0];
    assert_eq!(first.topic, "com.ainkrad.app");
    assert_eq!(first.collapse.as_deref(), Some("approval_needed"));
    assert_eq!(first.body["aps"]["alert"]["title"], "Approval needed");
    assert_eq!(first.body["ainkrad"]["data"], json!({"approval_id": "a1"}));
    let jwt = first
        .authorization
        .strip_prefix("Bearer ")
        .expect("a bearer token");
    let parts: Vec<&str> = jwt.split('.').collect();
    let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public)
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .expect("signed by the key the Core was given");

    // Dead and malformed tokens are gone; the failing one stays (once); the live ones stay.
    let left: Vec<String> = push_targets(&fx.pool)
        .await
        .unwrap()
        .into_iter()
        .map(|t| t.token)
        .collect();
    assert_eq!(left, [live.clone(), flaky.clone(), dev.clone()]);
    assert!(
        fx.actions()
            .await
            .iter()
            .filter(|a| *a == "notify.token_pruned")
            .count()
            == 2
    );
    let mut statuses: Vec<String> = fx
        .deliveries()
        .await
        .iter()
        .map(|e| e["status"].as_str().unwrap().to_owned())
        .collect();
    statuses.sort();
    assert_eq!(
        statuses,
        ["failed", "invalid_token", "invalid_token", "sent", "sent"]
    );
    let pruned = fx
        .deliveries()
        .await
        .into_iter()
        .find(|e| e["pruned"] == true)
        .unwrap();
    assert_eq!(pruned["provider"], "apns");
    assert!(
        pruned.get("token").is_none(),
        "an event never carries a token"
    );
    // The dead device itself is untouched: only its token went.
    assert!(
        crate::store::gov::device_usable(&fx.pool, &dead_id)
            .await
            .unwrap()
    );
    fx.done().await;
}

#[tokio::test]
async fn a_token_that_keeps_failing_is_pruned_and_a_success_resets_the_count() {
    let fx = fx("failing").await;
    let fcm = Arc::new(Fake::new("apns"));
    let (_, token) = fx.device("phone", &["approve"], 7).await;
    fcm.answers
        .lock()
        .unwrap()
        .insert(token.clone(), PushError::Failed("down".into()));
    let pusher = fx.pusher(vec![fcm.clone()]);
    let send = || pusher.deliver(vec![Notification::approval_needed("a")]);
    for _ in 0..4 {
        send().await.unwrap();
    }
    fcm.answers.lock().unwrap().clear();
    send().await.unwrap();
    fcm.answers
        .lock()
        .unwrap()
        .insert(token.clone(), PushError::Failed("down".into()));
    for _ in 0..4 {
        send().await.unwrap();
    }
    assert_eq!(
        push_targets(&fx.pool).await.unwrap().len(),
        1,
        "4 + 4 failures around a success: kept"
    );
    send().await.unwrap();
    assert!(
        push_targets(&fx.pool).await.unwrap().is_empty(),
        "the fifth in a row prunes it"
    );
    assert_eq!(
        fx.actions().await,
        ["device.enrolled", "notify.token_pruned"]
    );
    fx.done().await;
}

#[tokio::test]
async fn who_gets_what_scopes_ids_only_and_no_secrets() {
    let fx = fx("scopes").await;
    let fake = Arc::new(Fake::new("apns"));
    let (read, _) = fx.device("read-only", &["read"], 1).await;
    let (approver, _) = fx.device("approver", &["read", "approve"], 2).await;
    let (admin, _) = fx.device("admin", &["admin"], 3).await;
    let (terminal, _) = fx.device("terminal", &["read", "terminal"], 4).await;
    let (runner, _) = {
        let d = TestDevice::enroll(
            &fx.pool,
            "runner",
            "runner",
            &["runner"],
            "fp",
            Arc::new(SystemClock),
        )
        .await;
        let token = "5a".repeat(32);
        set_push_token(&fx.pool, &d.id, Some((&token, false)))
            .await
            .unwrap();
        (d.id, token)
    };
    let pusher = fx.pusher(vec![fake.clone()]);

    pusher
        .deliver(vec![Notification::approval_needed("a1")])
        .await
        .unwrap();
    let mut got: Vec<String> = fake.take().into_iter().map(|(d, _)| d).collect();
    got.sort();
    let mut want = vec![approver.clone(), admin.clone()];
    want.sort();
    assert_eq!(
        got, want,
        "approve and admin; not read, terminal or a runner"
    );
    let _ = (&read, &terminal, &runner);

    pusher
        .deliver(vec![Notification::terminal_exited("t1", Some(1))])
        .await
        .unwrap();
    let got: Vec<String> = fake.take().into_iter().map(|(d, _)| d).collect();
    assert!(got.contains(&terminal) && got.contains(&admin) && !got.contains(&read));

    // A module's notification with everything a careless one might carry.
    let nasty = Notification::new(
        "approval_needed",
        "approve",
        "Approve? Authorization: Bearer abcdefghij0123456789abcdefghij",
        "output: $ cat notes\nsk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        json!({
            "approval_id": "a9", "n": 4, "urgent": true,
            "terminal_output": "ls -la\ntotal 8",
            "api_key": "k", "password": "p", "token": "t",
            "leaked": "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "nested": {"a": 1}, "list": [1, 2],
        }),
    );
    pusher.deliver(vec![nasty]).await.unwrap();
    let (_, sent) = fake.take().remove(0);
    assert_eq!(
        sent.data,
        json!({"approval_id": "a9", "n": 4, "urgent": true})
    );
    let all = format!("{} {} {}", sent.title, sent.body, sent.data);
    for secret in ["abcdefghij0123456789", "sk-ant", "total 8"] {
        assert!(!all.contains(secret), "{secret} left the Core in {all}");
    }
    fx.done().await;
}

#[tokio::test]
async fn bursts_are_merged_and_each_device_has_a_ceiling() {
    let fx = fx("limits").await;
    let fake = Arc::new(Fake::new("apns"));
    fx.device("phone", &["approve"], 1).await;
    let pusher = fx.pusher(vec![fake.clone()]);

    let three = (1..=3)
        .map(|n| Notification::approval_needed(&format!("a{n}")))
        .collect();
    assert_eq!(
        pusher.deliver(three).await.unwrap(),
        1,
        "three approvals, one push"
    );
    let (_, merged) = fake.take().remove(0);
    assert_eq!(merged.data, json!({"approval_id": "a3", "count": 3}));
    assert_eq!(merged.body, "3 new");

    // Twelve separate pushes inside a minute: ten go.
    let many = (0..12)
        .map(|n| Notification::new("note", "approve", "x", "", json!({"n": n})))
        .collect();
    assert_eq!(pusher.deliver(many).await.unwrap(), 12);
    assert_eq!(
        fake.take().len(),
        9,
        "ten in the window, one already used by the merged push"
    );
    fx.done().await;
}

#[test]
fn the_ceiling_is_a_sliding_window_per_device() {
    let limiter = policy::Limiter::default();
    assert!((0..10).all(|_| limiter.allow(1, "", 1000)));
    assert!(!limiter.allow(1, "", 1059), "the eleventh in 60 s");
    assert!(limiter.allow(2, "", 1059), "another device has its own");
    assert!(limiter.allow(1, "", 1060), "the window moved on");
    assert!(
        limiter.allow(1, "toy", 1059),
        "a module has a budget of its own"
    );
}

#[tokio::test]
async fn tokens_belong_to_one_device_and_go_with_its_revocation() {
    let fx = fx("tokens").await;
    let (phone, token) = fx.device("phone", &["read"], 1).await;
    let (tablet, _) = fx.device("tablet", &["read"], 2).await;
    assert_eq!(push_targets(&fx.pool).await.unwrap().len(), 2);

    // A second provider for the same device; a bad token for either is refused.
    assert!(
        set_token(&fx.pool, &phone, "fcm", Some(("fcm-token-abcdef", false)))
            .await
            .unwrap()
    );
    for (provider, bad) in [
        ("fcm", "x"),
        ("fcm", "has space in it"),
        ("apns", "zz"),
        ("sms", "abcdefgh"),
    ] {
        let r = set_token(&fx.pool, &phone, provider, Some((bad, false))).await;
        assert!(
            matches!(r, Err(sqlx::Error::InvalidArgument(_))),
            "{provider} {bad}"
        );
    }
    // A token another device holds cannot be registered: no takeover, and the holder keeps it.
    let r = set_push_token(&fx.pool, &tablet, Some((&token, false))).await;
    assert!(matches!(r, Err(sqlx::Error::InvalidArgument(_))), "{r:?}");
    let by_device: Vec<(String, String)> = push_targets(&fx.pool)
        .await
        .unwrap()
        .into_iter()
        .map(|t| (t.device_id, t.provider))
        .collect();
    assert_eq!(
        by_device,
        [
            (phone.clone(), "apns".to_owned()),
            (phone.clone(), "fcm".to_owned()),
            (tablet.clone(), "apns".to_owned())
        ]
    );
    // The holder re-registering its own token is fine (a reinstall).
    assert!(
        set_push_token(&fx.pool, &phone, Some((&token, false)))
            .await
            .unwrap()
    );
    assert!(
        set_kinds(&fx.pool, &phone, Some(&["approval_needed".to_owned()]))
            .await
            .unwrap()
    );

    // Revoking removes every token the device had, and a revoked device cannot register one.
    assert!(
        revoke_device(
            &fx.pool,
            &phone,
            AuditActor::User(UserId(1)),
            None,
            "2026-10-30T10:00:00.000Z"
        )
        .await
        .unwrap()
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM core_push_tokens t JOIN core_devices d ON d.seq = t.device_seq WHERE d.id = ?")
        .bind(&phone)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(
        rows, 0,
        "the revoked device's tokens are gone, not just skipped"
    );
    let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM core_push_kinds")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(kept, 0, "and so is its opt-in");
    assert!(
        !set_push_token(&fx.pool, &phone, Some((&token, false)))
            .await
            .unwrap()
    );
    assert_eq!(push_targets(&fx.pool).await.unwrap().len(), 1);
    assert!(set_token(&fx.pool, &tablet, "apns", None).await.unwrap());
    assert!(push_targets(&fx.pool).await.unwrap().is_empty());
    fx.done().await;
}

#[tokio::test]
async fn a_provider_without_a_transport_neither_fails_nor_prunes() {
    let fx = fx("stub").await;
    let (id, _) = fx.device("phone", &["approve"], 1).await;
    set_token(&fx.pool, &id, "fcm", Some(("fcm-token-abcdef", false)))
        .await
        .unwrap();
    let fcm = Arc::new(Fake::new("fcm"));
    let pusher = fx.pusher(vec![Arc::new(Unimplemented("apns")), fcm.clone()]);
    for _ in 0..4 {
        pusher
            .deliver(vec![Notification::approval_needed("a")])
            .await
            .unwrap();
    }
    assert_eq!(
        push_targets(&fx.pool).await.unwrap().len(),
        2,
        "both tokens kept after 4 pushes"
    );
    let statuses: Vec<String> = fx
        .deliveries()
        .await
        .iter()
        .map(|e| e["status"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(statuses.iter().filter(|s| *s == "unsupported").count(), 4);
    assert_eq!(
        statuses.iter().filter(|s| *s == "sent").count(),
        4,
        "the fake FCM took its own"
    );
    assert_eq!(fcm.take().len(), 4);
    fx.done().await;
}
