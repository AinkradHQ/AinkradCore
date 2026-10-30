//! The pusher with a recording notifier, and the APNs request it would send (never sent).

use std::collections::HashSet;
use std::sync::Mutex;

use ainkrad_core::audit::{AuditActor, AuditEntity, NewAuditEvent};
use ainkrad_core::ids::{DeviceKeyId, UserId};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use serde_json::json;

use super::apns::ApnsNotifier;
use super::*;
use crate::auth::testing::TestDevice;
use crate::store::gov::{PushTarget, get_device, revoke_device, set_push_token};
use crate::store::{audit, connect};

#[derive(Default)]
struct Recorder(Mutex<Vec<(DeviceKeyId, Notification)>>);

impl PushProvider for Recorder {
    fn name(&self) -> &'static str {
        "apns"
    }

    fn send<'a>(&'a self, to: &'a PushTarget, n: &'a Notification) -> Sent<'a> {
        self.0.lock().unwrap().push((to.device, n.clone()));
        Box::pin(async { Ok(()) })
    }
}

impl Recorder {
    fn take(&self) -> Vec<(DeviceKeyId, Notification)> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

/// A module's rules, as a test has them: every `alert.*` audit is pushed.
struct Alerts;

impl Classifier for Alerts {
    fn notification(&self, e: &StoredEvent) -> Option<Notification> {
        let action = e.payload.0["action"].as_str()?;
        (e.kind == "audit" && action.starts_with("alert.")).then(|| Notification {
            kind: "alert",
            title: action.to_owned(),
            body: String::new(),
            data: json!({"seq": e.seq}),
            scope: "read",
            collapse: None,
        })
    }
}

fn audited(action: &str) -> NewAuditEvent {
    NewAuditEvent {
        actor: AuditActor::System,
        action: action.to_owned(),
        entity: Some(AuditEntity {
            kind: "thing".to_owned(),
            id: 1,
        }),
        details: "{}".to_owned(),
    }
}

#[tokio::test]
async fn pushes_what_the_classifier_picks_to_live_devices_once() {
    let dir = std::env::temp_dir().join(format!("core-push-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    crate::store::kinds::allow(
        &pool,
        &[],
        &[
            "alert.before",
            "alert.first",
            "alert.second",
            "alert.third",
            "thing.routine",
        ],
    )
    .await;

    let by = AuditActor::User(UserId(1));
    let token = |n: u8| format!("{n:02x}").repeat(32);
    let mut devices = vec![];
    let mut ids = vec![];
    for (n, name) in ["mac", "phone", "old", "silent"].iter().enumerate() {
        let clock = Arc::new(crate::scheduler::SystemClock);
        let d = TestDevice::enroll(&pool, name, "device", &["read"], "fp", clock).await;
        if *name != "silent" {
            set_push_token(&pool, &d.id, Some((&token(n as u8), false)))
                .await
                .unwrap();
        }
        let seq = get_device(&pool, &d.id).await.unwrap().unwrap().seq;
        devices.push(DeviceKeyId(seq));
        ids.push(d.id);
    }
    revoke_device(&pool, &ids[2], by, None, "2026-10-22T10:00:00.000Z")
        .await
        .unwrap();

    let recorder = Arc::new(Recorder::default());
    let pusher = |classifier: Arc<dyn Classifier>| {
        let clock = Arc::new(crate::scheduler::SystemClock);
        let providers: Vec<Arc<dyn PushProvider>> = vec![recorder.clone()];
        Pusher::new(
            pool.clone(),
            providers,
            classifier,
            Duration::from_secs(1),
            clock,
        )
    };
    let alerts = pusher(Arc::new(Alerts));
    audit::append_one(&pool, &audited("alert.before"))
        .await
        .unwrap();
    assert_eq!(alerts.tick().await.unwrap(), 0, "history is not pushed");

    for action in ["alert.first", "thing.routine", "alert.second"] {
        audit::append_one(&pool, &audited(action)).await.unwrap();
    }
    assert_eq!(alerts.tick().await.unwrap(), 2);
    let sent = recorder.take();
    let to: HashSet<i64> = sent.iter().map(|(d, _)| d.0).collect();
    assert_eq!(
        to,
        HashSet::from([devices[0].0, devices[1].0]),
        "live, with a token"
    );
    let titles: Vec<&str> = sent
        .iter()
        .step_by(2)
        .map(|(_, n)| n.title.as_str())
        .collect();
    assert_eq!(titles, ["alert.first", "alert.second"]);
    assert_eq!(alerts.tick().await.unwrap(), 0, "each once");

    // The platform's default pushes nothing, and still moves the cursor.
    audit::append_one(&pool, &audited("alert.third"))
        .await
        .unwrap();
    assert_eq!(pusher(Arc::new(Silent)).tick().await.unwrap(), 0);
    assert_eq!(alerts.tick().await.unwrap(), 0);
    assert!(recorder.take().is_empty());

    pool.close().await;
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A throwaway P-256 key as Apple's `.p8` file would hold it, and its public key.
pub(super) fn p8() -> (String, Vec<u8>) {
    use base64::Engine;
    let rng = SystemRandom::new();
    let der = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der.as_ref(), &rng).unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        lines.join("\n")
    );
    (pem, pair.public_key().as_ref().to_vec())
}

#[test]
fn the_apns_request_carries_a_valid_es256_token_and_goes_to_the_right_gateway() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (pem, public) = p8();
    let apns = ApnsNotifier::new(&pem, "KEY123", "TEAM456", "com.ainkrad.app").unwrap();
    assert!(ApnsNotifier::new("not a key", "k", "t", "b").is_err());

    let jwt = apns.jwt(1_000_000).unwrap();
    let parts: Vec<&str> = jwt.split('.').collect();
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(header, json!({"alg": "ES256", "kid": "KEY123"}));
    assert_eq!(claims, json!({"iss": "TEAM456", "iat": 1_000_000}));
    let signed = format!("{}.{}", parts[0], parts[1]);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public)
        .verify(
            signed.as_bytes(),
            &URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
        )
        .expect("a valid ES256 signature");
    assert_eq!(
        apns.jwt(1_000_000 + 49 * 60).unwrap(),
        jwt,
        "reused while fresh"
    );
    assert_ne!(
        apns.jwt(1_000_000 + 51 * 60).unwrap(),
        jwt,
        "renewed after 50 minutes"
    );

    let n = Notification {
        kind: "approval",
        title: "Approval needed".to_owned(),
        body: "A pr merge waits on you".to_owned(),
        data: json!({"approval_id": 3, "seq": 9}),
        scope: "approve",
        collapse: Some("approval".to_owned()),
    };
    let mut to = PushTarget {
        device: DeviceKeyId(1),
        device_id: "d_x".to_owned(),
        scopes: vec!["approve".to_owned()],
        provider: "apns".to_owned(),
        token: "ab".repeat(32),
        sandbox: false,
    };
    let req = apns.request(&to, &n, 2_000_000).unwrap();
    assert_eq!(req.method(), "POST");
    assert_eq!(
        req.url().as_str(),
        format!("https://api.push.apple.com/3/device/{}", to.token)
    );
    let h = req.headers();
    assert_eq!(h["apns-topic"], "com.ainkrad.app");
    assert_eq!(h["apns-collapse-id"], "approval");
    assert_eq!(h["apns-push-type"], "alert");
    assert!(
        h["authorization"]
            .to_str()
            .unwrap()
            .starts_with("Bearer ey")
    );
    let body: Value = serde_json::from_slice(req.body().unwrap().as_bytes().unwrap()).unwrap();
    assert_eq!(body["aps"]["alert"]["title"], "Approval needed");
    assert_eq!(body["ainkrad"]["data"]["approval_id"], 3);
    to.sandbox = true;
    let req = apns.request(&to, &n, 2_000_000).unwrap();
    assert_eq!(req.url().host_str(), Some("api.sandbox.push.apple.com"));
}
