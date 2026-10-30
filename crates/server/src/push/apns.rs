//! APNs over HTTP/2 with token-based auth (E10.4, E2-12.2): an ES256 JWT signed with the team's
//! `.p8` key, reused for 50 minutes (Apple wants 20 to 60), sent to `api.push.apple.com`, or to
//! the sandbox gateway for a development build's token.
//!
//! What the server needs from Apple (the operator's to supply): the APNs auth key `.p8` file,
//! its key id, the team id, and the app's bundle id (the topic), passed to `serve` as
//! `--apns-key`, `--apns-key-id`, `--apns-team-id`, `--apns-topic`; and the app built with
//! the push notification entitlement, registering its token at `PUT /api/v1/push-token`. The
//! key is read as a secret ([`SecretSource`]): the file today, the secrets broker (E2-07) when
//! it lands. Tests point the gateways at a local fake (`with_gateways`); no key is ever real.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde_json::json;

use super::{Notification, PushError, PushProvider, Sent};
use crate::store::gov::PushTarget;

/// Seconds a provider token is reused.
const TOKEN_TTL_SECS: u64 = 50 * 60;

/// Where a secret's value comes from by name: the secrets broker when it lands (E2-07), a
/// file or a map until then.
pub trait SecretSource: Send + Sync {
    fn get(&self, name: &str) -> Option<String>;
}

pub struct ApnsNotifier {
    key: EcdsaKeyPair,
    key_id: String,
    team_id: String,
    topic: String,
    client: reqwest::Client,
    /// The sandbox and production gateways' base URLs.
    gateways: (String, String),
    /// The current token and when it was made (seconds since the epoch).
    token: Mutex<Option<(String, u64)>>,
}

impl ApnsNotifier {
    /// The notifier for a `.p8` key (PKCS#8 PEM, as Apple hands it out).
    pub fn new(p8_pem: &str, key_id: &str, team_id: &str, topic: &str) -> Result<Self, String> {
        let body: String = p8_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .map(str::trim)
            .collect();
        let der = STANDARD
            .decode(body)
            .map_err(|e| format!("the APNs key is not PEM: {e}"))?;
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &SystemRandom::new())
                .map_err(|e| format!("the APNs key is not a P-256 PKCS#8 key: {e}"))?;
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            key,
            key_id: key_id.to_owned(),
            team_id: team_id.to_owned(),
            topic: topic.to_owned(),
            client,
            gateways: (
                "https://api.sandbox.push.apple.com".to_owned(),
                "https://api.push.apple.com".to_owned(),
            ),
            token: Mutex::default(),
        })
    }

    /// The notifier for the `.p8` held as secret `name`.
    pub fn from_secret(
        secrets: &dyn SecretSource,
        name: &str,
        key_id: &str,
        team_id: &str,
        topic: &str,
    ) -> Result<Self, String> {
        let pem = secrets
            .get(name)
            .ok_or_else(|| format!("no secret named {name:?} holds the APNs key"))?;
        Self::new(&pem, key_id, team_id, topic)
    }

    /// Sends to these gateways (sandbox, production) instead of Apple's, which must speak
    /// HTTP/2 (prior knowledge, so `http://` works for a local fake).
    pub fn with_gateways(mut self, sandbox: &str, production: &str) -> Self {
        self.gateways = (sandbox.to_owned(), production.to_owned());
        self
    }

    /// The provider token at `now` (seconds since the epoch): reused while fresh.
    pub fn jwt(&self, now: u64) -> Result<String, String> {
        let mut cached = self.token.lock().unwrap();
        if let Some((token, at)) = cached.as_ref()
            && now.saturating_sub(*at) < TOKEN_TTL_SECS
        {
            return Ok(token.clone());
        }
        let header = json!({"alg": "ES256", "kid": self.key_id}).to_string();
        let claims = json!({"iss": self.team_id, "iat": now}).to_string();
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let sig = self
            .key
            .sign(&SystemRandom::new(), input.as_bytes())
            .map_err(|e| format!("signing the APNs token: {e}"))?;
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));
        *cached = Some((token.clone(), now));
        Ok(token)
    }

    /// The request that pushes `n` to `to` at `now`; built here, sent by `send`.
    pub fn request(
        &self,
        to: &PushTarget,
        n: &Notification,
        now: u64,
    ) -> Result<reqwest::Request, String> {
        let base = match to.sandbox {
            true => &self.gateways.0,
            false => &self.gateways.1,
        };
        let body = json!({
            "aps": {"alert": {"title": n.title, "body": n.body}, "sound": "default",
                    "thread-id": n.kind},
            "ainkrad": {"kind": n.kind, "data": n.data},
        });
        let mut req = self
            .client
            .post(format!("{base}/3/device/{}", to.token))
            .bearer_auth(self.jwt(now)?)
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .json(&body);
        // Apple replaces an undelivered push with the same collapse id (at most 64 bytes).
        if let Some(key) = n.collapse.as_deref().filter(|k| k.is_ascii()) {
            req = req.header("apns-collapse-id", &key[..key.len().min(64)]);
        }
        req.build().map_err(|e| e.to_string())
    }
}

/// What a non-2xx answer means for the token: Apple's `reason` says whether it is dead.
fn classify(status: u16, reason: &str) -> PushError {
    let why = format!("APNs {status} {reason}");
    match (status, reason) {
        (410, _) | (400, "BadDeviceToken" | "DeviceTokenNotForTopic") => {
            PushError::InvalidToken(why)
        }
        _ => PushError::Failed(why),
    }
}

impl PushProvider for ApnsNotifier {
    fn name(&self) -> &'static str {
        "apns"
    }

    fn send<'a>(&'a self, to: &'a PushTarget, n: &'a Notification) -> Sent<'a> {
        Box::pin(async move {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let req = self.request(to, n, now).map_err(PushError::Failed)?;
            let res = self
                .client
                .execute(req)
                .await
                .map_err(|e| PushError::Failed(e.to_string()))?;
            let status = res.status();
            if status.is_success() {
                return Ok(());
            }
            let body: serde_json::Value = res.json().await.unwrap_or_default();
            let reason = body["reason"].as_str().unwrap_or_default();
            if status.as_u16() == 403 {
                // An expired or rejected provider token: make a fresh one next time.
                *self.token.lock().unwrap() = None;
            }
            Err(classify(status.as_u16(), reason))
        })
    }
}
