//! APNs over HTTP/2 with token-based auth (E10.4): an ES256 JWT signed with the team's `.p8`
//! key, reused for 50 minutes (Apple wants 20 to 60), sent to `api.push.apple.com`, or to
//! the sandbox gateway for a development build's token.
//!
//! What the server needs from Apple (Ahmed's to supply): the APNs auth key `.p8` file, its
//! key id, the team id, and the app's bundle id (the topic), passed to `serve` as
//! `--apns-key`, `--apns-key-id`, `--apns-team-id`, `--apns-topic`; and the app built with
//! the push notification entitlement, registering its token at `PUT /api/v1/push-token`.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde_json::json;

use super::{Notification, Notifier, Sent};
use crate::store::gov::PushTarget;

/// Seconds a provider token is reused.
const TOKEN_TTL_SECS: u64 = 50 * 60;

pub struct ApnsNotifier {
    key: EcdsaKeyPair,
    key_id: String,
    team_id: String,
    topic: String,
    client: reqwest::Client,
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
            token: Mutex::default(),
        })
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
        let host = match to.sandbox {
            true => "api.sandbox.push.apple.com",
            false => "api.push.apple.com",
        };
        let body = json!({
            "aps": {"alert": {"title": n.title, "body": n.body}, "sound": "default",
                    "thread-id": n.kind},
            "citadel": {"kind": n.kind, "data": n.data},
        });
        self.client
            .post(format!("https://{host}/3/device/{}", to.token))
            .bearer_auth(self.jwt(now)?)
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .json(&body)
            .build()
            .map_err(|e| e.to_string())
    }
}

impl Notifier for ApnsNotifier {
    fn send<'a>(&'a self, to: &'a PushTarget, n: &'a Notification) -> Sent<'a> {
        Box::pin(async move {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let req = self.request(to, n, now)?;
            let res = self.client.execute(req).await.map_err(|e| e.to_string())?;
            if res.status().is_success() {
                return Ok(());
            }
            let status = res.status();
            Err(format!(
                "APNs {status}: {}",
                res.text().await.unwrap_or_default()
            ))
        })
    }
}
