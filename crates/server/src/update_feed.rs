//! The release feed the updater reads (`scripts/release/update.sh`), read the same way for the App's "Check now"
//! (`POST /api/v1/core/update/check`): `manifest.json` and its minisign signature from `BASE` (default
//! `https://ainkrad.io/releases`; `/etc/ainkrad/update.conf` `BASE=` / `CHANNEL=` when readable), verified with the
//! pinned release key (`/usr/local/lib/ainkrad/ainkrad-release.pub`, else the key compiled in). A manifest that does
//! not verify is never read. The Core only looks: installing is the root-side updater's, which verifies everything again.
//!
//! ponytail: only legacy (`minisign -S -l`, plain Ed25519) signatures verify, which is what `ci-publish.sh` makes; a
//! prehashed (BLAKE2b) one is refused as `bad_signature`. Add BLAKE2b when the release switches.

use std::path::Path;
use std::time::Duration;

use base64::Engine;
use ring::signature::{ED25519, UnparsedPublicKey};

const BASE: &str = "https://ainkrad.io/releases";
const CHANNEL: &str = "stable";
const CONF: &str = "/etc/ainkrad/update.conf";
const KEY_FILE: &str = "/usr/local/lib/ainkrad/ainkrad-release.pub";
const PINNED: &str = include_str!("../../../scripts/release/ainkrad-release.pub");
/// The same cap as update.sh's `curl --max-filesize`.
const MAX: usize = 1_000_000;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Where to look. `Default` is the host's own setup; tests fix the base and the key.
#[derive(Default)]
pub struct Feed {
    /// `(base, channel, public key file text)`, replacing update.conf and the pinned key.
    pub fixed: Option<(String, String, String)>,
}

/// What a verified manifest names for this channel.
#[derive(Debug, PartialEq, Eq)]
pub struct Latest {
    pub core: String,
    pub runner: Option<String>,
}

impl Feed {
    /// Fetches, verifies and reads the manifest. The error is a short code (update.sh's words where it has one).
    pub async fn latest(&self, now: i64) -> Result<Latest, &'static str> {
        let (base, channel, key) = match &self.fixed {
            Some((b, c, k)) => (b.clone(), c.clone(), k.clone()),
            None => {
                let (b, c) = conf(&std::fs::read_to_string(CONF).unwrap_or_default());
                let key = std::fs::read_to_string(KEY_FILE).unwrap_or_else(|_| PINNED.to_owned());
                (b, c, key)
            }
        };
        let manifest = get(&base, "manifest.json").await?;
        let sig = get(&base, "manifest.json.minisig").await?;
        verify(&key, &manifest, &String::from_utf8_lossy(&sig))?;
        read(&manifest, &channel, now)
    }
}

/// `BASE=` and `CHANNEL=` from update.conf (a shell file root sources: the last assignment wins, quotes are dropped).
pub fn conf(text: &str) -> (String, String) {
    let (mut base, mut channel) = (BASE.to_owned(), CHANNEL.to_owned());
    for l in text.lines() {
        let Some((k, v)) = l.trim().split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches(['"', '\'']).to_owned();
        match k {
            "BASE" => base = v,
            "CHANNEL" => channel = v,
            _ => {}
        }
    }
    (base, channel)
}

async fn get(base: &str, name: &str) -> Result<Vec<u8>, &'static str> {
    if base.starts_with('/') {
        let b = tokio::fs::read(Path::new(base).join(name)).await;
        return b.ok().filter(|b| b.len() <= MAX).ok_or("no_manifest");
    }
    if !base.starts_with("https://") {
        return Err("bad_base");
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .timeout(TIMEOUT)
        .build()
        .map_err(|_| "no_manifest")?;
    let mut resp = client
        .get(format!("{}/{name}", base.trim_end_matches('/')))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|_| "no_manifest")?;
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| "no_manifest")? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX {
            return Err("no_manifest");
        }
    }
    Ok(body)
}

fn b64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()
}

/// A minisign signature (legacy `Ed`) of `msg` by the key in `pubkey` (a `.pub` file's text), and its trusted comment.
pub fn verify(pubkey: &str, msg: &[u8], sig: &str) -> Result<(), &'static str> {
    let pk = pubkey
        .lines()
        .find_map(|l| b64(l).filter(|b| b.len() == 42 && &b[..2] == b"Ed"))
        .ok_or("bad_key")?;
    let mut lines = sig.lines();
    let (Some(_untrusted), Some(s), Some(trusted), Some(global)) =
        (lines.next(), lines.next(), lines.next(), lines.next())
    else {
        return Err("bad_signature");
    };
    let s = b64(s)
        .filter(|s| s.len() == 74 && &s[..2] == b"Ed" && s[2..10] == pk[2..10])
        .ok_or("bad_signature")?;
    let trusted = trusted
        .strip_prefix("trusted comment: ")
        .ok_or("bad_signature")?;
    let global = b64(global).ok_or("bad_signature")?;
    let key = UnparsedPublicKey::new(&ED25519, &pk[10..]);
    key.verify(msg, &s[10..]).map_err(|_| "bad_signature")?;
    let signed = [&s[10..], trusted.as_bytes()].concat();
    key.verify(&signed, &global).map_err(|_| "bad_signature")
}

/// The channel's core and runner versions from a verified manifest that has not expired.
pub fn read(raw: &[u8], channel: &str, now: i64) -> Result<Latest, &'static str> {
    let m: serde_json::Value = serde_json::from_slice(raw).map_err(|_| "bad_manifest")?;
    let expires = m["expires"].as_i64().ok_or("bad_manifest")?;
    if now > expires {
        return Err("manifest_expired");
    }
    let c = &m["channels"][channel];
    let v = |k: &str| {
        c[k]["version"]
            .as_str()
            .filter(|v| ainkrad_proto::v2::plain_version(v))
            .map(str::to_owned)
    };
    Ok(Latest {
        core: v("core").ok_or("bad_manifest")?,
        runner: v("runner"),
    })
}

/// `a` is newer than `b` in semver order, as update.sh orders them: `1.1.0-rc1` < `1.1.0`.
pub fn newer(a: &str, b: &str) -> bool {
    type Key = ((u64, u64, u64), bool, Vec<(bool, u64, String)>);
    fn key(v: &str) -> Option<Key> {
        let (core, pre) = v.split_once(['-', '+']).unwrap_or((v, ""));
        let mut n = core.split('.').map(|p| p.parse().ok());
        let nums = (n.next()??, n.next()??, n.next()??);
        // A numeric part sorts below a word, numbers by value.
        let ids = pre
            .split(['.', '-'])
            .filter(|p| !p.is_empty())
            .map(|p| match p.parse() {
                Ok(n) => (false, n, String::new()),
                Err(_) => (true, 0, p.to_owned()),
            })
            .collect();
        Some((nums, pre.is_empty(), ids))
    }
    matches!((key(a), key(b)), (Some(a), Some(b)) if a > b)
}

/// A key and a signer in minisign's legacy format, for tests: `(public key file, sign(msg) -> signature file)`.
#[cfg(test)]
pub fn test_signer() -> (String, impl Fn(&[u8]) -> String) {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let rng = ring::rand::SystemRandom::new();
    let pair =
        Ed25519KeyPair::from_pkcs8(Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
    let e = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let id = [7u8; 8];
    let pk = [b"Ed".as_slice(), &id, pair.public_key().as_ref()].concat();
    let public = format!("untrusted comment: test key\n{}\n", e(&pk));
    let sign = move |msg: &[u8]| {
        let s = pair.sign(msg);
        let global = pair.sign(&[s.as_ref(), b"test"].concat());
        let sig = [b"Ed".as_slice(), &id, s.as_ref()].concat();
        format!(
            "untrusted comment: t\n{}\ntrusted comment: test\n{}\n",
            e(&sig),
            e(global.as_ref())
        )
    };
    (public, sign)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made by minisign 0.12: `minisign -G -W`, then `-S -l -t "ainkrad manifest test"` and `-S -t x` (prehashed) over
    // "hello manifest\n".
    const PUB: &str = "untrusted comment: minisign public key 1C7048DDBACC1C94\nRWSUHMy63UhwHP09/neFsOvm9dp8WihQwHXyS9Tmg0TD/e4quOaMbhFu\n";
    const LEGACY: &str = "untrusted comment: signature from minisign secret key\nRWSUHMy63UhwHJ+OCtX2E/vmxGCSfDc6FrggUrK5keCFIZ6mw4l9lQWvmRF8ZVgOKAsG7GINo7wASfyeJ8nmTM/WK3dngBnDdgY=\ntrusted comment: ainkrad manifest test\nr50H6r7/6qK5Fs9fa+L1CEJSnFKHKEiO2cAA12N4fEBFW8e4Rrby6nriX7Tx0LLde7yaCktrqM8N0EJBEcmwAg==\n";
    const PREHASHED: &str = "untrusted comment: signature from minisign secret key\nRUSUHMy63UhwHL1KtMQgKwPIJgRuVj53275IyA3uHpy4fjmTK3F7NmDRsIi8o67t5JDbDhCcr108Vjc0iOMlko3oKJ33WCZXlQo=\ntrusted comment: x\nPg3hpq8v5O68yvrM21hlB/ctVnnuEuX902Yv0x5eOG3YiVIdEyuECKDnVkIRJZ+7RJLBcZTdQxymMy6geb1HAA==\n";
    const MSG: &[u8] = b"hello manifest\n";

    #[test]
    fn a_real_minisign_signature_verifies_and_nothing_else_does() {
        assert_eq!(verify(PUB, MSG, LEGACY), Ok(()));
        assert_eq!(
            verify(PUB, b"hello manifest!\n", LEGACY),
            Err("bad_signature")
        );
        assert_eq!(verify(PUB, MSG, PREHASHED), Err("bad_signature"));
        // a changed trusted comment breaks the global signature
        let t = LEGACY.replace("manifest test", "manifest tesT");
        assert_eq!(verify(PUB, MSG, &t), Err("bad_signature"));
        // another key (the shipped release key) does not verify it
        assert_eq!(verify(PINNED, MSG, LEGACY), Err("bad_signature"));
        assert_eq!(verify("nope", MSG, LEGACY), Err("bad_key"));
        assert_eq!(verify(PUB, MSG, ""), Err("bad_signature"));
    }

    #[test]
    fn the_pinned_key_parses() {
        assert_eq!(verify(PINNED, MSG, ""), Err("bad_signature"));
    }

    #[test]
    fn a_manifest_names_core_and_runner_until_it_expires() {
        let m = br#"{"expires":100,"channels":{"stable":{"core":{"version":"0.10.2"},"runner":{"version":"0.10.2"}}}}"#;
        let l = read(m, "stable", 50).unwrap();
        assert_eq!(
            (l.core.as_str(), l.runner.as_deref()),
            ("0.10.2", Some("0.10.2"))
        );
        assert_eq!(read(m, "stable", 101), Err("manifest_expired"));
        assert_eq!(read(m, "beta", 50), Err("bad_manifest"));
        let bad = br#"{"expires":100,"channels":{"stable":{"core":{"version":"1.0; rm -rf"}}}}"#;
        assert_eq!(read(bad, "stable", 50), Err("bad_manifest"));
    }

    #[test]
    fn versions_order_like_the_updater() {
        assert!(newer("0.10.2", "0.10.1"));
        assert!(newer("0.10.10", "0.10.9"));
        assert!(newer("1.1.0", "1.1.0-rc1"));
        assert!(!newer("1.1.0-rc1", "1.1.0"));
        assert!(newer("1.1.0-rc2", "1.1.0-rc1"));
        assert!(!newer("0.10.2", "0.10.2"));
        assert!(!newer("x", "0.1.0"));
    }

    #[test]
    fn update_conf_is_read_like_the_shell() {
        assert_eq!(conf(""), (BASE.to_owned(), CHANNEL.to_owned()));
        let (b, c) = conf("# mirror\nBASE=\"https://m.example/r\"\nCHANNEL=beta\n");
        assert_eq!((b.as_str(), c.as_str()), ("https://m.example/r", "beta"));
    }

    #[tokio::test]
    async fn a_local_feed_is_verified_before_it_is_read() {
        let d = std::env::temp_dir().join(format!("core-feed-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let (public, sign) = test_signer();
        let m = br#"{"expires":9999999999,"channels":{"stable":{"core":{"version":"9.0.0"},"runner":{"version":"9.0.1"}}}}"#;
        std::fs::write(d.join("manifest.json"), m).unwrap();
        std::fs::write(d.join("manifest.json.minisig"), sign(m)).unwrap();
        let base = d.to_str().unwrap().to_owned();
        let feed = Feed {
            fixed: Some((base.clone(), "stable".into(), public)),
        };
        let l = feed.latest(0).await.unwrap();
        assert_eq!(
            (l.core.as_str(), l.runner.as_deref()),
            ("9.0.0", Some("9.0.1"))
        );
        let (other, _) = test_signer();
        let feed = Feed {
            fixed: Some((base, "stable".into(), other)),
        };
        assert_eq!(feed.latest(0).await, Err("bad_signature"));
        let feed = Feed {
            fixed: Some(("http://x".into(), "stable".into(), String::new())),
        };
        assert_eq!(feed.latest(0).await, Err("bad_base"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
