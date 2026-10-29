//! `ainkrad-runner pair` (E1-11.3, handshake spec §7.2 steps 2–4 and 8, §13): enrols this
//! runner as a `runner` device with a typed code or a QR payload, and pins the Core identity.
//!
//! 1. A new routine key (`device.p8`, 0600).
//! 2. The Core's fingerprint: the QR's `c`, which `/handshake` must also report; on the typed
//!    path, `/handshake`'s, confirmed by the human comparing the SAS.
//! 3. `POST /pair/claim` with the proof of possession; the answer's `core_spki` must have that
//!    fingerprint, else `core_identity_mismatch` and nothing is saved.
//! 4. The SAS, computed here from the Core key and this key, for the human to compare with
//!    the approver's screen.
//! 5. `POST /pair/status` (signed, session `-`) until approved; then `enrolment.json` (0600)
//!    holds the URL, the device id and the pinned fingerprint.
//!
//! Encodings and vectors: `crates/server/tests/vectors/pairing-v1.json`.

use std::time::Duration;

use serde_json::json;

use super::client::{Client, LinkError, Signer};
use super::key::{Enrolment, Key, State, b64, fingerprint, sha256, unb64};

/// Upper-case Crockford base32.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// What the human was given: the typed code, or the QR payload's parts.
pub enum Credential {
    Code(String),
    Qr { secret: String, core_fp: String },
}

/// The typed code, canonical: case folded, dashes and spaces dropped, `I`/`L` → `1`, `O` → `0`.
pub fn normal_code(typed: &str) -> Option<String> {
    let code: String = typed
        .chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        })
        .collect();
    (code.len() == 10 && code.bytes().all(|b| ALPHABET.contains(&b))).then_some(code)
}

/// `ainkrad-pair:v1?h=<host>&p=<port>&c=<core_fp>&s=<secret>&e=<expires>`: the Core's base URL
/// (`https://host[:port]`), its fingerprint and the secret.
pub fn parse_qr(payload: &str) -> Option<(String, String, String)> {
    let query = payload.strip_prefix("ainkrad-pair:v1?")?;
    let get = |k: &str| {
        query
            .split('&')
            .find_map(|kv| kv.strip_prefix(k)?.strip_prefix('='))
    };
    let (h, p, c, s) = (get("h")?, get("p")?, get("c")?, get("s")?);
    p.parse::<u16>().ok()?;
    let base = match p {
        "443" => format!("https://{h}"),
        _ => format!("https://{h}:{p}"),
    };
    Some((base, c.to_owned(), s.to_owned()))
}

/// `n` Crockford characters of `bytes`' 5-bit groups, most significant first.
fn crockford(bytes: &[u8], n: usize) -> String {
    let mut out = String::with_capacity(n);
    let (mut acc, mut bits) = (0u32, 0);
    for b in bytes {
        if out.len() == n {
            break;
        }
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 && out.len() < n {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    out
}

/// The SAS (§3): `XXXX-XXXX-XXXX-XXXX`.
pub fn sas(core_spki: &[u8], device_spki: &[u8], pairing_id: &str) -> String {
    let s = crockford(
        &sha256(
            &[
                b"AINKRAD-SAS-V1",
                core_spki,
                device_spki,
                pairing_id.as_bytes(),
            ]
            .concat(),
        ),
        16,
    );
    format!("{}-{}-{}-{}", &s[..4], &s[4..8], &s[8..12], &s[12..])
}

/// The proof-of-possession string (§7.2 step 3).
pub fn pop_message(core_fp: &str, credential_hash: &[u8], routine_fp: &str) -> Vec<u8> {
    format!(
        "AINKRAD-PAIR-V1\n{core_fp}\n{}\n{routine_fp}\n-",
        b64(credential_hash)
    )
    .into_bytes()
}

/// Pairs with the Core at `client` and saves the enrolment in `state`. `show_sas` gets the SAS
/// to display; `/pair/status` is polled every `poll`.
pub async fn pair(
    client: &Client,
    state: &State,
    credential: Credential,
    show_sas: impl FnOnce(&str),
    poll: Duration,
) -> Result<Enrolment, LinkError> {
    if state.enrolment().exists() {
        return Err(LinkError::Config(format!(
            "{} exists: this runner is enrolled already",
            state.enrolment().display()
        )));
    }
    let presented = client.core_fp().await?;
    let (expected, hash, field) = match &credential {
        Credential::Code(typed) => {
            let code = normal_code(typed)
                .ok_or_else(|| LinkError::Config("the code is 10 Crockford characters".into()))?;
            (
                presented.clone(),
                sha256(code.as_bytes()),
                json!({"code": typed}),
            )
        }
        Credential::Qr { secret, core_fp } => {
            let bytes = unb64(secret, 22)
                .ok_or_else(|| LinkError::Config("the QR secret is malformed".into()))?;
            (core_fp.clone(), sha256(&bytes), json!({"secret": secret}))
        }
    };
    if presented != expected {
        return Err(LinkError::Mismatch {
            pinned: expected,
            presented,
        });
    }
    std::fs::create_dir_all(&state.0).map_err(|e| LinkError::Config(e.to_string()))?;
    let _ = std::fs::remove_file(state.key());
    let key = Key::create(&state.key()).map_err(|e| LinkError::Config(e.to_string()))?;
    let mut body = field;
    body["routine_spki"] = json!(b64(&key.spki));
    body["platform"] = json!(format!(
        "{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    body["key_storage"] = json!("software");
    body["pop"] = json!(b64(&key.sign(&pop_message(&expected, &hash, &key.fp()))));
    let (_, claimed) = client
        .call("POST", "/pair/claim", Some(&body), None)
        .await?;
    let text = |k: &str| claimed[k].as_str().unwrap_or_default().to_owned();
    let core_spki = unb64(&text("core_spki"), 122).unwrap_or_default();
    if fingerprint(&core_spki) != expected {
        return Err(LinkError::Mismatch {
            pinned: expected,
            presented: fingerprint(&core_spki),
        });
    }
    let device = text("device_id");
    show_sas(&sas(&core_spki, &key.spki, &text("pairing_id")));
    let signer = Signer {
        key: &key,
        device: &device,
        core_fp: &expected,
    };
    loop {
        let (_, s) = client
            .call("POST", "/pair/status", None, Some((signer, None)))
            .await?;
        match s["status"].as_str() {
            Some("active") => break,
            Some("pending") => tokio::time::sleep(poll).await,
            other => {
                let why = format!("the pairing ended {}", other.unwrap_or("oddly"));
                return Err(LinkError::Refused(403, why));
            }
        }
    }
    let enrolment = Enrolment {
        url: client.base.clone(),
        device_id: device,
        core_fp: expected,
        rotation_seq: 0,
    };
    enrolment
        .save(&state.enrolment())
        .map_err(|e| LinkError::Config(e.to_string()))?;
    Ok(enrolment)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use ainkrad_proto::v2::{core_auth_message, runner_auth_message};
    use serde_json::Value;

    use super::super::client::canonical;
    use super::super::key::verify;
    use super::*;

    fn vectors(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    fn bytes(v: &Value, k: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(v[k].as_str().unwrap())
            .unwrap()
    }

    /// The Core's committed vectors hold for the runner's own builders too.
    #[test]
    fn the_cores_vectors_hold_here() {
        let p = vectors(include_str!(
            "../../../server/tests/vectors/pairing-v1.json"
        ));
        let s = |k: &str| p[k].as_str().unwrap().to_owned();
        let code = normal_code(&s("typed_code")).unwrap();
        assert_eq!(code, s("canonical_code"));
        assert_eq!(b64(&sha256(code.as_bytes())), s("code_hash"));
        let secret = unb64(&s("secret"), 22).unwrap();
        assert_eq!(b64(&sha256(&secret)), s("secret_hash"));
        let device = Key::from_pkcs8(&bytes(&p, "device_pkcs8")).unwrap();
        assert_eq!(b64(&device.spki), s("device_spki"));
        let core_spki = bytes(&p, "core_spki");
        let pop = pop_message(&s("core_fp"), &sha256(code.as_bytes()), &device.fp());
        assert_eq!(
            String::from_utf8(pop.clone()).unwrap(),
            s("pop_message_code")
        );
        assert!(verify(&device.spki, &pop, &bytes(&p, "pop_code")));
        assert_eq!(sas(&core_spki, &device.spki, &s("pairing_id")), s("sas"));

        let h = vectors(include_str!(
            "../../../server/tests/vectors/handshake-v1.json"
        ));
        let t = |k: &str| h[k].as_str().unwrap().to_owned();
        let message = canonical(
            &t("core_fp"),
            &t("device_id"),
            Some(&t("session_id")),
            &t("method"),
            &t("path"),
            h["timestamp"].as_i64().unwrap(),
            &t("nonce"),
            t("body").as_bytes(),
        );
        assert_eq!(String::from_utf8(message.clone()).unwrap(), t("canonical"));
        assert!(verify(
            &bytes(&h, "device_spki"),
            &message,
            &bytes(&h, "signature")
        ));

        let a = vectors(include_str!(
            "../../../server/tests/vectors/runner-auth-v1.json"
        ));
        let u = |k: &str| a[k].as_str().unwrap().to_owned();
        let (x, nr, nc) = (
            bytes(&a, "exporter"),
            bytes(&a, "nonce_r"),
            bytes(&a, "nonce_c"),
        );
        let core_msg = core_auth_message(&x, &nr, &u("device_id"));
        let runner_msg = runner_auth_message(&x, &nc, &u("core_fp"));
        assert_eq!(core_msg, bytes(&a, "core_auth_message"));
        assert_eq!(runner_msg, bytes(&a, "runner_auth_message"));
        assert!(verify(
            &bytes(&a, "core_spki"),
            &core_msg,
            &bytes(&a, "sig_core")
        ));
        assert!(verify(
            &bytes(&a, "device_spki"),
            &runner_msg,
            &bytes(&a, "sig_runner")
        ));
    }

    #[test]
    fn qr_payloads_parse_and_bad_codes_do_not() {
        let (base, c, s) =
            parse_qr("ainkrad-pair:v1?h=core.example&p=443&c=FP&s=SECRET&e=1").unwrap();
        assert_eq!(
            (base.as_str(), c.as_str(), s.as_str()),
            ("https://core.example", "FP", "SECRET")
        );
        let (base, ..) = parse_qr("ainkrad-pair:v1?h=127.0.0.1&p=7700&c=F&s=S&e=1").unwrap();
        assert_eq!(base, "https://127.0.0.1:7700");
        assert!(parse_qr("ainkrad-pair:v2?h=x&p=1&c=F&s=S").is_none());
        assert!(parse_qr("ainkrad-pair:v1?h=x&p=port&c=F&s=S").is_none());
        assert!(normal_code("ABCDE-FGHJ").is_none());
        assert!(normal_code("ABCDE-FGHJU").is_none(), "U is not Crockford");
    }

    #[test]
    fn the_key_and_enrolment_are_private_files() {
        let dir = std::env::temp_dir().join(format!("runner-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let state = State(dir.clone());
        let key = Key::create(&state.key()).unwrap();
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&state.key()), 0o600);
        assert_eq!(Key::load(&state.key()).unwrap().spki, key.spki);
        assert!(Key::create(&state.key()).is_err(), "never overwritten");
        let e = Enrolment {
            url: "https://core.example".to_owned(),
            device_id: "d_x".to_owned(),
            core_fp: key.fp(),
            rotation_seq: 2,
        };
        e.save(&state.enrolment()).unwrap();
        assert_eq!(mode(&state.enrolment()), 0o600);
        assert_eq!(Enrolment::load(&state.enrolment()).unwrap(), e);
        std::fs::set_permissions(state.key(), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Key::load(&state.key()).is_err(), "readable by others");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
