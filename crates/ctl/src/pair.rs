//! Pairing as the new device (spec §7.2 steps 2–4 and 8; §7.3 for the first device, whose
//! claim is the same call over the host's Unix socket): generate the routine key and the
//! step-up key (§8, Q6: sealed under a passphrase, `stepup`) here, claim
//! with the typed code or the QR secret and the proof of possession, pin the Core, show the
//! SAS computed locally, then poll `/pair/status` until the approver decides.

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use crate::Error;
use crate::client::{Client, handshake, parse, refusal, unix_now};
use crate::keystore::Keystore;
use crate::net::{Endpoint, Net};
use crate::proto::{
    Key, Qr, b64, code_hash, fp, normal_code, pop_message, sas, secret_hash, unb64,
};
use crate::stepup::{self, Passphrase};

/// What was typed or scanned.
pub enum Credential {
    Code(String),
    Qr(Qr),
}

impl Credential {
    /// A QR payload (`ainkrad-pair:v1?…`) or a typed code (`ABCDE-FGHJK`, any case).
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.starts_with("ainkrad-pair:") {
            return Qr::parse(text)
                .map(Self::Qr)
                .ok_or_else(|| Error::Usage("the QR payload is not ainkrad-pair:v1".into()));
        }
        normal_code(text).map(Self::Code).ok_or_else(|| {
            Error::Usage("a pairing code is 10 Crockford characters, ABCDE-FGHJK".into())
        })
    }
}

#[derive(Deserialize)]
struct Claimed {
    device_id: Option<String>,
    core_spki: Option<String>,
    pairing_id: Option<String>,
    sas: Option<String>,
}

/// What `pair` needs besides the credential.
pub struct Pairing<'a> {
    /// `--socket`/`--url`; a QR names its own (`https://h:p`) when this is `None`.
    pub endpoint: Option<Endpoint>,
    pub host: Option<String>,
    pub ca: Option<&'a Path>,
    pub keystore: &'a Path,
    /// `--core-fp`: the fingerprint the host printed (bootstrap), checked against the Core.
    pub core_fp: Option<String>,
    pub json: bool,
    /// How long to wait for the approver (the pairing lives 5 minutes).
    pub wait: Duration,
    /// Where the step-up key's passphrase comes from; `None` enrols no step-up key
    /// (`--no-stepup`), and the device can then never elevate.
    pub stepup: Option<Passphrase>,
}

fn say(out: &mut impl Write, json: bool, line: &str, value: serde_json::Value) {
    let _ = match json {
        true => writeln!(out, "{value}"),
        false => writeln!(out, "{line}"),
    };
    let _ = out.flush();
}

/// Claims, shows the SAS, waits for approval. The keystore is written once the claim is
/// accepted and removed again if the pairing ends unapproved.
pub async fn pair(cred: Credential, p: Pairing<'_>, out: &mut impl Write) -> Result<(), Error> {
    if p.keystore.exists() || stepup::path_for(p.keystore).exists() {
        return Err(Error::Usage(format!(
            "{} exists: this device is paired already (use another --keystore)",
            p.keystore.display()
        )));
    }
    let endpoint = match (&p.endpoint, &cred) {
        (Some(e), _) => e.clone(),
        (None, Credential::Qr(q)) => Endpoint::Https(match q.port {
            443 => q.host.clone(),
            port => format!("{}:{port}", q.host),
        }),
        (None, Credential::Code(_)) => {
            return Err(Error::Usage("a typed code needs --socket or --url".into()));
        }
    };
    let net = Net::new(endpoint.clone(), p.host.clone(), p.ca)?;
    // The fingerprint the proof binds: the QR's, else the one the host printed, else what
    // the Core says (trust on first use, confirmed by the SAS). Any two must agree.
    let served = handshake(&net)
        .await?
        .identity_fingerprint
        .unwrap_or_default();
    let pinned = match (&cred, &p.core_fp) {
        (Credential::Qr(q), _) => q.core_fp.clone(),
        (_, Some(f)) => f.clone(),
        _ => served.clone(),
    };
    if served != pinned {
        return Err(Error::Identity { pinned, served });
    }
    // Asked before the claim, so a failed prompt does not spend the pairing.
    let sealing = match &p.stepup {
        Some(source) => Some(source.read(true).map_err(Error::StepUp)?),
        None => None,
    };
    let key = Key::generate();
    let routine = key.spki();
    let second = sealing.as_ref().map(|_| Key::generate());
    let second_spki = second.as_ref().map(Key::spki);
    let second_fp = second_spki.as_deref().map(fp);
    let (field, value, hash) = match &cred {
        Credential::Code(c) => ("code", c.clone(), code_hash(c)),
        Credential::Qr(q) => ("secret", b64(&q.secret), secret_hash(&q.secret)),
    };
    let message = pop_message(&pinned, &hash, &fp(&routine), second_fp.as_deref());
    let mut body = serde_json::json!({
        "routine_spki": b64(&routine),
        "platform": std::env::consts::OS,
        "key_storage": "software",
        "pop": b64(&key.sign(message.as_bytes())),
    });
    if let (Some(k), Some(spki)) = (&second, &second_spki) {
        body["stepup_spki"] = b64(spki).into();
        body["pop_stepup"] = b64(&k.sign(message.as_bytes())).into();
    }
    body[field] = value.into();
    let res = net
        .send(
            "POST",
            "/pair/claim",
            &[],
            serde_json::to_vec(&body).expect("serialisable"),
        )
        .await?;
    if res.status != 202 {
        return Err(refusal(&res, unix_now()));
    }
    let c: Claimed = parse(&res)?;
    let (Some(device_id), Some(core_spki), Some(pairing_id)) =
        (c.device_id, c.core_spki, c.pairing_id)
    else {
        return Err(Error::Protocol(
            "a claim answer without device_id, core_spki or pairing_id".into(),
        ));
    };
    let core_spki =
        unb64(&core_spki).ok_or_else(|| Error::Protocol("core_spki is not base64url".into()))?;
    // §7.2 step 4: the Core key that answered is the pinned one.
    if fp(&core_spki) != pinned {
        return Err(Error::Identity {
            pinned,
            served: fp(&core_spki),
        });
    }
    // The SAS shown is the one computed here, never the server's word for it.
    let mine = sas(&core_spki, &routine, &pairing_id);
    if c.sas.as_deref() != Some(mine.as_str()) {
        return Err(Error::Protocol(
            "the Core's SAS is not the one its key and ours make".into(),
        ));
    }
    let store = Keystore {
        device_id: device_id.clone(),
        core_fp: pinned,
        endpoint: endpoint.to_string(),
        host: p.host.clone(),
        key,
    };
    store.save(p.keystore).map_err(Error::Usage)?;
    let stepup_file = stepup::path_for(p.keystore);
    if let (Some(k), Some(pass)) = (&second, &sealing) {
        stepup::save(&stepup_file, k, pass, &device_id, &store.core_fp).map_err(|e| {
            let _ = std::fs::remove_file(p.keystore);
            Error::Usage(e)
        })?;
    }
    say(
        out,
        p.json,
        &format!("device {device_id}"),
        serde_json::json!({"device_id": device_id}),
    );
    say(
        out,
        p.json,
        &format!("sas {mine}"),
        serde_json::json!({"sas": mine}),
    );
    eprintln!("Check that the approving device shows this SAS, then approve it there.");
    let client = Client::new(net, store);
    let status = wait(&client, p.wait).await;
    match status.as_deref() {
        Ok("active") => {
            say(
                out,
                p.json,
                "status active",
                serde_json::json!({"status": "active"}),
            );
            Ok(())
        }
        Ok(other) => {
            let _ = std::fs::remove_file(p.keystore);
            let _ = std::fs::remove_file(&stepup_file);
            Err(Error::NotApproved(other.to_owned()))
        }
        Err(_) => status.map(drop),
    }
}

/// Polls `POST /pair/status` (signed, session `-`) until the device is no longer pending.
async fn wait(client: &Client, limit: Duration) -> Result<String, Error> {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        let res = client.sessionless("/pair/status", Vec::new()).await?;
        if res.status != 200 {
            return Err(refusal(&res, client.now()));
        }
        let s: serde_json::Value = parse(&res)?;
        match s["status"].as_str() {
            Some("pending") if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Some("pending") => return Ok("expired (waited too long)".into()),
            Some(other) => return Ok(other.to_owned()),
            None => return Err(Error::Protocol("a pairing status without a status".into())),
        }
    }
}
