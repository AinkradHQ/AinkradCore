//! `runner-enroll-local <db> <out-dir> <url>`: the installer's way to a built-in runner (N8). It makes the
//! runner's key, enrols it as an active `runner` device (scope `runner` only, nothing else) through the same
//! store calls as a pairing (create, claim, approve, all audited as the system), and writes the runner's
//! `device.p8` and `enrolment.json` (both 0600) into `<out-dir>`, ready to be moved to the runner's state dir.
//! Like `pairing-invite` it runs as the database's owner and is only possible on the Core's own machine.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::crypto::{random_id, spki_of};
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{self, gov};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};

use super::bootstrap::owner_only;
use crate::cli::Result_;

const HOST: gov::Decider<'static> = gov::Decider {
    actor: AuditActor::System,
    device: None,
    scopes: None,
};

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

pub async fn enrol_local(db: &Path, out: &Path, url: &str) -> Result_ {
    if !url.starts_with("https://") || url.bytes().any(|b| !b.is_ascii_graphic()) {
        return Err("url is the Core's https:// address, as the runner dials it".into());
    }
    owner_only(db)?;
    let key = out.join("device.p8");
    if key.exists() {
        return Err(format!("{} exists: this runner is enrolled already", key.display()).into());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(out)?;
    let pool = store::connect(db).await?;
    let state = db
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let identity = Identity::load_or_create(
        state,
        &ainkrad_core_server::ops::secretbox::SecretBox::for_home(state)?,
    )?;
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
        .map_err(|_| "generating the runner key failed")?;
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .map_err(|_| "the runner key is not usable")?;
    let spki = spki_of(pair.public_key().as_ref());
    let device_id = random_id("d_");
    let scopes = vec!["runner".to_owned()];
    let now = SystemClock.unix();
    let created = gov::create_pairing(
        &pool,
        &gov::NewPairing {
            kind: "runner",
            name: "This Core (built-in)",
            scopes: &scopes,
            created_by: None,
            bootstrap: false,
            recovery: false,
            invite: false,
        },
        AuditActor::System,
        now,
    )
    .await?;
    let pairing = gov::get_pairing(&pool, &created.id)
        .await?
        .ok_or("the pairing is gone")?;
    let sas = gov::LOCAL_ENROL_SAS;
    let claim = gov::Claim {
        pairing: &pairing,
        device_id: &device_id,
        routine_spki: &spki,
        stepup_spki: None,
        platform: Some("linux"),
        key_storage: Some("software"),
        sas,
        device_name: None,
        passkey: None,
    };
    if !gov::claim_pairing(&pool, &claim, now).await? {
        return Err("the pairing was not claimable".into());
    }
    match gov::approve_pairing(&pool, &created.id, sas, None, HOST, now).await? {
        gov::Decision::Done => {}
        other => return Err(format!("not approved: {other:?}").into()),
    }
    let enrolment = serde_json::json!({
        "url": url, "device_id": device_id, "core_fp": identity.fp, "rotation_seq": 0, "next_fp": null,
    });
    write_new(&key, pkcs8.as_ref())?;
    write_new(
        &out.join("enrolment.json"),
        (serde_json::to_string_pretty(&enrolment)? + "\n").as_bytes(),
    )?;
    println!("{device_id}");
    eprintln!(
        "Runner device {device_id} enrolled (scope runner); key and enrolment are in {}.",
        out.display()
    );
    Ok(())
}
