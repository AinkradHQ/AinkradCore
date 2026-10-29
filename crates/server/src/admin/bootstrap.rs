//! `bootstrap` (handshake spec §7.3, E1-07.6): the first device, from the host. Refused once any
//! device row exists, revoked ones included. It creates a pairing for every scope, prints its
//! code, waits for the claim (which the server takes only over its Unix socket, from this
//! user), prints the claimant and the SAS, and approves on an explicit `y` typed here.
//! Recovery once devices exist is `recover` (§12), not here.

use std::io::{BufRead, Write};
use std::path::Path;
use std::time::Duration;

use ainkrad_core::audit::AuditActor;
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::pairing::show_code;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{self, gov};

use crate::Result_;

pub const USAGE: &str = "Devices (E1-07):
  ainkrad-core-server bootstrap <db> [<name>]
bootstrap pairs the first device, and only the first: it prints a one-time code, good for 5
minutes and only over the server's Unix socket (core.sock, or admin.sock beside a TCP or public
listener) from this user, then the claimant's SAS, and approves it when you type y.";

/// The host's decisions are audited as the system, decided by `local-admin`.
const HOST: gov::Decider<'static> = gov::Decider {
    actor: AuditActor::System,
    device: None,
    scopes: None,
};

pub async fn run(db: &Path, name: &str) -> Result_ {
    let pool = store::connect(db).await?;
    let dir = db
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let identity = Identity::load_or_create(dir)?;
    let scopes: Vec<String> = gov::SCOPES.iter().map(|s| (*s).to_owned()).collect();
    let new = gov::NewPairing {
        kind: "device",
        name,
        scopes: &scopes,
        created_by: None,
        bootstrap: true,
    };
    let created = gov::create_pairing(&pool, &new, AuditActor::System, SystemClock.unix())
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => format!("bootstrap refused: {why}").into(),
            e => Box::<dyn std::error::Error>::from(e),
        })?;
    let mut out = std::io::stdout();
    writeln!(out, "code {}", show_code(&created.code))?;
    writeln!(out, "core_fp {}", identity.fp)?;
    out.flush()?;
    eprintln!("Claim it from the new device over the server's Unix socket within 5 minutes.");
    let claimed = loop {
        let p = gov::get_pairing(&pool, &created.id)
            .await?
            .ok_or("the pairing is gone")?;
        match p.status.as_str() {
            "live" if SystemClock.unix() < created.expires => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            "claimed" => break p,
            other => return Err(format!("the pairing ended unclaimed: {other}").into()),
        }
    };
    let device = gov::get_device(&pool, claimed.device_id.as_deref().unwrap_or_default())
        .await?
        .ok_or("the claimant is gone")?;
    let sas = claimed.sas.clone().unwrap_or_default();
    writeln!(
        out,
        "device {} fingerprint {}",
        device.id, device.fingerprint
    )?;
    writeln!(
        out,
        "platform {} key_storage {} (claimed)",
        device.platform.as_deref().unwrap_or("-"),
        device.key_storage.as_deref().unwrap_or("-")
    )?;
    writeln!(out, "sas {sas}")?;
    out.flush()?;
    eprint!("Does the new device show the same SAS? Type y to approve: ");
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    let now = SystemClock.unix();
    if answer.trim() != "y" {
        gov::reject_pairing(&pool, &claimed.id, HOST, now).await?;
        return Err("not approved: the pairing is rejected".into());
    }
    match gov::approve_pairing(&pool, &claimed.id, &sas, None, HOST, now).await? {
        gov::Decision::Done => {
            writeln!(out, "approved {}", device.id)?;
            Ok(())
        }
        other => Err(format!("not approved: {other:?}").into()),
    }
}
