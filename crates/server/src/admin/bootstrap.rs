//! The host's own ways to enrol a device (handshake spec §7.3, §12; E1-07.6, review H2):
//!
//! - `bootstrap`: the first device. Refused while a device is pending, active or locked, or
//!   was ever revoked; a claimant the host declined or let lapse does not count, so a failed
//!   bootstrap can be run again.
//! - `recover`: a new `admin` device whatever devices exist, when the admins are lost. It asks
//!   for the host name, audits `recover.started`, revokes every app device (and runner) only
//!   when told to, and enrols the new one as `device.enrolled`.
//!
//! Both create a pairing for every scope, print its code and the Core fingerprint, wait for the
//! claim (which the server accepts only over its own Unix socket, from this user), print the
//! claimant and the SAS, and approve on a `y` typed here; anything else rejects it. They run
//! as the database's owner only, beside a running `serve` (SQLite takes their writes between
//! its own; the claim goes to the running server), or with none running (the claim then waits
//! for one).

use std::io::{BufRead, Write};
use std::path::Path;
use std::time::Duration;

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::auth::pairing::show_code;
use ainkrad_core_server::scheduler::{Clock, SystemClock};
use ainkrad_core_server::store::{self, audit, gov};
use sqlx::SqlitePool;

use crate::Result_;

pub const USAGE: &str = "Devices (E1-07):
  ainkrad-core-server bootstrap <db> [<name>]
  ainkrad-core-server recover <db> [--revoke-all] [--revoke-runners] [<name>]
bootstrap pairs the first device, and only the first: it prints a one-time code, good for 5
minutes and only over the server's Unix socket (core.sock, or admin.sock beside a TCP or public
listener) from this user, then the claimant's SAS, and approves it when you type y. A declined
or lapsed attempt can be run again. recover does the same for a new admin device whatever
devices exist, after you type the host name; --revoke-all revokes every app device first,
--revoke-runners the runners too. Both run only as the database's owner (the service user).
For a remote Core, forward the socket over SSH as that user, e.g.
  ssh -L /tmp/core.sock:/var/lib/ainkrad/admin.sock ainkrad@host
and point the new device at the local end.";

/// The host's decisions are audited as the system, decided by `local-admin`.
const HOST: gov::Decider<'static> = gov::Decider {
    actor: AuditActor::System,
    device: None,
    scopes: None,
};

fn state_dir(db: &Path) -> &Path {
    db.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Refuses unless this process runs as the database file's owner: the host's verbs are for the
/// service user only, the same user the server's socket accepts claims from.
fn owner_only(db: &Path) -> Result_ {
    use std::os::unix::fs::MetadataExt;
    let owner = std::fs::metadata(db)
        .map_err(|e| format!("{}: {e}", db.display()))?
        .uid();
    // This process's uid, without libc: the owner of a file it creates.
    let probe = state_dir(db).join(format!(".uid-probe-{}", std::process::id()));
    std::fs::write(&probe, b"")?;
    let me = std::fs::metadata(&probe).map(|m| m.uid());
    let _ = std::fs::remove_file(&probe);
    if me? != owner {
        return Err(format!("{} belongs to another user: run as its owner", db.display()).into());
    }
    Ok(())
}

pub async fn bootstrap(db: &Path, name: &str) -> Result_ {
    let pool = store::connect(db).await?;
    owner_only(db)?;
    enrol(&pool, db, name, false).await
}

pub async fn recover(db: &Path, name: &str, revoke_all: bool, revoke_runners: bool) -> Result_ {
    let pool = store::connect(db).await?;
    owner_only(db)?;
    let host = std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "recover".to_owned());
    eprint!("This enrols a new admin device. Type the host name ({host}) to go on: ");
    let mut typed = String::new();
    std::io::stdin().lock().read_line(&mut typed)?;
    if typed.trim() != host {
        return Err("not confirmed: nothing changed".into());
    }
    let mut tx = store::begin_write(&pool).await?;
    let details = serde_json::json!({"by": "local-admin", "revoke_all": revoke_all,
        "revoke_runners": revoke_runners});
    let event = NewAuditEvent {
        actor: AuditActor::System,
        action: "recover.started".to_owned(),
        entity: None,
        details: details.to_string(),
    };
    audit::append(&mut tx, &event).await?;
    tx.commit().await?;
    let now = SystemClock.now();
    for d in gov::list_devices(&pool).await? {
        let revoke = match d.kind.as_str() {
            "runner" => revoke_runners,
            _ => revoke_all,
        };
        if revoke && d.revoked_at.is_none() {
            gov::revoke_device(&pool, &d.id, AuditActor::System, None, &now).await?;
            eprintln!("revoked {} ({})", d.id, d.name);
        }
    }
    enrol(&pool, db, name, true).await
}

/// Creates the host's pairing, waits for its claim, shows the SAS and approves on `y`.
async fn enrol(pool: &SqlitePool, db: &Path, name: &str, recovery: bool) -> Result_ {
    let identity = Identity::load_or_create(state_dir(db))?;
    let scopes: Vec<String> = gov::SCOPES.iter().map(|s| (*s).to_owned()).collect();
    let new = gov::NewPairing {
        kind: "device",
        name,
        scopes: &scopes,
        created_by: None,
        bootstrap: !recovery,
        recovery,
    };
    let created = gov::create_pairing(pool, &new, AuditActor::System, SystemClock.unix())
        .await
        .map_err(|e| match e {
            sqlx::Error::InvalidArgument(why) => format!("refused: {why}").into(),
            e => Box::<dyn std::error::Error>::from(e),
        })?;
    let mut out = std::io::stdout();
    writeln!(out, "code {}", show_code(&created.code))?;
    writeln!(out, "core_fp {}", identity.fp)?;
    out.flush()?;
    eprintln!("Claim it from the new device over the server's Unix socket within 5 minutes.");
    let claimed = loop {
        let p = gov::get_pairing(pool, &created.id)
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
    let device = gov::get_device(pool, claimed.device_id.as_deref().unwrap_or_default())
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
        gov::reject_pairing(pool, &claimed.id, HOST, now).await?;
        return Err("not approved: the attempt is rejected; run it again".into());
    }
    match gov::approve_pairing(pool, &claimed.id, &sas, None, HOST, now).await? {
        gov::Decision::Done => {
            writeln!(out, "approved {}", device.id)?;
            Ok(())
        }
        other => Err(format!("not approved: {other:?}").into()),
    }
}
