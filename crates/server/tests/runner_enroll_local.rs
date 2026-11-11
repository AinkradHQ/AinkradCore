//! `runner-enroll-local` (N8): an active `runner` device with the runner scope only, its key and enrolment written
//! 0600, and a second run into the same directory refused.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use ainkrad_core_server::auth::Identity;
use ainkrad_core_server::store::{self, gov};

#[tokio::test]
async fn enrols_an_active_runner_with_only_the_runner_scope() {
    let dir = std::env::temp_dir().join(format!("core-enrol-local-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("keys")).unwrap();
    std::fs::write(dir.join("keys/master.key"), [7u8; 32]).unwrap();
    std::fs::set_permissions(
        dir.join("keys/master.key"),
        PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let db = dir.join("core.db");
    let pool = store::connect(&db).await.unwrap();
    let identity = Identity::load_or_create(
        &dir,
        &ainkrad_core_server::ops::secretbox::SecretBox::new(&[7; 32]),
    )
    .unwrap();
    let out = dir.join("runner-enrol");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
            .args([
                "runner-enroll-local",
                db.to_str().unwrap(),
                out.to_str().unwrap(),
                "https://core.example.com",
            ])
            .output()
            .unwrap()
    };
    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let id = String::from_utf8(first.stdout).unwrap().trim().to_owned();
    let d = gov::get_device(&pool, &id)
        .await
        .unwrap()
        .expect("the device exists");
    assert_eq!((d.kind.as_str(), d.status.as_str()), ("runner", "active"));
    assert_eq!(d.scopes, ["runner"]);
    let e: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("enrolment.json")).unwrap()).unwrap();
    assert_eq!(e["device_id"], id.as_str());
    assert_eq!(e["core_fp"], identity.fp.as_str());
    assert_eq!(e["url"], "https://core.example.com");
    for f in ["device.p8", "enrolment.json"] {
        let mode = std::fs::metadata(out.join(f)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{f}");
    }
    assert!(
        !run().status.success(),
        "a second run into the same directory is refused"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
