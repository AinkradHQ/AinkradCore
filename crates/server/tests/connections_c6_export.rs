//! C6: the export archive of a Core that holds GitHub and Jira connections with every kind of
//! secret (access, refresh, app client secret, PEM key) carries none of them, in any form, and
//! not their sealed bytes either; what it keeps is rows that need a new credential.

use std::path::{Path, PathBuf};
use std::process::Command;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::connections::adapter::Registry;
use ainkrad_core_server::connections::material::Material;
use ainkrad_core_server::ops::secretbox::SecretBox;
use ainkrad_core_server::store;
use ainkrad_core_server::store::connections::{self as conns, NewConnection, Who, apps};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

const NOW: &str = "2026-11-06T10:00:00.000Z";
const GH: &str = "c6x-gh-access-7f3a9d41e0b2";
const JIRA_ACCESS: &str = "c6x-jira-access-2e9d41f7a3b0";
const JIRA_REFRESH: &str = "c6x-jira-refresh-8a1f3c5d7e92";
const CLIENT_SECRET: &str = "c6x-client-secret-3b9f6e2d1a70";
const PEM_LINE: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCc6x";

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Stdout and stderr of a command that must succeed.
fn run(args: &[&str]) -> (String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(args)
        .env_remove("AINKRAD_CONFIG")
        .output()
        .unwrap();
    let (o, e) = (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    );
    assert!(out.status.success(), "{args:?}: {e}");
    (o, e)
}

fn ok(args: &[&str]) -> String {
    run(args).0
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn who() -> Who<'static> {
    Who {
        workspace: 1,
        by_device: "d_test",
        actor: AuditActor::System,
        now: NOW,
    }
}

fn forms(secret: &str) -> Vec<String> {
    vec![
        secret.to_owned(),
        STANDARD.encode(secret),
        URL_SAFE_NO_PAD.encode(secret),
        format!("Bearer {secret}"),
    ]
}

#[tokio::test]
async fn an_export_of_github_and_jira_connections_and_their_apps_carries_no_secret_in_any_form() {
    let d = Dir(std::env::temp_dir().join(format!("core-c6-export-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&d.0);
    std::fs::create_dir_all(&d.0).unwrap();
    let home = d.0.join("home");
    let fp = ok(&["init", s(&home)]).trim().to_owned();
    let pool = store::connect(&home.join("core.db")).await.unwrap();
    store::settings::set(
        &pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    let sealer = SecretBox::from_file(&home.join("keys/master.key")).unwrap();
    let reg = Registry::builtin();
    let mut ids = Vec::new();
    for (kind, name, auth, m) in [
        (
            "github",
            "main",
            "token",
            Material::new(GH, None, None).unwrap(),
        ),
        (
            "jira",
            "acme",
            "oauth",
            Material::new(
                JIRA_ACCESS,
                Some(JIRA_REFRESH),
                Some("2026-11-06T11:00:00Z"),
            )
            .unwrap(),
        ),
    ] {
        let new = NewConnection {
            kind,
            name,
            label: "A connection",
            auth_method: auth,
        };
        ids.push(
            conns::create(&pool, &sealer, &reg, &new, &m, who())
                .await
                .unwrap()
                .id,
        );
    }
    let fields: [(&str, Option<&str>); 2] = [
        ("client_id", Some("client-1")),
        ("client_secret", Some(CLIENT_SECRET)),
    ];
    apps::set(&pool, &sealer, "jira", &fields, who())
        .await
        .unwrap();
    apps::set(
        &pool,
        &sealer,
        "github",
        &[("app_key", Some(PEM_LINE))],
        who(),
    )
    .await
    .unwrap();
    // The sealed bytes of each secret, to prove they are gone too.
    let mut sealed: Vec<Vec<u8>> = sqlx::query_scalar("SELECT sealed FROM core_connection_secrets")
        .fetch_all(&pool)
        .await
        .unwrap();
    sealed.extend(
        sqlx::query_scalar::<_, Vec<u8>>("SELECT sealed FROM core_connection_apps")
            .fetch_all(&pool)
            .await
            .unwrap(),
    );
    assert!(sealed.len() >= 4);
    pool.close().await;

    let config = home.join("config.toml");
    let file = d.0.join("core.export");
    let said = run(&["export", "--config", s(&config), s(&file)]).1;
    let bytes = std::fs::read(&file).unwrap();
    let has = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    for secret in [GH, JIRA_ACCESS, JIRA_REFRESH, CLIENT_SECRET, PEM_LINE] {
        for form in forms(secret) {
            assert!(
                !has(&bytes, form.as_bytes()),
                "{form} is in the export archive"
            );
            assert!(!said.contains(&form), "{form} is in what `export` printed");
        }
    }
    for blob in &sealed {
        assert!(
            !has(&bytes, &blob[13..]),
            "a sealed secret is in the export archive"
        );
    }
    // What is left needs a new credential.
    let imported = d.0.join("imported");
    ok(&["import", s(&file), "--signer", &fp, s(&imported)]);
    let pool = store::connect(&imported.join("core.db")).await.unwrap();
    store::settings::set(
        &pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        NOW,
    )
    .await
    .unwrap();
    for id in ids {
        let c = conns::get(&pool, 1, id).await.unwrap();
        assert_eq!(
            (c.status.as_str(), c.state_reason.as_deref()),
            ("disabled", Some("exported")),
            "{}",
            c.name
        );
    }
    let left: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM core_connection_secrets) + (SELECT count(*) FROM core_connection_apps)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(left, 0);
    pool.close().await;
}
