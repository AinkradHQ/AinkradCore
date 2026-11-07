//! Connections' credentials across the operator tools (C1): an export never carries one, a
//! backup does, master-key rotation moves them, and a restore counts their key ids.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use ainkrad_core::audit::AuditActor;
use ainkrad_core::settings::{Key, Scope};
use ainkrad_core_server::connections::adapter::{
    AuthMethodSpec, Capability, Descriptor, Identity as ConnIdentity, KindAdapter, Registry,
    TestError,
};
use ainkrad_core_server::connections::material::Material;
use ainkrad_core_server::ops::master_rotate::{Stop, rotate};
use ainkrad_core_server::ops::secretbox::SecretBox;
use ainkrad_core_server::store;
use ainkrad_core_server::store::connections::{self as conns, NewConnection, Who};
use futures_util::future::{BoxFuture, FutureExt};
use sqlx::SqlitePool;

const NOW: &str = "2026-11-06T10:00:00.000Z";

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn dir(name: &str) -> Dir {
    let d = std::env::temp_dir().join(format!("core-conn-ops-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    Dir(d)
}

fn run(args: &[&str], env: &[(&str, &str)]) -> Result<String, String> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"));
    cmd.args(args).env_remove("AINKRAD_CONFIG");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    match out.status.success() {
        true => Ok(String::from_utf8(out.stdout).unwrap().trim().to_owned()),
        false => Err(String::from_utf8(out.stderr).unwrap()),
    }
}

fn ok(args: &[&str], env: &[(&str, &str)]) -> String {
    run(args, env).unwrap_or_else(|e| panic!("{args:?}: {e}"))
}

/// The stderr of a command that must succeed (the purge lists what it removed there).
fn stderr_of(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_ainkrad-core-server"))
        .args(args)
        .env_remove("AINKRAD_CONFIG")
        .output()
        .unwrap();
    assert!(out.status.success(), "{args:?}");
    String::from_utf8(out.stderr).unwrap()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// A new home with the broker on (mode 1).
struct Home {
    root: PathBuf,
    fp: String,
    pool: SqlitePool,
}

impl Home {
    fn db(&self) -> PathBuf {
        self.root.join("core.db")
    }
    fn keys(&self) -> PathBuf {
        self.root.join("keys")
    }
    fn master(&self) -> SecretBox {
        SecretBox::from_private_file(&self.keys().join("master.key")).unwrap()
    }
}

async fn home(root: &Path) -> Home {
    let fp = ok(&["init", s(root)], &[]);
    let pool = store::connect(&root.join("core.db")).await.unwrap();
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
    Home {
        root: root.to_path_buf(),
        fp,
        pool,
    }
}

async fn go(h: &Home) -> Result<ainkrad_core_server::ops::master_rotate::Report, String> {
    rotate(&h.db(), &h.keys(), Stop::Never)
        .await
        .map_err(|e| e.to_string())
}

fn backup(h: &Home, recipient: &str) -> String {
    ok(
        &[
            "backup",
            "--config",
            s(&h.root.join("config.toml")),
            "--local-only",
        ],
        &[("AINKRAD_BACKUP_RECIPIENT", recipient)],
    )
}

static KIND: Descriptor = Descriptor {
    kind: "probe",
    title: "Probe",
    summary: "",
    auth_methods: &[AuthMethodSpec {
        id: "token",
        title: "Token",
        help: "",
        steps: &[],
        advanced: false,
    }],
    capabilities: &[Capability {
        name: "read_things",
        title: "Read",
        write: false,
        operations: &["probe.get"],
    }],
    hosts: &["api.probe.test"],
    limits: &[],
    token_shapes: &[],
    refresh_prefixes: &[],
    self_limited: &[],
    hourly_calls: 1000,
};

struct Probe;

impl KindAdapter for Probe {
    fn descriptor(&self) -> &Descriptor {
        &KIND
    }
    fn test<'a>(&'a self, _: &'a Material) -> BoxFuture<'a, Result<ConnIdentity, TestError>> {
        async { Err(TestError::Inconclusive) }.boxed()
    }
}

/// A connection whose credential is the only thing sealed in the home.
async fn only_a_connection(h: &Home) -> i64 {
    let mut reg = Registry::new();
    reg.register(Arc::new(Probe)).unwrap();
    let new = NewConnection {
        kind: "probe",
        name: "only",
        label: "Only one",
        auth_method: "token",
    };
    let who = Who {
        workspace: 1,
        by_device: "d_test",
        actor: AuditActor::System,
        now: NOW,
    };
    let m = Material::new(
        "conn-planted-value-77ab",
        Some("conn-planted-refresh-19cd"),
        None,
    )
    .unwrap();
    conns::create(&h.pool, &h.master(), &reg, &new, &m, who)
        .await
        .unwrap()
        .id
}

async fn conn_rows(pool: &SqlitePool) -> Vec<(String, Vec<u8>)> {
    sqlx::query_as("SELECT key_id, sealed FROM core_connection_secrets ORDER BY connection_id")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn rotating_with_only_a_connection_secret_moves_it_and_keeps_its_old_key() {
    let d = dir("conn-only");
    let h = home(&d.0.join("home")).await;
    only_a_connection(&h).await;
    let (old_id, before) = (h.master().key_id().to_owned(), conn_rows(&h.pool).await);
    assert_eq!(before[0].0, old_id);
    let r = go(&h).await.unwrap();
    assert_eq!((r.secrets, r.moved, r.resumed), (1, 1, false));
    let after = conn_rows(&h.pool).await;
    assert_eq!(after[0].0, h.master().key_id(), "under the new key");
    assert_ne!(after[0].1, before[0].1, "sealed afresh");
    // The old key is retired but not purged while a row still names it (here: forced back).
    sqlx::query("UPDATE core_connection_secrets SET key_id = ?")
        .bind(&old_id)
        .execute(&h.pool)
        .await
        .unwrap();
    let err = stderr_of(&[
        "secrets",
        "purge-retired-keys",
        s(&h.db()),
        "--older-than-days",
        "0",
    ]);
    assert!(!err.contains(&old_id), "{err}");
    assert!(
        h.keys()
            .join(format!("master.{old_id}.key.retired"))
            .exists(),
        "a key only a connection names is kept"
    );
    h.pool.close().await;
}

#[tokio::test]
async fn a_restore_refuses_when_only_a_connection_names_a_key_the_archive_lacks() {
    let d = dir("conn-lostkey");
    let h = home(&d.0.join("home")).await;
    only_a_connection(&h).await;
    let keygen = ok(&["backup-keygen"], &[]);
    let identity = d.0.join("identity.txt");
    std::fs::write(&identity, &keygen).unwrap();
    let recipient = keygen
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap()
        .to_owned();
    sqlx::query("UPDATE core_connection_secrets SET key_id = 'deadbeefdeadbeef'")
        .execute(&h.pool)
        .await
        .unwrap();
    let file = backup(&h, &recipient);
    h.pool.close().await;
    let to = d.0.join("restored");
    let e = run(
        &[
            "restore",
            &file,
            "--identity",
            s(&identity),
            "--signer",
            &h.fp,
            s(&to),
        ],
        &[],
    )
    .unwrap_err();
    assert!(
        e.contains("restore refused") && e.contains("deadbeefdeadbeef"),
        "{e}"
    );
    assert!(
        !to.join("core.db").exists(),
        "the half-built home is removed"
    );
}

/// A connection's credential is sealed under the master key, which an export carries in clear:
/// so an export carries neither it nor its ciphertext, and marks the connection as needing a new
/// credential. An encrypted backup keeps it.
#[tokio::test]
async fn an_export_never_carries_a_connection_credential_and_a_backup_does() {
    use ainkrad_core::audit::AuditActor;
    use ainkrad_core::settings::{Key, Scope};
    const TOKEN: &str = "conn-export-planted-token-5d2e";
    let d = dir("conn-export");
    let home = d.0.join("home");
    let fp = ok(&["init", s(&home)], &[]);
    let pool = store::connect(&home.join("core.db")).await.unwrap();
    let now = "2026-11-06T10:00:00.000Z";
    store::settings::set(
        &pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        now,
    )
    .await
    .unwrap();
    let sealer = SecretBox::from_file(&home.join("keys/master.key")).unwrap();
    let mut reg = Registry::new();
    reg.register(std::sync::Arc::new(Probe)).unwrap();
    let new = NewConnection {
        kind: "probe",
        name: "main",
        label: "Main",
        auth_method: "token",
    };
    let who = Who {
        workspace: 1,
        by_device: "d_test",
        actor: AuditActor::System,
        now,
    };
    let m = Material::new(TOKEN, None, None).unwrap();
    let c = conns::create(&pool, &sealer, &reg, &new, &m, who)
        .await
        .unwrap();
    let sealed: Vec<u8> = sqlx::query_scalar("SELECT sealed FROM core_connection_secrets")
        .fetch_one(&pool)
        .await
        .unwrap();
    pool.close().await;

    let config = home.join("config.toml");
    let file = d.0.join("core.export");
    ok(&["export", "--config", s(&config), s(&file)], &[]);
    let plain = std::fs::read(&file).unwrap();
    let has = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    assert!(!has(&plain, TOKEN.as_bytes()));
    assert!(
        !has(&plain, &sealed[13..45]),
        "a sealed credential in the export"
    );
    let imported = d.0.join("imported");
    ok(&["import", s(&file), "--signer", &fp, s(&imported)], &[]);
    let pool = store::connect(&imported.join("core.db")).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_connection_secrets")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    let got = conns::get(&pool, 1, c.id).await.unwrap();
    assert_eq!(
        (got.status.as_str(), got.state_reason.as_deref()),
        ("disabled", Some("exported")),
        "it needs a new credential"
    );
    assert_eq!(got.name, "main", "the row, its name and its label stay");
    // A new credential brings it back.
    let sealer = SecretBox::from_file(&imported.join("keys/master.key")).unwrap();
    store::settings::set(
        &pool,
        Key::SecretsMode,
        Scope::Server,
        "1",
        AuditActor::System,
        now,
    )
    .await
    .unwrap();
    let again = Material::new("conn-second-token-91af", None, None).unwrap();
    let back = conns::secret::replace(&pool, &sealer, c.id, &again, who)
        .await
        .unwrap();
    assert_eq!(back.status, "active");
    pool.close().await;

    let keygen = ok(&["backup-keygen"], &[]);
    let identity = d.0.join("identity.txt");
    std::fs::write(&identity, &keygen).unwrap();
    let recipient = keygen
        .lines()
        .find_map(|l| l.strip_prefix("# public key: "))
        .unwrap();
    let env = [("AINKRAD_BACKUP_RECIPIENT", recipient)];
    let backup = ok(&["backup", "--config", s(&config), "--local-only"], &env);
    let restored = d.0.join("restored");
    ok(
        &[
            "restore",
            &backup,
            "--identity",
            s(&identity),
            "--signer",
            &fp,
            s(&restored),
        ],
        &[],
    );
    let pool = store::connect(&restored.join("core.db")).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_connection_secrets")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1, "a backup keeps it");
    pool.close().await;
}

#[tokio::test]
async fn an_export_never_carries_the_oauth_apps_config() {
    use ainkrad_core_server::store::connections::apps;
    const SECRET: &str = "app-export-planted-secret-8e41";
    const PEM: &str = "app-export-planted-pem-line-3c9f";
    let d = dir("app-export");
    let home = d.0.join("home");
    let fp = ok(&["init", s(&home)], &[]);
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
    let who = Who {
        workspace: 1,
        by_device: "d_test",
        actor: AuditActor::System,
        now: NOW,
    };
    let fields: [(&str, Option<&str>); 3] = [
        ("client_id", Some("client-1")),
        ("client_secret", Some(SECRET)),
        ("loopback_port", Some("47613")),
    ];
    apps::set(&pool, &sealer, "jira", &fields, who)
        .await
        .unwrap();
    apps::set(&pool, &sealer, "github", &[("app_key", Some(PEM))], who)
        .await
        .unwrap();
    let sealed: Vec<u8> =
        sqlx::query_scalar("SELECT sealed FROM core_connection_apps WHERE field = 'client_secret'")
            .fetch_one(&pool)
            .await
            .unwrap();
    pool.close().await;
    let config = home.join("config.toml");
    let file = d.0.join("core.export");
    ok(&["export", "--config", s(&config), s(&file)], &[]);
    let plain = std::fs::read(&file).unwrap();
    let has = |needle: &[u8]| plain.windows(needle.len()).any(|w| w == needle);
    assert!(!has(SECRET.as_bytes()) && !has(PEM.as_bytes()));
    assert!(!has(&sealed[13..45]), "a sealed app field in the export");
    let imported = d.0.join("imported");
    ok(&["import", s(&file), "--signer", &fp, s(&imported)], &[]);
    let pool = store::connect(&imported.join("core.db")).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_connection_apps")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0, "the apps' config is entered again after an import");
}
