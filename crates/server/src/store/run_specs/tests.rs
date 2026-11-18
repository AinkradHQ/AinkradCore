use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use ainkrad_core::audit::AuditActor;
use serde_json::{Value, json};

use super::spec::{image_ref_problem, secret_refs, secret_refs_in};
use super::*;
use crate::store::connect;

const NOW: &str = "2026-11-17T10:00:00.000Z";
const W: Who<'static> = Who {
    by_device: "d_test",
    actor: AuditActor::System,
    now: NOW,
};

struct Fx {
    pool: SqlitePool,
    dir: PathBuf,
    project: i64,
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A database with an active project `shop` that has a repo `web`.
async fn fx() -> Fx {
    static N: AtomicUsize = AtomicUsize::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("core-spec-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    let p = projects::create(&pool, "shop", "Shop", "", "manual", W)
        .await
        .unwrap();
    projects::add_repo(
        &pool,
        p.id,
        "web",
        "https://github.com/acme/web.git",
        "main",
        false,
        W,
    )
    .await
    .unwrap();
    // The names `good()` refers to are secrets of the project.
    crate::store::project_secrets::fixtures::seed(&pool, p.id, &["db_password", "database_url"])
        .await;
    Fx {
        pool,
        dir,
        project: p.id,
    }
}

fn good() -> Value {
    json!({"services": {
        "db": {"image": "postgres:17", "env": {"POSTGRES_PASSWORD": "${secret:db_password}"},
               "volumes": {"data": "/var/lib/postgresql/data"}, "health": {"cmd": "pg_isready"}},
        "web": {"image": "node:22", "workdir": "/repo/web", "command": ["npm", "run", "dev"],
                "repo": "web", "ports": [{"port": 3000, "expose": true}],
                "depends_on": ["db"], "env": {"DATABASE_URL": "${secret:database_url}"}}}})
}

fn problem(r: Result<SpecVersion, Error>) -> String {
    match r {
        Err(Error::Refused { code, message }) => {
            assert_eq!(code, "invalid_spec", "{message}");
            message
        }
        Err(Error::Db(e)) => panic!("db error {e}"),
        Ok(_) => panic!("expected a refusal"),
    }
}

async fn save_manual(fx: &Fx, body: &Value) -> Result<SpecVersion, Error> {
    save(&fx.pool, fx.project, body, "manual", W).await
}

fn with(f: impl FnOnce(&mut Value)) -> Value {
    let mut v = good();
    f(&mut v);
    v
}

#[tokio::test]
async fn a_save_is_a_new_version_and_history_is_kept() {
    let fx = fx().await;
    assert!(matches!(
        latest(&fx.pool, fx.project).await,
        Err(Error::Refused {
            code: "not_found",
            ..
        })
    ));
    let v1 = save_manual(&fx, &good()).await.unwrap();
    assert_eq!((v1.version, v1.origin.as_str()), (1, "manual"));
    let two = with(|v| v["services"]["web"]["env"]["X"] = json!("1"));
    let v2 = save(&fx.pool, fx.project, &two, "compose", W)
        .await
        .unwrap();
    assert_eq!(v2.version, 2);
    assert_eq!(latest(&fx.pool, fx.project).await.unwrap(), v2);
    assert_eq!(version(&fx.pool, fx.project, 1).await.unwrap(), v1);
    let all = versions(&fx.pool, fx.project).await.unwrap();
    assert_eq!(
        all.iter()
            .map(|s| (s.version, s.origin.as_str()))
            .collect::<Vec<_>>(),
        [(2, "compose"), (1, "manual")]
    );
    assert!(matches!(
        version(&fx.pool, fx.project, 3).await,
        Err(Error::Refused {
            code: "not_found",
            ..
        })
    ));
    assert!(matches!(
        latest(&fx.pool, 999).await,
        Err(Error::Refused {
            code: "not_found",
            ..
        })
    ));
    // A bad origin is refused before anything is stored.
    let r = save(&fx.pool, fx.project, &good(), "bogus", W).await;
    assert!(matches!(
        r,
        Err(Error::Refused {
            code: "bad_request",
            ..
        })
    ));
    assert_eq!(versions(&fx.pool, fx.project).await.unwrap().len(), 2);
}

#[tokio::test]
async fn an_archived_project_takes_no_new_version() {
    let fx = fx().await;
    save_manual(&fx, &good()).await.unwrap();
    projects::archive(&fx.pool, fx.project, W).await.unwrap();
    let r = save_manual(&fx, &good()).await;
    assert!(matches!(
        r,
        Err(Error::Refused {
            code: "conflict",
            ..
        })
    ));
    assert_eq!(latest(&fx.pool, fx.project).await.unwrap().version, 1);
}

#[tokio::test]
async fn invalid_specs_are_refused_with_the_path_of_the_bad_field() {
    let fx = fx().await;
    let cases: Vec<(Value, &str)> = vec![
        // Forbidden keys cannot be expressed: the shape has no field for them.
        (
            with(|v| v["services"]["web"]["privileged"] = json!(true)),
            "privileged",
        ),
        (
            with(|v| v["services"]["web"]["network"] = json!("host")),
            "network",
        ),
        (
            with(|v| v["services"]["web"]["network_mode"] = json!("host")),
            "network_mode",
        ),
        (
            with(|v| v["services"]["web"]["cap_add"] = json!(["SYS_ADMIN"])),
            "cap_add",
        ),
        (
            with(|v| v["services"]["web"]["devices"] = json!(["/dev/sda"])),
            "devices",
        ),
        (with(|v| v["host_network"] = json!(true)), "host_network"),
        // A host path is not a volume name.
        (
            with(|v| v["services"]["db"]["volumes"] = json!({"/etc": "/data"})),
            "services.db.volumes./etc",
        ),
        (
            with(|v| v["services"]["db"]["volumes"] = json!({"../x": "/data"})),
            "services.db.volumes",
        ),
        (
            with(|v| v["services"]["db"]["volumes"] = json!({"data": "/repo/web"})),
            "services.db.volumes.data",
        ),
        (
            with(|v| v["services"]["db"]["volumes"] = json!({"data": "relative"})),
            "services.db.volumes.data",
        ),
        (
            with(|v| v["services"]["db"]["volumes"] = json!({"data": "/a/../b"})),
            "services.db.volumes.data",
        ),
        (
            with(|v| v["services"]["db"]["volumes"] = json!({"a": "/d", "b": "/d"})),
            "services.db.volumes",
        ),
        // Wrong types and shapes.
        (
            with(|v| v["services"]["web"]["ports"][0]["port"] = json!(70000)),
            "services.web.ports[0].port",
        ),
        (
            with(|v| v["services"]["web"]["ports"][0]["port"] = json!(0)),
            "services.web.ports[0].port",
        ),
        (json!({}), "services"),
        (json!({"services": {}}), "services"),
        (json!(5), "spec"),
        (
            with(|v| v["services"]["web"]["image"] = Value::Null),
            "services.web",
        ),
        (
            with(|v| v["services"]["web"]["build"] = json!({"repo": "web"})),
            "services.web",
        ),
        (
            with(|v| {
                v["services"]["web"]["image"] = Value::Null;
                v["services"]["web"]["build"] =
                    json!({"repo": "web", "dockerfile": "../Dockerfile"});
            }),
            "services.web.build.dockerfile",
        ),
        (
            with(|v| v["services"]["web"]["workdir"] = json!("src")),
            "services.web.workdir",
        ),
        (
            with(|v| v["services"]["web"]["workdir"] = json!("/a:/etc,ro")),
            "services.web.workdir",
        ),
        (
            with(|v| v["services"]["web"]["command"] = json!([])),
            "services.web.command",
        ),
        (
            with(|v| v["services"]["db"]["health"]["cmd"] = json!("a\nb")),
            "services.db.health.cmd",
        ),
        (
            with(|v| v["services"]["db"]["env"] = json!({"1BAD": "x"})),
            "services.db.env.1BAD",
        ),
        // Names and the graph.
        (
            with(|v| {
                let s = v["services"]
                    .as_object_mut()
                    .unwrap()
                    .remove("web")
                    .unwrap();
                v["services"]["Web_1"] = s;
            }),
            "services.Web_1",
        ),
        (
            with(|v| v["services"]["web"]["depends_on"] = json!(["nope"])),
            "services.web.depends_on[0]",
        ),
        (
            with(|v| v["services"]["web"]["depends_on"] = json!(["web"])),
            "services.web.depends_on[0]",
        ),
        (
            with(|v| v["services"]["db"]["depends_on"] = json!(["web"])),
            "depends_on",
        ),
        (
            with(|v| v["services"]["web"]["depends_on"] = json!(["db", "db"])),
            "services.web.depends_on[1]",
        ),
        // The project has no such repo.
        (
            with(|v| v["services"]["web"]["repo"] = json!("api")),
            "services.web.repo",
        ),
        // Exposure.
        (
            with(|v| {
                v["services"]["web"]["ports"] =
                    json!([{"port": 1, "expose": true}, {"port": 2, "expose": true}])
            }),
            "services.web.ports",
        ),
        (
            with(|v| v["services"]["web"]["ports"] = json!([{"port": 1}, {"port": 1}])),
            "services.web.ports[1].port",
        ),
    ];
    for (body, path) in cases {
        let msg = problem(save_manual(&fx, &body).await);
        assert!(msg.contains(path), "{path} not in {msg}");
    }
    assert!(versions(&fx.pool, fx.project).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_limits_are_16_services_and_8_ports() {
    let fx = fx().await;
    let svc = |n: usize| (format!("s{n}"), json!({"image": "redis:7"}));
    let many = |n: usize| json!({"services": (0..n).map(svc).collect::<serde_json::Map<_, _>>()});
    save_manual(&fx, &many(16)).await.unwrap();
    assert!(problem(save_manual(&fx, &many(17)).await).starts_with("services:"));
    let ports = |n: u16| {
        let ps: Vec<Value> = (1..=n).map(|p| json!({"port": p})).collect();
        json!({"services": {"a": {"image": "redis:7", "ports": ps}}})
    };
    save_manual(&fx, &ports(8)).await.unwrap();
    assert!(problem(save_manual(&fx, &ports(9)).await).starts_with("services.a.ports:"));
}

#[tokio::test]
async fn secret_references_are_syntax_checked_and_listed() {
    let fx = fx().await;
    for bad in [
        "${secret:}",
        "${secret:Bad}",
        "${secret:a",
        "${HOME}",
        "${secret:a}${oops}",
        "${secret:a b}",
    ] {
        let body = with(|v| v["services"]["db"]["env"]["K"] = json!(bad));
        let msg = problem(save_manual(&fx, &body).await);
        assert!(msg.contains("services.db.env.K"), "{bad}: {msg}");
    }
    // Plain values and a bare `$` are fine; several references in one value are all found.
    crate::store::project_secrets::fixtures::seed(&fx.pool, fx.project, &["a.b-c_1", "z"]).await;
    for ok in ["plain", "cost $5", "${secret:a.b-c_1}:${secret:z}"] {
        let body = with(|v| v["services"]["db"]["env"]["K"] = json!(ok));
        save_manual(&fx, &body).await.unwrap();
    }
    assert_eq!(
        secret_refs_in("${secret:a}-${secret:b}"),
        Ok(vec!["a", "b"])
    );
    let spec = super::spec::parse(&good()).unwrap();
    assert_eq!(
        secret_refs(&spec).into_iter().collect::<Vec<_>>(),
        ["database_url", "db_password"]
    );
}

#[tokio::test]
async fn a_reference_must_name_a_secret_of_the_project() {
    let fx = fx().await;
    let body = with(|v| v["services"]["db"]["env"]["K"] = json!("${secret:nope}"));
    let msg = problem(save_manual(&fx, &body).await);
    assert!(msg.contains("${secret:nope}"), "{msg}");
    // Another project's secret of the same name does not count.
    let other = projects::create(&fx.pool, "blog", "Blog", "", "manual", W)
        .await
        .unwrap();
    crate::store::project_secrets::fixtures::seed(&fx.pool, other.id, &["nope"]).await;
    assert!(problem(save_manual(&fx, &body).await).contains("${secret:nope}"));
}

#[test]
fn image_references_follow_the_distribution_grammar() {
    let digest = format!("sha256:{}", "a".repeat(64));
    for ok in [
        "postgres",
        "postgres:17",
        "node:22-alpine",
        "library/redis:7.2.1",
        "ghcr.io/acme/app:v1_2",
        "localhost:5000/team/app",
        "registry.example.com:5000/a/b-c.d__e:latest",
        &format!("ghcr.io/acme/app@{digest}"),
        &format!("app:1@{digest}"),
    ] {
        assert_eq!(image_ref_problem(ok), None, "{ok}");
    }
    for bad in [
        "",
        "--privileged",
        "-v",
        "a b",
        "a\nb",
        "Postgres:17",
        "postgres:",
        "postgres:-1",
        "postgres::17",
        "/abs/path",
        "a//b",
        "a/",
        "a..b",
        "a._b",
        "a-",
        "ghcr.io/",
        "host:port/app",
        "ghcr.io/acme/app@sha256:short",
        "ghcr.io/acme/app@md5:abc",
        &format!("a@{}", "SHA256:".to_owned() + &"a".repeat(64)),
        &"a".repeat(256),
        "é/app",
    ] {
        assert!(image_ref_problem(bad).is_some(), "{bad:?}");
    }
}

#[tokio::test]
async fn a_save_is_audited_and_emitted_in_the_same_transaction() {
    let fx = fx().await;
    let v = save_manual(&fx, &good()).await.unwrap();
    let got = crate::store::events::replay(&fx.pool, 0, 100)
        .await
        .unwrap()
        .unwrap();
    let e = got
        .iter()
        .find(|e| e.kind == "project.spec_saved")
        .expect("event");
    assert_eq!(e.payload.0["id"], fx.project);
    assert_eq!(e.payload.0["version"], v.version);
    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM audit_events WHERE entity_kind = 'project' AND action LIKE '%spec%'",
    )
    .fetch_all(&fx.pool)
    .await
    .unwrap();
    assert_eq!(actions, ["project.spec_saved"]);
    // A refused save leaves neither.
    let _ = save_manual(&fx, &json!({"services": {}})).await;
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM core_project_run_specs")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn the_stored_spec_is_normalised_and_the_table_checks_its_origin() {
    let fx = fx().await;
    save_manual(&fx, &good()).await.unwrap();
    let text: String = sqlx::query_scalar("SELECT spec FROM core_project_run_specs")
        .fetch_one(&fx.pool)
        .await
        .unwrap();
    assert!(text.starts_with(r#"{"services":{"db":"#), "{text}");
    let r =
        sqlx::query("INSERT INTO core_project_run_specs VALUES (?, 2, '{}', 'bogus', 'd', 'n')")
            .bind(fx.project)
            .execute(&fx.pool)
            .await;
    assert!(r.is_err(), "origin is a closed list");
    let r = sqlx::query(
        "INSERT INTO core_project_run_specs VALUES (?, 2, 'not json', 'manual', 'd', 'n')",
    )
    .bind(fx.project)
    .execute(&fx.pool)
    .await;
    assert!(r.is_err(), "spec must be JSON");
}

#[test]
fn the_json_schema_forbids_unknown_keys_everywhere() {
    let schema = serde_json::to_value(schemars::schema_for!(RunSpec)).unwrap();
    let text = schema.to_string();
    for forbidden in ["privileged", "network", "cap_add", "devices", "host_path"] {
        assert!(!text.contains(&format!("\"{forbidden}\"")), "{forbidden}");
    }
    assert_eq!(schema["additionalProperties"], json!(false));
    for name in ["Service", "Build", "Port", "Health"] {
        assert_eq!(
            schema["$defs"][name]["additionalProperties"],
            json!(false),
            "{name}"
        );
    }
}
