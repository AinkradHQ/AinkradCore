//! API 112: a run in an environment (its project-level variables over the spec, a configuration's
//! own over those), permanent project delete (archived first, refused while running, a full
//! cascade) and `slug_locked`.

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::project_runs::{Fake, project, run, start, w};
use super::*;
use crate::runs::{self, StartOpts};
use crate::store::projects;

async fn call(fx: &Fx, m: Method, uri: &str, body: Value) -> (StatusCode, Value) {
    let body = (!body.is_null()).then_some(body);
    send(&fx.app, req(m, uri, Some(&fx.dev), body)).await
}

fn code(r: &(StatusCode, Value)) -> (StatusCode, &str) {
    (r.0, r.1["code"].as_str().unwrap_or(""))
}

async fn set(fx: &Fx, p: i64, env: &str, key: &str, value: &str) {
    let uri = format!("/api/v1/projects/{p}/run-envs/{env}/env/{key}");
    let r = call(fx, Method::PUT, &uri, json!({"value": value})).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
}

/// What the runner was told for the web service's environment in the last start.
fn web_env(link: &Fake) -> std::collections::BTreeMap<String, String> {
    let started = link.started.lock().unwrap();
    started.last().unwrap().spec.services["web"].env.clone()
}

async fn count(fx: &Fx, sql: &str) -> i64 {
    sqlx::query_scalar(sqlx::AssertSqlSafe(sql.to_owned()))
        .fetch_one(&fx.app.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_run_gets_its_environments_variables_and_a_configurations_win() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    let now = fx.app.clock.now();
    set(&fx, p, "Development", "MODE", "dev").await;
    set(&fx, p, "Staging", "MODE", "staging").await;
    set(&fx, p, "Staging", "ONLY_STAGING", "1").await;
    let go = |env: Option<&str>, config: Option<i64>| {
        let opts = StartOpts {
            config,
            environment: env.map(str::to_owned),
        };
        let (fx, link) = (&fx, &link);
        async move {
            let now = fx.app.clock.now();
            let pending = runs::begin_start_with(&fx.app, link, p, &opts, w(&now))
                .await
                .unwrap();
            let id = pending.run.id.clone();
            runs::drive_start(&fx.app, link, pending, crate::hub::Elevated::for_tests()).await;
            runs::stop(&fx.app, link, p, "user", w(&now)).await.unwrap();
            id
        }
    };
    // No environment named, no default: the first one.
    let id = go(None, None).await;
    assert_eq!(web_env(&link)["MODE"], "dev");
    assert_eq!(
        run(&fx, &id).await.environment.as_deref(),
        Some("Development")
    );
    // Named.
    let id = go(Some("Staging"), None).await;
    assert_eq!(web_env(&link)["ONLY_STAGING"], "1");
    assert_eq!(run(&fx, &id).await.environment.as_deref(), Some("Staging"));
    // The project's default environment.
    let r = call(
        &fx,
        Method::PATCH,
        &format!("/api/v1/projects/{p}"),
        json!({"default_environment": "Staging"}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    go(None, None).await;
    assert_eq!(web_env(&link)["MODE"], "staging");
    // A configuration's variable wins over the environment's.
    let c = call(
        &fx,
        Method::POST,
        &format!("/api/v1/projects/{p}/run-configs"),
        json!({"name": "api", "command": "npm start"}),
    )
    .await;
    let cid = c.1["id"].as_i64().unwrap();
    let uri = format!("/api/v1/projects/{p}/run-configs/{cid}/env/Staging/MODE");
    let r = call(&fx, Method::PUT, &uri, json!({"value": "config"})).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    go(None, Some(cid)).await;
    let env = web_env(&link);
    assert_eq!(
        (env["MODE"].as_str(), env["ONLY_STAGING"].as_str()),
        ("config", "1")
    );
    // An environment the project does not have.
    let bad = StartOpts {
        config: None,
        environment: Some("Nope".into()),
    };
    let e = runs::begin_start_with(&fx.app, &link, p, &bad, w(&now)).await;
    assert_eq!(super::project_runs::code(e.err().unwrap()), "not_found");
}

#[tokio::test]
async fn the_start_route_takes_an_optional_environment() {
    let fx = fx().await;
    let p = project(&fx, "shop").await;
    let uri = format!("/api/v1/projects/{p}/run/start");
    // No runner is online: the answer is the start's own refusal, not a body error; a body that
    // names no environment of the project is a 404 before that.
    let r = call(&fx, Method::POST, &uri, json!({"environment": "Nope"})).await;
    assert_eq!(code(&r), (StatusCode::NOT_FOUND, "not_found"), "{}", r.1);
    let r = call(&fx, Method::POST, &uri, Value::Null).await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "no_runner"), "{}", r.1);
    let r = call(&fx, Method::POST, &uri, json!({"environment": "Staging"})).await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "no_runner"), "{}", r.1);
}

#[tokio::test]
async fn environment_variables_never_show_a_value_follow_the_rules_and_go_with_their_environment() {
    let fx = fx().await;
    let p = project(&fx, "shop").await;
    set(&fx, p, "Staging", "KEY", "secret-looking-value").await;
    let base = format!("/api/v1/projects/{p}/run-envs");
    let list = call(
        &fx,
        Method::GET,
        &format!("{base}/Staging/env"),
        Value::Null,
    )
    .await;
    assert_eq!(list.0, StatusCode::OK);
    assert_eq!(list.1[0]["key"], "KEY");
    assert!(
        !list.1.to_string().contains("secret-looking-value"),
        "{}",
        list.1
    );
    let put = |body: Value, key: &'static str| {
        let uri = format!("{base}/Staging/env/{key}");
        let fx = &fx;
        async move { call(fx, Method::PUT, &uri, body).await }
    };
    assert_eq!(
        code(&put(json!({"value": "a${b}"}), "K").await).0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        code(&put(json!({"value": "x"}), "1bad").await).0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(code(&put(json!({}), "K").await).0, StatusCode::BAD_REQUEST);
    // A Secret link must be one of the project's.
    let r = put(json!({"secret": "missing"}), "K").await;
    assert!(r.0.is_client_error(), "{}", r.1);
    let r = call(&fx, Method::GET, &format!("{base}/Nope/env"), Value::Null).await;
    assert_eq!(r.0, StatusCode::NOT_FOUND);
    let r = call(
        &fx,
        Method::DELETE,
        &format!("{base}/Staging/env/KEY"),
        Value::Null,
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    let r = call(
        &fx,
        Method::DELETE,
        &format!("{base}/Staging/env/KEY"),
        Value::Null,
    )
    .await;
    assert_eq!(r.0, StatusCode::NOT_FOUND);
    set(&fx, p, "Staging", "KEY", "v").await;
    // Deleting the environment takes its variables.
    let r = call(&fx, Method::DELETE, &format!("{base}/Staging"), Value::Null).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(
        count(&fx, "SELECT count(*) FROM core_run_env_vars").await,
        0
    );
}

#[tokio::test]
async fn slug_locked_says_why_the_link_name_is_fixed() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    let uri = format!("/api/v1/projects/{p}");
    let get = || call(&fx, Method::GET, &uri, Value::Null);
    assert!(get().await.1["slug_locked"].is_null());
    start(&fx, &link, p).await.unwrap();
    assert_eq!(get().await.1["slug_locked"], "running");
    let now = fx.app.clock.now();
    runs::stop(&fx.app, &link, p, "user", w(&now))
        .await
        .unwrap();
    assert!(get().await.1["slug_locked"].is_null());
    seed_secret(&fx, p).await;
    assert_eq!(get().await.1["slug_locked"], "has_secrets");
    // The same two reasons are what PATCH refuses a new slug for.
    let r = call(&fx, Method::PATCH, &uri, json!({"slug": "shop2"})).await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "conflict"));
}

async fn seed_secret(fx: &Fx, p: i64) {
    let mut conn = fx.app.pool.acquire().await.unwrap();
    let group = projects::get(&mut conn, p).await.unwrap().secret_group;
    let group = group.expect("a project is made with its secret group");
    let now = fx.app.clock.now();
    sqlx::query(
        "INSERT INTO core_secrets (name, owner, delivery, version, key_id, sealed, size, \
         created_at, updated_at, group_id) \
         VALUES ('shop.api_key', ?, 'env', 1, '0123456789abcdef', x'00', 1, ?, ?, ?)",
    )
    .bind(&fx.dev.id)
    .bind(&now)
    .bind(&now)
    .bind(group)
    .execute(&fx.app.pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn a_project_is_deleted_only_when_archived_and_not_running() {
    let fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    let uri = format!("/api/v1/projects/{p}");
    // Not archived.
    let r = call(&fx, Method::DELETE, &uri, Value::Null).await;
    assert_eq!(code(&r), (StatusCode::CONFLICT, "not_archived"), "{}", r.1);
    // Running (even when archived).
    start(&fx, &link, p).await.unwrap();
    let r = call(&fx, Method::POST, &format!("{uri}/archive"), Value::Null).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    let r = call(&fx, Method::DELETE, &uri, Value::Null).await;
    assert_eq!(
        code(&r),
        (StatusCode::CONFLICT, "project_running"),
        "{}",
        r.1
    );
    // Unknown.
    let r = call(&fx, Method::DELETE, "/api/v1/projects/999", Value::Null).await;
    assert_eq!(r.0, StatusCode::NOT_FOUND);
    // Admin only.
    let phone = fx.enroll("phone", &["read"]).await;
    let r = send(&fx.app, req(Method::DELETE, &uri, Some(&phone), None)).await;
    assert_eq!(code(&r), (StatusCode::FORBIDDEN, "forbidden_scope"));
    let now = fx.app.clock.now();
    runs::stop(&fx.app, &link, p, "user", w(&now))
        .await
        .unwrap();
    let r = call(&fx, Method::DELETE, &uri, Value::Null).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    let r = call(&fx, Method::GET, &uri, Value::Null).await;
    assert_eq!(r.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn deleting_a_project_removes_everything_tied_to_it_and_nothing_else() {
    let mut fx = fx().await;
    let (link, p) = (Fake::new(), project(&fx, "shop").await);
    let keep = project(&fx, "keep").await;
    let base = format!("/api/v1/projects/{p}");
    // Two repos, each with a mirror folder on disk.
    let mut repo_ids = Vec::new();
    for name in ["web", "api"] {
        let b = json!({"name": name, "default_branch": "main",
                       "remote_url": format!("https://github.com/acme/{name}.git")});
        let r = call(&fx, Method::POST, &format!("{base}/repos"), b).await;
        assert_eq!(r.0, StatusCode::OK, "{}", r.1);
        repo_ids = r.1["repos"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["id"].as_i64().unwrap())
            .collect();
    }
    let root = std::env::temp_dir().join(format!("core-mirrors-{}-{p}", std::process::id()));
    let mirrors = Arc::new(crate::mirrors::Mirrors::new(root.clone()));
    for r in &repo_ids {
        std::fs::create_dir_all(mirrors.dir(*r).join("objects")).unwrap();
    }
    fx.app.mirrors = Some(mirrors);
    // Configurations, variables, a finished run, secrets, rules, history, caches, a job, a session.
    set(&fx, p, "Staging", "A", "1").await;
    let c = call(
        &fx,
        Method::POST,
        &format!("{base}/run-configs"),
        json!({"name": "api", "command": "x"}),
    )
    .await;
    let cid = c.1["id"].as_i64().unwrap();
    let r = call(
        &fx,
        Method::PUT,
        &format!("{base}/run-configs/{cid}/env/Staging/B"),
        json!({"value": "2"}),
    )
    .await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    start(&fx, &link, p).await.unwrap();
    let now = fx.app.clock.now();
    runs::stop(&fx.app, &link, p, "user", w(&now))
        .await
        .unwrap();
    seed_secret(&fx, p).await;
    let dev = &fx.dev.id;
    let pool = &fx.app.pool;
    let q = "INSERT INTO core_approval_rules (project_id, tool, pattern, created_by, created_at) \
             VALUES (?, 'Bash', 'ls', ?, ?)";
    sqlx::query(q)
        .bind(p)
        .bind(dev)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
    let q = "INSERT INTO core_cmd_history (project_id, cmd_key, runs, p50_ms, last_ms, updated_at) \
             VALUES (?, 'cargo test', 1, 1, 1, ?)";
    sqlx::query(q)
        .bind(p)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
    let q = "INSERT INTO core_hw_cache (device_id, project_id, tree_hash, synced_at) \
             VALUES (?, ?, zeroblob(32), ?)";
    sqlx::query(q)
        .bind(dev)
        .bind(p)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
    let q = "INSERT INTO core_hw_jobs (id, project_id, run_config_id, argv, device_id, place_reason, \
             tier, state, created_at) VALUES ('j_done', ?, ?, '[\"x\"]', ?, 'core', 'rule', 'ended', ?)";
    sqlx::query(q)
        .bind(p)
        .bind(cid)
        .bind(dev)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();
    let q = "INSERT INTO core_agent_sessions (id, runner, harness, policy, secrets, state, \
             created_by, created_at, updated_at, project_id) \
             VALUES ('as_keep', ?, 'claude', '{}', '[]', 'ended', ?, ?, ?, ?)";
    sqlx::query(q)
        .bind(dev)
        .bind(dev)
        .bind(&now)
        .bind(&now)
        .bind(p)
        .execute(pool)
        .await
        .unwrap();
    // A bystander project keeps its own rows.
    set(&fx, keep, "Staging", "A", "1").await;
    let r = call(&fx, Method::POST, &format!("{base}/archive"), Value::Null).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);

    let r = call(&fx, Method::DELETE, &base, Value::Null).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(r.1["deleted"], true);
    for (table, col) in [
        ("core_project_repos", "project_id"),
        ("core_project_run_specs", "project_id"),
        ("core_project_runs", "project_id"),
        ("core_run_configs", "project_id"),
        ("core_run_envs", "project_id"),
        ("core_run_env_vars", "project_id"),
        ("core_approval_rules", "project_id"),
        ("core_cmd_history", "project_id"),
        ("core_hw_cache", "project_id"),
        ("core_hw_jobs", "project_id"),
    ] {
        let n = count(
            &fx,
            &format!("SELECT count(*) FROM {table} WHERE {col} = {p}"),
        )
        .await;
        assert_eq!(n, 0, "{table}");
    }
    assert_eq!(count(&fx, "SELECT count(*) FROM core_run_vars").await, 0);
    assert_eq!(
        count(&fx, "SELECT count(*) FROM core_project_mirrors").await,
        0
    );
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM core_secrets WHERE name = 'shop.api_key'"
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM core_secret_groups WHERE name LIKE '%shop'"
        )
        .await,
        0
    );
    for r in &repo_ids {
        assert!(!root.join(format!("{r}.git")).exists(), "mirror folder {r}");
    }
    // The session stays, untied.
    let tied: Option<i64> =
        sqlx::query_scalar("SELECT project_id FROM core_agent_sessions WHERE id = 'as_keep'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(tied, None);
    // Audited, and emitted.
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM audit_events WHERE action = 'project.deleted'"
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &fx,
            "SELECT count(*) FROM events WHERE kind = 'project.deleted'"
        )
        .await,
        1
    );
    // The other project is untouched.
    assert_eq!(
        count(
            &fx,
            &format!("SELECT count(*) FROM core_run_env_vars WHERE project_id = {keep}")
        )
        .await,
        1
    );
    let r = call(
        &fx,
        Method::GET,
        &format!("/api/v1/projects/{keep}"),
        Value::Null,
    )
    .await;
    assert_eq!(r.0, StatusCode::OK);
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test]
async fn a_chosen_room_is_checked_before_anything_is_made_and_rides_the_created_event() {
    let fx = fx().await;
    let create = |slug: &str, room: &str| {
        let body = json!({"slug": slug, "name": slug, "room": room});
        call(&fx, Method::POST, "/api/v1/projects", body)
    };
    // No Brain, no rooms.
    assert_eq!(
        code(&create("aa", "r1").await),
        (StatusCode::BAD_REQUEST, "bad_request")
    );
    // The Brain's tables, as its migrations make them.
    for sql in [
        "CREATE TABLE brain_rooms (id TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '')",
        "CREATE TABLE brain_project_rooms (project TEXT PRIMARY KEY, room TEXT NOT NULL UNIQUE)",
        "INSERT INTO brain_rooms (id) VALUES ('r1'), ('r2')",
        "INSERT INTO brain_project_rooms (project, room) VALUES ('99', 'r2')",
    ] {
        sqlx::query(sql).execute(&fx.app.pool).await.unwrap();
    }
    assert_eq!(
        code(&create("bb", "nope").await),
        (StatusCode::NOT_FOUND, "not_found")
    );
    assert_eq!(
        code(&create("cc", "r2").await),
        (StatusCode::CONFLICT, "room_linked")
    );
    assert_eq!(
        count(&fx, "SELECT count(*) FROM core_projects").await,
        0,
        "nothing was made"
    );
    let r = create("dd", "r1").await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    let payload: String =
        sqlx::query_scalar("SELECT payload FROM events WHERE kind = 'project.created'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert!(payload.contains("\"room\":\"r1\""), "{payload}");
}

#[tokio::test]
async fn a_project_can_be_several_kinds_and_kind_stays_the_first() {
    let fx = fx().await;
    let mk = |slug: &str, body: Value| {
        let mut b = json!({"slug": slug, "name": slug});
        b.as_object_mut()
            .unwrap()
            .extend(body.as_object().unwrap().clone());
        call(&fx, Method::POST, "/api/v1/projects", b)
    };
    for bad in [
        json!({"kinds": []}),
        json!({"kinds": ["web", "web"]}),
        json!({"kinds": ["other", "web"]}),
        json!({"kinds": ["nope"]}),
        json!({"kinds": ["app", "web"], "kind": "web"}),
    ] {
        assert_eq!(
            code(&mk("bad", bad.clone()).await),
            (StatusCode::BAD_REQUEST, "bad_kind"),
            "{bad}"
        );
    }
    assert_eq!(count(&fx, "SELECT count(*) FROM core_projects").await, 0);
    let r = mk("aa", json!({"kinds": ["app", "web"]})).await;
    assert_eq!(r.0, StatusCode::OK, "{}", r.1);
    assert_eq!(
        (&r.1["kind"], &r.1["kinds"]),
        (&json!("app"), &json!(["app", "web"]))
    );
    // `kind` alone is `[kind]`; neither is the default web.
    let r = mk("bb", json!({"kind": "infra"})).await;
    assert_eq!(r.1["kinds"], json!(["infra"]));
    let r = mk("cc", json!({})).await;
    assert_eq!(
        (&r.1["kind"], &r.1["kinds"]),
        (&json!("web"), &json!(["web"]))
    );
    // PATCH: kinds, then kind alone resets them to it.
    let id = r.1["id"].as_i64().unwrap();
    let uri = format!("/api/v1/projects/{id}");
    let r = call(&fx, Method::PATCH, &uri, json!({"kinds": ["infra", "app"]})).await;
    assert_eq!(
        (&r.1["kind"], &r.1["kinds"]),
        (&json!("infra"), &json!(["infra", "app"]))
    );
    let r = call(&fx, Method::PATCH, &uri, json!({"name": "x"})).await;
    assert_eq!(r.1["kinds"], json!(["infra", "app"]), "untouched");
    let r = call(&fx, Method::PATCH, &uri, json!({"kind": "other"})).await;
    assert_eq!(
        (&r.1["kind"], &r.1["kinds"]),
        (&json!("other"), &json!(["other"]))
    );
    let r = call(
        &fx,
        Method::PATCH,
        &uri,
        json!({"kinds": ["web"], "kind": "app"}),
    )
    .await;
    assert_eq!(code(&r), (StatusCode::BAD_REQUEST, "bad_kind"));
}

/// The migration gives every existing project `kinds = [kind]`.
#[tokio::test]
async fn the_kinds_migration_copies_each_projects_kind() {
    let fx = fx().await;
    let p = project(&fx, "old").await;
    sqlx::query("UPDATE core_projects SET kind = 'app', kinds = 'web' WHERE id = ?")
        .bind(p)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let up = include_str!("../../../../migrations/0071_project_kinds.up.sql");
    let copy = up.lines().find(|l| l.starts_with("UPDATE")).unwrap();
    sqlx::query(copy).execute(&fx.app.pool).await.unwrap();
    let kinds: String = sqlx::query_scalar("SELECT kinds FROM core_projects WHERE id = ?")
        .bind(p)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(kinds, "app");
}
