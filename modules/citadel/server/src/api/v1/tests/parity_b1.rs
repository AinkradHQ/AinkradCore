//! API minor 18, the prototype-parity additions: issue fields and edits, issue activity, epic
//! fields, project fields, charts, repo probes and requirement controls.

use citadel_core::work::ProjectMode;
use serde_json::json;

use super::*;

impl Fx {
    async fn patch(&self, uri: &str, body: Value) -> (StatusCode, Value) {
        send(
            &self.app,
            req(Method::PATCH, uri, Some(&self.key), Some(body)),
        )
        .await
    }

    async fn ok_patch(&self, uri: &str, body: Value) -> Value {
        let (status, got) = self.patch(uri, body).await;
        assert_eq!(status, StatusCode::OK, "PATCH {uri}: {got}");
        got
    }
}

async fn audit_actions(pool: &SqlitePool) -> Vec<String> {
    sqlx::query_scalar("SELECT action FROM audit_events ORDER BY seq")
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn an_issue_takes_a_priority_level_criteria_and_new_kinds_by_patch() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/issues/{}", a.issue.0);
    let before = fx.ok(&uri).await;
    assert_eq!(before["priority_level"], "none");
    assert_eq!(before["criteria"], json!([]));

    let got = fx
        .ok_patch(
            &uri,
            json!({"title": " Renamed ", "body": "New body", "kind": "spike",
                   "priority_level": "urgent",
                   "criteria": [{"text": "It works", "done": true}, {"text": "It is fast"}]}),
        )
        .await;
    assert_eq!(got["title"], "Renamed");
    assert_eq!(got["kind"], "spike");
    assert_eq!(got["priority_level"], "urgent");
    assert_eq!(got["priority"], true, "the bool follows from high up");
    assert_eq!(
        got["criteria"],
        json!([{"text": "It works", "done": true}, {"text": "It is fast", "done": false}])
    );
    assert_eq!(fx.ok(&uri).await, got, "it is stored");

    // Medium is below `high`; the bool follows it down. The bump sets `high`, and clears to none.
    let got = fx.ok_patch(&uri, json!({"priority_level": "medium"})).await;
    assert_eq!(
        (got["priority"].clone(), got["kind"].clone()),
        (json!(false), json!("spike"))
    );
    let bumped = fx
        .ok_post(&format!("{uri}/priority"), json!({"priority": true}))
        .await;
    assert_eq!(
        (bumped["priority"].clone(), bumped["priority_level"].clone()),
        (json!(true), json!("high"))
    );
    let cleared = fx
        .ok_post(&format!("{uri}/priority"), json!({"priority": false}))
        .await;
    assert_eq!(cleared["priority_level"], "none");

    // Chore too; nothing changes, nothing is audited; refusals are 400s.
    fx.ok_patch(&uri, json!({"kind": "chore"})).await;
    let n = audit_actions(&fx.app.pool).await.len();
    fx.ok_patch(&uri, json!({"kind": "chore", "title": "Renamed"}))
        .await;
    assert_eq!(audit_actions(&fx.app.pool).await.len(), n);
    for bad in [
        json!({"title": "  "}),
        json!({"kind": "subtask"}),
        json!({"criteria": [{"text": ""}]}),
    ] {
        let (status, body) = fx.patch(&uri, bad.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    let (status, _) = fx.patch("/api/v1/issues/999", json!({"title": "x"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let updated = audit_actions(&fx.app.pool)
        .await
        .into_iter()
        .filter(|a| a == "issue.updated")
        .count();
    assert_eq!(updated, 3, "one audit row per change");
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_events WHERE action = 'issue.updated' ORDER BY seq LIMIT 1",
    )
    .fetch_one(&fx.app.pool)
    .await
    .unwrap();
    let details: Value = serde_json::from_str(&details).unwrap();
    assert_eq!(details["kind"], json!({"from": "task", "to": "spike"}));
    assert_eq!(
        details["fields"],
        json!(["title", "body", "kind", "priority_level", "criteria"])
    );
}

#[tokio::test]
async fn a_subtask_keeps_its_kind() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    sqlx::query(
        "INSERT INTO issues (project_id, number, parent_id, kind, title, state, next_user_id, rank) \
         VALUES (?, 50, ?, 'subtask', 'Sub', 'todo', 1, 99)",
    )
    .bind(a.project.0)
    .bind(a.issue.0)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let id: i64 = sqlx::query_scalar("SELECT id FROM issues WHERE number = 50")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    let (status, _) = fx
        .patch(&format!("/api/v1/issues/{id}"), json!({"kind": "task"}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The kind list is edited in place by the migration: every connection of the pool, the one that
/// migrated included, must see the new list, and the migration must undo and redo.
#[tokio::test]
async fn every_connection_accepts_the_new_kinds_and_the_migration_undoes() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let mut conns = vec![];
    for _ in 0..4 {
        conns.push(fx.app.pool.acquire().await.unwrap());
    }
    for (n, conn) in conns.iter_mut().enumerate() {
        let sql = "INSERT INTO issues (project_id, number, kind, title, state, next_user_id, rank) \
                   VALUES (?, ?, ?, 'x', 'todo', 1, 1)";
        for kind in ["chore", "spike"] {
            let r = sqlx::query(sql)
                .bind(a.project.0)
                .bind(100 + n as i64)
                .bind(kind)
                .execute(&mut **conn)
                .await;
            assert!(r.is_ok(), "connection {n} refuses {kind}: {r:?}");
            sqlx::query("DELETE FROM issues WHERE number = ?")
                .bind(100 + n as i64)
                .execute(&mut **conn)
                .await
                .unwrap();
        }
    }
    drop(conns);
    // Down puts chores back to tasks and the old list back; up again accepts them.
    let to = crate::store::MIGRATOR
        .iter()
        .map(|m| m.version)
        .filter(|v| *v < 20261120001000)
        .max()
        .unwrap();
    sqlx::query("UPDATE issues SET kind = 'chore' WHERE id = ?")
        .bind(a.issue.0)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    crate::store::MIGRATOR.undo(&fx.app.pool, to).await.unwrap();
    let kind: String = sqlx::query_scalar("SELECT kind FROM issues WHERE id = ?")
        .bind(a.issue.0)
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(kind, "task");
    let r = sqlx::query("UPDATE issues SET kind = 'spike' WHERE id = ?")
        .bind(a.issue.0)
        .execute(&fx.app.pool)
        .await;
    assert!(r.is_err(), "the old list is back");
    crate::store::MIGRATOR.run(&fx.app.pool).await.unwrap();
    sqlx::query("UPDATE issues SET kind = 'spike' WHERE id = ?")
        .bind(a.issue.0)
        .execute(&fx.app.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn an_issues_activity_is_its_audit_trail_newest_first_and_pages() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/issues/{}", a.issue.0);
    fx.ok_patch(&uri, json!({"title": "One"})).await;
    fx.ok_post(&format!("{uri}/estimate"), json!({"points": 3}))
        .await;
    fx.ok_patch(&uri, json!({"title": "Two"})).await;
    fx.ok_patch(
        &format!("/api/v1/issues/{}", b.issue.0),
        json!({"title": "Other"}),
    )
    .await;

    let page = fx.ok(&format!("{uri}/activity")).await;
    let actions: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        &actions[..3],
        ["issue.updated", "issue.estimated", "issue.updated"]
    );
    assert!(actions.iter().all(|a| a.starts_with("issue.")));
    assert!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["entity_id"] == json!(a.issue.0))
    );
    assert_eq!(page["next_before"], Value::Null);

    let first = fx.ok(&format!("{uri}/activity?limit=2")).await;
    assert_eq!(first["items"].as_array().unwrap().len(), 2);
    let cursor = first["next_before"].as_i64().expect("more rows");
    let rest = fx
        .ok(&format!("{uri}/activity?limit=2&before={cursor}"))
        .await;
    assert!(rest["items"][0]["seq"].as_i64().unwrap() < cursor);
    let (status, _) = fx.get("/api/v1/issues/999/activity").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_epic_takes_a_colour_dates_and_a_requirement_by_patch() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let epic = fx
        .ok_post(
            &format!("/api/v1/projects/{}/epics", a.project.0),
            json!({"title": "Launch"}),
        )
        .await;
    assert_eq!(epic["color"], Value::Null);
    let uri = format!("/api/v1/epics/{}", epic["id"]);
    let req_a = fx
        .ok_post(
            &format!("/api/v1/companies/{}/requests", a.company.0),
            json!({"title": "Ship it", "body": "Please"}),
        )
        .await;
    let rid = req_a["requirement_id"]
        .as_i64()
        .or(req_a["id"].as_i64())
        .expect("a requirement");

    let got = fx
        .ok_patch(
            &uri,
            json!({"color": "#12ab34", "starts_on": "2026-11-01", "ends_on": "2026-11-30",
                   "requirement_id": rid, "status": "in_progress", "title": "Launch 2"}),
        )
        .await;
    assert_eq!(got["color"], "#12ab34");
    assert_eq!(
        (got["starts_on"].clone(), got["ends_on"].clone()),
        (json!("2026-11-01"), json!("2026-11-30"))
    );
    assert_eq!(got["requirement_id"], rid);
    assert_eq!(
        (got["status"].clone(), got["title"].clone()),
        (json!("in_progress"), json!("Launch 2"))
    );
    let listed = fx
        .ok(&format!("/api/v1/projects/{}/epics", a.project.0))
        .await;
    assert_eq!(listed[0], got);

    // Absent keeps, null clears.
    let got = fx
        .ok_patch(&uri, json!({"color": null, "requirement_id": null}))
        .await;
    assert_eq!(
        (got["color"].clone(), got["requirement_id"].clone()),
        (Value::Null, Value::Null)
    );
    assert_eq!(got["starts_on"], "2026-11-01");

    for bad in [
        json!({"color": "red"}),
        json!({"starts_on": "2026-13-45"}),
        json!({"ends_on": "2026-10-01"}),
        json!({"title": " "}),
    ] {
        let (status, body) = fx.patch(&uri, bad.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    let (status, _) = fx.patch("/api/v1/epics/999", json!({"title": "x"})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        audit_actions(&fx.app.pool)
            .await
            .contains(&"epic.updated".to_owned())
    );

    // Another company's requirement is refused, and its epic is invisible to this company.
    let req_b = fx
        .ok_post(
            &format!("/api/v1/companies/{}/requests", b.company.0),
            json!({"title": "Theirs", "body": "x"}),
        )
        .await;
    let theirs = req_b["requirement_id"]
        .as_i64()
        .or(req_b["id"].as_i64())
        .unwrap();
    let (status, _) = fx.patch(&uri, json!({"requirement_id": theirs})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let mut r = req(
        Method::PATCH,
        &uri,
        Some(&fx.key),
        Some(json!({"title": "x"})),
    );
    r.headers_mut().insert(
        "x-citadel-company",
        b.company.0.to_string().parse().unwrap(),
    );
    let (status, _) = send(&fx.app, r).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

async fn put(fx: &Fx, uri: &str, body: Value) -> (StatusCode, Value) {
    send(&fx.app, req(Method::PUT, uri, Some(&fx.key), Some(body))).await
}

#[tokio::test]
async fn a_project_takes_presentation_teams_and_runtime_fields_and_a_logo() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let by = super::super::BY;
    let dept = crate::store::org::add_department(&fx.app.pool, a.company, "Eng", by)
        .await
        .unwrap();
    let mut teams = vec![];
    for n in ["One", "Two", "Three"] {
        teams.push(
            crate::store::org::add_team(&fx.app.pool, dept.id, n, by)
                .await
                .unwrap()
                .id
                .0,
        );
    }
    let uri = format!("/api/v1/projects/{}", a.project.0);
    let before = fx.ok(&uri).await;
    assert_eq!(
        (before["team_ids"].clone(), before["runner_tags"].clone()),
        (json!([]), json!([]))
    );
    assert!(before["icon"].is_null() && before["logo_url"].is_null());

    let (status, got) = put(
        &fx,
        &uri,
        json!({"icon": "hammer", "color": "#aabbcc", "team_ids": [teams[1], teams[0]],
               "runner_tags": ["mac", "gpu"], "max_parallel_runs": 3,
               "run_timeout_secs": 3600, "worktree_keep_days": 7}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["team_ids"], json!([teams[1], teams[0]]));
    assert_eq!(got["team_id"], teams[1], "the owner is the first");
    assert_eq!(
        (
            got["icon"].clone(),
            got["color"].clone(),
            got["runner_tags"].clone()
        ),
        (json!("hammer"), json!("#aabbcc"), json!(["mac", "gpu"]))
    );
    assert_eq!(
        (
            got["max_parallel_runs"].clone(),
            got["run_timeout_secs"].clone(),
            got["worktree_keep_days"].clone()
        ),
        (json!(3), json!(3600), json!(7))
    );
    assert_eq!(fx.ok(&uri).await, got);

    // The legacy owner field keeps the others; null clears; a deleted team leaves the list.
    let (_, got) = put(
        &fx,
        &uri,
        json!({"team_id": teams[2], "max_parallel_runs": null}),
    )
    .await;
    assert_eq!(got["team_ids"], json!([teams[2], teams[0]]));
    assert!(got["max_parallel_runs"].is_null());
    crate::store::org::delete_team(&fx.app.pool, citadel_core::org::TeamId(teams[0]))
        .await
        .unwrap();
    assert_eq!(fx.ok(&uri).await["team_ids"], json!([teams[2]]));

    for bad in [
        json!({"color": "red"}),
        json!({"max_parallel_runs": 0}),
        json!({"run_timeout_secs": 0}),
        json!({"team_ids": [teams[2], teams[2]]}),
        json!({"icon": " "}),
        json!({"runner_tags": [""]}),
    ] {
        let (status, body) = put(&fx, &uri, bad.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {body}");
    }
    let (status, _) = put(&fx, &uri, json!({"team_ids": [9999]})).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Creating takes them atomically: a refused value creates nothing.
    let create = format!("/api/v1/companies/{}/projects", a.company.0);
    let made = fx
        .ok_post(
            &create,
            json!({"name": "N", "key": "NEW", "team_ids": [teams[2], teams[1]],
                                 "icon": "star", "color": "#000000", "runner_tags": ["x"]}),
        )
        .await;
    assert_eq!(made["team_ids"], json!([teams[2], teams[1]]));
    assert_eq!(
        (made["icon"].clone(), made["runner_tags"].clone()),
        (json!("star"), json!(["x"]))
    );
    let (status, _) = fx
        .post(&create, json!({"name": "M", "key": "MMM", "color": "nope"}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let all = fx.ok(&create).await;
    assert!(!all.to_string().contains("MMM"), "nothing was created");

    // Logo: upload, serve, delete.
    let logo = format!("{uri}/logo");
    assert_eq!(fx.get(&logo).await.0, StatusCode::NOT_FOUND);
    let png: &[u8] = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0";
    let r = Request::builder()
        .method(Method::PUT)
        .uri(&logo)
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {}", fx.key))
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from(png.to_vec()))
        .unwrap();
    let (status, got) = send(&fx.app, r).await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["logo_url"], logo);
    let res = crate::api::router(fx.app.clone())
        .oneshot(req(Method::GET, &logo, Some(&fx.key), None))
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers()[header::CONTENT_TYPE], "image/png");
    let r = Request::builder()
        .method(Method::PUT)
        .uri(&logo)
        .header(header::HOST, HOST)
        .header(header::AUTHORIZATION, format!("Bearer {}", fx.key))
        .header(header::CONTENT_TYPE, "image/png")
        .body(Body::from("not an image"))
        .unwrap();
    assert_eq!(send(&fx.app, r).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let (status, got) = send(&fx.app, req(Method::DELETE, &logo, Some(&fx.key), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(got["logo_url"].is_null());
    assert_eq!(fx.get(&logo).await.0, StatusCode::NOT_FOUND);
    let acts = audit_actions(&fx.app.pool).await;
    for want in ["project.updated", "project.logo_set", "project.logo_reset"] {
        assert!(acts.iter().any(|a| a == want), "{want}");
    }
}

#[tokio::test]
async fn definition_of_done_rules_and_network_hosts_ride_the_profile() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/projects/{}/profile", a.project.0);
    let (status, got) = put(
        &fx,
        &uri,
        json!({"definition_of_done_rules": [{"text": "Tests pass", "on": true},
                                           {"text": "Docs updated", "on": false}],
               "network": "ask", "network_hosts": ["crates.io", "*.github.com"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    let p = &got["profile"];
    assert_eq!(
        p["definition_of_done"],
        json!(["Tests pass"]),
        "the list is the rules that are on"
    );
    assert_eq!(
        p["definition_of_done_rules"][1],
        json!({"text": "Docs updated", "on": false})
    );
    assert_eq!(p["network_hosts"], json!(["crates.io", "*.github.com"]));

    // The legacy list alone replaces the rules, all on.
    let (_, got) = put(&fx, &uri, json!({"definition_of_done": ["One", "Two"]})).await;
    assert_eq!(
        got["profile"]["definition_of_done_rules"],
        json!([{"text": "One", "on": true}, {"text": "Two", "on": true}])
    );
    let (status, _) = put(&fx, &uri, json!({"network_hosts": ["https://x.com/path"]})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_projects_cumulative_flow_counts_each_state_per_day() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    sqlx::query("UPDATE issue_state_history SET at = '2026-10-20T10:00:00.000Z'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO issue_state_history (issue_id, from_state, to_state, at) \
         VALUES (?, 'todo', 'done', '2026-10-22T09:00:00.000Z')",
    )
    .bind(a.issue.0)
    .execute(&fx.app.pool)
    .await
    .unwrap();
    let uri = format!(
        "/api/v1/projects/{}/cfd?since=2026-10-19&bucket=day",
        a.project.0
    );
    let days = fx.ok(&uri).await;
    let days = days.as_array().unwrap();
    let at = |i: usize, state: &str| days[i]["counts"][state].as_i64().unwrap();
    let on: Vec<&str> = days.iter().map(|d| d["day"].as_str().unwrap()).collect();
    assert_eq!(on, ["2026-10-19", "2026-10-20", "2026-10-21", "2026-10-22"]);
    assert_eq!((at(0, "todo"), at(0, "done")), (0, 0), "not created yet");
    assert_eq!((at(1, "todo"), at(2, "todo")), (1, 1));
    assert_eq!((at(3, "todo"), at(3, "done")), (0, 1));
    assert_eq!(
        days[3]["counts"].as_object().unwrap().len(),
        7,
        "every state is there"
    );
    let _ = b;

    let (status, _) = fx
        .get(&format!("/api/v1/projects/{}/cfd?bucket=week", a.project.0))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = fx
        .get(&format!(
            "/api/v1/projects/{}/cfd?since=2020-01-01",
            a.project.0
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "over a year");
    assert_eq!(
        fx.get("/api/v1/projects/99/cfd").await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_profile_preview_is_the_run_context_text() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let empty = fx
        .ok(&format!("/api/v1/projects/{}/profile/preview", a.project.0))
        .await;
    assert_eq!(empty["text"], "");
    let (status, _) = put(
        &fx,
        &format!("/api/v1/projects/{}/profile", a.project.0),
        json!({"stack": "Rust", "definition_of_done": ["Tests pass"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let got = fx
        .ok(&format!("/api/v1/projects/{}/profile/preview", a.project.0))
        .await;
    let text = got["text"].as_str().unwrap();
    assert!(text.starts_with("# Project profile"), "{text}");
    assert!(
        text.contains("- Tests pass") && text.contains("Rust"),
        "{text}"
    );
    let (fitted, budget) = crate::store::work::run_profile(&fx.app.pool, a.project)
        .await
        .unwrap();
    assert_eq!(text, fitted.text.unwrap(), "the same text a run is given");
    assert_eq!(
        (
            got["bytes"].as_u64().unwrap(),
            got["budget_bytes"].as_u64().unwrap()
        ),
        (text.len() as u64, budget)
    );
}

#[tokio::test]
async fn a_repo_shows_its_stack_and_who_uses_it_and_rejects_local_probes() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let repos = format!("/api/v1/projects/{}/repos", a.project.0);
    let added = fx
        .ok_post(
            &repos,
            json!({"name": "app", "url": "https://example.test/app", "stack": "Swift"}),
        )
        .await;
    assert_eq!(
        (added["stack"].clone(), added["in_use_by"].clone()),
        (json!("Swift"), json!([]))
    );
    sqlx::query("UPDATE issues SET state = 'in_progress' WHERE id = ?")
        .bind(a.issue.0)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let listed = fx.ok(&repos).await;
    assert_eq!(
        listed[0]["in_use_by"],
        json!(["AAA-1"]),
        "the primary repo of an issue with none approved"
    );
    let (status, got) = put(
        &fx,
        &format!("/api/v1/repos/{}", added["id"]),
        json!({"name": "app", "url": "https://example.test/app"}),
    )
    .await;
    assert_eq!(
        (status, got["stack"].clone()),
        (StatusCode::OK, json!("Swift")),
        "absent keeps it"
    );
    let (_, got) = put(
        &fx,
        &format!("/api/v1/repos/{}", added["id"]),
        json!({"name": "app", "url": "https://example.test/app", "stack": "Rust"}),
    )
    .await;
    assert_eq!(got["stack"], "Rust");

    // Local probes are refused without running git or saving a repo.
    let probe = format!("{repos}/probe");
    assert_eq!(fx.ok(&repos).await.as_array().unwrap().len(), 1);
    for bad in [
        "ext::sh -c id",
        "relative",
        "--upload-pack=x",
        "/srv/repo",
        "/no/such/repo",
    ] {
        let (status, _) = fx.post(&probe, json!({"url": bad})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (status, _) = fx
        .post(&probe, json!({"url": "https://example.test/x", "forge": {"kind": "github", "repo": "a/b", "token_file": "/no/token"}}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an unreadable token file");
}

#[tokio::test]
async fn a_request_carries_a_project_priority_and_criteria() {
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let b = seed(&fx.app.pool, "B", "BBB", ProjectMode::Kanban).await;
    let uri = format!("/api/v1/companies/{}/requests", a.company.0);
    let issue = fx
        .ok_post(
            &uri,
            json!({"title": "Ship", "body": "b", "project_id": a.project.0, "priority": "urgent",
                   "criteria": ["Works", "Fast"]}),
        )
        .await;
    assert_eq!(issue["priority_level"], "urgent");
    assert_eq!(issue["priority"], true);
    assert_eq!(
        issue["criteria"],
        json!([{"text": "Works", "done": false}, {"text": "Fast", "done": false}])
    );
    let req = fx
        .ok(&format!("/api/v1/requirements/{}", issue["requirement_id"]))
        .await;
    assert_eq!(req["project_id"], a.project.0);
    assert_eq!(req["priority_level"], "urgent");
    assert_eq!(req["criteria"][1]["text"], "Fast");
    assert!(req["paused_at"].is_null());

    let plain = fx.ok_post(&uri, json!({"title": "Plain"})).await;
    assert_eq!(
        (plain["priority_level"].clone(), plain["priority"].clone()),
        (json!("none"), json!(false))
    );
    let normal = fx
        .ok_post(&uri, json!({"title": "N", "priority": "normal"}))
        .await;
    assert_eq!(normal["priority_level"], "medium");

    let (status, _) = fx
        .post(&uri, json!({"title": "X", "project_id": b.project.0}))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another company's project");
    let (status, _) = fx
        .post(&uri, json!({"title": "X", "criteria": [" "]}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = fx
        .post(&uri, json!({"title": "X", "priority": "high"}))
        .await;
    assert!(status.is_client_error());
}

#[tokio::test]
async fn a_paused_requirement_holds_its_wakes_until_resumed_and_done_needs_no_open_issue() {
    use crate::store::exec::dispatch_next;
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let issue = fx
        .ok_post(
            &format!("/api/v1/companies/{}/requests", a.company.0),
            json!({"title": "Goal"}),
        )
        .await;
    let rid = issue["requirement_id"].as_i64().unwrap();
    let uri = format!("/api/v1/requirements/{rid}");
    // Done needs it to be in progress.
    assert_eq!(
        fx.post(&format!("{uri}/done"), json!({})).await.0,
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE requirements SET state = 'in_progress' WHERE id = ?")
        .bind(rid)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let work = fx
        .ok_post(
            &format!("/api/v1/projects/{}/issues", a.project.0),
            json!({"title": "Work", "assignee_agent_id": a.agent.0}),
        )
        .await;
    sqlx::query("UPDATE issues SET requirement_id = ? WHERE id = ?")
        .bind(rid)
        .bind(work["id"].as_i64().unwrap())
        .execute(&fx.app.pool)
        .await
        .unwrap();

    let paused = fx.ok_post(&format!("{uri}/pause"), json!({})).await;
    assert!(paused["paused_at"].is_string());
    let n = audit_actions(&fx.app.pool).await.len();
    fx.ok_post(&format!("{uri}/pause"), json!({})).await;
    assert_eq!(
        audit_actions(&fx.app.pool).await.len(),
        n,
        "pausing twice audits once"
    );
    let dispatch = || {
        dispatch_next(
            &fx.app.pool,
            a.runner,
            &[],
            &citadel_core::org::Harness::ALL,
            NOW,
        )
    };
    assert!(dispatch().await.unwrap().is_none(), "its wake is held");
    let why = crate::store::work::plan_hold(
        &fx.app.pool,
        citadel_core::work::IssueId(work["id"].as_i64().unwrap()),
        a.agent,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(why.contains("paused"), "{why}");
    // Done is refused while its issues are open.
    assert_eq!(
        fx.post(&format!("{uri}/done"), json!({})).await.0,
        StatusCode::CONFLICT
    );

    let resumed = fx.ok_post(&format!("{uri}/resume"), json!({})).await;
    assert!(resumed["paused_at"].is_null());
    assert!(dispatch().await.unwrap().is_some(), "the held wake goes");

    for id in [work["id"].as_i64().unwrap(), issue["id"].as_i64().unwrap()] {
        sqlx::query("UPDATE issues SET state = 'cancelled', next_agent_id = NULL, next_user_id = NULL, next_at = NULL WHERE id = ?")
            .bind(id)
            .execute(&fx.app.pool)
            .await
            .unwrap();
    }
    let done = fx.ok_post(&format!("{uri}/done"), json!({})).await;
    assert_eq!(done["state"], "done");
    assert_eq!(
        fx.post(&format!("{uri}/pause"), json!({})).await.0,
        StatusCode::CONFLICT
    );
    let acts = audit_actions(&fx.app.pool).await;
    for want in [
        "requirement.paused",
        "requirement.resumed",
        "requirement.done",
    ] {
        assert!(acts.iter().any(|a| a == want), "{want}");
    }
    assert_eq!(
        fx.post("/api/v1/requirements/999/pause", json!({})).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_stuck_issue_carries_its_run_its_usual_time_and_its_trail() {
    use citadel_core::exec::RunEvent;
    let fx = fx().await;
    let a = seed(&fx.app.pool, "A", "AAA", ProjectMode::Kanban).await;
    let by = AuditActor::Runner(a.runner);
    crate::store::exec::transition_run(&fx.app.pool, a.run.id, by, &RunEvent::Succeed, NOW)
        .await
        .unwrap();
    // Three past stays in `todo` of 100, 200 and 300 seconds, and a dead checkout.
    sqlx::query("DELETE FROM issue_state_history WHERE issue_id = ?")
        .bind(a.issue.0)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    for (n, secs) in [(1, 100), (2, 200), (3, 300)] {
        let at = format!("2026-10-1{n}T10:00:00.000Z");
        let then = format!("2026-10-1{n}T10:{:02}:{:02}.000Z", secs / 60, secs % 60);
        for (from, to, at) in [(None, "todo", &at), (Some("todo"), "in_progress", &then)] {
            sqlx::query("INSERT INTO issue_state_history (issue_id, from_state, to_state, at) VALUES (?, ?, ?, ?)")
                .bind(a.issue.0)
                .bind(from)
                .bind(to)
                .bind(at)
                .execute(&fx.app.pool)
                .await
                .unwrap();
        }
    }
    sqlx::query("UPDATE issues SET checkout_run_id = ?, checked_out_at = ? WHERE id = ?")
        .bind(a.run.id.0)
        .bind(NOW)
        .bind(a.issue.0)
        .execute(&fx.app.pool)
        .await
        .unwrap();
    fx.ok_patch(
        &format!("/api/v1/issues/{}", a.issue.0),
        json!({"title": "Renamed"}),
    )
    .await;
    *fx.clock.0.lock().unwrap() = "2026-10-25T10:00:00.000Z".to_owned();

    let stuck = fx.ok("/api/v1/stuck").await;
    let ours: Vec<&Value> = stuck
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["issue_id"] == json!(a.issue.0))
        .collect();
    assert!(!ours.is_empty(), "{stuck}");
    let s = ours[0];
    assert_eq!(s["run_id"], a.run.id.0, "{s}");
    assert_eq!(s["usual_secs"], 200, "the median of its past stays in todo");
    let trail = s["trail"].as_array().unwrap();
    assert_eq!(trail.last().unwrap()["what"], "issue updated");
    assert!(trail.last().unwrap()["at"].is_string());
    assert!(trail.len() <= 6);
}
