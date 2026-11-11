use axum::http::{Method, StatusCode};
use serde_json::json;
use sqlx::Row;

use super::common::*;

/// Alpha (2 items), Beta (1), Optimus (employer, 2), one with no signal at all.
async fn sample_run(fx: &Fx) -> String {
    let run = start(fx).await;
    send(
        fx,
        &run,
        vec![
            item(1, "/h/Projects/Alpha/api", "alpha one", "alpha body one"),
            item(2, "/h/Projects/Alpha/web", "alpha two", "alpha body two"),
            item(3, "/h/Projects/Beta/x", "beta one", "beta body"),
            item(4, "/h/Projects/Optimus/api", "opt one", "optimus body one"),
            item(5, "/h/Projects/Optimus/api", "opt two", "optimus body two"),
            item(6, "", "loose", "no signal"),
        ],
    )
    .await;
    assert_eq!(finish(fx, &run).await["state"], "review");
    run
}

#[tokio::test]
async fn discovery_proposes_rooms_with_cards_and_unsorted_last() {
    let fx = fx().await;
    let run = sample_run(&fx).await;
    let p = proposals(&fx, &run).await;
    let names: Vec<_> = p.iter().map(|x| x["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["Alpha", "Beta", "Optimus", "Unsorted"]);
    let alpha = by_name(&p, "Alpha");
    assert_eq!(
        (
            alpha["item_count"].as_i64(),
            alpha["kind"].as_str(),
            alpha["state"].as_str()
        ),
        (Some(2), Some("general"), Some("proposed"))
    );
    assert_eq!(alpha["sample_titles"], json!(["alpha one", "alpha two"]));
    assert_eq!(by_name(&p, "Optimus")["kind"], "employer");
    let items = ok(
        &fx,
        Method::GET,
        &format!(
            "/imports/{run}/proposals/{}/items",
            alpha["id"].as_str().unwrap()
        ),
        None,
    )
    .await;
    assert_eq!(items["items"].as_array().unwrap().len(), 2);
    assert!(
        items["items"][0].get("text").is_none(),
        "text is not sent in a list"
    );
}

#[tokio::test]
async fn every_review_action_shows_in_the_proposals() {
    let fx = fx().await;
    let run = sample_run(&fx).await;
    let p = proposals(&fx, &run).await;
    let (alpha, beta, un) = (
        by_name(&p, "Alpha")["id"].as_str().unwrap().to_owned(),
        by_name(&p, "Beta")["id"].as_str().unwrap().to_owned(),
        "unsorted",
    );
    let base = format!("/imports/{run}/proposals");

    // rename, kind, config
    let v = ok(&fx, Method::PATCH, &format!("{base}/{alpha}"), Some(json!({"name": "Alpha App", "kind": "product", "config": {"allowed_models": "local_only", "review_days": 30}}))).await;
    assert_eq!(
        (
            v["name"].as_str(),
            v["kind"].as_str(),
            v["config"]["allowed_models"].as_str()
        ),
        (Some("Alpha App"), Some("product"), Some("local_only"))
    );
    let (s, _) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("{base}/{alpha}"),
        Some(json!({"config": {"review_days": 0}})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // split one item out of Alpha
    let alpha_items = ok(&fx, Method::GET, &format!("{base}/{alpha}/items"), None).await;
    let first = alpha_items["items"][0]["id"].as_str().unwrap().to_owned();
    let new = ok(
        &fx,
        Method::POST,
        &format!("{base}/{alpha}/split"),
        Some(json!({"item_ids": [first], "name": "Alpha side"})),
    )
    .await;
    assert_eq!(
        (new["name"].as_str(), new["item_count"].as_i64()),
        (Some("Alpha side"), Some(1))
    );
    assert_eq!(
        by_name(&proposals(&fx, &run).await, "Alpha App")["item_count"],
        1
    );

    // merge Beta into Alpha side
    let target = new["id"].as_str().unwrap().to_owned();
    let merged = ok(
        &fx,
        Method::POST,
        &format!("{base}/{beta}/merge"),
        Some(json!({"into": target})),
    )
    .await;
    assert_eq!(merged["item_count"], 2);
    assert!(
        !proposals(&fx, &run)
            .await
            .iter()
            .any(|x| x["name"] == "Beta")
    );

    // marks and a move out of Unsorted
    let loose = ok(&fx, Method::GET, &format!("{base}/{un}/items"), None).await["items"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        &fx,
        Method::PATCH,
        &format!("/imports/{run}/items"),
        Some(json!({"ids": [loose], "mark": "needed", "proposal": target})),
    )
    .await;
    let moved = ok(&fx, Method::GET, &format!("{base}/{target}/items"), None).await;
    let row = moved["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == loose.as_str())
        .unwrap()
        .clone();
    assert_eq!(row["mark"], "needed");
    assert!(
        !proposals(&fx, &run)
            .await
            .iter()
            .any(|x| x["id"] == "unsorted" && x["item_count"].as_i64() != Some(0))
    );

    // Unsorted is not a room
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("{base}/{un}"),
        Some(json!({"state": "accepted"})),
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::BAD_REQUEST, &json!("unsorted_not_a_room"))
    );
}

#[tokio::test]
async fn refusing_a_room_writes_a_draft_rule_that_commit_turns_on() {
    let fx = fx().await;
    let run = sample_run(&fx).await;
    let p = proposals(&fx, &run).await;
    let beta = by_name(&p, "Beta")["id"].as_str().unwrap().to_owned();
    let v = ok(
        &fx,
        Method::POST,
        &format!("/imports/{run}/proposals/{beta}/refuse"),
        None,
    )
    .await;
    assert_eq!(v["state"], "refused");
    let draft: (String, i64) =
        sqlx::query_as("SELECT pattern, enabled FROM brain_rules WHERE reason LIKE 'draft:%'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(draft, ("Beta".to_owned(), 0));
    ok(&fx, Method::POST, &format!("/imports/{run}/commit"), None).await;
    let on: i64 = sqlx::query_scalar("SELECT enabled FROM brain_rules WHERE pattern = 'Beta'")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(on, 1);
    // The next run: the folder is refused at intake, and nothing of it was stored.
    let run2 = start(&fx).await;
    let r = send(
        &fx,
        &run2,
        vec![item(9, "/h/Projects/Beta/y", "again", "beta second run")],
    )
    .await;
    assert_eq!(r["results"][0]["status"], "refused");
    assert!(!everything_stored(&fx).await.contains("beta body"));
}

#[tokio::test]
async fn commit_needs_a_step_up_writes_personal_rooms_and_holds_employer_rooms() {
    let fx = fx().await;
    let run = sample_run(&fx).await;
    let p = proposals(&fx, &run).await;
    for n in ["Alpha", "Optimus"] {
        let id = by_name(&p, n)["id"].as_str().unwrap();
        ok(
            &fx,
            Method::PATCH,
            &format!("/imports/{run}/proposals/{id}"),
            Some(json!({"state": "accepted"})),
        )
        .await;
    }
    let (s, v) = call(
        &fx,
        &fx.laptop,
        Method::POST,
        &format!("/imports/{run}/commit"),
        None,
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::FORBIDDEN, &json!("step_up_required"))
    );
    let r = ok(&fx, Method::POST, &format!("/imports/{run}/commit"), None).await;
    assert_eq!(r["rooms"].as_array().unwrap().len(), 1);
    assert_eq!(
        (
            r["rooms"][0]["name"].as_str(),
            r["rooms"][0]["sources"].as_i64()
        ),
        (Some("Alpha"), Some(2))
    );
    assert_eq!(
        r["held"].as_array().unwrap().len(),
        1,
        "the employer room waits for room_backup"
    );
    assert_eq!(r["state"], "review");
    let rooms = ok(&fx, Method::GET, "/rooms", None).await;
    assert_eq!(rooms.as_array().unwrap().len(), 1);
    assert_eq!(rooms[0]["sources"], 2);
    // One audit row and one event for the room.
    let created: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'brain.room.created'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(created, 1);
    // No text in the control plane or the audit trail.
    let audit: Vec<(String,)> = sqlx::query_as("SELECT details FROM audit_events")
        .fetch_all(&fx.app.pool)
        .await
        .unwrap();
    assert!(!audit.iter().any(|(d,)| d.contains("alpha body")));
}

#[tokio::test]
async fn a_commit_that_is_run_again_writes_nothing_twice() {
    let fx = fx().await;
    let run = sample_run(&fx).await;
    let alpha = by_name(&proposals(&fx, &run).await, "Alpha")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    ok(
        &fx,
        Method::PATCH,
        &format!("/imports/{run}/proposals/{alpha}"),
        Some(json!({"state": "accepted"})),
    )
    .await;
    let first = ok(&fx, Method::POST, &format!("/imports/{run}/commit"), None).await;
    let room = first["rooms"][0]["room"].as_str().unwrap().to_owned();
    // A crash after the room file was written but before the proposal closed: put the run back.
    let st = staging_pool(&fx, &run).await;
    sqlx::query("UPDATE proposals SET state = 'accepted' WHERE id = ?")
        .bind(&alpha)
        .execute(&st)
        .await
        .unwrap();
    st.close().await;
    sqlx::query("UPDATE brain_import_runs SET state = 'review'")
        .execute(&fx.app.pool)
        .await
        .unwrap();
    let again = ok(&fx, Method::POST, &format!("/imports/{run}/commit"), None).await;
    assert_eq!(
        (
            again["rooms"][0]["created"].as_bool(),
            again["rooms"][0]["sources"].as_i64()
        ),
        (Some(false), Some(0))
    );
    let created: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action = 'brain.room.created'")
            .fetch_one(&fx.app.pool)
            .await
            .unwrap();
    assert_eq!(created, 1);
    ok(&fx, Method::POST, &format!("/rooms/{room}/open"), None).await;
    let key = key_of(&fx).await;
    let access = fx
        .brain
        .rooms()
        .access(&fx.app, &key, &room)
        .await
        .ok()
        .unwrap();
    let (n, ops, out): (i64, i64, i64) = (
        sqlx::query_scalar("SELECT count(*) FROM sources")
            .fetch_one(access.pool())
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT count(*) FROM op_log")
            .fetch_one(access.pool())
            .await
            .unwrap(),
        sqlx::query_scalar("SELECT count(*) FROM outbox")
            .fetch_one(access.pool())
            .await
            .unwrap(),
    );
    assert_eq!((n, ops, out), (2, 2, 2));
}

#[tokio::test]
async fn two_employers_never_share_a_room_and_a_mixed_commit_is_refused() {
    let fx = fx().await;
    let run = start(&fx).await;
    send(
        &fx,
        &run,
        vec![
            item(1, "/h/Projects/Shared/a", "for Optimus", "opt text"),
            item(2, "/h/Projects/Shared/b", "for AutomotiveAi", "auto text"),
        ],
    )
    .await;
    finish(&fx, &run).await;
    let p = proposals(&fx, &run).await;
    assert_eq!(p.len(), 2, "split per employer: {p:?}");
    // The user merges them anyway: the card warns and cannot be accepted.
    let (a, b) = (
        p[0]["id"].as_str().unwrap().to_owned(),
        p[1]["id"].as_str().unwrap().to_owned(),
    );
    let merged = ok(
        &fx,
        Method::POST,
        &format!("/imports/{run}/proposals/{a}/merge"),
        Some(json!({"into": b})),
    )
    .await;
    assert!(
        merged["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w == "mixed_employers")
    );
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::PATCH,
        &format!("/imports/{run}/proposals/{b}"),
        Some(json!({"state": "accepted"})),
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("mixed_employers"))
    );
    // Even with the state forced in the file, the commit route re-checks and writes nothing.
    let st = staging_pool(&fx, &run).await;
    sqlx::query("UPDATE proposals SET state = 'accepted' WHERE id = ?")
        .bind(&b)
        .execute(&st)
        .await
        .unwrap();
    st.close().await;
    let (s, v) = call(
        &fx,
        &fx.admin,
        Method::POST,
        &format!("/imports/{run}/commit"),
        None,
    )
    .await;
    assert_eq!(
        (s, &v["code"]),
        (StatusCode::CONFLICT, &json!("mixed_employers"))
    );
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM brain_rooms")
        .fetch_one(&fx.app.pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn import_isolation_room_a_is_never_readable_through_room_b_and_deprecated_items_are_in_no_file()
 {
    let fx = fx().await;
    let run = start(&fx).await;
    send(
        &fx,
        &run,
        vec![
            item(1, "/h/Projects/Alpha/a", "a", "ALPHA_ONLY_TEXT"),
            item(2, "/h/Projects/Beta/a", "b", "BETA_ONLY_TEXT"),
            item(3, "/h/Projects/GitScope/a", "g", "DEPRECATED_TEXT"),
            item(4, "/h/Projects/Finvo/a", "f", "DEPRECATED_TEXT_TWO"),
        ],
    )
    .await;
    finish(&fx, &run).await;
    for p in proposals(&fx, &run).await {
        ok(
            &fx,
            Method::PATCH,
            &format!("/imports/{run}/proposals/{}", p["id"].as_str().unwrap()),
            Some(json!({"state": "accepted"})),
        )
        .await;
    }
    let done = ok(&fx, Method::POST, &format!("/imports/{run}/commit"), None).await;
    assert_eq!(done["rooms"].as_array().unwrap().len(), 2);
    let key = key_of(&fx).await;
    let mut seen = vec![];
    for r in done["rooms"].as_array().unwrap() {
        let id = r["room"].as_str().unwrap();
        ok(&fx, Method::POST, &format!("/rooms/{id}/open"), None).await;
        let h = fx
            .brain
            .rooms()
            .access(&fx.app, &key, id)
            .await
            .ok()
            .unwrap();
        let texts: Vec<String> = sqlx::query("SELECT text FROM sources")
            .fetch_all(h.pool())
            .await
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        seen.push((r["name"].as_str().unwrap().to_owned(), texts));
    }
    for (name, texts) in &seen {
        let other = if name == "Alpha" {
            "BETA_ONLY_TEXT"
        } else {
            "ALPHA_ONLY_TEXT"
        };
        assert!(
            !texts.iter().any(|t| t.contains(other)),
            "{name} holds the other room's text"
        );
        assert_eq!(texts.len(), 1);
    }
    let all = everything_stored(&fx).await;
    assert!(
        !all.contains("DEPRECATED_TEXT"),
        "a deprecated item reached a file"
    );
    // The refusal holds on a second run.
    let run2 = start(&fx).await;
    let r = send(
        &fx,
        &run2,
        vec![item(
            7,
            "/h/Projects/GitScope/b",
            "again",
            "DEPRECATED_TEXT again",
        )],
    )
    .await;
    assert_eq!(r["results"][0]["status"], "refused");
    assert!(!everything_stored(&fx).await.contains("DEPRECATED_TEXT"));
}
