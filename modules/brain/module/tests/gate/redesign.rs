//! The Brain redesign (API minor 101): series, rule kinds, places, topics, ask, source reads,
//! activity days, inbox reasons, follow and written rules, and the About-you area. Synthetic data only.

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::ai::open_room;
use super::common::*;

#[allow(clippy::too_many_arguments)]
/// A record in the room's file created now, with `tags` (a JSON array) and `support`.
async fn put(
    fx: &Fx,
    room: &str,
    id: &str,
    kind: &str,
    status: &str,
    body: &str,
    tags: &str,
    support: i64,
) {
    let p = canon_pool(fx, room).await;
    sqlx::query(
        "INSERT INTO records (id, type, status, body, tags, source_ids, created_at, support) \
         VALUES (?, ?, ?, ?, ?, '[]', ?, ?)",
    )
    .bind(id)
    .bind(kind)
    .bind(status)
    .bind(body)
    .bind(tags)
    .bind(fx.app.clock.now())
    .bind(support)
    .execute(&p)
    .await
    .unwrap();
    p.close().await;
}

async fn two_rooms(fx: &Fx) -> (String, String) {
    let a = committed_room_named(fx, "Alpha", &[("A", "alpha text one")]).await;
    let b = committed_room_named(fx, "Beta", &[("B", "beta text two")]).await;
    open_room(fx, &a).await;
    open_room(fx, &b).await;
    (a, b)
}

fn area<'a>(v: &'a Value, name: &str) -> &'a Value {
    v["areas"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["area"] == name)
        .unwrap()
}

#[tokio::test]
async fn about_you_counts_the_profile_answers_of_the_personal_room() {
    let fx = fx().await;
    let saved = ok(
        &fx,
        Method::PUT,
        "/me/profile",
        Some(json!({"items": [{"key": "role", "body": "Builds software and runs a small team."}]})),
    )
    .await;
    let room = saved["room"].as_str().unwrap().to_owned();
    open_room(&fx, &room).await;
    // A rule in the personal room stays a rule; the answer is About you, not a rule.
    put(
        &fx,
        &room,
        "r1",
        "rule",
        "accepted",
        "Never share my address",
        "[]",
        1,
    )
    .await;
    put(
        &fx,
        &room,
        "f1",
        "fact",
        "accepted",
        "Lives in Cairo",
        "[]",
        1,
    )
    .await;
    let v = ok(&fx, Method::GET, "/areas", None).await;
    assert_eq!(area(&v, "me")["count"], 2, "{v}");
    assert_eq!(area(&v, "rules")["count"], 1, "{v}");
    let me = ok(&fx, Method::GET, "/areas/me", None).await;
    let ids: Vec<&str> = me["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"me-role") && ids.contains(&"f1"), "{me}");
    let rules = ok(&fx, Method::GET, "/areas/rules", None).await;
    assert_eq!(rules["total"], 1, "{rules}");
    let learned = ok(&fx, Method::GET, "/learned", None).await;
    let l = learned
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "me-role")
        .unwrap();
    assert_eq!(l["area"], "me", "{learned}");
}

#[tokio::test]
async fn areas_carry_a_series_rule_kinds_and_the_topic_filters() {
    let fx = fx().await;
    let (a, b) = two_rooms(&fx).await;
    put(
        &fx,
        &a,
        "r1",
        "rule",
        "accepted",
        "Never push to main",
        "[]",
        3,
    )
    .await;
    put(
        &fx,
        &a,
        "r2",
        "preference",
        "accepted",
        "Short answers please",
        "[]",
        1,
    )
    .await;
    put(
        &fx,
        &a,
        "r3",
        "rule",
        "accepted",
        "Run the tests before a PR",
        "[]",
        1,
    )
    .await;
    put(
        &fx,
        &b,
        "r4",
        "rule",
        "accepted",
        "Run the tests before a PR",
        "[]",
        1,
    )
    .await;
    put(
        &fx,
        &a,
        "k1",
        "fact",
        "accepted",
        "We export invoices as CSV",
        r#"["billing","csv"]"#,
        4,
    )
    .await;
    put(
        &fx,
        &b,
        "k2",
        "fact",
        "accepted",
        "Billing runs monthly",
        r#"["billing"]"#,
        2,
    )
    .await;
    let v = ok(&fx, Method::GET, "/areas", None).await;
    let rules = area(&v, "rules");
    assert_eq!(rules["count"], 4, "{v}");
    let s = rules["series"].as_array().unwrap();
    assert_eq!(s.len(), 14, "{v}");
    assert_eq!(s[13], 4, "today is last: {v}");
    assert_eq!(s[0], 0, "{v}");
    assert_eq!(
        v["rule_kinds"],
        json!({"always": 2, "never": 1, "prefer": 1}),
        "{v}"
    );

    let never = ok(&fx, Method::GET, "/areas/rules?kind=never", None).await;
    assert_eq!(never["total"], 1, "{never}");
    assert_eq!(never["records"][0]["kind"], "never");
    let all = ok(&fx, Method::GET, "/areas/rules", None).await;
    let tests: Vec<&Value> = all["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["body"] == "Run the tests before a PR")
        .collect();
    assert!(
        tests
            .iter()
            .all(|r| r["everywhere"] == true && r["rooms"].as_array().unwrap().len() == 2),
        "{all}"
    );
    let one = all["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "r1")
        .unwrap();
    assert_eq!(one["everywhere"], false, "{all}");
    assert_eq!(one["following"], true);
    let know = ok(&fx, Method::GET, "/areas/knowledge?topic=billing", None).await;
    assert_eq!(know["total"], 2, "{know}");
    let know = ok(
        &fx,
        Method::GET,
        &format!("/areas/knowledge?topic=billing&room={b}"),
        None,
    )
    .await;
    assert_eq!(know["total"], 1, "{know}");
    let know = ok(&fx, Method::GET, "/areas/knowledge?q=INVOICES", None).await;
    assert_eq!(
        (know["total"].as_i64(), know["records"][0]["id"].as_str()),
        (Some(1), Some("k1")),
        "{know}"
    );
    for bad in ["kind=sometimes", &format!("q={}", "x".repeat(201))] {
        let (st, _) = call(
            &fx,
            &fx.admin,
            Method::GET,
            &format!("/areas/rules?{bad}"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{bad}");
    }

    let t = ok(&fx, Method::GET, "/topics?limit=1", None).await;
    assert_eq!(t[0]["name"], "billing", "{t}");
    assert_eq!(t[0]["count"], 2, "{t}");
    assert_eq!(t[0]["example"], "We export invoices as CSV", "{t}");
    assert_eq!(t[0]["rooms"].as_array().unwrap().len(), 2, "{t}");
    let (st, _) = call(&fx, &fx.admin, Method::GET, "/topics?limit=0", None).await;
    assert_eq!(st, StatusCode::BAD_REQUEST);

    let p = ok(&fx, Method::GET, "/places", None).await;
    let pa = p
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["room"] == a.as_str())
        .unwrap();
    assert_eq!(
        (
            pa["knowledge"].as_i64(),
            pa["rules"].as_i64(),
            pa["timeline"].as_i64()
        ),
        (Some(1), Some(3), Some(0)),
        "{p}"
    );
    assert_eq!(
        (pa["locked"].clone(), pa["learning"].clone()),
        (json!(false), json!(false))
    );
    assert!(pa["last_learned_at"].is_string(), "{p}");
}

#[tokio::test]
async fn a_closed_place_is_locked_and_empty() {
    let fx = fx().await;
    let a = committed_room(&fx, &[("A", "alpha text one")]).await;
    let p = ok(&fx, Method::GET, "/places", None).await;
    assert_eq!(p[0]["room"], a.as_str());
    assert_eq!(
        (p[0]["locked"].clone(), p[0]["knowledge"].clone()),
        (json!(true), json!(0)),
        "{p}"
    );
}

#[tokio::test]
async fn a_written_rule_is_saved_followed_and_can_be_unfollowed() {
    let fx = fx().await;
    let (a, b) = two_rooms(&fx).await;
    let w = ok(
        &fx,
        Method::POST,
        "/areas/rules",
        Some(json!({"body": "Use tabs", "kind": "never", "rooms": "everywhere"})),
    )
    .await;
    assert_eq!(
        (w["written"].as_array().unwrap().len(), w["skipped"].clone()),
        (2, json!(0)),
        "{w}"
    );
    let again = ok(
        &fx,
        Method::POST,
        "/areas/rules",
        Some(json!({"body": "use tabs", "kind": "never", "rooms": [a]})),
    )
    .await;
    assert_eq!(
        (
            again["written"].as_array().unwrap().len(),
            again["skipped"].clone()
        ),
        (0, json!(1)),
        "{again}"
    );
    let rules = ok(&fx, Method::GET, "/areas/rules?kind=never", None).await;
    assert_eq!(rules["total"], 2, "{rules}");
    let r = &rules["records"][0];
    assert_eq!(
        (
            r["support"].clone(),
            r["everywhere"].clone(),
            r["following"].clone()
        ),
        (json!(5), json!(true), json!(true)),
        "{rules}"
    );
    let id = r["id"].as_str().unwrap();
    let room = r["room"].as_str().unwrap();
    let f = ok(
        &fx,
        Method::PUT,
        &format!("/rooms/{room}/records/{id}/follow"),
        Some(json!({"on": false})),
    )
    .await;
    assert_eq!(f["following"], false);
    let rules = ok(&fx, Method::GET, &format!("/areas/rules?room={room}"), None).await;
    assert_eq!(rules["records"][0]["following"], false, "{rules}");
    let (st, _) = call(
        &fx,
        &fx.admin,
        Method::PUT,
        &format!("/rooms/{room}/records/nope/follow"),
        Some(json!({"on": true})),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    for body in [
        json!({"body": " ", "kind": "never", "rooms": "everywhere"}),
        json!({"body": "x", "kind": "maybe", "rooms": "everywhere"}),
        json!({"body": "x", "kind": "never", "rooms": []}),
        json!({"body": "x", "kind": "never", "rooms": "some"}),
    ] {
        let (st, _) = call(
            &fx,
            &fx.admin,
            Method::POST,
            "/areas/rules",
            Some(body.clone()),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    }
    let (st, _) = call(
        &fx,
        &fx.admin,
        Method::POST,
        "/areas/rules",
        Some(json!({"body": "x", "kind": "never", "rooms": ["nope"]})),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    let _ = b;
}

#[tokio::test]
async fn ask_returns_the_best_matches_and_no_written_answer_yet() {
    let fx = fx().await;
    let (a, b) = two_rooms(&fx).await;
    put(
        &fx,
        &a,
        "k1",
        "fact",
        "accepted",
        "We export invoices as CSV",
        "[]",
        1,
    )
    .await;
    put(
        &fx,
        &b,
        "k2",
        "fact",
        "accepted",
        "The garden is green",
        "[]",
        1,
    )
    .await;
    let v = ok(
        &fx,
        Method::POST,
        "/ask",
        Some(json!({"q": "how do we export invoices?"})),
    )
    .await;
    assert!(v["answer"].is_null(), "{v}");
    assert_eq!(v["sources"][0]["id"], "k1", "{v}");
    assert_eq!(v["sources"][0]["room_name"], "Alpha", "{v}");
    assert!(v["sources"].as_array().unwrap().len() <= 8);
    let v = ok(
        &fx,
        Method::POST,
        "/ask",
        Some(json!({"q": "invoices garden", "room": b})),
    )
    .await;
    assert_eq!(v["sources"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["sources"][0]["id"], "k2", "{v}");
    for body in [json!({"q": "  "}), json!({"q": "x".repeat(301)})] {
        let (st, _) = call(&fx, &fx.admin, Method::POST, "/ask", Some(body)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
    let days = ok(&fx, Method::GET, "/activity/days?days=1", None).await;
    let asked = days["days"][0]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "asked")
        .unwrap();
    assert_eq!(asked["count"], 2, "{days}");
}

#[tokio::test]
async fn activity_days_counts_what_was_learned_and_tidied_per_day() {
    let fx = fx().await;
    let (a, _) = two_rooms(&fx).await;
    let p = canon_pool(&fx, &a).await;
    for (id, kind, counts) in [
        ("c1", "distil", r#"{"saved":3}"#),
        ("c2", "tidy", r#"{"archived":2,"merged":1}"#),
    ] {
        sqlx::query("INSERT INTO changes (id, kind, summary, counts, at) VALUES (?, ?, 's', ?, ?)")
            .bind(id)
            .bind(kind)
            .bind(counts)
            .bind(fx.app.clock.now())
            .execute(&p)
            .await
            .unwrap();
    }
    p.close().await;
    let v = ok(&fx, Method::GET, "/activity/days?days=3", None).await;
    let days = v["days"].as_array().unwrap();
    assert_eq!(days.len(), 3, "{v}");
    assert!(
        days[0]["day"].as_str().unwrap() > days[1]["day"].as_str().unwrap(),
        "newest first: {v}"
    );
    assert_eq!(
        (days[0]["learned"].clone(), days[0]["tidied"].clone()),
        (json!(3), json!(2)),
        "{v}"
    );
    let kinds: Vec<&str> = days[0]["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert!(
        ["learned", "merged", "tidied"]
            .iter()
            .all(|k| kinds.contains(k)),
        "{v}"
    );
    let learned = days[0]["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "learned")
        .unwrap();
    assert_eq!(learned["rooms"], json!(["Alpha"]), "{v}");
    assert_eq!(days[1]["events"], json!([]), "{v}");
    for q in ["days=0", "days=91"] {
        let (st, _) = call(
            &fx,
            &fx.admin,
            Method::GET,
            &format!("/activity/days?{q}"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{q}");
    }
}

#[tokio::test]
async fn sources_report_what_was_read() {
    let fx = fx().await;
    committed_room(&fx, &[("A", "alpha text one")]).await;
    let v = ok(&fx, Method::GET, "/sources", None).await;
    let any = v
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["read_total"].as_i64().unwrap() > 0);
    let s = any.unwrap_or(&v[0]);
    assert!(s["read_week"].is_i64() && s["reading"].is_boolean(), "{v}");
    if let Some(s) = any {
        assert!(
            s["read_week"].as_i64().unwrap() > 0 && s["last_read_at"].is_string(),
            "{v}"
        );
    }
}

#[tokio::test]
async fn an_inbox_candidate_says_why_it_waits() {
    let fx = fx().await;
    let a = committed_room(&fx, &[("A", "alpha text one")]).await;
    open_room(&fx, &a).await;
    put(
        &fx,
        &a,
        "m1",
        "fact",
        "accepted",
        "We deploy on Fridays",
        "[]",
        1,
    )
    .await;
    put(
        &fx,
        &a,
        "c-dup",
        "fact",
        "candidate",
        "we deploy on fridays ",
        "[]",
        1,
    )
    .await;
    put(
        &fx,
        &a,
        "c-one",
        "fact",
        "candidate",
        "Staging is in Frankfurt",
        "[]",
        1,
    )
    .await;
    let p = canon_pool(&fx, &a).await;
    p.close().await;
    put(
        &fx,
        &a,
        "c-con",
        "fact",
        "candidate",
        "We never deploy on Fridays",
        "[]",
        1,
    )
    .await;
    let p = canon_pool(&fx, &a).await;
    sqlx::query("UPDATE records SET contests = 'm1' WHERE id = 'c-con'")
        .execute(&p)
        .await
        .unwrap();
    p.close().await;
    let v = ok(
        &fx,
        Method::GET,
        &format!("/rooms/{a}/inbox?status=candidate"),
        None,
    )
    .await;
    let by = |id: &str| {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(
        (
            by("c-dup")["reason"].clone(),
            by("c-dup")["other_id"].clone()
        ),
        (json!("duplicate"), json!("m1")),
        "{v}"
    );
    assert_eq!(by("c-dup")["other_body"], "We deploy on Fridays");
    assert_eq!(
        (
            by("c-con")["reason"].clone(),
            by("c-con")["other_id"].clone()
        ),
        (json!("conflict"), json!("m1")),
        "{v}"
    );
    assert_eq!(by("c-one")["reason"], "single_source", "{v}");
    assert!(by("c-one").get("other_id").is_none());
}
