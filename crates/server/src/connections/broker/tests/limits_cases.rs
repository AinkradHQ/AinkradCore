//! Limits: what a grant covers, which connection wins, and how much one session may do.

use std::time::Duration;

use super::*;

fn get(repo: &str) -> Value {
    json!({"repo": repo, "number": 1})
}

async fn limited() -> (Fx, Connection, String) {
    let f = fx().await;
    let c = f.github("main", GH_TOKEN).await;
    f.member(c.id, &["read_repo"], &[("repos", &["acme/app", "tools/*"])])
        .await;
    f.grant(c.id, ("agent", "bot"), &["read_repo"], &[]).await;
    let s = f.session(&["read_repo"]).await;
    (f, c, s)
}

#[tokio::test]
async fn a_repo_outside_the_limit_is_refused_before_anything_is_sent() {
    let (f, _c, s) = limited().await;
    for repo in ["acme/other", "evil/app", "acme/app-2"] {
        let r = f.ask(&s, "github.get_issue", get(repo)).await;
        assert_eq!((r.ok, code(&r)), (false, "resource_denied"), "{repo}");
    }
    assert!(f.gh.seen().is_empty());
    f.gh.push(200, &[], ISSUE);
    assert!(
        f.ask(&s, "github.get_issue", get("tools/anything"))
            .await
            .ok
    );
    assert_eq!(f.gh.seen().len(), 1);
}

#[tokio::test]
async fn an_agent_grant_narrows_the_users_limits() {
    let (f, c, s) = limited().await;
    f.grant(
        c.id,
        ("agent", "bot"),
        &["read_repo"],
        &[("repos", &["tools/*"])],
    )
    .await;
    let r = f.ask(&s, "github.get_issue", get("acme/app")).await;
    assert_eq!(
        (r.ok, code(&r)),
        (false, "resource_denied"),
        "the agent's limit wins"
    );
    f.gh.push(200, &[], ISSUE);
    assert!(f.ask(&s, "github.get_issue", get("tools/x")).await.ok);
}

#[tokio::test]
async fn a_jira_project_outside_the_limit_is_refused_on_the_request_and_the_answer() {
    let f = fx().await;
    let c = f.jira("acme").await;
    f.member(c.id, &["read_issues"], &[("projects", &["ABC"])])
        .await;
    f.grant(c.id, ("agent", "bot"), &["read_issues"], &[]).await;
    let s = f.session(&["read_issues"]).await;
    let r = f.ask(&s, "jira.get_issue", json!({"key": "XYZ-1"})).await;
    assert_eq!((r.ok, code(&r)), (false, "resource_denied"));
    assert!(f.j.fake.seen().is_empty(), "never asked");
    // A search names no project: the adapter is handed the effective limits and enforces them on
    // the answer too (one issue of another project refuses the whole answer).
    let key = format!("POST {}", jt::site_path("/search/jql"));
    f.j.fake.reply(
        &key,
        200,
        json!({"issues": [{"key": "ABC-1", "fields": {"project": {"key": "ABC"}}},
                          {"key": "DEF-1", "fields": {"project": {"key": "DEF"}}}]}),
    );
    let r = f
        .ask(&s, "jira.search_issues", json!({"jql": "status = Open"}))
        .await;
    assert_eq!((r.ok, code(&r)), (false, "refused"));
    let sent = f.j.fake.last(&key).unwrap();
    assert!(
        sent.body["jql"]
            .as_str()
            .unwrap()
            .starts_with("project in (\"ABC\")"),
        "{sent:?}"
    );
    assert_eq!(f.uses().await.last().unwrap()["result"], "refused");
}

#[tokio::test]
async fn the_default_wins_and_without_one_an_ambiguous_use_refuses() {
    let f = fx().await;
    let a = f.github("work", GH_TOKEN).await;
    let b = f.github("personal", GH_TOKEN_2).await;
    let hidden = f.github("secret-one", "gh3probe-aaaaaaaaaaaaaaaa").await;
    for c in [&a, &b] {
        f.member(c.id, &["read_repo"], &[]).await;
        f.grant(c.id, ("agent", "bot"), &["read_repo"], &[]).await;
    }
    // `hidden` exists but nobody is granted it.
    let s = f.session(&["read_repo"]).await;
    let r = f.ask(&s, "github.get_issue", get("acme/app")).await;
    assert_eq!((r.ok, code(&r)), (false, "ambiguous"));
    let said = r.message.clone().unwrap();
    assert!(said.contains("work") && said.contains("personal"), "{said}");
    assert!(
        !said.contains("secret-one"),
        "an ungranted connection is never named: {said}"
    );
    assert!(f.gh.seen().is_empty());
    f.default(b.id).await;
    f.gh.push(200, &[], ISSUE);
    assert!(f.ask(&s, "github.get_issue", get("acme/app")).await.ok);
    let seen = f.gh.seen();
    assert_eq!(
        seen[0].header("authorization"),
        Some(format!("Bearer {GH_TOKEN_2}").as_str())
    );
    let used = f.uses().await.last().cloned().unwrap();
    assert_eq!(used["result"], "ok");
    let _ = hidden;
}

#[tokio::test]
async fn a_session_over_its_rate_gets_a_plain_rate_limited_refusal() {
    let f = fx_with(Limits {
        per_session_per_min: 2,
        flood_window: Duration::from_millis(100),
        ..Limits::default()
    })
    .await;
    let c = f.github("main", GH_TOKEN).await;
    f.member(c.id, &["read_repo"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_repo"], &[]).await;
    let s = f.session(&["read_repo"]).await;
    for _ in 0..2 {
        f.gh.push(200, &[], ISSUE);
        assert!(f.ask(&s, "github.get_issue", get("acme/app")).await.ok);
    }
    let r = f.ask(&s, "github.get_issue", get("acme/app")).await;
    assert_eq!((r.ok, code(&r)), (false, "rate_limited"));
    assert_eq!(f.gh.seen().len(), 2);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(f.uses().await.last().unwrap()["code"], "rate_limited");
    // Another session has its own budget.
    let other = f.session(&["read_repo"]).await;
    f.gh.push(200, &[], ISSUE);
    assert!(f.ask(&other, "github.get_issue", get("acme/app")).await.ok);
}

#[tokio::test]
async fn a_connection_over_its_rate_refuses_every_session() {
    let f = fx_with(Limits {
        per_connection_per_min: 1,
        ..Limits::default()
    })
    .await;
    let c = f.github("main", GH_TOKEN).await;
    f.member(c.id, &["read_repo"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_repo"], &[]).await;
    let (s1, s2) = (
        f.session(&["read_repo"]).await,
        f.session(&["read_repo"]).await,
    );
    f.gh.push(200, &[], ISSUE);
    assert!(f.ask(&s1, "github.get_issue", get("acme/app")).await.ok);
    let r = f.ask(&s2, "github.get_issue", get("acme/app")).await;
    assert_eq!((r.ok, code(&r)), (false, "rate_limited"));
    assert_eq!(f.gh.seen().len(), 1);
}

#[tokio::test]
async fn parallel_calls_past_the_cap_wait_and_only_a_full_queue_refuses() {
    let f = fx_with(Limits {
        concurrent_per_session: 1,
        queue_per_session: 1,
        ..Limits::default()
    })
    .await;
    let c = f.jira("acme").await;
    f.member(c.id, &["read_issues"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_issues"], &[]).await;
    let s = f.session(&["read_issues"]).await;
    let one = format!("GET {}", jt::site_path("/issue/ABC-1"));
    f.j.fake.on(&one, |_| {
        jt::Reply::json(
            200,
            json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}}}),
        )
        .delayed(300)
    });
    let args = || json!({"key": "ABC-1"});
    // One runs, one waits for its place (and still succeeds), the third finds the queue full.
    let (a, b, c3) = tokio::join!(
        f.ask(&s, "jira.get_issue", args()),
        f.ask(&s, "jira.get_issue", args()),
        f.ask(&s, "jira.get_issue", args())
    );
    let mut ok = [a.ok, b.ok, c3.ok];
    ok.sort_unstable();
    assert_eq!(ok, [false, true, true], "{a:?} {b:?} {c3:?}");
    let refused = [&a, &b, &c3].into_iter().find(|r| !r.ok).unwrap();
    assert_eq!(code(refused), "rate_limited");
    assert!(
        f.ask(&s, "jira.get_issue", args()).await.ok,
        "the place is free again"
    );
}

#[tokio::test]
async fn ten_thousand_refused_calls_write_one_row_with_the_exact_count_by_operation() {
    for mode in ["1", "0"] {
        let f = fx_with(Limits {
            per_session_per_min: 5,
            flood_window: Duration::from_millis(300),
            ..Limits::default()
        })
        .await;
        let c = f.github("main", GH_TOKEN).await;
        f.member(c.id, &["read_repo"], &[]).await;
        let s = f.session(&["read_repo"]).await;
        f.mode(mode).await;
        for i in 0..10_000u64 {
            let tool = if i % 2 == 0 {
                "github.get_issue"
            } else {
                "github.get_repo"
            };
            f.ask(&s, tool, json!({"repo": "acme/app", "number": i + 1}))
                .await;
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
        let rows = f.uses().await;
        assert!(rows.len() <= 7, "mode {mode}: {} rows", rows.len());
        let flood: Vec<_> = rows.iter().filter(|r| r.get("count").is_some()).collect();
        assert_eq!(flood.len(), 1, "one aggregated row for the window");
        assert_eq!(
            flood[0]["count"],
            10_000 - 5,
            "the exact count, mode {mode}"
        );
        let ops = flood[0]["ops"].as_object().unwrap();
        let sum: u64 = ops.values().map(|v| v.as_u64().unwrap()).sum();
        assert_eq!(sum, 10_000 - 5);
        assert!(ops.keys().all(|k| k.starts_with("github.")), "{ops:?}");
        assert!(f.gh.seen().is_empty());
    }
}

#[tokio::test]
async fn a_write_that_outlives_the_wait_is_not_called_timed_out_and_still_finishes() {
    let f = fx_with(Limits {
        timeout: Duration::from_millis(100),
        ..Limits::default()
    })
    .await;
    let c = f.jira("acme").await;
    f.member(c.id, &["write_issues"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["write_issues"], &[])
        .await;
    let s = f.session(&["write_issues"]).await;
    let issue = format!("GET {}", jt::site_path("/issue/ABC-1"));
    f.j.fake.reply(
        &issue,
        200,
        json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}}}),
    );
    let post = format!("POST {}", jt::site_path("/issue/ABC-1/comment"));
    f.j.fake.on(&post, |_| {
        jt::Reply::json(201, json!({"id": "10"})).delayed(600)
    });
    let r = f
        .ask(
            &s,
            "jira.add_comment",
            json!({"key": "ABC-1", "body": "hello"}),
        )
        .await;
    assert_eq!((r.ok, code(&r)), (false, "outcome_unknown"));
    assert!(r.message.unwrap().contains("check before retrying"));
    // The write is not dropped: it lands, and is audited when it does.
    let mut late = None;
    for _ in 0..40 {
        late = f.uses().await.into_iter().find(|u| u["code"] == "late_ok");
        if late.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(late.is_some(), "the late completion is audited");
    assert_eq!(f.j.fake.count(&post), 1);
    // A read keeps `timed_out`.
    let one = format!("GET {}", jt::site_path("/issue/ABC-2"));
    f.j.fake
        .on(&one, |_| jt::Reply::json(200, json!({})).delayed(1500));
    f.member(c.id, &["read_issues", "write_issues"], &[]).await;
    f.grant(
        c.id,
        ("agent", "bot"),
        &["read_issues", "write_issues"],
        &[],
    )
    .await;
    let s2 = f.session(&["read_issues"]).await;
    let r = f.ask(&s2, "jira.get_issue", json!({"key": "ABC-2"})).await;
    assert_eq!(code(&r), "timed_out");
}

#[tokio::test]
async fn a_connection_the_service_says_is_nearly_out_is_refused_locally_until_it_resets() {
    let (f, _c, s) = limited().await;
    let reset = (crate::scheduler::unix_secs(NOW).unwrap() + 3600).to_string();
    f.gh.push(
        200,
        &[
            ("x-ratelimit-remaining", "3"),
            ("x-ratelimit-reset", &reset),
            ("x-ratelimit-limit", "5000"),
        ],
        ISSUE,
    );
    assert!(f.ask(&s, "github.get_issue", get("tools/x")).await.ok);
    // The reset is in the real clock's past or future; the gate uses the real clock, so use a
    // reset far enough ahead.
    let far = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 1800)
        .to_string();
    f.gh.push(
        200,
        &[("x-ratelimit-remaining", "3"), ("x-ratelimit-reset", &far)],
        ISSUE,
    );
    let other = f.session(&["read_repo"]).await;
    assert!(f.ask(&other, "github.get_issue", get("tools/x")).await.ok);
    let r = f.ask(&s, "github.get_issue", get("tools/x")).await;
    assert_eq!((r.ok, code(&r)), (false, "connection_busy"));
    assert!(r.message.unwrap().contains("can be used again at"));
    assert_eq!(
        f.gh.seen().len(),
        2,
        "nothing went upstream for the refused call"
    );
}

#[tokio::test]
async fn arguments_and_results_are_bounded() {
    let (f, _c, s) = limited().await;
    let big = "x".repeat(ainkrad_proto::v2::MAX_ARGS_BYTES + 10);
    let r = f
        .ask(
            &s,
            "github.get_issue",
            json!({"repo": "acme/app", "number": 1, "query": {"q": big}}),
        )
        .await;
    assert_eq!((r.ok, code(&r)), (false, "bad_args"));
    assert!(f.gh.seen().is_empty());
    let huge = format!(
        r#"{{"body":"{}"}}"#,
        "y".repeat(ainkrad_proto::v2::MAX_RESULT_BYTES + 10)
    );
    f.gh.push(200, &[], &huge);
    let r = f.ask(&s, "github.get_issue", get("acme/app")).await;
    assert_eq!((r.ok, code(&r)), (false, "too_large"));
    assert!(r.result.is_none() && r.message.unwrap().len() < 200);
}

#[tokio::test]
async fn a_call_that_does_not_come_back_in_time_is_timed_out() {
    let f = fx_with(Limits {
        timeout: Duration::from_millis(100),
        ..Limits::default()
    })
    .await;
    let c = f.jira("acme").await;
    f.member(c.id, &["read_issues"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_issues"], &[]).await;
    let s = f.session(&["read_issues"]).await;
    let one = format!("GET {}", jt::site_path("/issue/ABC-1"));
    f.j.fake
        .on(&one, |_| jt::Reply::json(200, json!({})).delayed(1500));
    let r = f.ask(&s, "jira.get_issue", json!({"key": "ABC-1"})).await;
    assert_eq!((r.ok, code(&r)), (false, "timed_out"));
    assert_eq!(
        f.status(c.id).await.0,
        "active",
        "a slow answer says nothing about health"
    );
    let u = f.uses().await.last().cloned().unwrap();
    assert_eq!(
        (u["result"].as_str(), u["code"].as_str()),
        (Some("error"), Some("timed_out"))
    );
}

async fn jira_pair(limits: Limits) -> (Fx, Connection, String, String) {
    let f = fx_with(limits).await;
    let c = f.jira("acme").await;
    f.member(c.id, &["read_issues"], &[]).await;
    f.grant(c.id, ("agent", "bot"), &["read_issues"], &[]).await;
    let s = f.session(&["read_issues"]).await;
    let one = format!("GET {}", jt::site_path("/issue/ABC-1"));
    f.j.fake.on(&one, |_| {
        jt::Reply::json(
            200,
            json!({"key": "ABC-1", "fields": {"project": {"key": "ABC"}}}),
        )
        .delayed(400)
    });
    (f, c, s, one)
}

#[tokio::test]
async fn a_call_that_waited_does_not_run_if_its_grant_was_revoked_meanwhile() {
    let (f, c, s, one) = jira_pair(Limits {
        concurrent_per_session: 1,
        ..Limits::default()
    })
    .await;
    let args = || json!({"key": "ABC-1"});
    let (a, b, ()) = tokio::join!(
        f.ask(&s, "jira.get_issue", args()),
        async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            f.ask(&s, "jira.get_issue", args()).await
        },
        async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            grants::revoke(&f.j.pool, c.id, ("role", "member"), who())
                .await
                .unwrap();
        }
    );
    assert!(a.ok, "the running call was already admitted");
    assert_eq!((b.ok, code(&b)), (false, "not_granted"), "{b:?}");
    assert_eq!(
        f.j.fake.count(&one),
        1,
        "the queued call never went upstream"
    );
}

#[tokio::test]
async fn a_call_that_waited_does_not_run_if_its_session_ended_or_the_broker_went_off() {
    for ending in ["ended", "mode"] {
        let (f, _c, s, one) = jira_pair(Limits {
            concurrent_per_session: 1,
            ..Limits::default()
        })
        .await;
        let args = || json!({"key": "ABC-1"});
        let (_a, b, ()) = tokio::join!(
            f.ask(&s, "jira.get_issue", args()),
            async {
                tokio::time::sleep(Duration::from_millis(60)).await;
                f.ask(&s, "jira.get_issue", args()).await
            },
            async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                match ending {
                    "ended" => {
                        let over = json!({"kind": "succeeded"});
                        sessions::end(&f.j.pool, &s, "ended", &over, NOW)
                            .await
                            .unwrap();
                    }
                    _ => f.mode("0").await,
                }
            }
        );
        let want = if ending == "ended" {
            "session_over"
        } else {
            "secrets_disabled"
        };
        assert_eq!((b.ok, code(&b)), (false, want), "{ending}");
        assert_eq!(f.j.fake.count(&one), 1, "{ending}: not run");
    }
}

#[tokio::test]
async fn a_call_that_waits_too_long_for_its_place_is_refused_queue_timeout() {
    let (f, _c, s, one) = jira_pair(Limits {
        concurrent_per_session: 1,
        queue_wait: Duration::from_millis(100),
        ..Limits::default()
    })
    .await;
    let args = || json!({"key": "ABC-1"});
    let (a, b) = tokio::join!(f.ask(&s, "jira.get_issue", args()), async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        f.ask(&s, "jira.get_issue", args()).await
    });
    assert!(a.ok);
    assert_eq!((b.ok, code(&b)), (false, "queue_timeout"));
    assert_eq!(f.j.fake.count(&one), 1);
}
