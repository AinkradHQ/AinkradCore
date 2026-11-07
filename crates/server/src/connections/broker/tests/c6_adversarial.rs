//! C6: the broker against a hostile caller. Every registered operation gets forged, garbage and
//! oversize arguments; hostile tool and session names are tried; the call cursor is walked against
//! a model and raced; none of it reaches a service, changes health or flows into the audit log.

use super::*;
use crate::store::connections::access::Step;

const MARK: &str = "FORGED-7c1e-marker";

/// Every operation name of every registered kind.
fn operations(f: &Fx) -> Vec<String> {
    f.reg
        .descriptors()
        .iter()
        .flat_map(|d| d.capabilities.iter())
        .flat_map(|c| c.operations.iter().map(|o| (*o).to_owned()))
        .collect()
}

fn deep(n: usize) -> Value {
    let mut v = json!(1);
    for _ in 0..n {
        v = json!([v]);
    }
    v
}

/// A broker whose per-session rate never gets in the way, a GitHub and a Jira connection with
/// every capability granted to the user and to agent `bot`, and a session allowed all of them.
async fn open() -> (Fx, String, [Connection; 2]) {
    let limits = Limits {
        per_session_per_min: 1_000_000,
        per_connection_per_min: 1_000_000,
        ..Limits::default()
    };
    let f = fx_with(limits).await;
    let gh = f.github("main", GH_TOKEN).await;
    let jira = f.jira("acme").await;
    let mut all: Vec<&str> = Vec::new();
    for c in [&gh, &jira] {
        let d = f.reg.get(&c.kind).unwrap().descriptor();
        let caps: Vec<&str> = d.capabilities.iter().map(|c| c.name).collect();
        f.member(c.id, &caps, &[]).await;
        f.grant(c.id, ("agent", "bot"), &caps, &[]).await;
        all.extend(caps);
    }
    let s = f.session(&all).await;
    (f, s, [gh, jira])
}

#[tokio::test]
async fn every_operation_refuses_forged_garbage_and_oversize_arguments_before_the_service() {
    let (f, s, conns) = open().await;
    let ops = operations(&f);
    assert!(ops.len() >= 20, "{} operations", ops.len());
    let huge = json!({ "note": "x".repeat(400 * 1024) });
    let mut bad: Vec<Value> = vec![
        Value::Null,
        json!(true),
        json!(1),
        json!("x"),
        json!([]),
        json!([1, 2]),
        huge,
        json!({"note": deep(1500)}),
        deep(1500),
    ];
    for key in [
        "user",
        "agent",
        "session",
        "connection",
        "connection_id",
        "capability",
        "allowlist",
        "runner",
        "tc_seq",
        "token",
        "authorization",
        "host",
        "url",
        "base_url",
        "headers",
        "cloud_id",
        "site",
    ] {
        bad.push(json!({ key: MARK }));
        bad.push(json!({ key: deep(50) }));
    }
    for op in &ops {
        for args in &bad {
            // Jira reads `null` as "no arguments" (a search with none is allowed and limited by
            // the grant's projects); every other shape is refused.
            if args.is_null() && op.starts_with("jira.") {
                continue;
            }
            let r = f.ask(&s, op, args.clone()).await;
            let asked = f.gh.seen().len() + f.j.fake.seen().len();
            assert_eq!(
                asked,
                0,
                "{op} reached a service with {}",
                args.to_string().chars().take(120).collect::<String>()
            );
            assert!(
                !r.ok,
                "{op} accepted {}",
                args.to_string().chars().take(80).collect::<String>()
            );
            let said = format!("{:?}", (&r.code, &r.message));
            assert!(
                !said.contains(MARK),
                "{op}: the refusal repeats the caller's text: {said}"
            );
        }
    }
    assert!(
        f.gh.seen().is_empty(),
        "GitHub was asked: {:?}",
        f.gh.seen().len()
    );
    assert!(f.j.fake.seen().is_empty(), "Jira was asked");
    for c in &conns {
        assert_eq!(
            f.status(c.id).await,
            ("active".to_owned(), None),
            "health moved"
        );
    }
    let audit = f.audit_text().await;
    assert!(
        !audit.contains(MARK),
        "the caller's text is in the audit log"
    );
    // Each call is one plain row, never its arguments.
    assert!(f.uses().await.iter().all(|u| u["result"] == "refused"));
}

#[tokio::test]
async fn hostile_tool_names_are_unknown_and_never_written_into_the_audit_log() {
    let (f, s, _) = open().await;
    let long = format!("github.{}", "z".repeat(10_000));
    let names = [
        "",
        ".",
        "github.",
        ".get_issue",
        "github",
        "GITHUB.get_issue",
        "github.get_issue ",
        "github.get_issue\0",
        "github.get_issue\n",
        "github..get_issue",
        "github.get_issue.x",
        "jira.get_issue/../github.get_issue",
        "\u{ff47}ithub.get_issue",
        "github.get_issu\u{e9}",
        "github.__proto__",
        long.as_str(),
        MARK,
        "github.FORGED-7c1e-marker",
    ];
    for name in names {
        let r = f
            .ask(&s, name, json!({"repo": "acme/app", "number": 1}))
            .await;
        assert_eq!((r.ok, code(&r)), (false, "unknown_tool"), "{name:?}");
    }
    assert!(f.gh.seen().is_empty() && f.j.fake.seen().is_empty());
    let audit = f.audit_text().await;
    assert!(
        !audit.contains(MARK) && !audit.contains("zzzzzzzzzz"),
        "a tool name is in the audit log"
    );
}

#[tokio::test]
async fn the_call_cursor_matches_a_model_and_a_number_is_taken_exactly_once() {
    let f = fx().await;
    let s = f.bare_session(RUNNER).await;
    // No such session: nothing is taken and no row appears.
    let ghost = access::advance(&f.j.pool, "as_nosuchsession", 1)
        .await
        .unwrap();
    assert_eq!(ghost, Step::Stale);
    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM core_session_connections WHERE session = 'as_nosuchsession'",
    )
    .fetch_one(&f.j.pool)
    .await
    .unwrap();
    assert_eq!(rows, 0);
    // A seeded walk of numbers around the cursor.
    let mut seed: u64 = 0xC6_5EED;
    let mut cur: u64 = 0;
    for step in 0..300 {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let d = (seed >> 33) % 8;
        let seq = (cur + d).saturating_sub(2);
        let want = match seq {
            n if n <= cur => Step::Stale,
            n if n == cur + 1 => Step::Take,
            _ => Step::Gap,
        };
        let got = access::advance(&f.j.pool, &s, seq).await.unwrap();
        assert_eq!(got, want, "step {step}: seq {seq} with the cursor at {cur}");
        cur = cur.max(seq);
        let held = access::load(&f.j.pool, &s)
            .await
            .unwrap()
            .unwrap()
            .grant
            .tc_seq;
        assert_eq!(held, cur, "step {step}");
    }
    // Zero, and the largest numbers: never taken, and the cursor never goes back.
    assert_eq!(
        access::advance(&f.j.pool, &s, 0).await.unwrap(),
        Step::Stale
    );
    let top = access::advance(&f.j.pool, &s, u64::MAX).await.unwrap();
    assert_eq!(top, Step::Gap);
    assert_eq!(
        access::advance(&f.j.pool, &s, cur + 1).await.unwrap(),
        Step::Stale
    );
    assert_eq!(
        access::advance(&f.j.pool, &s, u64::MAX).await.unwrap(),
        Step::Stale
    );
}

#[tokio::test]
async fn sixteen_runners_sending_one_number_at_once_take_it_exactly_once() {
    let f = fx().await;
    let s = f.bare_session(RUNNER).await;
    for seq in 1..=5u64 {
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let (pool, s) = (f.j.pool.clone(), s.clone());
            tasks.push(tokio::spawn(async move {
                access::advance(&pool, &s, seq).await.unwrap()
            }));
        }
        let mut takes = 0;
        for t in tasks {
            match t.await.unwrap() {
                Step::Take => takes += 1,
                Step::Stale => {}
                Step::Gap => panic!("seq {seq}: a gap in an in-order run"),
            }
        }
        assert_eq!(takes, 1, "seq {seq} was taken {takes} times");
    }
}

/// BUG (found by C6): the per-session rate gate is keyed by the session name the runner SENDS, so
/// a runner that invents a new name per call is never limited, and each call about a session that
/// does not exist writes its own `connection.used` row (attributed to user 0). Audit growth is
/// linear in what an authenticated runner chooses to send. Fixing it means deciding what an
/// unattributable refusal is worth in the audit log (the existing
/// `a_session_that_is_over_the_wrong_runner_and_a_stranger_are_refused` expects a row each), so
/// it is reported, not changed here.
#[tokio::test]
#[ignore = "BUG: calls about invented session names each write an audit row (no per-runner flood gate)"]
async fn a_runner_cannot_write_an_audit_row_per_invented_session_name() {
    let f = fx().await;
    let c = f.github("main", GH_TOKEN).await;
    f.member(c.id, &["read_repo"], &[]).await;
    let before = f.uses().await.len();
    for n in 0..400 {
        let r = f
            .ask(
                &format!("as_invented{n:04}"),
                "github.get_issue",
                json!({"repo": "a/b", "number": 1}),
            )
            .await;
        assert_eq!((r.ok, code(&r)), (false, "session"));
    }
    let rows = f.uses().await.len() - before;
    assert!(
        rows <= 64,
        "400 calls with invented session names wrote {rows} audit rows"
    );
}
