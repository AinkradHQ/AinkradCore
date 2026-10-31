//! Off-box anchors (E1-10.4): a rebuilt, truncated or rolled-back chain fails against anchors it
//! cannot reach; a clean chain, a key rotation, two sinks and a flaky bucket all behave.

use super::fixture::*;
use super::*;
use crate::auth::identity::WINDOW;
use ainkrad_proto::v2::rotation_message;
use std::sync::Arc;
use std::sync::atomic::Ordering;

// ---- tests ----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_clean_chain_passes_from_the_bucket_and_from_a_file_and_anchors_hold_no_audit_content() {
    let fake = fake().await;
    let h = home(3).await;
    let id = Identity::ephemeral();
    let file = h.dir.join("anchors.jsonl");
    let s = Sinks {
        bucket: Some(bucket(&fake)),
        file: Some(file.clone()),
    };
    let first = anchored(&h, &id, &s).await;
    add(&h, 4).await;
    let second = anchored(&h, &id, &s).await;
    let (a, b): (Statement, Statement) = (
        serde_json::from_str(&first.statement).unwrap(),
        serde_json::from_str(&second.statement).unwrap(),
    );
    assert_eq!(
        (a.anchor_seq, b.anchor_seq, b.head_seq, b.rows),
        (1, 2, 4, 4)
    );
    assert_eq!(b.prev_anchor_hash, hash_of(&first.statement));

    let in_bucket = read_bucket(&bucket(&fake)).await.unwrap();
    assert_eq!(in_bucket.len(), 2);
    let r = checked(&h, &in_bucket, Some(&id.fp)).await.unwrap();
    assert_eq!((r.anchors, r.last.head_seq), (2, 4));
    let from_file = read_lines(&file).unwrap();
    assert_eq!(
        checked(&h, &from_file, Some(&id.fp)).await.unwrap().anchors,
        2
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );

    for l in lines(&fake) {
        assert!(
            !l.contains("audit-content") && !l.contains("thing.done") && !l.contains(SECRET),
            "{l}"
        );
    }
    // The key is under the distinct prefix with a unique name each time.
    let keys = bucket(&fake).list("core/anchors/").await.unwrap();
    assert_eq!(keys.len(), 2);
    assert!(
        keys.iter()
            .all(|k| k.starts_with("core/anchors/00000000000")),
        "{keys:?}"
    );
}

#[tokio::test]
async fn a_chain_rebuilt_after_the_last_anchor_fails_though_verify_passes_it() {
    let fake = fake().await;
    let h = home(5).await;
    let id = Identity::ephemeral();
    anchored(&h, &id, &sinks(&fake)).await;
    let l = lines(&fake);
    checked(&h, &l, Some(&id.fp)).await.expect("clean first");
    rebuild_from(&h, 2).await;
    let w = why(checked(&h, &l, Some(&id.fp)).await);
    assert!(w.contains("rebuilt"), "{w}");
}

#[tokio::test]
async fn a_truncated_chain_fails_even_with_the_counter_reset_and_new_rows_appended() {
    let fake = fake().await;
    let h = home(5).await;
    let id = Identity::ephemeral();
    anchored(&h, &id, &sinks(&fake)).await;
    let l = lines(&fake);
    sql(&h.pool, "DROP TRIGGER audit_events_no_delete").await;
    sql(&h.pool, "DELETE FROM audit_events WHERE seq > 3").await;
    sql(
        &h.pool,
        "UPDATE sqlite_sequence SET seq = 3 WHERE name = 'audit_events'",
    )
    .await;
    // The gap `verify` documents: it cannot see a tail removed with its counter.
    assert_eq!(chain::verify_db(&h.pool).await.unwrap().unwrap().rows, 3);
    let w = why(checked(&h, &l, None).await);
    assert!(w.contains("truncated"), "{w}");
    // Writing new rows over the removed tail changes the hash at the anchored seq.
    add(&h, 40).await;
    add(&h, 50).await;
    let w = why(checked(&h, &l, None).await);
    assert!(w.contains("rebuilt"), "{w}");
}

#[tokio::test]
async fn bad_anchors_are_refused() {
    let fake = fake().await;
    let h = home(3).await;
    let (id, other) = (Identity::ephemeral(), Identity::ephemeral());
    let s = sinks(&fake);
    for _ in 0..3 {
        anchored(&h, &id, &s).await;
    }
    let l = lines(&fake); // anchors 1, 2, 3 in name order
    assert_eq!(checked(&h, &l, Some(&id.fp)).await.unwrap().anchors, 3);

    // Edited statement: the signature no longer holds.
    let edited = l[2].replace(r#"\"rows\":3"#, r#"\"rows\":2"#);
    assert_ne!(edited, l[2]);
    assert!(
        why(checked(&h, &[l[0].clone(), l[1].clone(), edited], None).await).contains("signature")
    );
    // A missing middle anchor.
    assert!(why(checked(&h, &[l[0].clone(), l[2].clone()], None).await).contains("missing"));
    // The same anchor twice is one; a different anchor at its number is a fork.
    assert_eq!(
        checked(&h, &[l[0].clone(), l[0].clone()], None)
            .await
            .unwrap()
            .anchors,
        1
    );
    let fork = anchor_once(
        &h.pool,
        &home(3).await.dir,
        &other,
        &Sinks {
            bucket: None,
            file: Some(h.dir.join("f")),
        },
        &at(5),
    )
    .await
    .unwrap()
    .unwrap();
    let fork = serde_json::to_string(&fork).unwrap();
    assert!(why(checked(&h, &[l[0].clone(), fork], None).await).contains("share sequence"));
    // The wrong signer for the pin, an unknown key change, garbage, nothing.
    assert!(why(checked(&h, &l, Some(&other.fp)).await).contains("expected"));
    assert!(why(checked(&h, &["not json".to_owned()], None).await).contains("readable"));
    assert!(why(checked(&h, &[], None).await).contains("no anchors"));
    // Another key continuing the chain with no rotation statement is refused.
    let mut st: Statement =
        serde_json::from_str(&serde_json::from_str::<Signed>(&l[2]).unwrap().statement).unwrap();
    st.anchor_seq = 4;
    st.core_fp = other.fp.clone();
    st.prev_anchor_hash = hash_of(&serde_json::from_str::<Signed>(&l[2]).unwrap().statement);
    let text = serde_json::to_string(&st).unwrap();
    let hijack = Signed {
        sig: b64(&other.sign(&message(&text))),
        spki: b64(&other.spki),
        statement: text,
        rotation: None,
    };
    let mut all = l.clone();
    all.push(serde_json::to_string(&hijack).unwrap());
    assert!(why(checked(&h, &all, None).await).contains("no valid rotation"));
}

#[tokio::test]
async fn a_key_rotation_keeps_verifying_and_a_missing_or_forged_statement_does_not() {
    let fake = fake().await;
    let h = home(3).await;
    let old = Identity::load_at(&h.dir, 1_000).unwrap();
    let s = sinks(&fake);
    anchored(&h, &old, &s).await;
    Identity::rotate(&h.dir, 1_000).unwrap();
    let pending = Identity::load_readonly(&h.dir).unwrap();
    assert!(pending.rotation.is_some());
    anchored(&h, &pending, &s).await; // files the statement under anchors/rotations.json
    Identity::announce(&h.dir, 1_000).unwrap();
    let new = Identity::load_at(&h.dir, 1_000 + WINDOW).unwrap();
    assert_ne!(new.fp, old.fp);
    add(&h, 4).await;
    let third = anchored(&h, &new, &s).await;
    assert!(
        third.rotation.is_some(),
        "the first anchor of the new key carries the statement"
    );

    let l = lines(&fake);
    let r = checked(&h, &l, Some(&new.fp)).await.unwrap();
    assert_eq!(r.anchors, 3);
    assert!(
        why(checked(&h, &l, Some(&old.fp)).await).contains("expected"),
        "the pin follows the rotation"
    );

    let last = l.last().unwrap().clone();
    let mut signed: Signed = serde_json::from_str(&last).unwrap();
    let real = signed.rotation.take().unwrap();
    let mut without = l.clone();
    *without.last_mut().unwrap() = serde_json::to_string(&signed).unwrap();
    assert!(why(checked(&h, &without, None).await).contains("no valid rotation"));
    signed.rotation = Some(Rotation {
        sig: b64(&Identity::ephemeral().sign(&rotation_message(&real))),
        ..real
    });
    let mut forged = l.clone();
    *forged.last_mut().unwrap() = serde_json::to_string(&signed).unwrap();
    assert!(why(checked(&h, &forged, None).await).contains("no valid rotation"));
}

#[tokio::test]
async fn concurrent_anchors_take_turns_and_stay_one_chain_and_a_new_home_continues_from_the_bucket()
{
    let fake = fake().await;
    let h = home(2).await;
    let id = Identity::ephemeral();
    let s = sinks(&fake);
    let c = at(2_000);
    let (a, b, c3, d) = tokio::join!(
        anchor_once(&h.pool, &h.dir, &id, &s, &c),
        anchor_once(&h.pool, &h.dir, &id, &s, &c),
        anchor_once(&h.pool, &h.dir, &id, &s, &c),
        anchor_once(&h.pool, &h.dir, &id, &s, &c),
    );
    for r in [a, b, c3, d] {
        r.unwrap().unwrap();
    }
    assert_eq!(fake.puts.load(Ordering::SeqCst), 4);
    let all = read_bucket(&bucket(&fake)).await.unwrap(); // four keys: two LIST pages
    assert_eq!(checked(&h, &all, Some(&id.fp)).await.unwrap().anchors, 4);

    // Restored on a new box with no anchor state: it asks the bucket where the chain stands.
    fs::remove_file(dir(&h.dir).join("head.json")).unwrap();
    let next = anchored(&h, &id, &s).await;
    let st: Statement = serde_json::from_str(&next.statement).unwrap();
    assert_eq!(st.anchor_seq, 5);
    assert_eq!(
        checked(&h, &read_bucket(&bucket(&fake)).await.unwrap(), None)
            .await
            .unwrap()
            .anchors,
        5
    );
}

#[tokio::test]
async fn the_bucket_never_overwrites_and_names_are_unique() {
    let fake = fake().await;
    let b = bucket(&fake);
    let p = std::env::temp_dir().join(format!("core-anchor-put-{}", std::process::id()));
    fs::write(&p, b"one").unwrap();
    b.put_new("core/other/x", &p).await.unwrap();
    fs::write(&p, b"two").unwrap();
    assert!(
        b.put_new("core/other/x", &p).await.is_err(),
        "the create-only bucket refuses it"
    );
    let _ = fs::remove_file(&p);
    assert_eq!(fake.objects.lock().unwrap()["core/other/x"], b"one");
    // Two anchors in the same second still get different keys.
    let h = home(1).await;
    let id = Identity::ephemeral();
    let (s1, s2) = (sinks(&fake), sinks(&fake));
    anchor_once(&h.pool, &h.dir, &id, &s1, &at(7))
        .await
        .unwrap();
    anchor_once(&h.pool, &h.dir, &id, &s2, &at(7))
        .await
        .unwrap();
    assert_eq!(b.list("core/anchors/0").await.unwrap().len(), 2);
}

#[test]
fn the_schedule_backs_off_up_to_the_interval_and_resets() {
    let mut s = Schedule::new(100, Duration::from_secs(3_600));
    assert!(s.due(100));
    s.fail(100);
    assert_eq!(s.next, 130);
    assert!(!s.due(129) && s.due(130));
    s.fail(130);
    assert_eq!(s.next, 190);
    for _ in 0..30 {
        s.fail(200);
    }
    assert_eq!(s.next, 200 + 3_600, "never later than one interval");
    s.ok(5_000);
    assert_eq!(s.next, 8_600);
    s.fail(8_600);
    assert_eq!(s.next, 8_630, "the backoff restarted");
}

#[tokio::test]
async fn an_unreachable_bucket_is_logged_and_retried_without_touching_the_log_or_the_state() {
    let fake = fake().await;
    let h = home(3).await;
    let id = Arc::new(Identity::ephemeral());
    let job = AnchorJob {
        pool: h.pool.clone(),
        home: h.dir.clone(),
        identity: id.clone(),
        sinks: Sinks {
            bucket: Some(bucket(&fake)),
            file: Some(h.dir.join("a.jsonl")),
        },
        clock: at(10_000),
        interval: Duration::from_secs(3_600),
    };
    let rows = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_events")
            .fetch_one(&h.pool)
            .await
            .unwrap()
    };
    let before = rows().await;
    fake.down.store(true, Ordering::SeqCst);
    let err = anchor_once(&h.pool, &h.dir, &id, &job.sinks, &job.clock)
        .await
        .unwrap_err();
    assert!(
        err.contains("503") && !err.contains(SECRET) && !err.contains("AKPLANTED"),
        "{err}"
    );

    let mut sched = Schedule::new(10_000, job.interval);
    assert!(job.step(&mut sched).await);
    assert_eq!(sched.next, 10_030);
    *job.clock.0.lock().unwrap() = 10_010;
    assert!(!job.step(&mut sched).await, "not due: no attempt");
    *job.clock.0.lock().unwrap() = 10_030;
    assert!(job.step(&mut sched).await);
    assert_eq!(sched.next, 10_090);
    assert!(
        !dir(&h.dir).join("head.json").exists() && !h.dir.join("a.jsonl").exists(),
        "nothing recorded as anchored"
    );
    assert_eq!(rows().await, before, "the audit log is untouched");

    fake.down.store(false, Ordering::SeqCst);
    *job.clock.0.lock().unwrap() = 10_090;
    assert!(job.step(&mut sched).await);
    assert_eq!(sched.next, 10_090 + 3_600);
    assert_eq!(fake.puts.load(Ordering::SeqCst), 1);
    assert_eq!(read_lines(&h.dir.join("a.jsonl")).unwrap().len(), 1);
    assert_eq!(rows().await, before);
}

#[tokio::test]
async fn a_broken_chain_is_never_anchored_and_an_empty_one_has_nothing_to_anchor() {
    let fake = fake().await;
    let id = Identity::ephemeral();
    let empty = home(0).await;
    assert!(
        anchor_once(&empty.pool, &empty.dir, &id, &sinks(&fake), &at(1))
            .await
            .unwrap()
            .is_none()
    );
    let h = home(3).await;
    rebuild_from(&h, 2).await;
    sql(
        &h.pool,
        "UPDATE audit_events SET hash = zeroblob(32) WHERE seq = 3",
    )
    .await;
    let e = anchor_once(&h.pool, &h.dir, &id, &sinks(&fake), &at(1))
        .await
        .unwrap_err();
    assert!(e.contains("not anchoring"), "{e}");
    assert_eq!(fake.puts.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_directory_of_copied_files_verifies_like_the_bucket() {
    let h = home(2).await;
    let id = Identity::ephemeral();
    let (a, b) = (h.dir.join("copy/a.jsonl"), h.dir.join("copy/b.jsonl"));
    fs::create_dir_all(a.parent().unwrap()).unwrap();
    anchor_once(
        &h.pool,
        &h.dir,
        &id,
        &Sinks {
            bucket: None,
            file: Some(a),
        },
        &at(1),
    )
    .await
    .unwrap();
    anchor_once(
        &h.pool,
        &h.dir,
        &id,
        &Sinks {
            bucket: None,
            file: Some(b),
        },
        &at(2),
    )
    .await
    .unwrap();
    let l = read_lines(&h.dir.join("copy")).unwrap();
    assert_eq!(checked(&h, &l, Some(&id.fp)).await.unwrap().anchors, 2);
}

#[tokio::test]
async fn a_crash_after_the_put_or_a_stale_head_never_repeats_a_sequence_number() {
    let fake = fake().await;
    let h = home(3).await;
    let id = Identity::ephemeral();
    let s = sinks(&fake);
    let seq = |a: &Signed| {
        serde_json::from_str::<Statement>(&a.statement)
            .unwrap()
            .anchor_seq
    };
    assert_eq!(seq(&anchored(&h, &id, &s).await), 1);
    let head = dir(&h.dir).join("head.json");
    let after_one = fs::read(&head).unwrap();
    assert_eq!(seq(&anchored(&h, &id, &s).await), 2);
    // The PUT of anchor 2 landed but head.json never did (a crash), or an old copy came back.
    fs::write(&head, &after_one).unwrap();
    assert_eq!(
        seq(&anchored(&h, &id, &s).await),
        3,
        "the bucket's newest wins"
    );
    // head.json lost altogether.
    fs::remove_file(&head).unwrap();
    assert_eq!(seq(&anchored(&h, &id, &s).await), 4);

    let all = read_bucket(&bucket(&fake)).await.unwrap();
    assert_eq!(all.len(), 4);
    assert_eq!(
        checked(&h, &all, Some(&id.fp)).await.unwrap().anchors,
        4,
        "no fork, verify stays ok"
    );
    let keys = bucket(&fake).list("core/anchors/").await.unwrap();
    assert_eq!(keys[0], "core/anchors/000000000001.json", "{keys:?}");
}

#[tokio::test]
async fn a_junk_object_at_the_newest_name_stops_the_anchor_loudly() {
    let fake = fake().await;
    let h = home(2).await;
    let id = Identity::ephemeral();
    let s = sinks(&fake);
    let first = anchored(&h, &id, &s).await;
    // Something that is not an anchor sits at the next name.
    let key = "core/anchors/000000000002.json";
    fake.objects
        .lock()
        .unwrap()
        .insert(key.to_owned(), b"{}\n".to_vec());
    // The newest in the bucket is now "2", which is not an anchor: refused loudly, nothing forked.
    let e = anchor_once(&h.pool, &h.dir, &id, &s, &at(9))
        .await
        .unwrap_err();
    assert!(e.contains("000000000002.json"), "{e}");
    assert_eq!(fake.objects.lock().unwrap().len(), 2);
    assert_eq!(
        serde_json::from_str::<Statement>(&first.statement)
            .unwrap()
            .anchor_seq,
        1
    );
}

#[tokio::test]
async fn transport_errors_name_no_host_url_or_bucket() {
    let dead = || {
        Bucket::new(
            "http://127.0.0.1:1",
            "secretbucket",
            "r",
            "core/",
            "AK".into(),
            SECRET.into(),
        )
        .unwrap()
    };
    let h = home(1).await;
    let id = Identity::ephemeral();
    let sink = Sinks {
        bucket: Some(dead()),
        file: None,
    };
    let mut errors = vec![
        anchor_once(&h.pool, &h.dir, &id, &sink, &at(1))
            .await
            .unwrap_err(),
    ];
    let tmp = h.dir.join("probe");
    fs::write(&tmp, b"x").unwrap();
    errors.push(
        dead()
            .put_new("core/anchors/k", &tmp)
            .await
            .unwrap_err()
            .to_string(),
    );
    errors.push(
        dead()
            .get("core/anchors/k", &h.dir.join("out"))
            .await
            .unwrap_err()
            .to_string(),
    );
    errors.push(dead().list("core/").await.unwrap_err().to_string());
    for e in errors {
        for leak in ["127.0.0.1", "http", "secretbucket", SECRET, ":1"] {
            assert!(!e.contains(leak), "{leak} in {e}");
        }
        assert!(e.contains("network error (connect)"), "{e}");
    }
}
