//! Anchors against a hostile or failing bucket (E1-10.4): crashes, forgeries, junk, leaks.

use super::fixture::*;
use super::*;
use crate::scheduler::iso_of_unix;
use std::sync::atomic::Ordering;

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

    let all = read_bucket(&bucket(&fake)).await.unwrap().unwrap();
    assert_eq!(all.len(), 4);
    assert_eq!(
        checked(&h, &all, Some(&id.fp)).await.unwrap().anchors,
        4,
        "no fork, verify stays ok"
    );
    let keys = bucket(&fake).list("core/anchors/").await.unwrap();
    assert_eq!(keys[0], "core/anchors/000000000001.json", "{keys:?}");
}

fn put_raw(f: &Fake, key: &str, body: &str) {
    f.objects
        .lock()
        .unwrap()
        .insert(key.to_owned(), body.as_bytes().to_vec());
}

/// A well-formed anchor signed by `by`, claiming `seq`, stored under `key`.
fn forged(f: &Fake, by: &Identity, seq: u64, key: &str) {
    let st = Statement {
        v: 1,
        core_fp: by.fp.clone(),
        anchor_seq: seq,
        prev_anchor_hash: chain::GENESIS.to_owned(),
        head_seq: 1,
        head_hash: "00".repeat(32),
        rows: 1,
        at: iso_of_unix(1),
    };
    let statement = serde_json::to_string(&st).unwrap();
    let signed = Signed {
        sig: b64(&by.sign(&message(&statement))),
        spki: b64(&by.spki),
        statement,
        rotation: None,
    };
    put_raw(f, key, &serde_json::to_string(&signed).unwrap());
}

fn seq(a: &Signed) -> u64 {
    serde_json::from_str::<Statement>(&a.statement)
        .unwrap()
        .anchor_seq
}

#[tokio::test]
async fn forged_and_garbage_objects_never_panic_or_block_anchoring_and_read_as_tampering() {
    let fake = fake().await;
    let h = home(2).await;
    let (id, stranger) = (Identity::ephemeral(), Identity::ephemeral());
    let s = sinks(&fake);
    assert_eq!(seq(&anchored(&h, &id, &s).await), 1);
    // A stranger's self-signed anchor claiming u64::MAX under a far-out name.
    forged(&fake, &stranger, u64::MAX, "core/anchors/000000000900.json");
    // Our own key, valid signature, but the number does not match the name.
    forged(&fake, &id, 5, "core/anchors/000000000700.json");
    // Names that are not anchors, and junk under an anchor name.
    put_raw(&fake, "core/anchors/zzz", "junk");
    put_raw(&fake, "core/anchors/notes.json", "junk");
    put_raw(
        &fake,
        "core/anchors/000000000800.json",
        &"x".repeat(100_000),
    );
    // Anchoring walks past all of it to the newest valid one.
    let next = anchored(&h, &id, &s).await;
    assert_eq!(seq(&next), 2);
    // The evidence is not hidden: reading the bucket for verification is tampering (exit 3).
    let t = read_bucket(&bucket(&fake)).await.unwrap().unwrap_err();
    assert!(t.0.contains("anchor") || t.0.contains("named"), "{t}");
}

#[tokio::test]
async fn a_bad_signature_on_the_newest_object_is_skipped_and_the_taken_number_stops_the_write() {
    let fake = fake().await;
    let h = home(2).await;
    let id = Identity::ephemeral();
    let s = sinks(&fake);
    anchored(&h, &id, &s).await;
    // The real anchor 1 re-labelled as number 2 with an edited statement and no new signature.
    let mut one: Signed = serde_json::from_str(&lines(&fake)[0]).unwrap();
    one.statement = one
        .statement
        .replace("\"anchor_seq\":1", "\"anchor_seq\":2");
    put_raw(
        &fake,
        "core/anchors/000000000002.json",
        &serde_json::to_string(&one).unwrap(),
    );
    let before = fake.objects.lock().unwrap().len();
    // Walks back to 1, would write 2, finds the name taken by something else: loud, nothing written.
    let e = anchor_once(&h.pool, &h.dir, &id, &s, &at(9))
        .await
        .unwrap_err();
    assert!(e.contains("already taken"), "{e}");
    assert_eq!(fake.objects.lock().unwrap().len(), before);
    assert!(
        read_bucket(&bucket(&fake)).await.unwrap().is_err(),
        "and it reads as tampering"
    );
}

#[tokio::test]
async fn a_bucket_with_only_invalid_anchors_and_an_overflowing_head_refuse_instead_of_panicking() {
    let fake = fake().await;
    let h = home(2).await;
    let id = Identity::ephemeral();
    forged(
        &fake,
        &Identity::ephemeral(),
        1,
        "core/anchors/000000000001.json",
    );
    let e = anchor_once(&h.pool, &h.dir, &id, &sinks(&fake), &at(1))
        .await
        .unwrap_err();
    assert!(e.contains("no valid"), "{e}");
    assert_eq!(
        fake.puts.load(Ordering::SeqCst),
        0,
        "nothing bogus is written"
    );

    // A head.json at the top of the range (file sink only) cannot wrap to 0.
    private_dir(&dir(&h.dir)).unwrap();
    let max = Head {
        anchor_seq: u64::MAX,
        hash: "00".repeat(32),
        fp: id.fp.clone(),
    };
    fs::write(
        dir(&h.dir).join("head.json"),
        serde_json::to_vec(&max).unwrap(),
    )
    .unwrap();
    let only_file = Sinks {
        bucket: None,
        file: Some(h.dir.join("f.jsonl")),
    };
    let e = anchor_once(&h.pool, &h.dir, &id, &only_file, &at(1))
        .await
        .unwrap_err();
    assert!(e.contains("cannot grow"), "{e}");
    assert!(!h.dir.join("f.jsonl").exists());
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
