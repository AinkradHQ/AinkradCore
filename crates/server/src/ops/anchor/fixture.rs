//! Test fixtures for the anchors: a fake create-only S3, a database home, a fake clock.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ainkrad_core::audit::{AuditActor, NewAuditEvent};
use sqlx::AssertSqlSafe;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::scheduler::iso_of_unix;
use crate::store::audit::append_one;
use crate::store::{connect, kinds::allow};

pub(super) const SECRET: &str = "SKPLANTED";

// ---- a fake create-only S3: PUT refuses an existing key, LIST pages two keys at a time --------

pub(super) struct Fake {
    pub(super) addr: SocketAddr,
    pub(super) objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    pub(super) down: Arc<AtomicBool>,
    pub(super) puts: Arc<AtomicUsize>,
}

pub(super) fn unpct(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16)
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

pub(super) async fn fake() -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let f = Fake {
        addr: listener.local_addr().unwrap(),
        objects: Arc::default(),
        down: Arc::default(),
        puts: Arc::default(),
    };
    let (objects, down, puts) = (f.objects.clone(), f.down.clone(), f.puts.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let (objects, down, puts) = (objects.clone(), down.clone(), puts.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let head_end = loop {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break p + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let len = head
                    .lines()
                    .find_map(|l| {
                        l.to_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + len {
                    let n = sock.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let body = buf[head_end..head_end + len].to_vec();
                let mut first = head.lines().next().unwrap().split(' ');
                let (method, target) = (first.next().unwrap(), first.next().unwrap());
                let (path, query) = target.split_once('?').unwrap_or((target, ""));
                let key = unpct(path.strip_prefix("/b/").unwrap_or(""));
                let q = |n: &str| {
                    query
                        .split('&')
                        .find_map(|p| p.strip_prefix(&format!("{n}=")).map(unpct))
                };
                let (status, out) = if down.load(Ordering::SeqCst) {
                    (
                        "503 Service Unavailable",
                        b"<Error><Code>SlowDown</Code></Error>".to_vec(),
                    )
                } else if method == "PUT" {
                    let mut o = objects.lock().unwrap();
                    if let std::collections::btree_map::Entry::Vacant(e) = o.entry(key) {
                        e.insert(body);
                        puts.fetch_add(1, Ordering::SeqCst);
                        ("200 OK", Vec::new())
                    } else {
                        (
                            "403 Forbidden",
                            b"<Error><Code>AccessDenied</Code></Error>".to_vec(),
                        )
                    }
                } else if key.is_empty() {
                    let (prefix, after) = (
                        q("prefix").unwrap_or_default(),
                        q("continuation-token").unwrap_or_default(),
                    );
                    let o = objects.lock().unwrap();
                    let keys: Vec<&String> = o
                        .keys()
                        .filter(|k| k.starts_with(&prefix) && **k > after)
                        .collect();
                    let page = &keys[..keys.len().min(2)];
                    let mut xml = String::from("<ListBucketResult>");
                    for k in page {
                        xml += &format!("<Contents><Key>{k}</Key></Contents>");
                    }
                    if keys.len() > 2 {
                        xml += &format!(
                            "<IsTruncated>true</IsTruncated><NextContinuationToken>{}</NextContinuationToken>",
                            page[1]
                        );
                    } else {
                        xml += "<IsTruncated>false</IsTruncated>";
                    }
                    ("200 OK", (xml + "</ListBucketResult>").into_bytes())
                } else {
                    match objects.lock().unwrap().get(&key) {
                        Some(b) => ("200 OK", b.clone()),
                        None => (
                            "404 Not Found",
                            b"<Error><Code>NoSuchKey</Code></Error>".to_vec(),
                        ),
                    }
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    out.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&out).await;
            });
        }
    });
    f
}

pub(super) fn bucket(f: &Fake) -> Bucket {
    Bucket::new(
        &format!("http://{}", f.addr),
        "b",
        "r",
        "core/",
        "AKPLANTED".into(),
        SECRET.into(),
    )
    .unwrap()
}

// ---- a database, a home, a clock ---------------------------------------------------------------

pub(super) struct Home {
    pub(super) dir: PathBuf,
    pub(super) pool: SqlitePool,
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

pub(super) async fn home(rows: i64) -> Home {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "core-anchor-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    private_dir(&dir).unwrap();
    let pool = connect(&dir.join("core.db")).await.unwrap();
    allow(&pool, &[], &["thing.done"]).await;
    let h = Home { dir, pool };
    for i in 1..=rows {
        add(&h, i).await;
    }
    h
}

pub(super) async fn add(h: &Home, i: i64) {
    let e = NewAuditEvent {
        actor: AuditActor::System,
        action: "thing.done".to_owned(),
        entity: None,
        details: format!(r#"{{"i":{i},"secretish":"audit-content"}}"#),
    };
    append_one(&h.pool, &e).await.unwrap();
}

pub(super) async fn sql(pool: &SqlitePool, text: &str) {
    sqlx::raw_sql(AssertSqlSafe(text.to_owned()))
        .execute(pool)
        .await
        .unwrap();
}

pub(super) struct At(pub(super) Mutex<i64>);

impl Clock for At {
    fn now(&self) -> String {
        iso_of_unix(*self.0.lock().unwrap())
    }
}

pub(super) fn at(t: i64) -> At {
    At(Mutex::new(t))
}

pub(super) fn sinks(f: &Fake) -> Sinks {
    Sinks {
        bucket: Some(bucket(f)),
        file: None,
    }
}

pub(super) async fn anchored(h: &Home, id: &Identity, s: &Sinks) -> Signed {
    anchor_once(&h.pool, &h.dir, id, s, &at(1_000))
        .await
        .unwrap()
        .unwrap()
}

pub(super) fn lines(f: &Fake) -> Vec<String> {
    f.objects
        .lock()
        .unwrap()
        .values()
        .map(|v| String::from_utf8(v.clone()).unwrap().trim().to_owned())
        .collect()
}

pub(super) async fn checked(
    h: &Home,
    lines: &[String],
    pin: Option<&str>,
) -> Result<Report, Tampered> {
    verify(&h.pool, lines, pin).await.unwrap()
}

/// Rewrites row `seq`'s details and re-chains every row from it on, as an attacker with the
/// database would: the result passes `verify_db`.
pub(super) async fn rebuild_from(h: &Home, seq: i64) {
    sql(&h.pool, "DROP TRIGGER audit_events_no_update").await;
    let mut rows: Vec<chain::ChainRow> = sqlx::query_as(
        "SELECT seq, at, user_id, actor_kind, actor_id, action, entity_kind, entity_id, details, \
         NULL AS prev_hash, NULL AS hash FROM audit_events WHERE seq >= ? ORDER BY seq",
    )
    .bind(seq)
    .fetch_all(&h.pool)
    .await
    .unwrap();
    let mut prev: String = sqlx::query_scalar(
        "SELECT coalesce((SELECT lower(hex(hash)) FROM audit_events WHERE seq = ?), ?)",
    )
    .bind(seq - 1)
    .bind(chain::GENESIS)
    .fetch_one(&h.pool)
    .await
    .unwrap();
    for r in &mut rows {
        if r.seq == seq {
            r.details = r#"{"i":0,"secretish":"edited"}"#.to_owned();
        }
        let hash = chain::hex(&chain::digest(r, &prev));
        sqlx::query("UPDATE audit_events SET details = ?, prev_hash = unhex(?), hash = unhex(?) WHERE seq = ?")
            .bind(&r.details)
            .bind(&prev)
            .bind(&hash)
            .bind(r.seq)
            .execute(&h.pool)
            .await
            .unwrap();
        prev = hash;
    }
    chain::verify_db(&h.pool)
        .await
        .unwrap()
        .expect("the rebuilt chain is internally consistent");
}

pub(super) fn why(r: Result<Report, Tampered>) -> String {
    r.expect_err("must fail").0
}
