//! Verifying anchors against the database (E1-10.4): see the module doc of `anchor`.

use std::fmt;
use std::fs;
use std::path::Path;

use ainkrad_proto::v2::rotation_message;
use sqlx::sqlite::SqlitePool;

use super::{
    PREFIX, SIG_B64, SPKI_B64, Signed, Statement, fetch_text, hash_of, message, seq_of_key,
};
use crate::auth::crypto::{fingerprint, unb64, verify as verify_sig};
use crate::ops::s3::Bucket;
use crate::store::audit::chain;

type Error = String;

/// Evidence that the anchors and the database disagree (or the anchors are bad).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tampered(pub String);

impl fmt::Display for Tampered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "audit anchors do not match: {}", self.0)
    }
}

impl std::error::Error for Tampered {}

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub anchors: usize,
    pub last: Statement,
}

fn bad<T>(why: impl Into<String>) -> Result<T, Tampered> {
    Err(Tampered(why.into()))
}

/// The anchors in `from`: a file (one anchor per line) or a directory of such files.
pub fn read_lines(from: &Path) -> std::io::Result<Vec<String>> {
    let mut files = if from.is_dir() {
        fs::read_dir(from)?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect()
    } else {
        vec![from.to_path_buf()]
    };
    files.sort();
    let mut lines = Vec::new();
    for f in files {
        lines.extend(
            fs::read_to_string(f)?
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(str::to_owned),
        );
    }
    Ok(lines)
}

/// Every anchor object under the bucket's `anchors/` prefix, read only. The bucket is
/// create-only, so an object there that is not a well-formed anchor of its own name (junk, a
/// forgery, an oversized blob) is evidence, not noise: `Tampered`. The outer error is a failure
/// to read the bucket at all.
pub async fn read_bucket(bucket: &Bucket) -> Result<Result<Vec<String>, Tampered>, Error> {
    let prefix = format!("{}{PREFIX}", bucket.prefix);
    let mut lines = Vec::new();
    for key in bucket.list(&prefix).await.map_err(|e| e.to_string())? {
        let Some(n) = seq_of_key(&prefix, &key) else {
            return Ok(bad(format!(
                "an object in the anchor prefix is not named like an anchor ({key})"
            )));
        };
        let Some(text) = fetch_text(bucket, &key).await? else {
            return Ok(bad(format!(
                "{key} is not a readable anchor (gone, too large or not text)"
            )));
        };
        let Ok(c) = check_one(text.trim()) else {
            return Ok(bad(format!("{key} is not a validly signed anchor")));
        };
        if c.st.anchor_seq != n {
            return Ok(bad(format!(
                "{key} holds anchor {}, not {n}",
                c.st.anchor_seq
            )));
        }
        lines.push(text.trim().to_owned());
    }
    Ok(Ok(lines))
}

pub(super) struct Checked {
    pub(super) st: Statement,
    pub(super) signed: Signed,
    pub(super) spki: Vec<u8>,
}

pub(super) fn check_one(line: &str) -> Result<Checked, Tampered> {
    let Ok(signed) = serde_json::from_str::<Signed>(line) else {
        return bad("an anchor is not readable");
    };
    let Ok(st) = serde_json::from_str::<Statement>(&signed.statement) else {
        return bad("an anchor's statement is not readable");
    };
    let n = st.anchor_seq;
    let (Some(spki), Some(sig)) = (unb64(&signed.spki, SPKI_B64), unb64(&signed.sig, SIG_B64))
    else {
        return bad(format!("anchor {n}: malformed key or signature"));
    };
    if st.v != 1 || fingerprint(&spki) != st.core_fp {
        return bad(format!(
            "anchor {n}: not a version 1 statement of its signer"
        ));
    }
    if !verify_sig(&spki, &message(&signed.statement), &sig) {
        return bad(format!("anchor {n}: the signature is not valid"));
    }
    Ok(Checked { st, signed, spki })
}

/// Verifies `lines` (one anchor each) against the database: signatures, the anchor chain and
/// key lineage (a key change needs the old key's rotation statement), the newest signer being
/// `pin` when given, and every anchored head still in the database with the same hash and row
/// count. The outer error is a database failure, the inner the evidence.
pub async fn verify(
    pool: &SqlitePool,
    lines: &[String],
    pin: Option<&str>,
) -> Result<Result<Report, Tampered>, sqlx::Error> {
    let mut all = Vec::new();
    for l in lines {
        match check_one(l) {
            Ok(c) => all.push(c),
            Err(t) => return Ok(Err(t)),
        }
    }
    all.sort_by_key(|a| a.st.anchor_seq);
    // The same anchor from two copies is one; two different ones at a sequence number are a fork.
    all.dedup_by(|b, a| a.signed.statement == b.signed.statement);
    if let Some(w) = all
        .windows(2)
        .find(|w| w[0].st.anchor_seq == w[1].st.anchor_seq)
    {
        return Ok(bad(format!(
            "two different anchors share sequence {}",
            w[0].st.anchor_seq
        )));
    }
    let Some(last) = all.last() else {
        return Ok(bad("there are no anchors to check"));
    };
    for w in all.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        let n = b.st.anchor_seq;
        if n != a.st.anchor_seq + 1 {
            return Ok(bad(format!(
                "anchors {} to {} are missing",
                a.st.anchor_seq + 1,
                n - 1
            )));
        }
        if b.st.prev_anchor_hash != hash_of(&a.signed.statement) {
            return Ok(bad(format!(
                "anchor {n} does not follow anchor {}",
                a.st.anchor_seq
            )));
        }
        if a.st.core_fp != b.st.core_fp {
            let proven = b.signed.rotation.as_ref().is_some_and(|r| {
                r.old_fp == a.st.core_fp
                    && r.new_fp == b.st.core_fp
                    && unb64(&r.sig, SIG_B64)
                        .is_some_and(|s| verify_sig(&a.spki, &rotation_message(r), &s))
            });
            if !proven {
                return Ok(bad(format!(
                    "anchor {n} is signed by a new key with no valid rotation from the old one"
                )));
            }
        }
    }
    if let Some(pin) = pin
        && last.st.core_fp != pin
    {
        return Ok(bad(format!(
            "the newest anchor is signed by {}, not the expected {pin}",
            last.st.core_fp
        )));
    }
    if let Err(b) = chain::verify_db(pool).await? {
        return Ok(bad(b.to_string()));
    }
    for c in &all {
        let s = &c.st;
        let found: Option<(String, i64)> = sqlx::query_as(
            "SELECT lower(hex(hash)), (SELECT count(*) FROM audit_events WHERE seq <= ?1) \
             FROM audit_events WHERE seq = ?1",
        )
        .bind(s.head_seq)
        .fetch_optional(pool)
        .await?;
        match found {
            None => {
                return Ok(bad(format!(
                    "anchor {} saw audit row {}, which is gone (the chain was truncated or rolled back)",
                    s.anchor_seq, s.head_seq
                )));
            }
            Some((h, rows)) if h != s.head_hash || u64::try_from(rows) != Ok(s.rows) => {
                return Ok(bad(format!(
                    "anchor {} saw audit row {} with another hash or history (the chain was rebuilt)",
                    s.anchor_seq, s.head_seq
                )));
            }
            Some(_) => {}
        }
    }
    Ok(Ok(Report {
        anchors: all.len(),
        last: last.st.clone(),
    }))
}
