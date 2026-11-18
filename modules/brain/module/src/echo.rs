//! The no-echo guard (Brain v2, B5-02): memory loaded into a session is never distilled back as a
//! new fact (Honcho's feedback loop, plan R4).
//!
//! Security model:
//! - `brain_session_loaded` holds the ids of every record a session was given (start bundle,
//!   per-prompt context, evidence). Before a transcript becomes items, the text of those records
//!   and every outside-data envelope (`ainkrad_core::untrusted`) is cut out of its turns.
//! - Fail closed: if a room that holds a loaded record cannot be read, that session is not
//!   collected this round (`Loaded::blocked`). Nothing is lost: its cursor does not move.
//! - Brain-owned sessions are never collected at all (`sync::collect`), so the Brain's own prompts
//!   are never a source either.
//! - Matching is exact text. ponytail: a model that rephrases a loaded record is not caught; the
//!   admission filter and the judge are the next line. Add fuzzy matching only if the eval shows echoes.

use std::collections::{HashMap, HashSet};

use ainkrad_core::untrusted::{CLOSE, OPEN};
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::ApiError;

use crate::{Brain, distil};

/// Shorter spans are not cut: a few words match too much ordinary text.
const MIN_SPAN: usize = 24;

/// `text` without envelopes and without the exact text of any of `spans`.
pub(crate) fn strip(text: &str, spans: &[String]) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(OPEN) {
        out.push_str(&rest[..i]);
        // An envelope that never closes is cut to the end of the turn: fail closed.
        rest = match rest[i..].find(CLOSE) {
            Some(j) => &rest[i + j + CLOSE.len()..],
            None => "",
        };
    }
    out.push_str(rest);
    for s in spans
        .iter()
        .map(|s| s.trim())
        .filter(|s| s.len() >= MIN_SPAN)
    {
        out = out.replace(s, "");
    }
    out
}

/// A turn that had nothing but loaded memory in it: only its `User:` / `Assistant:` label is left.
pub(crate) fn is_empty_turn(block: &str) -> bool {
    matches!(block.trim(), "User:" | "Assistant:")
}

/// What each session was given from the Brain.
#[derive(Default)]
pub(crate) struct Loaded {
    /// Session id to the bodies of the records it was given.
    pub spans: HashMap<String, Vec<String>>,
    /// Sessions whose loaded records could not be read: do not collect them now.
    pub blocked: HashSet<String>,
}

impl Loaded {
    pub(crate) fn of(&self, session: &str) -> &[String] {
        self.spans.get(session).map_or(&[], Vec::as_slice)
    }
}

/// Reads the bodies of every loaded record, once per room file.
/// ponytail: one pass over the whole table per sync; per-session reads if it grows past thousands.
pub(crate) async fn loaded(app: &App, b: &Brain) -> Result<Loaded, ApiError> {
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT session, room, record FROM brain_session_loaded ORDER BY room")
            .fetch_all(&app.pool)
            .await?;
    let mut out = Loaded::default();
    let mut i = 0;
    while i < rows.len() {
        let room = &rows[i].1;
        let end = rows[i..]
            .iter()
            .position(|r| &r.1 != room)
            .map_or(rows.len(), |n| i + n);
        let group = &rows[i..end];
        i = end;
        // The record rows, not the `memory` view: a record that was superseded after it was
        // loaded is still text the session saw.
        let Ok(pool) = distil::canon(app, b, room).await else {
            out.blocked.extend(group.iter().map(|r| r.0.clone()));
            continue;
        };
        for (session, _, record) in group {
            let body: Result<Option<String>, _> =
                sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
                    .bind(record)
                    .fetch_optional(&pool)
                    .await;
            match body {
                Ok(Some(body)) => out.spans.entry(session.clone()).or_default().push(body),
                Ok(None) => {}
                Err(_) => {
                    out.blocked.insert(session.clone());
                }
            }
        }
        pool.close().await;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use ainkrad_core::untrusted::wrap;

    use super::*;

    #[test]
    fn an_envelope_and_a_loaded_record_are_cut_out_and_other_text_stays() {
        let rec = "Deploys go out on Friday after the freeze.".to_owned();
        let wrapped = wrap("record r1", &rec);
        let turn = format!("Assistant: As noted {wrapped} and also {rec} so we ship the cache.");
        let out = strip(&turn, std::slice::from_ref(&rec));
        assert!(
            !out.contains("Friday") && !out.contains("OUTSIDE TEXT"),
            "{out}"
        );
        assert!(out.contains("so we ship the cache."), "{out}");
    }

    #[test]
    fn an_envelope_that_never_closes_is_cut_to_the_end() {
        let out = strip(&format!("User: hi {OPEN} | x >>>\nsecret"), &[]);
        assert_eq!(out, "User: hi ");
    }

    #[test]
    fn a_short_span_is_left_alone_and_an_emptied_turn_is_detected() {
        assert_eq!(strip("User: yes", &["yes".to_owned()]), "User: yes");
        let rec = "Never push straight to the main branch.".to_owned();
        let out = strip(&format!("Assistant: {rec}"), &[rec]);
        assert!(is_empty_turn(&out), "{out:?}");
    }
}
