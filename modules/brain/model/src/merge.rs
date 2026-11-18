//! B4-01: merge-on-save. `decide` says whether a candidate fact is one the memory already holds, in
//! three tiers, in order: the same normalised body, an e5 cosine at or above `Q_MERGE_COSINE`, a
//! model-emitted `same_as` that names a known id. Pure: no I/O, no model call. Facts of different
//! types never merge, in any tier.

use crate::semantic::dot;

/// Q: two facts of one type whose unit vectors have at least this cosine are the same fact.
pub const Q_MERGE_COSINE: f32 = 0.95;

/// The exact-match key. Must equal the SQL backfill in `canon_0006.sql` (a gate test compares them):
/// ASCII-lowercase; CR, LF and TAB become spaces; runs of spaces collapse to one; trimmed.
pub fn body_norm(body: &str) -> String {
    body.split([' ', '\t', '\n', '\r'])
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

/// A fact the memory holds. `vec` is a unit vector when one is stored.
pub struct Known<'a> {
    pub id: &'a str,
    pub kind: &'a str,
    pub norm: &'a str,
    pub vec: Option<&'a [f32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Exact,
    Meaning,
    SameAs,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Reinforce { id: String, tier: Tier },
    Insert,
}

/// `vec` is the candidate's unit vector; `same_as` the id the model named, if any.
pub fn decide(
    kind: &str,
    norm: &str,
    vec: Option<&[f32]>,
    same_as: Option<&str>,
    known: &[Known],
) -> Decision {
    let hit = |id: &str, tier| Decision::Reinforce {
        id: id.to_owned(),
        tier,
    };
    let same_kind = || known.iter().filter(|k| k.kind == kind);
    if let Some(k) = same_kind().find(|k| k.norm == norm) {
        return hit(k.id, Tier::Exact);
    }
    if let Some(v) = vec {
        let best = same_kind()
            .filter_map(|k| Some((k, dot(v, k.vec?))))
            .filter(|(_, s)| *s >= Q_MERGE_COSINE)
            .max_by(|a, b| a.1.total_cmp(&b.1));
        if let Some((k, _)) = best {
            return hit(k.id, Tier::Meaning);
        }
    }
    if let Some(k) = same_as.and_then(|s| same_kind().find(|k| k.id == s)) {
        return hit(k.id, Tier::SameAs);
    }
    Decision::Insert
}

/// What backs a candidate, by the strict test (`admit::Grounds::supports`, B4-02 round 3): every
/// content word in one clause of ONE user turn of a source it cites, with that clause's negation
/// words, or in the tool-set fields (title, status, resolution, assignee) of ONE cited Jira or
/// GitHub item, never its description or comments (`answer::user_supported` /
/// `answer::fields_supported`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Grounding {
    pub user_turn: bool,
    pub structured_item: bool,
}

/// B4-02 security rule (fallback, round 4): lexical grounding cannot read word order or meaning, so
/// a `replaces` of a `rule`, `preference`, `decision` or `fact` never supersedes: it always saves
/// the candidate alone (if admitted), keeps the target in force, and marks the two contested. Only a
/// `task` or `project-state` of one kind supersedes, when the candidate passes the strict test
/// (`Grounding`) on one user-turn clause or on one cited Jira or GitHub item's tool-set fields. A contested record never steers (ranks last, labelled).
pub fn may_supersede(candidate_kind: &str, target_kind: &str, g: Grounding) -> bool {
    candidate_kind == target_kind
        && matches!(candidate_kind, "task" | "project-state")
        && (g.user_turn || g.structured_item)
}

/// B4-02: a record of this kind goes stale, and ranks down, once it was last in use before the room's
/// review cut-off. Other kinds never go stale.
pub fn is_stale(kind: &str, last_seen: &str, cutoff: &str) -> bool {
    matches!(kind, "project-state" | "task") && last_seen < cutoff
}

macro_rules! stale_sql {
    () => {
        "(type IN ('project-state','task') AND coalesce(last_seen_at, created_at) < ?)"
    };
}

/// The same test as `is_stale`, as an SQL expression of one `?` (the cut-off, ISO text) over the
/// `records` / `memory` columns. A gate test keeps the two equal.
pub const STALE_SQL: &str = stale_sql!();

/// The retrieval sort key (B4-02 round 3), one `?` like `STALE_SQL`: 0 fresh, 1 stale, 2 or 3
/// contested (`contests IS NOT NULL`), so a contested record comes after everything else.
pub const DEMOTE_SQL: &str = concat!("((contests IS NOT NULL) * 2 + ", stale_sql!(), ")");

#[cfg(test)]
mod tests {
    use super::*;

    const A: [f32; 2] = [1.0, 0.0];
    const NEAR: [f32; 2] = [0.98, 0.198_997_5]; // cosine 0.98 with A
    const FAR: [f32; 2] = [0.8, 0.6]; // cosine 0.8 with A

    fn k<'a>(id: &'a str, kind: &'a str, norm: &'a str, vec: Option<&'a [f32]>) -> Known<'a> {
        Known {
            id,
            kind,
            norm,
            vec,
        }
    }

    fn reinforce(id: &str, tier: Tier) -> Decision {
        Decision::Reinforce {
            id: id.to_owned(),
            tier,
        }
    }

    #[test]
    fn norm_lowercases_collapses_and_trims() {
        assert_eq!(
            body_norm("  Deploy\ton   FRIDAYS \r\n"),
            "deploy on fridays"
        );
        assert_eq!(body_norm(""), "");
        // ASCII only, like SQLite's lower().
        assert_eq!(body_norm("ÄB"), "Äb");
    }

    #[test]
    fn tier_one_exact_body_wins_even_against_a_closer_vector() {
        let known = [
            k("v", "fact", "other", Some(&A)),
            k("e", "fact", "same", None),
        ];
        assert_eq!(
            decide("fact", "same", Some(&A), None, &known),
            reinforce("e", Tier::Exact)
        );
    }

    #[test]
    fn tier_two_meaning_at_the_threshold_picks_the_closest() {
        let known = [
            k("far", "fact", "x", Some(&FAR)),
            k("near", "fact", "y", Some(&NEAR)),
        ];
        assert_eq!(
            decide("fact", "z", Some(&A), None, &known),
            reinforce("near", Tier::Meaning)
        );
        let known = [k("far", "fact", "x", Some(&FAR))];
        assert_eq!(
            decide("fact", "z", Some(&A), None, &known),
            Decision::Insert
        );
    }

    #[test]
    fn tier_three_same_as_names_a_known_id() {
        let known = [k("rec-1", "fact", "x", Some(&FAR))];
        assert_eq!(
            decide("fact", "z", Some(&A), Some("rec-1"), &known),
            reinforce("rec-1", Tier::SameAs)
        );
        // An id that is not known is ignored.
        assert_eq!(
            decide("fact", "z", None, Some("rec-9"), &known),
            Decision::Insert
        );
    }

    #[test]
    fn no_match_inserts() {
        let known = [k("a", "fact", "x", Some(&FAR))];
        assert_eq!(
            decide("fact", "z", Some(&A), None, &known),
            Decision::Insert
        );
        assert_eq!(decide("fact", "z", None, None, &[]), Decision::Insert);
    }

    #[test]
    fn different_types_never_merge() {
        let known = [k("a", "rule", "same", Some(&A))];
        assert_eq!(
            decide("fact", "same", Some(&A), Some("a"), &known),
            Decision::Insert
        );
    }

    #[test]
    fn a_supersede_needs_one_kind_and_strong_grounding() {
        let none = Grounding::default();
        let user = Grounding {
            user_turn: true,
            ..none
        };
        let item = Grounding {
            structured_item: true,
            ..none
        };
        for kind in [
            "rule",
            "preference",
            "fact",
            "decision",
            "task",
            "project-state",
        ] {
            assert!(!may_supersede(kind, kind, none), "{kind}");
            let strict = matches!(kind, "task" | "project-state");
            assert_eq!(may_supersede(kind, kind, user), strict, "{kind}");
        }
        assert!(may_supersede("task", "task", item));
        assert!(may_supersede("project-state", "project-state", item));
        for kind in ["rule", "preference", "fact", "decision"] {
            assert!(!may_supersede(kind, kind, item), "{kind}");
            assert!(!may_supersede(kind, kind, user), "{kind}");
        }
        assert!(!may_supersede("fact", "rule", user));
        assert!(!may_supersede("task", "project-state", item));
    }

    #[test]
    fn only_old_project_state_and_tasks_are_stale() {
        let cut = "2026-08-01T00:00:00Z";
        assert!(is_stale("project-state", "2026-07-01T00:00:00Z", cut));
        assert!(is_stale("task", "2026-07-01T00:00:00Z", cut));
        assert!(!is_stale("task", "2026-09-01T00:00:00Z", cut));
        assert!(!is_stale("decision", "2026-01-01T00:00:00Z", cut));
        assert!(!is_stale("rule", "2026-01-01T00:00:00Z", cut));
    }
}
