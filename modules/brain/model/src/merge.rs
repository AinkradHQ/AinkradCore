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
}
