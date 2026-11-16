//! Local selection for the room Overview: which items stand for a room, and which lines read like a
//! rule. Pure and deterministic; the cloud model only ever sees what this picks.

use brain_model::semantic::dot;

/// An item of a room as selection sees it. Callers pass newest first.
pub struct Cand<'a> {
    pub title: &'a str,
    pub text: &'a str,
    /// Written by the person, not an assistant.
    pub person: bool,
    /// Unit vector from the local model, when it has one.
    pub vec: Option<&'a [f32]>,
}

/// Up to `k` indices that stand for the room: first the items nearest the room's centroid, each
/// next one trading closeness for difference from those already picked; items without a vector
/// fill the rest in the order given.
/// ponytail: greedy over the first 2000 vectored items; real clustering when a room outgrows that.
pub fn representatives(c: &[Cand], k: usize) -> Vec<usize> {
    let vecd: Vec<usize> = (0..c.len())
        .filter(|&i| c[i].vec.is_some_and(|v| !v.is_empty()))
        .take(2000)
        .collect();
    let mut picked: Vec<usize> = vec![];
    if let Some(&first) = vecd.first() {
        let dim = c[first].vec.map_or(0, <[f32]>::len);
        let mut centroid = vec![0f32; dim];
        for &i in &vecd {
            let v = c[i].vec.unwrap_or_default();
            if v.len() == dim {
                centroid.iter_mut().zip(v).for_each(|(a, b)| *a += b);
            }
        }
        let vecd: Vec<usize> = vecd
            .into_iter()
            .filter(|&i| c[i].vec.is_some_and(|v| v.len() == dim))
            .collect();
        let near: Vec<f32> = vecd
            .iter()
            .map(|&i| dot(&centroid, c[i].vec.unwrap_or_default()) / vecd.len() as f32)
            .collect();
        let mut far = vec![f32::MIN; vecd.len()]; // closest similarity to a picked item
        while picked.len() < k.min(vecd.len()) {
            let best = (0..vecd.len())
                .filter(|j| !picked.contains(&vecd[*j]))
                .max_by(|&a, &b| {
                    let s = |j: usize| near[j] - 0.5 * far[j].max(0.0);
                    s(a).total_cmp(&s(b))
                });
            let Some(b) = best else { break };
            picked.push(vecd[b]);
            let pv = c[vecd[b]].vec.unwrap_or_default();
            for (j, f) in far.iter_mut().enumerate() {
                *f = f.max(dot(pv, c[vecd[j]].vec.unwrap_or_default()));
            }
        }
    }
    for i in 0..c.len() {
        if picked.len() >= k {
            break;
        }
        if !picked.contains(&i) {
            picked.push(i);
        }
    }
    picked
}

const ARABIC: &[&str] = &[
    "دائما",
    "دائماً",
    "أبدا",
    "أبداً",
    "يجب",
    "لا تستخدم",
    "لا تفعل",
    "ممنوع",
];

/// A line that states a rule: always, never, must, don't, do not, prefer, or "use ... instead".
pub fn is_rule_line(line: &str) -> bool {
    let l = line.trim().to_lowercase().replace('\u{2019}', "'");
    if !(15..=240).contains(&l.chars().count()) {
        return false;
    }
    if ARABIC.iter().any(|a| l.contains(a)) {
        return true;
    }
    let w: Vec<&str> = l
        .split(|c: char| !c.is_alphanumeric() && c != '\'')
        .filter(|t| !t.is_empty())
        .collect();
    let use_at = w.iter().position(|t| *t == "use");
    w.iter().enumerate().any(|(i, t)| {
        matches!(
            *t,
            "always" | "never" | "must" | "don't" | "dont" | "prefer" | "prefers" | "preferred"
        ) || (*t == "do" && w.get(i + 1) == Some(&"not"))
            || (*t == "instead" && use_at.is_some_and(|u| u < i))
    })
}

/// Up to `max` rule-like lines as (item index, line), the person's own lines first, no line twice.
pub fn rule_lines(c: &[Cand], max: usize) -> Vec<(usize, String)> {
    let mut seen = std::collections::HashSet::new();
    let mut out: Vec<(bool, usize, String)> = vec![];
    for (i, it) in c.iter().enumerate() {
        // Only the start of a long item: a transcript's tail is not worth the scan.
        let head: String = it.text.chars().take(20_000).collect();
        for line in head.lines().map(str::trim).filter(|l| is_rule_line(l)) {
            if seen.insert(line.to_lowercase()) {
                out.push((!it.person, i, line.to_owned()));
            }
        }
    }
    out.sort_by_key(|r| r.0); // stable: newest first within each group
    out.into_iter().take(max).map(|(_, i, l)| (i, l)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_lines_are_found_in_english_and_arabic() {
        for yes in [
            "Always run the linter before you push.",
            "we never commit to main directly",
            "Don\u{2019}t use force pushes on shared branches",
            "You must keep files under 500 lines.",
            "use rustls instead of openssl for the client",
            "Prefer small commits over big ones.",
            "لا تستخدم المتغيرات العامة في هذا المشروع",
        ] {
            assert!(is_rule_line(yes), "{yes}");
        }
        for no in [
            "The build ran fine today and nothing broke.",
            "ok",
            "Never.",
        ] {
            assert!(!is_rule_line(no), "{no}");
        }
    }

    #[test]
    fn selection_prefers_people_and_spreads_over_the_room() {
        let (a, b, z) = ([1.0, 0.0], [0.99, 0.14], [0.0, 1.0]);
        let c = [
            Cand {
                title: "a",
                text: "x\nNever deploy on Fridays at all.",
                person: false,
                vec: Some(&a),
            },
            Cand {
                title: "b",
                text: "Always tag a release before deploy.",
                person: true,
                vec: Some(&b),
            },
            Cand {
                title: "z",
                text: "z",
                person: true,
                vec: Some(&z),
            },
            Cand {
                title: "n",
                text: "n",
                person: true,
                vec: None,
            },
        ];
        let r = rule_lines(&c, 5);
        assert_eq!(r[0].0, 1, "the person's line comes first");
        assert_eq!(r.len(), 2);
        let p = representatives(&c, 3);
        assert_eq!(p.len(), 3);
        assert!(p.contains(&2), "the odd one out is represented: {p:?}");
        assert_eq!(
            representatives(&c, 10).len(),
            4,
            "no vector items fill in last"
        );
    }
}
