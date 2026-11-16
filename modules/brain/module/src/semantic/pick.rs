//! Local selection for the room Overview: which items stand for a room, and which lines read like a
//! rule. Pure and deterministic; the cloud model only ever sees what this picks.

use brain_model::semantic::dot;

/// An item of a room as selection sees it. Callers pass newest first.
#[derive(Clone, Copy)]
pub struct Cand<'a> {
    pub title: &'a str,
    pub text: &'a str,
    /// Written by the person, not an assistant.
    pub person: bool,
    /// An instruction file (AGENTS.md and the like): its list entries are conventions.
    pub doc: bool,
    /// Other documentation: a doc, a note, a README.
    pub note: bool,
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

/// The comparison key of a line: lower case, without a list mark or a `User:` lead, words only.
pub fn line_key(line: &str) -> String {
    let l = line.trim().to_lowercase();
    let l = l.strip_prefix("user:").unwrap_or(&l);
    l.split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// A line without its list mark (`- `, `* `, `1. `) or its `User:` lead.
fn bare(line: &str) -> &str {
    let l = line.trim();
    let l = l.strip_prefix("User:").unwrap_or(l).trim_start();
    let l = l.trim_start_matches(['-', '*', '+', '>']).trim_start();
    let digits = l.bytes().take_while(u8::is_ascii_digit).count();
    match l[digits..].strip_prefix(['.', ')']) {
        Some(rest) if digits > 0 => rest.trim_start(),
        _ => l,
    }
}

/// A list entry: `- `, `* `, `+ ` or `1. `.
fn listed(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with(['-', '*', '+'])
        || t.bytes().take_while(u8::is_ascii_digit).count() > 0
            && t.trim_start_matches(|c: char| c.is_ascii_digit())
                .starts_with(['.', ')'])
}

/// A documentation line that states a convention without a rule word: a list entry of a sentence.
fn doc_entry(line: &str) -> bool {
    let b = bare(line);
    listed(line) && (15..=240).contains(&b.chars().count()) && b.split_whitespace().count() >= 3
}

/// Whether a line can be a rule at all: not a link, a checkbox, a plan step, code, a table row or
/// a `Label: value` entry.
fn shaped(line: &str) -> bool {
    let b = bare(line);
    let plain = b.replace("**", "").replace('_', " ");
    let low = plain.trim().to_lowercase();
    if b.contains("[[")
        || b.starts_with(['[', '`', '#', '|', '"', '{', '<', '$', '>', '/', '@', '('])
        || b.contains("  #")
        || b.contains(" // ")
        || b.trim_end_matches(['*', '_'])
            .ends_with([':', '{', ';', ','])
        || ["=>", "();", "function ", "it('", "test_", "->"]
            .iter()
            .any(|c| b.contains(c))
        || low.starts_with("step ")
    {
        return false;
    }
    // A short label before a colon is a field, not a sentence: `Repo: ...`, `Tech Stack: ...`.
    match low.split_once(':') {
        Some((label, _)) => {
            let w = label.split_whitespace().count();
            // `Never:` or `Do not:` heads a rule; any other short label is a field.
            !(1..=3).contains(&w)
                || label
                    .split_whitespace()
                    .any(|t| matches!(t, "never" | "always" | "must" | "don't" | "not"))
        }
        None => true,
    }
}

/// The rule-like lines of every item as (item index, line), at most once per item. A
/// documentation item also gives its list entries; an assistant's lines are never a rule.
pub fn candidate_lines(c: &[Cand]) -> Vec<(usize, String)> {
    let mut out = vec![];
    for (i, it) in c.iter().enumerate() {
        let mut seen = std::collections::HashSet::new();
        // Only the start of a long item: a transcript's tail is not worth the scan.
        let head: String = it.text.chars().take(20_000).collect();
        let mut prev = "";
        let mut fenced = false;
        // The sentence that introduces a list (`Never, without asking:`): its entries say
        // nothing on their own, so an instruction file's entry carries it.
        let mut lead: Option<&str> = None;
        for line in head.lines().map(str::trim) {
            if line.starts_with("```") || line.starts_with("~~~") {
                fenced = !fenced;
                continue;
            }
            // A wrapped sentence's later line is a fragment, not a rule.
            let fragment = !prev.is_empty()
                && !prev.ends_with(['.', '!', '?', ':', ')'])
                && line.starts_with(char::is_lowercase);
            prev = line;
            if !listed(line) && !line.is_empty() {
                let l = line.trim_end_matches(['*', '_']);
                lead =
                    (l.ends_with(':') && l.starts_with(|c: char| !c.is_lowercase())).then_some(l);
            }
            // Documentation is written in sentences: a lower-case start there is code or a
            // wrapped line (a person's prompt often starts lower case).
            let written = it.doc || it.note;
            if fenced
                || fragment
                || written && bare(line).starts_with(char::is_lowercase)
                || line.to_lowercase().starts_with("assistant:")
                || !shaped(line)
            {
                continue;
            }
            let text = if is_rule_line(line) {
                bare(line).to_owned()
            } else if it.doc && doc_entry(line) {
                match lead.filter(|_| listed(line)) {
                    Some(l) => format!("{} {}", bare(l), bare(line)),
                    None => bare(line).to_owned(),
                }
            } else {
                continue;
            };
            let key = line_key(&text);
            if !key.is_empty() && seen.insert(key) {
                out.push((i, text));
            }
        }
    }
    out
}

/// A rule the room states, with every item that states it (indices into the items).
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub text: String,
    pub items: Vec<usize>,
    /// One of its items is an instruction file.
    pub doc: bool,
    /// Only AI session items state it (no documentation, no note).
    pub session: bool,
}

/// Best first: documentation and notes before what only sessions say, then the items that state
/// it, an instruction file counting as two more.
fn score(g: &Candidate) -> (bool, std::cmp::Reverse<usize>) {
    (
        g.session,
        std::cmp::Reverse(g.items.len() + 2 * usize::from(g.doc)),
    )
}

/// Lines closer than this (cosine of e5 vectors) say the same thing. e5 scores unrelated short
/// lines about 0.82-0.85.
pub const SAME_LINE: f32 = 0.93;

/// Groups `lines` into candidate rules: the same words first, then the same meaning when
/// `vec_of` gives a group's first line a vector (`None` for the rest). Documentation lines lead
/// their group, so its wording is the one shown. Best supported first.
pub fn group(
    c: &[Cand],
    lines: &[(usize, String)],
    vec_of: impl Fn(&str) -> Option<Vec<f32>>,
) -> Vec<Candidate> {
    let mut by_key: std::collections::HashMap<String, usize> = Default::default();
    let mut groups: Vec<Candidate> = vec![];
    let mut order: Vec<&(usize, String)> = lines.iter().collect();
    // Documentation, then the person's own words, then the rest; stable within each.
    order.sort_by_key(|(i, _)| (!c[*i].doc, !c[*i].person));
    for (i, line) in order {
        let k = line_key(line);
        let g = *by_key.entry(k).or_insert_with(|| {
            groups.push(Candidate {
                text: line.clone(),
                items: vec![],
                doc: false,
                session: true,
            });
            groups.len() - 1
        });
        if !groups[g].items.contains(i) {
            groups[g].items.push(*i);
        }
        groups[g].doc |= c[*i].doc;
        groups[g].session &= !(c[*i].doc || c[*i].note);
    }
    groups.sort_by_key(score);
    // ponytail: greedy pairwise merge, O(n^2) over the vectored groups; fine for a few thousand.
    let vecs: Vec<Option<Vec<f32>>> = groups.iter().map(|g| vec_of(&g.text)).collect();
    let mut out: Vec<(Candidate, Option<Vec<f32>>)> = vec![];
    for (g, v) in groups.into_iter().zip(vecs) {
        let into = v.as_ref().and_then(|v| {
            out.iter()
                .position(|(_, o)| o.as_ref().is_some_and(|o| dot(o, v) >= SAME_LINE))
        });
        match into {
            Some(j) => {
                let t = &mut out[j].0;
                for i in g.items {
                    if !t.items.contains(&i) {
                        t.items.push(i);
                    }
                }
                t.doc |= g.doc;
                t.session &= g.session;
            }
            None => out.push((g, v)),
        }
    }
    let mut out: Vec<Candidate> = out.into_iter().map(|x| x.0).collect();
    out.sort_by_key(score);
    out
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

    fn cand<'a>(text: &'a str, doc: bool, vec: Option<&'a [f32]>) -> Cand<'a> {
        Cand {
            title: "t",
            text,
            person: true,
            doc,
            note: false,
            vec,
        }
    }

    #[test]
    fn representatives_spread_over_the_room() {
        let (a, b, z) = ([1.0, 0.0], [0.99, 0.14], [0.0, 1.0]);
        let c = [
            cand("a", false, Some(&a)),
            cand("b", false, Some(&b)),
            cand("z", false, Some(&z)),
            cand("n", false, None),
        ];
        let p = representatives(&c, 3);
        assert_eq!(p.len(), 3);
        assert!(p.contains(&2), "the odd one out is represented: {p:?}");
        assert_eq!(
            representatives(&c, 10).len(),
            4,
            "no vector items fill in last"
        );
    }

    /// Support is counted: the same rule in three items is one candidate with three items, a doc's
    /// list entry is a candidate, an assistant's line is not, and close vectors merge wordings.
    #[test]
    fn lines_are_grouped_by_words_and_by_meaning() {
        let c = [
            cand(
                "# Rules\n- Keep handlers thin, logic in app/Actions.\n- ok",
                true,
                None,
            ),
            cand(
                "User: always run the tests before you push!\nAssistant: I never skip tests, always.",
                false,
                None,
            ),
            cand("Always run the tests before you push.", false, None),
            cand("Never push without running the tests first.", false, None),
        ];
        let lines = candidate_lines(&c);
        assert_eq!(lines.len(), 4, "{lines:?}");
        let g = group(&c, &lines, |_| None);
        assert_eq!(g[0].text, "Keep handlers thin, logic in app/Actions.");
        assert!(g[0].doc);
        assert_eq!((g[1].items.clone(), g[1].doc), (vec![1, 2], false));
        assert_eq!(g.len(), 3);
        // The same meaning in other words joins the group when vectors say so.
        let g = group(&c, &lines, |t| {
            Some(if t.contains("test") {
                vec![1.0, 0.0]
            } else {
                vec![0.0, 1.0]
            })
        });
        assert_eq!(g.len(), 2);
        assert_eq!(g[1].items, [1, 2, 3]);
    }
}
