//! The pure half of the save path (T2): what a save becomes, given the text the client edited from
//! (`base`), the head and the client's text. No database, so the property test can run it 10 000 times.
//!
//! Rule: nothing a person typed is ever discarded. A clean 3-way merge (`diffy`, line based) keeps
//! both sides; a conflicting merge, or a base that has left the ring, makes the client text the new
//! head and hands the old head back to be kept as a `conflict` version.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The client's text is the head (base was the head, or the text did not change).
    Saved,
    /// Both sides were kept by a clean merge.
    Merged,
    /// Overlapping edits: the client's hunk won, the old head is a `conflict` version.
    Conflict,
    /// The base is no longer in the ring: the client text won, the old head is a `conflict` version.
    BaseLost,
}

impl Outcome {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Saved => "saved",
            Self::Merged => "merged",
            Self::Conflict => "conflict",
            Self::BaseLost => "base_lost",
        }
    }
}

pub(crate) struct Resolved {
    /// The text that becomes the head.
    pub text: String,
    pub outcome: Outcome,
    /// The old head must be kept as a `conflict` version.
    pub keep_head: bool,
}

/// `fresh`: the client edited from the head itself. `base`: the ring's text at the client's revision.
pub(crate) fn resolve(fresh: bool, base: Option<&str>, head: &str, client: &str) -> Resolved {
    let done = |text: &str, outcome, keep_head| Resolved {
        text: text.to_owned(),
        outcome,
        keep_head,
    };
    if fresh || client == head {
        return done(client, Outcome::Saved, false);
    }
    let Some(base) = base else {
        return done(client, Outcome::BaseLost, true);
    };
    if client == base {
        // The client changed nothing: the head stands, and is what the client now gets back.
        return done(head, Outcome::Merged, false);
    }
    if head == base {
        return done(client, Outcome::Saved, false);
    }
    match diffy::merge(base, head, client) {
        Ok(merged) => done(&merged, Outcome::Merged, false),
        Err(_) => done(client, Outcome::Conflict, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    /// SplitMix64: a deterministic stream, so a failing interleaving reproduces from its number.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    fn lines(t: &str) -> Vec<String> {
        t.lines().map(str::to_owned).collect()
    }

    fn join(l: &[String]) -> String {
        l.iter().map(|x| format!("{x}\n")).collect()
    }

    #[test]
    fn the_basic_outcomes() {
        let r = resolve(false, Some("a\nb\nc\n"), "a\nb\nc\nAI\n", "x\na\nb\nc\n");
        assert_eq!(
            (r.text.as_str(), r.outcome),
            ("x\na\nb\nc\nAI\n", Outcome::Merged)
        );
        let r = resolve(false, Some("a\nb\n"), "a\nAI\n", "a\nme\n");
        assert_eq!(
            (r.text.as_str(), r.outcome, r.keep_head),
            ("a\nme\n", Outcome::Conflict, true)
        );
        let r = resolve(false, None, "head\n", "mine\n");
        assert_eq!(
            (r.text.as_str(), r.outcome, r.keep_head),
            ("mine\n", Outcome::BaseLost, true)
        );
        let r = resolve(false, Some("a\n"), "a\nAI\n", "a\n");
        assert_eq!((r.text.as_str(), r.outcome), ("a\nAI\n", Outcome::Merged));
        let r = resolve(true, None, "a\n", "b\n");
        assert_eq!(
            (r.text.as_str(), r.outcome, r.keep_head),
            ("b\n", Outcome::Saved, false)
        );
    }

    /// 10 000 random interleavings of client saves (from a random, possibly stale or vanished base)
    /// and head appends/inserts: every line a writer inserted is in the head or in a kept version.
    #[test]
    fn no_inserted_line_is_lost_in_10000_interleavings() {
        let mut outcomes: HashMap<&str, u32> = HashMap::new();
        for seed in 0..10_000u64 {
            let mut rng = Rng(seed);
            let mut head: Vec<String> = (0..rng.below(6))
                .map(|i| format!("seed-{seed}-{i}"))
                .collect();
            let mut rev = 1u32;
            let mut ring: Vec<(u32, String)> = vec![(1, join(&head))];
            let mut kept: Vec<String> = Vec::new();
            let mut tracked: HashSet<String> = HashSet::new();
            for step in 0..(4 + rng.below(12)) {
                let mark = format!("ins-{seed}-{step}");
                if rng.below(2) == 0 {
                    // a head write (AI append, or an insert in the middle)
                    let at = if rng.below(2) == 0 {
                        head.len()
                    } else {
                        rng.below(head.len() + 1)
                    };
                    head.insert(at, mark.clone());
                    tracked.insert(mark);
                    rev += 1;
                    ring.push((rev, join(&head)));
                    if ring.len() > 20 {
                        ring.remove(0);
                    }
                } else {
                    // a client save from a ring revision, or from one that has left the ring
                    let (base, base_text) = if rng.below(10) == 0 {
                        (None, lines(&ring[0].1))
                    } else {
                        let (_, t) = &ring[rng.below(ring.len())];
                        (Some(t.clone()), lines(t))
                    };
                    let mut client = base_text;
                    if !client.is_empty() && rng.below(3) == 0 {
                        // a deletion is the writer's choice, so what it removes is no longer owed
                        let gone = client.remove(rng.below(client.len()));
                        tracked.remove(&gone);
                    }
                    let at = rng.below(client.len() + 1);
                    client.insert(at, mark.clone());
                    tracked.insert(mark);
                    let head_text = join(&head);
                    let r = resolve(false, base.as_deref(), &head_text, &join(&client));
                    *outcomes.entry(r.outcome.name()).or_default() += 1;
                    if r.keep_head {
                        kept.push(head_text);
                    }
                    head = lines(&r.text);
                    rev += 1;
                    ring.push((rev, r.text));
                    if ring.len() > 20 {
                        ring.remove(0);
                    }
                }
                let present: HashSet<String> = head
                    .iter()
                    .cloned()
                    .chain(kept.iter().flat_map(|k| lines(k)))
                    .collect();
                for t in &tracked {
                    assert!(present.contains(t), "seed {seed} step {step}: lost {t}");
                }
            }
        }
        // the generator really exercises every path
        for k in ["saved", "merged", "conflict", "base_lost"] {
            assert!(
                outcomes.get(k).copied().unwrap_or(0) > 100,
                "{k}: {outcomes:?}"
            );
        }
    }
}
