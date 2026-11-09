//! What a run is told of its project's knowledge (E8.1): the accepted entries, most relevant
//! first, fitted to a size budget. What the budget leaves out is listed, never dropped silently.

use super::{KnowledgeEntry, KnowledgeKind};

/// The most a run is given of knowledge entries (titles and bodies), in bytes: the default of
/// the `knowledge.budget_bytes` setting (E15.17).
pub const KNOWLEDGE_BUDGET_BYTES: usize = 16 * 1024;

impl KnowledgeKind {
    /// Higher is more relevant, and is kept first when a project's knowledge overflows the
    /// budget: landmines, then decisions, then state, then retro notes.
    pub fn precedence(self) -> u8 {
        match self {
            Self::Landmine => 3,
            Self::Decision => 2,
            Self::State => 1,
            Self::Retro => 0,
        }
    }
}

/// The knowledge a run is given, and what its budget left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunKnowledge {
    /// By precedence (highest first), then newest first.
    pub entries: Vec<KnowledgeEntry>,
    /// What did not fit, in the same order.
    pub dropped: Vec<KnowledgeEntry>,
}

/// The size an entry takes from the budget.
fn size(k: &KnowledgeEntry) -> usize {
    k.title.len() + k.body.len()
}

/// Orders `entries` by precedence, then newest (highest id) first, and keeps each one that
/// still fits in `budget` bytes; one that does not is dropped and listed, and smaller ones
/// after it may still fit.
pub fn fit_knowledge(mut entries: Vec<KnowledgeEntry>, budget: usize) -> RunKnowledge {
    entries.sort_by(|a, b| {
        let by_precedence = b.kind.precedence().cmp(&a.kind.precedence());
        by_precedence.then_with(|| b.id.cmp(&a.id))
    });
    let (mut out, mut left) = (RunKnowledge::default(), budget);
    for k in entries {
        match left.checked_sub(size(&k)) {
            Some(rest) => {
                left = rest;
                out.entries.push(k);
            }
            None => out.dropped.push(k),
        }
    }
    out
}

impl RunKnowledge {
    /// The kept entries as one markdown document, for a harness's instructions; `None` when
    /// there are none. What the budget dropped is named at the end, so the agent knows.
    pub fn render(&self) -> Option<String> {
        if self.entries.is_empty() && self.dropped.is_empty() {
            return None;
        }
        let mut out = String::from("# Project knowledge\n\n");
        for k in &self.entries {
            out.push_str(&format!(
                "## {} {}: {}\n\n{}\n\n",
                k.kind.as_str(),
                k.id.0,
                k.title,
                k.body.trim()
            ));
        }
        if !self.dropped.is_empty() {
            let left: Vec<String> = self
                .dropped
                .iter()
                .map(|k| format!("{} {} ({})", k.kind.as_str(), k.id.0, k.title))
                .collect();
            out.push_str(&format!(
                "Left out for size (read them with get_context): {}.\n",
                left.join(", ")
            ));
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{KnowledgeEntryId, KnowledgeStatus};
    use super::*;
    use crate::work::ProjectId;

    fn entry(id: i64, kind: KnowledgeKind, bytes: usize) -> KnowledgeEntry {
        KnowledgeEntry {
            id: KnowledgeEntryId(id),
            project_id: ProjectId(1),
            kind,
            title: format!("t{id}"),
            body: "x".repeat(bytes),
            status: KnowledgeStatus::Accepted,
            proposed_by: None,
            decided_by: None,
            decided_by_agent: None,
            reason: None,
            targets_spec: false,
            profile_field: None,
            rationale: None,
            retired_reason: None,
            supersedes: None,
        }
    }

    #[test]
    fn landmines_first_newest_first_and_the_overflow_is_listed() {
        use KnowledgeKind::*;
        let all = vec![
            entry(1, Retro, 8),
            entry(2, Landmine, 8),
            entry(3, State, 8),
            entry(4, Decision, 8),
            entry(5, Landmine, 8),
        ];
        let ids = |v: &[KnowledgeEntry]| v.iter().map(|k| k.id.0).collect::<Vec<_>>();
        let fitted = fit_knowledge(all.clone(), 1000);
        assert_eq!(ids(&fitted.entries), [5, 2, 4, 3, 1]);
        assert!(fitted.dropped.is_empty());

        // Each takes 10 bytes (a 2-byte title and an 8-byte body).
        let tight = fit_knowledge(all.clone(), 35);
        assert_eq!(ids(&tight.entries), [5, 2, 4]);
        assert_eq!(ids(&tight.dropped), [3, 1]);
        let used: usize = tight.entries.iter().map(size).sum();
        assert!(used <= 35);

        let shown = tight.render().unwrap();
        assert!(shown.starts_with("# Project knowledge\n\n## landmine 5: t5\n\n"));
        assert!(
            shown.ends_with(
                "Left out for size (read them with get_context): state 3 (t3), retro 1 (t1).\n"
            ),
            "{shown}"
        );
        assert_eq!(fit_knowledge(vec![], 10).render(), None);
    }

    #[test]
    fn a_big_entry_is_dropped_and_smaller_ones_still_fit() {
        let fitted = fit_knowledge(
            vec![
                entry(1, KnowledgeKind::Decision, 8),
                entry(2, KnowledgeKind::Landmine, 100),
            ],
            20,
        );
        assert_eq!(fitted.entries[0].id.0, 1);
        assert_eq!(fitted.dropped[0].id.0, 2);
    }
}
