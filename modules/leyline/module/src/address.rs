//! Which host a caller means (port of the old plugin's `ConnectionAddress`).
//!
//! 1. An exact id wins outright, even when another host's label is that same string: an id is
//!    Leyline's own name for a host, a label is typed text that can be made to look like one.
//! 2. Otherwise a unique case-insensitive label.
//! 3. Two or more hosts with that label: an error naming the ambiguity, never a silent pick.
//! 4. Nothing: not found.
//!
//! Address and username are deliberately not matched. The table keeps labels unique, so (3) cannot
//! happen through the API today; the rule stays so a future import or a relaxed constraint can
//! never make addressing guess which machine a command runs on.

/// One candidate: a stored id and stored label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cand {
    pub id: String,
    pub label: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Match<'a> {
    One(&'a Cand),
    /// The shared label (the stored one, never the caller's text) and how many hosts carry it.
    Ambiguous {
        label: String,
        count: usize,
    },
    NotFound,
}

pub fn resolve<'a>(ident: &str, hosts: &'a [Cand]) -> Match<'a> {
    if let Some(h) = hosts.iter().find(|h| h.id.eq_ignore_ascii_case(ident)) {
        return Match::One(h);
    }
    let by_label: Vec<&Cand> = hosts
        .iter()
        .filter(|h| !h.label.is_empty() && h.label.eq_ignore_ascii_case(ident))
        .collect();
    match by_label.as_slice() {
        [] => Match::NotFound,
        [one] => Match::One(one),
        [first, ..] => Match::Ambiguous {
            label: first.label.clone(),
            count: by_label.len(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(id: &str, label: &str) -> Cand {
        Cand {
            id: id.into(),
            label: label.into(),
        }
    }

    #[test]
    fn an_id_wins_over_a_label_that_equals_it() {
        let hosts = [
            c("h_0000000000000001", "web"),
            c("h_0000000000000002", "h_0000000000000001"),
        ];
        assert_eq!(resolve("h_0000000000000001", &hosts), Match::One(&hosts[0]));
        assert_eq!(resolve("H_0000000000000001", &hosts), Match::One(&hosts[0]));
    }

    #[test]
    fn a_label_matches_case_insensitively_and_only_when_unique() {
        let hosts = [c("h_1", "Web"), c("h_2", "db"), c("h_3", "DB")];
        assert_eq!(resolve("WEB", &hosts), Match::One(&hosts[0]));
        assert_eq!(
            resolve("db", &hosts),
            Match::Ambiguous {
                label: "db".into(),
                count: 2
            }
        );
        assert_eq!(resolve("nope", &hosts), Match::NotFound);
        assert_eq!(resolve("", &[c("h_9", "")]), Match::NotFound);
    }
}
