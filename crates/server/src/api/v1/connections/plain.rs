//! The plain sentence under each capability's title, for the guided Add and "What AI may do".
//! Data, not logic: a kind or capability this table does not know gets a sentence by its class,
//! so a new kind needs no change here to draw a screen.

/// What `capability` of `kind` lets AI do, in one sentence. A write one says it changes things.
pub fn summary(kind: &str, capability: &str, write: bool) -> &'static str {
    match (kind, capability) {
        ("github", "read_repo") => "See what is in your repositories. Nothing changes.",
        ("github", "issues_write") => "Create and edit issues, and comment on them.",
        ("github", "pr_write") => "Open pull requests and comment on them.",
        ("github", "push") => "Create branches and commit files in your repositories.",
        ("jira", "read_issues") => "See your tickets and boards. Nothing changes.",
        ("jira", "write_issues") => "Create tickets, edit them and comment.",
        ("jira", "transition") => "Change a ticket's status.",
        ("linear", "read_issues") => "See your issues, teams and projects. Nothing changes.",
        ("linear", "write_issues") => "Create issues, edit them and comment.",
        ("slack", "read_messages") => "See the conversation in your channels. Nothing is sent.",
        ("slack", "post_messages") => "Write in your channels and react.",
        ("teams", "read_messages") => "See the conversation. Nothing is sent.",
        ("teams", "post_messages") => "Reply and post in channels, as you.",
        (_, _) if write => "Changes things on the service.",
        _ => "Looks, never changes anything.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::adapter::Registry;

    #[test]
    fn every_shipped_capability_has_its_own_sentence() {
        let generic = [
            "Changes things on the service.",
            "Looks, never changes anything.",
        ];
        for d in Registry::builtin().descriptors() {
            for c in d.capabilities {
                let s = summary(d.kind, c.name, c.write);
                assert!(
                    !generic.contains(&s),
                    "{}.{} has no sentence",
                    d.kind,
                    c.name
                );
                assert_eq!(
                    s.contains("Nothing changes") || s.contains("Nothing is sent"),
                    !c.write
                );
            }
        }
    }

    #[test]
    fn an_unknown_capability_is_told_by_its_class() {
        assert_eq!(summary("x", "y", true), "Changes things on the service.");
        assert_eq!(summary("x", "y", false), "Looks, never changes anything.");
    }
}
