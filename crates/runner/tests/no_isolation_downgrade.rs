//! There is no downgrade path (E8a-09, plan P8a.2): a session that needs an isolation tier is
//! refused where it cannot get it, never run at a weaker one. The behaviour is tested where it
//! happens (the scheduler, the runner's start, the watch); this scans the code for the shapes a
//! downgrade would take, so adding one fails a test and not only a review.

use std::path::{Path, PathBuf};

fn crates() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Every non-test `.rs` file under the crates' `src` directories, with its text.
fn sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    let mut files = vec![];
    for krate in ["core", "server", "runner", "harness", "proto"] {
        walk(&crates().join(krate).join("src"), &mut files);
    }
    files
        .into_iter()
        .filter(|p| {
            let s = p.to_string_lossy();
            !(s.contains("/tests/")
                || s.ends_with("tests.rs")
                || s.ends_with("_tests.rs")
                || s.ends_with("skew.rs"))
        })
        .map(|p| {
            let text = std::fs::read_to_string(&p).unwrap();
            // Drop `#[cfg(test)]` modules written inline: from the attribute to the end of file.
            let text = match text.find("#[cfg(test)]\nmod tests {") {
                Some(at) => text[..at].to_owned(),
                None => text,
            };
            let rel = p
                .strip_prefix(crates())
                .unwrap()
                .to_string_lossy()
                .into_owned();
            (rel, text)
        })
        .collect()
}

fn files_containing(sources: &[(String, String)], needle: &str) -> Vec<String> {
    let mut found: Vec<String> = sources
        .iter()
        .filter(|(_, t)| t.contains(needle))
        .map(|(f, _)| f.clone())
        .collect();
    found.sort();
    found
}

#[test]
fn tiers_have_no_ordering_but_satisfies_and_only_the_known_places_compare() {
    let src = sources();
    // The enum is not `Ord`: nothing can `max`, `min` or `<` two tiers around `satisfies`.
    let iso = &src
        .iter()
        .find(|(f, _)| f == "proto/src/runner/isolation.rs")
        .unwrap()
        .1;
    let before = &iso[..iso.find("pub enum Isolation").unwrap()];
    let attrs = &before[before.rfind("#[derive(").unwrap()..];
    assert!(
        !attrs.contains("PartialOrd") && !attrs.contains("Ord"),
        "Isolation must not be ordered: {attrs}"
    );
    // The rank is private to the type.
    assert_eq!(
        files_containing(&src, ".rank()"),
        ["proto/src/runner/isolation.rs"]
    );
    // A requirement is met in exactly these places: an offer (`meets`), the runner's own start
    // and its watch. The Core's placement goes through `meets`.
    assert_eq!(
        files_containing(&src, ".satisfies("),
        ["proto/src/v2/mod.rs", "runner/src/v2/agent.rs"]
    );
    assert_eq!(files_containing(&src, ".meets("), ["server/src/agents.rs"]);
}

#[test]
fn nothing_rewrites_a_sessions_required_tier() {
    let src = sources();
    // `min_isolation` is read where a session is checked and set only by its owner (the policy);
    // no code assigns it, defaults it, takes it or maps it to something weaker.
    let allowed = [
        "proto/src/runner/policy.rs",
        "runner/src/v2/agent.rs",
        "server/src/agents.rs",
        // The changelog line of API minor 26.
        "server/src/api/v1/types.rs",
    ];
    assert_eq!(
        files_containing(&src, "min_isolation"),
        allowed.map(String::from).to_vec()
    );
    for (file, text) in &src {
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.starts_with("//") || !line.contains("min_isolation") {
                continue;
            }
            for bad in [
                "min_isolation =",
                "min_isolation.take()",
                "min_isolation.replace(",
                "min_isolation.unwrap_or",
                "min_isolation.map(",
                "min_isolation.or(",
                "min_isolation.or_else(",
                "min_isolation.get_or_insert",
                ".min_isolation = ",
            ] {
                assert!(
                    !line.contains(bad) || line.contains("==") && bad == "min_isolation =",
                    "{file}:{}: a required tier is rewritten: {line}",
                    n + 1
                );
            }
        }
    }
}

#[test]
fn the_places_that_refuse_never_fall_back_to_another_tier() {
    let src = sources();
    for (file, text) in &src {
        if !(file.ends_with("server/src/agents.rs") || file.ends_with("runner/src/v2/agent.rs")) {
            continue;
        }
        for (n, line) in text.lines().enumerate() {
            // `Arc::downgrade` is a weak pointer, not a tier.
            let l = line.trim().to_lowercase().replace("arc::downgrade", "");
            if l.starts_with("//") {
                continue;
            }
            for word in [
                "downgrade",
                "fall back",
                "falls back",
                "weaker tier",
                "lower tier",
            ] {
                assert!(
                    !l.contains(word) || l.contains("never") || l.contains("not "),
                    "{file}:{}: reads like a fallback: {line}",
                    n + 1
                );
            }
        }
    }
}
