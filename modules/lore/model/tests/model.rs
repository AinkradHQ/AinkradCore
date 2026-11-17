//! R1-03 acceptance: golden fixtures, limits, hostile input, properties, speed, dependency list.
//! Regenerate the goldens with `UPDATE_GOLDEN=1 cargo test` and read the diff before committing.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Instant;

use lore_model::{ParseError, Parsed, limits, normalize_title, parse};
use proptest::prelude::*;

#[test]
fn fixtures_parse_to_the_expected_json() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut n = 0;
    for entry in fs::read_dir(&root).unwrap() {
        let dir = entry.unwrap().path();
        let text = fs::read_to_string(dir.join("note.md")).unwrap();
        let got = serde_json::to_value(parse(&text).unwrap()).unwrap();
        let path = dir.join("expected.json");
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            fs::write(&path, serde_json::to_string_pretty(&got).unwrap() + "\n").unwrap();
        } else {
            let want: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(got, want, "{}", dir.display());
        }
        n += 1;
    }
    assert!(n >= 3);
}

#[test]
fn title_rules() {
    let t = |s: &str| parse(s).unwrap().title;
    assert_eq!(t(""), "Untitled");
    assert_eq!(t("   \n\n"), "Untitled");
    assert_eq!(t("hello\n# Heading"), "Heading"); // the first H1 beats the first line
    assert_eq!(t("hello\n## Sub"), "hello");
    assert_eq!(t("## Sub\ntext"), "Sub");
    assert_eq!(t("```\ncode\n```\nafter"), "after");
    assert_eq!(t(&"é".repeat(500)).chars().count(), limits::MAX_TITLE_CHARS);
    assert_eq!(parse("# A  Title ").unwrap().title_norm, "a title");
}

#[test]
fn normalisation() {
    assert_eq!(normalize_title("  Spare \t Parts\n"), "spare parts");
    assert_eq!(normalize_title(""), "");
}

#[test]
fn too_large_is_refused() {
    let big = "a".repeat(limits::MAX_TEXT_BYTES + 1);
    assert_eq!(
        parse(&big),
        Err(ParseError::TooLarge {
            len: big.len(),
            max: limits::MAX_TEXT_BYTES
        })
    );
    assert!(parse(&"a".repeat(limits::MAX_TEXT_BYTES)).is_ok());
}

#[test]
fn deep_nesting_gets_no_structure_but_no_crash() {
    let quotes = format!("{}# Deep\n", "> ".repeat(50_000));
    let p = parse(&quotes).unwrap();
    assert!(p.headings.is_empty() && p.tasks.is_empty());
    assert_eq!(parse("> > > # Ok\n").unwrap().headings.len(), 1);
    let indented = format!("{}- [ ] deep\n", " ".repeat(200));
    assert!(parse(&indented).unwrap().tasks.is_empty());
}

#[test]
fn item_caps_set_truncated() {
    let many: String = (0..limits::MAX_WIKILINKS + 10)
        .map(|i| format!("[[T{i}]] "))
        .collect();
    let p = parse(&many).unwrap();
    assert_eq!(p.wikilinks.len(), limits::MAX_WIKILINKS);
    assert!(p.truncated);
    let tags: String = (0..300).map(|i| format!("#t{i} ")).collect();
    let p = parse(&tags).unwrap();
    assert_eq!(p.tags.len(), limits::MAX_TAGS);
    assert!(p.truncated);
    assert!(!parse("# fine").unwrap().truncated);
}

fn timed(text: &str) {
    let text = &text[..text.floor_char_boundary(limits::MAX_TEXT_BYTES)];
    let t = Instant::now();
    let p = parse(text).unwrap();
    let e = t.elapsed();
    // hostile shapes must stay linear: 2 MB in well under 2 s even unoptimised
    let head = &text[..text.floor_char_boundary(12)];
    // linear means seconds-not-minutes even unoptimised (2M blank lines take ~7 s in debug, well under 1 s in release)
    let budget = if cfg!(debug_assertions) { 30.0 } else { 2.0 };
    assert!(
        e.as_secs_f64() < budget,
        "{e:?} for {} bytes: {head:?}",
        text.len()
    );
    check_invariants(&p);
}

#[test]
fn hostile_shapes_stay_linear() {
    let n = limits::MAX_TEXT_BYTES;
    timed(&"[[".repeat(n / 2));
    timed(&"[a](x".repeat(n / 5));
    timed(&"[a](".repeat(n / 4));
    timed(&"[a]".repeat(n / 3));
    timed(&"#".repeat(n));
    timed(&"# ".repeat(n / 2));
    timed(&"`".repeat(n));
    timed(&"\\".repeat(n));
    timed(&"é[[".repeat(n / 4));
    timed(&"> ".repeat(n / 2));
    timed(&"\n".repeat(n));
    timed(&"- [ ] x\n".repeat(n / 8));
    timed(&"[[a]]\n".repeat(n / 6));
    timed(&"[[a|b#c]] ".repeat(n / 10));
    timed(&"[a](u \"t\") ".repeat(n / 11));
    // backtick runs of every length: the case a naive closer search makes quadratic
    let runs: String = (1..1900).map(|k| format!("{} ", "`".repeat(k))).collect();
    timed(&runs);
    timed(&format!("---\n{}", "tags: a\n".repeat(n / 8)));
}

#[test]
fn ten_thousand_words_parse_fast() {
    let para = "Words with a [[Link Target]] and #tag and `code` and [text](https://example.test/x) here. ";
    let text: String = (0..10_000 / 12).map(|i| format!("{para}{i}\n")).collect();
    let words = parse(&text).unwrap().words;
    assert!(words >= 10_000, "{words}");
    // best of many: sibling tests run in parallel on a small box
    let best = (0..30)
        .map(|_| {
            let t = Instant::now();
            std::hint::black_box(parse(&text).unwrap());
            t.elapsed()
        })
        .min()
        .unwrap();
    // the 2 ms budget is for the release profile (vps-1 runs `cargo test --release`); debug only checks it is sane
    let budget = if cfg!(debug_assertions) { 1000.0 } else { 2.0 };
    assert!(best.as_secs_f64() * 1000.0 < budget, "{best:?}");
}

/// What the store relies on, for any input.
fn check_invariants(p: &Parsed) {
    use limits::*;
    assert!(!p.title.is_empty() && p.title.chars().count() <= MAX_TITLE_CHARS);
    assert_eq!(p.title_norm, normalize_title(&p.title));
    assert!(p.headings.len() <= MAX_HEADINGS && p.wikilinks.len() <= MAX_WIKILINKS);
    assert!(p.links.len() <= MAX_LINKS && p.tasks.len() <= MAX_TASKS);
    assert!(p.tags.len() <= MAX_TAGS && p.attachments.len() <= MAX_ATTACHMENTS);
    assert!(
        p.headings
            .iter()
            .all(|h| (1..=6).contains(&h.level) && !h.text.is_empty())
    );
    assert!(
        p.tags
            .iter()
            .all(|t| t.chars().count() <= MAX_TAG_CHARS && *t == t.to_lowercase())
    );
    assert_eq!(p.tags.iter().collect::<BTreeSet<_>>().len(), p.tags.len());
    let mut keys = BTreeSet::new();
    for w in &p.wikilinks {
        assert!(!w.title.is_empty() && !w.title_norm.is_empty());
        assert_eq!(w.title_norm, normalize_title(&w.title));
        assert!(w.context.chars().count() <= MAX_CONTEXT_CHARS);
        assert!(
            keys.insert((w.title_norm.clone(), w.heading.clone())),
            "duplicate link"
        );
    }
    assert!(
        p.links
            .iter()
            .all(|l| !l.url.is_empty() && l.url.len() <= MAX_URL_BYTES)
    );
    assert!(p.attachments.iter().all(|a| a.len() == 64));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn any_text_parses_deterministically_within_bounds(s in "\\PC{0,600}") {
        let a = parse(&s).unwrap();
        check_invariants(&a);
        prop_assert_eq!(a, parse(&s).unwrap());
    }

    /// Markdown-shaped soup, so the structural branches get hit.
    #[test]
    fn markup_soup_is_bounded(parts in proptest::collection::vec(
        prop_oneof![
            Just("[["), Just("]]"), Just("["), Just("]("), Just(")"), Just("`"), Just("```\n"), Just("\n"),
            Just("# "), Just("> "), Just("- [ ] "), Just("- [x] "), Just("#t "), Just("|"), Just("\\"),
            Just("---\n"), Just("tags: a, b\n"), Just("lore-attachment:"), Just("é"), Just(" "), Just("word"),
        ], 0..120)) {
        let s: String = parts.concat();
        check_invariants(&parse(&s).unwrap());
    }

    #[test]
    fn normalisation_is_idempotent(s in "\\PC{0,80}") {
        let n = normalize_title(&s);
        prop_assert_eq!(normalize_title(&n), n);
    }

    #[test]
    fn code_hides_links(title in "[A-Za-z]{1,12}") {
        let inline = parse(&format!("`[[{title}]]` #t")).unwrap();
        prop_assert!(inline.wikilinks.is_empty());
        let fenced = parse(&format!("```\n[[{title}]]\n```\n")).unwrap();
        prop_assert!(fenced.wikilinks.is_empty());
        let plain = parse(&format!("[[{title}]]")).unwrap();
        prop_assert_eq!(plain.wikilinks.len(), 1);
    }

    /// Anything after a blank line never changes what came before it, unless it opens a fence at the very start of
    /// the tail; those cases are excluded by starting the tail with a letter.
    #[test]
    fn a_closed_prefix_is_stable(tail in "[A-Za-z]\\PC{0,200}") {
        let head = "# T\n\n- [ ] a #x [[B]]\n\n";
        let p = parse(&format!("{head}{tail}")).unwrap();
        prop_assert_eq!(&p.headings[0].text, "T");
        prop_assert!(p.tasks.iter().any(|t| t.text.starts_with("a #x")));
        prop_assert!(p.wikilinks.iter().any(|w| w.title == "B"));
    }
}

#[test]
fn the_crate_has_only_the_reviewed_dependencies() {
    let manifest = include_str!("../Cargo.toml");
    let deps: BTreeSet<&str> = manifest
        .split("\n[")
        .filter(|s| s.starts_with("dependencies]") || s.starts_with("dev-dependencies]"))
        .flat_map(|s| s.lines().skip(1))
        .filter_map(|l| l.split('=').next().map(str::trim))
        .filter(|n| !n.is_empty() && !n.starts_with('#'))
        .collect();
    assert_eq!(
        deps,
        BTreeSet::from(["serde", "serde_json", "proptest"]),
        "a new dependency needs a conscious review"
    );
    // normal dependencies, transitive included: serde only, no Markdown parser, no I/O or DB stack
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = std::process::Command::new(cargo)
        .args([
            "tree",
            "--offline",
            "-p",
            "lore-model",
            "-e",
            "normal",
            "--prefix",
            "none",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tree = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(
        tree.contains("serde"),
        "cargo tree printed nothing useful: {tree}"
    );
    for banned in [
        "pulldown",
        "comrak",
        "skia",
        "tokio",
        "sqlx",
        "rusqlite",
        "serde_json",
        "regex",
    ] {
        assert!(
            !tree.contains(banned),
            "lore-model must not depend on {banned}"
        );
    }
}
