#![no_main]
//! R1-03: the Markdown scanner on arbitrary text. Properties: no panic or hang, deterministic output, every limit
//! respected, titles and tags well-formed, wikilinks unique per (title, heading), context cut.
use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use lore_model::{limits, normalize_title, parse};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let p = parse(s).expect("fuzz inputs are under the size limit");
    assert_eq!(p, parse(s).unwrap(), "parse is not deterministic");
    assert!(!p.title.is_empty() && p.title.chars().count() <= limits::MAX_TITLE_CHARS);
    assert_eq!(p.title_norm, normalize_title(&p.title));
    assert!(p.headings.len() <= limits::MAX_HEADINGS && p.tasks.len() <= limits::MAX_TASKS);
    assert!(p.links.len() <= limits::MAX_LINKS && p.wikilinks.len() <= limits::MAX_WIKILINKS);
    assert!(p.tags.len() <= limits::MAX_TAGS && p.attachments.len() <= limits::MAX_ATTACHMENTS);
    assert!(
        p.headings
            .iter()
            .all(|h| (1..=6).contains(&h.level) && !h.text.is_empty())
    );
    assert!(
        p.tags
            .iter()
            .all(|t| !t.is_empty() && t.chars().count() <= limits::MAX_TAG_CHARS)
    );
    assert_eq!(p.tags.iter().collect::<BTreeSet<_>>().len(), p.tags.len());
    let mut keys = BTreeSet::new();
    for w in &p.wikilinks {
        assert!(!w.title_norm.is_empty() && w.context.chars().count() <= limits::MAX_CONTEXT_CHARS);
        assert!(keys.insert((&w.title_norm, &w.heading)));
    }
    assert!(p.attachments.iter().all(|a| a.len() == 64));
});
