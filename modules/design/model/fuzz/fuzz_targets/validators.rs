#![no_main]
//! V1-02: every validator, the resolver and the lint on arbitrary bytes. Property: no panic, no hang, and whatever
//! the resolver returns stays within its diagnostics budget. The first byte picks the entry point.
use design_model::{Doc, NodeType, Theme, ids, lint, resolve, svgpath, validate};
use libfuzzer_sys::fuzz_target;

const TYPES: [NodeType; 9] = [
    NodeType::Page,
    NodeType::Frame,
    NodeType::Text,
    NodeType::Rect,
    NodeType::Ellipse,
    NodeType::Image,
    NodeType::Vector,
    NodeType::Component,
    NodeType::Instance,
];

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else { return };
    match sel % 4 {
        0 => {
            // SVG path grammar
            if let Ok(s) = std::str::from_utf8(rest) {
                let _ = svgpath::validate(s);
            }
        }
        1 => {
            // one prop map against a node type, raw (token refs allowed) and resolved, and as overrides
            if let Ok(serde_json::Value::Object(m)) = serde_json::from_slice(rest) {
                let ty = TYPES[usize::from(sel / 4) % TYPES.len()];
                let _ = validate::props(ty, &m, &mut validate::Cx::raw());
                let _ = validate::props(ty, &m, &mut validate::Cx::resolved());
                let _ = validate::override_props(&serde_json::Value::Object(m), &mut validate::Cx::raw());
            }
        }
        2 => {
            // ids, orders, token names, refs
            if let Ok(s) = std::str::from_utf8(rest) {
                let _ = ids::is_node_id(s);
                let _ = ids::is_doc_id(s);
                let _ = ids::is_token_name(s);
                let _ = ids::parse_component_ref(s);
                let (a, b) = s.split_once('|').unwrap_or((s, ""));
                let _ = ids::between(Some(a), Some(b));
            }
        }
        _ => {
            // a whole document: parse, validate, lint, resolve both themes
            let Ok(doc) = Doc::from_json(rest) else { return };
            let _ = validate::doc(&doc);
            let _ = lint("dd_fuzz", &doc, None, None);
            for theme in [Theme::Day, Theme::Night] {
                if let Ok(r) = resolve("dd_fuzz", &doc, None, theme) {
                    assert!(r.diagnostics.len() <= 1000);
                }
            }
        }
    }
});
