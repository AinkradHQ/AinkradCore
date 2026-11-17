//! Structural lint: is this document well-formed enough to resolve and draw? (The house design rules, `radius.tokens`
//! and friends, are V5-02 and build on the same `Finding` shape.) Findings are ordered, so two runs agree.

use std::collections::BTreeSet;

use serde::Serialize;
use serde_json::Value;

use crate::ids::is_node_id;
use crate::ids::{is_sha256, parse_component_ref};
use crate::limits::*;
use crate::resolve::{Theme, resolve};
use crate::schema::{Doc, NodeType};
use crate::tree::{Forest, forest};
use crate::validate::{self, clip, clip_n};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    pub node: Option<String>,
    pub msg: String,
    pub fix: &'static str,
}

const MAX_FINDINGS: usize = 500;

fn fix_for(rule: &str) -> &'static str {
    match rule {
        "schema.invalid" => "remove the prop or set a value the schema allows",
        "tree.detached" => "move the node under a page or a frame, or delete it",
        "tree.cycle" => "two moves crossed; put the node back where it belongs",
        "tree.leaf-parent" => "move the node into a frame, or turn its parent into a frame",
        "tree.page-nested" => "move the page to the top level",
        "tree.depth" => "flatten the nesting",
        "tree.order-tie" => "reorder the siblings",
        "link.target" => "point the link at an existing screen, or remove it",
        "asset.missing" => "add the asset to the library or pick another",
        "token.local-ignored" => "put the token in the design system",
        "override.dangling" => "remove the override or point it at a child that exists",
        _ => "see the message",
    }
}

fn find(
    rule: &'static str,
    severity: Severity,
    node: Option<&str>,
    msg: impl Into<String>,
) -> Finding {
    Finding {
        rule,
        severity,
        node: node.map(|n| clip_n(n, 64)),
        msg: clip_n(&msg.into(), 256),
        fix: fix_for(rule),
    }
}

/// Lint `doc`. `system` is its design system doc (for component lookups); `assets` the known library hashes
/// (`None` = unknown, the asset check is skipped).
pub fn lint(
    doc_id: &str,
    doc: &Doc,
    system: Option<(&str, &Doc)>,
    assets: Option<&BTreeSet<String>>,
) -> Vec<Finding> {
    use Severity::*;
    // same rule as the resolver: only the system the design names
    let system = system.filter(|(id, _)| doc.meta.system.as_deref() == Some(*id));
    let mut out = vec![];
    for v in validate::doc(doc) {
        let node = v
            .path
            .strip_prefix("nodes.")
            .and_then(|r| r.split('.').next());
        out.push(find("schema.invalid", Error, node, v.msg));
    }
    // Too big to walk, or ids that are not ids (a 1 MB id would be copied into every finding): the schema findings
    // above already say so, and nothing below can be trusted to stay small.
    let bad_ids = doc
        .nodes
        .iter()
        .any(|(id, n)| !is_node_id(id) || n.parent.as_deref().is_some_and(|p| !is_node_id(p)));
    if doc.nodes.len() > MAX_NODES || bad_ids {
        out.sort();
        out.dedup();
        out.truncate(MAX_FINDINGS);
        return out;
    }
    let f = forest(doc);
    for id in &f.broken {
        out.push(find(
            "tree.cycle",
            Error,
            Some(id),
            "a move cycle was cut here",
        ));
    }
    for id in f
        .detached
        .iter()
        .filter(|i| f.broken.binary_search(i).is_err())
    {
        out.push(find(
            "tree.detached",
            Error,
            Some(id),
            "node has no parent (or its parent does not exist)",
        ));
    }
    for (pid, kids) in &f.children {
        let p = &doc.nodes[pid];
        if !p.ty.is_container() {
            for k in kids {
                out.push(find(
                    "tree.leaf-parent",
                    Error,
                    Some(k),
                    format!("parent is a {:?} node, which has no children", p.ty),
                ));
            }
        }
        for w in kids.windows(2) {
            if doc.nodes[&w[0]].order == doc.nodes[&w[1]].order {
                out.push(find(
                    "tree.order-tie",
                    Warning,
                    Some(&w[1]),
                    "same position as its previous sibling",
                ));
            }
        }
        for k in kids.iter().filter(|k| doc.nodes[*k].ty == NodeType::Page) {
            out.push(find(
                "tree.page-nested",
                Error,
                Some(k),
                "a page cannot sit inside another node",
            ));
        }
    }
    depth_findings(&f, &mut out);
    if doc.meta.system.is_some() && !doc.tokens.is_empty() {
        out.push(find(
            "token.local-ignored",
            Warning,
            None,
            "a design's own tokens are ignored; tokens come from its system",
        ));
    }
    let sys_f = system.map(|(_, d)| forest(d));
    for (id, n) in &doc.nodes {
        if let Some(Value::Object(l)) = n.props.get("link")
            && let Some(to) = l.get("to").and_then(Value::as_str)
            && !doc.nodes.contains_key(to)
        {
            out.push(find(
                "link.target",
                Error,
                Some(id),
                format!("link points at {}, which does not exist", clip(to)),
            ));
        }
        if let Some(known) = assets {
            for a in asset_refs(&n.props) {
                if is_sha256(&a) && !known.contains(&a) {
                    out.push(find(
                        "asset.missing",
                        Error,
                        Some(id),
                        format!("asset {a} is not in the library"),
                    ));
                }
            }
        }
        if n.ty == NodeType::Instance
            && let (Some(r), Some(Value::Object(ov))) = (
                n.props.get("component").and_then(Value::as_str),
                n.props.get("overrides"),
            )
        {
            for p in ov.keys().filter(|p| p.as_str() != ".").take(MAX_OVERRIDES) {
                if !override_target_exists(doc_id, doc, &f, system, sys_f.as_ref(), r, p) {
                    out.push(find(
                        "override.dangling",
                        Warning,
                        Some(id),
                        format!(
                            "override path {} matches no child of the component",
                            clip(p)
                        ),
                    ));
                }
            }
        }
    }
    // component refs, instance cycles, tokens and depth overflow: the resolver already knows
    match resolve(doc_id, doc, system, Theme::Day) {
        Ok(r) => {
            for d in r.diagnostics {
                let rule: &'static str = match d.code {
                    "tree.cycle" | "child.leaf" | "tree.depth" => continue, // reported above
                    "instance.component" => "instance.component",
                    "instance.cycle" => "instance.cycle",
                    "instance.depth" => "instance.depth",
                    "instance.missing" => "instance.missing",
                    "system.missing" => "system.missing",
                    "token.missing" => "token.missing",
                    "token.invalid" => "token.invalid",
                    "token.kind" => "token.kind",
                    "override.prop" => "override.prop",
                    _ => continue, // prop.invalid duplicates schema.invalid
                };
                out.push(find(rule, Error, Some(&d.node), d.msg));
            }
        }
        Err(_) => out.push(find(
            "resolve.too-large",
            Error,
            None,
            "the resolved tree is too large (instances multiply nodes)",
        )),
    }
    out.sort();
    out.dedup();
    out.truncate(MAX_FINDINGS);
    out
}

fn asset_refs(props: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut v = vec![];
    let s = |x: Option<&Value>| x.and_then(Value::as_str).map(str::to_string);
    v.extend(s(props.get("asset")));
    if let Some(Value::Array(fills)) = props.get("fill") {
        v.extend(
            fills
                .iter()
                .filter(|f| f.get("type").and_then(Value::as_str) == Some("image"))
                .filter_map(|f| s(f.get("asset"))),
        );
    }
    if let Some(t) = props.get("type") {
        v.extend(s(t.get("font").and_then(|f| f.get("asset"))));
    }
    v
}

fn depth_findings(f: &Forest, out: &mut Vec<Finding>) {
    let mut stack: Vec<(&str, usize)> = f
        .pages
        .iter()
        .chain(&f.detached)
        .map(|r| (r.as_str(), 0))
        .collect();
    while let Some((id, d)) = stack.pop() {
        if d > MAX_DEPTH {
            out.push(find(
                "tree.depth",
                Severity::Error,
                Some(id),
                format!("nested deeper than {MAX_DEPTH} levels"),
            ));
            continue; // do not descend; the subtree is cut by the resolver too
        }
        if let Some(k) = f.children.get(id) {
            stack.extend(k.iter().map(|c| (c.as_str(), d + 1)));
        }
    }
}

/// Does `path` (ids joined by `/`) name a node under component `r`, descending through nested instances?
fn override_target_exists(
    doc_id: &str,
    doc: &Doc,
    f: &Forest,
    system: Option<(&str, &Doc)>,
    sys_f: Option<&Forest>,
    r: &str,
    path: &str,
) -> bool {
    let find_doc = |d: &str| -> Option<(&Doc, &Forest)> {
        if d == doc_id {
            Some((doc, f))
        } else {
            system
                .zip(sys_f)
                .filter(|((sid, _), _)| *sid == d)
                .map(|((_, sd), sf)| (sd, sf))
        }
    };
    let Some((mut d, mut fo)) = parse_component_ref(r).and_then(|(dd, _)| find_doc(dd)) else {
        return false;
    };
    let mut cur = match parse_component_ref(r) {
        Some((_, n)) => n.to_string(),
        None => return false,
    };
    for seg in path.split('/') {
        if fo.parent.get(seg).map(String::as_str) != Some(cur.as_str()) {
            return false;
        }
        cur = seg.to_string();
        // descending into a nested instance continues in its component's subtree
        let nested = d
            .nodes
            .get(&cur)
            .filter(|n| n.ty == NodeType::Instance)
            .and_then(|n| n.props.get("component"))
            .and_then(Value::as_str);
        if let Some((nd_id, nn)) = nested.and_then(parse_component_ref)
            && let Some((nd, nf)) = find_doc(nd_id)
        {
            (d, fo, cur) = (nd, nf, nn.to_string());
        }
    }
    true
}
