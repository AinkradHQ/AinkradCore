//! Whole-document validation: limits, every node, every token.

use super::{
    Cx, R, Violation, at, clip, color, material_value, name_str, num, props, shadow_value,
    text_str, type_value,
};
use crate::ids::{is_doc_id, is_node_id, is_order, is_token_name};
use crate::limits::*;
use crate::schema::{Doc, Node, NodeType, Token, TokenKind as K};

/// A token's day and night literals must be valid for its kind (and contain no refs).
pub fn token(t: &Token) -> R {
    for (theme, v) in [("day", &t.day), ("night", &t.night)] {
        let mut cx = Cx::resolved();
        at(
            theme,
            match t.kind {
                K::Color => color(v, &mut cx),
                K::Space | K::Size | K::Radius => num(v, &mut cx, &[], 0.0, MAX_COORD),
                K::Type => type_value(v, &mut cx),
                K::Shadow => shadow_value(v, &mut cx),
                K::Material => material_value(v, &mut cx),
            },
        )?;
    }
    Ok(())
}

fn node(id: &str, n: &Node, out: &mut Vec<Violation>) {
    let id = &clip(id); // an id can be any length until it is refused
    let mut push = |path: &str, msg: String| {
        if out.len() < MAX_REPORTED {
            out.push(Violation {
                path: format!("nodes.{id}{path}"),
                msg,
            });
        }
    };
    if !is_node_id(id) {
        push("", "bad node id".into());
    }
    if !is_order(&n.order) {
        push(".order", "bad fractional index".into());
    }
    if n.parent.as_deref().is_some_and(|p| !is_node_id(p)) {
        push(".parent", "bad parent id".into());
    }
    if let Err(e) = name_str(&n.name) {
        push(".name", e);
    }
    match (&n.text, n.ty) {
        (Some(t), NodeType::Text) => {
            if let Err(e) = text_str(t) {
                push(".text", e);
            }
        }
        (Some(_), _) => push(".text", "only text nodes carry text".into()),
        _ => {}
    }
    let mut cx = Cx::raw();
    for v in props(n.ty, &n.props, &mut cx) {
        push(&v.path.replacen("props", ".props", 1), v.msg);
    }
}

/// Validate a whole document (limits, every node, every token). At most `MAX_REPORTED` violations are returned.
pub fn doc(d: &Doc) -> Vec<Violation> {
    let mut out = vec![];
    if d.nodes.len() > MAX_NODES {
        out.push(Violation {
            path: "nodes".into(),
            msg: format!("more than {MAX_NODES} nodes"),
        });
        return out;
    }
    if d.tokens.len() > MAX_TOKENS {
        out.push(Violation {
            path: "tokens".into(),
            msg: format!("more than {MAX_TOKENS} tokens"),
        });
        return out;
    }
    if d.meta.system.as_deref().is_some_and(|s| !is_doc_id(s)) {
        out.push(Violation {
            path: "meta.system".into(),
            msg: "bad design-system doc id".into(),
        });
    }
    for (id, n) in &d.nodes {
        if out.len() >= MAX_REPORTED {
            break;
        }
        node(id, n, &mut out);
    }
    for (name, t) in &d.tokens {
        if out.len() >= MAX_REPORTED {
            break;
        }
        if !is_token_name(name) {
            out.push(Violation {
                path: format!("tokens.{}", clip(name)),
                msg: "bad token name".into(),
            });
        } else if let Err(msg) = token(t) {
            out.push(Violation {
                path: format!("tokens.{name}"),
                msg,
            });
        }
    }
    out
}
