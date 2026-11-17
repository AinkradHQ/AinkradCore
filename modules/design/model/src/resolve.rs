//! The resolver (T11): one pass that turns a document (+ its design system) into the tree every consumer draws:
//! instances expanded from their components, overrides applied, token refs replaced by the theme's literal, every
//! prop re-validated. The output is always schema-valid; anything wrong is dropped and reported as a `Diagnostic`.
//! Safe on unvalidated input: depth, instance nesting and total node count are bounded (`limits`), so a hostile
//! document (instance cycles, nested instances multiplying the node count) ends in a diagnostic or `TooLarge`.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Map, Value};

use crate::ids::{is_node_id, is_token_name, parse_component_ref};
use crate::limits::*;
use crate::schema::{Doc, Node, NodeType, Token};
use crate::tree::{Forest, forest};
use crate::validate::{self, Cx, clip_n, token_ref};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    Day,
    Night,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub code: &'static str,
    pub node: String,
    pub msg: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResolvedNode {
    /// The node id; inside an instance it is the instance's resolved id + `/` + the component child's id.
    pub id: String,
    #[serde(rename = "type")]
    pub ty: NodeType,
    pub name: String,
    pub props: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Instances: the `<doc>/<node>` they expand.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<String>,
    pub children: Vec<ResolvedNode>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Resolved {
    pub doc: String,
    pub theme: Theme,
    pub pages: Vec<ResolvedNode>,
    /// Roots that are not pages (orphans, the cut node of a broken move cycle).
    pub detached: Vec<ResolvedNode>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    /// The resolved tree would exceed `MAX_RESOLVED_NODES`.
    TooLarge,
}

#[derive(Clone, Copy)]
struct Ctx<'a> {
    id: &'a str,
    doc: &'a Doc,
    forest: &'a Forest,
}

#[derive(Clone)]
struct Scope<'a> {
    /// This node's path inside the scope's component: `.` for the root, else `/`-joined child ids.
    path: String,
    overrides: Option<&'a Map<String, Value>>,
}

struct Rx<'a> {
    own: Ctx<'a>,
    sys: Option<Ctx<'a>>,
    /// The tokens that passed `validate::token`; an invalid one is as good as missing.
    toks: BTreeMap<&'a str, &'a Token>,
    theme: Theme,
    count: usize,
    bytes: usize,
    diags: Vec<Diagnostic>,
}

/// Resolve `doc` (id `doc_id`) for `theme`. `system` is the design system doc named by `doc.meta.system`, if the
/// caller has it: components and tokens come from it. A design never reads any other document.
pub fn resolve(
    doc_id: &str,
    doc: &Doc,
    system: Option<(&str, &Doc)>,
    theme: Theme,
) -> Result<Resolved, ResolveError> {
    // Only the system the design names is readable; a different document handed in is ignored.
    let system = system.filter(|(id, _)| doc.meta.system.as_deref() == Some(*id));
    let own_f = forest(doc);
    let sys_f = system.map(|(_, d)| forest(d));
    let mut rx = Rx {
        own: Ctx {
            id: doc_id,
            doc,
            forest: &own_f,
        },
        sys: system.zip(sys_f.as_ref()).map(|((id, d), f)| Ctx {
            id,
            doc: d,
            forest: f,
        }),
        toks: BTreeMap::new(),
        theme,
        count: 0,
        bytes: 0,
        diags: vec![],
    };
    let source: Option<&BTreeMap<String, Token>> = match (&doc.meta.system, rx.sys) {
        (None, _) => Some(&doc.tokens),
        (Some(want), Some(s)) if want == s.id => Some(&s.doc.tokens),
        (Some(_), _) => {
            rx.diag(
                "system.missing",
                doc_id,
                "the design system this design names was not provided",
            );
            None
        }
    };
    // Token values are untrusted too: validate them once, before any prop can clone one.
    for (name, t) in source.into_iter().flatten() {
        if is_token_name(name) && validate::token(t).is_ok() {
            rx.toks.insert(name, t);
        } else {
            rx.diag(
                "token.invalid",
                name,
                "token is malformed; treated as missing",
            );
        }
    }
    let mut out = Resolved {
        doc: doc_id.to_string(),
        theme,
        pages: vec![],
        detached: vec![],
        diagnostics: vec![],
    };
    for id in &own_f.broken {
        rx.diag(
            "tree.cycle",
            id,
            "a move cycle was cut here; the node is detached",
        );
    }
    let own = rx.own;
    for (ids, dst) in [
        (&own_f.pages, &mut out.pages),
        (&own_f.detached, &mut out.detached),
    ] {
        for id in ids {
            dst.extend(rx.node(own, id, "", 0, &[], &mut vec![])?);
        }
    }
    out.diagnostics = rx.diags;
    Ok(out)
}

/// Approximate bytes a JSON value costs when cloned into the output.
fn vbytes(v: &Value) -> usize {
    match v {
        Value::String(s) => s.len() + 8,
        Value::Array(a) => 8 + a.iter().map(vbytes).sum::<usize>(),
        Value::Object(m) => 8 + mbytes(m),
        _ => 8,
    }
}

fn mbytes(m: &Map<String, Value>) -> usize {
    m.iter().map(|(k, x)| k.len() + 8 + vbytes(x)).sum()
}

fn kids<'a>(c: Ctx<'a>, i: &str) -> &'a [String] {
    c.forest.children.get(i).map_or(&[], |v| &v[..])
}

fn descend<'a>(scopes: &[Scope<'a>], child: &str) -> Vec<Scope<'a>> {
    scopes
        .iter()
        .map(|s| Scope {
            path: if s.path == "." {
                child.to_string()
            } else {
                format!("{}/{}", s.path, child)
            },
            overrides: s.overrides,
        })
        .collect()
}

impl<'a> Rx<'a> {
    fn diag(&mut self, code: &'static str, node: &str, msg: impl Into<String>) {
        if self.diags.len() < 1000 {
            // ids and refs are attacker-sized strings: keep every diagnostic small
            self.diags.push(Diagnostic {
                code,
                node: clip_n(node, 256),
                msg: clip_n(&msg.into(), 256),
            });
        }
    }

    fn charge(&mut self, n: usize) -> Result<(), ResolveError> {
        self.bytes = self.bytes.saturating_add(n);
        if self.bytes > MAX_RESOLVED_BYTES {
            return Err(ResolveError::TooLarge);
        }
        Ok(())
    }

    /// A component node reachable from this resolve: in this doc or in its design system, never elsewhere.
    fn lookup(&self, r: &str) -> Option<(Ctx<'a>, &'a str)> {
        let (d, n) = parse_component_ref(r)?;
        let cx = [Some(self.own), self.sys]
            .into_iter()
            .flatten()
            .find(|c| c.id == d)?;
        let (key, node) = cx.doc.nodes.get_key_value(n)?;
        (node.ty == NodeType::Component).then_some((cx, key.as_str()))
    }

    fn apply_override(
        &mut self,
        rid: &str,
        ty: NodeType,
        raw: &mut Map<String, Value>,
        text: &mut Option<String>,
        m: &Map<String, Value>,
    ) {
        for (k, v) in m {
            if v.is_null() {
                raw.remove(k);
            } else if k == "text" {
                match (ty, v.as_str()) {
                    (NodeType::Text, Some(s)) => *text = Some(s.to_string()),
                    _ => self.diag(
                        "override.prop",
                        rid,
                        "text can only be overridden on a text node",
                    ),
                }
            } else if validate::applies(k, ty) == Some(true) && k != "component" && k != "overrides"
            {
                raw.insert(k.clone(), v.clone());
            } else {
                self.diag(
                    "override.prop",
                    rid,
                    format!(
                        "override {:?} does not apply to a {ty:?} node",
                        k.chars().take(40).collect::<String>()
                    ),
                );
            }
        }
    }

    /// Validate each prop, check and substitute its tokens, validate the literal result.
    fn finish_props(
        &mut self,
        rid: &str,
        ty: NodeType,
        raw: Map<String, Value>,
    ) -> Result<Map<String, Value>, ResolveError> {
        let mut out = Map::new();
        'props: for (k, v) in raw {
            let mut cx = Cx::raw();
            if let Err(e) = validate::prop(ty, &k, &v, &mut cx) {
                self.diag("prop.invalid", rid, e);
                continue;
            }
            for u in &cx.uses {
                match self.toks.get(u.name.as_str()) {
                    None => {
                        self.diag("token.missing", rid, format!("{k}: no token {:?}", u.name));
                        continue 'props;
                    }
                    Some(t) if !u.kinds.contains(&t.kind) => {
                        self.diag(
                            "token.kind",
                            rid,
                            format!("{k}: token {:?} is a {:?}, not usable here", u.name, t.kind),
                        );
                        continue 'props;
                    }
                    Some(_) => {}
                }
            }
            let lit = self.subst(&v)?;
            match validate::prop(ty, &k, &lit, &mut Cx::resolved()) {
                Ok(()) => {
                    out.insert(k, lit);
                }
                Err(e) => self.diag("prop.invalid", rid, format!("after tokens: {e}")),
            }
        }
        Ok(out)
    }

    /// Replace token refs by the theme's literal. Each substituted value is charged to the byte budget before it is
    /// cloned (a prop can name the same token many times, so the token's size multiplies).
    fn subst(&mut self, v: &Value) -> Result<Value, ResolveError> {
        if let Some(n) = token_ref(v) {
            let Some(t) = self.toks.get(n).copied() else {
                return Ok(Value::Null);
            };
            let lit = if self.theme == Theme::Day {
                &t.day
            } else {
                &t.night
            };
            self.charge(vbytes(lit))?;
            return Ok(lit.clone());
        }
        Ok(match v {
            Value::Object(m) => {
                let mut o = Map::new();
                for (k, x) in m {
                    o.insert(k.clone(), self.subst(x)?);
                }
                Value::Object(o)
            }
            Value::Array(a) => {
                Value::Array(a.iter().map(|x| self.subst(x)).collect::<Result<_, _>>()?)
            }
            _ => v.clone(),
        })
    }

    fn node(
        &mut self,
        cx: Ctx<'a>,
        id: &'a str,
        prefix: &str,
        depth: usize,
        scopes: &[Scope<'a>],
        stack: &mut Vec<String>,
    ) -> Result<Option<ResolvedNode>, ResolveError> {
        if !is_node_id(id) {
            self.diag("node.id", id, "node skipped: its id is not a valid node id");
            return Ok(None);
        }
        self.count += 1;
        if self.count > MAX_RESOLVED_NODES {
            return Err(ResolveError::TooLarge);
        }
        let rid = format!("{prefix}{id}");
        let n: &'a Node = &cx.doc.nodes[id];
        // charge before cloning: a hostile document is refused without first copying its strings
        self.charge(
            rid.len() + n.name.len() + n.text.as_ref().map_or(0, String::len) + mbytes(&n.props),
        )?;
        let mut raw = n.props.clone();
        let mut text = n.text.clone();
        let mut component = None;
        let mut expand: Option<(Ctx<'a>, &'a str)> = None;
        let mut own_ov: Option<&'a Map<String, Value>> = None;
        if n.ty == NodeType::Instance {
            raw.remove("component");
            raw.remove("overrides");
            match n.props.get("component").and_then(Value::as_str) {
                None => self.diag("instance.component", &rid, "instance names no component"),
                Some(r) if parse_component_ref(r).is_none() => {
                    self.diag("instance.component", &rid, "component ref is malformed")
                }
                Some(r) => {
                    component = Some(r.to_string());
                    if stack.iter().any(|s| s == r) {
                        self.diag(
                            "instance.cycle",
                            &rid,
                            "the component contains an instance of itself",
                        );
                    } else if stack.len() >= MAX_INSTANCE_DEPTH {
                        self.diag("instance.depth", &rid, "instances are nested too deeply");
                    } else if let Some((ccx, cid)) = self.lookup(r) {
                        // the component's props, minus its canvas position, under the instance's own props
                        self.charge(mbytes(&ccx.doc.nodes[cid].props))?;
                        let mut base = ccx.doc.nodes[cid].props.clone();
                        base.remove("x");
                        base.remove("y");
                        base.extend(std::mem::take(&mut raw));
                        raw = base;
                        own_ov = n.props.get("overrides").and_then(Value::as_object);
                        expand = Some((ccx, cid));
                    } else {
                        self.diag(
                            "instance.missing",
                            &rid,
                            format!("component {r:?} not found in this design or its system"),
                        );
                    }
                }
            }
        }
        // overrides: the instance's own `.`, then each enclosing scope's entry for this node (outermost wins)
        let mut layers: Vec<&'a Map<String, Value>> = vec![];
        layers.extend(own_ov.and_then(|o| o.get(".")).and_then(Value::as_object));
        for s in scopes.iter().rev() {
            layers.extend(
                s.overrides
                    .and_then(|o| o.get(&s.path))
                    .and_then(Value::as_object),
            );
        }
        for m in layers {
            self.charge(mbytes(m))?;
            self.apply_override(&rid, n.ty, &mut raw, &mut text, m);
        }
        let props = self.finish_props(&rid, n.ty, raw)?;
        if let Some(t) = &text
            && validate::text_str(t).is_err()
        {
            self.diag(
                "prop.invalid",
                &rid,
                "text: too long or has control characters",
            );
            text = None;
        }
        let mut children = vec![];
        if depth >= MAX_DEPTH {
            if !kids(cx, id).is_empty() || expand.is_some() {
                self.diag("tree.depth", &rid, "nested too deeply; children cut");
            }
        } else if let Some((ccx, cid)) = expand {
            let mut sc = scopes.to_vec();
            sc.push(Scope {
                path: ".".into(),
                overrides: own_ov,
            });
            let child_prefix = format!("{rid}/");
            stack.push(component.clone().unwrap_or_default());
            for k in kids(ccx, cid) {
                children.extend(self.node(
                    ccx,
                    k,
                    &child_prefix,
                    depth + 1,
                    &descend(&sc, k),
                    stack,
                )?);
            }
            stack.pop();
        } else if n.ty.is_container() {
            for k in kids(cx, id) {
                children.extend(self.node(cx, k, prefix, depth + 1, &descend(scopes, k), stack)?);
            }
        } else if !kids(cx, id).is_empty() {
            self.diag(
                "child.leaf",
                &rid,
                "a leaf node cannot have children; they are not drawn",
            );
        }
        Ok(Some(ResolvedNode {
            id: rid,
            ty: n.ty,
            name: n.name.clone(),
            props,
            text,
            component,
            children,
        }))
    }
}
