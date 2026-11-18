//! Versions and restore (T14, V1-04). A version is a full state encoding of the document: `auto` (before a restore;
//! the sync actor adds one at compaction, V7-01 one before an AI turn), `named` (a person's) or `approval` (frozen by
//! `review.rs`; never changed or removed, a trigger enforces it). At most 200 per doc; a new one prunes the oldest
//! `auto` first and is refused when only named and approval ones are left.
//!
//! Restore rewrites the live document to match a version, by node id, as ONE batch of typed ops through the same
//! door as `designApply` (`sync::Actor::edit`): peers see ordinary edits, and nothing is lost, because the state
//! before the restore is first stored as an `auto` version (that is the undo: restore that one). Limits: it brings
//! back the node tree (nodes, props, names, text, order, parent), not `meta` or the tokens of a system doc (no op
//! writes those yet; V5-01); and the whole change must fit one update (1 MB), a bigger one is refused, not split.

use std::collections::BTreeSet;
use std::sync::Arc;

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, BY, Caller};
use ainkrad_core_server::store::{audit, begin_write, events};
use axum::Json;
use axum::extract::{Extension, Path, State};
use design_doc::{MAX_GESTURE_OPS, Op};
use design_model::{Doc as Model, Node};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{Row, SqliteConnection};
use utoipa::ToSchema;

use crate::apply::{doc_err, edit_err, open_actor, person};
use crate::docs::{In, doc_id_ok, name_ok};
use crate::sync::{EditError, MAX_VERSIONS, Registry};

pub(crate) fn rand_id(prefix: &str) -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("the system random source");
    format!(
        "{prefix}_{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

fn version_id_ok(s: &str) -> bool {
    s.len() == 19 && s.starts_with("dv_") && s[3..].bytes().all(|c| c.is_ascii_hexdigit())
}

/// Audit + event for something a person did to versions, comments or approvals: ids only, never a name or a body.
pub(crate) async fn note(
    conn: &mut SqliteConnection,
    kind: &str,
    op: &str,
    details: Value,
) -> Result<(), sqlx::Error> {
    let row = NewAuditEvent {
        actor: BY,
        action: format!("{kind}.{op}"),
        entity: None,
        details: details.to_string(),
    };
    audit::append(conn, &row).await?;
    let mut e = details;
    e["op"] = json!(op);
    events::append(conn, kind, &e).await?;
    Ok(())
}

/// Store `state` as a version of `doc`, pruning the oldest `auto` ones to stay at 200.
pub(crate) async fn store_version(
    conn: &mut SqliteConnection,
    doc: &str,
    kind: &str,
    name: Option<&str>,
    state: &[u8],
    origin: &str,
) -> Result<String, ApiError> {
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM design_versions WHERE doc = ?")
        .bind(doc)
        .fetch_one(&mut *conn)
        .await?;
    let over = n - (MAX_VERSIONS - 1);
    if over > 0 {
        let gone = sqlx::query(
            "DELETE FROM design_versions WHERE id IN (SELECT id FROM design_versions \
             WHERE doc = ? AND kind = 'auto' ORDER BY rowid LIMIT ?)",
        )
        .bind(doc)
        .bind(over)
        .execute(&mut *conn)
        .await?
        .rows_affected();
        if (gone as i64) < over {
            return Err(ApiError::conflict(
                "the design holds the most versions it may",
            ));
        }
    }
    let id = rand_id("dv");
    sqlx::query(
        "INSERT INTO design_versions (id, doc, kind, name, state, origin) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(doc)
    .bind(kind)
    .bind(name)
    .bind(state)
    .bind(origin)
    .execute(&mut *conn)
    .await?;
    Ok(id)
}

#[derive(Serialize, ToSchema)]
pub struct VersionView {
    /// `dv_` and 16 hex characters.
    pub id: String,
    /// `auto`, `named` or `approval`.
    pub kind: String,
    pub name: Option<String>,
    /// `person:d_...` or `session:as_...` or `system`.
    pub origin: String,
    pub created_at: String,
    /// Size of the stored state.
    pub bytes: i64,
}

fn view(r: &sqlx::sqlite::SqliteRow) -> Result<VersionView, sqlx::Error> {
    Ok(VersionView {
        id: r.try_get("id")?,
        kind: r.try_get("kind")?,
        name: r.try_get("name")?,
        origin: r.try_get("origin")?,
        created_at: r.try_get("created_at")?,
        bytes: r.try_get("bytes")?,
    })
}

#[utoipa::path(get, path = "/docs/{doc}/versions", operation_id = "designListVersions", tag = "design",
    params(("doc" = String, Path, description = "Design id")),
    responses((status = 200, description = "The doc's versions, newest first (at most 200); the state itself is not listed", body = Vec<VersionView>)))]
pub(crate) async fn list(
    State(app): State<App>,
    Path(doc): Path<String>,
) -> ApiResult<Vec<VersionView>> {
    if !doc_id_ok(&doc) {
        return Err(ApiError::not_found("no such design"));
    }
    let rows = sqlx::query(
        "SELECT id, kind, name, origin, created_at, length(state) AS bytes FROM design_versions \
         WHERE doc = ? ORDER BY rowid DESC LIMIT ?",
    )
    .bind(&doc)
    .bind(MAX_VERSIONS)
    .fetch_all(&app.pool)
    .await?;
    let out = rows.iter().map(view).collect::<Result<Vec<_>, _>>()?;
    Ok(Json(out))
}

#[derive(Deserialize, ToSchema)]
pub struct NewVersion {
    /// 1 to 100 characters.
    pub name: String,
}

#[utoipa::path(post, path = "/docs/{doc}/versions", operation_id = "designCreateVersion", tag = "design",
    params(("doc" = String, Path, description = "Design id")), request_body = NewVersion,
    responses((status = 200, description = "A named version of the document as it is now (audited as `design.version.created`); refused when the design holds 200 and none is `auto`", body = VersionView)))]
pub(crate) async fn create(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Extension(reg): Extension<Arc<Registry>>,
    Path(doc): Path<String>,
    In(req): In<NewVersion>,
) -> ApiResult<VersionView> {
    if !name_ok(&req.name) {
        return Err(ApiError::bad_request("the name is not valid"));
    }
    let lease = open_actor(&app, &reg, &me, &doc).await?;
    let (_, state) = lease.actor.view().await.map_err(edit_err)?;
    let mut tx = begin_write(&app.pool).await?;
    let id = store_version(
        &mut tx,
        &doc,
        "named",
        Some(&req.name),
        &state,
        &person(&me),
    )
    .await?;
    note(
        &mut tx,
        "design.version",
        "created",
        json!({"doc": doc, "version": id}),
    )
    .await?;
    let row = sqlx::query(
        "SELECT id, kind, name, origin, created_at, length(state) AS bytes FROM design_versions WHERE id = ?",
    )
    .bind(&id)
    .fetch_one(&mut *tx)
    .await?;
    let out = view(&row)?;
    tx.commit().await?;
    Ok(Json(out))
}

fn depth(m: &Model, id: &str) -> Result<usize, String> {
    let (mut d, mut cur) = (0, m.nodes.get(id));
    while let Some(p) = cur.and_then(|n| n.parent.as_deref()) {
        d += 1;
        if d > m.nodes.len() {
            return Err("the version has a parent cycle".into());
        }
        cur = m.nodes.get(p);
    }
    Ok(d)
}

fn add_op(id: &str, n: &Node) -> Op {
    Op::Add {
        id: id.to_owned(),
        ty: n.ty,
        parent: n.parent.clone(),
        order: n.order.clone(),
        name: n.name.clone(),
        props: n.props.clone(),
        text: n.text.clone(),
    }
}

/// The ops that turn `cur` into `tgt`, in an order that validates one by one: adds (parents first), then updates and
/// moves by the target's depth (so a move's new parent is already in place and no step makes a cycle), then deletes
/// of what only `cur` has (their subtrees; everything that stays has moved out by then).
pub(crate) fn restore_ops(cur: &Model, tgt: &Model) -> Result<Vec<Op>, String> {
    let mut ops = vec![];
    let mut order: Vec<(usize, &String)> = tgt
        .nodes
        .keys()
        .map(|id| depth(tgt, id).map(|d| (d, id)))
        .collect::<Result<_, _>>()?;
    order.sort();
    for (_, id) in &order {
        let t = &tgt.nodes[*id];
        let Some(c) = cur.nodes.get(*id) else {
            ops.push(add_op(id, t));
            continue;
        };
        if c.ty != t.ty {
            return Err("the version does not belong to this design".into());
        }
        if c.parent != t.parent || c.order != t.order {
            ops.push(Op::Move {
                id: (*id).clone(),
                parent: t.parent.clone(),
                order: t.order.clone(),
            });
        }
        if c.name != t.name {
            ops.push(Op::Name {
                id: (*id).clone(),
                name: t.name.clone(),
            });
        }
        if let Some(text) = t.text.as_ref().filter(|x| c.text.as_ref() != Some(*x)) {
            ops.push(Op::Text {
                id: (*id).clone(),
                text: text.clone(),
            });
        }
        for (k, v) in &t.props {
            if c.props.get(k) != Some(v) {
                ops.push(Op::Set {
                    id: (*id).clone(),
                    key: k.clone(),
                    value: v.clone(),
                });
            }
        }
        for k in c.props.keys().filter(|k| !t.props.contains_key(*k)) {
            ops.push(Op::Set {
                id: (*id).clone(),
                key: k.clone(),
                value: Value::Null,
            });
        }
    }
    let gone: BTreeSet<&String> = cur
        .nodes
        .keys()
        .filter(|id| !tgt.nodes.contains_key(*id))
        .collect();
    for id in &gone {
        let top = cur.nodes[*id]
            .parent
            .as_ref()
            .is_none_or(|p| !gone.contains(p));
        if top {
            ops.push(Op::Delete { id: (*id).clone() });
        }
    }
    if ops.len() > MAX_GESTURE_OPS {
        return Err("too many changes".into());
    }
    Ok(ops)
}

/// Rewrite `live` to match the version state `blob`: one batch, nothing written when any op is refused.
pub(crate) fn restore_into(live: &mut design_doc::Live, blob: &[u8]) -> Result<(), EditError> {
    let mut target = design_doc::Live::new();
    target
        .apply_remote(blob)
        .map_err(|_| EditError::Refused("the version is not a design state".into()))?;
    let mut m = live.read();
    let ops = restore_ops(&m, &target.read()).map_err(EditError::Refused)?;
    live.apply_gesture_ops(&mut m, &ops).map_err(doc_err)
}

#[derive(Serialize, ToSchema)]
pub struct Restored {
    /// The version that was restored.
    pub restored: String,
    /// The `auto` version holding the document as it was before; restoring that one undoes this.
    pub before: String,
    /// The update seq the restore was stored under (the current head when nothing differed).
    pub seq: i64,
}

#[utoipa::path(post, path = "/docs/{doc}/versions/{version}/restore", operation_id = "designRestoreVersion", tag = "design",
    params(("doc" = String, Path, description = "Design id"), ("version" = String, Path, description = "Version id")),
    responses((status = 200, description = "The live document was rewritten to match the version, as one batch every open socket receives (audited as `design.version.restored`); the state before it is kept as an `auto` version", body = Restored),
        (status = 413, description = "The change does not fit one update"),
        (status = 422, description = "The version does not belong to this design")))]
pub(crate) async fn restore(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Extension(reg): Extension<Arc<Registry>>,
    Path((doc, version)): Path<(String, String)>,
) -> ApiResult<Restored> {
    if !version_id_ok(&version) {
        return Err(ApiError::not_found("no such version"));
    }
    let lease = open_actor(&app, &reg, &me, &doc).await?;
    let blob: Vec<u8> =
        sqlx::query_scalar("SELECT state FROM design_versions WHERE id = ? AND doc = ?")
            .bind(&version)
            .bind(&doc)
            .fetch_optional(&app.pool)
            .await?
            .ok_or_else(|| ApiError::not_found("no such version"))?;
    // The state before is read inside the edit, under the document lock, so an edit by a peer between a read and the
    // restore can never be missing from the safety copy; the copy is stored once the restore went through.
    let edited = lease
        .actor
        .edit(&person(&me), |live| {
            let before = live
                .diff(&[])
                .map_err(|_| EditError::Refused("the design could not be read".into()))?;
            restore_into(live, &blob)?;
            Ok(before)
        })
        .await;
    let (now, seq) = edited.map_err(edit_err)?;
    let mut tx = begin_write(&app.pool).await?;
    let before = store_version(
        &mut tx,
        &doc,
        "auto",
        Some("Before a restore"),
        &now,
        &person(&me),
    )
    .await?;
    tx.commit().await?;
    let mut tx = begin_write(&app.pool).await?;
    note(
        &mut tx,
        "design.version",
        "restored",
        json!({"doc": doc, "version": version, "before": before}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(Restored {
        restored: version,
        before,
        seq,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use design_model::NodeType::{Frame, Page, Text};
    use serde_json::Map;

    fn node(ty: design_model::NodeType, parent: Option<&str>, order: &str) -> Node {
        Node {
            ty,
            parent: parent.map(Into::into),
            order: order.into(),
            clock: 0,
            name: String::new(),
            props: Map::new(),
            text: None,
        }
    }

    fn doc(nodes: Vec<(&str, Node)>) -> Model {
        let mut d = Model::default();
        for (id, n) in nodes {
            d.nodes.insert(id.into(), n);
        }
        d
    }

    #[test]
    fn restore_ops_move_update_and_delete_in_a_valid_order() {
        let (p, a, b, c) = (
            "n_pppppppppppp",
            "n_aaaaaaaaaaaa",
            "n_bbbbbbbbbbbb",
            "n_cccccccccccc",
        );
        // now: page > a > b (text "new", prop x), c under the page. version: page > b (moved up, text "old")
        let mut b_now = node(Text, Some(a), "a");
        b_now.text = Some("new".into());
        b_now.props.insert("x".into(), json!(1));
        let cur = doc(vec![
            (p, node(Page, None, "a")),
            (a, node(Frame, Some(p), "a")),
            (b, b_now),
            (c, node(Frame, Some(p), "b")),
        ]);
        let mut b_then = node(Text, Some(p), "a");
        b_then.text = Some("old".into());
        let tgt = doc(vec![(p, node(Page, None, "a")), (b, b_then)]);
        let ops = restore_ops(&cur, &tgt).unwrap();
        // b moves up under the page, its text is restored, its prop removed, then a and c are deleted
        assert_eq!(ops.len(), 5, "{ops:?}");
        assert!(matches!(&ops[0], Op::Move { id, parent: Some(q), .. } if id == b && q == p));
        assert!(matches!(&ops[1], Op::Text { text, .. } if text == "old"));
        assert!(matches!(
            &ops[2],
            Op::Set {
                value: Value::Null,
                ..
            }
        ));
        assert!(ops[3..].iter().all(|o| matches!(o, Op::Delete { .. })));
    }

    #[test]
    fn equal_documents_need_no_ops_and_a_type_change_is_refused() {
        let p = "n_pppppppppppp";
        let d = doc(vec![(p, node(Page, None, "a"))]);
        assert_eq!(restore_ops(&d, &d.clone()).unwrap(), vec![]);
        let other = doc(vec![(p, node(Frame, None, "a"))]);
        assert!(restore_ops(&d, &other).is_err());
    }

    #[test]
    fn restore_ops_add_parents_before_children() {
        let (p, a, b) = ("n_pppppppppppp", "n_aaaaaaaaaaaa", "n_bbbbbbbbbbbb");
        let tgt = doc(vec![
            (b, node(Text, Some(a), "a")),
            (a, node(Frame, Some(p), "a")),
            (p, node(Page, None, "a")),
        ]);
        let ops = restore_ops(&Model::default(), &tgt).unwrap();
        let ids: Vec<&str> = ops
            .iter()
            .map(|o| match o {
                Op::Add { id, .. } => id.as_str(),
                _ => "",
            })
            .collect();
        assert_eq!(ids, [p, a, b]);
    }

    #[test]
    fn a_parent_cycle_in_a_version_is_refused() {
        let (a, b) = ("n_aaaaaaaaaaaa", "n_bbbbbbbbbbbb");
        let tgt = doc(vec![
            (a, node(Frame, Some(b), "a")),
            (b, node(Frame, Some(a), "a")),
        ]);
        assert!(restore_ops(&Model::default(), &tgt).is_err());
    }
}
