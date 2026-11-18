//! `designApply` (T12, V1-04): one batched write of typed ops, at most 200, validated all-or-nothing and written in one
//! CRDT transaction by `design_doc::Live::apply_ops` (the same op set the App's inspector uses), with temp ids and a
//! structural lint delta in the answer so an AI can correct itself.
//!
//! SECURITY MODEL
//! - The body is hostile. Op count (200) and size (1 MB) are capped before anything is parsed into ops; every op is
//!   then checked by the model's validators against the document as the earlier ops left it, and the whole batch is
//!   refused on the first invalid op (nothing is written, nothing is sent). The resulting update still goes through the
//!   replica gate, persist and broadcast of `sync.rs` like a peer's.
//! - Temp ids (`$1`...) are only ever defined by an `add`, used by later ops, and replaced with Core-minted ids (60
//!   random bits, checked against the document); a client cannot choose the id of a node by naming a temp.
//! - `paused` (a person took over) and archived are checked under the document lock, so a take-over is never raced.
//! - Who may call this as the AI (T13: linked, created by, or bound to the session) is the Code Mode op's check
//!   (V7-01); this route is the person's own door and the function `apply_to` is the AI's.
//! - Known limits: a temp id is replaced in `id` and `parent` fields only, not inside prop values; the lint delta
//!   runs without the design system doc (token/component findings come with V5-01).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use design_doc::{MAX_OPS, MAX_OPS_BYTES, Op};
use design_model::{Doc as Model, Finding, Severity};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::docs::{In, doc_id_ok};
use crate::sync::{Actor, EditError, Lease, OpenError, Registry};

const ALPHA: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// Findings returned per batch (the rest are counted in `more`).
const MAX_NEW_FINDINGS: usize = 100;

#[derive(Deserialize, ToSchema)]
pub struct ApplyReq {
    /// 1 to 200 typed ops: `add`, `set`, `name`, `text`, `splice`, `move`, `delete`. An `add` may give its `id` as a
    /// temp `$1`..`$9999`; later ops (and `parent`) may use it.
    #[schema(value_type = Vec<Object>)]
    pub ops: Vec<Value>,
}

#[derive(Serialize, ToSchema)]
pub struct FindingView {
    pub rule: String,
    /// `error` or `warning`.
    pub severity: String,
    pub node: Option<String>,
    pub msg: String,
    pub fix: String,
}

#[derive(Serialize, ToSchema)]
pub struct LintDelta {
    /// Findings the batch introduced (not present before), at most 100.
    pub new: Vec<FindingView>,
    pub more: usize,
    /// Findings that were there before and are gone.
    pub fixed: usize,
}

#[derive(Serialize, ToSchema)]
pub struct ApplyOut {
    /// Temp id -> the id the Core gave the node.
    pub ids: BTreeMap<String, String>,
    /// The update seq the batch was stored under.
    pub seq: i64,
    pub lint: LintDelta,
}

/// `$` and 1 to 4 digits.
fn is_temp(s: &str) -> bool {
    s.strip_prefix('$')
        .is_some_and(|d| (1..=4).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit()))
}

pub(crate) fn mint() -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("the system random source");
    let mut n = u64::from_le_bytes(b);
    let mut s = String::from("n_");
    for _ in 0..12 {
        s.push(ALPHA[(n & 31) as usize] as char);
        n >>= 5;
    }
    s
}

/// Replace the temp ids of a batch. A temp is defined by an `add` (its `id`) and may then be the `id` or `parent` of
/// any later op; a temp used before it is defined, defined twice, or used in a non-string spot is refused.
/// `taken` says which real ids already exist; `mint` makes a new one.
pub(crate) fn resolve_temps(
    ops: Vec<Value>,
    taken: &dyn Fn(&str) -> bool,
    mint: &mut dyn FnMut() -> String,
) -> Result<(Vec<Value>, BTreeMap<String, String>), String> {
    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    let mut used: BTreeSet<String> = BTreeSet::new();
    let mut out = Vec::with_capacity(ops.len());
    for (i, mut op) in ops.into_iter().enumerate() {
        let Some(o) = op.as_object_mut() else {
            return Err(format!("op {i}: not an object"));
        };
        let is_add = o.get("op").and_then(Value::as_str) == Some("add");
        // references first: an add's own temp is not yet defined for its own parent
        for key in if is_add {
            &["parent"][..]
        } else {
            &["id", "parent"][..]
        } {
            if let Some(Value::String(s)) = o.get(*key)
                && is_temp(s)
            {
                let real = ids
                    .get(s)
                    .ok_or_else(|| format!("op {i}: {key} uses {s} before an add defines it"))?;
                o.insert((*key).to_owned(), Value::String(real.clone()));
            }
        }
        if is_add
            && let Some(Value::String(s)) = o.get("id").cloned()
            && is_temp(&s)
        {
            if ids.contains_key(&s) {
                return Err(format!("op {i}: {s} is defined twice"));
            }
            let real = loop {
                let m = mint();
                if !taken(&m) && used.insert(m.clone()) {
                    break m;
                }
            };
            ids.insert(s, real.clone());
            o.insert("id".to_owned(), Value::String(real));
        }
        out.push(op);
    }
    Ok((out, ids))
}

fn view(f: &Finding) -> FindingView {
    FindingView {
        rule: f.rule.to_owned(),
        severity: match f.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        }
        .to_owned(),
        node: f.node.clone(),
        msg: f.msg.clone(),
        fix: f.fix.to_owned(),
    }
}

/// What the batch changed in the lint: findings now that were not there before, and how many went away.
pub(crate) fn lint_delta(doc: &str, before: &Model, after: &Model) -> LintDelta {
    let b: BTreeSet<Finding> = design_model::lint(doc, before, None, None)
        .into_iter()
        .collect();
    let a: BTreeSet<Finding> = design_model::lint(doc, after, None, None)
        .into_iter()
        .collect();
    let new: Vec<&Finding> = a.difference(&b).collect();
    LintDelta {
        more: new.len().saturating_sub(MAX_NEW_FINDINGS),
        new: new.into_iter().take(MAX_NEW_FINDINGS).map(view).collect(),
        fixed: b.difference(&a).count(),
    }
}

fn clip(s: &str) -> String {
    s.chars().take(200).collect()
}

pub(crate) fn doc_err(e: design_doc::Error) -> EditError {
    match e {
        design_doc::Error::TooLarge => EditError::TooLarge,
        design_doc::Error::Refused(m) => EditError::Refused(clip(&m)),
        _ => EditError::Store,
    }
}

/// The AI's door too (V7-01 calls this with `origin = session:as_...`): all-or-nothing, one transaction.
pub(crate) async fn apply_to(
    actor: &Actor,
    origin: &str,
    ops: Vec<Value>,
) -> Result<ApplyOut, EditError> {
    if ops.is_empty() {
        return Err(EditError::Refused("no ops".into()));
    }
    if ops.len() > MAX_OPS || serde_json::to_vec(&ops).map_or(true, |b| b.len() > MAX_OPS_BYTES) {
        return Err(EditError::TooLarge);
    }
    let doc = actor.id.clone();
    let ((ids, lint), seq) = actor
        .edit(origin, |live| {
            let before = live.read();
            let (ops, ids) = resolve_temps(ops, &|id| before.nodes.contains_key(id), &mut mint)
                .map_err(EditError::Refused)?;
            let ops: Vec<Op> = serde_json::from_value(Value::Array(ops))
                .map_err(|e| EditError::Refused(clip(&e.to_string())))?;
            live.apply_ops(&ops).map_err(doc_err)?;
            Ok((ids, lint_delta(&doc, &before, &live.read())))
        })
        .await?;
    Ok(ApplyOut { ids, seq, lint })
}

pub(crate) fn edit_err(e: EditError) -> ApiError {
    match e {
        EditError::Refused(m) => ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_ops", m),
        EditError::TooLarge => ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            "the batch or the change is too large",
        ),
        EditError::Paused => ApiError::new(
            StatusCode::CONFLICT,
            "paused",
            "a person took over this design; wait until they resume",
        ),
        EditError::Archived => ApiError::conflict("the design is archived"),
        EditError::DocFull => ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "doc_full",
            "the design is full",
        ),
        EditError::Store => ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "the change was not stored",
        ),
    }
}

/// The live actor of an active `design` or `system` doc (a mockup has no live document).
pub(crate) async fn open_actor(
    app: &App,
    reg: &Arc<Registry>,
    me: &Caller,
    doc: &str,
) -> Result<Lease, ApiError> {
    let none = || ApiError::not_found("no such design");
    if !doc_id_ok(doc) {
        return Err(none());
    }
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT kind, state FROM design_docs WHERE id = ?")
            .bind(doc)
            .fetch_optional(&app.pool)
            .await?;
    match row {
        None => return Err(none()),
        Some((k, _)) if k == "mockup" => return Err(none()),
        Some((_, s)) if s != "active" => return Err(ApiError::conflict("the design is archived")),
        Some(_) => {}
    }
    reg.open(&app.pool, doc, &me.device.id)
        .await
        .map_err(|e| match e {
            OpenError::Device => ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_sockets",
                "this device has too many open designs",
            ),
            OpenError::Busy => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "busy",
                "too many designs are open; try again",
            ),
            OpenError::Store(e) => e.into(),
        })
}

pub(crate) fn person(me: &Caller) -> String {
    format!("person:{}", me.device.id)
}

#[utoipa::path(post, path = "/docs/{doc}/apply", operation_id = "designApply", tag = "design",
    params(("doc" = String, Path, description = "Design id")), request_body = ApplyReq,
    responses((status = 200, description = "Every op applied in one transaction (stored and sent to the open sockets): the temp-id map and the lint findings the batch introduced or fixed", body = ApplyOut),
        (status = 409, description = "`paused` (a person took over) or the design is archived"),
        (status = 413, description = "More than 200 ops, over 1 MB, or the change is too large"),
        (status = 422, description = "An op is not valid (the first one is named); nothing was applied")))]
pub(crate) async fn apply(
    State(app): State<App>,
    Extension(me): Extension<Caller>,
    Extension(reg): Extension<Arc<Registry>>,
    Path(doc): Path<String>,
    In(req): In<ApplyReq>,
) -> ApiResult<ApplyOut> {
    let lease = open_actor(&app, &reg, &me, &doc).await?;
    let out = apply_to(&lease.actor, &person(&me), req.ops)
        .await
        .map_err(edit_err)?;
    Ok(Json(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn counter() -> impl FnMut() -> String {
        let mut n = 0;
        move || {
            n += 1;
            format!("n_{}", ((b'a' + n) as char).to_string().repeat(12))
        }
    }

    fn run(ops: Value) -> Result<(Vec<Value>, BTreeMap<String, String>), String> {
        resolve_temps(
            ops.as_array().cloned().unwrap_or_default(),
            &|_| false,
            &mut counter(),
        )
    }

    #[test]
    fn temps_are_defined_by_an_add_and_used_by_later_ops() {
        let (ops, ids) = run(json!([
            {"op": "add", "id": "$1", "type": "page", "parent": null, "order": "a"},
            {"op": "add", "id": "$2", "type": "frame", "parent": "$1", "order": "a"},
            {"op": "name", "id": "$2", "name": "Card"}
        ]))
        .unwrap();
        assert_eq!(ids["$1"], "n_bbbbbbbbbbbb");
        assert_eq!(ops[1]["parent"], json!(ids["$1"]));
        assert_eq!(ops[2]["id"], json!(ids["$2"]));
    }

    #[test]
    fn a_temp_before_its_add_twice_defined_or_not_a_temp_is_refused_or_left_alone() {
        let add = |id: &str, parent: Value| json!({"op": "add", "id": id, "type": "frame", "parent": parent, "order": "a"});
        assert!(run(json!([add("$1", json!("$2")), add("$2", Value::Null)])).is_err());
        assert!(run(json!([{"op": "delete", "id": "$1"}])).is_err());
        assert!(run(json!([add("$1", Value::Null), add("$1", Value::Null)])).is_err());
        assert!(
            run(json!([add("$1", json!("$1"))])).is_err(),
            "an add is not its own parent"
        );
        assert!(run(json!(["not an op"])).is_err());
        // not temps: left for the validators to refuse
        let (ops, ids) = run(json!([add("$x", Value::Null), add("$12345", Value::Null)])).unwrap();
        assert!(ids.is_empty());
        assert_eq!(ops[0]["id"], "$x");
    }

    #[test]
    fn a_minted_id_never_collides_with_the_document() {
        let mut m = counter();
        let (_, ids) = resolve_temps(
            vec![json!({"op": "add", "id": "$1", "type": "page", "parent": null, "order": "a"})],
            &|id| id == "n_bbbbbbbbbbbb",
            &mut m,
        )
        .unwrap();
        assert_eq!(ids["$1"], "n_cccccccccccc");
    }

    #[test]
    fn minted_ids_are_node_ids() {
        for _ in 0..50 {
            assert!(design_model::ids::is_node_id(&mint()));
        }
    }
}

/// The flows through a real actor and a real store. They go through `Actor::edit`, which hands the typed ops' update to
/// the replica gate, and a `design_doc::Live` whose updates pass the replica gate.
#[cfg(test)]
mod flow {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ainkrad_core_server::module::Module;
    use ainkrad_core_server::store::{connect, migrate};
    use serde_json::json;
    use sqlx::SqlitePool;

    use super::*;
    use crate::Design;
    use crate::sync::Registry;

    const DOC: &str = "dd_00000000000000bb";

    async fn boot() -> (SqlitePool, Arc<Registry>, std::path::PathBuf) {
        static N: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "design-ops-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pool = connect(&dir.join("core.db")).await.unwrap();
        let modules: Vec<Arc<dyn Module>> = vec![Arc::new(Design::default())];
        migrate::migrate_modules(&pool, &modules).await.unwrap();
        sqlx::query("INSERT INTO design_docs (id, kind, name, created_by) VALUES (?, 'design', 'T', 'person:d_t')")
            .bind(DOC)
            .execute(&pool)
            .await
            .unwrap();
        (pool, Arc::new(Registry::default()), dir)
    }

    fn page_and_frames(n: usize) -> Vec<Value> {
        let mut v =
            vec![json!({"op": "add", "id": "$1", "type": "page", "parent": null, "order": "a"})];
        for i in 0..n {
            v.push(
                json!({"op": "add", "id": format!("${}", i + 2), "type": "frame",
                "parent": "$1", "order": "a", "name": format!("F{i}")}),
            );
        }
        v
    }

    #[tokio::test]
    async fn a_batch_with_temp_ids_applies_and_returns_the_map() {
        let (pool, reg, dir) = boot().await;
        let lease = reg.open(&pool, DOC, "d_t").await.unwrap();
        let out = apply_to(&lease.actor, "person:d_t", page_and_frames(2))
            .await
            .unwrap();
        assert_eq!(out.ids.len(), 3);
        let (m, _) = lease.actor.view().await.unwrap();
        assert!(out.ids.values().all(|id| m.nodes.contains_key(id)));
        assert_eq!(m.nodes.len(), 3);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn an_invalid_op_anywhere_applies_nothing() {
        let (pool, reg, dir) = boot().await;
        let lease = reg.open(&pool, DOC, "d_t").await.unwrap();
        let mut ops = page_and_frames(3);
        ops.push(json!({"op": "set", "id": "$2", "key": "no-such-prop", "value": 1}));
        let (_, head) = lease.actor.edit("person:d_t", |_| Ok(())).await.unwrap();
        assert!(matches!(
            apply_to(&lease.actor, "person:d_t", ops).await,
            Err(EditError::Refused(_))
        ));
        let (m, _) = lease.actor.view().await.unwrap();
        assert!(m.nodes.is_empty(), "nothing applied");
        let (_, after) = lease.actor.edit("person:d_t", |_| Ok(())).await.unwrap();
        assert_eq!(head, after, "nothing stored");
        // 201 ops and a temp used before its add are refused too
        assert!(matches!(
            apply_to(&lease.actor, "person:d_t", page_and_frames(200)).await,
            Err(EditError::TooLarge)
        ));
        let bad = vec![json!({"op": "delete", "id": "$9"})];
        assert!(apply_to(&lease.actor, "person:d_t", bad).await.is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_paused_design_refuses_the_ai_not_the_person() {
        let (pool, reg, dir) = boot().await;
        let lease = reg.open(&pool, DOC, "d_t").await.unwrap();
        sqlx::query("UPDATE design_docs SET ai_paused = 1")
            .execute(&pool)
            .await
            .unwrap();
        let r = apply_to(&lease.actor, "session:as_1", page_and_frames(0)).await;
        assert!(matches!(r, Err(EditError::Paused)));
        assert!(
            apply_to(&lease.actor, "person:d_t", page_and_frames(0))
                .await
                .is_ok()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn restore_equals_the_version_and_the_state_before_is_kept() {
        let (pool, reg, dir) = boot().await;
        let lease = reg.open(&pool, DOC, "d_t").await.unwrap();
        let first = apply_to(&lease.actor, "person:d_t", page_and_frames(2))
            .await
            .unwrap();
        let (v1, v1_state) = lease.actor.view().await.unwrap();
        let page = first.ids["$1"].clone();
        // change: rename a frame, delete another, add one
        let f1 = first.ids["$2"].clone();
        let f2 = first.ids["$3"].clone();
        let ops = vec![
            json!({"op": "name", "id": f1, "name": "Changed"}),
            json!({"op": "delete", "id": f2}),
            json!({"op": "add", "id": "$1", "type": "frame", "parent": page, "order": "b"}),
        ];
        apply_to(&lease.actor, "person:d_t", ops).await.unwrap();
        let (v2, v2_state) = lease.actor.view().await.unwrap();
        assert_ne!(v1, v2);
        lease
            .actor
            .edit("person:d_t", |l| {
                crate::versions::restore_into(l, &v1_state)
            })
            .await
            .unwrap();
        let (back, _) = lease.actor.view().await.unwrap();
        assert_eq!(back.nodes.len(), v1.nodes.len());
        for (id, n) in &v1.nodes {
            let b = &back.nodes[id];
            assert_eq!(
                (&b.parent, &b.order, &b.name, &b.props),
                (&n.parent, &n.order, &n.name, &n.props)
            );
        }
        // undo = restore the state from before
        lease
            .actor
            .edit("person:d_t", |l| {
                crate::versions::restore_into(l, &v2_state)
            })
            .await
            .unwrap();
        let (again, _) = lease.actor.view().await.unwrap();
        assert_eq!(again.nodes.len(), v2.nodes.len());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn an_approval_version_never_changes_and_cannot_be_removed() {
        let (pool, _reg, dir) = boot().await;
        sqlx::query("INSERT INTO design_versions (id, doc, kind, state, origin) VALUES ('dv_1', ?, 'approval', x'00', 'person:d_t')")
            .bind(DOC).execute(&pool).await.unwrap();
        assert!(
            sqlx::query("UPDATE design_versions SET state = x'01' WHERE id = 'dv_1'")
                .execute(&pool)
                .await
                .is_err()
        );
        assert!(
            sqlx::query("DELETE FROM design_versions WHERE id = 'dv_1'")
                .execute(&pool)
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// T12 budget: a 200-op batch under 50 ms on vps-1 (release build there; the Mac debug build is slower).
    #[tokio::test]
    #[ignore = "timing: run in release on vps-1"]
    async fn a_200_op_batch_takes_under_50_ms() {
        let (pool, reg, dir) = boot().await;
        let lease = reg.open(&pool, DOC, "d_t").await.unwrap();
        let t = std::time::Instant::now();
        apply_to(&lease.actor, "person:d_t", page_and_frames(199))
            .await
            .unwrap();
        assert!(
            t.elapsed() < std::time::Duration::from_millis(50),
            "{:?}",
            t.elapsed()
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
