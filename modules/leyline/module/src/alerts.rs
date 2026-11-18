//! Alerts in the bell (Y5-02): a host that is down, full or whose key changed opens ONE alert
//! (`leyline_alerts`, one open per host and kind); getting better closes it. Every open and close
//! is an event (`leyline.alert`) and an audit row; the module's `classify` turns the event into the
//! Core's push (`Module::notification_kinds`).
//!
//! Security model: an alert is evidence of what the Core measured, never a remote's own words. The
//! push carries the host's name and the kind only (the gate's `policy::clean` still redacts it and
//! keeps ids), one push per burst (a shared `collapse` key merges a burst into "N new"), and
//! nothing here can trust or replace a host key.

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::BY;
use ainkrad_core_server::push::Notification;
use ainkrad_core_server::store::events::StoredEvent;
use ainkrad_core_server::store::{audit, begin_write, events};
use serde_json::json;
use sqlx::SqliteConnection;

/// The pushes Leyline may raise and the scope a device needs for each.
pub(crate) const KINDS: &[(&str, &str)] =
    &[("leyline.alert", "read"), ("leyline.recovered", "read")];

/// Newest sample first, as far as the rules need.
pub(crate) struct Sample {
    pub(crate) up: bool,
    pub(crate) mem_pct: Option<f64>,
    pub(crate) disk_pct: Option<f64>,
    pub(crate) failed_units: Option<i64>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Op {
    Open(&'static str),
    Resolve(&'static str),
}

/// Hysteresis: opening needs more than closing, so a number that hovers at the line does not flap.
/// down = 3 failed samples in a row, back after 2 good ones; disk opens at 90 %, closes under 85 %;
/// memory = 5 samples at 95 % or more, closes under 90 %; failed units open at 1, close at 0. A
/// sample that does not report a number (down, non-Linux, no systemd) changes nothing.
pub(crate) fn decide(recent: &[Sample], open: &[String]) -> Vec<Op> {
    let is = |k: &str| open.iter().any(|o| o == k);
    let newest = recent.first();
    let mut ops = Vec::new();
    if !is("down") && recent.len() >= 3 && recent[..3].iter().all(|s| !s.up) {
        ops.push(Op::Open("down"));
    } else if is("down") && recent.len() >= 2 && recent[..2].iter().all(|s| s.up) {
        ops.push(Op::Resolve("down"));
    }
    match newest.and_then(|s| s.disk_pct) {
        Some(d) if !is("disk") && d >= 90.0 => ops.push(Op::Open("disk")),
        Some(d) if is("disk") && d < 85.0 => ops.push(Op::Resolve("disk")),
        _ => {}
    }
    if !is("memory")
        && recent.len() >= 5
        && recent[..5]
            .iter()
            .all(|s| s.mem_pct.is_some_and(|m| m >= 95.0))
    {
        ops.push(Op::Open("memory"));
    } else if is("memory") && newest.and_then(|s| s.mem_pct).is_some_and(|m| m < 90.0) {
        ops.push(Op::Resolve("memory"));
    }
    match newest.and_then(|s| s.failed_units) {
        Some(n) if !is("failed_units") && n > 0 => ops.push(Op::Open("failed_units")),
        Some(0) if is("failed_units") => ops.push(Op::Resolve("failed_units")),
        _ => {}
    }
    ops
}

/// Reads the host's newest raw samples and its open alerts, and opens or closes what the rules say.
pub(crate) async fn evaluate(app: &App, host: &str) -> Result<(), sqlx::Error> {
    let mut tx = begin_write(&app.pool).await?;
    #[allow(clippy::type_complexity)] // one row of the sample query, read once
    let rows: Vec<(i64, Option<f64>, Option<f64>, Option<i64>)> = sqlx::query_as(
        "SELECT up, mem_pct, disk_pct, failed_units FROM leyline_health_samples \
         WHERE host_id = ? AND rolled = 0 ORDER BY at DESC LIMIT 5",
    )
    .bind(host)
    .fetch_all(&mut *tx)
    .await?;
    let recent: Vec<Sample> = rows
        .into_iter()
        .map(|(up, mem_pct, disk_pct, failed_units)| Sample {
            up: up == 1,
            mem_pct,
            disk_pct,
            failed_units,
        })
        .collect();
    let open: Vec<String> = sqlx::query_scalar(
        "SELECT kind FROM leyline_alerts WHERE host_id = ? AND resolved_at IS NULL",
    )
    .bind(host)
    .fetch_all(&mut *tx)
    .await?;
    for op in decide(&recent, &open) {
        match op {
            Op::Open(kind) => open_alert(&mut tx, host, kind).await?,
            Op::Resolve(kind) => resolve(&mut tx, host, kind).await?,
        };
    }
    tx.commit().await
}

/// Opens the alert unless one is open for this host and kind; `true` when it did. Call inside the
/// caller's write transaction.
pub(crate) async fn open_alert(
    conn: &mut SqliteConnection,
    host: &str,
    kind: &str,
) -> Result<bool, sqlx::Error> {
    let Some(name) = host_name(conn, host).await? else {
        return Ok(false);
    };
    let new = sqlx::query(
        "INSERT OR IGNORE INTO leyline_alerts (host_id, kind, opened_at) \
         VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
    )
    .bind(host)
    .bind(kind)
    .execute(&mut *conn)
    .await?
    .rows_affected()
        == 1;
    if new {
        note(conn, "opened", host, kind, &name).await?;
    }
    Ok(new)
}

/// Closes the open alert of this host and kind; `true` when there was one.
pub(crate) async fn resolve(
    conn: &mut SqliteConnection,
    host: &str,
    kind: &str,
) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE leyline_alerts SET resolved_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
         WHERE host_id = ? AND kind = ? AND resolved_at IS NULL",
    )
    .bind(host)
    .bind(kind)
    .execute(&mut *conn)
    .await?
    .rows_affected()
        == 1;
    if done && let Some(name) = host_name(conn, host).await? {
        note(conn, "resolved", host, kind, &name).await?;
    }
    Ok(done)
}

async fn host_name(conn: &mut SqliteConnection, host: &str) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar("SELECT name FROM leyline_hosts WHERE id = ?")
        .bind(host)
        .fetch_optional(conn)
        .await
}

/// The audit row and the event the bell reads: ids, the alert kind and the host's name.
async fn note(
    conn: &mut SqliteConnection,
    op: &str,
    host: &str,
    kind: &str,
    name: &str,
) -> Result<(), sqlx::Error> {
    let row = NewAuditEvent {
        actor: BY,
        action: format!("leyline.alert.{op}"),
        entity: None,
        details: json!({"host": host, "kind": kind}).to_string(),
    };
    audit::append(conn, &row).await?;
    events::append(
        conn,
        "leyline.alert",
        &json!({"op": op, "id": host, "kind": kind, "host": name}),
    )
    .await?;
    Ok(())
}

fn label(kind: &str) -> &str {
    match kind {
        "failed_units" => "failed units",
        "host_key_changed" => "host key changed",
        k => k,
    }
}

/// The push an alert event calls for. An opened alert says `<host> · <kind>`; a host that is back
/// says `<host> · recovered`; closing any other alert is silent (the bell entry just resolves).
pub(crate) fn classify(e: &StoredEvent) -> Option<Notification> {
    if e.kind != "leyline.alert" {
        return None;
    }
    let p = &e.payload.0;
    let (op, kind, host, id) = (
        p["op"].as_str()?,
        p["kind"].as_str()?,
        p["host"].as_str()?,
        p["id"].as_str()?,
    );
    let data = json!({"host_id": id});
    let n = match (op, kind) {
        ("opened", _) => {
            let mut n = Notification::new(
                "leyline.alert",
                "read",
                "Host alert",
                &format!("{host} · {}", label(kind)),
                data,
            );
            n.collapse = Some("alert".to_owned());
            n
        }
        ("resolved", "down") => {
            let mut n = Notification::new(
                "leyline.recovered",
                "read",
                "Host recovered",
                &format!("{host} · recovered"),
                data,
            );
            n.collapse = Some("recovered".to_owned());
            n
        }
        _ => return None,
    };
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::types::Json;

    fn s(up: bool, mem: Option<f64>, disk: Option<f64>, units: Option<i64>) -> Sample {
        Sample {
            up,
            mem_pct: mem,
            disk_pct: disk,
            failed_units: units,
        }
    }
    fn gone() -> Sample {
        s(false, None, None, None)
    }
    fn fine() -> Sample {
        s(true, Some(40.0), Some(40.0), Some(0))
    }
    fn open(k: &[&str]) -> Vec<String> {
        k.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn down_needs_three_in_a_row_and_two_good_ones_to_close() {
        assert!(decide(&[gone(), gone()], &[]).is_empty());
        assert_eq!(decide(&[gone(), gone(), gone()], &[]), [Op::Open("down")]);
        // Already open: more failures change nothing.
        assert!(decide(&[gone(), gone(), gone()], &open(&["down"])).is_empty());
        // One good sample is not recovery; two are.
        assert!(decide(&[fine(), gone(), gone()], &open(&["down"])).is_empty());
        assert_eq!(
            decide(&[fine(), fine(), gone()], &open(&["down"])),
            [Op::Resolve("down")]
        );
    }

    #[test]
    fn disk_opens_at_90_and_closes_under_85() {
        let d = |x| [s(true, None, Some(x), None)];
        assert!(decide(&d(89.9), &[]).is_empty());
        assert_eq!(decide(&d(90.0), &[]), [Op::Open("disk")]);
        assert!(decide(&d(87.0), &open(&["disk"])).is_empty());
        assert_eq!(decide(&d(84.9), &open(&["disk"])), [Op::Resolve("disk")]);
        // A sample without a disk number (macOS, no probe output) changes nothing.
        assert!(decide(&[s(true, None, None, None)], &open(&["disk"])).is_empty());
    }

    #[test]
    fn memory_needs_five_samples_and_failed_units_follow_the_count() {
        let hot = || s(true, Some(96.0), None, None);
        assert!(decide(&[hot(), hot(), hot(), hot()], &[]).is_empty());
        assert_eq!(
            decide(&[hot(), hot(), hot(), hot(), hot()], &[]),
            [Op::Open("memory")]
        );
        assert_eq!(
            decide(&[s(true, Some(80.0), None, None)], &open(&["memory"])),
            [Op::Resolve("memory")]
        );
        assert_eq!(
            decide(&[s(true, None, None, Some(2))], &[]),
            [Op::Open("failed_units")]
        );
        assert_eq!(
            decide(&[s(true, None, None, Some(0))], &open(&["failed_units"])),
            [Op::Resolve("failed_units")]
        );
        assert!(decide(&[s(true, None, None, None)], &open(&["failed_units"])).is_empty());
    }

    fn event(op: &str, kind: &str) -> StoredEvent {
        StoredEvent {
            seq: 1,
            kind: "leyline.alert".to_owned(),
            payload: Json(json!({"op": op, "id": "h_1", "kind": kind, "host": "web-1"})),
            at: "2026-11-18T00:00:00.000Z".to_owned(),
        }
    }

    #[test]
    fn the_push_is_host_name_and_kind_only() {
        let n = classify(&event("opened", "host_key_changed")).unwrap();
        assert_eq!(n.kind, "leyline.alert");
        assert_eq!(n.body, "web-1 · host key changed");
        assert_eq!(n.data, json!({"host_id": "h_1"}));
        assert_eq!(n.collapse.as_deref(), Some("alert"));
    }

    #[test]
    fn a_burst_shares_one_collapse_key_and_resolve_closes_quietly() {
        // The Core merges notifications with one collapse key into a single push.
        let a = classify(&event("opened", "down")).unwrap();
        let b = classify(&event("opened", "disk")).unwrap();
        assert_eq!(a.collapse, b.collapse);
        let r = classify(&event("resolved", "down")).unwrap();
        assert_eq!(
            (r.kind, r.body.as_str()),
            ("leyline.recovered", "web-1 · recovered")
        );
        // Closing any other alert raises no push; neither does a foreign or malformed event.
        assert!(classify(&event("resolved", "disk")).is_none());
        assert!(classify(&event("resolved", "host_key_changed")).is_none());
        let mut other = event("opened", "down");
        other.kind = "leyline.hostkey".to_owned();
        assert!(classify(&other).is_none());
        for (k, _) in KINDS {
            assert!(k.starts_with("leyline."));
        }
    }
}
