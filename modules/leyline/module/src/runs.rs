//! Run bookkeeping for the gate (a child of `gate`, so it sees `Authorized`'s private fields):
//! the run and per-host rows, the audit rows, the final states, and cancelling a run that never
//! got past its approval.

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, BY};
use ainkrad_core_server::store::{audit, begin_write, redact};
use ainkrad_proto::redact::names::secret_name;
use serde_json::{Value, json};
use sqlx::{SqliteConnection, SqlitePool};

use super::{Authorized, Call, Gated, H, KEPT};
use crate::policy::{Action, Principal, Verdict};

/// A run that was parked and did not finish its wait.
pub(super) struct Parked {
    pub(super) pool: SqlitePool,
    pub(super) run: String,
    pub(super) armed: bool,
}

impl Drop for Parked {
    /// The call itself was dropped (its task cancelled): cancel the run in the background.
    fn drop(&mut self) {
        if self.armed
            && let Ok(h) = tokio::runtime::Handle::try_current()
        {
            let (pool, run) = (self.pool.clone(), self.run.clone());
            h.spawn(async move { cancel(&pool, &run).await });
        }
    }
}

/// Marks a run still waiting for approval cancelled (a run that has settled is left alone).
pub(super) async fn cancel(pool: &SqlitePool, run: &str) {
    let done = async {
        let mut tx = begin_write(pool).await?;
        let n = sqlx::query(
            "UPDATE leyline_runs SET state = 'cancelled', ended_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE id = ? AND state = 'waiting_approval'",
        )
        .bind(run)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 1 {
            sqlx::query(
                "UPDATE leyline_run_hosts SET state = 'skipped' WHERE run_id = ? AND state = 'needs_approval'",
            )
            .bind(run)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    };
    if let Err(e) = done.await {
        tracing::error!(error = %e, "cancelling a parked leyline run failed");
    }
}

pub(super) async fn note(
    conn: &mut SqliteConnection,
    who: &Principal,
    action: &str,
    details: &Value,
) -> Result<(), ApiError> {
    let row = NewAuditEvent {
        actor: BY,
        action: action.to_owned(),
        entity: None,
        details: details.to_string(),
    };
    audit::append_as(conn, &row, who.origin())
        .await
        .map_err(|e| ApiError::from(sqlx::Error::Protocol(e.to_string())))?;
    Ok(())
}

/// The run and its host rows, before anything waits: a refused or parked call leaves a trace too.
pub(super) async fn write_run(
    app: &App,
    who: &Principal,
    run: &str,
    action: &Action,
    hosts: &[H],
    verdicts: &[Verdict],
    hash: &str,
) -> Result<(), ApiError> {
    let ask = verdicts.contains(&Verdict::Ask);
    let any = verdicts.contains(&Verdict::Allow);
    let state = if ask {
        "waiting_approval"
    } else if any {
        "running"
    } else {
        "denied"
    };
    let detail = cut(&redacted(action.detail()));
    let (command_id, adhoc) = match action {
        Action::Preset(id) => (Some(id.clone()), None),
        Action::Exec(_) => (None, Some(detail.clone())),
        _ => (None, None),
    };
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "INSERT INTO leyline_runs (id, command_id, adhoc, detail, action, principal, state) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(run)
    .bind(command_id)
    .bind(adhoc)
    .bind(detail)
    .bind(action.op())
    .bind(who.label())
    .bind(state)
    .execute(&mut *tx)
    .await?;
    for (h, v) in hosts.iter().zip(verdicts) {
        let s = match v {
            Verdict::Allow => "queued",
            Verdict::Ask => "needs_approval",
            Verdict::Deny(_) => "refused",
        };
        sqlx::query("INSERT INTO leyline_run_hosts (run_id, host_id, state) VALUES (?, ?, ?)")
            .bind(run)
            .bind(&h.id)
            .bind(s)
            .execute(&mut *tx)
            .await?;
    }
    let ids: Vec<&str> = hosts.iter().map(|h| h.id.as_str()).collect();
    let details = json!({"run": run, "op": action.op(), "principal": who.label(), "hosts": ids,
        "op_sha256": hash});
    note(&mut tx, who, "leyline.run.requested", &details).await?;
    tx.commit().await?;
    Ok(())
}

/// `s` with secrets masked: `NAME=value` and `NAME: value` lines whose NAME is secret-named (the
/// JSON key-name pass cannot see these in plain text), then every known secret shape.
pub(super) fn redacted(s: &str) -> String {
    let masked = s.split('\n').map(mask_line).collect::<Vec<_>>().join("\n");
    let mut v = Value::String(masked);
    redact::json(&mut v);
    v.as_str().unwrap_or_default().to_owned()
}

/// `export NAME=value`, `NAME=value`, `NAME: value`, `"name": "value",`: the value is replaced when
/// NAME is secret-named. The first separator on the line decides.
fn mask_line(line: &str) -> String {
    let Some(at) = line.find(['=', ':']) else {
        return line.to_owned();
    };
    let (head, rest) = line.split_at(at);
    let sep = &rest[..1];
    // `NAME: value` needs the space (or the end); `NAME=value` does not.
    if sep == ":" && !(rest[1..].is_empty() || rest[1..].starts_with([' ', '\t', '"'])) {
        return line.to_owned();
    }
    let name = head
        .rsplit(|c: char| c.is_whitespace())
        .next()
        .unwrap_or("")
        .trim_matches(['"', '\'']);
    let named = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if named && secret_name(name) && rest.len() > 1 {
        return format!("{head}{sep} [redacted:{name}]");
    }
    line.to_owned()
}

fn cut(s: &str) -> String {
    s.chars().take(KEPT).collect()
}

/// Final states, the `Authorized` values, the audit row.
pub(super) async fn settle(
    app: &App,
    c: &Call<'_>,
    hash: &str,
    hosts: &[H],
    verdicts: &[Verdict],
    approval_id: Option<&str>,
) -> Result<Gated, ApiError> {
    let (who, run) = (c.who, c.run);
    let mut authorized = Vec::new();
    let mut refused = Vec::new();
    let mut tx = begin_write(&app.pool).await?;
    for (h, v) in hosts.iter().zip(verdicts) {
        match v {
            Verdict::Allow => authorized.push(Authorized {
                run: run.to_owned(),
                host: h.id.clone(),
                action: c.action.clone(),
                op_sha256: hash.to_owned(),
                principal: who.clone(),
                steps: c.cmd.as_ref().map(|m| m.steps.clone()).unwrap_or_default(),
                tuple: h.tuple.clone(),
            }),
            Verdict::Deny(why) => refused.push((h.id.clone(), *why)),
            Verdict::Ask => unreachable!("every ask is decided before settling"),
        }
    }
    for (id, _) in &refused {
        sqlx::query(
            "UPDATE leyline_run_hosts SET state = 'refused' WHERE run_id = ? AND host_id = ?",
        )
        .bind(run)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    }
    for a in &authorized {
        sqlx::query(
            "UPDATE leyline_run_hosts SET state = 'queued' WHERE run_id = ? AND host_id = ? AND state = 'needs_approval'",
        )
        .bind(run)
        .bind(&a.host)
        .execute(&mut *tx)
        .await?;
    }
    let state = if authorized.is_empty() {
        "denied"
    } else {
        "running"
    };
    sqlx::query(
        "UPDATE leyline_runs SET state = ?, approval = ?, \
         ended_at = CASE WHEN ? = 'denied' THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now') END WHERE id = ?",
    )
    .bind(state)
    .bind(approval_id)
    .bind(state)
    .bind(run)
    .execute(&mut *tx)
    .await?;
    let reasons: Vec<Value> = refused
        .iter()
        .map(|(h, w)| json!({"host": h, "why": w}))
        .collect();
    if !refused.is_empty() {
        note(
            &mut tx,
            who,
            "leyline.run.refused",
            &json!({"run": run, "refused": reasons}),
        )
        .await?;
    }
    if !authorized.is_empty() {
        let ids: Vec<&str> = authorized.iter().map(|a| a.host.as_str()).collect();
        note(
            &mut tx,
            who,
            "leyline.run.allowed",
            &json!({"run": run, "hosts": ids, "approval": approval_id}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Gated {
        run: run.to_owned(),
        authorized,
        refused,
    })
}

/// The host's execution ended: spends the `Authorized`, and closes the run with its last host.
///
/// # Errors
///
/// A store failure.
pub async fn finish(app: &App, done: Authorized, ok: bool) -> Result<(), ApiError> {
    let mut tx = begin_write(&app.pool).await?;
    sqlx::query(
        "UPDATE leyline_run_hosts SET state = ? WHERE run_id = ? AND host_id = ? AND state = 'queued'",
    )
    .bind(if ok { "ok" } else { "failed" })
    .bind(&done.run)
    .bind(&done.host)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE leyline_runs SET state = 'done', ended_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
         WHERE id = ? AND state = 'running' AND NOT EXISTS \
         (SELECT 1 FROM leyline_run_hosts WHERE run_id = ? AND state IN ('queued', 'running', 'needs_approval'))",
    )
    .bind(&done.run)
    .bind(&done.run)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::redacted;

    /// Plain-text output is masked by the NAME, not only by shape (Y4-02 review, MEDIUM).
    #[test]
    fn secret_named_lines_in_output_are_masked() {
        let out = redacted(
            "$ env\nDB_PASSWORD=hunter2\nexport API_TOKEN=abc123\nclient_secret: s3cr3t\n\
             \"password\": \"pw\",\nHOME=/root\nnote: nothing here\nPASSWORD=\n",
        );
        for leaked in ["hunter2", "abc123", "s3cr3t", "\"pw\""] {
            assert!(!out.contains(leaked), "{leaked} leaked: {out}");
        }
        assert!(out.contains("DB_PASSWORD= [redacted:DB_PASSWORD]"), "{out}");
        assert!(out.contains("HOME=/root") && out.contains("note: nothing here"));
    }
}
