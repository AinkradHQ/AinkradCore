//! Run bookkeeping for the gate (a child of `gate`, so it sees `Authorized`'s private fields):
//! the run and per-host rows, the audit rows, the final states, and cancelling a run that never
//! got past its approval.

use ainkrad_core::audit::NewAuditEvent;
use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, BY};
use ainkrad_core_server::store::{audit, begin_write};
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

/// An approval asked for and not yet spent or voided by the gate itself.
pub(super) struct Abandon {
    pub(super) pool: SqlitePool,
    pub(super) id: String,
    pub(super) session: String,
    pub(super) armed: bool,
}

impl Drop for Abandon {
    /// The call was dropped while its approval was open: void it in the background.
    fn drop(&mut self) {
        if self.armed
            && let Ok(h) = tokio::runtime::Handle::try_current()
        {
            let (pool, id, session) = (self.pool.clone(), self.id.clone(), self.session.clone());
            h.spawn(async move {
                let _ = ainkrad_core_server::ops_catalog::abandon_approval(&pool, &id, &session).await;
            });
        }
    }
}

/// Marks a run still waiting for approval cancelled (a run that has settled is left alone), and
/// voids its approval so the call parked on it ends at once. True when this call cancelled it.
pub(crate) async fn cancel(pool: &SqlitePool, run: &str) -> bool {
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
                "UPDATE leyline_run_hosts SET state = 'skipped' WHERE run_id = ? AND state IN ('needs_approval', 'queued')",
            )
            .bind(run)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE core_code_mode_approvals SET state = 'void' \
                 WHERE id = (SELECT approval FROM leyline_runs WHERE id = ?) AND state IN ('pending', 'approved')",
            )
            .bind(run)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await.map(|()| n == 1)
    };
    done.await.unwrap_or_else(|e| {
        tracing::error!(error = %e, "cancelling a parked leyline run failed");
        false
    })
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

/// `s` with secrets masked: the shared text pass (`ainkrad_proto::redact::one`), which masks a
/// secret-named field anywhere in a line (`user=bob password=x`, one-line JSON, `NAME: value`), URL
/// passwords, base64 runs and every known secret shape.
pub(super) fn redacted(s: &str) -> String {
    ainkrad_proto::redact::one(s)
}

/// Whether `s` holds a secret written out. A masked value that is only a `$NAME` or `${NAME}`
/// reference is not one: the card can show it as written. `$(...)` is not accepted: its inner
/// text can hold the secret itself.
pub(crate) fn literal_secret(s: &str) -> bool {
    let masked = redacted(s);
    if masked == s {
        return false;
    }
    // `masked` is `s` with some spans swapped for `[redacted:...]`: walk both and judge each span.
    // Anything that does not line up counts as a secret (the safe side).
    let (mut i, mut r) = (0, masked.as_str());
    while let Some(at) = r.find(MARK) {
        let lit = &r[..at];
        if !s[i..].starts_with(lit) {
            return true;
        }
        i += lit.len();
        let Some(close) = r[at..].find(']') else {
            return true;
        };
        r = &r[at + close + 1..];
        let end = match r.find(MARK).map(|n| &r[..n]) {
            Some("") => return true,
            Some(next) => s[i..].find(next).map(|n| i + n),
            None if r.is_empty() => Some(s.len()),
            None => s.ends_with(r).then(|| s.len() - r.len()),
        };
        match end {
            Some(e) if e >= i && only_refs(&s[i..e]) => i = e,
            _ => return true,
        }
    }
    false
}

const MARK: &str = "[redacted:";

/// A value made only of `$NAME` and `${NAME}`, with optional quotes and auth scheme word.
fn only_refs(span: &str) -> bool {
    let mut t = span.trim().trim_matches(['"', '\'']);
    if let Some((w, rest)) = t.split_once(' ')
        && matches!(
            w.to_ascii_lowercase().as_str(),
            "bearer" | "basic" | "token" | "digest"
        )
    {
        t = rest.trim_start().trim_matches(['"', '\'']);
    }
    let b = t.as_bytes();
    let name = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let (mut i, mut seen) = (0, false);
    while i < b.len() {
        if b[i] != b'$' {
            return false;
        }
        i += 1;
        match b.get(i) {
            Some(b'{') => {
                let n = b[i + 1..].iter().take_while(|c| name(**c)).count();
                if n == 0 || b.get(i + 1 + n) != Some(&b'}') {
                    return false;
                }
                i += n + 2;
            }
            Some(c) if c.is_ascii_alphabetic() || *c == b'_' => {
                while b.get(i).is_some_and(|c| name(*c)) {
                    i += 1;
                }
            }
            _ => return false,
        }
        seen = true;
    }
    seen
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
                // A pre-set command's steps, or the one ad-hoc line the gate decided on.
                steps: match (&c.cmd, c.action) {
                    (Some(m), _) => m.steps.clone(),
                    (None, Action::Exec(line)) => vec![line.clone()],
                    _ => Vec::new(),
                },
                tuple: h.tuple.clone(),
            }),
            Verdict::Deny(why) => refused.push((h.id.clone(), *why)),
            Verdict::Ask => unreachable!("every ask is decided before settling"),
        }
    }
    for (id, why) in &refused {
        sqlx::query(
            "UPDATE leyline_run_hosts SET state = 'refused', reason = ? WHERE run_id = ? AND host_id = ? AND state <> 'skipped'",
        )
        .bind(*why)
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
         ended_at = CASE WHEN ? = 'denied' THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now') END \
         WHERE id = ? AND state IN ('waiting_approval', 'running')",
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
        "UPDATE leyline_run_hosts SET state = ? WHERE run_id = ? AND host_id = ? AND state IN ('queued', 'running')",
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
        assert!(out.contains("DB_PASSWORD=[redacted:DB_PASSWORD]"), "{out}");
        assert!(out.contains("HOME=/root") && out.contains("note: nothing here"));
    }
}
