//! Tool approvals and orphan sweeping.

use super::*;

/// The tool approvals the harness asked since the last look become `permission_escalation`
/// approvals (one per request, whatever the number of passes). The harness waits on the decision.
pub(super) async fn scan_approvals<H: Host>(
    app: &App,
    host: &H,
    r: &Run,
    s: &Session,
    now: &str,
    report: &mut Report,
) -> Result<(), Error> {
    let pool = &app.pool;
    if s.last_seq <= 0 {
        return Ok(());
    }
    let entries = sessions::transcript(pool, &s.id, r.approval_seq(pool).await?, 200).await?;
    let Some(last) = entries.last().map(|e| e.seq) else {
        return Ok(());
    };
    // A call an "allow for this issue" rule still covers goes ahead without a reviewer, with
    // these guards. (1) Fail closed: a rule must be a legal rule (`rule_problem`) and cover the
    // call in full (`allows`: every command and pattern, one simple command, nothing destructive);
    // a request id is allowed only when EVERY entry that carries it is covered, so a repeated id
    // can never hide an uncovered call. (2) One transaction audits `run.allowed_by_rule`,
    // escalates every other call and advances the cursor, and it commits BEFORE the harness is
    // told: an approval never exists without its row, a decision is never sent twice, and a crash
    // before it is sent leaves a request the runner denies on its own timeout. (3) A decision the
    // runner does not take is escalated like any other call and audited with outcome `unapplied`. The rows
    // carry the rule's id, never its text or the command.
    let rules = match r.issue_id {
        Some(issue) => crate::store::gov::issue_allow_rules(pool, issue, now).await?,
        None => vec![],
    };
    let mut verdicts: Vec<(&str, &str, Option<i64>)> = vec![];
    for e in entries
        .iter()
        .filter(|e| e.body["type"] == "approval_request")
    {
        let (Some(request), Some(tool)) = (e.body["id"].as_str(), e.body["tool"].as_str()) else {
            continue;
        };
        let sane = !request.is_empty()
            && request.len() <= 256
            && tool.len() <= 256
            && !request.contains(char::is_control);
        let covered = rules
            .iter()
            .find(|(_, rule)| {
                sane && ainkrad_proto::runner::rule_problem(rule).is_none()
                    && ainkrad_proto::runner::allows(rule, tool, &e.body["input"])
            })
            .map(|(id, _)| *id);
        match verdicts.iter_mut().find(|v| v.0 == request) {
            Some(v) if v.1 == tool && v.2 == covered => {}
            Some(v) => v.2 = None,
            None => verdicts.push((request, tool, covered)),
        }
    }
    let matched: Vec<(&str, &str, i64)> = verdicts
        .iter()
        .filter_map(|&(q, t, id)| id.map(|id| (q, t, id)))
        .collect();
    let company: i64 = sqlx::query_scalar("SELECT company_id FROM citadel_agents WHERE id = ?")
        .bind(r.agent_id.0)
        .fetch_one(pool)
        .await?;
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    for &m in &matched {
        audit_rule(&mut tx, r, company, m, "allowed").await?;
    }
    for e in entries
        .iter()
        .filter(|e| e.body["type"] == "approval_request")
    {
        if e.body["id"]
            .as_str()
            .is_some_and(|q| matched.iter().any(|m| m.0 == q))
        {
            continue;
        }
        escalate_in(&mut tx, r, s, company, e, now, report).await?;
    }
    sqlx::query("UPDATE citadel_runs SET approval_seq = ? WHERE id = ?")
        .bind(last as i64)
        .bind(r.id.0)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut unapplied = vec![];
    for &m in &matched {
        let told = Instruction::Decide {
            request: m.0.to_owned(),
            approved: true,
            reply: Some("allowed for this issue".to_owned()),
        };
        if host.instruct(app, &s.id, told).await.is_err() {
            unapplied.push(m);
        }
    }
    if unapplied.is_empty() {
        return Ok(());
    }
    let mut tx = ainkrad_core_server::store::begin_write(pool).await?;
    for m in unapplied {
        audit_rule(&mut tx, r, company, m, "unapplied").await?;
        for e in entries
            .iter()
            .filter(|e| e.body["id"].as_str() == Some(m.0))
        {
            escalate_in(&mut tx, r, s, company, e, now, report).await?;
        }
    }
    tx.commit().await
}

/// Opens the `permission_escalation` for one `approval_request` entry, once per request.
async fn escalate_in(
    tx: &mut sqlx::SqliteConnection,
    r: &Run,
    s: &Session,
    company: i64,
    e: &ainkrad_proto::v2::TranscriptEntry,
    now: &str,
    report: &mut Report,
) -> Result<(), Error> {
    let Some(request) = e.body["id"].as_str() else {
        return Ok(());
    };
    let asked: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM citadel_approvals WHERE kind = 'permission_escalation' \
         AND json_extract(payload, '$.session') = ?1 AND json_extract(payload, '$.request') = ?2)",
    )
    .bind(&s.id)
    .bind(request)
    .fetch_one(&mut *tx)
    .await?;
    if asked {
        return Ok(());
    }
    // The tool and a cut of what it was asked to do: the transcript is already redacted, and
    // what is kept here is shown on a phone, so it stays short.
    let tool = e.body["tool"].as_str().unwrap_or("a tool");
    let mut input = e.body["input"].clone();
    ainkrad_core_server::store::redact::json(&mut input);
    // The rule "allow for this issue" would store, from the whole call (not the cut below).
    let rule = ainkrad_proto::runner::default_rule(tool, &input);
    let input: String = input.to_string().chars().take(300).collect();
    let payload = json!({"run": r.id.0, "session": s.id, "request": request, "tool": tool,
                         "input": input, "rule": rule,
                         "summary": format!("{tool} needs a decision")});
    let new = NewApproval {
        company_id: crate::domain::org::CompanyId(company),
        kind: ApprovalKind::PermissionEscalation,
        issue_id: r.issue_id,
        sprint_id: None,
        agent_id: None,
        requested_by: r.agent_id,
        payload: payload.to_string(),
    };
    open_approval_in(tx, &new, None, now).await?;
    report.approvals += 1;
    Ok(())
}

/// One audit row for a rule that covered a call: ids and the tool name only, never the rule's text
/// or the command.
async fn audit_rule(
    conn: &mut sqlx::SqliteConnection,
    r: &Run,
    company: i64,
    (request, tool, rule_id): (&str, &str, i64),
    outcome: &str,
) -> Result<(), Error> {
    audit::append(
        conn,
        Event::new(SYSTEM, "run.allowed_by_rule")
            .entity("run", r.id.0)
            .company(company)
            .run(r.id.0)
            .details(json!({"outcome": outcome, "rule_id": rule_id,
                       "request": request.chars().take(256).collect::<String>(),
                       "tool": tool.chars().take(256).collect::<String>(),
                       "issue": r.issue_id.map(|i| i.0)})),
    )
    .await
}

impl Run {
    async fn approval_seq(&self, pool: &SqlitePool) -> Result<i64, Error> {
        sqlx::query_scalar("SELECT approval_seq FROM citadel_runs WHERE id = ?")
            .bind(self.id.0)
            .fetch_one(pool)
            .await
    }
}

/// A decided (or expired) `permission_escalation` is told to its harness once. Expired means no:
/// a tool nobody allowed does not run.
pub(super) async fn relay_decisions<H: Host>(
    app: &App,
    host: &H,
    report: &mut Report,
) -> Result<(), Error> {
    let decided: Vec<(i64, String, Option<String>, String)> = sqlx::query_as(
        "SELECT id, status, reply, payload FROM citadel_approvals \
         WHERE kind = 'permission_escalation' AND status IN ('approved', 'rejected', 'expired') \
         AND json_extract(payload, '$.session') IS NOT NULL \
         AND json_extract(payload, '$.relayed') IS NULL ORDER BY id LIMIT 50",
    )
    .fetch_all(&app.pool)
    .await?;
    for (id, status, reply, payload) in decided {
        let p: Value = serde_json::from_str(&payload).unwrap_or_default();
        let (Some(session), Some(request)) = (p["session"].as_str(), p["request"].as_str()) else {
            continue;
        };
        let live = sessions::get(&app.pool, session)
            .await?
            .is_some_and(|s| s.live());
        if live {
            let what = Instruction::Decide {
                request: request.to_owned(),
                approved: status == "approved",
                reply,
            };
            if let Err(why) = host.instruct(app, session, what).await {
                tracing::warn!(approval = id, why, "a decision was not taken; asking again");
                continue;
            }
        }
        sqlx::query(
            "UPDATE citadel_approvals SET payload = json_set(payload, '$.relayed', 1) WHERE id = ?",
        )
        .bind(id)
        .execute(&app.pool)
        .await?;
        report.relayed += 1;
        let mut tx = ainkrad_core_server::store::begin_write(&app.pool).await?;
        audit::append(
            &mut tx,
            Event::new(SYSTEM, "run.decided")
                .entity("approval", id)
                .run(p["run"].as_i64().unwrap_or(0))
                .details(json!({"status": status, "session_live": live})),
        )
        .await?;
        tx.commit().await?;
    }
    Ok(())
}

/// A live session of the engine's that no live run owns (a crash between starting it and
/// recording it, a cancel that raced the start) is killed: nothing may work unaccounted.
pub(super) async fn sweep_orphans<H: Host>(
    app: &App,
    host: &H,
    now: &str,
    report: &mut Report,
) -> Result<(), Error> {
    for s in sessions::live(&app.pool).await? {
        if s.owner_module.as_deref() != Some(crate::MODULE) {
            continue;
        }
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM citadel_runs WHERE session_id = ? \
             AND state IN ('claimed', 'running'))",
        )
        .bind(&s.id)
        .fetch_one(&app.pool)
        .await?;
        if owned || !older_than(&app.pool, &s.created_at, ORPHAN_GRACE_SECS, now).await? {
            continue;
        }
        if host
            .instruct(app, &s.id, Instruction::Stop { kill: true })
            .await
            .is_ok()
        {
            report.orphans += 1;
        }
    }
    Ok(())
}
