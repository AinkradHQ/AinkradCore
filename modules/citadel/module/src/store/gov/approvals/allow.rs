//! "Allow for this issue" on a permission escalation (decision #34): approved, with an
//! allowlist entry for the issue's runs until `approval.issue_allow_secs` from the decision.

use super::*;

/// Approves the pending `permission_escalation` as `decide_approval` does, and allows the same
/// call on its issue's runs until `approval.issue_allow_secs` from `now` (decision #34's "Allow
/// for this issue"): `rule` (`<tool>` or `<tool>:<command prefix>`), else the escalated call's
/// own (`allow_rule`). Its runs get the rule in their policy from then on, and a live run's
/// escalation it covers is allowed without asking (`issue_allowed`). Audited as
/// `approval.allowed_for_issue`. Anything else is `DecideError::Allow`.
pub async fn allow_for_issue(
    pool: &SqlitePool,
    id: ApprovalId,
    by: UserId,
    reply: Option<&str>,
    rule: Option<&str>,
    now: &str,
) -> Result<Approval, DecideError> {
    decide(pool, id, true, by, reply, Extra::Allow(rule), now).await
}

/// The allowlist entry that lets the escalated call through: `<tool>:<the first two plain words
/// of the command that really runs>` (a Codex `bash -lc '<script>'` is read as its script), else
/// the tool, which a shell then refuses (it needs a command prefix).
pub fn allow_rule(tool: &str, input: &serde_json::Value) -> String {
    ainkrad_proto::runner::default_rule(tool, input)
}

/// The most live rules of one issue the engine looks at: a bound on the work of a pass.
pub const MAX_ISSUE_RULES: i64 = 64;

/// The issue's live rules at `now` as `(rule id, allowlist entry)`, oldest first, at most
/// [`MAX_ISSUE_RULES`].
pub async fn issue_allow_rules(
    pool: impl sqlx::SqliteExecutor<'_>,
    issue: IssueId,
    now: &str,
) -> Result<Vec<(i64, String)>, Error> {
    sqlx::query_as(
        "SELECT id, rule FROM citadel_issue_allow_rules WHERE issue_id = ? \
         AND julianday(expires_at) > julianday(?) ORDER BY id LIMIT ?",
    )
    .bind(issue.0)
    .bind(now)
    .bind(MAX_ISSUE_RULES)
    .fetch_all(pool)
    .await
}

/// The issue and the entry an "allow for this issue" of `a` adds: `rule`, else the escalated
/// call's own; refused for anything but a permission escalation on an issue.
pub(super) fn target(a: &Approval, rule: Option<&str>) -> Result<(IssueId, String), DecideError> {
    let (ApprovalKind::PermissionEscalation, Some(issue)) = (a.kind, a.issue_id) else {
        let why = "only a permission escalation on an issue is allowed for its issue";
        return Err(DecideError::Allow(why.to_owned()));
    };
    let payload: serde_json::Value = serde_json::from_str(&a.payload).unwrap_or_default();
    let tool = payload["tool"].as_str().unwrap_or_default();
    let rule = match rule.map(str::trim) {
        Some("") => return Err(DecideError::Allow("an empty rule".to_owned())),
        Some(rule) => rule.to_owned(),
        None => allow_rule(tool, &payload["input"]),
    };
    if let Some(why) = ainkrad_proto::runner::rule_problem(&rule) {
        return Err(DecideError::Allow(why.to_owned()));
    }
    Ok((issue, rule))
}

/// Stores the issue's rule from the approved `a` and audits `approval.allowed_for_issue` by `by`.
pub(super) async fn allow_in(
    conn: &mut SqliteConnection,
    a: &Approval,
    issue: IssueId,
    rule: &str,
    by: UserId,
    now: &str,
) -> Result<(), Error> {
    let secs = setting_in(conn, "approval.issue_allow_secs").await?;
    let (rule_id, expires): (i64, String) = sqlx::query_as(
        "INSERT INTO citadel_issue_allow_rules (issue_id, rule, approval_id, created_at, \
         expires_at) VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ', ?4, ?5)) \
         RETURNING id, expires_at",
    )
    .bind(issue.0)
    .bind(rule)
    .bind(a.id.0)
    .bind(now)
    .bind(format!("+{secs} seconds"))
    .fetch_one(&mut *conn)
    .await?;
    // The rule's text can hold arguments: the audit row names the rule by id only.
    let details = json!({"rule_id": rule_id, "issue": issue.0, "expires_at": expires});
    let actor = user_actor(by);
    append_approval_event_as(conn, a, actor, "approval.allowed_for_issue", details).await
}
