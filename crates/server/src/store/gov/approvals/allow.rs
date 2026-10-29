//! "Allow for this issue" on a permission escalation (decision #34): approved, with an
//! allowlist entry for the issue's runs until `approval.issue_allow_secs` from the decision.

use ainkrad_core::settings::Scope;
use ainkrad_core::work::ProjectId;

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

/// The allowlist entry that lets the escalated call through: `<tool>:<the command's first two
/// words>` for a command (`Bash:cargo add`), else the tool.
pub fn allow_rule(tool: &str, input: &serde_json::Value) -> String {
    match ainkrad_proto::runner::command_of(input) {
        Some(c) => {
            let words: Vec<&str> = c.split_whitespace().take(2).collect();
            match words.is_empty() {
                true => tool.to_owned(),
                false => format!("{tool}:{}", words.join(" ")),
            }
        }
        None => tool.to_owned(),
    }
}

/// The allowlist entries of the issue's live rules at `now`.
pub async fn issue_allow_rules(
    pool: &SqlitePool,
    issue: IssueId,
    now: &str,
) -> Result<Vec<String>, Error> {
    sqlx::query_scalar(
        "SELECT rule FROM issue_allow_rules WHERE issue_id = ? \
         AND julianday(expires_at) > julianday(?) ORDER BY id",
    )
    .bind(issue.0)
    .bind(now)
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
    let project: i64 = sqlx::query_scalar("SELECT project_id FROM issues WHERE id = ?")
        .bind(issue.0)
        .fetch_one(&mut *conn)
        .await?;
    let secs = value_in(
        conn,
        Key::IssueAllowSecs,
        Scope::Project(ProjectId(project)),
    )
    .await?;
    let (rule_id, expires): (i64, String) = sqlx::query_as(
        "INSERT INTO issue_allow_rules (issue_id, rule, approval_id, created_at, expires_at) \
         VALUES (?1, ?2, ?3, ?4, strftime('%Y-%m-%dT%H:%M:%fZ', ?4, ?5)) \
         RETURNING id, expires_at",
    )
    .bind(issue.0)
    .bind(rule)
    .bind(a.id.0)
    .bind(now)
    .bind(format!("+{secs} seconds"))
    .fetch_one(&mut *conn)
    .await?;
    let details = json!({"rule": rule, "rule_id": rule_id, "issue": issue.0,
        "expires_at": expires});
    let actor = AuditActor::User(by);
    append_approval_event_as(conn, a, actor, "approval.allowed_for_issue", details).await
}
