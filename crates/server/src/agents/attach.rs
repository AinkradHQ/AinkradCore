//! A message's attachments (E4) on their way to the runner: each file goes in an `agent.attach`
//! of its own (one frame, at most 10 MiB), the runner writes it into the session's folder and
//! answers with its path, and the message the harness gets names every path. One way for both a
//! message to a running session and a pending one the supervisor delivers (`live`).

use std::time::Duration;

use ainkrad_proto::v2::{AgentAttach, AgentSend, Reply};
use base64::Engine as _;

use super::*;

/// How long one file has to reach the runner and be written: 10 MiB over a slow link.
const ATTACH_WAIT: Duration = Duration::from_secs(120);

/// Sends `text` to session `s`'s runner after attachments `ids`, the paths they landed at named
/// at its end.
pub async fn send_with(
    app: &App,
    s: &Session,
    text: String,
    ids: &[String],
    proof: Option<Elevated>,
) -> Result<AgentEvents, Refusal> {
    let mut paths = Vec::with_capacity(ids.len());
    for id in ids {
        let Some((name, data)) = crate::store::attachments::load(&app.pool, &s.id, id).await?
        else {
            return Err(StreamError::new(ErrorCode::InvalidArgs, "the attachment is gone").into());
        };
        let attach = Command::AgentAttach(AgentAttach {
            session: s.id.clone(),
            id: id.clone(),
            name,
            data: base64::engine::general_purpose::STANDARD.encode(data),
        });
        let missing = || StreamError::new(ErrorCode::InvalidArgs, "agent elevation missing");
        let sent = app
            .hub
            .dispatch_elevated(&s.runner, attach, proof.ok_or_else(missing)?)?;
        let answer = tokio::time::timeout(ATTACH_WAIT, sent.outcome())
            .await
            .map_err(|_| {
                StreamError::new(ErrorCode::Lost, "the runner did not answer in time")
            })??;
        match answer {
            Body::Result(Reply::AgentAttach(a)) if a.id == *id => paths.push(a.path),
            _ => {
                return Err(
                    StreamError::new(ErrorCode::BadFrame, "an answer of another op").into(),
                );
            }
        }
    }
    let send = Command::AgentSend(AgentSend {
        session: s.id.clone(),
        text: with_paths(&s.harness, text, &paths),
    });
    Ok(ask(app, &s.runner, send, app.agents.config.answer, proof).await?)
}

/// `text` with one line per path after it: `@<path>` for Claude Code (its file mention, which
/// reads the file into the turn), the bare path for every other harness.
pub fn with_paths(harness: &str, text: String, paths: &[String]) -> String {
    if paths.is_empty() {
        return text;
    }
    let mention = |p: &String| match harness {
        "claude" => format!("@{p}"),
        _ => p.clone(),
    };
    let lines = paths.iter().map(mention).collect::<Vec<_>>().join("\n");
    match text.is_empty() {
        true => lines,
        false => format!("{text}\n\n{lines}"),
    }
}

#[cfg(test)]
mod tests {
    use super::with_paths;

    #[test]
    fn claude_gets_mentions_and_the_others_plain_paths() {
        let p = vec!["/w/.ainkrad/attachments/at_1-a.png".to_owned()];
        assert_eq!(with_paths("claude", "hi".into(), &[]), "hi");
        assert_eq!(
            with_paths("claude", "hi".into(), &p),
            "hi\n\n@/w/.ainkrad/attachments/at_1-a.png"
        );
        assert_eq!(
            with_paths("codex", "hi".into(), &p),
            "hi\n\n/w/.ainkrad/attachments/at_1-a.png"
        );
        assert_eq!(
            with_paths("codex", String::new(), &p),
            "/w/.ainkrad/attachments/at_1-a.png"
        );
    }
}
