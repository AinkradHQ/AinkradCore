//! What a call's end tells a connection's health. Only classes the adapter says are about the
//! credential or the service reach here (`Outcome::health`, `CallError::health`): a 404, a 301, a
//! 451, a refused input or a huge answer, which an agent can provoke at will, are `None` already.
//!
//! - A rate limit or a quota goes in as an AGENT-sourced signal (`Signal::Agent`): it only cools,
//!   never counts, never disables, and only when the agent whose session made the call still holds
//!   a grant on the connection (a revoked agent cannot cool a connection it can no longer use).
//! - An auth failure is the Core's own observation of its own call: `Signal::Upstream` marks the
//!   connection out of use as `auth_suspected` until a TEST decides; this alone never disables it.
//!   Server errors and an unreachable service count as C1 says, and never disable either.
//! - A success starts the streaks over.

use ainkrad_proto::v2::UpstreamStatus;
use sqlx::sqlite::SqlitePool;

use crate::store::connections::access;
use crate::store::connections::health::{self, Signal};

/// One health class of a finished call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feed {
    pub status: UpstreamStatus,
    pub retry_after: Option<u64>,
    pub reset_at: Option<String>,
}

impl Feed {
    pub fn of(status: UpstreamStatus) -> Self {
        Self {
            status,
            retry_after: None,
            reset_at: None,
        }
    }
}

/// Tells connection `id` of workspace `ws` how a call made for `agent` ended.
pub async fn forward(
    pool: &SqlitePool,
    ws: i64,
    id: i64,
    agent: Option<&str>,
    feed: Option<&Feed>,
    now: &str,
) -> Result<(), sqlx::Error> {
    let Some(f) = feed else {
        return health::signal(pool, ws, id, Signal::Success, now).await;
    };
    match f.status {
        UpstreamStatus::RateLimited | UpstreamStatus::Quota => {
            if let Some(a) = agent
                && !access::agent_granted(pool, ws, id, a).await?
            {
                return Ok(());
            }
            let class = match f.status {
                UpstreamStatus::Quota => "quota",
                _ => "rate_limited",
            };
            health::signal(pool, ws, id, Signal::Agent { class }, now).await
        }
        status => {
            let signal = Signal::Upstream {
                status,
                retry_after: f.retry_after,
                reset_at: f.reset_at.as_deref(),
            };
            health::signal(pool, ws, id, signal, now).await
        }
    }
}
