//! Reachability (E8): is the host answering SSH at all? A TCP connect and the SSH banner, with no
//! login and no key, so nothing of the person's credentials is involved.
//!
//! Security model.
//! - The Core connects from its own machine, only to hosts a person already added, and only to the
//!   address and port stored for them. A host reached through a jump host or a runner is not probed
//!   (the Core cannot see it from here); it simply has no reachability.
//! - `POST /hosts/check` (the Add Host sheet's live check) takes an address and port from an `admin`
//!   caller, the same people who may add a host; it reads at most the banner line, with short timeouts,
//!   and answers a fixed set of words, never what the other side sent.
//! - The round runs every five minutes, a few hosts at a time: gentle, and a late round is skipped.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Missed, Run, Schedule};
use ainkrad_core_server::scheduler::iso_of_unix;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use utoipa::ToSchema;

use crate::valid;

const CONNECT: Duration = Duration::from_secs(5);
const BANNER: Duration = Duration::from_secs(4);
/// Probes at once in a round.
const AT_ONCE: usize = 4;

/// Connects and reads the first bytes: `Ok(milliseconds)` when they begin `SSH-`.
pub(crate) async fn answer(address: &str, port: u16) -> Result<u64, &'static str> {
    let started = Instant::now();
    let mut s = tokio::time::timeout(CONNECT, TcpStream::connect((address, port)))
        .await
        .map_err(|_| "it did not answer in time")?
        .map_err(|_| "nothing is listening there, or it cannot be reached")?;
    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(BANNER, s.read(&mut buf))
        .await
        .map_err(|_| "it answered, but not like an SSH server")?
        .map_err(|_| "the connection dropped")?;
    if !buf[..n].starts_with(b"SSH-") {
        return Err("it answered, but not like an SSH server");
    }
    Ok(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX))
}

/// What Add Host asks.
#[derive(Deserialize, ToSchema)]
pub struct CheckHost {
    pub address: String,
    pub port: Option<i64>,
}

/// The live check's answer: always 200, `ok` says whether it answered like an SSH server.
#[derive(Serialize, ToSchema)]
pub struct Checked {
    pub ok: bool,
    /// How long the connect and the banner took.
    pub ms: Option<u64>,
    /// In words, when it did not answer.
    pub reason: Option<String>,
}

#[utoipa::path(post, path = "/hosts/check", operation_id = "leylineCheckHost", tag = "leyline", request_body = CheckHost,
    responses((status = 200, description = "Whether the address answers like an SSH server from the Core (a TCP connect and the banner, no login), and how fast. 400 for an address or port that is not valid", body = Checked)))]
pub(crate) async fn check(Json(req): Json<CheckHost>) -> ApiResult<Checked> {
    let bad = || {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "that is not a valid address or port",
        )
    };
    if !valid::address(&req.address) {
        return Err(bad());
    }
    let port = req.port.map_or(Some(22), valid::port).ok_or_else(bad)?;
    Ok(Json(match answer(&req.address, port).await {
        Ok(ms) => Checked {
            ok: true,
            ms: Some(ms),
            reason: None,
        },
        Err(why) => Checked {
            ok: false,
            ms: None,
            reason: Some(why.to_owned()),
        },
    }))
}

/// How a host answered, on `HostView`.
#[derive(Serialize, ToSchema)]
pub struct HostReach {
    /// It answered like an SSH server at the last check.
    pub up: bool,
    pub latency_ms: Option<i64>,
    pub checked_at: String,
    /// The last time it answered; absent if it never has.
    pub seen_at: Option<String>,
}

/// The stored reachability of every host, by host id.
pub(crate) async fn all(pool: &SqlitePool) -> Result<Vec<(String, HostReach)>, sqlx::Error> {
    let rows =
        sqlx::query("SELECT host_id, up, latency_ms, checked_at, seen_at FROM leyline_reach")
            .fetch_all(pool)
            .await?;
    rows.iter()
        .map(|r| {
            Ok((
                r.try_get("host_id")?,
                HostReach {
                    up: r.try_get::<i64, _>("up")? == 1,
                    latency_ms: r.try_get("latency_ms")?,
                    checked_at: iso_of_unix(r.try_get("checked_at")?),
                    seen_at: r.try_get::<Option<i64>, _>("seen_at")?.map(iso_of_unix),
                },
            ))
        })
        .collect()
}

/// One round: every host the Core can reach directly.
async fn round(app: &App) -> Result<(), String> {
    let err = |e: sqlx::Error| e.to_string();
    let hosts = sqlx::query(
        "SELECT id, address, port FROM leyline_hosts WHERE via_runner IS NULL AND jump_chain = '[]'",
    )
    .fetch_all(&app.pool)
    .await
    .map_err(err)?;
    let gate = Arc::new(Semaphore::new(AT_ONCE));
    let mut set = JoinSet::new();
    for h in hosts {
        let (id, address): (String, String) = (
            h.try_get("id").map_err(err)?,
            h.try_get("address").map_err(err)?,
        );
        let port = u16::try_from(h.try_get::<i64, _>("port").map_err(err)?).unwrap_or(22);
        let gate = Arc::clone(&gate);
        set.spawn(async move {
            let _permit = gate.acquire().await;
            (id, answer(&address, port).await)
        });
    }
    let now = app.clock.unix();
    while let Some(done) = set.join_next().await {
        let Ok((id, result)) = done else { continue };
        let (up, ms) = match result {
            Ok(ms) => (1, i64::try_from(ms).ok()),
            Err(_) => (0, None),
        };
        sqlx::query(
            "INSERT INTO leyline_reach (host_id, up, latency_ms, checked_at, seen_at) \
             VALUES (?1, ?2, ?3, ?4, CASE WHEN ?2 = 1 THEN ?4 END) \
             ON CONFLICT(host_id) DO UPDATE SET up = ?2, latency_ms = ?3, checked_at = ?4, \
             seen_at = CASE WHEN ?2 = 1 THEN ?4 ELSE seen_at END",
        )
        .bind(id)
        .bind(up)
        .bind(ms)
        .bind(now)
        .execute(&app.pool)
        .await
        .map_err(err)?;
    }
    sqlx::query("DELETE FROM leyline_reach WHERE host_id NOT IN (SELECT id FROM leyline_hosts)")
        .execute(&app.pool)
        .await
        .map_err(err)?;
    Ok(())
}

struct Round;

impl JobHandler for Round {
    fn run<'a>(&'a self, run: &'a Run) -> Done<'a> {
        Box::pin(async move {
            let app = crate::health::app().ok_or("the leyline module is not attached")?;
            round(app).await?;
            run.idle();
            Ok(())
        })
    }
}

pub(crate) fn jobs() -> Vec<Job> {
    vec![Job {
        missed: Missed::Skip,
        ..Job::new("reach", Schedule::Every(300), Arc::new(Round))
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn server(banner: &'static [u8]) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let _ = s.write_all(banner).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn an_ssh_banner_answers_and_anything_else_or_nothing_does_not() {
        let ssh = server(b"SSH-2.0-OpenSSH_9.6\r\n").await;
        assert!(answer("127.0.0.1", ssh).await.is_ok());
        let web = server(b"HTTP/1.1 200 OK\r\n").await;
        assert_eq!(
            answer("127.0.0.1", web).await.unwrap_err(),
            "it answered, but not like an SSH server"
        );
        // A port nobody listens on.
        let free = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(answer("127.0.0.1", free).await.is_err());
    }
}
