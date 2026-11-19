//! Reachability (E8): is the host answering SSH at all? A TCP connect and the SSH banner, with no
//! login and no key, so nothing of the person's credentials is involved.
//!
//! Security model.
//! - The Core connects from its own machine, only to hosts a person already added, and only to the
//!   address and port stored for them. A host reached through a jump host or a runner is not probed
//!   (the Core cannot see it from here); it simply has no reachability.
//! - `POST /hosts/check` (the Add Host sheet's live check) takes an address and port from an `admin`
//!   caller at a live step-up, like the routes that point a host somewhere. It cannot be a port scanner:
//!   the name is resolved first and loopback, link-local (the cloud metadata address included),
//!   unspecified and multicast answers are refused; it connects to the address it checked, so a DNS
//!   change cannot swap it; every failure is the same sentence; a caller gets a few checks a minute and
//!   the Core a few at once. It reads at most the banner's first bytes and never returns them.
//! - The round runs every five minutes, a few hosts at a time: gentle, and a late round is skipped.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use ainkrad_core_server::api::App;
use ainkrad_core_server::api::v1::{ApiError, ApiResult, Caller};
use ainkrad_core_server::jobs::{Done, Job, JobHandler, Missed, Run, Schedule};
use ainkrad_core_server::scheduler::iso_of_unix;
use axum::Json;
use axum::extract::Extension;
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

/// A failed check is answered this long after it began, whatever the cause.
const FAIL_AFTER: Duration = Duration::from_secs(5);

/// An address the Core never probes (it is this machine): not marked down, simply not checked.
pub(crate) fn is_local(address: &str) -> bool {
    let a = address.trim_matches(['[', ']']).to_ascii_lowercase();
    a == "localhost" || a.ends_with(".localhost") || a.parse::<IpAddr>().is_ok_and(refused)
}

/// The one sentence for every failure: which of the reasons it was is not the caller's to learn.
const NO_ANSWER: &str = "it did not answer like an SSH server";

/// Loopback, link-local (which holds the cloud metadata address), unspecified, multicast and broadcast
/// are never probed: they are the Core's own machine or its cloud's, not a host a person owns.
pub(crate) fn refused(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_broadcast()
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return refused(IpAddr::V4(m));
            }
            // fe80::/10 link-local, and the metadata address some clouds use.
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (v.segments()[0] & 0xffc0) == 0xfe80
                || v.segments()[0] == 0xfd00 && v.segments()[1] == 0x0ec2
        }
    }
}

/// Resolves `address`, refuses it when any answer is refused, and returns the one to connect to.
async fn resolve(address: &str, port: u16) -> Result<SocketAddr, &'static str> {
    let all: Vec<SocketAddr> =
        tokio::time::timeout(CONNECT, tokio::net::lookup_host((address, port)))
            .await
            .map_err(|_| NO_ANSWER)?
            .map_err(|_| NO_ANSWER)?
            .collect();
    if all.is_empty() || all.iter().any(|a| refused(a.ip())) {
        return Err(NO_ANSWER);
    }
    Ok(all[0])
}

/// Connects and reads the first bytes: `Ok(milliseconds)` when they begin `SSH-`.
pub(crate) async fn answer(address: &str, port: u16) -> Result<u64, &'static str> {
    let to = resolve(address, port).await?;
    connect(to).await
}

async fn connect(to: SocketAddr) -> Result<u64, &'static str> {
    let started = Instant::now();
    let mut s = tokio::time::timeout(CONNECT, TcpStream::connect(to))
        .await
        .map_err(|_| NO_ANSWER)?
        .map_err(|_| NO_ANSWER)?;
    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(BANNER, s.read(&mut buf))
        .await
        .map_err(|_| NO_ANSWER)?
        .map_err(|_| NO_ANSWER)?;
    if !buf[..n].starts_with(b"SSH-") {
        return Err(NO_ANSWER);
    }
    Ok(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX))
}

/// A caller's checks this minute, and the Core's checks at once.
const PER_CALLER: usize = 10;
static CALLERS: OnceLock<Mutex<HashMap<String, Vec<Instant>>>> = OnceLock::new();
static AT_ONCE_CHECKS: OnceLock<Semaphore> = OnceLock::new();

/// True when `who` is within `PER_CALLER` checks in the last minute (and counts this one).
fn allowed(who: &str, now: Instant) -> bool {
    let mut all = CALLERS.get_or_init(Default::default).lock().unwrap();
    let mine = all.entry(who.to_owned()).or_default();
    mine.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
    if mine.len() >= PER_CALLER {
        return false;
    }
    mine.push(now);
    true
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
    responses((status = 200, description = "Whether the address answers like an SSH server from the Core (a TCP connect and the banner, no login), and how fast; one fixed sentence when it does not. Needs a step-up. 400 for an address or port that is not valid; 429 when this device checks too often or the Core is busy", body = Checked)))]
pub(crate) async fn check(
    Extension(me): Extension<Caller>,
    Json(req): Json<CheckHost>,
) -> ApiResult<Checked> {
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
    let busy = || {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            "too many checks; try again in a moment",
        )
    };
    if !allowed(&me.device.id, Instant::now()) {
        return Err(busy());
    }
    let gate = AT_ONCE_CHECKS.get_or_init(|| Semaphore::new(AT_ONCE));
    let _permit = gate.try_acquire().map_err(|_| busy())?;
    let started = Instant::now();
    Ok(Json(match answer(&req.address, port).await {
        Ok(ms) => Checked {
            ok: true,
            ms: Some(ms),
            reason: None,
        },
        Err(why) => {
            // Every failure takes the same time, so how fast it failed says nothing about why.
            tokio::time::sleep(FAIL_AFTER.saturating_sub(started.elapsed())).await;
            Checked {
                ok: false,
                ms: None,
                reason: Some(why.to_owned()),
            }
        }
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
        if is_local(&address) {
            continue;
        }
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

    #[test]
    fn loopback_link_local_metadata_and_unspecified_are_refused_and_a_lan_address_is_not() {
        for ip in [
            "127.0.0.1",
            "::1",
            "169.254.169.254",
            "0.0.0.0",
            "fe80::1",
            "fd00:ec2::254",
            "224.0.0.1",
            "::ffff:127.0.0.1",
        ] {
            assert!(refused(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["10.0.0.4", "192.168.1.20", "203.0.113.9", "2001:db8::1"] {
            assert!(!refused(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn every_failure_is_the_same_sentence_and_a_loopback_name_is_never_probed() {
        // A listener on loopback exists, yet the check will not touch it: the answer is the same as for a closed port.
        let ssh = server(b"SSH-2.0-OpenSSH_9.6\r\n").await;
        assert_eq!(answer("127.0.0.1", ssh).await.unwrap_err(), NO_ANSWER);
        assert_eq!(answer("localhost", ssh).await.unwrap_err(), NO_ANSWER);
    }

    #[test]
    fn this_machine_is_skipped_by_the_round_not_marked_down() {
        for a in [
            "localhost",
            "127.0.0.1",
            "::1",
            "[::1]",
            "db.localhost",
            "169.254.169.254",
        ] {
            assert!(is_local(a), "{a}");
        }
        for a in ["10.0.0.4", "birch.example.com"] {
            assert!(!is_local(a), "{a}");
        }
    }

    #[test]
    fn a_caller_gets_ten_checks_a_minute() {
        let t = Instant::now();
        assert!((0..PER_CALLER).all(|_| allowed("d_rate", t)));
        assert!(!allowed("d_rate", t));
        assert!(allowed("d_other", t));
        assert!(allowed("d_rate", t + Duration::from_secs(61)));
    }

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

    /// The banner reader itself, against a loopback listener (the public `answer` refuses loopback by design).
    #[tokio::test]
    async fn an_ssh_banner_answers_and_anything_else_does_not() {
        let ssh = server(b"SSH-2.0-OpenSSH_9.6\r\n").await;
        let to: SocketAddr = format!("127.0.0.1:{ssh}").parse().unwrap();
        assert!(connect(to).await.is_ok());
        let web = server(b"HTTP/1.1 200 OK\r\n").await;
        let to: SocketAddr = format!("127.0.0.1:{web}").parse().unwrap();
        assert_eq!(connect(to).await.unwrap_err(), NO_ANSWER);
    }
}
