//! The hardware the placement rules read (E15 §3.2, §3.5): the hub's live state joined with what
//! the Core keeps: which device is the Core host (the local enrolment) or This Mac (the attested
//! bundled runner), its pause and slot preferences, and the AI sessions and jobs it holds.

use std::collections::HashMap;

use ainkrad_proto::v2::{Arch, HwKind, Os};
use sqlx::sqlite::SqlitePool;

use super::place::HwView;
use crate::api::App;
use crate::hub::HwState;
use crate::store::gov::LOCAL_ENROL_SAS;

/// A job running on a machine.
pub struct LiveJob {
    pub id: String,
    pub project: Option<i64>,
    pub label: String,
    pub started_at: String,
}

/// One machine: the placement view plus what the API shows beyond it.
pub struct Machine {
    pub view: HwView,
    /// A pause in effect: its own or the pool's. On the Core host: the pool's (pause-all), which
    /// the Core row carries so it applies to runners paired later (the Core itself is never paused).
    pub paused_until: Option<String>,
    pub jobs: Vec<LiveJob>,
}

/// The kind of every paired runner device.
async fn kinds(pool: &SqlitePool) -> Result<HashMap<String, HwKind>, sqlx::Error> {
    let rows: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT device_id, sas, bundled FROM core_pairings \
         WHERE kind = 'runner' AND device_id IS NOT NULL",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(d, sas, bundled)| (d, kind_of(&sas, bundled)))
        .collect())
}

/// The local enrolment is the Core host; an attested bundled runner is This Mac.
fn kind_of(sas: &str, bundled: bool) -> HwKind {
    if sas == LOCAL_ENROL_SAS {
        HwKind::Core
    } else if bundled {
        HwKind::Mac
    } else {
        HwKind::Runner
    }
}

/// The later of two pause times.
fn later(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    }
}

/// `paused_until` in the future at `now` (ISO strings of one format compare as text).
fn is_paused(until: Option<&str>, now: &str) -> bool {
    until.is_some_and(|u| u > now)
}

fn view_of(
    h: HwState,
    kind: HwKind,
    paused: bool,
    slots: Option<u32>,
    sessions: u32,
    jobs: u32,
) -> HwView {
    let job_slots = slots.unwrap_or_else(|| h.capacity.as_ref().map_or(0, |c| c.job_slots));
    HwView {
        os: h.os.as_deref().and_then(Os::from_name),
        arch: h.arch.as_deref().and_then(Arch::from_name),
        device: h.device,
        name: h.name,
        kind,
        online: h.online,
        degraded: h.degraded,
        paused,
        capacity: h.capacity,
        sessions,
        jobs,
        job_slots,
        sustained_full: h.sustained_full,
    }
}

/// Every runner the hub has seen, as machines.
pub async fn machines(app: &App) -> Result<Vec<Machine>, sqlx::Error> {
    let kinds = kinds(&app.pool).await?;
    let now = app.clock.now();
    let prefs: HashMap<String, (Option<String>, Option<u32>)> =
        sqlx::query_as::<_, (String, Option<String>, Option<u32>)>(
            "SELECT device_id, paused_until, job_slots FROM core_hardware_prefs",
        )
        .fetch_all(&app.pool)
        .await?
        .into_iter()
        .map(|(d, p, s)| (d, (p, s)))
        .collect();
    let sessions: HashMap<String, i64> = sqlx::query_as::<_, (String, i64)>(
        "SELECT runner, count(*) FROM core_agent_sessions \
         WHERE state NOT IN ('ended', 'lost') GROUP BY runner",
    )
    .fetch_all(&app.pool)
    .await?
    .into_iter()
    .collect();
    let mut jobs: HashMap<String, Vec<LiveJob>> = HashMap::new();
    let rows: Vec<(String, String, Option<i64>, String, Option<String>, String)> = sqlx::query_as(
        "SELECT device_id, id, project_id, argv, started_at, created_at FROM core_hw_jobs \
         WHERE state IN ('queued', 'syncing', 'running') ORDER BY created_at",
    )
    .fetch_all(&app.pool)
    .await?;
    for (device, id, project, argv, started, created) in rows {
        jobs.entry(device).or_default().push(LiveJob {
            id,
            project,
            label: label_of(&argv),
            started_at: started.unwrap_or(created),
        });
    }
    let pool_pause = kinds
        .iter()
        .find(|(_, k)| **k == HwKind::Core)
        .and_then(|(d, _)| prefs.get(d))
        .and_then(|(p, _)| p.clone())
        .filter(|p| p.as_str() > now.as_str());
    Ok(app
        .hub
        .hardware()
        .into_iter()
        .map(|h| {
            let kind = kinds.get(&h.device).copied().unwrap_or(HwKind::Runner);
            let (own, slots) = prefs.get(&h.device).cloned().unwrap_or_default();
            // The later of the two pauses holds; the Core's row is the pool's, not its own.
            let until = if kind == HwKind::Core {
                None
            } else {
                later(own, pool_pause.clone())
            };
            let live = jobs.remove(&h.device).unwrap_or_default();
            let n_sessions =
                u32::try_from(sessions.get(&h.device).copied().unwrap_or(0)).unwrap_or(0);
            let view = view_of(
                h,
                kind,
                is_paused(until.as_deref(), &now),
                slots,
                n_sessions,
                u32::try_from(live.len()).unwrap_or(u32::MAX),
            );
            Machine {
                view,
                paused_until: if kind == HwKind::Core {
                    pool_pause.clone()
                } else {
                    until.filter(|u| u.as_str() > now.as_str())
                },
                jobs: live,
            }
        })
        .collect())
}

/// The placement views alone.
pub async fn views(app: &App) -> Result<Vec<HwView>, sqlx::Error> {
    Ok(machines(app).await?.into_iter().map(|m| m.view).collect())
}

/// `["cargo","build"]` as `cargo build`, cut to 120 characters.
fn label_of(argv: &str) -> String {
    let words: Vec<String> = serde_json::from_str(argv).unwrap_or_default();
    words.join(" ").chars().take(120).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_local_enrolment_is_the_core_and_the_attested_bundle_is_this_mac() {
        assert_eq!(kind_of(LOCAL_ENROL_SAS, false), HwKind::Core);
        assert_eq!(kind_of(LOCAL_ENROL_SAS, true), HwKind::Core);
        assert_eq!(kind_of("123456", true), HwKind::Mac);
        assert_eq!(kind_of("123456", false), HwKind::Runner);
    }

    #[test]
    fn a_pause_holds_until_its_time() {
        let now = "2026-11-20T10:00:00.000Z";
        assert!(is_paused(Some("2026-11-20T10:00:01.000Z"), now));
        assert!(!is_paused(Some(now), now));
        assert!(!is_paused(None, now));
        assert!(is_paused(Some("9999-12-31T00:00:00.000Z"), now));
    }

    #[test]
    fn the_later_pause_holds() {
        let (a, b) = (
            "2026-11-21T00:00:00.000Z".to_owned(),
            "2026-11-22T00:00:00.000Z".to_owned(),
        );
        assert_eq!(later(Some(a.clone()), Some(b.clone())), Some(b.clone()));
        assert_eq!(later(Some(a.clone()), None), Some(a));
        assert_eq!(later(None, None), None);
    }

    #[test]
    fn a_label_is_the_argv_joined() {
        assert_eq!(
            label_of(r#"["cargo","build","-p","x"]"#),
            "cargo build -p x"
        );
        assert_eq!(label_of("nonsense"), "");
    }
}
